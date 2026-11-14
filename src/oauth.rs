//! Browser authorization stays server-side: exact issuer, S256 PKCE and one-use state.
use crate::{digest, now, random, web::App};
use anyhow::{Result, ensure};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Redirect, Response},
};
use base64::Engine;
use rusqlite::params;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const ISSUER: &str = "https://nebulacoder.com";
const CLIENT: &str = "kagnode-proxy-manager";
fn enabled(s: &App) -> bool {
    s.store
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT value FROM settings WHERE key='kagnode_login'",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap_or_else(|_| "true".into())
        == "true"
}
fn http() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()?)
}
fn installation(s: &App) -> Result<String> {
    let origin = url::Url::parse(&s.origin)?;
    ensure!(
        origin.scheme() == "https" && origin.origin().ascii_serialization() == s.origin,
        "KagNode sign-in requires the exact configured HTTPS installation origin"
    );
    // The issuer binds the callback to this origin; an opaque instance ID is
    // not an installation URL and would make every authorization fail.
    Ok(s.origin.clone())
}
pub async fn start(State(s): State<App>, headers: HeaderMap) -> Response {
    match begin(&s, &headers, false).await {
        Ok(r) => r,
        Err(_) => failure("KagNode sign-in is unavailable. Local sign-in still works."),
    }
}
async fn begin(s: &App, headers: &HeaderMap, link: bool) -> Result<Response> {
    ensure!(
        enabled(s),
        "KagNode Account integration is disabled by the local administrator"
    );
    ensure!(
        s.origin.starts_with("https://"),
        "Browser account linking requires HTTPS"
    );
    let local = if link {
        crate::auth::session(&s.store, headers)?
    } else {
        None
    };
    if let Some(ref u) = local {
        crate::auth::recent(u)?;
    }
    let state = random();
    let nonce = random();
    let verifier = random();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let installation = installation(s)?;
    let cookie = random();
    let redirect = format!("{}/auth/kagnode/callback", s.origin);
    let response=http()?.post(format!("{ISSUER}/api/v1/account-sync/browser/start")).json(&json!({"client_id":CLIENT,"installation":installation,"redirect_uri":redirect,"state":state,"nonce":nonce,"code_challenge":challenge,"code_challenge_method":"S256","purpose":"sign_in","scope":"profile.read email.read"})).send().await?;
    ensure!(
        response.status().is_success(),
        "KagNode did not accept the authorization request"
    );
    let data: Value = response.json().await?;
    let uri = data["authorization_uri"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing authorization URL"))?;
    let url = url::Url::parse(uri)?;
    ensure!(
        url.origin().ascii_serialization() == ISSUER
            && url.path() == "/oauth/authorize"
            && url.fragment().is_none()
            && url.username().is_empty(),
        "Unexpected authorization destination"
    );
    let details = json!({"request_id":data["request_id"],"nonce":nonce,"installation":installation,"local_user":local.map(|u|u.id)});
    {
        let db = s.store.db.lock().unwrap();
        db.execute("DELETE FROM oauth WHERE expires<?", [now()])?;
        db.execute(
            "INSERT INTO oauth VALUES(?,?,?,?,?)",
            params![
                digest(&state),
                verifier,
                details.to_string(),
                digest(&cookie),
                now() + 600
            ],
        )?;
    }
    let mut response = Redirect::to(uri).into_response();
    response.headers_mut().insert(header::SET_COOKIE,format!("kn_proxy_oauth={cookie}; Secure; HttpOnly; SameSite=Lax; Path=/auth/kagnode; Max-Age=600").parse()?);
    Ok(response)
}
pub async fn callback(
    State(s): State<App>,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let result = complete(&s, &headers, &query).await;
    let mut response = match result {
        Ok(id) => crate::web::complete_password(&s, &id).unwrap_or_else(|_| {
            Redirect::to("/login?notice=verification_unavailable").into_response()
        }),
        Err(_) => Redirect::to("/login?notice=kagnode_unavailable").into_response(),
    };
    response.headers_mut().append(
        header::SET_COOKIE,
        "kn_proxy_oauth=; Secure; HttpOnly; SameSite=Lax; Path=/auth/kagnode; Max-Age=0"
            .parse()
            .unwrap(),
    );
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}
async fn complete(
    s: &App,
    headers: &HeaderMap,
    query: &std::collections::HashMap<String, String>,
) -> Result<String> {
    ensure!(enabled(s), "KagNode integration is disabled");
    let state = query
        .get("state")
        .ok_or_else(|| anyhow::anyhow!("Missing state"))?;
    ensure!(state.len() == 64, "Invalid state");
    let cookie = crate::auth::cookie(headers, "kn_proxy_oauth")
        .ok_or_else(|| anyhow::anyhow!("Missing browser binding"))?;
    let row = {
        let mut db = s.store.db.lock().unwrap();
        let tx = db.transaction()?;
        let row = tx.query_row(
            "SELECT verifier,request,cookie FROM oauth WHERE state=? AND expires>?",
            params![digest(state), now()],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            },
        )?;
        ensure!(row.2 == digest(cookie), "Browser binding mismatch");
        tx.execute("DELETE FROM oauth WHERE state=?", [digest(state)])?;
        tx.commit()?;
        row
    };
    ensure!(
        !query.contains_key("error") && query.get("iss").map(String::as_str) == Some(ISSUER),
        "Authorization denied or issuer mismatch"
    );
    let code = query
        .get("code")
        .ok_or_else(|| anyhow::anyhow!("Missing code"))?;
    ensure!(
        code.len() == 43
            && code
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
        "Invalid code"
    );
    let details: Value = serde_json::from_str(&row.1)?;
    let response=http()?.post(format!("{ISSUER}/api/v1/account-sync/token")).json(&json!({"client_id":CLIENT,"grant_type":"authorization_code","code":code,"code_verifier":row.0,"redirect_uri":format!("{}/auth/kagnode/callback",s.origin)})).send().await?;
    ensure!(response.status().is_success(), "Code exchange failed");
    let tokens: Value = response.json().await?;
    let access = tokens["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing access token"))?;
    let result=async{let proof=&tokens["authorization"];ensure!(proof["issuer"]==ISSUER&&proof["client_id"]==CLIENT&&proof["installation"]==details["installation"]&&proof["nonce"]==details["nonce"]&&proof["purpose"]=="sign_in"&&proof["expires_at"].as_i64().is_some_and(|v|v>=now())&&proof["issued_at"].as_i64().is_some_and(|v|(now()-v).abs()<=120)&&proof["auth_time"].as_i64().is_some_and(|v|v<=now()+5&&v>=now()-28800),"Authorization proof mismatch");let response=http()?.get(format!("{ISSUER}/api/v1/account-sync/profile")).query(&[("client_id",CLIENT)]).bearer_auth(access).send().await?;ensure!(response.status().is_success(),"Profile not available");let profile:Value=response.json().await?;ensure!(profile["issuer"]==ISSUER&&profile["subject"]==proof["subject"]&&profile["email_verified"]==true,"Profile identity mismatch");let subject=profile["subject"].as_str().ok_or_else(||anyhow::anyhow!("Missing identity"))?;let name=profile["name"].as_str().unwrap_or("KagNode user");ensure!(!subject.is_empty()&&subject.len()<=200&&name.len()<=80,"Invalid profile");let photo=profile["photo"].as_str().filter(|v|v.starts_with("data:image/webp;base64,")&&v.len()<256*1024).unwrap_or("");let linked:Option<String>=s.store.db.lock().unwrap().query_row("SELECT id FROM users WHERE subject=? AND disabled=0",[subject],|r|r.get(0)).ok();let id=if let Some(current)=details["local_user"].as_str(){let u=crate::auth::session(&s.store,headers)?.ok_or_else(||anyhow::anyhow!("Sign in again before linking"))?;ensure!(u.id==current&&linked.as_ref().is_none_or(|id|id==&u.id),"Account identity changed");u.id}else if let Some(id)=linked{id}else{let db=s.store.db.lock().unwrap();let signup=db.query_row("SELECT value FROM settings WHERE key='signup'",[],|r|r.get::<_,String>(0)).unwrap_or_else(|_|"false".into())=="true";drop(db);ensure!(signup,"This installation requires an invitation");let email=profile["email"].as_str().ok_or_else(||anyhow::anyhow!("Verified email required"))?;let id=random();s.store.db.lock().unwrap().execute("INSERT INTO users(id,email,name,password,role,subject)VALUES(?,?,?,'','\"viewer\"',?)",params![id,email,name,subject])?;id};s.store.db.lock().unwrap().execute("UPDATE users SET subject=?,name=?,photo=? WHERE id=? AND disabled=0",params![subject,name,photo,id])?;s.store.audit(&id,"account.kagnode.signin",&id,json!({"issuer":ISSUER}))?;Ok(id)}.await;
    // This sign-in synchronizes the profile once and retains no issuer credential.
    // Appearance uses Core's separate, browser-owned appearance grant.
    for token in [tokens["refresh_token"].as_str(), Some(access)]
        .into_iter()
        .flatten()
    {
        let _ = http()?
            .post(format!("{ISSUER}/api/v1/account-sync/revoke"))
            .json(&json!({"client_id":CLIENT,"token":token}))
            .send()
            .await;
    }
    result
}
fn failure(message: &str) -> Response {
    let content = format!(
        "<section class=\"login-frame\"><div><h1>Sign-in paused</h1><p>{}</p><a class=\"button\" href=\"/login\">Return to sign in</a></div></section>",
        crate::core::escape(message)
    );
    axum::response::Html(crate::web::shell("Sign-in paused", None, &content)).into_response()
}

#[derive(serde::Deserialize)]
pub struct LinkForm {
    #[serde(rename = "_csrf")]
    csrf: String,
}
pub async fn link(
    State(s): State<App>,
    mut headers: HeaderMap,
    axum::Form(input): axum::Form<LinkForm>,
) -> Response {
    let verify = || -> Result<()> {
        headers.insert("x-csrf-token", input.csrf.parse()?);
        let user = crate::auth::session(&s.store, &headers)?
            .ok_or_else(|| anyhow::anyhow!("Sign in first"))?;
        crate::auth::csrf(&user, &headers, &s.origin)?;
        crate::auth::recent(&user)?;
        Ok(())
    };
    let mut verify = verify;
    if verify().is_err() {
        return failure("Sign in locally again before linking KagNode Account.");
    }
    match begin(&s, &headers, true).await {
        Ok(response) => response,
        Err(_) => failure("KagNode linking could not be started; your local account is unchanged."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_installation_is_the_exact_callback_origin() {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(dir.path()).unwrap();
        let app = App::new(
            store,
            "https://192.168.0.6:8443".into(),
            "https://192.168.0.6:9444".into(),
        );
        assert_eq!(installation(&app).unwrap(), "https://192.168.0.6:8443");
        let mut bad = app.clone();
        bad.origin = "https://192.168.0.6:8443/path".into();
        assert!(installation(&bad).is_err());
    }
}
