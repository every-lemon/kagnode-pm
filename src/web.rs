use crate::{
    auth::{self, User},
    digest,
    domain::Resource,
    now, random,
    store::Store,
};
use axum::{
    Extension, Form, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use rusqlite::params;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
macro_rules! ensure {($test:expr,$($message:tt)*)=>{if !$test{return Err(Error::from(anyhow::anyhow!($($message)*)))}};}
#[derive(Clone)]
pub struct App {
    pub store: Store,
    pub origin: String,
    pub fleet_url: String,
    pub rates: Arc<Mutex<HashMap<String, (i64, u32)>>>,
    pub hashes: Arc<tokio::sync::Semaphore>,
}
impl App {
    pub fn new(store: Store, origin: String, fleet_url: String) -> Self {
        Self {
            store,
            origin,
            fleet_url,
            rates: Default::default(),
            hashes: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }
}
pub struct Error(pub StatusCode, pub String);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        let msg = e.to_string();
        let status = if msg.starts_with("conflict:") {
            StatusCode::CONFLICT
        } else {
            StatusCode::BAD_REQUEST
        };
        Self(
            status,
            if msg.contains("UNIQUE constraint") {
                "That name already exists".into()
            } else if msg.contains("sqlite") || msg.contains("SQLITE") {
                "Storage operation failed".into()
            } else {
                msg
            },
        )
    }
}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::from(anyhow::Error::from(e))
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self(
            StatusCode::BAD_REQUEST,
            "Invalid JSON or unsupported fields".into(),
        )
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The local service could not complete this operation".into(),
        )
    }
}
type Api<T> = std::result::Result<T, Error>;
fn user(s: &App, h: &HeaderMap, write: bool) -> Api<User> {
    let u = auth::session(&s.store, h)?
        .ok_or_else(|| Error(StatusCode::UNAUTHORIZED, "Sign in to continue".into()))?;
    if write {
        auth::csrf(&u, h, &s.origin).map_err(|_| {
            Error(
                StatusCode::FORBIDDEN,
                "This form expired or came from another origin. Reload before trying again.".into(),
            )
        })?;
    }
    Ok(u)
}
fn admin(u: &User) -> Api<()> {
    if u.role.administer() {
        Ok(())
    } else {
        Err(Error(
            StatusCode::FORBIDDEN,
            "Local administrator permission is required".into(),
        ))
    }
}
fn allowed(s: &App, u: &User, id: &str, write: bool, maintenance: bool) -> Api<()> {
    if s.store.allowed(&u.id, &u.role, id, write, maintenance)? {
        Ok(())
    } else {
        Err(Error(StatusCode::NOT_FOUND, "Server is unavailable".into()))
    }
}
pub fn router(state: App) -> Router {
    Router::new()
        .route(
            "/healthz",
            get(|| async {
                Json(json!({"ok":true,"service":"kagnode-proxy-manager","version":crate::VERSION}))
            }),
        )
        .route("/login", get(login_page).post(login_form))
        .route("/auth/kagnode/start", get(crate::oauth::start))
        .route("/auth/kagnode/link", post(crate::oauth::link))
        .route("/auth/kagnode/callback", get(crate::oauth::callback))
        .route("/logout", post(logout))
        .route("/mfa", get(mfa_page).post(mfa_finish))
        .route("/api/v1/account", get(account))
        .route("/api/v1/account/policy", post(account_policy))
        .route("/api/v1/account/mfa/start", post(mfa_start))
        .route("/api/v1/account/mfa/confirm", post(mfa_confirm))
        .route("/api/v1/session", get(session).post(login_api))
        .route("/api/v1/kagnode-core/status", get(core_status))
        .route("/api/v1/kagnode-core/whats-new", get(core_notice))
        .route(
            "/api/v1/kagnode-core/whats-new/dismiss",
            post(core_notice_dismiss),
        )
        .route("/api/v1/kagnode-core/{action}", post(core_action))
        .route("/api/v1/servers", get(servers))
        .route("/api/v1/search", get(search))
        .route("/api/v1/overview", get(overview))
        .route(
            "/api/v1/application-updates/status",
            get(application_status),
        )
        .route(
            "/api/v1/application-updates/{action}",
            post(application_action),
        )
        .route("/api/v1/enrollments", post(enrollment))
        .route("/api/v1/servers/{id}/revoke", post(revoke))
        .route(
            "/api/v1/servers/{id}/resources",
            get(resources).post(save_resource),
        )
        .route("/api/v1/servers/{id}/publish", post(publish))
        .route(
            "/api/v1/servers/{id}/publication-review",
            get(publication_review),
        )
        .route("/api/v1/resources/{id}/history", get(resource_history))
        .route("/api/v1/resources/{id}/reachability", post(probe_upstreams))
        .route("/api/v1/resources/{id}/restore", post(restore_resource))
        .route(
            "/api/v1/servers/{id}/retired-resources",
            get(retired_resources),
        )
        .route(
            "/api/v1/servers/{id}/certificates/inspect",
            post(certificate_inventory),
        )
        .route(
            "/api/v1/servers/{id}/certificates/issue",
            post(certificate_issue),
        )
        .route(
            "/api/v1/servers/{id}/certificates/upload",
            post(certificate_upload),
        )
        .route(
            "/api/v1/servers/{id}/certificates/activate",
            post(certificate_activate),
        )
        .route("/api/v1/resources/{id}", delete(remove_resource))
        .route("/api/v1/servers/{id}/jobs", get(jobs))
        .route("/api/v1/servers/{id}/inspect", post(inspect_server))
        .route("/api/v1/servers/{id}/discovery", post(discover_server))
        .route("/api/v1/servers/{id}/adoptions", post(review_import))
        .route("/api/v1/engines", get(engine_capabilities))
        .route("/api/v1/servers/{id}/engine-plan", post(engine_preview))
        .route("/api/v1/servers/{id}/packages/plans", post(package_plan))
        .route("/api/v1/servers/{id}/packages/apply", post(package_apply))
        .route("/api/v1/jobs/{id}/cancel", post(cancel_job))
        .route("/api/v1/jobs/{id}/resolve", post(resolve_job))
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/users", get(users).post(create_user))
        .route("/api/v1/users/{id}", post(update_user))
        .route("/api/v1/users/{id}/servers/{server}", post(grant_server))
        .route(
            "/api/v1/users/{id}/servers/{server}/revoke",
            post(revoke_grant),
        )
        .route("/agent/v1/enroll", post(enroll_agent))
        .route("/kagnode-core/{version}/{file}", get(crate::core::asset))
        .route("/assets/{file}", get(asset))
        .route("/", get(page))
        .route("/{page}", get(page_named))
        .layer(DefaultBodyLimit::max(65536))
        .layer(axum::middleware::from_fn(headers))
        .with_state(state)
}
pub fn fleet_router(state: App) -> Router {
    Router::new()
        .route("/agent/v1/poll", post(poll))
        .route("/agent/v1/heartbeat", post(heartbeat))
        .route("/agent/v1/jobs/{id}/result", post(job_result))
        .layer(DefaultBodyLimit::max(65536))
        .with_state(state)
}
async fn headers(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY,"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self' https://nebulacoder.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".parse().unwrap());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    // Native same-origin form POSTs need their real Origin. OAuth callbacks set
    // their own no-referrer policy and redirect before loading any assets.
    h.entry(header::REFERRER_POLICY)
        .or_insert("same-origin".parse().unwrap());
    h.entry(header::CACHE_CONTROL)
        .or_insert("no-store".parse().unwrap());
    response
}
async fn asset(Path(file): Path<String>) -> Response {
    match file.as_str() {
        crate::generated_assets::JS_NAME => (
            [
                (header::CONTENT_TYPE, "text/javascript"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            crate::generated_assets::JS,
        )
            .into_response(),
        crate::generated_assets::CSS_NAME => (
            [
                (header::CONTENT_TYPE, "text/css"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
            ],
            crate::generated_assets::CSS,
        )
            .into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}
pub fn shell(title: &str, u: Option<&User>, content: &str) -> String {
    let esc = crate::core::escape;
    let mark = format!("/kagnode-core/{}/mark.svg", crate::core::version());
    let navigation = u.map(navigation).unwrap_or_default();
    let search_source = format!(
        "<div hidden data-core-search-source data-endpoint=\"/api/v1/search\">{navigation}</div>"
    );
    let sidebar = if u.is_some() {
        crate::core::template(
            "sidebar",
            &[],
            &[
                (
                    "brand",
                    &format!(
                        "<a class=\"brand\" href=\"/\"><img src=\"{mark}\" alt=\"\" width=\"28\"><span class=\"brand-copy\"><strong>KagNode.</strong><small>Proxy</small></span></a>"
                    ),
                ),
                (
                    "navigation",
                    &format!(
                        "<button type=\"button\" data-command class=\"pm-search-trigger\"><span data-core-icon=\"search\"></span><span class=\"nav-label\">Quick search</span><kbd>Ctrl K</kbd></button><nav>{navigation}</nav>"
                    ),
                ),
                ("footer", ""),
            ],
        )
    } else {
        String::new()
    };
    let account = if let Some(user) = u {
        let avatar =
            if user.photo.starts_with("data:image/webp;base64,") && user.photo.len() < 256 * 1024 {
                format!(
                    "<img class=\"profile-photo\" src=\"{}\" alt=\"\">",
                    esc(&user.photo)
                )
            } else {
                esc(&user.name.chars().take(1).collect::<String>())
            };
        let identity = format!(
            "<strong>{}</strong><small>{}</small>",
            esc(&user.name),
            esc(&user.email)
        );
        let actions = format!(
            "<a href=\"/account\">Account and preferences</a><a href=\"/jobs\">Recent operations</a><form method=\"post\" action=\"/logout\"><input name=\"_csrf\" type=\"hidden\" value=\"{}\"><button>Sign out</button></form>",
            esc(&user.csrf)
        );
        let menu = crate::core::template(
            "account-menu",
            &[],
            &[("identity", &identity), ("actions", &actions)],
        );
        format!(
            "<button class=\"icon-button account-trigger\" data-core-account-trigger aria-label=\"Open account menu\">{avatar}</button>{menu}"
        )
    } else {
        String::new()
    };
    let bootstrap = u
        .map(|u| json!({"id":u.id,"name":u.name,"email":u.email,"version":crate::VERSION,"role":u.role,"csrf":u.csrf}))
        .unwrap_or(json!(null))
        .to_string()
        .replace('<', "\\u003c");
    if u.is_none() {
        return format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light dark\"><title>{} · KagNode. Proxy</title>{}<link rel=\"stylesheet\" href=\"/assets/{host_css}\"><link rel=\"icon\" href=\"{mark}\" type=\"image/svg+xml\"></head><body class=\"identity-screen\">{content}</body></html>",
            esc(title),
            crate::core::context(false, ""),
            host_css = crate::generated_assets::CSS_NAME
        );
    }
    let css = crate::generated_assets::CSS_NAME;
    let js = crate::generated_assets::JS_NAME;
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light dark\"><title>{} · KagNode. Proxy</title>{}<link rel=\"icon\" href=\"{mark}\" type=\"image/svg+xml\"><link rel=\"stylesheet\" href=\"/assets/{css}\"><script defer src=\"/assets/{js}\"></script></head><body class=\"{}\">{sidebar}{search_source}<div class=\"workspace\"><header class=\"topbar\"><div><span class=\"eyebrow\">KAGNODE PROXY</span><span>{}</span></div>{account}</header><main id=\"main\" tabindex=\"-1\">{content}</main><footer>Self-hosted. Your servers, your control. <a href=\"https://github.com/every-lemon/kagnode-pm\">Source</a></footer></div><script type=\"application/json\" id=\"session-data\">{bootstrap}</script></body></html>",
        esc(title),
        crate::core::context(u.is_some(), u.map_or("", |u| &u.id)),
        if u.is_some() { "" } else { "identity-screen" },
        esc(title)
    )
}
async fn page(State(s): State<App>, h: HeaderMap) -> Api<Response> {
    page_for(s, h, "overview".into()).await
}
async fn page_named(State(s): State<App>, h: HeaderMap, Path(name): Path<String>) -> Api<Response> {
    page_for(s, h, name).await
}
async fn page_for(s: App, h: HeaderMap, name: String) -> Api<Response> {
    let Some(u) = auth::session(&s.store, &h)? else {
        return Ok(Redirect::to("/login").into_response());
    };
    let title = match name.as_str() {
        "overview" => "Overview",
        "servers" => "Servers",
        "reverse-proxies" => "Reverse proxies",
        "streams" => "Streams",
        "forward-proxies" => "Forward proxies",
        "certificates" => "Certificates",
        "packages" => "Packages",
        "jobs" => "Jobs",
        "audit" => "Audit",
        "users" => "Users and access",
        "account" => "Account",
        "discovery" => "Discover configuration",
        "search" => "Search",
        _ => return Err(Error(StatusCode::NOT_FOUND, "Page not found".into())),
    };
    let content = format!(
        "<section class=\"page-heading\"><div><h1>{title}</h1><p id=\"page-description\">Manage your fleet with reviewed changes and clear results.</p></div><div id=\"page-actions\"></div></section><div id=\"feedback\" role=\"status\" aria-live=\"polite\"></div><section id=\"page-content\" data-page=\"{}\"><p>Loading {title}…</p></section>",
        crate::core::escape(&name)
    );
    Ok(Html(shell(title, Some(&u), &content)).into_response())
}
async fn login_page(State(s): State<App>) -> Response {
    render_login(&s, None)
}
fn render_login(s: &App, error: Option<(&str, &str)>) -> Response {
    let token = random();
    let (message, email) = error.map_or((String::new(), String::new()), |(m, e)| {
        (
            format!(
                "<p role=\"alert\" class=\"notice\">{}</p>",
                crate::core::escape(m)
            ),
            crate::core::escape(e),
        )
    });
    let form = format!(
        "{message}<form action=\"/login\" method=\"post\" data-core-login-progressive=\"on\"><input name=\"_csrf\" type=\"hidden\" value=\"{token}\"><label>Email<input name=\"email\" type=\"email\" autocomplete=\"username\" value=\"{email}\" maxlength=\"254\" required></label><label>Password<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required maxlength=\"256\"></label><button class=\"button primary\">Sign in</button></form><p class=\"muted\">Your server administrator manages local accounts.</p>"
    );
    let policy: String = s
        .store
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT value FROM settings WHERE key='kagnode_login'",
            [],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| "true".into());
    let provider = if policy == "true" {
        "<a data-core-login-provider href=\"/auth/kagnode/start\"><span data-core-icon=\"account\"></span>Continue with KagNode</a>"
    } else {
        ""
    };
    let content = crate::core::template(
        "login-frame",
        &[
            ("product", "KagNode. Proxy"),
            ("heading", "Sign in"),
            ("description", "Manage your proxy servers."),
        ],
        &[("content", &form), ("provider", provider)],
    );
    let mut response = Html(shell("Sign in", None, &content)).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!(
            "kn_proxy_login={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=600{}",
            if s.origin.starts_with("https:") {
                "; Secure"
            } else {
                ""
            }
        )
        .parse()
        .unwrap(),
    );
    response
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    email: String,
    password: String,
    #[serde(default, rename = "_csrf")]
    csrf: String,
}
async fn do_login(s: App, h: HeaderMap, input: Login) -> Api<Response> {
    ensure!(
        input.email.len() <= 254 && input.password.len() <= 256,
        "Email or password is incorrect"
    );
    ensure!(
        h.get("origin").and_then(|v| v.to_str().ok()) == Some(s.origin.as_str()),
        "Sign-in origin mismatch"
    );
    let given = if input.csrf.is_empty() {
        h.get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    } else {
        &input.csrf
    };
    ensure!(
        auth::cookie(&h, "kn_proxy_login").is_some_and(|v| v == given) && given.len() == 64,
        "Reload the sign-in page before continuing"
    );
    {
        let mut rates = s.rates.lock().unwrap();
        rates.retain(|_, (t, _)| now() - *t < 60);
        ensure!(rates.len() < 4096, "Sign-in temporarily busy");
        let all = rates.entry("all".into()).or_insert((now(), 0));
        all.1 += 1;
        ensure!(all.1 <= 30, "Sign-in temporarily busy; wait a minute");
        let key = digest(input.email.trim().to_lowercase());
        let count = rates.entry(key).or_insert((now(), 0));
        count.1 += 1;
        ensure!(count.1 <= 8, "Too many sign-in attempts; wait a minute");
    }
    let _permit = s
        .hashes
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("Sign-in busy; try again shortly"))?;
    let store = s.store.clone();
    let result = tokio::task::spawn_blocking(move || {
        auth::verify_password(&store, &input.email, &input.password)
    })
    .await
    .map_err(|_| anyhow::anyhow!("Sign-in unavailable"))??;
    complete_password(&s, &result)
}
async fn login_form(State(s): State<App>, h: HeaderMap, Form(input): Form<Login>) -> Api<Response> {
    let email = input.email.chars().take(254).collect::<String>();
    match do_login(s.clone(), h, input).await {
        Ok(response) => Ok(response),
        Err(error) => {
            let mut response = render_login(&s, Some((&error.1, &email)));
            *response.status_mut() = error.0;
            Ok(response)
        }
    }
}
async fn login_api(State(s): State<App>, h: HeaderMap, Json(input): Json<Login>) -> Api<Response> {
    do_login(s, h, input).await
}
async fn session(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    Ok(Json(
        json!({"user":u,"version":crate::VERSION,"core":"5.0.9"}),
    ))
}
#[derive(Deserialize)]
struct CsrfForm {
    #[serde(rename = "_csrf")]
    csrf: String,
}
async fn logout(
    State(s): State<App>,
    mut h: HeaderMap,
    Form(input): Form<CsrfForm>,
) -> Api<Response> {
    h.insert(
        "x-csrf-token",
        input
            .csrf
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CSRF token"))?,
    );
    let u = user(&s, &h, true)?;
    if let Some(token) = auth::cookie(&h, "kn_proxy") {
        s.store
            .db
            .lock()
            .unwrap()
            .execute("DELETE FROM sessions WHERE token=?", [digest(token)])?;
    }
    s.store.audit(&u.id, "account.logout", &u.id, json!({}))?;
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        "kn_proxy=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            .parse()
            .unwrap(),
    );
    Ok(response)
}
async fn servers(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    Ok(Json(s.store.servers(&u.id, &u.role)?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    name: String,
}
async fn enrollment(
    State(s): State<App>,
    h: HeaderMap,
    Json(input): Json<Enrollment>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    ensure!(
        !input.name.trim().is_empty() && input.name.len() <= 80,
        "Use a server name up to 80 characters"
    );
    let token = random();
    s.store.db.lock().unwrap().execute(
        "INSERT INTO enrollment(token,name,expires) VALUES(?,?,?)",
        params![digest(&token), input.name, now() + 600],
    )?;
    s.store.audit(
        &u.id,
        "agent.enrollment.create",
        "",
        json!({"name":input.name}),
    )?;
    Ok(Json(
        json!({"token":token,"expires":now()+600,"controller":s.origin,"ca_fingerprint":crate::digest(std::fs::read(s.store.root.join("pki/ca.pem"))?)}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollAgent {
    token: String,
    csr: String,
}
async fn enroll_agent(State(s): State<App>, Json(input): Json<EnrollAgent>) -> Api<Json<Value>> {
    ensure!(
        input.token.len() == 64 && input.csr.len() <= 16384,
        "Invalid enrollment request"
    );
    let key = digest(&input.token);
    let name = {
        let db = s.store.db.lock().unwrap();
        let name: String = db
            .query_row(
                "SELECT name FROM enrollment WHERE token=? AND used=0 AND expires>?",
                params![key, now()],
                |r| r.get(0),
            )
            .map_err(|_| anyhow::anyhow!("Enrollment expired or already used"))?;
        ensure!(
            db.execute(
                "UPDATE enrollment SET used=1 WHERE token=? AND used=0",
                [&key]
            )? == 1,
            "Enrollment already used"
        );
        name
    };
    let (cert, fingerprint) = crate::tls::issue_agent(&s.store.root, &input.csr).await?;
    let id = random();
    s.store.db.lock().unwrap().execute(
        "INSERT INTO servers(id,name,fingerprint) VALUES(?,?,?)",
        params![id, name, fingerprint],
    )?;
    s.store.audit(
        "agent",
        "agent.enroll",
        &id,
        json!({"fingerprint":fingerprint}),
    )?;
    Ok(Json(
        json!({"id":id,"certificate":cert,"ca":std::fs::read_to_string(s.store.root.join("pki/ca.pem"))?,"fleet_url":s.fleet_url}),
    ))
}
async fn revoke(State(s): State<App>, h: HeaderMap, Path(id): Path<String>) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    ensure!(
        s.store
            .db
            .lock()
            .unwrap()
            .execute("UPDATE servers SET revoked=1 WHERE id=?", [&id])?
            == 1,
        "Server not found"
    );
    s.store.audit(&u.id, "agent.revoke", &id, json!({}))?;
    Ok(Json(
        json!({"revoked":true,"traffic":"Existing traffic remains on its last working configuration"}),
    ))
}
async fn resources(State(s): State<App>, h: HeaderMap, Path(id): Path<String>) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    allowed(&s, &u, &id, false, false)?;
    Ok(Json(s.store.resources(&id)?))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveResource {
    name: String,
    resource: Resource,
    id: Option<String>,
    #[serde(default)]
    revision: i64,
}
async fn save_resource(
    State(s): State<App>,
    h: HeaderMap,
    Path(server): Path<String>,
    Json(input): Json<SaveResource>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    allowed(&s, &u, &server, true, false)?;
    let id = s.store.save_resource(
        &u.id,
        &server,
        &input.name,
        &input.resource,
        input.id.as_deref(),
        input.revision,
    )?;
    Ok(Json(json!({"id":id,"state":"draft"})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Key {
    request_key: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Publication {
    request_key: String,
    #[serde(default)]
    review_sha256: Option<String>,
    revisions: std::collections::BTreeMap<String, i64>,
}
async fn publish(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(key): Json<Publication>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    allowed(&s, &u, &id, true, false)?;
    let job = s.store.queue_publication(
        &u.id,
        &id,
        &key.request_key,
        &key.revisions,
        key.review_sha256.as_deref(),
    )?;
    Ok(Json(json!({"job":job,"state":"queued"})))
}
async fn publication_review(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    allowed(&s, &u, &id, false, false)?;
    Ok(Json(s.store.publication_review(&id)?))
}
async fn resource_history(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    let server: String = s
        .store
        .db
        .lock()
        .unwrap()
        .query_row("SELECT server FROM resources WHERE id=?", [&id], |r| {
            r.get(0)
        })
        .map_err(|_| anyhow::anyhow!("Resource unavailable"))?;
    allowed(&s, &u, &server, false, false)?;
    Ok(Json(s.store.resource_history(&id)?))
}
async fn retired_resources(
    State(s): State<App>,
    h: HeaderMap,
    Path(server): Path<String>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    allowed(&s, &u, &server, false, false)?;
    let db = s.store.db.lock().unwrap();
    let mut q=db.prepare("SELECT id,name,kind,settings,revision,published FROM resources WHERE server=? AND deleted=1 ORDER BY name LIMIT 200")?;
    let rows=q.query_map([server],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"kind":r.get::<_,String>(2)?,"settings":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(Value::Null),"revision":r.get::<_,i64>(4)?,"published":r.get::<_,i64>(5)?,"deleted":true})))?.collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(Json(json!(rows)))
}
async fn restore_resource(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Value>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    let server: String = s
        .store
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT server FROM resources WHERE id=? AND deleted=1",
            [&id],
            |r| r.get(0),
        )
        .map_err(|_| anyhow::anyhow!("Retired resource unavailable"))?;
    allowed(&s, &u, &server, true, false)?;
    let revision = input["revision"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("Provide current revision"))?;
    let mut db = s.store.db.lock().unwrap();
    let tx = db.transaction()?;
    ensure!(tx.execute("UPDATE resources SET deleted=0,revision=revision+1 WHERE id=? AND revision=? AND deleted=1",params![id,revision])?==1,"conflict: resource changed; reload before restoring");
    tx.execute("INSERT INTO revisions(resource,revision,settings,actor,created)SELECT id,revision,settings,?,? FROM resources WHERE id=?",params![u.id,now(),id])?;
    tx.execute(
        "INSERT INTO audit(actor,action,target,detail,created)VALUES(?,?,?,?,?)",
        params![
            u.id,
            "resource.restore",
            id,
            json!({"revision":revision+1}).to_string(),
            now()
        ],
    )?;
    tx.commit()?;
    Ok(Json(json!({"id":id,"state":"draft","revision":revision+1})))
}
async fn remove_resource(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Value>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    let server: String = s
        .store
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT server FROM resources WHERE id=? AND deleted=0",
            [&id],
            |r| r.get(0),
        )
        .map_err(|_| anyhow::anyhow!("Resource unavailable"))?;
    allowed(&s, &u, &server, true, false)?;
    let revision = input["revision"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("Provide current revision"))?;
    ensure!(s.store.db.lock().unwrap().execute("UPDATE resources SET deleted=1,revision=revision+1 WHERE id=? AND revision=? AND deleted=0",params![id,revision])?==1,"conflict: resource changed");
    s.store
        .audit(&u.id, "resource.retire", &id, json!({"revision":revision}))?;
    Ok(Json(
        json!({"retired":true,"message":"Publish this server to remove the active route"}),
    ))
}
async fn jobs(State(s): State<App>, h: HeaderMap, Path(id): Path<String>) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    allowed(&s, &u, &id, false, false)?;
    let db = s.store.db.lock().unwrap();
    let mut q=db.prepare("SELECT id,kind,state,result,created,updated FROM jobs WHERE server=? ORDER BY rowid DESC LIMIT 100")?;
    let rows=q.query_map([id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"state":r.get::<_,String>(2)?,"result":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(json!({})),"created":r.get::<_,i64>(4)?,"updated":r.get::<_,i64>(5)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(Json(json!(rows)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageRequest {
    names: Vec<String>,
    request_key: String,
}
async fn package_plan(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<PackageRequest>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    allowed(&s, &u, &id, true, true)?;
    ensure!(
        !input.names.is_empty()
            && input.names.len() <= 32
            && input.names.iter().all(|n| crate::packages::valid_name(n)),
        "Choose exact package names"
    );
    let job = s.store.enqueue(
        &u.id,
        &id,
        "package_preview",
        json!({"names":input.names}),
        &input.request_key,
    )?;
    Ok(Json(json!({"job":job,"state":"queued"})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyPackage {
    preview_job: String,
    confirmation: String,
    request_key: String,
}
async fn package_apply(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ApplyPackage>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    auth::recent(&u)?;
    allowed(&s, &u, &id, true, true)?;
    let result:String=s.store.db.lock().unwrap().query_row("SELECT result FROM jobs WHERE id=? AND server=? AND actor=? AND kind='package_preview' AND state='completed' AND updated>?",params![input.preview_job,id,u.id,now()-300],|r|r.get(0)).map_err(|_|anyhow::anyhow!("Obtain a fresh package preview"))?;
    let result: Value = serde_json::from_str(&result)?;
    let plan: crate::packages::RemovalPlan = serde_json::from_value(result["result"].clone())?;
    ensure!(
        plan.confirmation == input.confirmation && plan.blockers.is_empty(),
        "Removal is blocked or the preview changed"
    );
    let job = s.store.enqueue(
        &u.id,
        &id,
        "package_remove",
        json!({"plan":plan}),
        &input.request_key,
    )?;
    s.store.audit(
        &u.id,
        "packages.remove.queued",
        &id,
        json!({"job":job,"preview":input.preview_job}),
    )?;
    Ok(Json(json!({"job":job,"state":"queued"})))
}
async fn cancel_job(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    let server: String =
        s.store
            .db
            .lock()
            .unwrap()
            .query_row("SELECT server FROM jobs WHERE id=?", [&id], |r| r.get(0))?;
    allowed(&s, &u, &server, true, false)?;
    ensure!(
        s.store.db.lock().unwrap().execute(
            "UPDATE jobs SET state='cancelled',updated=? WHERE id=? AND state='queued'",
            params![now(), id]
        )? == 1,
        "Only unsent queued jobs may be cancelled"
    );
    Ok(Json(json!({"cancelled":true})))
}
async fn inspect_server(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Key>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    allowed(&s, &u, &id, false, false)?;
    let job = s
        .store
        .enqueue(&u.id, &id, "status", json!({}), &input.request_key)?;
    Ok(Json(json!({"job":job,"state":"queued"})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveJob {
    inspection: String,
    confirmation: String,
    reason: String,
}
async fn resolve_job(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ResolveJob>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    ensure!(
        input.confirmation == id && (20..=1000).contains(&input.reason.trim().len()),
        "Confirm the full operation ID and explain the inspected outcome (20–1000 characters)"
    );
    let server: String = s.store.db.lock().unwrap().query_row(
        "SELECT server FROM jobs WHERE id=? AND state='uncertain'",
        [&id],
        |r| r.get(0),
    )?;
    allowed(&s, &u, &server, true, true)?;
    let mut db = s.store.db.lock().unwrap();
    let tx = db.transaction()?;
    let (updated, original): (i64, String) = tx.query_row(
        "SELECT updated,result FROM jobs WHERE id=? AND server=? AND state='uncertain'",
        params![id, server],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let inspected: String = tx.query_row(
        "SELECT result FROM jobs WHERE id=? AND server=? AND kind='status' AND state='completed' AND updated>=? AND updated>=?",
        params![input.inspection,server,updated,now()-60], |r|r.get(0))
        .map_err(|_|anyhow::anyhow!("Inspect the connected server again before resolving its hold"))?;
    let proof: Value = serde_json::from_str(&inspected)?;
    ensure!(
        proof["state"] == "completed"
            && proof["result"]["pending"] == false
            && proof["result"]["package_recovery_required"] == false,
        "The node still has an unresolved native journal. Reconcile it locally before clearing this hold"
    );
    let detail = json!({"inspection":input.inspection,"reason":input.reason.trim(),"original_outcome":serde_json::from_str::<Value>(&original)?,"state":"failed","resolved_by":u.id,"replayed":false});
    ensure!(
        tx.execute(
            "UPDATE jobs SET state='failed',result=?,updated=? WHERE id=? AND state='uncertain'",
            params![detail.to_string(), now(), id]
        )? == 1,
        "conflict: operation changed"
    );
    tx.execute(
        "INSERT INTO audit(actor,action,target,detail,created)VALUES(?,?,?,?,?)",
        params![
            u.id,
            "job.recovery_acknowledged",
            id,
            detail.to_string(),
            now()
        ],
    )?;
    tx.commit()?;
    Ok(Json(
        json!({"resolved":true,"replayed":false,"message":"Inspection recorded. The previous operation was not replayed; review drafts before any new publication."}),
    ))
}
async fn audit(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    admin(&u)?;
    let db = s.store.db.lock().unwrap();
    let mut q =
        db.prepare("SELECT actor,action,target,created FROM audit ORDER BY id DESC LIMIT 200")?;
    let out=q.query_map([],|r|Ok(json!({"actor":r.get::<_,String>(0)?,"action":r.get::<_,String>(1)?,"target":r.get::<_,String>(2)?,"created":r.get::<_,i64>(3)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(Json(json!(out)))
}
async fn users(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    admin(&u)?;
    let db = s.store.db.lock().unwrap();
    let mut q=db.prepare("SELECT id,email,name,role,disabled,subject IS NOT NULL,mfa!='' FROM users ORDER BY email LIMIT 1000")?;
    let rows=q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"email":r.get::<_,String>(1)?,"name":r.get::<_,String>(2)?,"role":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(Value::Null),"disabled":r.get::<_,bool>(4)?,"kagnode_linked":r.get::<_,bool>(5)?,"mfa_enabled":r.get::<_,bool>(6)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(Json(json!(rows)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewUser {
    email: String,
    name: String,
    password: String,
    role: crate::domain::Role,
}
async fn create_user(
    State(s): State<App>,
    h: HeaderMap,
    Json(input): Json<NewUser>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    ensure!(
        input.role != crate::domain::Role::Owner,
        "Owner transfer requires the explicit recovery procedure"
    );
    ensure!(
        input.role != crate::domain::Role::Administrator || u.role == crate::domain::Role::Owner,
        "Only the owner can create administrators"
    );
    ensure!(
        s.store
            .db
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))?
            < 1000,
        "Account limit reached"
    );
    let permit = s
        .hashes
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("Account creation busy; try again shortly"))?;
    let store = s.store.clone();
    let id = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth::create_user(
            &store,
            &input.email,
            &input.name,
            &input.password,
            input.role,
        )
    })
    .await
    .map_err(|_| anyhow::anyhow!("Account creation unavailable"))??;
    s.store
        .audit(&u.id, "account.create.local", &id, json!({}))?;
    Ok(Json(json!({"id":id})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserChange {
    role: crate::domain::Role,
    disabled: bool,
}
async fn update_user(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<UserChange>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    let mut db = s.store.db.lock().unwrap();
    let tx = db.transaction()?;
    let old: String = tx.query_row("SELECT role FROM users WHERE id=?", [&id], |r| r.get(0))?;
    let old: crate::domain::Role = serde_json::from_str(&old)?;
    ensure!(
        id != u.id,
        "Change another account; self-demotion and self-disabling are blocked"
    );
    ensure!(
        old != crate::domain::Role::Owner && input.role != crate::domain::Role::Owner,
        "Owner transfer requires the explicit recovery procedure"
    );
    ensure!(
        (old != crate::domain::Role::Administrator
            && input.role != crate::domain::Role::Administrator)
            || u.role == crate::domain::Role::Owner,
        "Only the owner can change administrators"
    );
    tx.execute(
        "UPDATE users SET role=?,disabled=? WHERE id=?",
        params![serde_json::to_string(&input.role)?, input.disabled, id],
    )?;
    tx.execute("DELETE FROM sessions WHERE user=?", [&id])?;
    tx.execute(
        "UPDATE jobs SET state='cancelled',updated=? WHERE actor=? AND state='queued'",
        params![now(), id],
    )?;
    tx.commit()?;
    drop(db);
    s.store.audit(
        &u.id,
        "account.permissions",
        &id,
        json!({"role":input.role,"disabled":input.disabled}),
    )?;
    Ok(Json(json!({"updated":true,"sessions_revoked":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    role: crate::domain::Role,
    maintenance: bool,
}
async fn grant_server(
    State(s): State<App>,
    h: HeaderMap,
    Path((id, server)): Path<(String, String)>,
    Json(input): Json<Grant>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    ensure!(
        matches!(
            input.role,
            crate::domain::Role::Viewer | crate::domain::Role::Maintainer
        ),
        "Choose a node-scoped viewer or maintainer role"
    );
    ensure!(
        !input.maintenance || input.role == crate::domain::Role::Maintainer,
        "Host maintenance requires node maintainer permission"
    );
    allowed(&s, &u, &server, true, false)?;
    let mut db = s.store.db.lock().unwrap();
    let tx = db.transaction()?;
    let role: String = tx.query_row(
        "SELECT role FROM users WHERE id=? AND disabled=0",
        [&id],
        |r| r.get(0),
    )?;
    ensure!(
        !serde_json::from_str::<crate::domain::Role>(&role)?.administer(),
        "Global administrators already have fleet permission"
    );
    let role = if input.role == crate::domain::Role::Maintainer {
        "maintainer"
    } else {
        "viewer"
    };
    tx.execute("INSERT INTO server_permissions(user,server,role,maintenance) VALUES(?,?,?,?) ON CONFLICT(user,server) DO UPDATE SET role=excluded.role,maintenance=excluded.maintenance",params![id,server,role,input.maintenance])?;
    tx.execute(
        "UPDATE jobs SET state='cancelled',updated=? WHERE actor=? AND server=? AND state='queued'",
        params![now(), id, server],
    )?;
    tx.commit()?;
    drop(db);
    s.store.audit(
        &u.id,
        "server.permissions",
        &server,
        json!({"user":id,"role":role,"maintenance":input.maintenance}),
    )?;
    Ok(Json(json!({"updated":true})))
}
async fn revoke_grant(
    State(s): State<App>,
    h: HeaderMap,
    Path((id, server)): Path<(String, String)>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    allowed(&s, &u, &server, true, false)?;
    let mut db = s.store.db.lock().unwrap();
    let tx = db.transaction()?;
    tx.execute(
        "DELETE FROM server_permissions WHERE user=? AND server=?",
        params![id, server],
    )?;
    tx.execute(
        "UPDATE jobs SET state='cancelled',updated=? WHERE actor=? AND server=? AND state='queued'",
        params![now(), id, server],
    )?;
    tx.commit()?;
    drop(db);
    s.store.audit(
        &u.id,
        "server.permissions.revoke",
        &server,
        json!({"user":id}),
    )?;
    Ok(Json(
        json!({"revoked":true,"queued_operations_cancelled":true}),
    ))
}
fn peer(s: &App, p: &crate::tls::Peer) -> Api<String> {
    ensure!(!p.fingerprint.is_empty(), "Mutual TLS certificate required");
    s.store
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id FROM servers WHERE fingerprint=? AND revoked=0",
            [&p.fingerprint],
            |r| r.get(0),
        )
        .map_err(|_| {
            Error(
                StatusCode::FORBIDDEN,
                "Agent certificate is not enrolled or has been revoked".into(),
            )
        })
}
async fn poll(
    State(s): State<App>,
    Extension(p): Extension<crate::tls::Peer>,
    Json(data): Json<Value>,
) -> Api<Json<Value>> {
    let id = peer(&s, &p)?;
    s.store.heartbeat(&id, &data)?;
    let mut job = s.store.claim(&id)?;
    if job["kind"] == "certificate_upload" {
        job["payload"] = crate::certificates::unseal(&s.store.root, &id, &job["payload"])?;
    }
    Ok(Json(json!({"job":job})))
}
async fn heartbeat(
    State(s): State<App>,
    Extension(p): Extension<crate::tls::Peer>,
    Json(data): Json<Value>,
) -> Api<Json<Value>> {
    let server = peer(&s, &p)?;
    s.store.heartbeat(&server, &data)?;
    Ok(Json(json!({"accepted":true})))
}
async fn job_result(
    State(s): State<App>,
    Extension(p): Extension<crate::tls::Peer>,
    Path(id): Path<String>,
    Json(data): Json<Value>,
) -> Api<Json<Value>> {
    let server = peer(&s, &p)?;
    let lease = data["lease"].as_str().unwrap_or("");
    s.store.acknowledge(&server, &id, lease, &data["outcome"])?;
    Ok(Json(json!({"accepted":true})))
}

pub fn complete_password(s: &App, id: &str) -> Api<Response> {
    let secure = if s.origin.starts_with("https:") {
        "; Secure"
    } else {
        ""
    };
    let mut response = if let Some(token) = crate::mfa::begin(&s.store, id)? {
        let mut r = Redirect::to("/mfa").into_response();
        r.headers_mut().insert(
            header::SET_COOKIE,
            format!("kn_proxy_mfa={token}; HttpOnly; SameSite=Lax; Path=/mfa; Max-Age=300{secure}")
                .parse()
                .unwrap(),
        );
        r
    } else {
        let (token, _) = auth::new_session(&s.store, id)?;
        let mut r = Redirect::to("/").into_response();
        r.headers_mut().insert(
            header::SET_COOKIE,
            format!("kn_proxy={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800{secure}")
                .parse()
                .unwrap(),
        );
        r
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    Ok(response)
}
async fn mfa_page(State(_s): State<App>, h: HeaderMap) -> Api<Response> {
    let token = auth::cookie(&h, "kn_proxy_mfa")
        .ok_or_else(|| anyhow::anyhow!("Verification expired; sign in again"))?;
    ensure!(token.len() == 64, "Verification expired");
    let form = format!(
        "<form method=\"post\" action=\"/mfa\"><input type=\"hidden\" name=\"_csrf\" value=\"{}\"><label>Verification code<input name=\"code\" autocomplete=\"one-time-code\" required maxlength=\"32\" autofocus></label><button class=\"button primary\">Continue</button><a href=\"/login\">Return to sign in</a></form>",
        crate::core::escape(&token)
    );
    let content = crate::core::template(
        "login-frame",
        &[
            ("product", "KagNode. Proxy"),
            ("heading", "Verify it’s you"),
            (
                "description",
                "Enter an authenticator code or an unused recovery code.",
            ),
        ],
        &[("content", &form), ("provider", "")],
    );
    Ok(Html(shell("Verify your account", None, &content)).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MfaInput {
    code: String,
    #[serde(default, rename = "_csrf")]
    csrf: String,
}
async fn mfa_finish(
    State(s): State<App>,
    h: HeaderMap,
    Form(input): Form<MfaInput>,
) -> Api<Response> {
    ensure!(
        h.get("origin").and_then(|v| v.to_str().ok()) == Some(s.origin.as_str()),
        "Unexpected verification origin"
    );
    let token =
        auth::cookie(&h, "kn_proxy_mfa").ok_or_else(|| anyhow::anyhow!("Verification expired"))?;
    ensure!(
        token == input.csrf && token.len() == 64,
        "Reload the verification page"
    );
    let id = crate::mfa::finish(&s.store, &token, &input.code)?;
    let (new, _) = auth::new_session(&s.store, &id)?;
    let mut response = Redirect::to("/").into_response();
    let secure = if s.origin.starts_with("https:") {
        "; Secure"
    } else {
        ""
    };
    response.headers_mut().append(
        header::SET_COOKIE,
        format!("kn_proxy={new}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800{secure}")
            .parse()
            .unwrap(),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        format!("kn_proxy_mfa=; HttpOnly; SameSite=Lax; Path=/mfa; Max-Age=0{secure}")
            .parse()
            .unwrap(),
    );
    Ok(response)
}
async fn account(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    let db = s.store.db.lock().unwrap();
    let mfa: String = db.query_row("SELECT mfa FROM users WHERE id=?", [&u.id], |r| r.get(0))?;
    let linked: bool = db.query_row(
        "SELECT subject IS NOT NULL FROM users WHERE id=?",
        [&u.id],
        |r| r.get(0),
    )?;
    let mut value = json!({"user":u,"mfa_enabled":!mfa.is_empty(),"kagnode_linked":linked});
    if u.role.administer() {
        let mut policy = serde_json::Map::new();
        for (k, default) in [("kagnode_login", "true"), ("signup", "false")] {
            let v: String = db
                .query_row("SELECT value FROM settings WHERE key=?", [k], |r| r.get(0))
                .unwrap_or(default.into());
            policy.insert(k.into(), json!(v == "true"));
        }
        value["policy"] = Value::Object(policy);
    }
    Ok(Json(value))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountPolicy {
    kagnode_login: bool,
    signup: bool,
}
async fn account_policy(
    State(s): State<App>,
    h: HeaderMap,
    Json(input): Json<AccountPolicy>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    let mut db = s.store.db.lock().unwrap();
    let tx = db.transaction()?;
    if !input.kagnode_login {
        let password: String =
            tx.query_row("SELECT password FROM users WHERE id=?", [&u.id], |r| {
                r.get(0)
            })?;
        ensure!(
            !password.is_empty(),
            "Set a local recovery credential before disabling KagNode sign-in"
        );
        tx.execute("DELETE FROM oauth", [])?;
    }
    for (k, v) in [
        ("kagnode_login", input.kagnode_login),
        ("signup", input.signup),
    ] {
        tx.execute(
            "INSERT INTO settings VALUES(?,?) ON CONFLICT(key)DO UPDATE SET value=excluded.value",
            params![k, v.to_string()],
        )?;
    }
    tx.commit()?;
    drop(db);
    s.store.audit(
        &u.id,
        "account.policy",
        "",
        json!({"kagnode_login":input.kagnode_login,"signup":input.signup}),
    )?;
    Ok(Json(json!({"saved":true})))
}
async fn mfa_start(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    auth::recent(&u)?;
    let secret = crate::mfa::start_enrollment(&s.store, &u.id)?;
    let uri = format!(
        "otpauth://totp/KagNode%20Proxy%20Manager:{}?secret={secret}&issuer=KagNode%20Proxy%20Manager&algorithm=SHA1&digits=6&period=30",
        percent_encoding::utf8_percent_encode(&u.email, percent_encoding::NON_ALPHANUMERIC)
    );
    Ok(Json(json!({"secret":secret,"uri":uri,"expires":now()+600})))
}
async fn mfa_confirm(
    State(s): State<App>,
    h: HeaderMap,
    Json(input): Json<MfaInput>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    auth::recent(&u)?;
    let recovery = crate::mfa::confirm_enrollment(&s.store, &u.id, &input.code)?;
    Ok(Json(
        json!({"enabled":true,"recovery_codes":recovery,"sign_in_again":true}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueCertificate {
    request: crate::certificates::Request,
    request_key: String,
}
async fn certificate_inventory(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Key>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    allowed(&s, &u, &id, false, false)?;
    let job = s.store.enqueue(
        &u.id,
        &id,
        "certificate_inventory",
        json!({}),
        &input.request_key,
    )?;
    Ok(Json(json!({"job":job,"state":"queued"})))
}
async fn certificate_issue(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<IssueCertificate>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    allowed(&s, &u, &id, true, false)?;
    auth::recent(&u)?;
    input.request.validate()?;
    let job = s.store.enqueue(
        &u.id,
        &id,
        "certificate_issue",
        json!({"request":input.request}),
        &input.request_key,
    )?;
    Ok(Json(json!({"job":job,"state":"queued"})))
}

async fn core_status(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    admin(&u)?;
    let value=crate::core::manager("status".into(),json!({})).await.unwrap_or_else(|_|json!({"enabled":false,"version":crate::core::version(),"message":"Enable reviewed Core management through KagNode Daemon on this server."}));
    Ok(Json(value))
}
async fn core_action(
    State(s): State<App>,
    h: HeaderMap,
    Path(action): Path<String>,
    Json(input): Json<Value>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    let fields: &[&str] = match action.as_str() {
        "check" | "rollback" => &[],
        "apply" => &["release_id"],
        "policy" => &["automatic", "summaries", "channel"],
        _ => return Err(Error(StatusCode::NOT_FOUND, "Unknown Core action".into())),
    };
    ensure!(
        input
            .as_object()
            .is_some_and(|o| o.keys().all(|k| fields.contains(&k.as_str()))),
        "Unexpected Core parameters"
    );
    for name in ["automatic", "summaries"] {
        if let Some(value) = input.get(name) {
            ensure!(value.is_boolean(), "Core policy values must be booleans");
        }
    }
    if let Some(channel) = input.get("channel") {
        ensure!(
            matches!(channel.as_str(), Some("stable" | "beta")),
            "Choose Stable or Beta"
        );
    }
    if action == "apply" {
        ensure!(
            input["release_id"].as_i64().is_some_and(|v| v > 0),
            "Review the available release before applying"
        );
    }
    let value = crate::core::manager(action.clone(), input).await?;
    s.store
        .audit(&u.id, &format!("core.{action}"), "proxy-manager", json!({}))?;
    Ok(Json(value))
}
async fn core_notice(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    let value = crate::core::manager("summary".into(), json!({}))
        .await
        .ok()
        .and_then(|v| crate::core::public_notice(&v))
        .unwrap_or_else(|| json!({"available":false,"notice":null}));
    if let Some(id) = value["notice"]["id"].as_str() {
        let dismissed: bool = s.store.db.lock().unwrap().query_row(
            "SELECT EXISTS(SELECT 1 FROM core_notice_dismissals WHERE user=? AND notice=?)",
            params![u.id, id],
            |r| r.get(0),
        )?;
        if dismissed {
            return Ok(Json(json!({"available":true,"notice":null})));
        }
    }
    Ok(Json(value))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DismissNotice {
    id: String,
}
async fn core_notice_dismiss(
    State(s): State<App>,
    h: HeaderMap,
    Json(input): Json<DismissNotice>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    let value = crate::core::manager("summary".into(), json!({}))
        .await
        .ok()
        .and_then(|v| crate::core::public_notice(&v))
        .ok_or_else(|| anyhow::anyhow!("The update summary is unavailable"))?;
    ensure!(
        value["notice"]["id"] == input.id,
        "The update summary changed; refresh before dismissing"
    );
    s.store.db.lock().unwrap().execute(
        "INSERT OR IGNORE INTO core_notice_dismissals VALUES(?,?,?)",
        params![u.id, input.id, now()],
    )?;
    Ok(Json(json!({"dismissed":true})))
}

async fn engine_capabilities(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let _ = user(&s, &h, false)?;
    Ok(Json(crate::engines::capabilities()))
}
async fn discover_server(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<Key>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    allowed(&s, &u, &id, true, true)?;
    let job = s
        .store
        .enqueue(&u.id, &id, "discovery", json!({}), &input.request_key)?;
    s.store
        .audit(&u.id, "discovery.request", &id, json!({"job":job}))?;
    Ok(Json(json!({"job":job,"state":"queued","read_only":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportReview {
    fingerprint: String,
    selected: Vec<String>,
    request_key: String,
}
async fn review_import(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ImportReview>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    allowed(&s, &u, &id, true, true)?;
    ensure!(
        input.fingerprint.len() == 64
            && input.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
            && !input.selected.is_empty()
            && input.selected.len() <= 32,
        "Select a bounded configuration review"
    );
    let job = s.store.enqueue(
        &u.id,
        &id,
        "import_review",
        json!({"fingerprint":input.fingerprint,"selected":input.selected}),
        &input.request_key,
    )?;
    s.store
        .audit(&u.id, "adoption.review", &id, json!({"job":job}))?;
    Ok(Json(
        json!({"job":job,"state":"queued","traffic_changed":false}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadCertificate {
    upload: crate::certificates::Upload,
    request_key: String,
}
async fn certificate_upload(
    State(s): State<App>,
    h: HeaderMap,
    Path(server): Path<String>,
    Json(input): Json<UploadCertificate>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    allowed(&s, &u, &server, true, true)?;
    input.upload.validate()?;
    let value = serde_json::to_value(&input.upload)?;
    let prior: Option<(String, String, String, String)> = s
        .store
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id,actor,server,payload FROM jobs WHERE request_key=?",
            [&input.request_key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .ok();
    if let Some((job, actor, node, payload)) = prior {
        ensure!(
            actor == u.id
                && node == server
                && crate::certificates::unseal(
                    &s.store.root,
                    &server,
                    &serde_json::from_str::<Value>(&payload)?
                )? == value,
            "Idempotency key belongs to a different upload"
        );
        return Ok(Json(json!({"job":job,"state":"queued"})));
    }
    let sealed = crate::certificates::sealed(&s.store.root, &server, &value)?;
    let job = s.store.enqueue(
        &u.id,
        &server,
        "certificate_upload",
        sealed,
        &input.request_key,
    )?;
    s.store.audit(
        &u.id,
        "certificate.upload",
        &server,
        json!({"id":input.upload.id,"job":job,"private_key":"not_recorded"}),
    )?;
    Ok(Json(
        json!({"job":job,"state":"queued","traffic_changed":false}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnginePreview {
    engine: crate::engines::Engine,
}
async fn engine_preview(
    State(s): State<App>,
    h: HeaderMap,
    Path(server): Path<String>,
    Json(input): Json<EnginePreview>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    allowed(&s, &u, &server, true, true)?;
    let rows = s.store.resources(&server)?;
    let resources = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            Ok((
                r["id"].as_str().unwrap().to_string(),
                serde_json::from_value::<Resource>(r["settings"].clone())?,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let result = crate::engines::render(
        input.engine,
        &resources,
        "/srv/kagnode/proxy-manager/traffic",
    )?;
    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivateCertificate {
    id: String,
    version: String,
    expected_sha256: String,
    request_key: String,
}
async fn certificate_activate(
    State(s): State<App>,
    h: HeaderMap,
    Path(server): Path<String>,
    Json(input): Json<ActivateCertificate>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    allowed(&s, &u, &server, true, true)?;
    crate::domain::ident(&input.id)?;
    crate::domain::ident(&input.version)?;
    let job = s.store.enqueue(
        &u.id,
        &server,
        "certificate_activate",
        json!({"id":input.id,"version":input.version,"expected_sha256":input.expected_sha256}),
        &input.request_key,
    )?;
    s.store.audit(
        &u.id,
        "certificate.activate",
        &server,
        json!({"id":input.id,"job":job}),
    )?;
    Ok(Json(json!({"job":job,"state":"queued"})))
}

fn navigation(user: &User) -> String {
    [("Overview","/","home",false),("Servers","/servers","compute",false),("Reverse proxies","/reverse-proxies","domains",false),("Streams","/streams","networking",false),("Forward proxies","/forward-proxies","delivery",false),("Certificates","/certificates","lock",false),("Packages","/packages","archive",false),("Jobs","/jobs","clock",false),("Discovery","/discovery","search",true),("Audit","/audit","observability",true),("Users and access","/users","community",true),("Account","/account","account",false)].into_iter().filter(|(_,_,_,admin)| !admin || user.role.administer()).map(|(label,url,icon,_)|format!("<a class=\"nav-item\" href=\"{url}\"><span data-core-icon=\"{icon}\"></span><span class=\"nav-label\">{label}</span></a>")).collect()
}
#[derive(Deserialize)]
struct SearchQuery {
    #[serde(default)]
    q: String,
}
async fn search(
    State(s): State<App>,
    h: HeaderMap,
    Query(input): Query<SearchQuery>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    ensure!(
        input.q.len() <= 200 && !input.q.chars().any(char::is_control),
        "Search text must be at most 200 characters"
    );
    let q = input.q.trim().to_lowercase();
    let nodes = s.store.servers(&u.id, &u.role)?;
    let db = s.store.db.lock().unwrap();
    let mut query=db.prepare("SELECT r.id,r.server,r.name,r.kind,s.name FROM resources r JOIN servers s ON s.id=r.server WHERE r.deleted=0 AND s.revoked=0 AND (?1 OR EXISTS(SELECT 1 FROM server_permissions p WHERE p.server=s.id AND p.user=?2 AND p.role IN ('viewer','maintainer'))) AND instr(lower(r.name),?3)>0 ORDER BY r.name LIMIT 30")?;
    let mut results=query.query_map(params![u.role.administer(),u.id,q],|r|{let id:String=r.get(0)?;let server:String=r.get(1)?;let kind:String=r.get(3)?;let path=match kind.as_str(){"stream"=>"streams","forward_proxy"=>"forward-proxies",_=>"reverse-proxies"};Ok(json!({"id":id,"title":r.get::<_,String>(2)?,"description":r.get::<_,String>(4)?,"type":"Configuration","url":format!("/{path}?server={server}")}))})?.collect::<std::result::Result<Vec<_>,_>>()?;
    for node in nodes
        .as_array()
        .unwrap()
        .iter()
        .filter(|n| n["name"].as_str().unwrap_or("").to_lowercase().contains(&q))
        .take(10)
    {
        results.push(json!({"id":node["id"],"title":node["name"],"description":"Managed server","type":"Server","url":format!("/reverse-proxies?server={}",node["id"].as_str().unwrap())}));
    }
    Ok(Json(
        json!({"results":results,"moreUrl":format!("/search?q={}",percent_encoding::utf8_percent_encode(&input.q,percent_encoding::NON_ALPHANUMERIC))}),
    ))
}
async fn overview(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    let db = s.store.db.lock().unwrap();
    let drafts:i64=db.query_row("SELECT COUNT(*) FROM resources r JOIN servers s ON s.id=r.server WHERE s.revoked=0 AND ((r.deleted=0 AND r.revision!=r.published) OR (r.deleted=1 AND r.published>0)) AND (?1 OR EXISTS(SELECT 1 FROM server_permissions p WHERE p.server=s.id AND p.user=?2 AND p.role IN ('viewer','maintainer')))",params![u.role.administer(),u.id],|r|r.get(0))?;
    let mut query=db.prepare("SELECT j.id,j.kind,j.state,j.updated,s.name FROM jobs j JOIN servers s ON s.id=j.server WHERE s.revoked=0 AND (?1 OR EXISTS(SELECT 1 FROM server_permissions p WHERE p.server=s.id AND p.user=?2 AND p.role IN ('viewer','maintainer'))) ORDER BY j.updated DESC LIMIT 10")?;
    let jobs=query.query_map(params![u.role.administer(),u.id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"kind":r.get::<_,String>(1)?,"state":r.get::<_,String>(2)?,"updated":r.get::<_,i64>(3)?,"server":r.get::<_,String>(4)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
    Ok(Json(json!({"draft_changes":drafts,"recent_jobs":jobs})))
}

async fn application_status(State(s): State<App>, h: HeaderMap) -> Api<Json<Value>> {
    let u = user(&s, &h, false)?;
    admin(&u)?;
    Ok(Json(crate::updates::request("state", json!({})).await?))
}
async fn application_action(
    State(s): State<App>,
    h: HeaderMap,
    Path(action): Path<String>,
    Json(input): Json<Value>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    admin(&u)?;
    auth::recent(&u)?;
    let fields: &[&str] = match action.as_str() {
        "check" => &[],
        "apply" => &["release_id"],
        "policy" => &["channel", "mode", "window", "revision"],
        _ => return Err(Error(StatusCode::NOT_FOUND, "Unknown update action".into())),
    };
    ensure!(
        input
            .as_object()
            .is_some_and(|v| v.keys().all(|key| fields.contains(&key.as_str()))),
        "Unexpected update parameters"
    );
    let value = crate::updates::request(&action, input).await?;
    s.store.audit(
        &u.id,
        &format!("application.update.{action}"),
        "proxy-manager",
        json!({}),
    )?;
    Ok(Json(value))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeInput {
    request_key: String,
    revision: i64,
}
async fn probe_upstreams(
    State(s): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ProbeInput>,
) -> Api<Json<Value>> {
    let u = user(&s, &h, true)?;
    let server: String = s
        .store
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT server FROM resources WHERE id=? AND deleted=0",
            [&id],
            |r| r.get(0),
        )
        .map_err(|_| anyhow::anyhow!("Resource unavailable"))?;
    allowed(&s, &u, &server, true, false)?;
    let job =
        s.store
            .queue_upstream_probe(&u.id, &server, &id, input.revision, &input.request_key)?;
    Ok(Json(
        json!({"job":job,"state":"queued","read_only":true,"application_health_verified":false}),
    ))
}
