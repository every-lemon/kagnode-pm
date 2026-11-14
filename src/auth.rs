use crate::{digest, domain::Role, now, random, store::Store};
use anyhow::{Result, ensure};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::http::HeaderMap;
use rusqlite::params;
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct User {
    pub id: String,
    pub email: String,
    pub name: String,
    pub photo: String,
    pub role: Role,
    pub csrf: String,
    pub authenticated: i64,
}
pub fn password_hash(password: &str) -> Result<String> {
    ensure!(
        (14..=256).contains(&password.len()),
        "Use a password of 14–256 characters"
    );
    let mut salt = [0; 16];
    getrandom::fill(&mut salt)?;
    let salt = SaltString::encode_b64(&salt).map_err(|_| anyhow::anyhow!("Salt error"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| anyhow::anyhow!("Password hashing failed"))?
        .to_string())
}
pub fn create_user(
    store: &Store,
    email: &str,
    name: &str,
    password: &str,
    role: Role,
) -> Result<String> {
    let email = email.trim().to_lowercase();
    ensure!(
        email.len() <= 254
            && email.contains('@')
            && !email.contains(['\n', '\r', ' '])
            && !name.trim().is_empty()
            && name.len() <= 80,
        "Use a valid email and name"
    );
    let hash = password_hash(password)?;
    let id = random();
    store.db.lock().unwrap().execute(
        "INSERT INTO users(id,email,name,password,role) VALUES(?,?,?,?,?)",
        params![id, email, name.trim(), hash, serde_json::to_string(&role)?],
    )?;
    store.audit(&id, "account.create", &id, serde_json::json!({}))?;
    Ok(id)
}
pub fn verify_password(store: &Store, email: &str, password: &str) -> Result<String> {
    let db = store.db.lock().unwrap();
    let before = db.query_row(
        "SELECT id,password FROM users WHERE email=? AND disabled=0",
        [email.trim().to_lowercase()],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    );
    drop(db);
    let dummy = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$7RZyuQskYhOy0HFBmRrIGPzx5gZVQ9EGxCbn8kDzED8";
    let encoded = before.as_ref().map_or(
        dummy,
        |(_, h)| if h.is_empty() { dummy } else { h.as_str() },
    );
    let hash = PasswordHash::new(encoded).map_err(|_| anyhow::anyhow!("Sign-in unavailable"))?;
    let valid = password.len() <= 256
        && Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok();
    ensure!(valid && before.is_ok(), "Email or password is incorrect");
    let (id, expected) = before?;
    let db = store.db.lock().unwrap();
    let current: String = db.query_row(
        "SELECT password FROM users WHERE id=? AND disabled=0",
        [&id],
        |r| r.get(0),
    )?;
    ensure!(expected == current, "Account changed; sign in again");
    drop(db);
    Ok(id)
}
pub fn new_session(store: &Store, id: &str) -> Result<(String, User)> {
    let token = random();
    let csrf = random();
    let db = store.db.lock().unwrap();
    db.execute("DELETE FROM sessions WHERE expires<?", [now()])?;
    db.execute(
        "INSERT INTO sessions VALUES(?,?,?,?,?)",
        params![digest(&token), id, csrf, now() + 28800, now()],
    )?;
    drop(db);
    let mut headers = HeaderMap::new();
    headers.insert("cookie", format!("kn_proxy={token}").parse()?);
    let user =
        session(store, &headers)?.ok_or_else(|| anyhow::anyhow!("Session creation failed"))?;
    Ok((token, user))
}
pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| {
            let (k, v) = s.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}
pub fn session(store: &Store, headers: &HeaderMap) -> Result<Option<User>> {
    let Some(token) = cookie(headers, "kn_proxy") else {
        return Ok(None);
    };
    if token.len() != 64 {
        return Ok(None);
    }
    let db = store.db.lock().unwrap();
    let row=db.query_row("SELECT u.id,u.email,u.name,u.role,s.csrf,s.authenticated,u.photo FROM sessions s JOIN users u ON u.id=s.user WHERE s.token=? AND s.expires>? AND u.disabled=0",params![digest(token),now()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?,r.get::<_,String>(6)?)));
    match row {
        Ok((id, email, name, role, csrf, authenticated, photo)) => Ok(Some(User {
            id,
            email,
            name,
            photo,
            role: serde_json::from_str(&role)?,
            csrf,
            authenticated,
        })),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}
pub fn csrf(user: &User, headers: &HeaderMap, origin: &str) -> Result<()> {
    use subtle::ConstantTimeEq;
    let token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    ensure!(
        bool::from(user.csrf.as_bytes().ct_eq(token.as_bytes())),
        "Invalid CSRF token"
    );
    if let Some(actual) = headers.get("origin") {
        ensure!(actual.to_str()? == origin, "Unexpected request origin");
    }
    Ok(())
}
pub fn recent(user: &User) -> Result<()> {
    ensure!(
        now() - user.authenticated <= 600,
        "Sign in again before this administrative action"
    );
    Ok(())
}

pub fn login(store: &Store, email: &str, password: &str) -> Result<(String, User)> {
    let id = verify_password(store, email, password)?;
    anyhow::ensure!(
        crate::mfa::begin(store, &id)?.is_none(),
        "MFA verification is required"
    );
    new_session(store, &id)
}
