use crate::{digest, now, random, store::Store};
use anyhow::{Result, ensure};
use hmac::{Hmac, Mac};
use rusqlite::params;
use sha1::Sha1;
pub fn schema(store: &Store) -> Result<()> {
    store.db.lock().unwrap().execute_batch("CREATE TABLE IF NOT EXISTS mfa_attempts(token TEXT PRIMARY KEY,user TEXT NOT NULL,expires INTEGER NOT NULL,tries INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS mfa_pending(user TEXT PRIMARY KEY,secret TEXT NOT NULL,expires INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS mfa_state(user TEXT PRIMARY KEY,last_step INTEGER NOT NULL,recovery TEXT NOT NULL DEFAULT '[]');")?;
    Ok(())
}
pub fn encode(bytes: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut bits, mut value) = (0, 0u32);
    for b in bytes {
        value = (value << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((value >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((value << (5 - bits)) & 31) as usize] as char);
    }
    out
}
fn decode(secret: &str) -> Result<Vec<u8>> {
    let mut out = vec![];
    let (mut bits, mut value) = (0, 0u32);
    for b in secret.bytes() {
        let n = match b {
            b'A'..=b'Z' => b - b'A',
            b'2'..=b'7' => b - b'2' + 26,
            _ => anyhow::bail!("Invalid MFA secret"),
        };
        value = (value << 5) | n as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((value >> bits) as u8);
        }
    }
    Ok(out)
}
pub fn code(secret: &str, step: i64) -> Result<String> {
    ensure!(step >= 0, "Invalid MFA clock");
    let key = zeroize::Zeroizing::new(decode(secret)?);
    let mut mac = Hmac::<Sha1>::new_from_slice(&key)?;
    mac.update(&(step as u64).to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let index = (hash[19] & 15) as usize;
    let value = u32::from_be_bytes(hash[index..index + 4].try_into()?) & 0x7fff_ffff;
    Ok(format!("{:06}", value % 1_000_000))
}
fn matched(secret: &str, input: &str, clock: i64, last: i64) -> Result<i64> {
    use subtle::ConstantTimeEq;
    ensure!(
        input.len() == 6 && input.bytes().all(|b| b.is_ascii_digit()),
        "Enter the six-digit verification code"
    );
    for step in [clock / 30 - 1, clock / 30, clock / 30 + 1] {
        if step > last && bool::from(code(secret, step)?.as_bytes().ct_eq(input.as_bytes())) {
            return Ok(step);
        }
    }
    anyhow::bail!("Verification code is incorrect, expired or already used")
}
pub fn begin(store: &Store, user: &str) -> Result<Option<String>> {
    schema(store)?;
    let db = store.db.lock().unwrap();
    let enabled: String = db.query_row(
        "SELECT mfa FROM users WHERE id=? AND disabled=0",
        [user],
        |r| r.get(0),
    )?;
    if enabled.is_empty() {
        return Ok(None);
    }
    let token = random();
    db.execute("DELETE FROM mfa_attempts WHERE expires<?", [now()])?;
    db.execute(
        "INSERT INTO mfa_attempts(token,user,expires)VALUES(?,?,?)",
        params![digest(&token), user, now() + 300],
    )?;
    Ok(Some(token))
}
pub fn finish(store: &Store, token: &str, input: &str) -> Result<String> {
    schema(store)?;
    let mut db = store.db.lock().unwrap();
    let tx = db.transaction()?;
    let (user, tries): (String, u32) = tx.query_row(
        "SELECT user,tries FROM mfa_attempts WHERE token=? AND expires>?",
        params![digest(token), now()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(tries < 5, "Verification attempt expired; sign in again");
    tx.execute(
        "UPDATE mfa_attempts SET tries=tries+1 WHERE token=?",
        [digest(token)],
    )?;
    let(secret,last,recovery):(String,i64,String)=tx.query_row("SELECT u.mfa,COALESCE(s.last_step,-1),COALESCE(s.recovery,'[]') FROM users u LEFT JOIN mfa_state s ON s.user=u.id WHERE u.id=? AND u.disabled=0",[&user],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
    let mut codes: Vec<String> = serde_json::from_str(&recovery)?;
    let valid = if input.len() == 32 {
        let hash = digest(input);
        if let Some(index) = codes.iter().position(|c| c == &hash) {
            codes.remove(index);
            Ok(last)
        } else {
            Err(anyhow::anyhow!(
                "Recovery code is incorrect or already used"
            ))
        }
    } else {
        matched(&secret, input, now(), last)
    };
    match valid {
        Ok(step) => {
            tx.execute("INSERT INTO mfa_state(user,last_step,recovery)VALUES(?,?,?) ON CONFLICT(user)DO UPDATE SET last_step=excluded.last_step,recovery=excluded.recovery",params![user,step,serde_json::to_string(&codes)?])?;
            tx.execute("DELETE FROM mfa_attempts WHERE user=?", [&user])?;
            tx.commit()?;
            Ok(user)
        }
        Err(error) => {
            tx.commit()?;
            Err(error)
        }
    }
}
pub fn start_enrollment(store: &Store, user: &str) -> Result<String> {
    schema(store)?;
    let mut bytes = [0; 20];
    getrandom::fill(&mut bytes)?;
    let secret = encode(&bytes);
    store.db.lock().unwrap().execute("INSERT INTO mfa_pending VALUES(?,?,?) ON CONFLICT(user)DO UPDATE SET secret=excluded.secret,expires=excluded.expires",params![user,secret,now()+600])?;
    Ok(secret)
}
pub fn confirm_enrollment(store: &Store, user: &str, input: &str) -> Result<Vec<String>> {
    schema(store)?;
    let mut db = store.db.lock().unwrap();
    let tx = db.transaction()?;
    let secret: String = tx.query_row(
        "SELECT secret FROM mfa_pending WHERE user=? AND expires>?",
        params![user, now()],
        |r| r.get(0),
    )?;
    let step = matched(&secret, input, now(), -1)?;
    let recovery: Vec<String> = (0..10).map(|_| random()[..32].to_string()).collect();
    let hashes: Vec<_> = recovery.iter().map(digest).collect();
    tx.execute("UPDATE users SET mfa=? WHERE id=?", params![secret, user])?;
    tx.execute("INSERT INTO mfa_state(user,last_step,recovery)VALUES(?,?,?) ON CONFLICT(user)DO UPDATE SET last_step=excluded.last_step,recovery=excluded.recovery",params![user,step,serde_json::to_string(&hashes)?])?;
    tx.execute("DELETE FROM mfa_pending WHERE user=?", [user])?;
    tx.execute("DELETE FROM sessions WHERE user=?", [user])?;
    tx.commit()?;
    drop(db);
    store.audit(user, "account.mfa.enabled", user, serde_json::json!({}))?;
    Ok(recovery)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc_6238_vectors() {
        let secret = encode(b"12345678901234567890");
        assert_eq!(secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        for (t, expected) in [
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
            (20000000000, "353130"),
        ] {
            assert_eq!(code(&secret, t / 30).unwrap(), expected);
        }
    }
    #[test]
    fn replay_and_invalid_codes_are_rejected() {
        let secret = encode(b"12345678901234567890");
        assert!(matched(&secret, "287082", 59, 1).is_err());
        assert!(matched(&secret, "287082", 59, -1).is_ok());
        assert!(matched(&secret, "abcdef", 59, -1).is_err());
        assert!(matched(&secret, "287082", 3600, -1).is_err());
    }
}
