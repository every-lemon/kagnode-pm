use crate::{
    digest,
    domain::{Resource, Role},
    now, random,
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
#[derive(Clone)]
pub struct Store {
    pub db: Arc<Mutex<Connection>>,
    pub root: PathBuf,
}
impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            root.is_absolute()
                && !root
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
            "Use an absolute private storage path"
        );
        std::fs::create_dir_all(root)?;
        ensure!(
            !std::fs::symlink_metadata(root)?.file_type().is_symlink(),
            "Storage cannot be a symlink"
        );
        for name in ["proxy.sqlite", "proxy.sqlite-wal", "proxy.sqlite-shm"] {
            if let Ok(meta) = std::fs::symlink_metadata(root.join(name)) {
                ensure!(
                    meta.is_file() && !meta.file_type().is_symlink() && meta.nlink() == 1,
                    "Storage files must be regular and unlinked"
                );
            }
        }
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
        let db = Connection::open_with_flags(
            root.join("proxy.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        std::fs::set_permissions(
            root.join("proxy.sqlite"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,name TEXT NOT NULL,password TEXT NOT NULL,role TEXT NOT NULL,mfa TEXT NOT NULL DEFAULT '',disabled INTEGER NOT NULL DEFAULT 0,subject TEXT UNIQUE,photo TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user TEXT NOT NULL REFERENCES users(id),csrf TEXT NOT NULL,expires INTEGER NOT NULL,authenticated INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY,name TEXT NOT NULL,fingerprint TEXT UNIQUE,revoked INTEGER NOT NULL DEFAULT 0,seen INTEGER NOT NULL DEFAULT 0,capabilities TEXT NOT NULL DEFAULT '{}',summary TEXT NOT NULL DEFAULT '{}');
 CREATE TABLE IF NOT EXISTS server_permissions(user TEXT NOT NULL REFERENCES users(id),server TEXT NOT NULL REFERENCES servers(id),role TEXT NOT NULL,maintenance INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(user,server));
 CREATE TABLE IF NOT EXISTS enrollment(token TEXT PRIMARY KEY,name TEXT NOT NULL,expires INTEGER NOT NULL,used INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS resources(id TEXT PRIMARY KEY,server TEXT NOT NULL REFERENCES servers(id),name TEXT NOT NULL,kind TEXT NOT NULL,settings TEXT NOT NULL,revision INTEGER NOT NULL DEFAULT 1,published INTEGER NOT NULL DEFAULT 0,deleted INTEGER NOT NULL DEFAULT 0,UNIQUE(server,name));
 CREATE TABLE IF NOT EXISTS revisions(resource TEXT NOT NULL,revision INTEGER NOT NULL,settings TEXT NOT NULL,actor TEXT NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(resource,revision));
 CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,server TEXT NOT NULL REFERENCES servers(id),kind TEXT NOT NULL,payload TEXT NOT NULL,state TEXT NOT NULL DEFAULT 'queued',result TEXT NOT NULL DEFAULT '{}',actor TEXT NOT NULL,created INTEGER NOT NULL,updated INTEGER NOT NULL,request_key TEXT UNIQUE NOT NULL,lease TEXT NOT NULL DEFAULT '',expires INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,target TEXT NOT NULL,detail TEXT NOT NULL,created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS oauth(state TEXT PRIMARY KEY,verifier TEXT NOT NULL,request TEXT NOT NULL,cookie TEXT NOT NULL,expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS core_notice_dismissals(user TEXT NOT NULL,notice TEXT NOT NULL,seen INTEGER NOT NULL,PRIMARY KEY(user,notice));
 ")?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            root: root.into(),
        })
    }
    pub fn audit(&self, actor: &str, action: &str, target: &str, detail: Value) -> Result<()> {
        self.db.lock().unwrap().execute(
            "INSERT INTO audit(actor,action,target,detail,created) VALUES(?,?,?,?,?)",
            params![actor, action, target, detail.to_string(), now()],
        )?;
        Ok(())
    }
    pub fn allowed(
        &self,
        user: &str,
        role: &Role,
        server: &str,
        write: bool,
        maintenance: bool,
    ) -> Result<bool> {
        let db = self.db.lock().unwrap();
        let exists: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM servers WHERE id=? AND revoked=0)",
            [server],
            |r| r.get(0),
        )?;
        if !exists {
            return Ok(false);
        }
        if role.administer() {
            return Ok(true);
        }
        let mut q = db
            .prepare("SELECT role,maintenance FROM server_permissions WHERE user=? AND server=?")?;
        let row = q.query_row(params![user, server], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?))
        });
        Ok(row.is_ok_and(|(r, m)| {
            matches!(r.as_str(), "viewer" | "maintainer")
                && (!write || r == "maintainer")
                && (!maintenance || (m && r == "maintainer"))
        }))
    }
    pub fn servers(&self, user: &str, role: &Role) -> Result<Value> {
        let db = self.db.lock().unwrap();
        let mut q = db.prepare(
            "SELECT id,name,revoked,seen,capabilities,summary FROM servers ORDER BY name",
        )?;
        let rows=q.query_map([],|r|Ok((r.get::<_,String>(0)?,json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"revoked":r.get::<_,bool>(2)?,"seen":r.get::<_,i64>(3)?,"capabilities":serde_json::from_str::<Value>(&r.get::<_,String>(4)?).unwrap_or(json!({})),"summary":serde_json::from_str::<Value>(&r.get::<_,String>(5)?).unwrap_or(json!({}))}))))?.collect::<std::result::Result<Vec<_>,_>>()?;
        drop(q);
        drop(db);
        let mut out = vec![];
        for (id, mut row) in rows {
            if self.allowed(user, role, &id, false, false)? {
                row["permissions"] = json!({"write":self.allowed(user,role,&id,true,false)?,"maintenance":self.allowed(user,role,&id,true,true)?});
                out.push(row)
            }
        }
        Ok(json!(out))
    }
    pub fn save_resource(
        &self,
        user: &str,
        server: &str,
        name: &str,
        resource: &Resource,
        id: Option<&str>,
        expected: i64,
    ) -> Result<String> {
        crate::domain::ident(name)?;
        resource.validate()?;
        let key = id.map_or_else(random, String::from);
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let revision = if id.is_some() {
            let (s, r): (String, i64) = tx.query_row(
                "SELECT server,revision FROM resources WHERE id=? AND deleted=0",
                [&key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                s == server && r == expected,
                "conflict: resource changed; reload before saving"
            );
            r + 1
        } else {
            1
        };
        let value = serde_json::to_string(resource)?;
        let kind = match resource {
            Resource::ProxyHost(_) => "proxy_host",
            Resource::Stream(_) => "stream",
            Resource::ForwardProxy(_) => "forward_proxy",
        };
        tx.execute("INSERT INTO resources(id,server,name,kind,settings,revision) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,kind=excluded.kind,settings=excluded.settings,revision=excluded.revision",params![key,server,name,kind,value,revision])?;
        tx.execute(
            "INSERT INTO revisions VALUES(?,?,?,?,?)",
            params![key, revision, value, user, now()],
        )?;
        tx.execute(
            "INSERT INTO audit(actor,action,target,detail,created) VALUES(?,?,?,?,?)",
            params![
                user,
                "resource.save",
                key,
                json!({"revision":revision}).to_string(),
                now()
            ],
        )?;
        tx.commit()?;
        Ok(key)
    }
    pub fn resources(&self, server: &str) -> Result<Value> {
        let db = self.db.lock().unwrap();
        let mut q=db.prepare("SELECT id,name,kind,settings,revision,published FROM resources WHERE server=? AND deleted=0 ORDER BY name")?;
        let out=q.query_map([server],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"kind":r.get::<_,String>(2)?,"settings":serde_json::from_str::<Value>(&r.get::<_,String>(3)?).unwrap_or(json!(null)),"revision":r.get::<_,i64>(4)?,"published":r.get::<_,i64>(5)?})))?.collect::<std::result::Result<Vec<_>,_>>()?;
        Ok(json!(out))
    }
    pub fn enqueue(
        &self,
        actor: &str,
        server: &str,
        kind: &str,
        payload: Value,
        request_key: &str,
    ) -> Result<String> {
        ensure!(
            (16..=128).contains(&request_key.len()),
            "Supply an idempotency key"
        );
        let serialized_payload = payload.to_string();
        ensure!(
            serialized_payload.len() < 48 * 1024,
            "Operation exceeds the bounded agent protocol; split this change into smaller server configurations"
        );
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        if let Ok((id, s, k, p, a)) = tx.query_row(
            "SELECT id,server,kind,payload,actor FROM jobs WHERE request_key=?",
            [request_key],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            },
        ) {
            ensure!(
                s == server && k == kind && a == actor && p == serialized_payload,
                "Idempotency key belongs to a different operation"
            );
            return Ok(id);
        }
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM jobs WHERE server=? AND state IN ('queued','running')",
            [server],
            |r| r.get(0),
        )?;
        ensure!(count < 100, "Server job queue is full");
        let id = random();
        tx.execute("INSERT INTO jobs(id,server,kind,payload,actor,created,updated,request_key) VALUES(?,?,?,?,?,?,?,?)",params![id,server,kind,payload.to_string(),actor,now(),now(),request_key])?;
        tx.commit()?;
        Ok(id)
    }
    pub fn claim(&self, server: &str) -> Result<Value> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        // An expired running operation requires reconciliation, never automatic replay.
        tx.execute("UPDATE jobs SET state='uncertain',updated=? WHERE server=? AND state='running' AND expires<?",params![now(),server,now()])?;
        let busy: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM jobs WHERE server=? AND state='running')",
            [server],
            |r| r.get(0),
        )?;
        if busy {
            tx.commit()?;
            return Ok(json!(null));
        }
        // Read-only node inspection must remain possible during a recovery hold.
        // No new mutation may pass an uncertain operation.
        let row=tx.query_row("SELECT id,kind,payload FROM jobs WHERE server=?1 AND state='queued' AND (kind='status' OR NOT EXISTS(SELECT 1 FROM jobs WHERE server=?1 AND state='uncertain')) ORDER BY rowid LIMIT 1",[server],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)));
        if let Ok((id, kind, payload)) = row {
            let lease = random();
            tx.execute(
                "UPDATE jobs SET state='running',lease=?,expires=?,updated=? WHERE id=?",
                params![digest(&lease), now() + 1800, now(), id],
            )?;
            tx.commit()?;
            Ok(
                json!({"id":id,"kind":kind,"payload":serde_json::from_str::<Value>(&payload)?,"lease":lease}),
            )
        } else {
            tx.commit()?;
            Ok(json!(null))
        }
    }
    pub fn heartbeat(&self, server: &str, data: &Value) -> Result<()> {
        ensure!(data.to_string().len() < 16384, "Agent summary too large");
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "UPDATE servers SET seen=?,summary=?,capabilities=? WHERE id=? AND revoked=0",
            params![
                now(),
                data["summary"].to_string(),
                data["capabilities"].to_string(),
                server
            ],
        )?;
        if let (Some(id), Some(lease)) = (
            data["active_job"]["id"].as_str(),
            data["active_job"]["lease"].as_str(),
        ) {
            ensure!(
                id.len() == 64 && lease.len() == 64,
                "Invalid active job receipt"
            );
            // A live operation may extend its own lease, but cannot clear a recovery hold.
            tx.execute("UPDATE jobs SET expires=?,updated=? WHERE id=? AND server=? AND lease=? AND state='running'", params![now()+1800, now(), id, server, digest(lease)])?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn acknowledge(&self, server: &str, id: &str, lease: &str, outcome: &Value) -> Result<()> {
        let state = outcome["state"].as_str().unwrap_or("");
        ensure!(
            matches!(state, "completed" | "failed" | "uncertain"),
            "Invalid job outcome"
        );
        ensure!(
            lease.len() == 64 && outcome.to_string().len() <= 65536,
            "Invalid job receipt"
        );
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        let (previous, result): (String, String) = tx
            .query_row(
                "SELECT state,result FROM jobs WHERE id=? AND server=? AND lease=?",
                params![id, server, digest(lease)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| anyhow::anyhow!("conflict: job lease changed"))?;
        let result: Value = serde_json::from_str(&result)?;
        if result == *outcome && matches!(previous.as_str(), "completed" | "failed" | "uncertain") {
            // The response may have been lost after commit. Identical receipts are safe to retry.
            return Ok(());
        }
        ensure!(
            matches!(previous.as_str(), "running" | "uncertain") && result == json!({}),
            "conflict: a different job result was already recorded"
        );
        tx.execute(
            "UPDATE jobs SET state=?,result=?,updated=? WHERE id=?",
            params![state, outcome.to_string(), now(), id],
        )?;
        if state == "completed" && outcome["result"]["state"] == "active" {
            let (kind, payload): (String, String) =
                tx.query_row("SELECT kind,payload FROM jobs WHERE id=?", [id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            if kind == "configure" {
                let payload: Value = serde_json::from_str(&payload)?;
                let revisions = payload["revisions"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Missing frozen publication revisions"))?;
                tx.execute("UPDATE resources SET published=0 WHERE server=?", [server])?;
                for row in revisions {
                    tx.execute(
                        "UPDATE resources SET published=? WHERE id=? AND server=?",
                        params![
                            row["revision"]
                                .as_i64()
                                .ok_or_else(|| anyhow::anyhow!("Invalid publication revision"))?,
                            row["id"]
                                .as_str()
                                .ok_or_else(|| anyhow::anyhow!("Invalid publication resource"))?,
                            server
                        ],
                    )?;
                }
            }
        }
        if state == "completed" {
            let (kind, actor): (String, String) =
                tx.query_row("SELECT kind,actor FROM jobs WHERE id=?", [id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            if kind == "import_review" {
                let resources = outcome["result"]["resources"]
                    .as_array()
                    .ok_or_else(|| anyhow::anyhow!("Missing reviewed resources"))?;
                ensure!(
                    !resources.is_empty() && resources.len() <= 32,
                    "Invalid reviewed resource count"
                );
                for row in resources {
                    let name = row["name"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("Missing import name"))?;
                    crate::domain::ident(name)?;
                    let resource: Resource = serde_json::from_value(row["resource"].clone())?;
                    resource.validate()?;
                    let key = digest(format!("{server}:{name}"));
                    let value = serde_json::to_string(&resource)?;
                    let inserted=tx.execute("INSERT INTO resources(id,server,name,kind,settings) VALUES(?,?,?,'proxy_host',?) ON CONFLICT(server,name) DO NOTHING",params![key,server,name,value])?;
                    if inserted == 1 {
                        tx.execute(
                            "INSERT INTO revisions VALUES(?,1,?,?,?)",
                            params![key, value, actor, now()],
                        )?;
                    }
                }
                tx.execute("INSERT INTO audit(actor,action,target,detail,created) VALUES(?,'adoption.drafts',?,?,?)",params![actor,server,json!({"job":id,"traffic_changed":false}).to_string(),now()])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}
