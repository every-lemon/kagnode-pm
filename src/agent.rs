use crate::broker::Operation;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub id: String,
    pub controller: String,
    pub broker_socket: PathBuf,
    pub root: PathBuf,
}
pub async fn enroll(root: &Path, controller: &str, token: &str, ca: &Path) -> Result<()> {
    let url = url::Url::parse(controller)?;
    ensure!(
        url.scheme() == "https"
            || url
                .host_str()
                .is_some_and(|h| h == "127.0.0.1" || h == "localhost"),
        "Enrollment requires trusted HTTPS"
    );
    ensure!(token.len() == 64, "Invalid one-time enrollment token");
    ensure!(!root.join("agent.json").exists(), "Agent already enrolled");
    std::fs::create_dir_all(root)?;
    let key = root.join("agent.key");
    let csr = root.join("agent.csr");
    crate::tls::command(
        "/usr/bin/openssl",
        &[
            "req",
            "-new",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
            "-subj",
            "/CN=KagNode Proxy Agent",
        ],
    )
    .await?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30));
    if ca.is_file() {
        builder =
            builder.add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(ca)?)?);
    }
    let client = builder.build()?;
    let response = client
        .post(format!(
            "{}/agent/v1/enroll",
            controller.trim_end_matches('/')
        ))
        .json(&json!({"token":token,"csr":std::fs::read_to_string(csr)?}))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "Enrollment refused; inspect the controller and use a new token"
    );
    let data: Value = response.json().await?;
    let cert = data["certificate"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing agent certificate"))?;
    let authority = data["ca"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing fleet authority"))?;
    let fleet = data["fleet_url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing fleet endpoint"))?;
    ensure!(
        url::Url::parse(fleet)?.scheme() == "https",
        "Fleet endpoint must use TLS"
    );
    crate::private_write(&root.join("agent.pem"), cert.as_bytes())?;
    crate::private_write(&root.join("ca.pem"), authority.as_bytes())?;
    let config = AgentConfig {
        id: data["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing server identity"))?
            .into(),
        controller: fleet.into(),
        broker_socket: "/run/kagnode-proxy-manager/broker.sock".into(),
        root: root.into(),
    };
    crate::private_write(
        &root.join("agent.json"),
        &serde_json::to_vec_pretty(&config)?,
    )?;
    Ok(())
}
pub fn client(config: &AgentConfig) -> Result<reqwest::Client> {
    let mut identity = std::fs::read(config.root.join("agent.pem"))?;
    identity.extend(std::fs::read(config.root.join("agent.key"))?);
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .add_root_certificate(reqwest::Certificate::from_pem(&std::fs::read(
            config.root.join("ca.pem"),
        )?)?)
        .identity(reqwest::Identity::from_pem(&identity)?)
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(40))
        .build()?)
}
type ActiveJob = std::sync::Arc<tokio::sync::Mutex<Option<(String, String)>>>;
fn heartbeat_data(active: Option<(String, String)>) -> Value {
    json!({"version":crate::VERSION,"summary":summary(),"active_job":active.map(|(id,lease)|json!({"id":id,"lease":lease})),"capabilities":{"package_removal":Path::new("/etc/kagnode/proxy-manager/allow-package-removal").is_file(),"nginx":Path::new("/usr/sbin/nginx").is_file(),"forward_proxy":crate::traffic::engine().is_ok(),"platform":std::fs::read_to_string("/etc/os-release").unwrap_or_default().lines().filter(|l|l.starts_with("ID=")||l.starts_with("VERSION_ID=")).collect::<Vec<_>>().join(" ")}})
}
pub async fn run(config: AgentConfig) -> Result<()> {
    let client = client(&config)?;
    let active: ActiveJob = Default::default();
    let heartbeat_config = config.clone();
    let heartbeat_client = client.clone();
    let heartbeat_active = active.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let current = heartbeat_active.lock().await.clone();
            let result = heartbeat_client
                .post(format!(
                    "{}/agent/v1/heartbeat",
                    heartbeat_config.controller.trim_end_matches('/')
                ))
                .json(&heartbeat_data(current))
                .send()
                .await;
            if !result.is_ok_and(|r| r.status().is_success()) {
                eprintln!(
                    "Agent heartbeat deferred; local traffic and durable operation records are retained"
                );
            }
        }
    });
    loop {
        if let Err(e) = tick(&config, &client, &active).await {
            eprintln!(
                "Agent synchronization deferred: {}",
                e.to_string().chars().take(300).collect::<String>()
            );
        }
        tokio::select! {_=tokio::time::sleep(std::time::Duration::from_secs(15))=>{},_=tokio::signal::ctrl_c()=>{heartbeat.abort();return Ok(())}}
    }
}
async fn flush_results(config: &AgentConfig, client: &reqwest::Client) -> Result<()> {
    let folder = config.root.join("jobs");
    if !folder.is_dir() {
        return Ok(());
    }
    let mut entries = std::fs::read_dir(folder)?.collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        entries.len() <= 1000,
        "Local job inventory needs archival review"
    );
    entries.sort_by_key(|e| e.file_name());
    for file in entries {
        let meta = file.file_type()?;
        if !meta.is_file() {
            continue;
        }
        let mut record: Value = serde_json::from_slice(&std::fs::read(file.path())?)?;
        if record["acknowledged"] == true {
            continue;
        }
        let id = record["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid local job record"))?
            .to_string();
        let lease = record["lease"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing local job lease"))?
            .to_string();
        if record["outcome"].is_null() {
            record["outcome"] = json!({"state":"uncertain","error":"Agent restarted during an operation. Inspect local recovery status; the operation was not replayed."});
            crate::private_write(&file.path(), &serde_json::to_vec(&record)?)?;
        }
        report(config, client, &id, &lease, record["outcome"].clone()).await?;
        record["acknowledged"] = json!(true);
        crate::private_write(&file.path(), &serde_json::to_vec(&record)?)?;
    }
    Ok(())
}
async fn tick(config: &AgentConfig, client: &reqwest::Client, active: &ActiveJob) -> Result<()> {
    flush_results(config, client).await?;
    let response = client
        .post(format!(
            "{}/agent/v1/poll",
            config.controller.trim_end_matches('/')
        ))
        .json(&heartbeat_data(None))
        .send()
        .await?;
    ensure!(response.status().is_success(), "Fleet connection refused");
    let body: Value = response.json().await?;
    if body["job"].is_null() {
        return Ok(());
    }
    let job = &body["job"];
    let id = job["id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid job ID"))?;
    let lease = job["lease"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid job lease"))?;
    crate::domain::ident(id)?;
    ensure!(lease.len() == 64, "Invalid lease");
    let path = config.root.join("jobs").join(format!("{id}.json"));
    ensure!(
        !path.exists(),
        "Local job already exists; refusing duplicate execution"
    );
    let mut record =
        json!({"id":id,"lease":lease,"started":crate::now(),"outcome":null,"acknowledged":false});
    crate::private_write(&path, &serde_json::to_vec(&record)?)?;
    *active.lock().await = Some((id.into(), lease.into()));
    let operation = operation(job);
    let (result, mutation) = match operation {
        Ok(operation) => {
            let mutation = matches!(
                operation,
                Operation::Configure { .. }
                    | Operation::PackageRemove { .. }
                    | Operation::CertificateIssue { .. }
                    | Operation::CertificateActivate { .. }
            );
            (
                crate::broker::request(&config.broker_socket, &operation).await,
                mutation,
            )
        }
        Err(error) => (Err(error), false),
    };
    record["outcome"] = match result {
        Ok(result) => json!({"state":"completed","result":result,"completed":crate::now()}),
        Err(error) => {
            json!({"state":if mutation{"uncertain"}else{"failed"},"error":error.to_string(),"completed":crate::now(),"recovery":if mutation{"Inspect the private node recovery state before clearing this hold; the operation is not replayed."}else{"No mutating operation was requested."}})
        }
    };
    crate::private_write(&path, &serde_json::to_vec(&record)?)?;
    *active.lock().await = None;
    flush_results(config, client).await
}
fn operation(job: &Value) -> Result<Operation> {
    Ok(match job["kind"].as_str() {
        Some("configure") => Operation::Configure {
            resources: serde_json::from_value(job["payload"]["resources"].clone())?,
        },
        Some("package_preview") => Operation::PackagePreview {
            names: serde_json::from_value(job["payload"]["names"].clone())?,
        },
        Some("package_remove") => {
            ensure!(
                Path::new("/etc/kagnode/proxy-manager/allow-package-removal").is_file(),
                "Local package-removal capability is disabled"
            );
            Operation::PackageRemove {
                plan: serde_json::from_value(job["payload"]["plan"].clone())?,
            }
        }
        Some("certificate_issue") => Operation::CertificateIssue {
            request: serde_json::from_value(job["payload"]["request"].clone())?,
        },
        Some("certificate_activate") => Operation::CertificateActivate {
            id: job["payload"]["id"].as_str().unwrap_or("").into(),
            version: job["payload"]["version"].as_str().unwrap_or("").into(),
            expected_sha256: job["payload"]["expected_sha256"]
                .as_str()
                .unwrap_or("")
                .into(),
        },
        Some("certificate_upload") => Operation::CertificateUpload {
            upload: serde_json::from_value(job["payload"].clone())?,
        },
        Some("certificate_inventory") => Operation::CertificateInventory {},
        Some("status") => Operation::Status {},
        Some("discovery") => Operation::Discover {},
        Some("import_review") => Operation::ReviewImport {
            fingerprint: job["payload"]["fingerprint"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing review fingerprint"))?
                .into(),
            selected: serde_json::from_value(job["payload"]["selected"].clone())?,
        },
        _ => anyhow::bail!("Unsupported typed job"),
    })
}
async fn report(
    config: &AgentConfig,
    client: &reqwest::Client,
    id: &str,
    lease: &str,
    result: Value,
) -> Result<()> {
    let response = client
        .post(format!(
            "{}/agent/v1/jobs/{id}/result",
            config.controller.trim_end_matches('/')
        ))
        .json(&json!({"lease":lease,"outcome":result}))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "Result acknowledgement deferred; private local receipt retained"
    );
    Ok(())
}
pub fn summary() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let rss = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0);
    let mem = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let available = mem
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse::<u64>().ok())
        .unwrap_or(0);
    json!({"agent_rss_kib":rss,"available_memory_kib":available,"load":std::fs::read_to_string("/proc/loadavg").unwrap_or_default().split_whitespace().take(3).collect::<Vec<_>>().join(" "),"sampled":crate::now()})
}
