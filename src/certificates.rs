//! Transient distribution Certbot integration. No credential or private-key browser reads.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::Path;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub domains: Vec<String>,
    pub email: String,
    pub provider: Provider,
    #[serde(default = "staging")]
    pub staging: bool,
}
fn staging() -> bool {
    true
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Provider {
    Http {},
    Cloudflare { credential: String },
    Rfc2136 { credential: String },
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        crate::domain::ident(&self.id)?;
        ensure!(
            !self.domains.is_empty() && self.domains.len() <= 32,
            "Choose 1–32 certificate domains"
        );
        ensure!(
            self.email.contains('@')
                && self.email.len() <= 254
                && !self.email.contains(['\n', '\r', ' ']),
            "Use a certificate contact email"
        );
        for domain in &self.domains {
            ensure!(
                crate::domain::hostname(domain)? == domain.to_lowercase(),
                "Use normalized certificate domains"
            );
            if matches!(self.provider, Provider::Http {}) {
                ensure!(
                    !domain.starts_with("*."),
                    "Wildcard certificates need DNS validation"
                );
            }
        }
        if let Provider::Cloudflare { credential } | Provider::Rfc2136 { credential } =
            &self.provider
        {
            crate::domain::ident(credential)?;
        }
        Ok(())
    }
    pub fn arguments(&self, root: &Path) -> Result<Vec<String>> {
        self.validate()?;
        let base = root
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Invalid certificate root"))?;
        let mut args = vec![
            "certonly".into(),
            "--non-interactive".into(),
            "--agree-tos".into(),
            "--email".into(),
            self.email.clone(),
            "--cert-name".into(),
            format!("kn-{}", self.id),
            "--config-dir".into(),
            format!("{base}/acme/config"),
            "--work-dir".into(),
            format!("{base}/acme/work"),
            "--logs-dir".into(),
            format!("{base}/acme/logs"),
            "--key-type".into(),
            "ecdsa".into(),
        ];
        if self.staging {
            args.push("--staging".into());
        }
        match &self.provider {
            Provider::Http {} => args.extend([
                "--webroot".into(),
                "-w".into(),
                format!("{base}/acme/challenges"),
            ]),
            Provider::Cloudflare { credential } => args.extend([
                "--dns-cloudflare".into(),
                "--dns-cloudflare-credentials".into(),
                format!("{base}/credentials/{credential}.ini"),
            ]),
            Provider::Rfc2136 { credential } => args.extend([
                "--dns-rfc2136".into(),
                "--dns-rfc2136-credentials".into(),
                format!("{base}/credentials/{credential}.ini"),
            ]),
        };
        for domain in &self.domains {
            args.extend(["-d".into(), domain.clone()]);
        }
        Ok(args)
    }
}
pub async fn issue(root: &Path, request: Request) -> Result<Value> {
    request.validate()?;
    let args = request.arguments(root)?;
    for path in [
        "acme/config",
        "acme/work",
        "acme/logs",
        "acme/challenges/.well-known/acme-challenge",
        "certificates",
    ] {
        std::fs::create_dir_all(root.join(path))?;
    }
    if let Provider::Cloudflare { credential } | Provider::Rfc2136 { credential } =
        &request.provider
    {
        let path = root.join("credentials").join(format!("{credential}.ini"));
        let meta = std::fs::symlink_metadata(path)?;
        use std::os::unix::fs::MetadataExt;
        ensure!(
            meta.is_file()
                && !meta.file_type().is_symlink()
                && meta.uid() == 0
                && meta.mode() & 0o077 == 0,
            "Provider credentials must be private root-owned files"
        );
    }
    let mut command = tokio::process::Command::new("/usr/bin/certbot");
    command
        .args(&args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .kill_on_drop(true);
    let output =
        tokio::time::timeout(std::time::Duration::from_secs(900), command.output()).await??;
    ensure!(
        output.status.success(),
        "Certificate issuance failed; inspect the private ACME operation log. No active certificate was replaced."
    );
    let generated = root
        .join("acme/config/live")
        .join(format!("kn-{}", request.id));
    let leaf = std::fs::read(generated.join("fullchain.pem"))?;
    let key = std::fs::read(generated.join("privkey.pem"))?;
    validate_pair(&leaf, &key, root).await?;
    let version = crate::random();
    let dir = root
        .join("certificate-versions")
        .join(&request.id)
        .join(&version);
    std::fs::create_dir_all(&dir)?;
    crate::private_write(&dir.join("fullchain.pem"), &leaf)?;
    crate::private_write(&dir.join("privkey.pem"), &key)?;
    crate::private_write(
        &dir.join("metadata.json"),
        &serde_json::to_vec(
            &json!({"domains":request.domains,"staging":request.staging,"provider":request.provider,"issued":crate::now(),"sha256":crate::digest(&leaf)}),
        )?,
    )?;
    // A staging certificate can be inspected but never replaces a production key pair.
    if request.staging {
        return Ok(
            json!({"state":"staging_validated","id":request.id,"version":version,"activated":false}),
        );
    }
    let next = root
        .join("certificates")
        .join(format!(".{}-next", request.id));
    ensure!(
        !next.exists() && !next.is_symlink(),
        "Certificate activation requires reconciliation"
    );
    std::os::unix::fs::symlink(&dir, &next)?;
    std::fs::rename(next, root.join("certificates").join(&request.id))?;
    Ok(
        json!({"state":"issued","id":request.id,"version":version,"message":"Publish or reload the verified traffic generation to use this certificate"}),
    )
}
pub async fn validate_pair(cert: &[u8], key: &[u8], root: &Path) -> Result<()> {
    ensure!(
        cert.len() <= 128 * 1024 && key.len() <= 32 * 1024,
        "Certificate upload is oversized"
    );
    let temp = root.join(format!(".certificate-check-{}", crate::random()));
    std::fs::create_dir_all(&temp)?;
    let result = async {
        crate::private_write(&temp.join("cert.pem"), cert)?;
        crate::private_write(&temp.join("key.pem"), key)?;
        let cert_pub = crate::tls::command(
            "/usr/bin/openssl",
            &[
                "x509",
                "-in",
                temp.join("cert.pem").to_str().unwrap(),
                "-pubkey",
                "-noout",
            ],
        )
        .await?;
        let key_pub = crate::tls::command(
            "/usr/bin/openssl",
            &[
                "pkey",
                "-in",
                temp.join("key.pem").to_str().unwrap(),
                "-pubout",
            ],
        )
        .await?;
        ensure!(
            cert_pub == key_pub,
            "Certificate and private key do not match"
        );
        crate::tls::command(
            "/usr/bin/openssl",
            &[
                "x509",
                "-in",
                temp.join("cert.pem").to_str().unwrap(),
                "-checkend",
                "0",
                "-noout",
            ],
        )
        .await?;
        Ok(())
    }
    .await;
    let _ = std::fs::remove_dir_all(temp);
    result
}
pub async fn inventory(root: &Path) -> Result<Value> {
    let mut result = vec![];
    let directory = root.join("certificates");
    if !directory.is_dir() {
        return Ok(json!([]));
    }
    for entry in std::fs::read_dir(directory)?.take(250) {
        let entry = entry?;
        let id = entry.file_name().to_string_lossy().to_string();
        if crate::domain::ident(&id).is_err() {
            continue;
        }
        let leaf = entry.path().join("fullchain.pem");
        if !leaf.is_file() {
            continue;
        }
        let info = crate::tls::command(
            "/usr/bin/openssl",
            &[
                "x509",
                "-in",
                leaf.to_str().unwrap(),
                "-noout",
                "-enddate",
                "-fingerprint",
                "-sha256",
                "-ext",
                "subjectAltName",
            ],
        )
        .await;
        match info{Ok(info)=>result.push(json!({"id":id,"certificate":String::from_utf8_lossy(&info),"private_key":"not_exposed"})),Err(_)=>result.push(json!({"id":id,"error":"Certificate cannot be inspected"}))}
    }
    Ok(json!(result))
}
pub fn write_credential(root: &Path, name: &str, provider: &str, value: Value) -> Result<()> {
    crate::domain::ident(name)?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Credentials must be an object"))?;
    let required: &[&str] = match provider {
        "cloudflare" => &["dns_cloudflare_api_token"],
        "rfc2136" => &[
            "dns_rfc2136_server",
            "dns_rfc2136_name",
            "dns_rfc2136_secret",
            "dns_rfc2136_algorithm",
        ],
        _ => anyhow::bail!("Unsupported DNS provider"),
    };
    ensure!(
        object.len() == required.len() && required.iter().all(|k| object.contains_key(*k)),
        "Unexpected DNS credential fields"
    );
    let mut content = String::new();
    for key in required {
        let value = object[*key]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Credential values must be strings"))?;
        ensure!(
            !value.is_empty() && value.len() <= 2048 && !value.contains(['\r', '\n', '\0']),
            "Invalid provider credential"
        );
        content.push_str(&format!("{key} = {value}\n"));
    }
    crate::private_write(
        &root.join("credentials").join(format!("{name}.ini")),
        content.as_bytes(),
    )
}
