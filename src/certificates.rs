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
    #[serde(default = "default_authority")]
    pub authority: String,
    #[serde(default = "staging")]
    pub staging: bool,
}
fn default_authority() -> String {
    "letsencrypt".into()
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
        crate::domain::ident(&self.authority)?;
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
        if self.authority == "letsencrypt" {
            args.extend([
                "--server".into(),
                if self.staging {
                    "https://acme-staging-v02.api.letsencrypt.org/directory"
                } else {
                    "https://acme-v02.api.letsencrypt.org/directory"
                }
                .into(),
            ]);
        } else {
            let policy = std::path::Path::new("/etc/kagnode/proxy-manager/acme-providers.json");
            crate::traffic::trusted_directory(policy.parent().unwrap())?;
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::symlink_metadata(policy)?;
            ensure!(
                meta.is_file()
                    && !meta.file_type().is_symlink()
                    && meta.uid() == 0
                    && meta.mode() & 0o077 == 0
                    && meta.len() <= 65536,
                "ACME provider policy must be private and root-owned"
            );
            let policies: Value = serde_json::from_slice(&std::fs::read(policy)?)?;
            let directory = policies[&self.authority][if self.staging {
                "staging_directory"
            } else {
                "directory"
            }]
            .as_str()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Configure this authority and staging directory locally before issuance"
                )
            })?;
            let url = url::Url::parse(directory)?;
            ensure!(
                url.scheme() == "https"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.fragment().is_none(),
                "ACME directory must be an approved HTTPS URL"
            );
            args.extend(["--server".into(), directory.into()]);
            if let Some(config) = policies[&self.authority]["eab_config"].as_str() {
                crate::domain::ident(config)?;
                let path = root.join("credentials").join(format!("{config}.eab.ini"));
                let meta = std::fs::symlink_metadata(&path)?;
                ensure!(
                    meta.is_file()
                        && !meta.file_type().is_symlink()
                        && meta.uid() == 0
                        && meta.mode() & 0o077 == 0
                        && meta.len() <= 8192,
                    "EAB configuration must be private and root-owned"
                );
                let text = std::fs::read_to_string(&path)?;
                let keys = text
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .map(|l| l.split_once('=').map(|(k, _)| k.trim()).unwrap_or(""))
                    .collect::<Vec<_>>();
                ensure!(
                    keys.len() == 2 && keys.contains(&"eab-kid") && keys.contains(&"eab-hmac-key"),
                    "EAB configuration permits only account-binding fields"
                );
                args.extend([
                    "--config".into(),
                    path.to_str()
                        .ok_or_else(|| anyhow::anyhow!("Invalid EAB path"))?
                        .into(),
                ]);
            }
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
            &json!({"domains":request.domains,"staging":request.staging,"provider":request.provider,"authority":request.authority,"issued":crate::now(),"sha256":crate::digest(&leaf)}),
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upload {
    pub id: String,
    pub domains: Vec<String>,
    pub certificate: String,
    pub private_key: String,
    #[serde(default)]
    pub intermediate_chain: String,
    #[serde(default)]
    pub private_ca: bool,
}
impl Drop for Upload {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}
impl Upload {
    pub fn validate(&self) -> Result<()> {
        crate::domain::ident(&self.id)?;
        ensure!(
            !self.domains.is_empty() && self.domains.len() <= 32,
            "Choose 1–32 certificate hostnames"
        );
        for d in &self.domains {
            crate::domain::hostname(d)?;
        }
        ensure!(
            self.certificate.starts_with("-----BEGIN CERTIFICATE-----")
                && self.certificate.len() + self.intermediate_chain.len() <= 16384
                && self.private_key.len() <= 8192,
            "Upload bounded PEM files (chain up to 16 KiB, key up to 8 KiB)"
        );
        ensure!(
            self.private_key.contains("PRIVATE KEY-----")
                && !self.private_key.contains("ENCRYPTED"),
            "Provide an unencrypted PEM private key over HTTPS; it is stored privately"
        );
        Ok(())
    }
}
pub async fn upload(root: &Path, input: Upload) -> Result<Value> {
    input.validate()?;
    let mut chain = input.certificate.trim().to_string();
    if !input.intermediate_chain.trim().is_empty() {
        chain.push('\n');
        chain.push_str(input.intermediate_chain.trim());
    }
    chain.push('\n');
    validate_pair(chain.as_bytes(), input.private_key.as_bytes(), root).await?;
    let check = root.join(format!(".hostname-check-{}", crate::random()));
    std::fs::create_dir(&check)?;
    let validation = async {
        crate::private_write(&check.join("chain.pem"), chain.as_bytes())?;
        let certificates = rustls_pemfile::certs(&mut std::io::BufReader::new(chain.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            !certificates.is_empty() && certificates.len() <= 8 && !chain.contains("PRIVATE KEY"),
            "Provide a chain containing 1–8 certificates"
        );
        use base64::Engine;
        let pem = |der: &[u8]| {
            let encoded = base64::engine::general_purpose::STANDARD.encode(der);
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                encoded
                    .as_bytes()
                    .chunks(64)
                    .map(|b| std::str::from_utf8(b).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        let chain_path = check.join("chain.pem");
        let leaf = check.join("leaf.pem");
        let anchor = check.join("anchor.pem");
        crate::private_write(&leaf, pem(certificates[0].as_ref()).as_bytes())?;
        crate::private_write(
            &anchor,
            pem(certificates.last().unwrap().as_ref()).as_bytes(),
        )?;
        let mut verify = vec![
            "verify",
            "-purpose",
            "sslserver",
            "-untrusted",
            chain_path.to_str().unwrap(),
        ];
        if input.private_ca {
            verify.extend(["-partial_chain", "-trusted", anchor.to_str().unwrap()]);
        }
        verify.push(leaf.to_str().unwrap());
        crate::tls::command("/usr/bin/openssl", &verify).await?;
        for d in &input.domains {
            ensure!(
                !d.starts_with("*."),
                "List concrete hostnames to verify wildcard certificate coverage"
            );
            let result = crate::tls::command(
                "/usr/bin/openssl",
                &[
                    "x509",
                    "-in",
                    chain_path.to_str().unwrap(),
                    "-noout",
                    "-checkhost",
                    d,
                ],
            )
            .await?;
            ensure!(
                String::from_utf8_lossy(&result).contains("does match certificate"),
                "Uploaded certificate does not cover a requested hostname"
            );
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = std::fs::remove_dir_all(check);
    validation?;
    let version = crate::random();
    let directory = root
        .join("certificate-versions")
        .join(&input.id)
        .join(&version);
    std::fs::create_dir_all(&directory)?;
    crate::private_write(&directory.join("fullchain.pem"), chain.as_bytes())?;
    crate::private_write(&directory.join("privkey.pem"), input.private_key.as_bytes())?;
    crate::private_write(
        &directory.join("metadata.json"),
        &serde_json::to_vec(
            &json!({"domains":input.domains,"provider":"uploaded","renewal":"manual","sha256":crate::digest(chain.as_bytes()),"created":crate::now()}),
        )?,
    )?;
    // Select a new ID only. Replacements are staged until a reviewed activation.
    std::fs::create_dir_all(root.join("certificates"))?;
    let active = root.join("certificates").join(&input.id);
    let previous_sha256 = std::fs::read(active.join("fullchain.pem"))
        .ok()
        .map(crate::digest)
        .unwrap_or_default();
    let selected =
        std::fs::symlink_metadata(&active).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
    if selected {
        std::os::unix::fs::symlink(&directory, &active)?;
    }
    Ok(
        json!({"id":input.id,"version":version,"state":"validated","selected":selected,"current_sha256":if selected {crate::digest(chain.as_bytes())}else{previous_sha256},"traffic_reloaded":false,"renewal":"manual","message":if selected{"Certificate is available for a reviewed site publication"}else{"Existing certificate retained; review this replacement before activation"}}),
    )
}

/// AEAD-protected queued secrets. Root/controller data backups must include this key.
pub fn sealed(root: &Path, server: &str, value: &Value) -> Result<Value> {
    use base64::Engine;
    use ring::aead;
    let key = queue_key(root)?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| anyhow::anyhow!("Invalid queue key"))?,
    );
    let mut nonce = [0u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
    let mut bytes = zeroize::Zeroizing::new(serde_json::to_vec(value)?);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(server.as_bytes()),
        &mut *bytes,
    )
    .map_err(|_| anyhow::anyhow!("Cannot protect certificate upload"))?;
    Ok(
        json!({"sealed":base64::engine::general_purpose::STANDARD.encode(&*bytes),"nonce":hex::encode(nonce),"schema":1}),
    )
}
pub fn unseal(root: &Path, server: &str, value: &Value) -> Result<Value> {
    use base64::Engine;
    use ring::aead;
    ensure!(value["schema"] == 1, "Unsupported queued secret");
    let raw = hex::decode(value["nonce"].as_str().unwrap_or(""))?;
    let nonce: [u8; 12] = raw
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid queue nonce"))?;
    let mut bytes = zeroize::Zeroizing::new(
        base64::engine::general_purpose::STANDARD.decode(value["sealed"].as_str().unwrap_or(""))?,
    );
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &queue_key(root)?)
            .map_err(|_| anyhow::anyhow!("Invalid queue key"))?,
    );
    let clear = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(server.as_bytes()),
            &mut bytes,
        )
        .map_err(|_| anyhow::anyhow!("Queued certificate integrity check failed"))?;
    Ok(serde_json::from_slice(clear)?)
}
fn queue_key(root: &Path) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let path = root.join("queue-secret.key");
    let mut key = [0u8; 32];
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut file) => {
            getrandom::fill(&mut key).map_err(|_| anyhow::anyhow!("OS randomness unavailable"))?;
            file.write_all(&key)?;
            file.sync_all()?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let meta = std::fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.nlink() == 1
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
            && meta.len() == 32,
        "Invalid protected queue key"
    );
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    std::fs::File::open(path)?
        .take(33)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() == 32, "Invalid queue key length");
    Ok(bytes)
}

pub async fn activate_uploaded(
    root: &Path,
    id: &str,
    version: &str,
    expected: &str,
) -> Result<Value> {
    crate::domain::ident(id)?;
    crate::domain::ident(version)?;
    ensure!(
        expected.is_empty()
            || (expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit())),
        "Invalid reviewed certificate fingerprint"
    );
    crate::traffic::trusted_directory(root)?;
    ensure!(
        !root.join("activation.json").exists()
            && !root.join("certificate-activation.json").exists(),
        "An interrupted activation requires recovery first"
    );
    let selected = root.join("certificates").join(id);
    let previous = std::fs::read_link(&selected).ok();
    let actual = std::fs::read(selected.join("fullchain.pem"))
        .ok()
        .map(crate::digest)
        .unwrap_or_default();
    ensure!(
        actual == expected,
        "Certificate changed; review the current inventory again"
    );
    let directory = root.join("certificate-versions").join(id).join(version);
    crate::traffic::trusted_directory(&directory)?;
    let chain = std::fs::read(directory.join("fullchain.pem"))?;
    let key = zeroize::Zeroizing::new(std::fs::read(directory.join("privkey.pem"))?);
    validate_pair(&chain, &key, root).await?;
    if let Ok(bytes) = std::fs::read(root.join("current/generation.json")) {
        let generation: Value = serde_json::from_slice(&bytes)?;
        let resources: Vec<(String, crate::domain::Resource)> =
            serde_json::from_value(generation["resources"].clone())?;
        for (_, resource) in resources {
            let crate::domain::Resource::ProxyHost(host) = resource else {
                continue;
            };
            if host.certificate.as_deref() != Some(id) {
                continue;
            }
            for domain in host.domains {
                let leaf = directory.join("fullchain.pem");
                let result = crate::tls::command(
                    "/usr/bin/openssl",
                    &[
                        "x509",
                        "-in",
                        leaf.to_str().unwrap(),
                        "-noout",
                        "-checkhost",
                        &domain,
                    ],
                )
                .await?;
                ensure!(
                    String::from_utf8_lossy(&result).contains("does match certificate"),
                    "Replacement does not cover an active site hostname"
                );
            }
        }
    }
    let journal = root.join("certificate-activation.json");
    crate::private_write(
        &journal,
        &serde_json::to_vec(
            &json!({"id":id,"version":version,"previous":previous,"expected_sha256":expected,"started":crate::now()}),
        )?,
    )?;
    let next = root
        .join("certificates")
        .join(format!(".next-{}", crate::random()));
    let result = async {
        std::os::unix::fs::symlink(&directory, &next)?;
        std::fs::rename(&next, &selected)?;
        if root.join("current/nginx.conf").is_file() {
            crate::tls::command(
                "/usr/sbin/nginx",
                &[
                    "-t",
                    "-p",
                    root.to_str().unwrap(),
                    "-c",
                    root.join("current/nginx.conf").to_str().unwrap(),
                ],
            )
            .await?;
            crate::tls::command(
                "/usr/bin/systemctl",
                &["reload", "kagnode-proxy-traffic.service"],
            )
            .await?;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        let _ = std::fs::remove_file(&next);
        if let Some(previous) = previous {
            std::os::unix::fs::symlink(previous, &next)?;
            std::fs::rename(&next, &selected)?;
        } else {
            std::fs::remove_file(&selected)?;
        }
        // Retain the journal for independent inspection; no automatic replay.
        return Err(error
            .context("Certificate activation rolled back; inspect the retained recovery record"));
    }
    std::fs::remove_file(journal)?;
    std::fs::File::open(root)?.sync_all()?;
    Ok(
        json!({"id":id,"version":version,"state":"activated","sha256":crate::digest(chain),"private_key":"not_exposed"}),
    )
}
