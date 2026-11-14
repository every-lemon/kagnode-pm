use crate::{domain::Resource, packages::RemovalPlan};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    PackagePreview {
        names: Vec<String>,
    },
    PackageRemove {
        plan: RemovalPlan,
    },
    Configure {
        resources: Vec<(String, Resource)>,
    },
    CertificateIssue {
        request: crate::certificates::Request,
    },
    CertificateInventory {},
    CertificateUpload {
        upload: crate::certificates::Upload,
    },
    CertificateActivate {
        id: String,
        version: String,
        expected_sha256: String,
    },
    Status {},
    Discover {},
    ReviewImport {
        fingerprint: String,
        selected: Vec<String>,
    },
    Reconcile {},
}
pub async fn request(socket: &Path, operation: &Operation) -> Result<Value> {
    let stream = tokio::net::UnixStream::connect(socket).await?;
    let (read, mut write) = stream.into_split();
    let mut bytes = serde_json::to_vec(operation)?;
    ensure!(bytes.len() < 65536, "Operation too large");
    bytes.push(b'\n');
    write.write_all(&bytes).await?;
    let mut data = Vec::new();
    let mut reader = tokio::io::BufReader::new(read).take(1024 * 1024);
    tokio::time::timeout(
        std::time::Duration::from_secs(1800),
        reader.read_until(b'\n', &mut data),
    )
    .await??;
    let response: Value = serde_json::from_slice(&data)?;
    ensure!(
        response["ok"] == true,
        "{}",
        response["error"]
            .as_str()
            .unwrap_or("Local operation failed")
    );
    Ok(response["result"].clone())
}
use tokio::io::AsyncReadExt;
struct Active(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
pub async fn serve(root: PathBuf, socket: PathBuf, agent_uid: u32) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "The restricted helper must run as root"
    );
    let parent = socket
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Missing socket parent"))?;
    std::fs::create_dir_all(parent)?;
    crate::traffic::trusted_directory(parent)?;
    let inherited = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        == Some(std::process::id())
        && std::env::var("LISTEN_FDS").ok().as_deref() == Some("1");
    let listener = if inherited {
        use std::os::fd::FromRawFd;
        let native = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
        native.set_nonblocking(true)?;
        tokio::net::UnixListener::from_std(native)?
    } else {
        ensure!(
            !socket.exists() && !socket.is_symlink(),
            "Helper socket already exists; reconcile its service"
        );
        let listener = tokio::net::UnixListener::bind(&socket)?;
        let passwd = std::fs::read_to_string("/etc/passwd")?;
        let gid = passwd
            .lines()
            .find_map(|l| {
                let p: Vec<_> = l.split(':').collect();
                (p.len() >= 4 && p[2].parse::<u32>().ok() == Some(agent_uid))
                    .then(|| p[3].parse::<u32>().ok())
                    .flatten()
            })
            .ok_or_else(|| anyhow::anyhow!("Agent identity does not exist"))?;
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
        let value = std::ffi::CString::new(socket.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::chown(value.as_ptr(), 0, gid) } == 0,
            "Could not set socket group"
        );
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660))?;
        listener
    };
    let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    loop {
        let connection =
            tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept()).await;
        let (stream, _) = match connection {
            Ok(value) => value?,
            Err(_) => {
                if active.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                    break;
                } else {
                    continue;
                }
            }
        };
        if stream.peer_cred()?.uid() != agent_uid {
            continue;
        }
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let root = root.clone();
        let lock = lock.clone();
        active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let guard = Active(active.clone());
        tokio::spawn(async move {
            let _active = guard;
            let _permit = permit;
            let mut reader = tokio::io::BufReader::new(stream).take(65537);
            let mut bytes = Vec::new();
            if !matches!(
                tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    reader.read_until(b'\n', &mut bytes)
                )
                .await,
                Ok(Ok(_))
            ) || bytes.len() > 65536
            {
                return;
            }
            let operation = serde_json::from_slice::<Operation>(&bytes);
            let result = match operation {
                Ok(op) => {
                    let _guard = lock.lock().await;
                    execute(&root, op).await
                }
                Err(e) => Err(e.into()),
            };
            let value = match result {
                Ok(result) => json!({"ok":true,"result":result}),
                Err(error) => json!({"ok":false,"error":error.to_string()}),
            };
            let mut bytes = serde_json::to_vec(&value).unwrap();
            bytes.push(b'\n');
            let _ = reader.get_mut().get_mut().write_all(&bytes).await;
        });
    }
    drop(listener);
    if !inherited {
        std::fs::remove_file(socket)?;
    }
    Ok(())
}
pub async fn execute(root: &Path, operation: Operation) -> Result<Value> {
    match operation {
        Operation::PackagePreview { names } => Ok(serde_json::to_value(
            crate::packages::native_preview(names).await?,
        )?),
        Operation::PackageRemove { plan } => {
            let capability = Path::new("/etc/kagnode/proxy-manager/allow-package-removal");
            crate::traffic::trusted_directory(capability.parent().unwrap())?;
            use std::os::unix::fs::MetadataExt;
            let capability = std::fs::symlink_metadata(capability)?;
            ensure!(
                capability.is_file()
                    && !capability.file_type().is_symlink()
                    && capability.uid() == 0
                    && capability.mode() & 0o022 == 0,
                "Local package-removal capability is disabled or untrusted"
            );
            ensure!(
                plan.created_at <= crate::now() + 5 && crate::now() - plan.created_at <= 300,
                "Package approval expired; obtain a fresh preview"
            );
            crate::traffic::trusted_directory(root)?;
            let journal = root.join("package-operation.json");
            ensure!(
                !journal.exists(),
                "An interrupted package operation requires local reconciliation; it cannot be replayed"
            );
            ensure!(
                plan.blockers.is_empty(),
                "Removal contains protected packages"
            );
            let fresh = crate::packages::native_preview(plan.requested.clone()).await?;
            ensure!(
                fresh.confirmation == plan.confirmation && fresh.blockers.is_empty(),
                "Package plan changed; review again"
            );
            ensure!(
                unsafe { libc::geteuid() } == 0,
                "Package removal requires the local root helper"
            );
            let request = json!({"requested":plan.requested,"removals":plan.removals,"fingerprint":plan.fingerprint,"approved":true});
            let script = crate::packages::transaction_script()?;
            crate::private_write(
                &journal,
                &serde_json::to_vec(
                    &json!({"phase":"starting","confirmation":plan.confirmation,"request":request,"started":crate::now()}),
                )?,
            )?;
            let mut child = tokio::process::Command::new("/usr/bin/python3")
                .arg("-I")
                .arg(script)
                .arg("apply")
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .env("LC_ALL", "C")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&serde_json::to_vec(&request)?)
                .await?;
            // Do not kill an in-progress dpkg transaction when the browser disconnects.
            let stdout = child.stdout.take().unwrap();
            let stderr = child.stderr.take().unwrap();
            let (status, stdout, stderr) =
                tokio::join!(child.wait(), drain(stdout, 65536), drain(stderr, 8192));
            let (status, stdout, stderr) = (status?, stdout?, stderr?);
            ensure!(
                status.success(),
                "Package transaction needs review: {}",
                String::from_utf8_lossy(&stderr)
                    .chars()
                    .take(1000)
                    .collect::<String>()
            );
            let result: Value = serde_json::from_slice(&stdout)?;
            ensure!(
                result["completed"] == true,
                "Package transaction did not confirm completion"
            );
            crate::private_write(
                &root.join("last-package-operation.json"),
                &serde_json::to_vec(
                    &json!({"confirmation":plan.confirmation,"result":result,"completed":crate::now()}),
                )?,
            )?;
            std::fs::remove_file(journal)?;
            std::fs::File::open(root)?.sync_all()?;
            Ok(result)
        }
        Operation::Discover {} => discovery_worker("discover", json!({})).await,
        Operation::ReviewImport {
            fingerprint,
            selected,
        } => {
            discovery_worker(
                "review",
                json!({"fingerprint":fingerprint,"selected":selected}),
            )
            .await
        }
        Operation::Configure { resources } => activate(root, &resources).await,
        Operation::CertificateIssue { request } => crate::certificates::issue(root, request).await,
        Operation::CertificateActivate {
            id,
            version,
            expected_sha256,
        } => crate::certificates::activate_uploaded(root, &id, &version, &expected_sha256).await,
        Operation::CertificateUpload { upload } => crate::certificates::upload(root, upload).await,
        Operation::CertificateInventory {} => crate::certificates::inventory(root).await,
        Operation::Status {} => Ok(
            json!({"current":std::fs::read_link(root.join("current")).ok().map(|p|p.to_string_lossy().to_string()),"pending":root.join("activation.json").exists() || root.join("certificate-activation.json").exists(),"package_recovery_required":root.join("package-operation.json").exists(),"last_package_receipt":std::fs::read(root.join("last-package-operation.json")).ok().and_then(|v|serde_json::from_slice::<Value>(&v).ok())}),
        ),
        Operation::Reconcile {} => {
            if !root.join("activation.json").exists() {
                return Ok(json!({"required":false}));
            }
            let journal: Value =
                serde_json::from_slice(&std::fs::read(root.join("activation.json"))?)?;
            Ok(
                json!({"required":true,"journal":journal,"message":"Check traffic health and choose explicit rollback or completion; an interrupted activation is never replayed."}),
            )
        }
    }
}
async fn drain(reader: impl tokio::io::AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut reader = reader;
    let mut out = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let keep = read.min(limit.saturating_sub(out.len()));
        out.extend_from_slice(&buffer[..keep]);
    }
    Ok(out)
}
pub async fn activate(root: &Path, resources: &[(String, Resource)]) -> Result<Value> {
    crate::traffic::configure(root, resources).await
}

async fn discovery_worker(action: &str, input: Value) -> Result<Value> {
    let source = if cfg!(debug_assertions) {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/discover_config.py")
    } else {
        PathBuf::from("/usr/libexec/kagnode-proxy-manager/discover_config.py")
    };
    crate::traffic::trusted_directory(source.parent().unwrap())?;
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(&source)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0,
        "Untrusted discovery helper"
    );
    let mut child = tokio::process::Command::new("/usr/bin/python3")
        .arg("-I")
        .arg(source)
        .arg(action)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(&input)?)
        .await?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (status, out, err) = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        tokio::join!(child.wait(), drain(stdout, 65537), drain(stderr, 2000))
    })
    .await?;
    ensure!(
        status?.success(),
        "Discovery needs review: {}",
        String::from_utf8_lossy(&err?)
    );
    let bytes = out?;
    ensure!(
        bytes.len() <= 65536,
        "Discovery report exceeds the supported limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
