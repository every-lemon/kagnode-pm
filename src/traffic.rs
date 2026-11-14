//! Only generated engine units and reviewed traffic generations are executable.
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
pub fn identity(name: &str) -> Result<(u32, u32)> {
    let passwd = std::fs::read_to_string("/etc/passwd")?;
    let line = passwd
        .lines()
        .find(|l| l.split(':').next() == Some(name))
        .ok_or_else(|| anyhow::anyhow!("Required service identity {name} is not installed"))?;
    let p: Vec<_> = line.split(':').collect();
    ensure!(p.len() >= 4, "Invalid service identity");
    Ok((p[2].parse()?, p[3].parse()?))
}
pub fn trusted_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    ensure!(path.is_absolute(), "Runtime directory must be absolute");
    let mut current = PathBuf::from("/");
    for part in path.components() {
        use std::path::Component;
        match part {
            Component::RootDir => continue,
            Component::Normal(p) => current.push(p),
            _ => anyhow::bail!("Unsafe runtime path"),
        };
        let m = std::fs::symlink_metadata(&current)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.uid() == 0
                && (m.mode() & 0o022 == 0
                    || (current == Path::new("/tmp") && m.mode() & 0o1000 != 0)),
            "Runtime ancestors must be protected root-owned directories"
        );
    }
    Ok(())
}
pub fn readable_by_traffic(path: &Path, directory: bool) -> Result<()> {
    let (_, gid) = identity("kn-proxy-traffic")?;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let value = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    ensure!(
        unsafe { libc::chown(value.as_ptr(), 0, gid) } == 0,
        "Could not set traffic ownership"
    );
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if directory { 0o750 } else { 0o640 }),
    )?;
    Ok(())
}
pub fn engine() -> Result<&'static str> {
    for file in [
        "/usr/libexec/kagnode-proxy-manager/3proxy",
        "/usr/bin/3proxy",
        "/usr/local/bin/3proxy",
    ] {
        if Path::new(file).is_file() {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::symlink_metadata(file)?;
            ensure!(
                m.uid() == 0 && m.mode() & 0o022 == 0 && !m.file_type().is_symlink(),
                "Forward engine must be protected"
            );
            return Ok(file);
        }
    }
    anyhow::bail!("The verified forward engine is not installed")
}
pub fn unit_name(generation: &str, id: &str) -> Result<String> {
    crate::domain::ident(generation)?;
    crate::domain::ident(id)?;
    Ok(format!(
        "kn-proxy-forward-{}-{id}.service",
        &generation[..generation.len().min(16)]
    ))
}
pub async fn start_forward(root: &Path, generation: &str, id: &str) -> Result<String> {
    let unit = unit_name(generation, id)?;
    if tokio::process::Command::new("/usr/bin/systemctl")
        .args(["is-active", "--quiet", &unit])
        .status()
        .await?
        .success()
    {
        return Ok(unit);
    }
    let dir = root.join("generations").join(generation);
    trusted_directory(&dir)?;
    readable_by_traffic(root, true)?;
    readable_by_traffic(&root.join("generations"), true)?;
    readable_by_traffic(&dir, true)?;
    let config = dir.join(format!("forward-{id}.cfg"));
    readable_by_traffic(&config, false)?;
    crate::tls::command(
        "/usr/bin/systemd-run",
        &[
            "--quiet",
            "--collect",
            "--no-block",
            "--unit",
            &unit,
            "--property=User=kn-proxy-traffic",
            "--property=Group=kn-proxy-traffic",
            "--property=NoNewPrivileges=yes",
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=yes",
            "--property=PrivateTmp=yes",
            "--property=MemoryHigh=48M",
            "--property=MemoryMax=64M",
            "--property=TasksMax=1024",
            &format!("--property=ReadWritePaths={}/counters", root.display()),
            engine()?,
            config.to_str().unwrap(),
        ],
    )
    .await?;
    for _ in 0..30 {
        let output = tokio::process::Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", &unit])
            .output()
            .await?;
        if output.status.success() {
            return Ok(unit);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    anyhow::bail!("Forward engine did not become active; candidate was not published")
}
pub async fn stop_forward(unit: &str) -> Result<()> {
    ensure!(
        unit.starts_with("kn-proxy-forward-")
            && unit.ends_with(".service")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-".contains(&b)),
        "Unexpected forward unit"
    );
    crate::tls::command("/usr/bin/systemctl", &["stop", unit]).await?;
    Ok(())
}
pub async fn configure(
    root: &Path,
    resources: &[(String, crate::domain::Resource)],
) -> Result<Value> {
    use crate::domain::Resource;
    ensure!(resources.len() <= 250, "Too many proxy resources");
    std::fs::create_dir_all(root)?;
    trusted_directory(root)?;
    readable_by_traffic(root, true)?;
    ensure!(
        !root.join("activation.json").exists(),
        "An interrupted activation requires reconciliation"
    );
    let generation = crate::random();
    let dir = root.join("generations").join(&generation);
    std::fs::create_dir_all(&dir)?;
    for d in [
        "run",
        "logs",
        "cache",
        "auth",
        "certificates",
        "counters",
        "tmp/client_body",
        "tmp/proxy",
        "acme/challenges/.well-known/acme-challenge",
    ] {
        std::fs::create_dir_all(root.join(d))?;
    }
    for path in [
        "acme",
        "acme/challenges",
        "acme/challenges/.well-known",
        "acme/challenges/.well-known/acme-challenge",
    ] {
        readable_by_traffic(&root.join(path), true)?;
    }
    let (uid, gid) = identity("kn-proxy-traffic")?;
    for path in [
        root.join("counters"),
        root.join("cache"),
        root.join("tmp"),
        root.join("tmp/client_body"),
        root.join("tmp/proxy"),
    ] {
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Unexpected traffic storage path"
        );
        let value = std::ffi::CString::new(path.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::chown(value.as_ptr(), uid, gid) } == 0,
            "Could not set private traffic storage ownership"
        );
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let base = root
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Invalid runtime path"))?;
    let mut http =
        String::from("map $http_upgrade $kn_connection_upgrade { default upgrade; '' close; }\n");
    let mut stream = String::new();
    let mut ports = std::collections::BTreeSet::new();
    let mut domains = std::collections::BTreeSet::new();
    let mut forwards = vec![];
    for (id, resource) in resources {
        crate::domain::ident(id)?;
        resource.validate()?;
        match resource {
            Resource::ProxyHost(host) => {
                for name in &host.domains {
                    ensure!(
                        domains.insert(name.to_lowercase()),
                        "Multiple resources claim the same domain; combine their routes before publishing"
                    );
                }
                http.push_str(&resource.nginx(id, base)?);
            }
            Resource::Stream(s) => {
                ensure!(ports.insert(s.listen), "Conflicting listeners");
                stream.push_str(&resource.nginx(id, base)?);
            }
            Resource::ForwardProxy(f) => {
                ensure!(ports.insert(f.listen), "Conflicting listeners");
                let internal = 20000
                    + u16::from_str_radix(&crate::digest(format!("{generation}-{id}"))[..4], 16)?
                        % 20000;
                ensure!(
                    ports.insert(format!("127.0.0.1:{internal}").parse()?),
                    "Internal listener collision; retry this preview"
                );
                let (config, front) = crate::forward::render(id, f, base, internal)?;
                let auth = root.join("auth").join(format!("{}.3proxy", f.user_group));
                ensure!(
                    auth.is_file() && std::fs::metadata(&auth)?.len() > 0,
                    "Forward credential group must contain an approved user before activation"
                );
                crate::private_write(&dir.join(format!("forward-{id}.cfg")), config.as_bytes())?;
                readable_by_traffic(&root.join("auth"), true)?;
                readable_by_traffic(&auth, false)?;
                stream.push_str(&front);
                forwards.push((id.clone(), internal));
            }
        }
    }
    let module = if stream.is_empty() {
        ""
    } else {
        ensure!(
            Path::new("/usr/lib/nginx/modules/ngx_stream_module.so").is_file(),
            "Install the Nginx stream module before activation"
        );
        "load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n"
    };
    let config = format!(
        "{module}user kn-proxy-traffic;\nworker_processes 1;\npid {base}/run/nginx.pid;\nerror_log {base}/logs/error.log warn;\nevents {{worker_connections 1024;}}\nhttp {{server_tokens off;access_log off;keepalive_timeout 30;client_body_temp_path {base}/tmp/client_body;proxy_temp_path {base}/tmp/proxy;proxy_buffer_size 8k;proxy_buffers 4 8k;{http}}}\n{}",
        if stream.is_empty() {
            String::new()
        } else {
            format!("stream {{{stream}}}")
        }
    );
    crate::private_write(&dir.join("nginx.conf"), config.as_bytes())?;
    let validation = crate::tls::command(
        "/usr/sbin/nginx",
        &[
            "-t",
            "-p",
            base,
            "-c",
            dir.join("nginx.conf").to_str().unwrap(),
        ],
    )
    .await;
    if let Err(error) = validation {
        return Ok(
            json!({"state":"rejected","phase":"validation","traffic_unchanged":true,"error":error.to_string()}),
        );
    }
    let current = root.join("current");
    let previous = std::fs::read_link(&current).ok();
    let mut units = vec![];
    crate::private_write(
        &root.join("activation.json"),
        &serde_json::to_vec(
            &json!({"generation":generation,"previous":previous,"phase":"validated","units":units}),
        )?,
    )?;
    // Persist boot preparation before switching the selected generation.
    crate::private_write(
        &dir.join("generation.json"),
        &serde_json::to_vec(
            &json!({"generation":generation,"forwards":forwards,"resources":resources,"created":crate::now()}),
        )?,
    )?;
    let result:Result<()>=async{for(id,port)in&forwards{let unit=start_forward(root,&generation,id).await?;units.push(unit);crate::private_write(&root.join("activation.json"),&serde_json::to_vec(&json!({"generation":generation,"previous":previous,"phase":"engines_started","units":units}))?)?;let mut alive=false;for _ in 0..20{if tokio::net::TcpStream::connect(("127.0.0.1",*port)).await.is_ok(){alive=true;break}tokio::time::sleep(std::time::Duration::from_millis(100)).await;}ensure!(alive,"Forward listener did not pass local readiness");}
 let next=root.join(".next");ensure!(!next.exists()&&!next.is_symlink(),"Activation link requires reconciliation");std::os::unix::fs::symlink(&dir,&next)?;std::fs::rename(next,&current)?;crate::tls::command("/usr/bin/systemctl",&["reload-or-restart","kagnode-proxy-traffic.service"]).await?;crate::tls::command("/usr/bin/systemctl",&["is-active","--quiet","kagnode-proxy-traffic.service"]).await?;Ok(())}.await;
    if let Err(error) = result {
        if let Some(ref old) = previous {
            let restore = root.join(".rollback");
            if !restore.exists() && !restore.is_symlink() {
                std::os::unix::fs::symlink(old, &restore)?;
                std::fs::rename(restore, &current)?;
                let _ = crate::tls::command(
                    "/usr/bin/systemctl",
                    &["reload-or-restart", "kagnode-proxy-traffic.service"],
                )
                .await;
            }
        }
        for unit in &units {
            let _ = stop_forward(unit).await;
        }
        return Err(anyhow::anyhow!(
            "Candidate activation failed; recovery journal retained: {error}"
        ));
    }
    crate::tls::command(
        "/usr/bin/systemctl",
        &["enable", "kagnode-proxy-traffic.service"],
    )
    .await?;
    crate::private_write(
        &root.join("last-activation.json"),
        &serde_json::to_vec(
            &json!({"generation":generation,"previous":previous,"state":"active"}),
        )?,
    )?;
    std::fs::remove_file(root.join("activation.json"))?;
    Ok(
        json!({"generation":generation,"state":"active","previous":previous,"forward_units":units,"health":"Configuration and local service readiness verified; external reachability is separate."}),
    )
}
pub fn write_forward_user(root: &Path, group: &str, username: &str, password: &str) -> Result<()> {
    crate::domain::ident(group)?;
    ensure!(
        !username.is_empty()
            && username.len() <= 64
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "Invalid proxy username"
    );
    ensure!(
        (16..=128).contains(&password.len())
            && password
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-!@%+=:".contains(&b)),
        "Use a 16–128 character proxy password without whitespace, quotes or macros"
    );
    let path = root.join("auth").join(format!("{group}.3proxy"));
    let mut entries = if path.is_file() {
        std::fs::read_to_string(&path)?
            .split_whitespace()
            .map(String::from)
            .collect::<Vec<_>>()
    } else {
        vec![]
    };
    entries.retain(|v| v.split(':').next() != Some(username));
    entries.push(format!("{username}:CL:{password}"));
    ensure!(entries.len() <= 256, "Credential group is full");
    crate::private_write(&path, (entries.join(" ") + "\n").as_bytes())?;
    readable_by_traffic(path.parent().unwrap(), true)?;
    readable_by_traffic(&path, false)?;
    Ok(())
}
pub async fn prepare_selected(root: &Path) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Traffic preparation requires the native root service"
    );
    trusted_directory(root)?;
    let selected = std::fs::read_link(root.join("current"))?;
    ensure!(
        selected.parent() == Some(root.join("generations").as_path()),
        "Unexpected selected traffic path"
    );
    let generation = selected
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid selected generation"))?;
    crate::domain::ident(generation)?;
    trusted_directory(&selected)?;
    let path = selected.join("generation.json");
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && meta.len() < 1024 * 1024,
        "Unsafe traffic manifest"
    );
    let value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    ensure!(
        value["generation"] == generation,
        "Traffic manifest does not match selected generation"
    );
    let forwards: Vec<(String, u16)> = serde_json::from_value(value["forwards"].clone())?;
    ensure!(forwards.len() <= 16, "Forward listener limit exceeded");
    for (id, port) in forwards {
        ensure!(
            (20000..40000).contains(&port),
            "Invalid private engine listener"
        );
        start_forward(root, generation, &id).await?;
    }
    Ok(())
}
