use anyhow::{Result, ensure};
use axum::{Extension, Router};
use std::{io::BufReader, path::Path, sync::Arc};
use tokio::net::TcpListener;
#[derive(Clone)]
pub struct Peer {
    pub fingerprint: String,
}
pub async fn command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .kill_on_drop(true)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C");
    let output = tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output()).await??;
    ensure!(
        output.status.success(),
        "{} failed: {}",
        program,
        String::from_utf8_lossy(&output.stderr)
            .chars()
            .take(1500)
            .collect::<String>()
    );
    ensure!(
        output.stdout.len() <= 1024 * 1024,
        "Command output exceeded limit"
    );
    Ok(output.stdout)
}
pub async fn init_ca(root: &Path, name: &str) -> Result<()> {
    crate::domain::hostname(name)?;
    let dir = root.join("pki");
    std::fs::create_dir_all(&dir)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    ensure!(
        !dir.join("ca.key").exists(),
        "Fleet authority already exists"
    );
    let ca_key = dir.join("ca.key");
    let ca = dir.join("ca.pem");
    command(
        "/usr/bin/openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            ca_key.to_str().unwrap(),
            "-out",
            ca.to_str().unwrap(),
            "-days",
            "3650",
            "-subj",
            "/CN=KagNode Proxy Fleet Authority",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    )
    .await?;
    let key = dir.join("server.key");
    let csr = dir.join("server.csr");
    command(
        "/usr/bin/openssl",
        &[
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            csr.to_str().unwrap(),
            "-subj",
            "/CN=KagNode Proxy Fleet",
        ],
    )
    .await?;
    let ext = dir.join("server.ext");
    let san = if name.parse::<std::net::IpAddr>().is_ok() {
        format!("IP:{name}")
    } else {
        format!("DNS:{name}")
    };
    crate::private_write(&ext,format!("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName={san},DNS:localhost,IP:127.0.0.1,IP:::1\n").as_bytes())?;
    command(
        "/usr/bin/openssl",
        &[
            "x509",
            "-req",
            "-in",
            csr.to_str().unwrap(),
            "-CA",
            ca.to_str().unwrap(),
            "-CAkey",
            ca_key.to_str().unwrap(),
            "-set_serial",
            &format!("0x{}", &crate::random()[..30]),
            "-out",
            dir.join("server.pem").to_str().unwrap(),
            "-days",
            "90",
            "-extfile",
            ext.to_str().unwrap(),
        ],
    )
    .await?;
    for file in [ca_key, key] {
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
pub async fn issue_agent(root: &Path, csr: &str) -> Result<(String, String)> {
    ensure!(
        csr.len() <= 16384 && csr.starts_with("-----BEGIN CERTIFICATE REQUEST-----"),
        "Invalid enrollment request"
    );
    let dir = root.join("pki").join(crate::random());
    std::fs::create_dir(&dir)?;
    let request = dir.join("agent.csr");
    crate::private_write(&request, csr.as_bytes())?;
    let result=async{command("/usr/bin/openssl",&["req","-in",request.to_str().unwrap(),"-verify","-noout"]).await?;let ext=dir.join("client.ext");crate::private_write(&ext,b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n")?;let output=dir.join("agent.pem");command("/usr/bin/openssl",&["x509","-req","-in",request.to_str().unwrap(),"-CA",root.join("pki/ca.pem").to_str().unwrap(),"-CAkey",root.join("pki/ca.key").to_str().unwrap(),"-set_serial",&format!("0x{}",&crate::random()[..30]),"-out",output.to_str().unwrap(),"-days","30","-extfile",ext.to_str().unwrap()]).await?;let cert=std::fs::read_to_string(output)?;let parsed=rustls_pemfile::certs(&mut BufReader::new(cert.as_bytes())).collect::<std::result::Result<Vec<_>,_>>()?;ensure!(parsed.len()==1,"Unexpected certificate chain");Ok((cert,crate::digest(parsed[0].as_ref())))}.await;
    let _ = std::fs::remove_dir_all(dir);
    result
}
pub async fn serve(
    listener: TcpListener,
    app: Router,
    cert: &Path,
    key: &Path,
    client_ca: Option<&Path>,
) -> Result<()> {
    use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key)?))?
        .ok_or_else(|| anyhow::anyhow!("Missing TLS private key"))?;
    let builder = ServerConfig::builder();
    let mut config = if let Some(ca) = client_ca {
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(ca)?)) {
            roots.add(cert?)?;
        }
        builder
            .with_client_cert_verifier(WebPkiClientVerifier::builder(Arc::new(roots)).build()?)
            .with_single_cert(certs, key)?
    } else {
        builder.with_no_client_auth().with_single_cert(certs, key)?
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let limit = Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(tls)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream))
                    .await
            else {
                return;
            };
            let fingerprint = tls
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map_or_else(String::new, |c| crate::digest(c.as_ref()));
            let service = hyper_util::service::TowerToHyperService::new(
                app.layer(Extension(Peer { fingerprint })),
            );
            let builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            let _ = builder
                .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(tls), service)
                .await;
        });
    }
}
