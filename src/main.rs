use anyhow::{Result, ensure};
use clap::{Parser, Subcommand};
use kagnode_proxy_manager as proxy;
use std::path::PathBuf;
#[derive(Parser)]
#[command(
    version,
    about = "KagNode. Proxy Manager — native fleet, reverse and forward proxy management"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Init {
        #[arg(long, default_value = "/srv/kagnode/proxy-manager/controller")]
        root: PathBuf,
        #[arg(long)]
        email: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        public_url: String,
        #[arg(long)]
        fleet_url: String,
    },
    Serve {
        #[arg(long, default_value = "/srv/kagnode/proxy-manager/controller")]
        root: PathBuf,
        #[arg(long, default_value = "127.0.0.1:9443")]
        bind: std::net::SocketAddr,
        #[arg(long, default_value = "0.0.0.0:9444")]
        fleet_bind: std::net::SocketAddr,
        #[arg(long)]
        behind_proxy: bool,
    },
    Enroll {
        #[arg(long, default_value = "/srv/kagnode/proxy-manager/agent")]
        root: PathBuf,
        #[arg(long)]
        controller: String,
        #[arg(long)]
        ca: PathBuf,
    },
    EnrollLocal {
        #[arg(long)]
        controller_root: PathBuf,
        #[arg(long)]
        agent_root: PathBuf,
        #[arg(long)]
        name: String,
    },
    Agent {
        #[arg(long, default_value = "/srv/kagnode/proxy-manager/agent")]
        root: PathBuf,
    },
    Broker {
        #[arg(long, default_value = "/srv/kagnode/proxy-manager/traffic")]
        root: PathBuf,
        #[arg(long, default_value = "/run/kagnode-proxy-manager/broker.sock")]
        socket: PathBuf,
        #[arg(long)]
        agent_uid: u32,
    },
    PackagePreview {
        names: Vec<String>,
    },
    TrafficPrepare {
        #[arg(long, default_value = "/srv/kagnode/proxy-manager/traffic")]
        root: PathBuf,
    },
    ImportPreview {
        file: PathBuf,
    },
    Tunnel {
        #[arg(long)]
        server: String,
        #[arg(long, default_value = "127.0.0.1:1081")]
        listen: std::net::SocketAddr,
        #[arg(long)]
        username: String,
        #[arg(long, default_value = "/etc/ssl/certs/ca-certificates.crt")]
        ca: PathBuf,
    },
}
fn secret_stdin() -> Result<zeroize::Zeroizing<String>> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().take(4096).read_to_string(&mut input)?;
    Ok(zeroize::Zeroizing::new(
        input.trim_end_matches(['\r', '\n']).into(),
    ))
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    match Cli::parse().command {
        Command::Init {
            root,
            email,
            name,
            public_url,
            fleet_url,
        } => {
            use std::os::unix::fs::PermissionsExt;
            let origin = url::Url::parse(&public_url)?;
            let fleet = url::Url::parse(&fleet_url)?;
            ensure!(
                origin.scheme() == "https"
                    || origin
                        .host_str()
                        .is_some_and(|h| h == "127.0.0.1" || h == "localhost"),
                "Use HTTPS for management"
            );
            ensure!(
                fleet.scheme() == "https"
                    && fleet.path() == "/"
                    && fleet.query().is_none()
                    && fleet.fragment().is_none(),
                "Use an HTTPS fleet origin"
            );
            ensure!(
                origin.path() == "/"
                    && origin.query().is_none()
                    && origin.fragment().is_none()
                    && origin.username().is_empty()
                    && fleet.username().is_empty(),
                "Use website origins without credentials or paths"
            );
            std::fs::create_dir_all(&root)?;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
            let store = proxy::store::Store::open(&root)?;
            let count: i64 =
                store
                    .db
                    .lock()
                    .unwrap()
                    .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
            ensure!(
                count == 0,
                "Already initialized; use account recovery instead of resetting data"
            );
            let password = secret_stdin()?;
            proxy::auth::create_user(&store, &email, &name, &password, proxy::domain::Role::Owner)?;
            proxy::tls::init_ca(&root, fleet.host_str().unwrap()).await?;
            proxy::private_write(
                &root.join("controller.json"),
                &serde_json::to_vec_pretty(
                    &serde_json::json!({"public_url":origin.origin().ascii_serialization(),"fleet_url":fleet.origin().ascii_serialization()}),
                )?,
            )?;
            println!(
                "Controller initialized. Owner created; no listener, proxy, firewall or package change was started."
            );
        }
        Command::Serve {
            root,
            bind,
            fleet_bind,
            behind_proxy,
        } => {
            let config: serde_json::Value =
                serde_json::from_slice(&std::fs::read(root.join("controller.json"))?)?;
            let origin = config["public_url"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing public origin"))?
                .to_string();
            ensure!(
                !behind_proxy || bind.ip().is_loopback(),
                "The plaintext management listener must stay on loopback"
            );
            ensure!(
                behind_proxy || origin.starts_with("https:") || bind.ip().is_loopback(),
                "Public management requires TLS"
            );
            let store = proxy::store::Store::open(&root)?;
            let state =
                proxy::web::App::new(store, origin, config["fleet_url"].as_str().unwrap().into());
            let fleet = tokio::net::TcpListener::bind(fleet_bind).await?;
            let management = tokio::net::TcpListener::bind(bind).await?;
            let pki = root.join("pki");
            let fleet_app = proxy::web::fleet_router(state.clone());
            let cert = pki.join("server.pem");
            let key = pki.join("server.key");
            let ca = pki.join("ca.pem");
            println!("Management listening on {bind}; fleet mutual TLS on {fleet_bind}");
            let app = proxy::web::router(state);
            let management_service = async {
                if behind_proxy {
                    axum::serve(management, app)
                        .with_graceful_shutdown(async {
                            let _ = tokio::signal::ctrl_c().await;
                        })
                        .await?;
                } else {
                    proxy::tls::serve(management, app, &cert, &key, None).await?;
                }
                Ok::<(), anyhow::Error>(())
            };
            tokio::try_join!(
                proxy::tls::serve(fleet, fleet_app, &cert, &key, Some(&ca)),
                management_service
            )?;
        }

        Command::Enroll {
            root,
            controller,
            ca,
        } => {
            let token = secret_stdin()?;
            proxy::agent::enroll(&root, &controller, &token, &ca).await?;
            println!(
                "Agent enrolled; credential files are private. No traffic or package operation was applied."
            );
        }
        Command::Agent { root } => {
            let config = serde_json::from_slice(&std::fs::read(root.join("agent.json"))?)?;
            proxy::agent::run(config).await?;
        }
        Command::EnrollLocal {
            controller_root,
            agent_root,
            name,
        } => {
            ensure!(
                unsafe { libc::geteuid() } == 0,
                "Local enrollment is reserved for native root setup"
            );
            ensure!(
                !agent_root.join("agent.json").exists()
                    && !name.trim().is_empty()
                    && name.len() <= 80,
                "Agent already enrolled or invalid server name"
            );
            let config: serde_json::Value =
                serde_json::from_slice(&std::fs::read(controller_root.join("controller.json"))?)?;
            std::fs::create_dir_all(&agent_root)?;
            let key = agent_root.join("agent.key");
            let csr = agent_root.join("agent.csr");
            proxy::tls::command(
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
                    "/CN=KagNode Local Proxy Agent",
                ],
            )
            .await?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
            let (cert, fingerprint) =
                proxy::tls::issue_agent(&controller_root, &std::fs::read_to_string(&csr)?).await?;
            let id = proxy::random();
            let store = proxy::store::Store::open(&controller_root)?;
            store.db.lock().unwrap().execute(
                "INSERT INTO servers(id,name,fingerprint) VALUES(?,?,?)",
                rusqlite::params![id, name, fingerprint],
            )?;
            proxy::private_write(&agent_root.join("agent.pem"), cert.as_bytes())?;
            proxy::private_write(
                &agent_root.join("ca.pem"),
                &std::fs::read(controller_root.join("pki/ca.pem"))?,
            )?;
            let agent = proxy::agent::AgentConfig {
                id: id.clone(),
                controller: config["fleet_url"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing fleet origin"))?
                    .into(),
                broker_socket: "/run/kagnode-proxy-manager/broker.sock".into(),
                root: agent_root,
            };
            proxy::private_write(
                &agent.root.join("agent.json"),
                &serde_json::to_vec_pretty(&agent)?,
            )?;
            store.audit(
                "native-root-setup",
                "agent.enroll.local",
                &id,
                serde_json::json!({}),
            )?;
            println!(
                "Local agent enrolled without exposing its certificate key or enrollment token."
            );
        }
        Command::Broker {
            root,
            socket,
            agent_uid,
        } => proxy::broker::serve(root, socket, agent_uid).await?,
        Command::PackagePreview { names } => println!(
            "{}",
            serde_json::to_string_pretty(&proxy::packages::native_preview(names).await?)?
        ),
        Command::TrafficPrepare { root } => proxy::traffic::prepare_selected(&root).await?,
        Command::ImportPreview { file } => {
            let metadata = std::fs::symlink_metadata(&file)?;
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() < 4 * 1024 * 1024,
                "Choose a regular bounded configuration file"
            );
            let data = serde_json::from_slice(&std::fs::read(file)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&proxy::migration::preview(&data)?)?
            );
        }
        Command::Tunnel {
            server,
            listen,
            username,
            ca,
        } => {
            let password = secret_stdin()?;
            proxy::forward::tunnel(&server, listen, &username, password, &ca).await?;
        }
    }
    Ok(())
}
