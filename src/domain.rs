use anyhow::{Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Administrator,
    Maintainer,
    Viewer,
}
impl Role {
    pub fn administer(&self) -> bool {
        matches!(self, Self::Owner | Self::Administrator)
    }
    pub fn write(&self) -> bool {
        !matches!(self, Self::Viewer)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub address: String,
    #[serde(default = "one")]
    pub weight: u16,
    #[serde(default)]
    pub backup: bool,
}
fn one() -> u16 {
    1
}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    #[default]
    RoundRobin,
    LeastConnections,
    IpHash,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyHost {
    pub domains: Vec<String>,
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub balance: Balance,
    #[serde(default = "default_path")]
    pub path: String,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default = "enabled")]
    pub force_https: bool,
    #[serde(default)]
    pub strip_prefix: bool,
    #[serde(default)]
    pub compression: bool,
    #[serde(default)]
    pub upstream_tls_name: Option<String>,
    #[serde(default)]
    pub upstream_client_certificate: Option<String>,
    #[serde(default)]
    pub client_ca: Option<String>,
    #[serde(default)]
    pub allowed_clients: Vec<IpNet>,
    #[serde(default)]
    pub authentication: Option<String>,
    #[serde(default)]
    pub websocket: bool,
    #[serde(default)]
    pub grpc: bool,
    #[serde(default)]
    pub redirect: Option<String>,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    #[serde(default = "upload_default")]
    pub max_body_mib: u16,
    #[serde(default = "timeout_default")]
    pub timeout_seconds: u16,
    #[serde(default)]
    pub rate_per_second: Option<u16>,
    #[serde(default)]
    pub cache_mib: Option<u16>,
}
fn default_path() -> String {
    "/".into()
}
fn enabled() -> bool {
    true
}
fn upload_default() -> u16 {
    16
}
fn timeout_default() -> u16 {
    60
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub listen: SocketAddr,
    pub upstream: SocketAddr,
    #[serde(default)]
    pub udp: bool,
    #[serde(default)]
    pub tls_passthrough: bool,
    #[serde(default)]
    pub allowed_clients: Vec<IpNet>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardProxy {
    pub listen: SocketAddr,
    pub protocol: ForwardProtocol,
    pub user_group: String,
    pub clients: Vec<IpNet>,
    #[serde(default)]
    pub destinations: Vec<IpNet>,
    #[serde(default)]
    pub public: bool,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default = "forward_limit")]
    pub max_connections: u16,
    #[serde(default = "default_ports")]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub bandwidth_kbps: Option<u32>,
    #[serde(default)]
    pub daily_mib: Option<u32>,
}
fn forward_limit() -> u16 {
    64
}
fn default_ports() -> Vec<u16> {
    vec![80, 443]
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ForwardProtocol {
    Https,
    Socks5Tls,
    Socks5Lan,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "settings", rename_all = "snake_case")]
pub enum Resource {
    ProxyHost(ProxyHost),
    Stream(Stream),
    ForwardProxy(ForwardProxy),
}
pub fn ident(s: &str) -> Result<()> {
    ensure!(
        !s.is_empty()
            && s.len() <= 64
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "Use a lowercase identifier of at most 64 letters, digits or hyphens"
    );
    Ok(())
}
pub fn hostname(s: &str) -> Result<String> {
    ensure!(
        s.len() <= 253 && !s.contains(['\n', '\r', ';', '{', '}', '\\', '/', '$', '\0']),
        "Invalid domain"
    );
    let (wild, host) = s.strip_prefix("*.").map_or((false, s), |h| (true, h));
    let ascii = url::Host::parse(host)?.to_string().to_lowercase();
    ensure!(
        ascii.split('.').all(|p| !p.is_empty()
            && p.len() <= 63
            && !p.starts_with('-')
            && !p.ends_with('-')
            && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "Invalid DNS name"
    );
    Ok(format!("{}{}", if wild { "*." } else { "" }, ascii))
}
pub fn safe_text(s: &str, max: usize) -> Result<()> {
    ensure!(
        s.len() <= max
            && !s
                .chars()
                .any(|c| c.is_control() || matches!(c, ';' | '{' | '}' | '$' | '"' | '\\')),
        "Unsafe configuration value"
    );
    Ok(())
}
pub fn private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_multicast()
                || v.octets()[0] == 0
                || v.octets()[0] >= 224
                || (v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1]))
                || (v.octets()[0] == 198 && matches!(v.octets()[1], 18 | 19))
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || v.is_unique_local()
                || v.is_unicast_link_local()
                || v.to_ipv4_mapped().is_some_and(|a| private_ip(a.into()))
        }
    }
}
fn private_network(net: &IpNet) -> bool {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]
    .iter()
    .any(|value| {
        let private: IpNet = value.parse().unwrap();
        private.contains(&net.network()) && net.prefix_len() >= private.prefix_len()
    })
}
impl Resource {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ProxyHost(p) => {
                ensure!(
                    !p.domains.is_empty() && p.domains.len() <= 32,
                    "Choose 1–32 domains"
                );
                for h in &p.domains {
                    hostname(h)?;
                }
                ensure!(
                    !p.upstreams.is_empty() && p.upstreams.len() <= 32,
                    "Choose 1–32 upstreams"
                );
                for u in &p.upstreams {
                    let uri = url::Url::parse(&u.address)?;
                    ensure!(
                        matches!(uri.scheme(), "http" | "https")
                            && uri.host_str().is_some()
                            && uri.username().is_empty()
                            && uri.password().is_none()
                            && uri.path() == "/"
                            && uri.query().is_none()
                            && uri.fragment().is_none(),
                        "Use an HTTP(S) upstream origin"
                    );
                    safe_text(&u.address, 300)?;
                    ensure!((1..=100).contains(&u.weight), "Weight must be 1–100");
                }
                ensure!(
                    p.path.starts_with('/')
                        && p.path.len() <= 2048
                        && !p
                            .path
                            .contains([' ', '"', ';', '{', '}', '\\', '$', '\n', '\r']),
                    "Use a literal route path"
                );
                ensure!(
                    p.max_body_mib <= 1024 && (1..=3600).contains(&p.timeout_seconds),
                    "Upload or timeout exceeds limits"
                );
                ensure!(
                    p.cache_mib.is_none_or(|n| (1..=4096).contains(&n)),
                    "Cache quota must be 1–4096 MiB"
                );
                ensure!(!(p.grpc && p.websocket), "Choose gRPC or WebSocket mode");
                ensure!(
                    !p.grpc
                        || (p.certificate.is_some() && p.cache_mib.is_none() && !p.strip_prefix),
                    "gRPC requires an HTTP/2 TLS listener without HTTP cache or prefix rewriting"
                );
                ensure!(
                    !p.upstreams.iter().all(|u| u.backup),
                    "At least one primary upstream is required"
                );
                ensure!(
                    !matches!(p.balance, Balance::IpHash) || p.upstreams.iter().all(|u| !u.backup),
                    "IP-hash balancing cannot use backup peers"
                );
                if let Some(name) = &p.upstream_tls_name {
                    ensure!(!name.starts_with("*."), "Use a concrete upstream TLS name");
                    hostname(name)?;
                }
                for s in [&p.certificate, &p.client_ca, &p.authentication]
                    .into_iter()
                    .flatten()
                {
                    ident(s)?;
                }
                if let Some(c) = &p.upstream_client_certificate {
                    ident(c)?;
                }
                for (k, v) in &p.headers {
                    ensure!(
                        !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                        "Invalid header name"
                    );
                    ensure!(
                        v.len() <= 1000
                            && !v.chars().any(|c| c.is_control())
                            && !v.contains(['"', '\\', '$']),
                        "Header values cannot contain control characters, quotes, backslashes or variables"
                    );
                }
                if let Some(ref target) = p.redirect {
                    let uri = url::Url::parse(target)?;
                    ensure!(
                        matches!(uri.scheme(), "http" | "https")
                            && uri.username().is_empty()
                            && uri.password().is_none(),
                        "Use an HTTP(S) redirect"
                    );
                    safe_text(target, 1000)?;
                }
            }
            Self::Stream(s) => {
                ensure!(
                    s.listen.port() > 0 && s.upstream.port() > 0 && s.listen != s.upstream,
                    "Invalid stream endpoints"
                );
                ensure!(
                    !matches!(s.listen.port(), 22 | 25 | 53 | 8443 | 9443 | 9444),
                    "Management ports are protected"
                );
            }
            Self::ForwardProxy(f) => {
                ident(&f.user_group)?;
                ensure!(
                    !f.clients.is_empty() && !f.ports.is_empty() && f.ports.len() <= 64,
                    "Explicit client networks and destination ports required"
                );
                ensure!(
                    f.clients.len() <= 128 && f.destinations.len() <= 128,
                    "Network access list exceeds limits"
                );
                ensure!(
                    f.bandwidth_kbps
                        .is_none_or(|n| (1..=1_000_000).contains(&n))
                        && f.daily_mib.is_none_or(|n| (1..=1_048_576).contains(&n)),
                    "Forward quotas exceed limits"
                );
                ensure!(
                    (1..=512).contains(&f.max_connections) && f.ports.iter().all(|p| *p > 0),
                    "Invalid forward limits"
                );
                ensure!(
                    f.listen.port() > 0
                        && !matches!(
                            f.listen.port(),
                            22 | 25 | 53 | 80 | 443 | 8443 | 9443 | 9444
                        ),
                    "Choose a dedicated forward port"
                );
                if f.public {
                    ensure!(
                        f.protocol != ForwardProtocol::Socks5Lan && f.certificate.is_some(),
                        "Public forward proxies require TLS"
                    );
                }
                ensure!(
                    f.protocol == ForwardProtocol::Socks5Lan || f.certificate.is_some(),
                    "TLS forward listeners require a certificate"
                );
                if f.protocol == ForwardProtocol::Socks5Lan {
                    ensure!(
                        private_ip(f.listen.ip())
                            && !f.listen.ip().is_unspecified()
                            && f.clients.iter().all(private_network),
                        "Plain SOCKS5 is restricted to private interfaces and networks"
                    );
                }
                if let Some(ref c) = f.certificate {
                    ident(c)?;
                }
            }
        };
        Ok(())
    }
    pub fn nginx(&self, id: &str, base: &str) -> Result<String> {
        ident(id)?;
        ensure!(
            base.starts_with('/') && !base.contains([' ', '\n', ';', '{', '}', '$', '"', '\\']),
            "Invalid runtime path"
        );
        self.validate()?;
        let mut s = String::new();
        match self {
            Self::ProxyHost(p) => {
                let name = format!("kn_{}", id.replace('-', "_"));
                let names = p
                    .domains
                    .iter()
                    .map(|h| hostname(h).unwrap())
                    .collect::<Vec<_>>()
                    .join(" ");
                let challenge = format!(
                    "location ^~ /.well-known/acme-challenge/ {{root {base}/acme/challenges; default_type text/plain; try_files $uri =404;}}\n"
                );
                if p.certificate.is_some() && p.force_https {
                    s.push_str(&format!("server {{listen 80; listen [::]:80; server_name {names}; {challenge} location / {{return 308 https://$host$request_uri;}}}}\n"));
                }
                s.push_str(&format!("upstream {name} {{\n"));
                match p.balance {
                    Balance::LeastConnections => s.push_str("least_conn;\n"),
                    Balance::IpHash => s.push_str("ip_hash;\n"),
                    _ => {}
                }
                for u in &p.upstreams {
                    let v = url::Url::parse(&u.address)?;
                    s.push_str(&format!(
                        "server {}:{} weight={} max_fails=3 fail_timeout=10s{};\n",
                        v.host_str().unwrap(),
                        v.port_or_known_default().unwrap(),
                        u.weight,
                        if u.backup { " backup" } else { "" }
                    ));
                }
                s.push_str("keepalive 16;\n}\n");
                if let Some(quota) = p.cache_mib {
                    s.push_str(&format!("proxy_cache_path {base}/cache/{id} keys_zone={name}:1m max_size={quota}m inactive=30m;\n"));
                }
                if let Some(rate) = p.rate_per_second {
                    ensure!(rate > 0, "Rate must be positive");
                    s.push_str(&format!(
                        "limit_req_zone $binary_remote_addr zone={name}_rate:1m rate={rate}r/s;\n"
                    ));
                }
                s.push_str(&format!(
                    "server {{\nlisten {};\nlisten [::]:{};\nserver_name {};\n",
                    if p.certificate.is_some() {
                        if p.grpc { "443 ssl http2" } else { "443 ssl" }
                    } else {
                        "80"
                    },
                    if p.certificate.is_some() {
                        if p.grpc { "443 ssl http2" } else { "443 ssl" }
                    } else {
                        "80"
                    },
                    names
                ));
                if p.certificate.is_some() && !p.force_https {
                    s.push_str("listen 80; listen [::]:80;\n");
                }
                s.push_str(&challenge);
                if p.compression {
                    s.push_str("gzip on; gzip_vary on; gzip_min_length 1024; gzip_types text/plain text/css application/javascript application/json image/svg+xml;\n");
                }
                if let Some(c) = &p.certificate {
                    s.push_str(&format!("ssl_certificate {base}/certificates/{c}/fullchain.pem;\nssl_certificate_key {base}/certificates/{c}/privkey.pem;\nssl_protocols TLSv1.2 TLSv1.3;\n"));
                }
                if let Some(c) = &p.client_ca {
                    s.push_str(&format!("ssl_client_certificate {base}/certificates/{c}/ca.pem;\nssl_verify_client on;\n"));
                }
                s.push_str(&format!(
                    "client_max_body_size {}m;\nlocation {} {{\n",
                    p.max_body_mib, p.path
                ));
                for net in &p.allowed_clients {
                    s.push_str(&format!("allow {net};\n"));
                }
                if !p.allowed_clients.is_empty() {
                    s.push_str("deny all;\n");
                }
                if let Some(group) = &p.authentication {
                    s.push_str(&format!(
                        "auth_basic \"Restricted\";\nauth_basic_user_file {base}/auth/{group};\n"
                    ));
                }
                if let Some(target) = &p.redirect {
                    s.push_str(&format!("return 308 \"{target}\";\n"));
                } else {
                    let scheme = url::Url::parse(&p.upstreams[0].address)?
                        .scheme()
                        .to_string();
                    ensure!(
                        p.upstreams
                            .iter()
                            .all(|u| url::Url::parse(&u.address).unwrap().scheme() == scheme),
                        "Upstreams must use the same scheme"
                    );
                    if p.grpc {
                        s.push_str(&format!(
                            "grpc_pass {}://{name};\n",
                            if scheme == "https" { "grpcs" } else { "grpc" }
                        ));
                        s.push_str(&format!("grpc_read_timeout {}s; grpc_send_timeout {}s; grpc_set_header Host $host;\n",p.timeout_seconds,p.timeout_seconds));
                    } else {
                        s.push_str(&format!("proxy_pass {scheme}://{name}{};\nproxy_http_version 1.1;\nproxy_set_header Host $host;\nproxy_set_header X-Real-IP $remote_addr;\nproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\nproxy_set_header X-Forwarded-Proto $scheme;\nproxy_read_timeout {}s; proxy_send_timeout {}s; proxy_connect_timeout 10s;\n",if p.strip_prefix { "/" } else { "" },p.timeout_seconds,p.timeout_seconds));
                    }
                    if scheme == "https" {
                        let prefix = if p.grpc { "grpc" } else { "proxy" };
                        s.push_str(&format!("{prefix}_ssl_verify on;\n{prefix}_ssl_server_name on;\n{prefix}_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;\n"));
                        let uri = url::Url::parse(&p.upstreams[0].address)?;
                        s.push_str(&format!(
                            "{prefix}_ssl_name {};\n",
                            p.upstream_tls_name
                                .as_deref()
                                .unwrap_or(uri.host_str().unwrap())
                        ));
                        if let Some(c) = &p.upstream_client_certificate {
                            s.push_str(&format!("{prefix}_ssl_certificate {base}/certificates/{c}/fullchain.pem;\n{prefix}_ssl_certificate_key {base}/certificates/{c}/privkey.pem;\n"));
                        }
                    }
                    if p.websocket {
                        s.push_str("proxy_set_header Upgrade $http_upgrade;\nproxy_set_header Connection $kn_connection_upgrade;\n");
                    }
                    if p.cache_mib.is_some() {
                        s.push_str(&format!("proxy_cache {name};\nproxy_cache_valid 200 5m;\n"));
                    }
                    if p.rate_per_second.is_some() {
                        s.push_str(&format!("limit_req zone={name}_rate burst=10 nodelay;\n"));
                    }
                    for (k, v) in &p.headers {
                        s.push_str(&format!("add_header {k} \"{v}\" always;\n"));
                    }
                }
                s.push_str("}\n}\n");
            }
            Self::Stream(p) => {
                s.push_str(&format!(
                    "server {{\nlisten {}{};\n",
                    p.listen,
                    if p.udp { " udp" } else { "" }
                ));
                for n in &p.allowed_clients {
                    s.push_str(&format!("allow {n};\n"));
                }
                if !p.allowed_clients.is_empty() {
                    s.push_str("deny all;\n");
                }
                s.push_str(&format!(
                    "proxy_pass {};\nproxy_timeout 60s;\n}}\n",
                    p.upstream
                ));
            }
            Self::ForwardProxy(_) => {
                bail!("Forward configuration is rendered by its dedicated engine")
            }
        }
        Ok(s)
    }
}
