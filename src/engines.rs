//! Explicit engine capabilities. Unsupported semantics are rejected, never omitted.
use crate::domain::{Balance, Resource};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    #[default]
    Nginx,
    Caddy,
    Apache,
    Haproxy,
    Traefik,
}
impl Engine {
    pub fn id(self) -> &'static str {
        match self {
            Self::Nginx => "nginx",
            Self::Caddy => "caddy",
            Self::Apache => "apache",
            Self::Haproxy => "haproxy",
            Self::Traefik => "traefik",
        }
    }
    pub fn executable(self) -> &'static str {
        match self {
            Self::Nginx => "/usr/sbin/nginx",
            Self::Caddy => "/usr/bin/caddy",
            Self::Apache => "/usr/sbin/apache2",
            Self::Haproxy => "/usr/sbin/haproxy",
            Self::Traefik => "/usr/bin/traefik",
        }
    }
}
pub fn capabilities() -> Value {
    json!({"selection":"one_primary_engine_per_server","engines":[
    {"id":"nginx","label":"Nginx","http":true,"tls":true,"websocket":true,"streams":true,"forward_frontend":true,"activation_qualified":true},
    {"id":"caddy","label":"Caddy","http":true,"tls":true,"websocket":true,"streams":false,"forward_frontend":false,"activation_qualified":false},
    {"id":"apache","label":"Apache HTTP Server","http":true,"tls":true,"websocket":true,"streams":false,"forward_frontend":false,"activation_qualified":false},
    {"id":"haproxy","label":"HAProxy","http":true,"tls":true,"websocket":true,"streams":false,"forward_frontend":false,"activation_qualified":false},
    {"id":"traefik","label":"Traefik","http":true,"tls":true,"websocket":true,"streams":false,"forward_frontend":false,"activation_qualified":false}
    ]})
}
fn supported(resource: &Resource) -> Result<&crate::domain::ProxyHost> {
    resource.validate()?;
    let Resource::ProxyHost(h) = resource else {
        anyhow::bail!(
            "This engine adapter needs a reviewed HTTP reverse-proxy resource; stream/forward resources are not converted"
        )
    };
    ensure!(
        h.path == "/"
            && !h.strip_prefix
            && h.redirect.is_none()
            && h.cache_mib.is_none()
            && h.rate_per_second.is_none()
            && h.allowed_clients.is_empty()
            && h.authentication.is_none()
            && h.client_ca.is_none()
            && h.upstream_client_certificate.is_none()
            && h.upstream_tls_name.is_none()
            && !h.compression
            && !h.grpc
            && h.headers.is_empty(),
        "This engine configuration contains policies that need an engine-specific implementation and review"
    );
    ensure!(
        matches!(h.balance, Balance::RoundRobin)
            && h.upstreams.iter().all(|u| u.weight == 1 && !u.backup),
        "This balancing policy requires an engine-specific implementation"
    );
    Ok(h)
}
pub fn render(engine: Engine, resources: &[(String, Resource)], base: &str) -> Result<Value> {
    ensure!(
        base.starts_with('/')
            && !base.contains(['\n', '\r', '\0', '"', '\'', ' ', ';', '{', '}', '$']),
        "Invalid engine storage root"
    );
    ensure!(resources.len() <= 250, "Too many proxy resources");
    let mut claimed = std::collections::BTreeSet::new();
    for (id, r) in resources {
        crate::domain::ident(id)?;
        r.validate()?;
        if let Resource::ProxyHost(h) = r {
            for d in &h.domains {
                ensure!(
                    claimed.insert(d.to_lowercase()),
                    "Multiple resources claim the same domain"
                )
            }
        }
    }
    if engine == Engine::Nginx {
        let mut http = String::new();
        for (id, r) in resources {
            http.push_str(&r.nginx(id, base)?)
        }
        return Ok(json!({"engine":engine,"files":{"http.conf":http},"activation_qualified":true}));
    }
    let mut caddy = Vec::new();
    let mut apache = String::new();
    let mut haproxy = String::from(
        "global\n  maxconn 1024\n\ndefaults\n  mode http\n  timeout connect 10s\n  timeout client 60s\n  timeout server 60s\n",
    );
    let mut routers = serde_json::Map::new();
    let mut services = serde_json::Map::new();
    let mut certs = Vec::new();
    let mut routes = Vec::new();
    for (id, r) in resources {
        let h = supported(r)?;
        let upstreams = h
            .upstreams
            .iter()
            .map(|u| url::Url::parse(&u.address))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let https = upstreams[0].scheme() == "https";
        ensure!(
            upstreams.iter().all(|u| (u.scheme() == "https") == https),
            "Mixed upstream TLS schemes need explicit review"
        );
        let addresses = upstreams
            .iter()
            .map(|u| {
                format!(
                    "{}:{}",
                    u.host_str().unwrap(),
                    u.port_or_known_default().unwrap()
                )
            })
            .collect::<Vec<_>>();
        match engine {
            Engine::Caddy => {
                let mut proxy = json!({"handler":"reverse_proxy","upstreams":addresses.iter().map(|a|json!({"dial":a})).collect::<Vec<_>>(),"transport":{"protocol":"http","dial_timeout":"10s","response_header_timeout":format!("{}s",h.timeout_seconds)}});
                if https {
                    proxy["transport"]["tls"] = json!({});
                }
                let route = json!({"match":[{"host":h.domains}],"handle":[proxy],"terminal":true});
                if let Some(cert) = &h.certificate {
                    certs.push(json!({"certificate":format!("{base}/certificates/{cert}/fullchain.pem"),"key":format!("{base}/certificates/{cert}/privkey.pem")}));
                }
                caddy.push((h.certificate.is_some(), h.force_https, route));
            }
            Engine::Apache => {
                ensure!(
                    h.upstreams.len() == 1,
                    "Apache balancing requires a reviewed balancer configuration"
                );
                let domain = &h.domains[0];
                let aliases = h.domains[1..].join(" ");
                let upstream = h.upstreams[0].address.trim_end_matches('/');
                apache.push_str(&format!("<VirtualHost *:{}>\nServerName {domain}\n{}ProxyRequests Off\nProxyPreserveHost On\nProxyTimeout {}\nLimitRequestBody {}\n",if h.certificate.is_some(){443}else{80},if aliases.is_empty(){String::new()}else{format!("ServerAlias {aliases}\n")},h.timeout_seconds,u64::from(h.max_body_mib)*1024*1024));
                if let Some(cert) = &h.certificate {
                    apache.push_str(&format!("SSLEngine on\nSSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCertificateFile {base}/certificates/{cert}/fullchain.pem\nSSLCertificateKeyFile {base}/certificates/{cert}/privkey.pem\n"));
                }
                if https {
                    apache.push_str("SSLProxyEngine On\nSSLProxyVerify require\nSSLProxyCheckPeerName on\nSSLProxyCACertificateFile /etc/ssl/certs/ca-certificates.crt\n");
                }
                apache.push_str(&format!(
                    "ProxyPass / {upstream}/{}\nProxyPassReverse / {upstream}/\n</VirtualHost>\n",
                    if h.websocket {
                        " upgrade=websocket"
                    } else {
                        ""
                    }
                ));
                ensure!(
                    !h.force_https || h.certificate.is_none(),
                    "Apache redirect listener needs explicit combined-host configuration"
                );
            }
            Engine::Haproxy => {
                ensure!(
                    h.certificate.is_none(),
                    "HAProxy requires a private combined PEM staging operation before TLS activation"
                );
                let hosts = h.domains.join(" ");
                routes.push(format!(
                    "  acl host_{id} hdr(host) -i {hosts}\n  use_backend kn_{id} if host_{id}\n"
                ));
                haproxy.push_str(&format!("backend kn_{id}\n  balance roundrobin\n"));
                for (index, address) in addresses.iter().enumerate() {
                    haproxy.push_str(&format!("  server s{index} {address} check{}\n",if https{format!(" ssl verify required ca-file /etc/ssl/certs/ca-certificates.crt sni str({})",upstreams[index].host_str().unwrap())}else{String::new()}));
                }
            }
            Engine::Traefik => {
                let rule = h
                    .domains
                    .iter()
                    .map(|d| format!("Host(`{d}`)"))
                    .collect::<Vec<_>>()
                    .join(" || ");
                let mut router = json!({"rule":rule,"service":id,"entryPoints":[if h.certificate.is_some(){"websecure"}else{"web"}]});
                if let Some(cert) = &h.certificate {
                    router["tls"] = json!({});
                    certs.push(json!({"certFile":format!("{base}/certificates/{cert}/fullchain.pem"),"keyFile":format!("{base}/certificates/{cert}/privkey.pem")}));
                }
                ensure!(
                    !h.force_https || h.certificate.is_none(),
                    "Traefik redirect middleware requires explicit review"
                );
                routers.insert(id.clone(), router);
                services.insert(id.clone(),json!({"loadBalancer":{"servers":h.upstreams.iter().map(|u|json!({"url":u.address})).collect::<Vec<_>>()}}));
            }
            Engine::Nginx => unreachable!(),
        }
    }
    let files = match engine {
        Engine::Caddy => {
            let mut servers = serde_json::Map::new();
            for tls in [false, true] {
                let selected = caddy
                    .iter()
                    .filter(|(t, _, _)| *t == tls)
                    .map(|(_, _, r)| r.clone())
                    .collect::<Vec<_>>();
                if !selected.is_empty() {
                    servers.insert(if tls{"https"}else{"http"}.into(),json!({"listen":[if tls{":443"}else{":80"}],"routes":selected,"automatic_https":{"disable":true}}));
                }
            }
            ensure!(
                !caddy.iter().any(|(tls, force, _)| *tls && *force),
                "Caddy redirect listener requires explicit review"
            );
            json!({"caddy.json":serde_json::to_string_pretty(&json!({"admin":{"disabled":true},"apps":{"http":{"servers":servers},"tls":{"certificates":{"load_files":certs}}}}))?})
        }
        Engine::Apache => json!({"sites.conf":apache}),
        Engine::Haproxy => {
            haproxy.push_str("frontend kn_http\n  bind :80\n");
            for r in routes {
                haproxy.push_str(&r)
            }
            json!({"haproxy.cfg":haproxy})
        }
        Engine::Traefik => {
            json!({"dynamic.json":serde_json::to_string_pretty(&json!({"http":{"routers":routers,"services":services},"tls":{"certificates":certs}}))?})
        }
        Engine::Nginx => unreachable!(),
    };
    Ok(
        json!({"engine":engine,"files":files,"activation_qualified":false,"message":"Configuration preview; native activation remains blocked until this engine's qualification passes"}),
    )
}
