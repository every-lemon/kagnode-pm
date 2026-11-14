use crate::domain::{Balance, ProxyHost, Resource, Upstream};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
pub fn preview(document: &Value) -> Result<Value> {
    ensure!(
        document["schema"] == 2 && document["sites"].is_array(),
        "Expected existing Nginx manager schema 2"
    );
    let mut resources = vec![];
    let mut blockers = vec![];
    if document["settings"]["trusted_proxies"]
        .as_array()
        .is_some_and(|v| !v.is_empty())
    {
        blockers.push("Trusted proxy configuration needs an explicit migration review".into());
    }
    for site in document["sites"].as_array().unwrap() {
        let id = site["id"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing site ID"))?;
        crate::domain::ident(id)?;
        if site["enabled"] != true {
            continue;
        }
        if site["routes"]
            .as_array()
            .is_some_and(|routes| routes.len() != 1)
        {
            blockers.push(format!(
                "{id}: multiple location routes require a combined-host migration"
            ));
        }
        if site["buffering"] == false || site["access_log"] == true {
            blockers.push(format!(
                "{id}: buffering/logging policy requires migration review"
            ));
        }
        if site["rate"].as_u64().is_some_and(|n| n > 0)
            && site["burst"].as_u64().is_some_and(|n| n != 10)
        {
            blockers.push(format!(
                "{id}: rate-limit burst differs from the supported policy"
            ));
        }
        if site["deny"].as_array().is_some_and(|a| !a.is_empty()) {
            blockers.push(format!(
                "{id}: explicit deny rules require migration review"
            ));
        }
        if site["verify_upstream"] == false {
            blockers.push(format!("{id}: upstream TLS verification is disabled"));
        }
        if site["auth"] == true {
            blockers.push(format!(
                "{id}: import authentication file separately without exposing passwords"
            ));
        }
        let domains = site["names"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Missing hostnames"))?
            .iter()
            .map(|n| {
                n.as_str()
                    .map(String::from)
                    .ok_or_else(|| anyhow::anyhow!("Invalid hostname"))
            })
            .collect::<Result<Vec<_>>>()?;
        for (index, route) in site["routes"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Missing routes"))?
            .iter()
            .enumerate()
        {
            if route["balance"]
                .as_str()
                .is_some_and(|b| !matches!(b, "round_robin" | "least_conn" | "ip_hash"))
            {
                blockers.push(format!("{id}: unsupported upstream balancing policy"));
            }
            let upstreams = route["backends"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Missing upstreams"))?
                .iter()
                .map(|v| {
                    Ok(Upstream {
                        address: v
                            .as_str()
                            .ok_or_else(|| anyhow::anyhow!("Invalid upstream"))?
                            .into(),
                        weight: 1,
                        backup: false,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let p = ProxyHost {
                domains: domains.clone(),
                upstreams,
                balance: match route["balance"].as_str() {
                    Some("least_conn") => Balance::LeastConnections,
                    Some("ip_hash") => Balance::IpHash,
                    _ => Balance::RoundRobin,
                },
                path: route["path"].as_str().unwrap_or("/").into(),
                certificate: (site["tls"] == true).then(|| id.into()),
                force_https: site["redirect"] != false,
                strip_prefix: route["strip_prefix"] == true,
                compression: false,
                upstream_tls_name: site["tls_name"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(String::from),
                upstream_client_certificate: None,
                client_ca: None,
                allowed_clients: serde_json::from_value(site["allow"].clone()).unwrap_or_default(),
                authentication: (site["auth"] == true).then(|| id.into()),
                websocket: site["websockets"] == true,
                grpc: false,
                redirect: None,
                headers: Default::default(),
                max_body_mib: site["body_mb"].as_u64().unwrap_or(16).try_into()?,
                timeout_seconds: site["timeout"].as_u64().unwrap_or(60).try_into()?,
                rate_per_second: site["rate"]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .map(u16::try_from)
                    .transpose()?,
                cache_mib: None,
            };
            let resource = Resource::ProxyHost(p);
            if let Err(e) = resource.validate() {
                blockers.push(format!("{id}: {e}"));
            }
            resources.push(json!({"name":format!("{id}-{index}"),"resource":resource,"certificate_import_required":site["tls"]==true}));
        }
    }
    Ok(
        json!({"source":"nginx-manager","schema":2,"resources":resources,"blockers":blockers,"can_cutover":blockers.is_empty(),"source_sha256":crate::digest(serde_json::to_vec(document)?),"mutated":false,"certificates":"Private keys remain local; certificate paths and fingerprints must be verified during explicit migration."}),
    )
}
