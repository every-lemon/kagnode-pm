//! Bounded TCP reachability from the unprivileged node agent, never an HTTP request.
use crate::domain::Resource;
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

pub fn targets(resource: &Resource) -> Result<Vec<(String, u16)>> {
    resource.validate()?;
    let Resource::ProxyHost(host) = resource else {
        anyhow::bail!("Reachability checks require a reverse proxy resource");
    };
    host.upstreams
        .iter()
        .map(|peer| {
            let url = url::Url::parse(&peer.address)?;
            let name = url
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("Missing upstream hostname"))?;
            let port = url
                .port_or_known_default()
                .ok_or_else(|| anyhow::anyhow!("Missing upstream port"))?;
            Ok((name.trim_matches(['[', ']']).to_owned(), port))
        })
        .collect()
}

pub async fn check(resource: &Resource) -> Result<Value> {
    let peers = targets(resource)?;
    ensure!(peers.len() <= 32, "Too many upstreams");
    let mut results = Vec::new();
    for chunk in peers.chunks(4) {
        let mut tasks = tokio::task::JoinSet::new();
        for (index, (host, port)) in chunk.iter().cloned().enumerate() {
            tasks.spawn(async move {
                let started = Instant::now();
                let state = match tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect((host.as_str(), port))).await {
                    Ok(Ok(stream)) => { drop(stream); "reachable" },
                    Ok(Err(_)) => "unreachable",
                    Err(_) => "timeout",
                };
                (index, json!({"host":host,"port":port,"state":state,"elapsed_ms":started.elapsed().as_millis() as u64}))
            });
        }
        let mut batch = Vec::new();
        while let Some(result) = tasks.join_next().await {
            batch.push(result?);
        }
        batch.sort_by_key(|entry| entry.0);
        results.extend(batch.into_iter().map(|(_, result)| result));
    }
    Ok(
        json!({"kind":"tcp_reachability","checked_at":crate::now(),"results":results,"application_health_verified":false,"traffic_changed":false}),
    )
}
