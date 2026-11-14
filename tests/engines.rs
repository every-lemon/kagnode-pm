use kagnode_proxy_manager::{
    domain::Resource,
    engines::{self, Engine},
};
use serde_json::json;
fn site() -> Resource {
    serde_json::from_value(json!({"kind":"proxy_host","settings":{"domains":["app.example.com"],"upstreams":[{"address":"http://127.0.0.1:8080"}],"force_https":false}})).unwrap()
}
#[test]
fn adapters_never_silently_drop_access_policies() {
    for engine in [
        Engine::Nginx,
        Engine::Caddy,
        Engine::Apache,
        Engine::Haproxy,
        Engine::Traefik,
    ] {
        let preview = engines::render(
            engine,
            &[("site".into(), site())],
            "/srv/kagnode/proxy-manager/traffic",
        )
        .unwrap();
        assert_eq!(preview["engine"], engine.id());
        assert!(preview["files"].as_object().is_some());
    }
    let mut s = site();
    if let Resource::ProxyHost(ref mut h) = s {
        h.allowed_clients.push("10.0.0.0/8".parse().unwrap());
    }
    for engine in [
        Engine::Caddy,
        Engine::Apache,
        Engine::Haproxy,
        Engine::Traefik,
    ] {
        assert!(
            engines::render(
                engine,
                &[("site".into(), s.clone())],
                "/srv/kagnode/proxy-manager/traffic"
            )
            .is_err()
        );
    }
}
#[test]
fn duplicate_hostnames_and_unsafe_roots_fail() {
    for engine in [
        Engine::Nginx,
        Engine::Caddy,
        Engine::Apache,
        Engine::Haproxy,
        Engine::Traefik,
    ] {
        assert!(
            engines::render(
                engine,
                &[("one".into(), site()), ("two".into(), site())],
                "/srv/kagnode/proxy-manager/traffic"
            )
            .is_err()
        );
        assert!(engines::render(engine, &[], "/srv/unsafe;root").is_err());
    }
}
