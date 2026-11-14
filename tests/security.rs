use kagnode_proxy_manager::{
    self as proxy,
    domain::{Balance, ProxyHost, Resource, Role, Upstream},
    packages::{Inventory, Package, analyze},
};
use serde_json::json;
fn host() -> Resource {
    Resource::ProxyHost(ProxyHost {
        domains: vec!["service.example.com".into()],
        upstreams: vec![Upstream {
            address: "http://127.0.0.1:8080".into(),
            weight: 1,
            backup: false,
        }],
        balance: Balance::RoundRobin,
        path: "/".into(),
        certificate: None,
        force_https: true,
        strip_prefix: false,
        compression: false,
        upstream_tls_name: None,
        upstream_client_certificate: None,
        client_ca: None,
        allowed_clients: vec![],
        authentication: None,
        websocket: true,
        grpc: false,
        redirect: None,
        headers: Default::default(),
        max_body_mib: 16,
        timeout_seconds: 60,
        rate_per_second: None,
        cache_mib: None,
    })
}
#[test]
fn renderer_escapes_configuration_boundaries() {
    for input in [
        "example.com;return 200",
        "example.com\n}",
        "$http_host",
        "/etc/passwd",
        "example.com\\x",
    ] {
        assert!(proxy::domain::hostname(input).is_err(), "{input}");
    }
    assert_eq!(
        proxy::domain::hostname("*.Example.COM").unwrap(),
        "*.example.com"
    );
    let r = host()
        .nginx("service", "/srv/kagnode/proxy-manager/traffic")
        .unwrap();
    assert!(r.contains("proxy_pass http://kn_service"));
    assert!(r.contains("proxy_set_header Upgrade"));
    assert!(host().nginx("../escape", "/tmp").is_err());
    assert!(host().nginx("name", "/tmp;root").is_err());
}
#[test]
fn credential_upstreams_and_mixed_protocols_are_rejected() {
    let Resource::ProxyHost(mut p) = host() else {
        unreachable!()
    };
    p.upstreams[0].address = "http://name:password@server.local".into();
    assert!(Resource::ProxyHost(p.clone()).validate().is_err());
    p.upstreams[0].address = "http://127.0.0.1:8080".into();
    p.upstreams.push(Upstream {
        address: "https://service.example.com".into(),
        weight: 1,
        backup: false,
    });
    assert!(Resource::ProxyHost(p).nginx("test", "/tmp").is_err());
}
fn inventory() -> Inventory {
    Inventory {
        packages: vec![
            Package {
                name: "optional:amd64".into(),
                version: "1".into(),
                essential: false,
                protected: false,
                held: false,
                bytes: 2000,
                services: vec![],
            },
            Package {
                name: "core:amd64".into(),
                version: "1".into(),
                essential: true,
                protected: false,
                held: false,
                bytes: 1000,
                services: vec![],
            },
        ],
        required: Default::default(),
        uncertain: vec![],
    }
}
#[test]
fn dependency_transaction_protects_unselected_essential_package() {
    let i = inventory();
    let p = analyze(
        &i,
        vec!["optional:amd64".into()],
        vec!["core:amd64".into(), "optional:amd64".into()],
    )
    .unwrap();
    assert!(p.blockers.contains_key("core:amd64"));
    assert_eq!(p.reclaimed_bytes, 3000);
}
#[test]
fn held_service_owned_required_and_unknown_packages_are_blocked() {
    for case in 0..5 {
        let mut i = inventory();
        match case {
            0 => i.packages[0].held = true,
            1 => i.packages[0].services.push("app.service".into()),
            2 => {
                i.required.insert("optional:amd64".into());
            }
            3 => i.uncertain.push("custom executable owner unknown".into()),
            _ => i.packages[0].protected = true,
        };
        let p = analyze(
            &i,
            vec!["optional:amd64".into()],
            vec!["optional:amd64".into()],
        )
        .unwrap();
        assert!(!p.blockers.is_empty());
    }
}
#[test]
fn changed_inventory_invalidates_approval() {
    let i = inventory();
    let a = analyze(
        &i,
        vec!["optional:amd64".into()],
        vec!["optional:amd64".into()],
    )
    .unwrap();
    assert!(a.blockers.is_empty());
    let mut changed = i;
    changed.packages[0].version = "2".into();
    let b = analyze(&changed, a.requested.clone(), a.removals.clone()).unwrap();
    assert_ne!(a.fingerprint, b.fingerprint);
    assert_ne!(a.confirmation, b.confirmation);
}
#[test]
fn package_options_paths_and_unknown_transactions_fail_closed() {
    for name in [
        "--allow-remove-essential",
        "../foo",
        "FOO",
        "apt;true",
        "a\nb",
        ":amd64",
    ] {
        assert!(!proxy::packages::valid_name(name));
    }
    assert!(analyze(&inventory(), vec!["optional:amd64".into()], vec![]).is_err());
    for n in [
        "nginx-core:amd64",
        "linux-image-6.8:amd64",
        "openssh-server:amd64",
        "systemd:amd64",
        "kagnode-proxy-manager:amd64",
    ] {
        assert!(proxy::packages::protected_name(n));
    }
}
#[test]
fn forward_proxy_cannot_be_public_plaintext_or_reach_metadata() {
    let Resource::ForwardProxy(mut f)=serde_json::from_value(json!({"kind":"forward_proxy","settings":{"listen":"0.0.0.0:8445","protocol":"socks5_lan","user_group":"users","clients":["0.0.0.0/0"],"public":true,"ports":[80,443]}})).unwrap()else{unreachable!()};
    assert!(Resource::ForwardProxy(f.clone()).validate().is_err());
    f.protocol = proxy::domain::ForwardProtocol::Socks5Tls;
    f.certificate = Some("gateway".into());
    assert!(Resource::ForwardProxy(f.clone()).validate().is_ok());
    for ip in [
        "169.254.169.254",
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "fe80::1",
        "192.168.0.6",
    ] {
        assert!(!proxy::forward::destination_allowed(
            ip.parse().unwrap(),
            443,
            &f,
            &[]
        ));
    }
    assert!(proxy::forward::destination_allowed(
        "1.1.1.1".parse().unwrap(),
        443,
        &f,
        &[]
    ));
    assert!(!proxy::forward::destination_allowed(
        "1.1.1.1".parse().unwrap(),
        25,
        &f,
        &[]
    ));
    assert!(!proxy::forward::destination_allowed(
        "1.1.1.1".parse().unwrap(),
        443,
        &f,
        &["1.1.1.1".parse().unwrap()]
    ));
}
#[test]
fn resource_revisions_never_overwrite_other_server_or_stale_work() {
    let dir = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(dir.path()).unwrap();
    {
        let db = store.db.lock().unwrap();
        db.execute("INSERT INTO servers(id,name)VALUES('a','A'),('b','B')", [])
            .unwrap();
    }
    let id = store
        .save_resource("owner", "a", "route", &host(), None, 0)
        .unwrap();
    assert!(
        store
            .save_resource("owner", "b", "route", &host(), Some(&id), 1)
            .is_err()
    );
    assert!(
        store
            .save_resource("owner", "a", "route", &host(), Some(&id), 0)
            .is_err()
    );
    store
        .save_resource("owner", "a", "route", &host(), Some(&id), 1)
        .unwrap();
    assert_eq!(store.resources("a").unwrap()[0]["revision"], 2);
}
#[test]
fn permissions_are_per_server_and_maintenance_is_separate() {
    let dir = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(dir.path()).unwrap();
    {
        let db = store.db.lock().unwrap();
        db.execute("INSERT INTO users(id,email,name,password,role)VALUES('reader','r@example.com','Reader','','\"viewer\"')",[]).unwrap();
        db.execute("INSERT INTO servers(id,name)VALUES('a','A'),('b','B')", [])
            .unwrap();
        db.execute(
            "INSERT INTO server_permissions VALUES('reader','a','viewer',0)",
            [],
        )
        .unwrap();
    }
    assert!(
        store
            .allowed("reader", &Role::Viewer, "a", false, false)
            .unwrap()
    );
    assert!(
        !store
            .allowed("reader", &Role::Viewer, "a", true, false)
            .unwrap()
    );
    assert!(
        !store
            .allowed("reader", &Role::Viewer, "b", false, false)
            .unwrap()
    );
    assert!(
        !store
            .allowed("reader", &Role::Viewer, "a", false, true)
            .unwrap()
    );
}
#[test]
fn idempotency_keys_cannot_be_reused_for_different_actions() {
    let dir = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(dir.path()).unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO servers(id,name)VALUES('a','A')", [])
        .unwrap();
    let a = store
        .enqueue("owner", "a", "status", json!({}), "request-key-long-enough")
        .unwrap();
    assert_eq!(
        store
            .enqueue("owner", "a", "status", json!({}), "request-key-long-enough")
            .unwrap(),
        a
    );
    assert!(
        store
            .enqueue("other", "a", "status", json!({}), "request-key-long-enough")
            .is_err()
    );
    assert!(
        store
            .enqueue(
                "owner",
                "a",
                "configure",
                json!({}),
                "request-key-long-enough"
            )
            .is_err()
    );
    let job = store.claim("a").unwrap();
    assert_eq!(job["id"], a);
    assert!(store.claim("a").unwrap().is_null());
    store
        .db
        .lock()
        .unwrap()
        .execute("UPDATE jobs SET expires=0", [])
        .unwrap();
    assert!(store.claim("a").unwrap().is_null());
    let state: String = store
        .db
        .lock()
        .unwrap()
        .query_row("SELECT state FROM jobs WHERE id=?", [a], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "uncertain");
}
#[test]
fn typed_helper_rejects_commands_and_unknown_fields() {
    for value in [
        json!({"operation":"shell","command":"whoami"}),
        json!({"operation":"status","command":"whoami"}),
        json!({"operation":"package_preview","names":["optional"],"sudo":true}),
    ] {
        assert!(serde_json::from_value::<proxy::broker::Operation>(value).is_err());
    }
}
#[test]
fn import_preview_is_non_mutating_and_blocks_lost_security_rules() {
    let input = json!({"schema":2,"sites":[{"id":"app","enabled":true,"names":["app.example.com"],"routes":[{"path":"/","backends":["http://127.0.0.1:8080"],"balance":"round_robin","strip_prefix":false}],"deny":["10.0.0.0/8"],"verify_upstream":false,"auth":true,"tls":false,"websockets":true,"allow":[],"body_mb":16,"timeout":60,"rate":0}]});
    let a = proxy::migration::preview(&input).unwrap();
    assert_eq!(a["can_cutover"], false);
    assert_eq!(a["mutated"], false);
    assert_eq!(a["blockers"].as_array().unwrap().len(), 3);
}
#[test]
fn release_line_stays_five_zero() {
    assert!(proxy::VERSION.starts_with("5.0."));
}
