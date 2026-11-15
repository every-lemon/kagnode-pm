use kagnode_proxy_manager::{
    self as proxy,
    domain::{Resource, Role},
};
use serde_json::json;
fn route(port: u16) -> Resource {
    serde_json::from_value(json!({"kind":"proxy_host","settings":{"domains":["app.example.test"],"upstreams":[{"address":format!("http://127.0.0.1:{port}")} ]}})).unwrap()
}
#[tokio::test]
async fn reachability_is_tcp_only_and_reports_connection_failure_without_native_changes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let result = proxy::probe::check(&route(port)).await.unwrap();
    assert_eq!(result["results"][0]["state"], "reachable");
    assert_eq!(result["application_health_verified"], false);
    assert_eq!(result["traffic_changed"], false);
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut bytes = [0u8; 1];
    use tokio::io::AsyncReadExt;
    assert_eq!(
        socket.read(&mut bytes).await.unwrap(),
        0,
        "The probe must never send an HTTP request"
    );
    drop(listener);
    assert_eq!(
        proxy::probe::check(&route(port)).await.unwrap()["results"][0]["state"],
        "unreachable"
    );
}
#[test]
fn checks_freeze_resource_revision_and_require_advertised_node_capability() {
    let dir = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(dir.path()).unwrap();
    let owner = proxy::auth::create_user(
        &store,
        "owner@example.test",
        "Owner",
        "Isolated long fixture password",
        Role::Owner,
    )
    .unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO servers(id,name)VALUES('node','Node')", [])
        .unwrap();
    let id = store
        .save_resource(&owner, "node", "route", &route(8080), None, 0)
        .unwrap();
    assert!(
        store
            .queue_upstream_probe(&owner, "node", &id, 1, "probe-no-capability")
            .is_err()
    );
    store
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE servers SET capabilities='{\"upstream_probe\":true}'",
            [],
        )
        .unwrap();
    let first = store
        .queue_upstream_probe(&owner, "node", &id, 1, "probe-request-0001")
        .unwrap();
    assert_eq!(
        store
            .queue_upstream_probe(&owner, "node", &id, 1, "probe-request-0001")
            .unwrap(),
        first
    );
    assert!(
        store
            .queue_upstream_probe(&owner, "node", &id, 2, "probe-stale-0002")
            .is_err()
    );
    for i in 2..=6 {
        store
            .queue_upstream_probe(&owner, "node", &id, 1, &format!("probe-request-{i:04}"))
            .unwrap();
    }
    assert!(
        store
            .queue_upstream_probe(&owner, "node", &id, 1, "probe-request-0007")
            .is_err()
    );
    assert!(
        store
            .queue_upstream_probe(&owner, "other-node", &id, 1, "probe-wrong-node")
            .is_err()
    );
}
