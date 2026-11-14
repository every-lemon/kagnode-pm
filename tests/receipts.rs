use kagnode_proxy_manager::{digest, now, store::Store};
use serde_json::json;

#[test]
fn lost_result_acknowledgement_is_retryable_but_cannot_change_the_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO servers(id,name)VALUES('a','A'),('b','B')", [])
        .unwrap();
    let id = store
        .enqueue(
            "owner",
            "a",
            "status",
            json!({}),
            "receipt-idempotency-test",
        )
        .unwrap();
    let job = store.claim("a").unwrap();
    let lease = job["lease"].as_str().unwrap();
    let outcome = json!({"state":"completed","result":{"healthy":true}});
    assert!(store.acknowledge("b", &id, lease, &outcome).is_err());
    assert!(
        store
            .acknowledge("a", &id, &"0".repeat(64), &outcome)
            .is_err()
    );
    store.acknowledge("a", &id, lease, &outcome).unwrap();
    store.acknowledge("a", &id, lease, &outcome).unwrap();
    assert!(
        store
            .acknowledge("a", &id, lease, &json!({"state":"failed"}))
            .is_err()
    );
    assert!(store.claim("a").unwrap().is_null());
}

#[test]
fn heartbeat_renews_only_the_matching_active_operation_and_never_clears_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO servers(id,name)VALUES('a','A'),('b','B')", [])
        .unwrap();
    let id = store
        .enqueue(
            "owner",
            "a",
            "status",
            json!({}),
            "heartbeat-long-operation",
        )
        .unwrap();
    let job = store.claim("a").unwrap();
    let lease = job["lease"].as_str().unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute("UPDATE jobs SET expires=1", [])
        .unwrap();
    let sample = json!({"summary":{},"capabilities":{},"active_job":{"id":id,"lease":lease}});
    store.heartbeat("b", &sample).unwrap();
    let expiry = || {
        store
            .db
            .lock()
            .unwrap()
            .query_row("SELECT expires FROM jobs", [], |r| r.get::<_, i64>(0))
            .unwrap()
    };
    assert_eq!(expiry(), 1);
    store.heartbeat("a", &sample).unwrap();
    assert!(expiry() >= now() + 1799);
    store
        .db
        .lock()
        .unwrap()
        .execute("UPDATE jobs SET expires=1", [])
        .unwrap();
    assert!(store.claim("a").unwrap().is_null());
    store.heartbeat("a", &sample).unwrap();
    assert_eq!(expiry(), 1);
    store
        .acknowledge("a", &id, lease, &json!({"state":"completed","result":{}}))
        .unwrap();
    assert!(store.claim("a").unwrap().is_null());
    let recorded: String = store
        .db
        .lock()
        .unwrap()
        .query_row("SELECT lease FROM jobs", [], |r| r.get(0))
        .unwrap();
    assert_eq!(recorded, digest(lease));
}
