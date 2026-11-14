use kagnode_proxy_manager::{
    self as proxy,
    domain::{Resource, Role},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn fixture() -> (tempfile::TempDir, proxy::store::Store, String) {
    let root = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(root.path()).unwrap();
    let owner = proxy::auth::create_user(
        &store,
        "owner@example.test",
        "Owner",
        "A long isolated fixture password",
        Role::Owner,
    )
    .unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO servers(id,name)VALUES('server','Server')", [])
        .unwrap();
    (root, store, owner)
}
fn resource(port: u16) -> Resource {
    serde_json::from_value(json!({"kind":"proxy_host","settings":{"domains":["app.example.test"],"upstreams":[{"address":format!("http://127.0.0.1:{port}"),"weight":7,"backup":false}],"headers":{"X-Original":"preserved"}}})).unwrap()
}
fn revisions(review: &Value) -> BTreeMap<String, i64> {
    serde_json::from_value(review["revisions"].clone()).unwrap()
}
#[test]
fn publication_freezes_reviewed_data_and_replays_the_exact_request_after_acknowledgement() {
    let (_root, store, owner) = fixture();
    let id = store
        .save_resource(&owner, "server", "app", &resource(8080), None, 0)
        .unwrap();
    let review = store.publication_review("server").unwrap();
    assert_eq!(review["pending_count"], 1);
    assert_eq!(review["changes"][0]["change"], "add");
    let key = "publication-fixture-0001";
    let map = revisions(&review);
    let hash = review["review_sha256"].as_str().unwrap();
    let job = store
        .queue_publication(&owner, "server", key, &map, Some(hash))
        .unwrap();
    assert_eq!(
        store
            .queue_publication(&owner, "server", key, &map, Some(hash))
            .unwrap(),
        job
    );
    store
        .save_resource(&owner, "server", "app", &resource(8081), Some(&id), 1)
        .unwrap();
    let claimed = store.claim("server").unwrap();
    assert_eq!(claimed["id"], job);
    assert_eq!(
        claimed["payload"]["resources"][0][1]["settings"]["upstreams"][0]["address"],
        "http://127.0.0.1:8080"
    );
    store
        .acknowledge(
            "server",
            &job,
            claimed["lease"].as_str().unwrap(),
            &json!({"state":"completed","result":{"state":"active"}}),
        )
        .unwrap();
    let rows = store.resources("server").unwrap();
    assert_eq!(rows[0]["published"], 1);
    assert_eq!(rows[0]["revision"], 2);
    assert_eq!(
        store
            .queue_publication(&owner, "server", key, &map, Some(hash))
            .unwrap(),
        job
    );
    assert!(
        store
            .queue_publication(&owner, "server", key, &map, Some("different-review"))
            .is_err()
    );
    assert_eq!(
        store.publication_review("server").unwrap()["changes"][0]["change"],
        "update"
    );
}
#[test]
fn changed_removal_reviews_and_duplicate_publications_are_rejected() {
    let (_root, store, owner) = fixture();
    let id = store
        .save_resource(&owner, "server", "app", &resource(8080), None, 0)
        .unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE resources SET published=1,deleted=1,revision=2 WHERE id=?",
            [&id],
        )
        .unwrap();
    let review = store.publication_review("server").unwrap();
    assert_eq!(review["changes"][0]["change"], "remove");
    assert_eq!(review["total_routes"], 0);
    store
        .db
        .lock()
        .unwrap()
        .execute("UPDATE resources SET revision=3 WHERE id=?", [&id])
        .unwrap();
    assert!(
        store
            .queue_publication(
                &owner,
                "server",
                "stale-fixture-0001",
                &revisions(&review),
                review["review_sha256"].as_str()
            )
            .is_err()
    );
    let fresh = store.publication_review("server").unwrap();
    store
        .queue_publication(
            &owner,
            "server",
            "current-fixture-0001",
            &revisions(&fresh),
            fresh["review_sha256"].as_str(),
        )
        .unwrap();
    assert!(
        store
            .queue_publication(
                &owner,
                "server",
                "another-fixture-0001",
                &revisions(&fresh),
                fresh["review_sha256"].as_str()
            )
            .is_err()
    );
}
#[tokio::test]
async fn retirement_restoration_requires_write_access_csrf_and_current_revision() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let (_root, store, owner) = fixture();
    let id = store
        .save_resource(&owner, "server", "app", &resource(8080), None, 0)
        .unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE resources SET deleted=1,revision=2 WHERE id=?",
            [&id],
        )
        .unwrap();
    let (token, user) = proxy::auth::new_session(&store, &owner).unwrap();
    let app = proxy::web::App::new(
        store.clone(),
        "https://pm.example.test".into(),
        "https://pm.example.test:9444".into(),
    );
    for (csrf, revision, expected) in [
        ("bad", 2, 403),
        (user.csrf.as_str(), 1, 409),
        (user.csrf.as_str(), 2, 200),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/resources/{id}/restore"))
            .header("cookie", format!("kn_proxy={token}"))
            .header("origin", "https://pm.example.test")
            .header("x-csrf-token", csrf)
            .header("content-type", "application/json")
            .body(Body::from(json!({"revision":revision}).to_string()))
            .unwrap();
        let response = proxy::web::router(app.clone())
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), expected);
    }
    let rows = store.resources("server").unwrap();
    assert_eq!(rows[0]["revision"], 3);
    assert_eq!(rows[0]["settings"]["settings"]["upstreams"][0]["weight"], 7);
    assert_eq!(
        store
            .resource_history(&id)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let viewer = proxy::auth::create_user(
        &store,
        "viewer@example.test",
        "Viewer",
        "Another long fixture password",
        Role::Viewer,
    )
    .unwrap();
    let (vtoken, vuser) = proxy::auth::new_session(&store, &viewer).unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute(
            "UPDATE resources SET deleted=1,revision=4 WHERE id=?",
            [&id],
        )
        .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/resources/{id}/restore"))
        .header("cookie", format!("kn_proxy={vtoken}"))
        .header("origin", "https://pm.example.test")
        .header("x-csrf-token", vuser.csrf)
        .header("content-type", "application/json")
        .body(Body::from(json!({"revision":4}).to_string()))
        .unwrap();
    assert_eq!(
        proxy::web::router(app)
            .oneshot(request)
            .await
            .unwrap()
            .status()
            .as_u16(),
        404
    );
}
