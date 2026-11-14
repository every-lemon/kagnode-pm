use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use kagnode_proxy_manager::{self as proxy, domain::Role};
use serde_json::{Value, json};
use tower::ServiceExt;
fn fixture() -> (tempfile::TempDir, proxy::web::App, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(dir.path()).unwrap();
    let id = proxy::auth::create_user(
        &store,
        "owner@example.com",
        "Owner",
        "A fictional long password!",
        Role::Owner,
    )
    .unwrap();
    let (token, user) = proxy::auth::new_session(&store, &id).unwrap();
    let app = proxy::web::App::new(
        store,
        "https://proxy.example.com".into(),
        "https://proxy.example.com:9444".into(),
    );
    (dir, app, token, user.csrf)
}
async fn call(
    app: &proxy::web::App,
    method: &str,
    url: &str,
    token: &str,
    csrf: &str,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(url)
        .header("cookie", format!("kn_proxy={token}"))
        .header("x-csrf-token", csrf)
        .header("origin", "https://proxy.example.com")
        .header("content-type", "application/json");
    if method == "GET" {
        req = req.header("accept", "application/json");
    }
    let result = proxy::web::router(app.clone())
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = result.status();
    let bytes = result.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
#[tokio::test]
async fn api_authentication_and_csrf_are_server_enforced() {
    let (_dir, app, token, csrf) = fixture();
    assert_eq!(
        call(&app, "GET", "/api/v1/servers", "", "", json!({}))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "GET", "/api/v1/servers", &token, "", json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert!(
        !call(
            &app,
            "POST",
            "/api/v1/enrollments",
            &token,
            "wrong",
            json!({"name":"server"})
        )
        .await
        .0
        .is_success()
    );
    let (status, data) = call(
        &app,
        "POST",
        "/api/v1/enrollments",
        &token,
        &csrf,
        json!({"name":"server","role":"owner"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(data.is_null());
}
#[tokio::test]
async fn logout_invalidates_actual_session() {
    let (_dir, app, token, csrf) = fixture();
    let result = proxy::web::router(app.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .header("cookie", format!("kn_proxy={token}"))
                .header("origin", "https://proxy.example.com")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("_csrf={csrf}")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        call(&app, "GET", "/api/v1/session", &token, &csrf, json!({}))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn viewers_cannot_enroll_or_remove_packages() {
    let (_dir, app, _, _) = fixture();
    let id = proxy::auth::create_user(
        &app.store,
        "viewer@example.com",
        "Viewer",
        "A fictional long password!",
        Role::Viewer,
    )
    .unwrap();
    let (token, user) = proxy::auth::new_session(&app.store, &id).unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/v1/enrollments",
            &token,
            &user.csrf,
            json!({"name":"server"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/v1/servers/hidden/packages/plans",
            &token,
            &user.csrf,
            json!({"names":["bash"],"request_key":"fictional-test-key"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}
#[tokio::test]
async fn source_assets_and_private_runtime_are_not_static_routes() {
    let (_dir, app, token, csrf) = fixture();
    for path in [
        "/assets/../Cargo.toml",
        "/proxy.sqlite",
        "/pki/ca.key",
        "/assets/source.map",
        "/kagnode-core/5.1.0/core.js",
    ] {
        let (status, _) = call(&app, "GET", path, &token, &csrf, json!({})).await;
        assert!(!status.is_success(), "{path}");
    }
}
#[tokio::test]
async fn account_administration_preserves_owner_and_cancels_revoked_work() {
    let (_dir, app, token, csrf) = fixture();
    app.store
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO servers(id,name)VALUES('node','Node')", [])
        .unwrap();
    let (status,created)=call(&app,"POST","/api/v1/users",&token,&csrf,json!({"email":"reader@example.com","name":"Reader","password":"A separate fictional password!","role":"viewer"})).await;
    assert_eq!(status, StatusCode::OK);
    let id = created["id"].as_str().unwrap();
    let (reader, session) = proxy::auth::new_session(&app.store, id).unwrap();
    assert_eq!(
        call(
            &app,
            "GET",
            "/api/v1/users",
            &reader,
            &session.csrf,
            json!({})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let path = format!("/api/v1/users/{id}/servers/node");
    assert_eq!(
        call(
            &app,
            "POST",
            &path,
            &token,
            &csrf,
            json!({"role":"viewer","maintenance":true})
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            "POST",
            &path,
            &token,
            &csrf,
            json!({"role":"maintainer","maintenance":true})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, nodes) = call(
        &app,
        "GET",
        "/api/v1/servers",
        &reader,
        &session.csrf,
        json!({}),
    )
    .await;
    assert_eq!(
        nodes[0]["permissions"],
        json!({"write":true,"maintenance":true})
    );
    let job = app
        .store
        .enqueue(id, "node", "status", json!({}), "revoked-operation-test")
        .unwrap();
    assert_eq!(
        call(&app, "POST", &(path + "/revoke"), &token, &csrf, json!({}))
            .await
            .0,
        StatusCode::OK
    );
    assert!(app.store.claim("node").unwrap().is_null());
    let state: String = app
        .store
        .db
        .lock()
        .unwrap()
        .query_row("SELECT state FROM jobs WHERE id=?", [&job], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "cancelled");
    let owner = proxy::auth::session(&app.store, &{
        let mut h = axum::http::HeaderMap::new();
        h.insert("cookie", format!("kn_proxy={token}").parse().unwrap());
        h
    })
    .unwrap()
    .unwrap();
    assert!(
        !call(
            &app,
            "POST",
            &format!("/api/v1/users/{}", owner.id),
            &token,
            &csrf,
            json!({"role":"viewer","disabled":true})
        )
        .await
        .0
        .is_success()
    );
}
#[tokio::test]
async fn only_fingerprinted_assets_have_immutable_cache_headers() {
    let (_dir, app, _, _) = fixture();
    let path = format!("/assets/{}", proxy::generated_assets::JS_NAME);
    let response = proxy::web::router(app.clone())
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["cache-control"],
        "public, max-age=31536000, immutable"
    );
    let response = proxy::web::router(app)
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
}

#[tokio::test]
async fn recovery_needs_fresh_node_proof_and_never_replays_the_mutation() {
    let (_dir, app, token, csrf) = fixture();
    app.store
        .db
        .lock()
        .unwrap()
        .execute("INSERT INTO servers(id,name)VALUES('node','Node')", [])
        .unwrap();
    let job = app
        .store
        .enqueue(
            "owner",
            "node",
            "configure",
            json!({}),
            "uncertain-config-0001",
        )
        .unwrap();
    app.store
        .db
        .lock()
        .unwrap()
        .execute("UPDATE jobs SET state='uncertain' WHERE id=?", [&job])
        .unwrap();
    let (status, result) = call(
        &app,
        "POST",
        "/api/v1/servers/node/inspect",
        &token,
        &csrf,
        json!({"request_key":"read-only-inspection-001"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let inspection = result["job"].as_str().unwrap();
    let next = app.store.claim("node").unwrap();
    assert_eq!(next["kind"], "status");
    let path = format!("/api/v1/jobs/{job}/resolve");
    let body = json!({"inspection":inspection,"confirmation":job,"reason":"Checked the selected traffic generation and unchanged route responses."});
    assert!(
        !call(&app, "POST", &path, &token, &csrf, body.clone())
            .await
            .0
            .is_success()
    );
    app.store.acknowledge("node",inspection,next["lease"].as_str().unwrap(),&json!({"state":"completed","result":{"pending":true,"package_recovery_required":false}})).unwrap();
    assert!(
        !call(&app, "POST", &path, &token, &csrf, body.clone())
            .await
            .0
            .is_success()
    );
    app.store.db.lock().unwrap().execute("UPDATE jobs SET result=? WHERE id=?",rusqlite::params![json!({"state":"completed","result":{"pending":false,"package_recovery_required":false}}).to_string(),inspection]).unwrap();
    assert_eq!(
        call(&app, "POST", &path, &token, &csrf, body.clone())
            .await
            .0,
        StatusCode::OK
    );
    assert!(
        !call(&app, "POST", &path, &token, &csrf, body)
            .await
            .0
            .is_success()
    );
    let db = app.store.db.lock().unwrap();
    let state: String = db
        .query_row("SELECT state FROM jobs WHERE id=?", [job], |r| r.get(0))
        .unwrap();
    assert_eq!(state, "failed");
    let audits: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM audit WHERE action='job.recovery_acknowledged'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(audits, 1);
}
