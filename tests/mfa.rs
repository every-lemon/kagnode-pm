use kagnode_proxy_manager::{self as proxy, domain::Role};
#[test]
fn enabling_mfa_revokes_sessions_and_never_stores_recovery_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(dir.path()).unwrap();
    let id = proxy::auth::create_user(
        &store,
        "owner@fixture.invalid",
        "Owner",
        "A fictional long password!",
        Role::Owner,
    )
    .unwrap();
    proxy::auth::new_session(&store, &id).unwrap();
    let secret = proxy::mfa::start_enrollment(&store, &id).unwrap();
    let step = proxy::now() / 30;
    let code = proxy::mfa::code(&secret, step).unwrap();
    let recovery = proxy::mfa::confirm_enrollment(&store, &id, &code).unwrap();
    assert_eq!(recovery.len(), 10);
    let db = store.db.lock().unwrap();
    let sessions: i64 = db
        .query_row("SELECT COUNT(*) FROM sessions WHERE user=?", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(sessions, 0);
    let stored: String = db
        .query_row("SELECT recovery FROM mfa_state WHERE user=?", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    for code in &recovery {
        assert!(!stored.contains(code));
    }
    drop(db);
    assert!(
        proxy::auth::login(
            &store,
            "owner@fixture.invalid",
            "A fictional long password!"
        )
        .is_err()
    );
}
#[test]
fn failed_codes_count_and_success_or_recovery_consumes_attempts() {
    let dir = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(dir.path()).unwrap();
    let id = proxy::auth::create_user(
        &store,
        "owner@fixture.invalid",
        "Owner",
        "A fictional long password!",
        Role::Owner,
    )
    .unwrap();
    let secret = proxy::mfa::start_enrollment(&store, &id).unwrap();
    let recovery = proxy::mfa::confirm_enrollment(
        &store,
        &id,
        &proxy::mfa::code(&secret, proxy::now() / 30).unwrap(),
    )
    .unwrap();
    let token = proxy::mfa::begin(&store, &id).unwrap().unwrap();
    assert!(proxy::mfa::finish(&store, &token, "invalid").is_err());
    let tries: i64 = store
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT tries FROM mfa_attempts WHERE token=?",
            [proxy::digest(&token)],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tries, 1);
    assert_eq!(
        proxy::mfa::finish(&store, &token, &recovery[0]).unwrap(),
        id
    );
    assert!(proxy::mfa::finish(&store, &token, &recovery[0]).is_err());
    let next = proxy::mfa::begin(&store, &id).unwrap().unwrap();
    assert!(proxy::mfa::finish(&store, &next, &recovery[0]).is_err());
    let current = proxy::mfa::code(&secret, proxy::now() / 30 + 1).unwrap();
    assert_eq!(proxy::mfa::finish(&store, &next, &current).unwrap(), id);
    let replay = proxy::mfa::begin(&store, &id).unwrap().unwrap();
    assert!(proxy::mfa::finish(&store, &replay, &current).is_err());
}
#[test]
fn expired_challenges_and_setup_are_not_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let store = proxy::store::Store::open(dir.path()).unwrap();
    let id = proxy::auth::create_user(
        &store,
        "owner@fixture.invalid",
        "Owner",
        "A fictional long password!",
        Role::Owner,
    )
    .unwrap();
    let secret = proxy::mfa::start_enrollment(&store, &id).unwrap();
    store
        .db
        .lock()
        .unwrap()
        .execute("UPDATE mfa_pending SET expires=0", [])
        .unwrap();
    assert!(
        proxy::mfa::confirm_enrollment(
            &store,
            &id,
            &proxy::mfa::code(&secret, proxy::now() / 30).unwrap()
        )
        .is_err()
    );
}
