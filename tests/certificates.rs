use kagnode_proxy_manager::certificates::{Provider, Request};
#[test]
fn certificate_requests_are_structured_and_never_shell_hooks() {
    let request = Request {
        id: "service".into(),
        domains: vec!["*.example.com".into()],
        email: "admin@example.com".into(),
        provider: Provider::Cloudflare {
            credential: "zone-limited".into(),
        },
        staging: true,
        authority: "letsencrypt".into(),
    };
    let args = request
        .arguments(std::path::Path::new("/srv/kagnode/proxy-manager/traffic"))
        .unwrap();
    assert!(args.iter().any(|v| v.contains("acme-staging-v02")));
    assert!(args.contains(&"--dns-cloudflare".into()));
    assert!(
        !args
            .iter()
            .any(|a| a.contains("--deploy-hook") || a.contains("--manual-auth-hook"))
    );
    let mut invalid = request.clone();
    invalid.provider = Provider::Http {};
    assert!(invalid.validate().is_err());
    invalid = request;
    invalid.domains = vec!["example.com\n--manual-auth-hook".into()];
    assert!(invalid.validate().is_err());
}
#[test]
fn dns_credentials_require_exact_fields_and_keep_secrets_out_of_arguments() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        kagnode_proxy_manager::certificates::write_credential(
            root.path(),
            "zone",
            "cloudflare",
            serde_json::json!({"dns_cloudflare_api_token":"test-secret\ninjected = yes"})
        )
        .is_err()
    );
    assert!(
        kagnode_proxy_manager::certificates::write_credential(
            root.path(),
            "../escape",
            "cloudflare",
            serde_json::json!({"dns_cloudflare_api_token":"test-secret"})
        )
        .is_err()
    );
    assert!(
        kagnode_proxy_manager::certificates::write_credential(
            root.path(),
            "zone",
            "cloudflare",
            serde_json::json!({"dns_cloudflare_api_token":"test-secret","hook":"whoami"})
        )
        .is_err()
    );
}

#[test]
fn uploaded_private_keys_are_encrypted_and_bound_to_server() {
    let root = tempfile::tempdir().unwrap();
    let input = serde_json::json!({"private_key":"fictional-sensitive-fixture"});
    let protected =
        kagnode_proxy_manager::certificates::sealed(root.path(), "server-a", &input).unwrap();
    assert!(
        !protected
            .to_string()
            .contains("fictional-sensitive-fixture")
    );
    assert_eq!(
        kagnode_proxy_manager::certificates::unseal(root.path(), "server-a", &protected).unwrap(),
        input
    );
    assert!(
        kagnode_proxy_manager::certificates::unseal(root.path(), "server-b", &protected).is_err()
    );
    let mut tampered = protected;
    tampered["nonce"] = serde_json::json!("11".repeat(12));
    assert!(
        kagnode_proxy_manager::certificates::unseal(root.path(), "server-a", &tampered).is_err()
    );
}

#[tokio::test]
async fn uploaded_certificate_checks_key_hostname_and_trust_before_selection() {
    use kagnode_proxy_manager::{certificates, tls};
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("fixture.pem");
    let key = dir.path().join("fixture.key");
    tls::command(
        "/usr/bin/openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=fixture.example.com",
            "-addext",
            "subjectAltName=DNS:fixture.example.com",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
        ],
    )
    .await
    .unwrap();
    let input = certificates::Upload {
        id: "fixture".into(),
        domains: vec!["fixture.example.com".into()],
        certificate: std::fs::read_to_string(&cert).unwrap(),
        private_key: std::fs::read_to_string(&key).unwrap(),
        intermediate_chain: String::new(),
        private_ca: true,
    };
    let mut bad = input.clone();
    bad.domains = vec!["other.example.com".into()];
    assert!(certificates::upload(dir.path(), bad).await.is_err());
    assert!(!dir.path().join("certificates/fixture").exists());
    let mut public = input.clone();
    public.private_ca = false;
    assert!(certificates::upload(dir.path(), public).await.is_err());
    let result = certificates::upload(dir.path(), input).await.unwrap();
    assert_eq!(result["state"], "validated");
    assert_eq!(result["renewal"], "manual");
    assert_eq!(result["traffic_reloaded"], false);
}

#[test]
fn production_promotion_replaces_a_staging_lineage_without_forcing_regular_renewals() {
    let root = tempfile::tempdir().unwrap();
    let renewal = root.path().join("acme/config/renewal");
    std::fs::create_dir_all(&renewal).unwrap();
    let file = renewal.join("kn-service.conf");
    std::fs::write(
        &file,
        "[renewalparams]\nserver = https://acme-staging-v02.api.letsencrypt.org/directory\n",
    )
    .unwrap();
    let mut request = Request {
        id: "service".into(),
        domains: vec!["service.example.com".into()],
        email: "admin@example.com".into(),
        provider: Provider::Http {},
        authority: "letsencrypt".into(),
        staging: false,
    };
    assert!(
        request
            .arguments(root.path())
            .unwrap()
            .contains(&"--force-renewal".into())
    );
    request.staging = true;
    assert!(
        !request
            .arguments(root.path())
            .unwrap()
            .contains(&"--force-renewal".into())
    );
    request.staging = false;
    std::fs::write(
        &file,
        "server = https://acme-v02.api.letsencrypt.org/directory\n",
    )
    .unwrap();
    assert!(
        !request
            .arguments(root.path())
            .unwrap()
            .contains(&"--force-renewal".into())
    );
}
#[tokio::test]
async fn public_production_issuance_refuses_untrusted_certificate_chains() {
    let root = tempfile::tempdir().unwrap();
    let cert = root.path().join("cert.pem");
    let key = root.path().join("key.pem");
    kagnode_proxy_manager::tls::command(
        "/usr/bin/openssl",
        &[
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=STAGING fixture",
        ],
    )
    .await
    .unwrap();
    std::fs::copy(&cert, root.path().join("chain.pem")).unwrap();
    let error = kagnode_proxy_manager::certificates::validate_public_chain(root.path())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("not publicly trusted"));
}
