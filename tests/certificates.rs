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
    };
    let args = request
        .arguments(std::path::Path::new("/srv/kagnode/proxy-manager/traffic"))
        .unwrap();
    assert!(args.contains(&"--staging".into()));
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
