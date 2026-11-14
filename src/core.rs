//! The application supplies context; the shared Core crate owns asset resolution.
use axum::{
    http::{StatusCode, header},
    response::IntoResponse,
};
pub const CORE_VERSION: &str = "5.0.9";
fn sdk() -> &'static kagnode_core::Core {
    static SDK: std::sync::OnceLock<kagnode_core::Core> = std::sync::OnceLock::new();
    SDK.get_or_init(|| {
        kagnode_core::Core::new(
            std::env::var_os("KAGNODE_CORE_ROOT")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| "/srv/kagnode/core".into()),
            "proxy-manager",
        )
        .expect("checked Core application ID and fallback")
    })
}
pub fn context(authenticated: bool, subject: &str) -> String {
    sdk().head(serde_json::json!({"authenticated":authenticated,"subject":subject,"issuer":"https://nebulacoder.com","publicNavigation":false,"officialAccount":false})).expect("canonical Core context")
}
pub fn escape(s: &str) -> String {
    kagnode_core::escape(s)
}
pub async fn manager(
    action: String,
    parameters: serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    tokio::task::spawn_blocking(move || {
        sdk().manager_request(&action, parameters).map_err(|_| anyhow::anyhow!("The local Core manager is unavailable; inspect its status before retrying an interrupted action"))
    }).await?
}
pub fn version() -> String {
    sdk().active()["version"]
        .as_str()
        .unwrap_or(CORE_VERSION)
        .to_string()
}
pub fn public_notice(value: &serde_json::Value) -> Option<serde_json::Value> {
    if value["available"] != true {
        return None;
    }
    if value["notice"].is_null() {
        return Some(serde_json::json!({"available":true,"notice":null}));
    }
    let n = &value["notice"];
    let text = |key: &str, max: usize| {
        n[key].as_str().is_some_and(|v| {
            !v.is_empty()
                && v.len() <= max
                && !v.chars().any(|c| c.is_control() || matches!(c, '<' | '>'))
        })
    };
    if !n["id"]
        .as_str()
        .is_some_and(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        || !n["version"]
            .as_str()
            .is_some_and(|v| v.starts_with("5.0.") && v.len() < 40)
        || !text("title", 120)
        || !n["items"].as_array().is_some_and(|a| {
            !a.is_empty()
                && a.len() <= 8
                && a.iter().all(|v| {
                    v.as_str().is_some_and(|t| {
                        !t.is_empty()
                            && t.len() <= 240
                            && !t.chars().any(|c| c.is_control() || matches!(c, '<' | '>'))
                    })
                })
        })
    {
        return None;
    }
    Some(
        serde_json::json!({"available":true,"notice":{"id":n["id"],"version":n["version"],"title":n["title"],"items":n["items"]}}),
    )
}
pub async fn asset(
    axum::extract::Path((version, file)): axum::extract::Path<(String, String)>,
) -> impl IntoResponse {
    match sdk().asset(&version, &file) {
        Ok(a) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, a.content_type)],
            a.bytes,
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain")],
            Vec::new(),
        ),
    }
}
