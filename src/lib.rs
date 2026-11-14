pub mod agent;
pub mod auth;
pub mod broker;
pub mod certificates;
pub mod core;
pub mod domain;
pub mod forward;
pub mod generated_assets;
pub mod mfa;
pub mod migration;
pub mod oauth;
pub mod packages;
pub mod store;
pub mod tls;
pub mod traffic;
pub mod web;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub fn random() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS randomness unavailable");
    hex::encode(bytes)
}
pub fn digest(data: impl AsRef<[u8]>) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}
pub fn private_write(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Missing parent"))?;
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".stage-{}", random()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        anyhow::ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "Refusing nonregular destination"
        );
    }
    std::fs::rename(&temp, path)?;
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
