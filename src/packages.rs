//! Read-only analysis runs without root. Execution belongs only to the broker.
use crate::digest;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub essential: bool,
    pub protected: bool,
    pub held: bool,
    pub bytes: u64,
    pub services: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub packages: Vec<Package>,
    pub required: BTreeSet<String>,
    pub uncertain: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovalPlan {
    #[serde(default)]
    pub created_at: i64,
    pub requested: Vec<String>,
    pub removals: Vec<String>,
    pub fingerprint: String,
    pub blockers: BTreeMap<String, Vec<String>>,
    pub reclaimed_bytes: u64,
    pub confirmation: String,
}
pub fn valid_name(name: &str) -> bool {
    let mut parts = name.split(':');
    let base = parts.next().unwrap_or("");
    let arch = parts.next();
    !base.is_empty()
        && base.len() <= 200
        && base.as_bytes()[0].is_ascii_alphanumeric()
        && base
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b))
        && arch.is_none_or(|a| matches!(a, "amd64" | "arm64" | "all" | "i386"))
        && parts.next().is_none()
}
pub fn protected_name(name: &str) -> bool {
    let p = name.split(':').next().unwrap_or("");
    [
        "apt",
        "dpkg",
        "systemd",
        "udev",
        "linux-",
        "grub",
        "shim",
        "initramfs",
        "network",
        "netplan",
        "ifupdown",
        "iproute",
        "isc-dhcp",
        "dhcpcd",
        "resolv",
        "libc6",
        "libpam",
        "libnss",
        "libssl",
        "libsystemd",
        "openssl",
        "openssh",
        "sudo",
        "kagnode",
        "nginx",
        "3proxy",
        "python3-apt",
        "python3-minimal",
        "python3.",
    ]
    .iter()
    .any(|s| p.starts_with(s))
        || [
            "bash",
            "dash",
            "coreutils",
            "util-linux",
            "mount",
            "login",
            "passwd",
            "ca-certificates",
            "dbus",
            "tzdata",
            "chrony",
            "ntp",
            "polkitd",
            "libapt-pkg6.0",
            "libapt-pkg7.0",
            "python3",
        ]
        .contains(&p)
}
pub fn analyze(
    inventory: &Inventory,
    requested: Vec<String>,
    removals: Vec<String>,
) -> Result<RemovalPlan> {
    ensure!(
        !requested.is_empty()
            && requested.len() <= 32
            && requested.iter().chain(&removals).all(|s| valid_name(s)),
        "Choose exact installed package names"
    );
    let by_name: BTreeMap<_, _> = inventory
        .packages
        .iter()
        .map(|p| (p.name.clone(), p))
        .collect();
    for n in &requested {
        ensure!(by_name.contains_key(n), "Package is not installed: {n}");
    }
    ensure!(
        !removals.is_empty() && requested.iter().all(|p| removals.contains(p)),
        "Incomplete dependency solution"
    );
    let mut blockers = BTreeMap::new();
    let mut bytes = 0;
    for name in &removals {
        let mut reasons = vec![];
        if let Some(p) = by_name.get(name) {
            if p.essential {
                reasons.push("Operating-system Essential package".into())
            }
            if p.protected {
                reasons.push("Operating-system Protected package".into())
            }
            if p.held {
                reasons.push("Package is held".into())
            }
            if protected_name(name) {
                reasons.push("Required for boot, networking, access or proxy management".into())
            }
            if inventory.required.contains(name) {
                reasons.push("Required by a managed application".into())
            }
            if !p.services.is_empty() {
                reasons.push(format!(
                    "Retire these services first: {}",
                    p.services.join(", ")
                ))
            }
            bytes += p.bytes;
        } else {
            reasons.push("Package ownership is unknown".into())
        }
        if !inventory.uncertain.is_empty() {
            reasons.push(format!(
                "Inventory could not be verified: {}",
                inventory.uncertain.join(", ")
            ))
        }
        if !reasons.is_empty() {
            blockers.insert(name.clone(), reasons);
        }
    }
    let fingerprint = digest(serde_json::to_vec(inventory)?);
    let mut plan = RemovalPlan {
        created_at: crate::now(),
        requested,
        removals,
        fingerprint,
        blockers,
        reclaimed_bytes: bytes,
        confirmation: String::new(),
    };
    plan.confirmation = digest(serde_json::to_vec(
        &serde_json::json!({"requested":plan.requested,"removals":plan.removals,"fingerprint":plan.fingerprint,"blockers":plan.blockers,"reclaimed_bytes":plan.reclaimed_bytes}),
    )?);
    Ok(plan)
}
pub fn transaction_script() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let installed = exe.parent().unwrap().join("libexec/package_transaction.py");
    let path = if installed.is_file() {
        installed
    } else if cfg!(debug_assertions) {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/package_transaction.py")
    } else {
        PathBuf::from("/usr/libexec/kagnode-proxy-manager/package_transaction.py")
    };
    let meta = std::fs::symlink_metadata(&path)?;
    use std::os::unix::fs::MetadataExt;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0,
        "Untrusted package worker"
    );
    Ok(path)
}
pub async fn native_preview(requested: Vec<String>) -> Result<RemovalPlan> {
    ensure!(
        requested.iter().all(|n| valid_name(n)),
        "Invalid package name"
    );
    let mut cmd = tokio::process::Command::new("/usr/bin/python3");
    cmd.arg("-I")
        .arg(transaction_script()?)
        .arg("preview")
        .args(&requested)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(90), cmd.output()).await??;
    ensure!(
        output.status.success(),
        "Package inventory failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(
        output.stdout.len() < 4 * 1024 * 1024,
        "Package inventory exceeded limit"
    );
    let data: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    analyze(
        &serde_json::from_value::<Inventory>(data["inventory"].clone())?,
        serde_json::from_value(data["requested"].clone())?,
        serde_json::from_value(data["removals"].clone())?,
    )
}
