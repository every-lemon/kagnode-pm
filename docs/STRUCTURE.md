# Repository map

- `src/`: editable Rust controller, agent, domain, TLS, restricted helper and shared UI adapter.
- `web/app.js`, `web/proxies.js`, `web/app.css`: editable application workflows and styles; shared components belong to KagNode Core. `web/generated/` and `src/generated_assets.rs` are separate minified, fingerprinted build output.
- `vendor/core/`: exact pinned browser fallback, manifest, signatures and retained licenses.
- `scripts/`: bounded package-manager worker, build and setup interfaces.
- `tests/`: permission, transaction, protocol and browser regressions.
- `scripts/systemd/`: native service templates. Installation is explicit; downloading packages does not start services.
- `packaging/`: committed source allowlist and package metadata. `scripts/release.py` builds normalized archives, Debian packages and source-only RPMs from committed source.
- `docs/`: operations, security boundaries, qualification results and migration procedures.
- `target/`, `dist/` and runtime databases: generated/private, excluded from source publication.

## Repository identity

The canonical repository is [every-lemon/kagnode-proxy](https://github.com/every-lemon/kagnode-proxy). `packaging/release.json` keeps `repository: kagnode-pm` as the archive/package prefix and records the canonical source separately as `source_repository`. New release manifests and RPM source URLs use the canonical repository; existing signed manifests and package/service identities are not rewritten.
