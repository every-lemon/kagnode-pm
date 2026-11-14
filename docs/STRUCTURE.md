# Repository map

- `src/`: editable Rust controller, agent, domain, TLS, restricted helper and shared UI adapter.
- `web/app.js`, `web/app.css`: editable application workflows and styles; shared components belong to KagNode Core. `web/generated/` and `src/generated_assets.rs` are separate minified, fingerprinted build output.
- `vendor/core/`: exact pinned browser fallback, manifest, signatures and retained licenses.
- `scripts/`: bounded package-manager worker, build and setup interfaces.
- `tests/`: permission, transaction, protocol and browser regressions.
- `scripts/systemd/`: native service templates. Installation is explicit; downloading packages does not start services.
- `packaging/`: committed source allowlist and package metadata. `scripts/release.py` builds normalized archives, Debian packages and source-only RPMs from committed source.
- `docs/`: operations, security boundaries, qualification results and migration procedures.
- `target/`, `dist/` and runtime databases: generated/private, excluded from source publication.
