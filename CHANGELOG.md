# Changelog

## Unreleased — target 5.0.0

New independent Rust implementation. Development and qualification are in progress; no stable release or live migration is represented by this entry.

### Native migration verification

- Preserve the existing TLS management listener and imported ACME certificate lineages during reviewed migration.
- Correct the KagNode OAuth installation origin and preserve recovery holds when no queued job can run.
- Add fresh-node inspection and audited recovery acknowledgements without replaying uncertain operations.
- Resolve merged-/usr package ownership and batch service inspection for smaller systems.
- Execute removal-only APT transactions without an unnecessary archive-download phase.
- Maintain the combined installation’s local fleet credentials before expiry.
