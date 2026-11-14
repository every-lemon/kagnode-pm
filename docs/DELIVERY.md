# Delivery checklist

The target product is the user-approved multi-server Rust Proxy Manager, Ubuntu 24.04/Debian 13 amd64/arm64, reverse and authenticated public forward proxying, Core presentation, guarded host packages, a verified TLS SOCKS5 client tunnel, and explicit migration from the existing manager at 192.168.0.6.

## Required before stable publication

- [ ] Rust format, type, static analysis and automated regression checks.
- [ ] Browser coverage in Chromium and WebKit, desktop/tablet/mobile and keyboard use.
- [ ] Mutual-TLS enrollment, revocation, rotation, reconnect and interrupted-job recovery.
- [ ] Qualified Nginx/3proxy routing, authentication, isolation, rate limits and traffic tests.
- [ ] Certificate issuance/renewal, Cloudflare and RFC 2136, with isolated CA/DNS checks.
- [ ] KagNode sign-in, local account/MFA and appearance integration.
- [ ] Disposable Ubuntu/Debian native installation, upgrades and protected package transactions.
- [ ] Actual 512 MB/one-vCPU resource benchmark and published scope/limits.
- [ ] Signed reproducible release packages, exact source inventory and protected branch checks.
- [ ] Core Rust adapter, CLI setup/tunnel integration, catalog and private maintainer snapshots.

## Required before live migration

- [ ] Read-only live inventory and supported import report; unsupported fields block cutover.
- [ ] Encrypted backup and isolated restoration verified.
- [ ] Existing certificates, keys, renewal state, routes and access rules preserved.
- [ ] Independent management listener and SSH/console access verified.
- [ ] Controlled cutover, route health checks and rollback rehearsal pass.

No production service, package, route, firewall, DNS or certificate has been changed by creating this source repository. This checklist records unfinished work explicitly; it is not a native qualification claim.

## Verified deployment scope

An explicit Ubuntu 24.04 amd64 deployment has passed native login, mTLS, typed-helper isolation, real reverse traffic, removal of a disposable package with configuration retention, protected SSH-package refusal, local credential rotation and failed-candidate recovery. Chromium and WebKit covered mobile/tablet/desktop; a separate live browser check covered seven pages. The live migration preserved five HTTPS host responses, redirects and certificate fingerprints, retained the independent management TLS identity, and verified a downloaded encrypted backup before cutover. The timed rollback was cancelled only after independent checks; manual rollback remains available.

GitHub checks also pass Rust 1.88 and ARM64 builds/unit tests. These results do not qualify Debian/ARM native operation, public forward-proxy isolation/quotas, every ACME provider, remote-agent certificate rotation or application-update transactions. Those remaining gates above are intentionally not marked complete.

## 5.0.2 editing and certificate patch

This patch adds grouped proxy editing, weighted upstream preservation, explicit published/draft state, route search, recoverable retirement/restoration, and bounded revision history. Publication reviews include additions, updates and removals; the browser supplies a review checksum and the controller freezes and queues the matching snapshot in one transaction. Overlapping publications are refused and exact retries retain their original operation ID.

Chromium and WebKit pass mobile/tablet/desktop workflows for login, Core navigation, TLS upload, route creation, preserving advanced configuration, weighted peers, review, retirement and restoration. Rust regression checks cover frozen publications, stale removal reviews, exact replay after activation, duplicate publication blocking, restore permissions/CSRF/revisions, staging lineage promotion and rejection of untrusted production chains.

A live Let's Encrypt production certificate for vscode.nebulacoder.com was issued and chain/SAN verified before native publication. HTTPS returned 200 from the configured 192.168.0.7:8000 upstream. The pre-existing staging lineage exposed Certbot reuse behavior; the patch forces replacement only during staging promotion and verifies public production trust before certificate selection. No other route or certificate was changed for this request.

Stable release packages retain existing service identities and installation roots. The scope remains Ubuntu 24.04 amd64 native operation; source/data RPMs and other platform limitations are unchanged. Verify release-manifest.sig with packaging/release-public.pem and then SHA256SUMS. The private signing key is excluded from source and packages.
