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
