<p align="center"><img src="vendor/core/mark.svg" width="64" alt="KagNode."></p>

# KagNode. PM

## Overview

A new Rust application for managing reverse proxies, authenticated forward proxies and server maintenance across a fleet. The controller and agents manage configuration; Nginx and optional 3proxy handle traffic.

### What it looks like

Screenshots come from an isolated test controller with one fictional, offline server. Nothing was applied to a real proxy, certificate or host.

| Overview                                                                                             | Reverse proxies                                                                            |
| ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| ![The overview with counts of servers and draft changes and a server list](docs/images/overview.png) | ![The reverse-proxy routes page for the fictional server](docs/images/reverse-proxies.png) |
| ![The certificates page](docs/images/certificates.png)                                               | ![The overview on a phone](docs/images/overview-mobile.png)                                |

### How it works

1. **One controller, many servers.** You run the controller once. Each server you enroll runs an agent that connects with a mutual-TLS identity; you can revoke it at any time.
2. **You edit typed configuration.** Reverse hosts, upstreams (with weights), TCP/UDP streams and authenticated forward proxies are structured forms, not free text. Every change carries a revision, so two people cannot silently overwrite each other.
3. **Review, then publish.** A publication is a reviewed snapshot. Its result is shown after it runs, and a conflicting or duplicate change cannot replace what was reviewed.
4. **Agents do the work; Nginx carries the traffic.** The controller and agents manage configuration; Nginx (and optionally 3proxy) handles the traffic. Jobs are durable, so a restart does not lose them.
5. **Bring what you already have.** Read-only discovery finds existing Nginx, Caddy, Apache, HAProxy and Traefik setups so you can review and import them as drafts.
6. **Certificates.** You choose the ACME authority and validation method, or upload a certificate, which is queued and encrypted.
7. **Accounts and audit.** Local accounts support MFA and recovery codes, with per-node permissions and an audit record of changes.
8. **Qualification matters.** Listing a feature here does not mean its native runtime is qualified. Check the delivery checklist before replacing a working proxy.

## Release status

**Version 5.0.2: PM editing, publication review and production-certificate repairs.** Ubuntu 24.04 amd64 is the native deployment target; see the dated validation notes. Broader native-platform, forward-engine and external certificate-provider qualification remains pending; a general stable package release has not been published.

The repository distinguishes implemented functions from verification still required in [the delivery checklist](docs/DELIVERY.md). Do not replace a working proxy using an unqualified development build. All KagNode release versions remain on the 5.0.x line.

## Features

- Typed reverse-host, upstream, TCP/UDP and forward-proxy configuration.
- Multi-server enrollment, mutual TLS identities, revocation and durable jobs.
- Local accounts, MFA/recovery codes, node permissions, revision checks and audit records.
- KagNode Core presentation, served locally with an embedded fallback.
- Dependency-aware package-removal previews and a restricted local execution helper.
- Read-only discovery for Nginx, Caddy, Apache, HAProxy and Traefik, with source review and verified draft import.
- Canonical Core login/sidebar/account presentation and permission-filtered quick search.
- Independent ACME authority/validation selection and encrypted queued certificate upload.
- Structured reverse-proxy editing, preserved upstream weights, publication status, searchable routes, recoverable retirement and revision history.
- Reviewed publication snapshots and visible asynchronous outcomes; conflicting or duplicate changes cannot silently replace a reviewed configuration.

Full capability and native-qualification status is recorded in the delivery checklist; listing a feature does not imply its native runtime is qualified.

## Requirements

Target systems: Ubuntu 24.04 or Debian 13, Linux amd64/arm64 with systemd. Nginx is the qualified native reverse engine; alternative-engine configuration previews reject unsupported policies and remain gated from native activation. forward listeners additionally require a qualified 3proxy build. Package inspection/transactions use distribution `python3-apt` transiently. Development requires Rust 1.88+, a C compiler and OpenSSL. Node.js 24 is used only when regenerating web assets; it is not a server runtime dependency.

## Installation and downloads

Release formats include application `.deb`, `.tar.xz`, `.tar.gz` and `.zip`, plus corresponding source archives. RPM is source/data only; Rocky Linux native operation is outside the supported platform matrix.

| Platform     | Architecture           | Application/native status                                     |
| ------------ | ---------------------- | ------------------------------------------------------------- |
| Ubuntu 24.04 | amd64 / arm64          | amd64 native verified; arm64 build/tests pass, native pending |
| Debian 13    | amd64 / arm64          | Qualification pending                                         |
| Rocky Linux  | noarch source/data RPM | No native support claim                                       |

## Usage

Run `cargo run -- --help` for the current command interface. Credentials and enrollment tokens are supplied through standard input, never command arguments. Initializing a controller does not start listeners or change networking. Live proxy replacement requires a separately validated migration.

## Configuration and storage

New managed installations use `/srv/kagnode/proxy-manager/`. Controller and agent data are separate; runtime sockets, OS services and package-manager state remain in their system locations. Secrets, runtime databases, live configurations and backups must never enter Git.

## Security

Read [SECURITY.md](SECURITY.md). The web process cannot issue arbitrary shell commands. Package operations require a host capability and recent authentication and a host-maintenance grant; protected or unverified removal plans are blocked. Root administrators outside this application remain responsible for their hosts.

## Development and testing

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Native package removal and proxy activation are tested only in disposable systems before rollout. Resource targets are goals until published measurements establish actual results.

## Documentation

- [Configuration discovery and engine comparison](docs/DISCOVERY.md)
- [Certificate authorities and uploads](docs/CERTIFICATES.md)
- [Native deployment and legacy migration](docs/MIGRATION.md)
- [Delivery and verification checklist](docs/DELIVERY.md)
- [Repository map](docs/STRUCTURE.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Licensing

Application source: **AGPL-3.0-only**. Retain third-party notices and their licenses. KagNode artwork has a separate permission policy in `vendor/core/ARTWORK-LICENSE.txt`. Nginx and 3proxy retain their upstream licenses.
