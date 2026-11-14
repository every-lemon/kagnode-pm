# Native deployment and legacy migration

KagNode Proxy Manager 5.0.0 separates the controller, outbound agent and typed root helper. The existing management listener can remain an independent Nginx TLS frontend. Its public origin must exactly match the configured controller origin, including its port. Bind a controller behind that frontend to loopback and use `--behind-proxy`.

## Before adoption

1. Inventory the existing Nginx routes, access rules, certificate identities, renewal accounts, enabled services and management listener. Run `import-preview` against the legacy schema-2 document. Unsupported routing or security settings block cutover.
2. Create an encrypted backup outside the public repository. Verify a fresh downloaded copy by decrypting it and comparing its full inventory, permissions and ownership. Keep a local rollback copy.
3. Qualify the exact application binary and Python helpers in a disposable system. Test native traffic, management authentication, mTLS enrollment, rejected unauthenticated agents, restricted-helper permissions and package transaction protection.
4. Stage the new controller and agent on dedicated management/fleet ports. This must not start a second traffic listener on ports already owned by the existing Nginx service.

## Imported certificates

Import each certificate/key pair into a private version directory under `traffic/certificate-versions/<id>/`. Validate the public chain, all hostnames and the key match. Select each version with an atomic `traffic/certificates/<id>` symlink. Keep private keys outside web assets, source archives and browser responses.

For existing `nginx-manager` acme.sh lineages, `scripts/legacy_renew.py` preserves the original accounts and renewal schedule without applying the previous manager's proxy configuration. Its root-controlled policy is `/etc/kagnode/proxy-manager/imported-certificates.json`:

```json
{ "schema": 1, "ids": ["existing-site-id"] }
```

The bridge calls only the reviewed lineage's renewal/export operations, validates the resulting certificate, switches the key pair atomically and reloads the new traffic service. An error restores selected certificate pointers. The old ACME challenge webroot must resolve to the new traffic challenge directory. Run `--check` to validate current certificates without an ACME request or file changes. Disable the previous renewal timer only after installing and checking the replacement timer. Existing manager code and ACME account directories remain available for this bridge and rollback.

New installations use the distribution Certbot integration. Public CA issuance and DNS-provider verification require the actual domain, DNS credentials and provider access; syntax tests are not issuance verification.

## Cutover and rollback

Prepare a root-controlled rollback command and arm a time-limited local watchdog before changing listeners. Retain SSH and the independent management listener. Stop the previous traffic service, publish the reviewed resource revisions and start the new agent immediately. Check every hostname over HTTP and verified HTTPS, compare certificate identities and check the independent management login. If a check fails, restore the original traffic and management configuration and services.

Only after these checks pass should the old traffic/web services be disabled and the rollback watchdog cancelled. Retain their original files and encrypted backup. Do not erase existing user data or reset any database.

## Recovery and credentials

Jobs are never automatically replayed after an ambiguous interruption. The Jobs page can request a read-only node inspection even while a recovery hold blocks mutations. A recently authenticated administrator can record the inspected failure only after fresh agent evidence confirms there are no unresolved native activation/package journals. The original outcome and explanation remain in the audit record. Native package journals require local inspection; clearing a portal hold cannot clear those journals.

Combined installations check their local fleet certificate expiry twice daily. `local_credentials.py` rotates the local agent and fleet server certificates before expiry, retaining the fleet CA and a rollback copy. `--check` makes no changes. `--rotate-now` is a root-only maintenance action. External agents are not rotated by this local operation; their identity rotation remains a separate enrollment/administration requirement.

Package removal uses a fresh dependency solution under APT's transaction locks. Only the exact reviewed removal set is executed, without purge, autoremove or an archive-download phase. Essential, protected, held, required, service-owned or uncertain packages are blocked. Package maintainer scripts still run as part of the operating system's normal removal transaction. Test actual transactions only in disposable systems.
