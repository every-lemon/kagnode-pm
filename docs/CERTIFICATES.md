# Certificate authorities, validation and uploaded certificates

Certificate authority and domain validation are independent selections. Let's Encrypt supports its production and staging directories. ZeroSSL or another ACME authority must be declared in a private, root-owned `/etc/kagnode/proxy-manager/acme-providers.json`; the browser supplies only its registered identifier, never an arbitrary directory URL or shell hook.

```json
{
  "zerossl": {
    "directory": "https://acme.zerossl.com/v2/DV90",
    "staging_directory": "https://your-approved-staging-authority.example/directory",
    "eab_config": "zerossl-account"
  },
  "custom": {
    "directory": "https://your-private-ca.example/acme/directory",
    "staging_directory": "https://your-private-ca-staging.example/acme/directory"
  }
}
```

The staging addresses above are examples, not functioning provider endpoints. KagNode. Proxy refuses staging issuance when no staging directory is configured; it never silently switches to production. External account binding uses a private `traffic/credentials/<id>.eab.ini` containing exactly `eab-kid` and `eab-hmac-key`. Secrets stay out of process arguments. HTTP, Cloudflare DNS and RFC 2136 DNS remain the existing structured validation methods. Credentials are local root-owned files. Actual issuance depends on the installed Certbot/plugin build, provider account and DNS access; a configuration test does not establish issuance readiness.

## Upload

Upload a PEM certificate/full chain, unencrypted PEM private key and optional intermediate chain over HTTPS. The interface supports chains up to 16 KiB and keys up to 8 KiB. List concrete site hostnames when uploading a wildcard certificate so coverage can be verified.

The agent checks the public/private key match, certificate dates, chain and hostname coverage. System trust is the default. Selecting **Private CA / self-signed** explicitly trusts the supplied chain anchor for validation; client devices must separately trust that CA. Uploaded certificates have manual renewal.

Uploaded private keys are AEAD-encrypted in the controller's persistent queue, bound to their destination server, and transported through the existing mutually authenticated agent connection and restricted local helper. Activity and job results contain no private keys. Keep the private `controller/queue-secret.key` in encrypted backups; it is needed to recover pending uploads.

Successful uploads create immutable certificate versions. They never reload traffic. An existing certificate ID retains its current selected key pair. **Review activation** rechecks the expected current fingerprint and coverage of all active sites, validates Nginx, then reloads the traffic service. Failed activation restores the old selection and retains a recovery journal for inspection. The journal is not cleared by replaying an update.

## API

- `POST /api/v1/servers/:id/certificates/upload`: enqueue a bounded PEM upload; requires a local administrator, host-maintenance grant, recent authentication and CSRF.
- `POST /api/v1/servers/:id/certificates/activate`: activate a reviewed certificate version with the expected current SHA-256 fingerprint and an idempotency key.

No private-key read/download endpoint is exposed.

## Staging-to-production promotion

A staging test uses an untrusted test certificate. When a Let's Encrypt lineage was created against staging, a production request explicitly replaces it rather than reusing Certbot's still-valid staging result. Public-authority production certificates must chain to the system CA store and cover every requested hostname before KagNode. Proxy selects them. A normal production lineage is not force-renewed on every request. Certificate selection still requires a reviewed route publication to change live traffic.
