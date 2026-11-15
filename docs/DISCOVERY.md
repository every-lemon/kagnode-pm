# Configuration discovery and adoption

KagNode. PM discovers Nginx, Caddy, Apache HTTP Server, HAProxy and Traefik configuration through the authenticated server agent. Installation includes a read-only inventory; the Discovery page lets an administrator request another scan. Scanning does not execute configuration, contact certificate authorities, change listeners or stop existing services.

The report contains source locations, checksums, parsed site settings, known directive names, active services, listening ports and container candidates. Raw source, private keys, credential directives and environment variables are not returned. Includes, security inheritance, custom listeners, unsupported routing and incomplete inventories block automatic adoption rather than disappearing during conversion. HAProxy ACL conversion and complex multi-file/container adoption currently require manual review; inventory support is not a claim that arbitrary configurations can be converted safely.

Select supported sites and choose **Import selected as drafts**. The agent inspects the source again and compares its fingerprint. The controller records verified drafts transactionally and never replaces an existing resource with a repeated import. Activation remains a separate reviewed publication. Partial adoption that would interrupt unselected sites on the same listener must remain blocked until a complete listener migration is reviewed.

## Engines

One primary reverse-proxy engine is selected per server. The current native runtime is Nginx. The comparison interface can generate bounded Caddy, Apache, HAProxy and Traefik previews for supported HTTP resources. Each adapter rejects policies it cannot preserve. Those alternative engines deliberately remain unavailable for native activation until installation, certificate handling, native validation, traffic checks and rollback qualification are complete. Forward proxying is a separate service and cannot be silently converted to an HTTP reverse proxy.

## API

- `POST /api/v1/servers/:id/discovery`: queue a read-only scan using an idempotency key.
- `POST /api/v1/servers/:id/adoptions`: recheck a fingerprint and selected site IDs, then create drafts from the authenticated agent's result.
- `GET /api/v1/engines`: inspect explicit engine capabilities and qualification state.
- `POST /api/v1/servers/:id/engine-plan`: compare generated configuration without activating it.

The interfaces enforce local administration, server grants and CSRF. Adoption additionally requires recent authentication. There is no arbitrary shell, configuration include execution or web-process container socket access.

## Node-side upstream reachability

A current agent advertises `upstream_probe`. Authorized maintainers can request
`POST /api/v1/resources/:id/reachability` with `revision` and `request_key`.
The controller freezes the stored reverse-proxy revision, checks local scope and
CSRF, and queues a read-only job. The caller cannot supply a different target.
Older agents do not advertise the capability and the control is unavailable.

The unprivileged node agent checks at most 32 configured upstreams, four at a
time, with a three-second deadline per connection. It sends no HTTP request and
changes no traffic configuration. Results report reachability, elapsed time and
`application_health_verified: false`. DNS, connect failure and timeout are useful
connectivity signals, not proof that an application is healthy. Six new requests
per actor/node/minute are allowed; exact retries reuse their original job.
