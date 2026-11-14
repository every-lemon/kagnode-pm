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
