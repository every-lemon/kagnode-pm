/* Readable proxy workflows; shared controls, dialogs and motion belong to Core. */
export const lines = (value) =>
  value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
export function parseHeaders(value) {
  const result = {},
    seen = new Set();
  for (const line of lines(value)) {
    const colon = line.indexOf(":");
    if (colon < 1) throw Error("Enter each header as Name: value.");
    const key = line.slice(0, colon).trim();
    if (seen.has(key.toLowerCase()))
      throw Error("Each header name must be unique.");
    seen.add(key.toLowerCase());
    result[key] = line.slice(colon + 1).trim();
  }
  return result;
}
export function routeStatus(row) {
  return row.published === row.revision
    ? "Published"
    : row.published
      ? "Unpublished changes"
      : "Draft";
}
export function proposedName(domain) {
  return domain
    .toLowerCase()
    .replace(/^\*\./, "wildcard-")
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 64);
}
export function createProxyUI(env) {
  const {
    api,
    post,
    el,
    button,
    modal,
    field,
    busy,
    notice,
    refresh,
    table,
    getServer,
    canWrite,
  } = env;
  function toggle(form, label, name, checked) {
    const row = el("label", undefined, "pm-switch-row"),
      input = el("input");
    input.type = "checkbox";
    input.name = name;
    input.checked = checked;
    input.dataset.coreSwitch = "";
    row.append(input, el("span", label));
    form.append(row);
    return input;
  }
  function section(form, title, description, collapsed = false) {
    const box = el(
      collapsed ? "details" : "section",
      undefined,
      "pm-editor-section wide",
    );
    box.append(el(collapsed ? "summary" : "h3", title));
    if (description) box.append(el("p", description, "muted"));
    const grid = el("div", undefined, "form-grid");
    box.append(grid);
    form.append(box);
    return grid;
  }
  function numeric(form, label, name, value, min, max) {
    const input = field(form, label, name, value, "number");
    input.min = min;
    input.max = max;
    input.step = "1";
    input.required = true;
    return input;
  }
  async function edit(row) {
    const server = getServer(),
      v = row?.settings.settings || {},
      m = modal(row ? "Edit reverse proxy" : "New reverse proxy"),
      f = el("form", undefined, "form-grid pm-proxy-editor");
    m.dialog.classList.add("pm-editor-dialog");
    const intro = el(
      "p",
      row
        ? "Save a draft, review the changes, then publish. Live traffic is unchanged until publication."
        : "Choose a domain and where requests should go. TLS and access settings can be configured below.",
      "muted",
    );
    m.body.append(intro, f);
    const basics = section(
      f,
      "Route",
      "Use a short identifier for this route. Domains can include a leading wildcard.",
    );
    const name = field(basics, "Route name", "name", row?.name || "");
    name.required = true;
    name.pattern = "[a-z0-9-]{1,64}";
    name.maxLength = 64;
    const domains = field(
      basics,
      "Domains, one per line",
      "domains",
      (v.domains || []).join("\n"),
      "textarea",
      true,
    );
    domains.required = true;
    domains.addEventListener("change", () => {
      if (!row && !name.value)
        name.value = proposedName(lines(domains.value)[0] || "");
    });
    const path = field(basics, "Route path", "path", v.path || "/");
    path.required = true;
    const routing = section(
        f,
        "Upstreams",
        "HTTP(S) origins only. Weight and backup settings are preserved when editing.",
      ),
      peers = el("div", undefined, "stack wide");
    routing.append(peers);
    function addPeer(value = { address: "", weight: 1, backup: false }) {
      const peer = el("div", undefined, "pm-upstream"),
        fields = el("div", undefined, "form-grid");
      const address = field(
        fields,
        "Upstream origin",
        "upstream_address",
        value.address,
      );
      address.type = "url";
      address.required = true;
      address.placeholder = "http://192.168.0.10:8080";
      numeric(fields, "Weight", "upstream_weight", value.weight, 1, 100);
      const backup = toggle(
        fields,
        "Backup upstream",
        "upstream_backup",
        !!value.backup,
      );
      const remove = button("Remove upstream", () => {
        if (peers.children.length > 1) peer.remove();
        else notice("Keep at least one primary upstream.");
      });
      remove.classList.add("quiet");
      peer.append(fields, remove);
      peer.read = () => ({
        address: address.value.trim(),
        weight: Number(fields.querySelector("[name=upstream_weight]").value),
        backup: backup.checked,
      });
      peers.append(peer);
    }
    (v.upstreams?.length
      ? v.upstreams
      : [{ address: "", weight: 1, backup: false }]
    ).forEach(addPeer);
    routing.append(button("Add upstream", () => addPeer()));
    const balanceLabel = el("label", "Load balancing"),
      balance = el("select");
    balance.name = "balance";
    for (const [value, label] of [
      ["round_robin", "Round robin"],
      ["least_connections", "Least connections"],
      ["ip_hash", "Client IP affinity"],
    ]) {
      const o = el("option", label);
      o.value = value;
      balance.append(o);
    }
    balance.value = v.balance || "round_robin";
    balanceLabel.append(balance);
    routing.append(balanceLabel);
    const transport = section(
      f,
      "TLS and protocols",
      "Choose an existing certificate, or manage providers and uploads on Certificates.",
      true,
    );
    const cert = field(
      transport,
      "Certificate ID (optional)",
      "certificate",
      v.certificate || "",
    );
    cert.placeholder = "Choose or enter a certificate ID";
    const choices = el("datalist");
    choices.id = "certificates-" + crypto.randomUUID();
    cert.setAttribute("list", choices.id);
    transport.append(choices);
    api("/servers/" + server + "/jobs")
      .then((jobs) => {
        const inventory =
          jobs.find(
            (j) =>
              j.kind === "certificate_inventory" && j.state === "completed",
          )?.result?.result || [];
        if (Array.isArray(inventory))
          for (const c of inventory) {
            const o = el("option");
            o.value = c.id;
            choices.append(o);
          }
      })
      .catch(() => {});
    const certPage = el("a", "Manage certificates");
    certPage.href = "/certificates?server=" + encodeURIComponent(server);
    transport.append(certPage);
    toggle(
      transport,
      "Redirect HTTP to HTTPS",
      "force_https",
      v.force_https !== false,
    );
    const ws = toggle(
        transport,
        "Enable WebSockets",
        "websocket",
        row ? !!v.websocket : true,
      ),
      grpc = toggle(transport, "Enable gRPC", "grpc", !!v.grpc);
    ws.addEventListener("change", () => {
      if (ws.checked) grpc.checked = false;
    });
    grpc.addEventListener("change", () => {
      if (grpc.checked) ws.checked = false;
    });
    const limits = section(
      f,
      "Limits and access",
      "An empty client list permits all clients. Existing authentication and mTLS references are retained.",
      true,
    );
    numeric(
      limits,
      "Timeout, seconds",
      "timeout",
      v.timeout_seconds ?? 60,
      1,
      3600,
    );
    numeric(
      limits,
      "Upload limit, MiB",
      "upload",
      v.max_body_mib ?? 16,
      0,
      1024,
    );
    field(
      limits,
      "Allowed client CIDRs, one per line",
      "clients",
      (v.allowed_clients || []).join("\n"),
      "textarea",
      true,
    );
    field(
      limits,
      "Authentication group (optional)",
      "authentication",
      v.authentication || "",
    );
    field(limits, "Client CA ID (optional)", "client_ca", v.client_ca || "");
    const advanced = section(
      f,
      "Advanced",
      "Settings below are included in the draft and validated again by the server.",
      true,
    );
    toggle(
      advanced,
      "Strip the route prefix",
      "strip_prefix",
      !!v.strip_prefix,
    );
    toggle(advanced, "Enable compression", "compression", !!v.compression);
    field(
      advanced,
      "Upstream TLS server name (optional)",
      "tls_name",
      v.upstream_tls_name || "",
    );
    field(
      advanced,
      "Upstream client certificate ID (optional)",
      "upstream_cert",
      v.upstream_client_certificate || "",
    );
    field(
      advanced,
      "Redirect URL (optional)",
      "redirect",
      v.redirect || "",
      "url",
      true,
    );
    const rate = field(
      advanced,
      "Requests per second (optional)",
      "rate",
      v.rate_per_second ?? "",
      "number",
    );
    rate.min = 1;
    rate.max = 65535;
    rate.step = 1;
    const cache = field(
      advanced,
      "Cache limit, MiB (optional)",
      "cache",
      v.cache_mib ?? "",
      "number",
    );
    cache.min = 1;
    cache.max = 4096;
    cache.step = 1;
    field(
      advanced,
      "Response headers, one Name: value per line",
      "headers",
      Object.entries(v.headers || {})
        .map(([k, value]) => k + ": " + value)
        .join("\n"),
      "textarea",
      true,
    );
    const footer = el("div", undefined, "pm-editor-footer wide"),
      cancel = button("Cancel", () => m.dialog.close()),
      save = el("button", "Save draft", "button primary");
    save.type = "submit";
    footer.append(cancel, save);
    f.append(footer);
    f.onsubmit = async (event) => {
      event.preventDefault();
      const get = (n) => f.elements[n].value.trim(),
        checked = (n) => f.elements[n].checked;
      try {
        const upstreams = [...peers.children].map((p) => p.read());
        if (upstreams.every((p) => p.backup))
          throw Error("Keep at least one primary upstream.");
        const settings = {
          ...v,
          domains: lines(get("domains")),
          upstreams,
          path: get("path"),
          certificate: get("certificate") || null,
          balance: get("balance"),
          force_https: checked("force_https"),
          websocket: ws.checked,
          grpc: grpc.checked,
          timeout_seconds: Number(get("timeout")),
          max_body_mib: Number(get("upload")),
          allowed_clients: lines(get("clients")),
          authentication: get("authentication") || null,
          client_ca: get("client_ca") || null,
          strip_prefix: checked("strip_prefix"),
          compression: checked("compression"),
          upstream_tls_name: get("tls_name") || null,
          upstream_client_certificate: get("upstream_cert") || null,
          redirect: get("redirect") || null,
          rate_per_second: get("rate") ? Number(get("rate")) : null,
          cache_mib: get("cache") ? Number(get("cache")) : null,
          headers: parseHeaders(get("headers")),
        };
        await busy(save, "Saving draft…", () =>
          post("/servers/" + server + "/resources", {
            name: get("name"),
            resource: { kind: "proxy_host", settings },
            id: row?.id || null,
            revision: row?.revision || 0,
          }),
        );
        m.dialog.close();
        notice("Draft saved. Review and publish to apply it.");
        refresh();
      } catch (error) {
        notice(error.message);
      }
    };
    return m;
  }
  async function history(row) {
    const server = getServer();
    const m = modal("Revision history · " + row.name);
    m.body.append(
      el(
        "p",
        "Restoring a revision creates a new draft; it does not change live traffic.",
        "muted",
      ),
    );
    try {
      const revisions = await api("/resources/" + row.id + "/history");
      if (!revisions.length)
        m.body.append(
          el(
            "p",
            "No historical snapshot is available for this imported route.",
          ),
        );
      for (const revision of revisions) {
        const item = el("section", undefined, "panel");
        item.append(
          el("h3", "Revision " + revision.revision),
          el("p", new Date(revision.created * 1000).toLocaleString(), "muted"),
        );
        const details = el("details");
        details.append(
          el("summary", "Configuration"),
          el("pre", JSON.stringify(revision.settings, null, 2)),
        );
        item.append(details);
        if (canWrite() && !row.deleted && revision.revision !== row.revision)
          item.append(
            button("Restore as draft", async (b) => {
              await busy(b, "Restoring draft…", () =>
                post("/servers/" + server + "/resources", {
                  id: row.id,
                  revision: row.revision,
                  name: row.name,
                  resource: revision.settings,
                }),
              );
              m.dialog.close();
              notice("Revision restored as a new draft.");
              refresh();
            }),
          );
        m.body.append(item);
      }
    } catch (error) {
      notice(error.message);
    }
  }
  async function publish() {
    const server = getServer(),
      review = await api("/servers/" + server + "/publication-review"),
      m = modal("Review publication");
    m.dialog.classList.add("pm-editor-dialog");
    m.body.append(
      el(
        "p",
        review.pending_count
          ? `${review.pending_count} pending change${review.pending_count === 1 ? "" : "s"} · ${review.total_routes} routes after publication.`
          : "All current routes are published.",
        "muted",
      ),
    );
    if (review.busy) {
      m.body.append(
        el(
          "p",
          "A publication is pending or needs recovery. Open Jobs before submitting another.",
          "notice",
        ),
      );
      return;
    }
    for (const change of review.changes) {
      const card = el("section", undefined, "pm-change");
      card.append(
        el(
          "span",
          { add: "New route", update: "Updated route", remove: "Remove route" }[
            change.change
          ],
          "pm-status " + change.change,
        ),
        el("h3", change.name),
      );
      const before = change.before?.settings || {},
        after = change.after?.settings || {};
      const fields = Object.keys({ ...before, ...after }).filter(
        (key) => JSON.stringify(before[key]) !== JSON.stringify(after[key]),
      );
      card.append(
        el(
          "p",
          change.change === "remove"
            ? "This route will stop receiving traffic after a successful publication."
            : (after.domains || [after.listen || ""]).join(", "),
        ),
      );
      if (fields.length)
        card.append(
          el(
            "p",
            "Changed: " + fields.map((k) => k.replaceAll("_", " ")).join(", "),
            "muted",
          ),
        );
      const details = el("details");
      details.append(
        el("summary", "Configuration details"),
        el(
          "pre",
          JSON.stringify(
            { published: change.before, draft: change.after },
            null,
            2,
          ),
        ),
      );
      card.append(details);
      m.body.append(card);
    }
    if (!review.pending_count) return;
    m.body.append(
      el(
        "p",
        "PM validates the complete candidate configuration before activating it. Follow the result here or in Jobs.",
        "muted",
      ),
    );
    const request_key = crypto.randomUUID(),
      publishButton = button(
        "Publish changes",
        async (b) => {
          const data = await busy(b, "Queueing publication…", () =>
            post("/servers/" + server + "/publish", {
              request_key,
              revisions: review.revisions,
              review_sha256: review.review_sha256,
            }),
          );
          b.disabled = true;
          const status = el("p", "Queued. Waiting for the agent…", "notice");
          status.setAttribute("role", "status");
          m.body.append(status);
          const link = el("a", "Open Jobs");
          link.href = "/jobs?server=" + encodeURIComponent(server);
          m.body.append(link);
          for (let i = 0; i < 90 && m.dialog.isConnected; i++) {
            try {
              const jobs = await api("/servers/" + server + "/jobs"),
                job = jobs.find((j) => j.id === data.job);
              if (job) {
                status.textContent =
                  job.state === "queued"
                    ? "Queued. Waiting for the agent…"
                    : job.state === "running"
                      ? "Validating and applying the configuration…"
                      : job.state;
                if (
                  ["completed", "failed", "uncertain", "cancelled"].includes(
                    job.state,
                  )
                ) {
                  status.textContent =
                    job.state === "completed" &&
                    job.result?.result?.state === "active"
                      ? "Published. The agent validated and activated this configuration."
                      : job.state === "uncertain"
                        ? "The outcome needs inspection. Open Jobs before retrying."
                        : "Publication " +
                          job.state +
                          ". Review its result in Jobs.";
                  refresh();
                  break;
                }
              }
            } catch {
              status.textContent =
                "Could not refresh progress. The operation remains available in Jobs.";
              break;
            }
            await new Promise((resolve) => setTimeout(resolve, 1500));
          }
        },
        true,
      );
    m.body.append(publishButton);
  }
  async function retire(row) {
    const m = modal("Retire " + row.name + "?");
    m.body.append(
      el(
        "p",
        "This creates a removal draft. The live route stays active until you review and publish. You can restore it from Retired routes.",
      ),
    );
    m.body.append(
      button(
        "Retire route",
        async (b) => {
          await busy(b, "Retiring route…", () =>
            api("/resources/" + row.id, {
              method: "DELETE",
              body: JSON.stringify({ revision: row.revision }),
            }),
          );
          m.dialog.close();
          notice(
            "Route retired. Review publication to remove it from live traffic.",
          );
          refresh();
        },
        true,
      ),
    );
  }
  async function restore(row) {
    await post("/resources/" + row.id + "/restore", { revision: row.revision });
    notice("Route restored as an unpublished draft.");
    refresh();
  }
  function list(rows) {
    const box = el("section", undefined, "pm-route-list"),
      filters = el("div", undefined, "filter-row"),
      search = el("input"),
      state = el("select"),
      host = el("div");
    search.type = "search";
    search.placeholder = "Search domains, upstreams or route names";
    search.setAttribute("aria-label", "Filter reverse proxies");
    state.setAttribute("aria-label", "Publication status");
    for (const [value, text] of [
      ["all", "All routes"],
      ["published", "Published"],
      ["draft", "Unpublished changes"],
      ["retired", "Retired routes"],
    ]) {
      const o = el("option", text);
      o.value = value;
      state.append(o);
    }
    filters.append(search, state);
    box.append(filters, host);
    const server = getServer();
    let retired = [];
    const render = () => {
      const q = search.value.toLowerCase(),
        selected = (state.value === "retired" ? retired : rows).filter(
          (r) =>
            JSON.stringify([
              r.name,
              r.settings.settings.domains,
              r.settings.settings.upstreams,
            ])
              .toLowerCase()
              .includes(q) &&
            (state.value === "retired" ||
              state.value === "all" ||
              (state.value === "published") === (r.revision === r.published)),
        );
      if (!selected.length) {
        host.replaceChildren(
          el("p", "No routes match these filters.", "empty"),
        );
        return;
      }
      host.replaceChildren(
        table(
          ["Route", "Upstreams", "Status", "Actions"],
          selected.map((r) => {
            const data = r.settings.settings,
              label = el("div", undefined, "pm-route-name");
            label.append(
              el("strong", (data.domains || []).join(", ")),
              el("small", r.name),
            );
            const upstream = el("div", undefined, "pm-route-upstreams");
            for (const u of data.upstreams)
              upstream.append(
                el(
                  "span",
                  u.address +
                    (u.backup ? " · backup" : "") +
                    (u.weight !== 1 ? " · weight " + u.weight : ""),
                ),
              );
            const status = el("div", undefined, "stack");
            status.append(
              el(
                "span",
                r.deleted ? "Retired" : routeStatus(r),
                "pm-status " +
                  (r.revision === r.published ? "published" : "draft"),
              ),
              el(
                "small",
                (data.certificate ? "TLS · " + data.certificate : "HTTP") +
                  " · " +
                  (data.path || "/"),
              ),
            );
            const actions = el("div", undefined, "actions");
            if (canWrite()) {
              if (r.deleted)
                actions.append(button("Restore", () => restore(r)));
              else
                actions.append(
                  button("Edit", () => edit(r)),
                  button("Retire", () => retire(r)),
                );
            }
            actions.append(button("History", () => history(r)));
            return [label, upstream, status, actions];
          }),
        ),
      );
    };
    search.addEventListener("input", render);
    state.addEventListener("change", async () => {
      if (state.value === "retired")
        try {
          retired = (
            await api("/servers/" + server + "/retired-resources")
          ).filter((r) => r.kind === "proxy_host");
        } catch (error) {
          notice(error.message);
        }
      render();
    });
    render();
    return box;
  }
  return { edit, history, publish, list };
}
