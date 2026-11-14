/* KagNode Proxy Manager host workflows. Core owns shared components and motion. */
(() => {
  "use strict";
  const session = JSON.parse(
    document.querySelector("#session-data")?.textContent || "null",
  );
  if (!session) return;
  document.body.dataset.coreNotices = "enabled";
  const root = document.querySelector("#page-content"),
    page = root?.dataset.page,
    feedback = document.querySelector("#feedback"),
    actions = document.querySelector("#page-actions");
  let servers = [],
    resources = [],
    selected = new URL(location.href).searchParams.get("server") || "",
    timer,
    epoch = 0;
  const admin = ["owner", "administrator"].includes(session.role);
  const canWrite = () =>
    !!servers.find((s) => s.id === selected)?.permissions?.write;
  const canMaintain = () =>
    !!servers.find((s) => s.id === selected)?.permissions?.maintenance;
  const el = (tag, text, cls) => {
    const n = document.createElement(tag);
    if (text !== undefined) n.textContent = text;
    if (cls) n.className = cls;
    return n;
  };
  function notice(message) {
    feedback.replaceChildren(el("p", message, "notice"));
  }
  async function api(path, options = {}) {
    const r = await fetch("/api/v1" + path, {
      credentials: "same-origin",
      redirect: "error",
      ...options,
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": session.csrf,
        ...options.headers,
      },
      signal: AbortSignal.timeout(20000),
    });
    const data = await r.json();
    if (!r.ok)
      throw Error(data.error || "This operation could not be completed.");
    return data;
  }
  const post = (path, data) =>
    api(path, { method: "POST", body: JSON.stringify(data) });
  const button = (text, action, primary = false) => {
    const b = el("button", text, primary ? "button primary" : "button");
    b.type = "button";
    b.addEventListener("click", () =>
      Promise.resolve(action(b)).catch((e) => notice(e.message)),
    );
    return b;
  };
  function empty(title, description) {
    const box = el("div", undefined, "empty");
    box.append(el("h2", title), el("p", description));
    return box;
  }
  function table(headers, rows) {
    const wrap = el("div", undefined, "table-wrap"),
      t = el("table"),
      head = el("thead"),
      tr = el("tr");
    for (const h of headers) tr.append(el("th", h));
    head.append(tr);
    const body = el("tbody");
    for (const row of rows) {
      const r = el("tr");
      for (const value of row) {
        const td = el("td");
        td.append(
          value instanceof Node
            ? value
            : document.createTextNode(String(value)),
        );
        r.append(td);
      }
      body.append(r);
    }
    t.append(head, body);
    wrap.append(t);
    return wrap;
  }
  function modal(title) {
    const d = el("dialog"),
      header = el("header"),
      body = el("div");
    const heading = el("h2", title);
    heading.id = "dialog-" + crypto.randomUUID();
    d.setAttribute("aria-labelledby", heading.id);
    header.append(
      heading,
      button("Close", () => d.close()),
    );
    d.append(header, body);
    document.body.append(d);
    d.addEventListener("close", () => d.remove(), { once: true });
    window.KagNodeDialogs?.open
      ? window.KagNodeDialogs.open(d, { sheet: innerWidth < 700 })
      : d.showModal();
    return { dialog: d, body };
  }
  function field(form, label, name, value = "", type = "text", wide = false) {
    const l = el("label", label, wide ? "wide" : undefined),
      input = el(type === "textarea" ? "textarea" : "input");
    input.name = name;
    input.value = value;
    if (type !== "textarea") input.type = type;
    l.append(input);
    form.append(l);
    return input;
  }
  async function busy(b, label, task) {
    b.disabled = true;
    const finish = window.KagNodeLoading?.begin({
      label,
      mode: "inline",
      target: b.parentElement,
    });
    try {
      return await task();
    } finally {
      finish?.();
      b.disabled = false;
    }
  }
  function serverPicker() {
    const row = el("div", undefined, "filter-row"),
      label = el("label", "Server"),
      select = el("select");
    select.setAttribute("aria-label", "Server");
    for (const s of servers) {
      const o = el("option", s.name);
      o.value = s.id;
      select.append(o);
    }
    select.value = selected;
    select.onchange = () => {
      selected = select.value;
      const u = new URL(location.href);
      u.searchParams.set("server", selected);
      history.replaceState(null, "", u);
      refresh();
    };
    label.append(select);
    row.append(label);
    return row;
  }
  async function refresh() {
    clearTimeout(timer);
    const identity = ++epoch;
    if (!root) return;
    try {
      servers = await api("/servers");
      if (identity !== epoch) return;
      if (!servers.some((s) => s.id === selected))
        selected = servers[0]?.id || "";
      actions.replaceChildren();
      root.replaceChildren();
      document.querySelectorAll(".nav-item").forEach((a) => {
        if (new URL(a.href).pathname === location.pathname)
          a.setAttribute("aria-current", "page");
      });
      if (page === "overview") await overview();
      else if (page === "servers") fleet();
      else if (["reverse-proxies", "streams", "forward-proxies"].includes(page))
        await resourcePage();
      else if (page === "packages") packages();
      else if (page === "jobs") await jobs();
      else if (page === "audit") await audit();
      else if (page === "account") await account();
      else if (page === "users") await users();
      else if (page === "certificates") await certificates();
      window.KagNodeScroll?.refresh();
      window.KagNodeSegments?.refresh();
    } catch (e) {
      if (identity === epoch) {
        notice(e.message);
        root.replaceChildren(
          empty(
            "Could not load this page",
            "Your current server configuration is unchanged.",
          ),
        );
        root.append(button("Try again", refresh));
      }
    } finally {
      if (["overview", "servers", "jobs"].includes(page) && !document.hidden)
        timer = setTimeout(refresh, 15000);
    }
  }
  async function overview() {
    if (!servers.length) {
      root.append(
        empty(
          "Connect your first server",
          "Enroll a server to manage routes, certificates and package operations from this dashboard.",
        ),
      );
      if (admin) root.append(button("Add server", addServer, true));
      return;
    }
    const cards = el("div", undefined, "cards");
    const online = servers.filter(
      (s) => Date.now() / 1000 - s.seen < 45,
    ).length;
    for (const [label, value] of [
      ["Servers", servers.length],
      ["Connected", online],
      ["Awaiting connection", servers.length - online],
    ]) {
      const c = el("article", undefined, "card");
      c.append(el("small", label), el("strong", value, "metric"));
      cards.append(c);
    }
    root.append(cards, el("h2", "Fleet activity"));
    fleet(false);
  }
  function fleet(showAction = true) {
    if (admin && showAction)
      actions.append(button("Add server", addServer, true));
    if (!servers.length) {
      root.append(
        empty(
          "No servers enrolled",
          "Enrollment uses a short-lived token and a separate agent identity.",
        ),
      );
      return;
    }
    root.append(
      table(
        ["Server", "Connection", "Agent memory", "Last contact", "Actions"],
        servers.map((s) => {
          const a = el("div", undefined, "actions");
          const link = el("a", "Manage routes", "button");
          link.href = "/reverse-proxies?server=" + s.id;
          a.append(link);
          if (admin)
            a.append(
              button("Revoke", () =>
                confirmAction(
                  "Revoke " + s.name + "?",
                  "This stops remote management. Existing proxy traffic keeps its last working configuration.",
                  async () => {
                    await post("/servers/" + s.id + "/revoke", {});
                    refresh();
                  },
                ),
              ),
            );
          return [
            s.name,
            Date.now() / 1000 - s.seen < 45 ? "Connected" : "Offline",
            s.summary.agent_rss_kib
              ? Math.round(s.summary.agent_rss_kib / 1024) + " MiB"
              : "—",
            s.seen ? new Date(s.seen * 1000).toLocaleString() : "Never",
            a,
          ];
        }),
      ),
    );
  }
  function addServer() {
    const m = modal("Connect a server"),
      f = el("form");
    field(f, "Server name", "name");
    const submit = el("button", "Create enrollment token", "button primary");
    f.append(submit);
    f.onsubmit = async (e) => {
      e.preventDefault();
      await busy(submit, "Creating enrollment…", async () => {
        try {
          const data = await post("/enrollments", {
            name: f.elements.name.value,
          });
          m.body.replaceChildren(
            el(
              "p",
              "Save the token in a private file or paste it into the agent’s standard input. It expires in ten minutes and works once.",
            ),
          );
          const token = el("input");
          token.value = data.token;
          token.type = "password";
          token.readOnly = true;
          token.setAttribute("aria-label", "One-time enrollment token");
          m.body.append(
            token,
            button("Reveal token", () => {
              token.type = token.type === "password" ? "text" : "password";
            }),
            button("Copy token", () =>
              navigator.clipboard.writeText(data.token),
            ),
            el(
              "pre",
              "kagnode-proxy-manager enroll --controller " +
                data.controller +
                " --ca /path/to/verified-controller-ca.pem < /path/to/private-token",
            ),
            el(
              "p",
              "Verify the controller CA fingerprint before trusting it: " +
                data.ca_fingerprint,
            ),
          );
        } catch (e) {
          notice(e.message);
        }
      });
    };
    m.body.append(f);
  }
  async function resourcePage() {
    const kind = {
      "reverse-proxies": "proxy_host",
      streams: "stream",
      "forward-proxies": "forward_proxy",
    }[page];
    if (!selected) {
      root.append(
        empty(
          "Connect a server first",
          "Routes are validated and activated by the agent on the selected server.",
        ),
      );
      return;
    }
    root.append(serverPicker());
    resources = await api("/servers/" + selected + "/resources");
    if (canWrite()) {
      actions.append(
        button(
          "Add " +
            (kind === "proxy_host"
              ? "proxy"
              : kind === "stream"
                ? "stream"
                : "forward proxy"),
          () => editResource(kind),
          true,
        ),
        button("Review and publish", publish),
      );
    }
    const rows = resources.filter((r) => r.kind === kind);
    if (!rows.length) {
      root.append(
        empty(
          "No " + page.replaceAll("-", " ") + " yet",
          "Create a draft, review the configuration and publish it to this server.",
        ),
      );
      return;
    }
    root.append(
      table(
        ["Name", "Routing", "Revision", "Actions"],
        rows.map((r) => {
          const a = el("div", undefined, "actions");
          if (canWrite())
            a.append(
              button("Edit", () => editResource(kind, r)),
              button("Retire", () =>
                confirmAction(
                  "Retire " + r.name + "?",
                  "The route remains active until you publish this server.",
                  async () => {
                    await api("/resources/" + r.id, {
                      method: "DELETE",
                      body: JSON.stringify({ revision: r.revision }),
                    });
                    refresh();
                  },
                ),
              ),
            );
          return [
            r.name,
            r.kind === "proxy_host"
              ? r.settings.settings.domains.join(", ")
              : r.settings.settings.listen,
            "Draft " + r.revision,
            a,
          ];
        }),
      ),
    );
  }
  function editResource(kind, row) {
    const m = modal(
        row ? "Edit " + row.name : "New " + kind.replaceAll("_", " "),
      ),
      f = el("form", undefined, "form-grid"),
      v = row?.settings.settings || {};
    field(f, "Name", "name", row?.name || "");
    if (kind === "proxy_host") {
      field(
        f,
        "Domains, one per line",
        "domains",
        (v.domains || []).join("\n"),
        "textarea",
        true,
      );
      field(
        f,
        "Upstream origins, one per line",
        "upstreams",
        (v.upstreams || []).map((u) => u.address).join("\n"),
        "textarea",
        true,
      );
      field(f, "Route path", "path", v.path || "/");
      field(f, "Certificate ID (optional)", "certificate", v.certificate || "");
      field(
        f,
        "Timeout, seconds",
        "timeout",
        v.timeout_seconds || 60,
        "number",
      );
      field(f, "Upload limit, MiB", "upload", v.max_body_mib ?? 16, "number");
      const label = el("label", "Balance"),
        select = el("select");
      select.name = "balance";
      for (const n of ["round_robin", "least_connections", "ip_hash"]) {
        const o = el("option", n.replaceAll("_", " "));
        o.value = n;
        select.append(o);
      }
      select.value = v.balance || "round_robin";
      label.append(select);
      f.append(label);
      const ws = field(f, "Enable WebSockets", "websocket", "", "checkbox");
      ws.checked = v.websocket !== false;
    } else if (kind === "stream") {
      field(
        f,
        "Listen address and port",
        "listen",
        v.listen || "192.168.0.6:8445",
      );
      field(
        f,
        "Upstream address and port",
        "upstream",
        v.upstream || "127.0.0.1:8080",
      );
      const udp = field(f, "UDP", "udp", "", "checkbox");
      udp.checked = !!v.udp;
      field(
        f,
        "Allowed client CIDRs, one per line",
        "clients",
        (v.allowed_clients || []).join("\n"),
        "textarea",
        true,
      );
    } else {
      field(f, "Listen address and port", "listen", v.listen || "0.0.0.0:8445");
      field(f, "Credential group", "group", v.user_group || "clients");
      field(f, "TLS certificate ID", "certificate", v.certificate || "");
      field(
        f,
        "Allowed client CIDRs, one per line",
        "clients",
        (v.clients || []).join("\n"),
        "textarea",
        true,
      );
      field(
        f,
        "Destination ports, comma separated",
        "ports",
        (v.ports || [80, 443]).join(","),
      );
      field(f, "Connection limit", "limit", v.max_connections || 64, "number");
      const label = el("label", "Protocol"),
        select = el("select");
      select.name = "protocol";
      for (const [key, text] of [
        ["https", "HTTPS forward proxy"],
        ["socks5_tls", "SOCKS5 over TLS"],
        ["socks5_lan", "SOCKS5 on LAN/VPN"],
      ]) {
        const o = el("option", text);
        o.value = key;
        select.append(o);
      }
      select.value = v.protocol || "https";
      label.append(select);
      f.append(label);
    }
    const submit = el("button", "Save draft", "button primary");
    f.append(submit);
    f.onsubmit = async (e) => {
      e.preventDefault();
      const get = (n) => f.elements[n].value.trim(),
        lines = (n) =>
          get(n)
            .split("\n")
            .map((s) => s.trim())
            .filter(Boolean);
      let settings;
      if (kind === "proxy_host")
        settings = {
          ...v,
          domains: lines("domains"),
          upstreams: lines("upstreams").map((address) => ({
            address,
            weight: 1,
            backup: false,
          })),
          path: get("path"),
          certificate: get("certificate") || null,
          timeout_seconds: Number(get("timeout")),
          max_body_mib: Number(get("upload")),
          balance: get("balance"),
          websocket: f.elements.websocket.checked,
        };
      else if (kind === "stream")
        settings = {
          listen: get("listen"),
          upstream: get("upstream"),
          udp: f.elements.udp.checked,
          allowed_clients: lines("clients"),
        };
      else
        settings = {
          ...v,
          listen: get("listen"),
          protocol: get("protocol"),
          user_group: get("group"),
          certificate: get("certificate") || null,
          clients: lines("clients"),
          ports: get("ports").split(",").map(Number),
          max_connections: Number(get("limit")),
          public: get("protocol") !== "socks5_lan",
          destinations: v.destinations || [],
        };
      await busy(submit, "Saving draft…", async () => {
        try {
          await post("/servers/" + selected + "/resources", {
            name: get("name"),
            resource: { kind, settings },
            id: row?.id || null,
            revision: row?.revision || 0,
          });
          m.dialog.close();
          notice(
            "Draft saved. Publish the server when you are ready to apply it.",
          );
          refresh();
        } catch (e) {
          m.body.prepend(el("p", e.message, "notice"));
        }
      });
    };
    m.body.append(f);
  }
  async function publish() {
    const current = await api("/servers/" + selected + "/resources");
    confirmAction(
      "Publish this server?",
      "The agent will validate the complete configuration before activating it. A failed validation keeps existing traffic unchanged.",
      async () => {
        const data = await post("/servers/" + selected + "/publish", {
          request_key: crypto.randomUUID(),
          revisions: Object.fromEntries(current.map((r) => [r.id, r.revision])),
        });
        notice(
          "Configuration queued. Follow operation " +
            data.job.slice(0, 12) +
            " in Jobs.",
        );
      },
      JSON.stringify(current, null, 2),
    );
  }
  function confirmAction(title, description, apply, preview) {
    const m = modal(title);
    m.body.append(el("p", description));
    if (preview) m.body.append(el("pre", preview));
    m.body.append(
      button(
        "Confirm",
        async (b) => {
          await busy(b, "Applying change…", apply);
          m.dialog.close();
        },
        true,
      ),
    );
  }
  function packages() {
    if (!canMaintain()) {
      root.append(
        empty(
          "Host-maintenance access required",
          "Your account needs a host-maintenance grant for this server.",
        ),
      );
      return;
    }
    if (!selected) {
      root.append(
        empty(
          "Connect a server first",
          "Package operations run on the selected server through its restricted helper.",
        ),
      );
      return;
    }
    root.append(serverPicker());
    const panel = el("section", undefined, "panel"),
      f = el("form");
    panel.append(
      el("h2", "Review package removal"),
      el(
        "p",
        "The complete dependency transaction is checked. Required, held and unverified packages are blocked; configuration files are retained.",
      ),
    );
    field(f, "Exact package names, one per line", "names", "", "textarea");
    const submit = el("button", "Preview dependency impact", "button primary");
    f.append(submit);
    f.onsubmit = async (e) => {
      e.preventDefault();
      await busy(submit, "Queueing package analysis…", async () => {
        try {
          const data = await post("/servers/" + selected + "/packages/plans", {
            names: f.elements.names.value
              .split("\n")
              .map((s) => s.trim())
              .filter(Boolean),
            request_key: crypto.randomUUID(),
          });
          notice(
            "Package analysis queued. Open Jobs to inspect the full result and removal controls.",
          );
          location.assign("/jobs?server=" + selected);
        } catch (e) {
          notice(e.message);
        }
      });
    };
    panel.append(f);
    root.append(panel);
  }
  async function jobs() {
    if (!selected) {
      root.append(
        empty(
          "No server operations yet",
          "Connect a server to view its durable operation history.",
        ),
      );
      return;
    }
    root.append(serverPicker());
    const data = await api("/servers/" + selected + "/jobs");
    actions.append(
      button("Inspect server", async () => {
        await post("/servers/" + selected + "/inspect", {
          request_key: crypto.randomUUID(),
        });
        notice("Read-only inspection queued. Its result will appear here.");
        refresh();
      }),
    );
    const inspection = data.find(
      (j) =>
        j.kind === "status" &&
        j.state === "completed" &&
        Date.now() / 1000 - j.updated < 60,
    );
    if (!data.length) {
      root.append(
        empty(
          "No operations yet",
          "Published configurations and maintenance operations appear here.",
        ),
      );
      return;
    }
    root.append(
      table(
        ["Operation", "Status", "Updated", "Actions"],
        data.map((j) => {
          const a = el("div", undefined, "actions");
          a.append(
            button("Details", () => {
              const m = modal(j.kind.replaceAll("_", " "));
              m.body.append(el("pre", JSON.stringify(j.result, null, 2)));
              const plan = j.result?.result;
              if (
                canMaintain() &&
                j.kind === "package_preview" &&
                j.state === "completed" &&
                plan?.confirmation &&
                Object.keys(plan.blockers || {}).length === 0
              )
                m.body.append(
                  button(
                    "Review removal",
                    () =>
                      confirmAction(
                        "Remove the reviewed packages?",
                        "This retains package configuration files. Package removal is not reversible through proxy configuration rollback.",
                        async () => {
                          await post(
                            "/servers/" + selected + "/packages/apply",
                            {
                              preview_job: j.id,
                              confirmation: plan.confirmation,
                              request_key: crypto.randomUUID(),
                            },
                          );
                          m.dialog.close();
                          refresh();
                        },
                        JSON.stringify(plan, null, 2),
                      ),
                    true,
                  ),
                );
            }),
          );
          if (j.state === "queued" && canWrite())
            a.append(
              button("Cancel", async () => {
                await post("/jobs/" + j.id + "/cancel", {});
                refresh();
              }),
            );
          if (j.state === "uncertain" && admin && canMaintain() && inspection)
            a.append(
              button("Review recovery hold", () => {
                const m = modal("Record the inspected outcome");
                m.body.append(
                  el(
                    "p",
                    "Review the node inspection and actual traffic first. This records the old operation as failed and releases its queue hold; it does not replay it or clear native recovery journals.",
                  ),
                  el("pre", JSON.stringify(inspection.result, null, 2)),
                );
                const form = el("form", undefined, "form-grid");
                field(
                  form,
                  "Type the complete operation ID: " + j.id,
                  "confirmation",
                  "",
                  "text",
                  true,
                );
                field(
                  form,
                  "Explain what you inspected (at least 20 characters)",
                  "reason",
                  "",
                  "textarea",
                  true,
                );
                const submit = el(
                  "button",
                  "Record inspection",
                  "button primary",
                );
                form.append(submit);
                form.onsubmit = async (e) => {
                  e.preventDefault();
                  await busy(submit, "Recording inspection…", async () => {
                    try {
                      await post("/jobs/" + j.id + "/resolve", {
                        inspection: inspection.id,
                        confirmation: form.elements.confirmation.value.trim(),
                        reason: form.elements.reason.value.trim(),
                      });
                      m.dialog.close();
                      refresh();
                    } catch (e) {
                      m.body.prepend(el("p", e.message, "notice"));
                    }
                  });
                };
                m.body.append(form);
              }),
            );
          return [
            j.kind.replaceAll("_", " "),
            el("span", j.state, "status " + j.state),
            new Date(j.updated * 1000).toLocaleString(),
            a,
          ];
        }),
      ),
    );
  }
  async function audit() {
    if (!admin) {
      root.append(
        empty(
          "Administrator access required",
          "Audit records are restricted to local administrators.",
        ),
      );
      return;
    }
    const rows = await api("/audit");
    root.append(
      rows.length
        ? table(
            ["Action", "Actor", "Target", "Time"],
            rows.map((r) => [
              r.action,
              r.actor.slice(0, 12),
              r.target.slice(0, 12),
              new Date(r.created * 1000).toLocaleString(),
            ]),
          )
        : empty(
            "No recorded changes",
            "Administrative changes will appear here.",
          ),
    );
  }
  async function account() {
    const data = await api("/account"),
      p = el("section", undefined, "panel");
    p.append(
      el("h2", session.name),
      el("p", "Role: " + session.role),
      el(
        "p",
        "Your local account and permissions remain independent of KagNode Account.",
      ),
    );
    const preference = el("div");
    preference.dataset.corePreferencesHost = "";
    p.append(preference);
    if (data.kagnode_linked)
      p.append(
        el(
          "p",
          "KagNode Account linked. Your name and photo synchronize when you sign in with KagNode.",
        ),
      );
    else {
      const link = el("form");
      link.method = "post";
      link.action = "/auth/kagnode/link";
      const csrf = el("input");
      csrf.type = "hidden";
      csrf.name = "_csrf";
      csrf.value = session.csrf;
      link.append(csrf, el("button", "Link KagNode Account", "button"));
      p.append(link);
    }
    p.append(
      button(
        data.mfa_enabled
          ? "Replace authenticator"
          : "Enable two-factor authentication",
        enrollMfa,
      ),
    );
    root.append(p);
    if (admin && data.policy) {
      const panel = el("section", undefined, "panel"),
        f = el("form");
      panel.append(el("h2", "Local account policy"));
      for (const [key, label] of [
        ["kagnode_login", "Allow KagNode Account sign-in"],
        [
          "signup",
          "Allow verified KagNode users to create a local Viewer account",
        ],
      ]) {
        const input = field(f, label, key, "", "checkbox");
        input.checked = data.policy[key];
      }
      const save = el("button", "Save account policy", "button primary");
      f.append(save);
      f.onsubmit = async (e) => {
        e.preventDefault();
        try {
          await post("/account/policy", {
            kagnode_login: f.elements.kagnode_login.checked,
            signup: f.elements.signup.checked,
          });
          notice("Local account policy saved.");
        } catch (error) {
          notice(error.message);
        }
      };
      panel.append(f);
      root.append(panel);
      const core = el("section", undefined, "panel");
      core.dataset.coreAdminHost = "";
      root.append(core);
    }
    window.KagNodeAppearance?.render();
    window.KagNodeCoreUpdates?.refresh?.();
  }
  async function enrollMfa() {
    const data = await post("/account/mfa/start", {}),
      m = modal("Set up an authenticator");
    m.body.append(
      el(
        "p",
        "Add this setup key to KagNode Passwords or another authenticator. Enter its verification code, then save the recovery codes.",
      ),
    );
    m.body.append(el("pre", data.secret));
    const f = el("form");
    field(f, "Six-digit verification code", "code", "", "text");
    const save = el("button", "Verify and enable", "button primary");
    f.append(save);
    f.onsubmit = async (e) => {
      e.preventDefault();
      try {
        const result = await post("/account/mfa/confirm", {
          code: f.elements.code.value.trim(),
        });
        m.body.replaceChildren(
          el("h2", "Save your recovery codes"),
          el(
            "p",
            "These codes appear once. Your previous sessions are now revoked; sign in again after saving them.",
          ),
          el("pre", result.recovery_codes.join("\n")),
        );
        const back = el("a", "I saved them — sign in again", "button primary");
        back.href = "/login";
        m.body.append(back);
      } catch (error) {
        m.body.prepend(el("p", error.message, "notice"));
      }
    };
    m.body.append(f);
  }
  async function users() {
    if (!admin) {
      root.append(
        empty(
          "Administration permission required",
          "Only local administrators manage accounts and server access.",
        ),
      );
      return;
    }
    actions.append(button("Create local account", createLocalUser, true));
    const data = await api("/users");
    root.append(
      table(
        ["Account", "Role", "Security", "Actions"],
        data.map((u) => {
          const identity = el("div");
          identity.append(el("strong", u.name), el("small", u.email));
          const controls = el("div", undefined, "actions");
          if (u.role !== "owner" && u.id !== session.id) {
            controls.append(
              button(u.disabled ? "Enable" : "Disable", () =>
                confirmAction(
                  u.disabled ? "Enable account?" : "Disable account?",
                  "Existing sessions and pending operations are revoked when account permissions change.",
                  async () => {
                    await post("/users/" + u.id, {
                      role: u.role,
                      disabled: !u.disabled,
                    });
                    await refresh();
                  },
                ),
              ),
            );
            controls.append(button("Server access", () => editAccess(u)));
          }
          return [
            identity,
            u.role + (u.disabled ? " · Disabled" : ""),
            (u.mfa_enabled ? "MFA enabled" : "MFA not enabled") +
              (u.kagnode_linked ? " · KagNode linked" : ""),
            controls,
          ];
        }),
      ),
    );
  }
  function createLocalUser() {
    const m = modal("Create local account"),
      f = el("form", undefined, "form-grid");
    field(f, "Name", "name").required = true;
    field(f, "Email", "email", "", "email").required = true;
    const password = field(f, "Initial password", "password", "", "password");
    password.minLength = 14;
    password.maxLength = 256;
    password.required = true;
    password.autocomplete = "new-password";
    const label = el("label", "Role"),
      role = el("select");
    role.name = "role";
    for (const name of session.role === "owner"
      ? ["viewer", "maintainer", "administrator"]
      : ["viewer", "maintainer"]) {
      const option = el("option", name);
      option.value = name;
      role.append(option);
    }
    label.append(role);
    f.append(label);
    f.append(
      el(
        "p",
        "Viewer and maintainer accounts need a separate server-access grant. Share the initial password through your own secure channel.",
        "wide",
      ),
    );
    const submit = el("button", "Create account", "button primary");
    f.append(submit);
    f.onsubmit = async (e) => {
      e.preventDefault();
      await busy(submit, "Creating account…", async () => {
        try {
          await post("/users", {
            name: f.elements.name.value,
            email: f.elements.email.value,
            password: password.value,
            role: role.value,
          });
          password.value = "";
          m.dialog.close();
          await refresh();
          notice(
            "Account created. Assign its server access before the user signs in.",
          );
        } catch (e) {
          notice(e.message);
        }
      });
    };
    m.body.append(f);
  }
  function editAccess(u) {
    const m = modal("Server access · " + u.name),
      f = el("form");
    if (!servers.length) {
      m.body.append(el("p", "Enroll a server first."));
      return;
    }
    const label = el("label", "Server"),
      node = el("select");
    for (const s of servers) {
      const o = el("option", s.name);
      o.value = s.id;
      node.append(o);
    }
    label.append(node);
    f.append(label);
    const rlabel = el("label", "Permission"),
      role = el("select");
    for (const name of ["viewer", "maintainer"]) {
      const o = el("option", name);
      o.value = name;
      role.append(o);
    }
    rlabel.append(role);
    f.append(rlabel);
    const maintenance = field(
      f,
      "Allow host-maintenance operations",
      "maintenance",
      "",
      "checkbox",
    );
    role.onchange = () => {
      maintenance.disabled = role.value !== "maintainer";
      if (maintenance.disabled) maintenance.checked = false;
    };
    role.onchange();
    const submit = el("button", "Save server access", "button primary");
    f.append(submit);
    f.onsubmit = async (e) => {
      e.preventDefault();
      await busy(submit, "Updating server access…", async () => {
        await post("/users/" + u.id + "/servers/" + node.value, {
          role: role.value,
          maintenance: maintenance.checked,
        });
        m.dialog.close();
        notice(
          "Server access saved. Previous queued operations were cancelled for review.",
        );
      });
    };
    m.body.append(
      f,
      button("Revoke server access", () =>
        confirmAction(
          "Revoke this server grant?",
          "Pending operations from this account on the selected server will be cancelled.",
          async () => {
            await post(
              "/users/" + u.id + "/servers/" + node.value + "/revoke",
              {},
            );
            m.dialog.close();
            notice("Server grant revoked.");
          },
        ),
      ),
    );
  }
  async function certificates() {
    if (!selected) {
      root.append(
        empty(
          "Connect a server first",
          "Certificate keys stay on the relevant agent.",
        ),
      );
      return;
    }
    root.append(serverPicker());
    actions.append(
      button("Refresh inventory", async () => {
        await post("/servers/" + selected + "/certificates/inspect", {
          request_key: crypto.randomUUID(),
        });
        notice(
          "Certificate inventory queued. Refresh this page after the agent responds.",
        );
      }),
    );
    if (canWrite())
      actions.append(button("Request certificate", requestCertificate, true));
    const history = await api("/servers/" + selected + "/jobs");
    const latest = history.find(
      (j) => j.kind === "certificate_inventory" && j.state === "completed",
    );
    const rows = latest?.result?.result;
    if (!Array.isArray(rows) || !rows.length) {
      root.append(
        empty(
          "No certificate inventory yet",
          "Refresh the inventory to inspect installed certificates, or request a staged certificate.",
        ),
      );
      return;
    }
    root.append(
      table(
        ["Certificate ID", "Details"],
        rows.map((c) => [c.id, c.certificate || c.error]),
      ),
    );
  }
  function requestCertificate() {
    const m = modal("Request a certificate"),
      f = el("form", undefined, "form-grid");
    field(f, "Certificate ID", "id");
    field(f, "Contact email", "email", session.email || "", "email");
    field(f, "Domains, one per line", "domains", "", "textarea", true);
    const l = el("label", "Validation provider"),
      select = el("select");
    select.name = "provider";
    for (const [key, label] of [
      ["http", "HTTP challenge"],
      ["cloudflare", "Cloudflare DNS"],
      ["rfc2136", "RFC 2136 DNS"],
    ]) {
      const o = el("option", label);
      o.value = key;
      select.append(o);
    }
    l.append(select);
    f.append(l);
    field(f, "Local DNS credential ID (DNS validation only)", "credential");
    const staged = field(
      f,
      "Use the certificate authority staging environment",
      "staging",
      "",
      "checkbox",
    );
    staged.checked = true;
    const submit = el("button", "Review certificate request", "button primary");
    f.append(submit);
    f.onsubmit = (e) => {
      e.preventDefault();
      const provider = { type: f.elements.provider.value };
      if (provider.type !== "http")
        provider.credential = f.elements.credential.value.trim();
      const request = {
        id: f.elements.id.value.trim(),
        email: f.elements.email.value.trim(),
        domains: f.elements.domains.value
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
        provider,
        staging: f.elements.staging.checked,
      };
      confirmAction(
        "Queue certificate request?",
        request.staging
          ? "Staging validates issuance but never replaces a production certificate."
          : "This contacts the production certificate authority and is subject to its issuance limits.",
        async () => {
          await post("/servers/" + selected + "/certificates/issue", {
            request,
            request_key: crypto.randomUUID(),
          });
          m.dialog.close();
          notice(
            "Certificate request queued. Check Jobs for its confirmed outcome.",
          );
        },
        JSON.stringify(request, null, 2),
      );
    };
    m.body.append(f);
  }
  document.addEventListener("visibilitychange", () => {
    clearTimeout(timer);
    if (!document.hidden && ["overview", "servers", "jobs"].includes(page))
      refresh();
  });
  refresh();
})();
