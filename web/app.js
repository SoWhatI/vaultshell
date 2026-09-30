/* vaultshell web UI — vanilla JS, zero external dependencies, offline-capable.
 * Token flow: ?token= in URL on first load → sessionStorage → Bearer header;
 * the token is stripped from the URL bar immediately. */
"use strict";

(function () {
  // ---- token bootstrap ----------------------------------------------------
  const params = new URLSearchParams(location.search);
  const urlToken = params.get("token");
  if (urlToken) {
    sessionStorage.setItem("vaultshell_token", urlToken);
    params.delete("token");
    history.replaceState(null, "", location.pathname + (params.toString() ? "?" + params : ""));
  }
  const token = sessionStorage.getItem("vaultshell_token") || "";

  async function api(method, path, body) {
    const res = await fetch(path, {
      method,
      headers: Object.assign(
        { Authorization: "Bearer " + token },
        body !== undefined ? { "Content-Type": "application/json" } : {},
      ),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = data && data.error ? data.error.message : res.statusText;
      throw new Error(res.status + " " + err);
    }
    return data;
  }

  // ---- dom helpers ---------------------------------------------------------
  const main = document.getElementById("main");
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined) continue;
      if (k === "class") node.className = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else if (k === "value") node.value = v;
      else if (k === "checked") node.checked = !!v;
      else node.setAttribute(k, v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined) continue;
      node.append(c.nodeType ? c : document.createTextNode(String(c)));
    }
    return node;
  }
  function msg(text, isErr) {
    return el("div", { class: "msg " + (isErr ? "err" : "ok") }, text);
  }
  let notice = null;
  function showNotice(text, isErr) {
    if (notice) notice.remove();
    notice = msg(text, isErr);
    main.prepend(notice);
  }

  // ---- tabs ---------------------------------------------------------------
  const tabs = { secrets: renderSecrets, rules: renderRules, config: renderConfig, audit: renderAudit };
  document.querySelectorAll("nav button").forEach((b) => {
    b.addEventListener("click", () => {
      document.querySelectorAll("nav button").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
      tabs[b.dataset.tab]();
    });
  });

  const csv = (s) => s.split(",").map((x) => x.trim()).filter(Boolean);
  const joinCsv = (a) => (a || []).join(", ");

  // ---- Secrets -------------------------------------------------------------
  async function renderSecrets() {
    main.replaceChildren(el("p", null, "Loading…"));
    try {
      const data = await api("GET", "/api/secrets");
      const rows = data.secrets.map((s) =>
        el("tr", null,
          el("td", { class: "mono" }, s.name),
          el("td", { class: "mono" }, s.ref),
          el("td", null, el("span", { class: "chip " + (s.resolvable ? "ok" : "bad") }, s.resolvable ? "resolvable" : "unresolvable")),
          el("td", { class: "narrow" },
            el("button", { onclick: async () => {
              try {
                const p = await api("POST", "/api/secrets/" + encodeURIComponent(s.name) + "/probe");
                showNotice(s.name + ": " + (p.ok ? "ok " + p.masked : "FAILED — " + (p.error || "")), !p.ok);
              } catch (e) { showNotice(e.message, true); }
            } }, "probe"),
            " ",
            el("button", { class: "danger", onclick: async () => {
              if (!confirm("Delete secret " + s.name + "?")) return;
              try { await api("DELETE", "/api/secrets/" + encodeURIComponent(s.name)); renderSecrets(); }
              catch (e) { showNotice(e.message, true); }
            } }, "delete"),
          ),
        ),
      );

      const nameIn = el("input", { type: "text", placeholder: "NAME (e.g. PROD_DB_URL)" });
      const valueIn = el("textarea", { rows: 2, placeholder: "secret value — write-only, never shown again" });
      const refIn = el("input", { type: "text", placeholder: "ref override (optional), e.g. keychain://svc/acct" });

      main.replaceChildren(
        el("h2", null, "Secrets"),
        el("table", null,
          el("tr", null, el("th", null, "name"), el("th", null, "ref"), el("th", null, "status"), el("th", null, "actions")),
          rows.length ? rows : el("tr", null, el("td", { colspan: 4 }, "no secrets registered yet")),
        ),
        el("h3", null, "Add / overwrite secret"),
        el("div", { class: "card" },
          el("div", { class: "grid" },
            el("div", null, el("label", null, "name"), nameIn),
            el("div", null, el("label", null, "ref (optional)"), refIn),
          ),
          el("div", null, el("label", null, "value (write-only)"), valueIn),
          el("p", null,
            el("button", { class: "primary", onclick: async () => {
              try {
                if (!nameIn.value.trim()) throw new Error("name required");
                if (!valueIn.value) throw new Error("value required");
                const body = { value: valueIn.value };
                if (refIn.value.trim()) body.ref = refIn.value.trim();
                await api("PUT", "/api/secrets/" + encodeURIComponent(nameIn.value.trim()), body);
                valueIn.value = ""; // 提交即清空，不回显
                showNotice("stored " + nameIn.value.trim() + " (value not shown, by design)");
                renderSecrets();
              } catch (e) { showNotice(e.message, true); }
            } }, "store"),
          ),
        ),
      );
    } catch (e) {
      main.replaceChildren(msg(e.message, true));
    }
  }

  // ---- Rules ---------------------------------------------------------------
  async function renderRules() {
    main.replaceChildren(el("p", null, "Loading…"));
    try {
      const data = await api("GET", "/api/rules");
      const state = { rules: data.rules.map((r) => ({ ...r, match: { ...r.match } })) };
      const secretNames = data.secrets.map((s) => s.name);

      const findingsBox = el("div", null);
      function showFindings(findings) {
        findingsBox.replaceChildren(
          el("h3", null, "Static findings"),
          findings.length
            ? findings.map((f) => el("p", { class: f.severity }, `[${f.severity}] ${f.ruleId}: ${f.message}`))
            : el("p", null, "no findings ✓"),
        );
      }
      showFindings(data.findings);

      const listBox = el("div", null);
      function renderCards() {
        listBox.replaceChildren(
          ...state.rules.map((r, i) =>
            el("div", { class: "card" },
              el("div", { class: "row" },
                el("div", null, el("label", null, "id"), el("input", { type: "text", value: r.id, oninput: (e) => (r.id = e.target.value) })),
                el("div", null, el("label", null, "cwd globs (comma)"), el("input", { type: "text", value: joinCsv(r.match.cwd), oninput: (e) => { r.match.cwd = csv(e.target.value); } })),
                el("div", null, el("label", null, "command globs (comma)"), el("input", { type: "text", value: joinCsv(r.match.command), oninput: (e) => { r.match.command = csv(e.target.value); } })),
                el("div", null, el("label", null, "profiles (comma)"), el("input", { type: "text", value: joinCsv(r.match.profiles), oninput: (e) => { r.match.profiles = csv(e.target.value); } })),
              ),
              el("div", { class: "row" },
                el("div", null, el("label", null, "inject (comma, registered: " + (secretNames.join(", ") || "none") + ")"),
                  el("input", { type: "text", value: joinCsv(r.inject), oninput: (e) => { r.inject = csv(e.target.value); } })),
                el("div", null, el("label", null, "onMiss"),
                  el("select", { onchange: (e) => (r.onMiss = e.target.value) },
                    ["fail", "skip", "warn"].map((o) => el("option", { value: o, selected: r.onMiss === o ? "" : null }, o)))),
                el("div", null, el("label", null, "mergeStrategy"),
                  el("select", { onchange: (e) => (r.mergeStrategy = e.target.value) },
                    ["override", "union"].map((o) => el("option", { value: o, selected: r.mergeStrategy === o ? "" : null }, o)))),
                el("div", null, el("label", null, "ttlSeconds (blank=inherit)"),
                  el("input", { type: "number", value: r.ttlSeconds ?? "", oninput: (e) => { r.ttlSeconds = e.target.value ? parseInt(e.target.value, 10) : undefined; } })),
                el("div", { class: "narrow" }, el("label", null, "requireConfirm"),
                  el("input", { type: "checkbox", checked: r.requireConfirm, onchange: (e) => (r.requireConfirm = e.target.checked) })),
              ),
              el("p", null,
                el("button", { onclick: () => { if (i > 0) { [state.rules[i - 1], state.rules[i]] = [state.rules[i], state.rules[i - 1]]; renderCards(); } } }, "↑"),
                " ",
                el("button", { onclick: () => { if (i < state.rules.length - 1) { [state.rules[i + 1], state.rules[i]] = [state.rules[i], state.rules[i + 1]]; renderCards(); } } }, "↓"),
                " ",
                el("button", { class: "danger", onclick: () => { state.rules.splice(i, 1); renderCards(); } }, "delete"),
                " ",
                el("span", { style: "color:#888;font-size:.8rem" }, "order matters: first match wins"),
              ),
            ),
          ),
        );
      }
      renderCards();

      // Test matcher
      const cwdIn = el("input", { type: "text", value: "~/", });
      const cmdIn = el("input", { type: "text", placeholder: "pnpm run build" });
      const profIn = el("input", { type: "text", placeholder: "profile (optional)" });
      const evalOut = el("span", { class: "mono" });

      main.replaceChildren(
        el("h2", null, "Rules"),
        findingsBox,
        listBox,
        el("p", null,
          el("button", { onclick: () => {
            state.rules.push({ id: "new-rule", match: {}, inject: [], onMiss: "fail", requireConfirm: false, mergeStrategy: "override" });
            renderCards();
          } }, "+ add rule"),
          " ",
          el("button", { class: "primary", onclick: async () => {
            try {
              const r = await api("PUT", "/api/rules", { rules: state.rules });
              showNotice("rules.yaml saved (schema-validated, atomic write)");
              showFindings(r.findings || []);
            } catch (e) { showNotice("NOT saved: " + e.message, true); }
          } }, "save rules"),
        ),
        el("h3", null, "Test matcher (saved rules)"),
        el("div", { class: "row" },
          el("div", null, el("label", null, "cwd"), cwdIn),
          el("div", null, el("label", null, "command"), cmdIn),
          el("div", null, el("label", null, "profile"), profIn),
          el("div", { class: "narrow" }, el("button", { onclick: async () => {
            try {
              const r = await api("POST", "/api/rules/evaluate", {
                cwd: cwdIn.value, command: cmdIn.value, profile: profIn.value || undefined,
              });
              evalOut.textContent = " → ruleId=" + (r.ruleId || "(none)") + " inject=[" + r.inject.join(", ") + "]";
            } catch (e) { showNotice(e.message, true); }
          } }, "evaluate")),
        ),
        evalOut,
        el("details", null,
          el("summary", null, "raw rules.yaml (read-only reference; form edits rewrite the file)"),
          el("pre", { class: "mono" }, data.yaml || "(file does not exist yet)"),
        ),
      );
    } catch (e) {
      main.replaceChildren(msg(e.message, true));
    }
  }

  // ---- Config --------------------------------------------------------------
  async function renderConfig() {
    main.replaceChildren(el("p", null, "Loading…"));
    try {
      const data = await api("GET", "/api/config");
      const c = JSON.parse(JSON.stringify(data.config)); // working copy
      const d = c.defaults;

      const field = (labelText, input) => el("div", null, el("label", null, labelText), input);
      const num = (obj, key) => el("input", { type: "number", value: obj[key], oninput: (e) => (obj[key] = parseInt(e.target.value, 10)) });
      const txt = (obj, key) => el("input", { type: "text", value: obj[key] ?? "", oninput: (e) => (obj[key] = e.target.value) });
      const listTxt = (obj, key) => el("input", { type: "text", value: joinCsv(obj[key]), oninput: (e) => (obj[key] = csv(e.target.value)) });
      const chk = (obj, key) => el("input", { type: "checkbox", checked: obj[key], onchange: (e) => (obj[key] = e.target.checked) });

      const backendSel = el("select", { onchange: (e) => (c.storage.backend = e.target.value) },
        ["encrypted-file", "local-keychain"].map((o) => el("option", { value: o, selected: c.storage.backend === o ? "" : null }, o)));
      const modeSel = el("select", { onchange: (e) => (c.security.dangerousCommands.mode = e.target.value) },
        ["block", "warn"].map((o) => el("option", { value: o, selected: c.security.dangerousCommands.mode === o ? "" : null }, o)));

      main.replaceChildren(
        el("h2", null, "Config"),
        el("div", { class: "card" },
          el("h3", null, "storage"),
          el("div", { class: "grid" },
            field("backend", backendSel),
            field("encryptedFile.path", txt(c.storage.encryptedFile, "path")),
            field("encryptedFile.keySource", txt(c.storage.encryptedFile, "keySource")),
          ),
        ),
        el("div", { class: "card" },
          el("h3", null, "defaults"),
          el("div", { class: "grid" },
            field("envPassthrough (comma)", listTxt(d, "envPassthrough")),
            field("extraEnvAllowlist (comma)", listTxt(d, "extraEnvAllowlist")),
            field("maskTail (0 = no fragments)", num(d, "maskTail")),
            field("execTimeoutSeconds", num(d, "execTimeoutSeconds")),
            field("sessionTtlSeconds", num(d, "sessionTtlSeconds")),
            field("maxOutputBytes", num(d, "maxOutputBytes")),
            field("maxConcurrentExecs", num(d, "maxConcurrentExecs")),
            field("proxyTtlSeconds", num(d, "proxyTtlSeconds")),
            field("redact", chk(d, "redact")),
            field("audit", chk(d, "audit")),
            field("allowInline (dev only!)", chk(d, "allowInline")),
          ),
        ),
        el("div", { class: "card" },
          el("h3", null, "security.dangerousCommands"),
          el("div", { class: "grid" },
            field("mode", modeSel),
            field("extraPatterns (one regex per line)", el("textarea", {
              rows: 3,
              oninput: (e) => (c.security.dangerousCommands.extraPatterns = e.target.value.split("\n").map((x) => x.trim()).filter(Boolean)),
            }, (c.security.dangerousCommands.extraPatterns || []).join("\n"))),
          ),
        ),
        el("p", null, el("button", { class: "primary", onclick: async () => {
          try {
            await api("PUT", "/api/config", { config: c });
            showNotice("config.yaml saved (schema-validated, atomic write)");
          } catch (e) { showNotice("NOT saved: " + e.message, true); }
        } }, "save config")),
        el("details", null,
          el("summary", null, "raw config.yaml (read-only reference; form edits rewrite the file, comments are lost)"),
          el("pre", { class: "mono" }, data.yaml || "(file does not exist yet)"),
        ),
      );
    } catch (e) {
      main.replaceChildren(msg(e.message, true));
    }
  }

  // ---- Audit ---------------------------------------------------------------
  async function renderAudit() {
    main.replaceChildren(el("p", null, "Loading…"));
    try {
      const data = await api("GET", "/api/audit?limit=100");
      const dateSel = el("select", { onchange: async (e) => {
        const q = e.target.value ? "?date=" + e.target.value + "&limit=200" : "?limit=100";
        renderEntries(await api("GET", "/api/audit" + q));
      } }, [el("option", { value: "" }, "(latest)")].concat((data.dates || []).map((d0) => el("option", { value: d0 }, d0))));

      const tableBox = el("div", null);
      function renderEntries(d2) {
        tableBox.replaceChildren(
          el("table", null,
            el("tr", null,
              el("th", null, "ts"), el("th", null, "event"), el("th", null, "ruleId"),
              el("th", null, "command (redacted)"), el("th", null, "injected"),
              el("th", null, "exit"), el("th", null, "redacted")),
            (d2.entries || []).slice().reverse().map((e2) =>
              el("tr", null,
                el("td", { class: "mono" }, (e2.ts || "").replace("T", " ").slice(0, 19)),
                el("td", null, e2.event + (e2.dangerousCommand ? " ⚠" : "") + (e2.dryRun ? " (dry)" : "")),
                el("td", { class: "mono" }, e2.ruleId || "-"),
                el("td", { class: "mono" }, e2.command || ""),
                el("td", null, (e2.injectedNames || []).map((n) => el("span", { class: "chip" }, n))),
                el("td", null, e2.exitCode === null || e2.exitCode === undefined ? "-" : String(e2.exitCode)),
                el("td", null, String(e2.redactedCount ?? 0)),
              ),
            ),
          ),
        );
      }
      renderEntries(data);

      main.replaceChildren(
        el("h2", null, "Audit"),
        el("p", null, "date: ", dateSel, " — entries are redacted at write time; names only, never values."),
        tableBox,
      );
    } catch (e) {
      main.replaceChildren(msg(e.message, true));
    }
  }

  // ---- boot ----------------------------------------------------------------
  renderSecrets();
})();
