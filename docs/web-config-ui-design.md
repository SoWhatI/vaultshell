# Web Config UI — Design Proposal (no implementation yet)

Status: **design only**. This document argues feasibility and value, fixes
scope, and sketches architecture, API, threat model, UI, and phasing.

## 1. Why a web UI, and why it is feasible

Editing `config.yaml` / `rules.yaml` by hand is the highest-friction part of
vaultshell: glob syntax, rule ordering semantics, `onMiss`, backend refs —
all easy to get subtly wrong, and mistakes fail *open* in user experience
(rules that never match) or *scary* (rules that inject everywhere). A local
web UI gives immediate validation and feedback:

- Rule editor with **static warnings as you type** (the same checks
  `rule_list` does: matches-everything, unregistered inject names) plus
  "which rule wins for this cwd/command?" dry evaluation.
- Secrets page listing names/refs/resolvability at a glance — the answer to
  "why didn't my secret inject?" in one click (`secret_probe`).
- Audit viewer: chronological, filterable, readable — today it's raw JSONL.

Feasibility is high because **every capability already exists** in the MCP
tool layer (`secret_list`, `secret_set`, `secret_probe`, `rule_list`,
`audit_query`, plus config/rules loaders in `src/config.ts`). The web UI is
a thin HTTP rendering of the same `ServerContext` — no new trust boundaries
in the core, no changes to the launcher or redactor.

## 2. Scope

In scope:

- Edit `config.yaml` and `rules.yaml` (structured forms + raw YAML fallback),
  with validation on save (the existing zod schemas) and static rule warnings.
- `secret_set` (write-only: form submits the value, server persists,
  **never echoes it back**), `secret_delete`, `secret_probe`, `secret_list`.
- Read-only audit viewer.

Out of scope (explicitly):

- **No secret reads.** The UI never displays, downloads, or round-trips an
  existing secret value. `secret_set` is write-only; there is no "edit
  current value" (delete + re-set instead). The iron rule holds on the web
  exactly as in MCP: responses contain names, refs, masks — never plaintext.
- No `shell_exec` from the browser (running arbitrary commands from a local
  web page is a much bigger attack surface; keep execution in the MCP
  client where the user sees the agent's intent).
- No remote access, no multi-user, no auth beyond the local token (see §4).
- No rule *activation* logic beyond editing the YAML — the MCP server
  re-reads `rules.yaml` per operation already, so edits take effect
  immediately for the next `shell_exec`.

## 3. Architecture

```
vaultshell web [--port 0]          # new subcommand of the same binary
  └─ local HTTP server on 127.0.0.1:<random port>
       ├─ serves the single-page UI (static, no CDN)
       ├─ JSON API under /api/*    (Bearer: one-time random token)
       └─ shares ServerContext with the MCP server code (same loaders,
          resolvers, audit reader — different process, same files)
```

- **Subcommand, same package**: `vaultshell` with no args = MCP stdio;
  `vaultshell web` = web UI. One install, shared code, no version drift.
- **Bind 127.0.0.1 only.** Never 0.0.0.0. Refuse to start if asked to bind
  anything else.
- **Ephemeral port + one-time token**: on start, generate a 128-bit random
  token, listen on port 0, and print `http://127.0.0.1:<port>/?token=<t>`
  to the console (optionally auto-open the browser). The token is required
  as a Bearer header on every `/api` call and is set into the page at first
  load (then kept in `sessionStorage`). Token dies with the process.
- **CSRF**: the random Bearer token already defeats classic CSRF (attacker
  pages can't attach it). Defense in depth: `Content-Type:
  application/json` required on mutations (no simple cross-site forms),
  `SameSite=Strict` on any cookie if we ever add one, and check
  `Sec-Fetch-Site` / `Origin` headers, rejecting cross-origin requests.
- **Tech stack (deliberately light)**:
  - Server: Node's built-in `node:http`, or [Hono](https://hono.dev) (~13 kB,
    zero-dependency routing/middleware) if `node:http` gets tedious. No
    Express/Nest — this is a dozen endpoints.
  - Frontend: a **single static HTML page** with vanilla JS or a small
    framework (Preact + htm, no build step) served from memory. Rationale:
    no bundler, no `node_modules` in the UI, no supply-chain surface, and
    the whole UI is auditable in one file. YAML round-trip in the browser
    uses the same `yaml` package we already ship, bundled at build time.
  - No websocket/SSE needed; audit viewer polls or refetches.

## 4. Threat model (web-specific)

| Threat | Mitigation | Boundary we accept |
|---|---|---|
| Another local process (same UID) hits the port | Random port + unguessable one-time token per process; 127.0.0.1 only | A same-UID process can already read `~/.vaultshell/*.yaml` and `/proc/<pid>/environ` — the OS boundary from the main threat model applies. The token stops *casual* and cross-user access, not a determined same-UID attacker. |
| Malicious website in the user's browser (DNS rebinding / CSRF) | Bearer token unknown to the web page; `Host` header check (must be `127.0.0.1:*`/`localhost:*`); Origin/`Sec-Fetch-Site` rejection; JSON-only mutations | A browser already logged-in is the trusted context. |
| Token leakage via console scrollback / shell history | Token printed once to stderr of an interactive command; not written to any file; dies with the process; `vaultshell web --token-file <0600 path>` option for scripts | If your terminal scrollback is compromised you have bigger problems. |
| XSS in the UI exfiltrating the token | No third-party JS, no CDN, strict `Content-Security-Policy: default-src 'self'`; all dynamic text rendered as text, never HTML | — |
| UI tricked into displaying a secret | Structural: **no API endpoint can return a secret value**. The worst an XSS can do is *set/delete* secrets or read names/audit — bad, but it cannot exfiltrate stored plaintext through this service. | `secret_set` is intentionally write-only. |
| Remote access misuse | No listen option beyond loopback; no TLS/termination features (they'd imply remote use); docs say "do not port-forward this" | We explicitly do not do authn/authz for network use — that's a different product (multi-user RBAC is a stated non-goal). |

## 5. API sketch

All under `http://127.0.0.1:<port>/api`, all requiring
`Authorization: Bearer <token>`, all JSON. Error shape:
`{"error": {"code": "string", "message": "string"}}`.

| Method & path | Purpose | Request → Response (example) |
|---|---|---|
| `GET /api/config` | Read effective config | → `{ "config": {…parsed config.yaml…} }` |
| `PUT /api/config` | Replace config (validated) | `{ "config": {…} }` → `{ "ok": true }` or `400` with zod issues |
| `GET /api/rules` | Rules + static warnings (same logic as `rule_list`) | → `{ "rules": [{ "id": "…", "inject": [...], "warnings": [...] }] }` |
| `PUT /api/rules` | Replace rules (validated) | `{ "rules": [...], "secrets": [...] }` → `{ "ok": true, "warnings": [...] }` |
| `POST /api/rules/evaluate` | Dry-run: which rule matches? | `{ "cwd": "~/work/x", "command": "pnpm build" }` → `{ "ruleId": "…", "inject": [...], "matchedIds": [...] }` |
| `GET /api/secrets` | List names + refs + resolvable | → `{ "secrets": [{ "name": "…", "ref": "…", "resolvable": true }] }` |
| `PUT /api/secrets/:name` | **Write-only** set | `{ "value": "…", "ref?": "…" }` → `{ "name": "…", "ok": true }` (value never returned) |
| `DELETE /api/secrets/:name` | Delete | → `{ "ok": true }` |
| `POST /api/secrets/:name/probe` | Resolve check | → `{ "ok": true, "masked": "****" }` |
| `GET /api/audit?limit=50&cursor=…` | Audit entries (redacted at write time) | → `{ "entries": [...] }` |

Note the API mirrors the MCP tools one-for-one minus `shell_exec` — same
`ServerContext`, same guarantees.

## 6. UI pages (text sketches)

**Secrets**
Table: name · ref (scheme chip: encfile/keychain/env/file) · resolvable
(✓/✗ via probe on load) · actions [probe] [delete]. "Add secret" opens a
form: name, value (password input, "this will not be shown again"), optional
ref override → PUT → row appears. No value column exists anywhere.

**Rules**
Two-pane: rule list (ordered, drag to reorder — order is semantics!) and an
editor for the selected rule: id, cwd globs, command globs, profiles,
inject (multi-select from registered secrets), onMiss, mergeStrategy.
Live warnings under the editor ("matches every directory", "inject name not
registered"). A "Test matcher" box (cwd + command + profile → shows winning
rule and inject set via `/api/rules/evaluate`).

**Config**
Form over `config.yaml` sections (backend picker toggling per-backend
fields; envPassthrough/extraEnvAllowlist as tag editors; checkboxes for
redact/audit/allowInline with warning copy on allowInline). Save → PUT
→ shows validation errors inline.

**Audit**
Table newest-first: ts · event · ruleId · cwd · command (redacted, mono) ·
injectedNames (chips) · exitCode · redactedCount. Filter by event
(`shell_exec_blocked` quickly surfaces agent probing attempts) and by
injected name.

## 7. Phasing

- **W1 (smallest useful)**: read-only UI — Secrets list (+probe), Rules
  viewer with warnings + matcher dry-run, Audit viewer. Zero mutation
  endpoints → minimal security surface, validates the architecture.
- **W2**: mutation — config/rules editors with validation, `secret_set` /
  `secret_delete` (write-only), CSRF hardening finalized.
- **W3 (maybe)**: first-run wizard (generate master key, create
  config/rules, print client config snippet), export/import of rules,
  backend plugin health page.

Dependencies on M2/M3 work: none for W1/W2; session management UI would
follow M2's PTY sessions.

## 8. W1/W2 implementation status vs. this design (as built)

Implemented as designed: loopback-only bind; ephemeral port + one-time
128-bit token printed to console (token moves to `sessionStorage` and is
stripped from the URL on load); Bearer on every API call; same-origin
Origin/Referer + `application/json` checks on mutations; Host-header check
against DNS rebinding; strict CSP with zero third-party JS (plain
`node:http` + two static files, no CDN, offline-capable); all 9 sketched
endpoints; schema-validated atomic writes (tmp + rename) that never touch
the file when validation fails.

Deviations from the sketch, with reasons:

- **YAML round-trip moved server-side.** The sketch planned to bundle the
  `yaml` package into the browser. Instead, the UI forms produce JSON and
  the server serializes YAML (`yaml.stringify`) after zod validation; raw
  YAML in the UI is read-only reference. Reason: zero browser dependencies
  (stricter CSP, no bundler at all) and validation logic stays single-sourced
  on the server. Cost: comments in hand-edited YAML are lost on save —
  accepted and documented.
- **`PUT /api/rules` replaces only the `rules` array.** The sketch included
  `secrets` in the payload; the implementation forces the server-side
  secrets registry to survive, so a stale form snapshot can't silently drop
  secrets added via `secret_set` in the meantime. (`yaml` raw mode still
  replaces the whole document deliberately.)
- **Bodyless POSTs (probe) don't require `Content-Type: application/json`.**
  The JSON-only-mutations rule applies to requests *with a body*; bodyless
  POSTs are still Bearer-protected. Reason: simpler client code with no CSRF
  loss (cross-site forms can't attach the token anyway).
- **Audit endpoint** uses `?date=YYYY-MM-DD` (strictly validated) + a `dates`
  list instead of an opaque `cursor`; simpler and sufficient for JSONL files.
- **No auto-open of the browser** (`open` module / `xdg-open`): printing the
  URL is enough and avoids another dependency. `--token-file` was dropped
  for the same reason (YAGNI for W1/W2).
- **Rule reorder** is ↑/↓ buttons, not drag-and-drop — same semantics, much
  less JS.

W3 items (first-run wizard, export/import, backend health page) remain TODO.
