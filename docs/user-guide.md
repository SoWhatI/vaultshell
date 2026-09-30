# vaultshell User Guide

English | [简体中文](user-guide.zh-CN.md)

This guide takes you from install to daily use. It assumes you know what
[MCP](https://modelcontextprotocol.io) is and have an MCP-capable client
(Claude Desktop, Cursor, …).

Contents:

1. [Installation](#1-installation)
2. [First-time configuration](#2-first-time-configuration)
3. [Backends](#3-backends)
4. [Connecting your MCP client](#4-connecting-your-mcp-client)
5. [Writing rules](#5-writing-rules)
6. [Everyday operations](#6-everyday-operations)
7. [Troubleshooting FAQ](#7-troubleshooting-faq)

---

## 1. Installation

Requirements: **Node.js 20 or newer**.

```bash
# Option A: run on demand (after the package is published)
npx -y vaultshell

# Option B: global install
npm install -g vaultshell
vaultshell            # starts the MCP server on stdio

# Option C: install from GitHub (no npm registry account needed —
# npm clones the repo and builds dist/ via the `prepare` script)
npx -y github:SoWhatI/vaultshell
npm i -g github:SoWhatI/vaultshell
# pin a tag for reproducibility: github:SoWhatI/vaultshell#v0.1.1

# Option D: Docker (ghcr.io)
docker run -i --rm \
  -e MASTER_KEY=<64 hex chars> \
  -v ~/.vaultshell:/home/node/.vaultshell \
  ghcr.io/sowhati/vaultshell:latest

# Option E: from source
git clone <repo-url> && cd vaultshell
npm install && npm run build
node dist/index.js
```

Notes on the channels:

- **GitHub install vs npm registry**: identical code; from git, npm installs
  devDependencies and runs `prepare` (→ `npm run build`), so TypeScript is
  compiled on your machine. Registry tarballs ship prebuilt `dist/` instead.
- **Docker**: the image runs as the non-root `node` user
  (`HOME=/home/node`), so mount your data directory at
  `/home/node/.vaultshell`. node-pty is not in the image — sessions fall
  back to pipe mode (`pty: false`); injection and redaction are unchanged.
  MCP client config example with `docker run`: see the README.

You normally don't run vaultshell by hand — your MCP client spawns it over
stdio. Running it directly is fine for a smoke test (it will sit waiting for
JSON-RPC; Ctrl-C to quit).

All vaultshell data lives in `~/.vaultshell/`. Set `VAULTSHELL_HOME` to use a
different directory.

## 2. First-time configuration

Two files: `~/.vaultshell/config.yaml` (how to store and run) and
`~/.vaultshell/rules.yaml` (what to inject, where). Both are optional —
defaults shown below apply when a key or file is missing.

### 2.1 config.yaml — complete annotated example

```yaml
version: 1

storage:
  # Which backend secret_set writes to by default, and where refs without a
  # scheme resolve from. One of: encrypted-file | local-keychain
  backend: encrypted-file

  encryptedFile:
    # Where the AES-256-GCM store lives. File must be mode 0600 or stricter,
    # vaultshell refuses to read it otherwise.
    path: ~/.vaultshell/secrets.enc

    # Where the 32-byte master key comes from:
    #   env:MASTER_KEY  → read hex (64 chars) or base64 from that env var
    #   keychain        → macOS login keychain (auto-generated on first use)
    keySource: env:MASTER_KEY

defaults:
  redact: true          # redact injected secrets from command output. KEEP THIS true.
  audit: true           # append JSONL audit records to ~/.vaultshell/audit/

  # Host env vars passed to child processes. Deliberately short: anything not
  # listed does not exist for the child (less host noise, less leakage).
  envPassthrough: [PATH, HOME, USER, LANG, SHELL, TERM, TMPDIR]

  # extraEnv keys shell_exec callers may set. Ordinary variables only —
  # secrets must go through rules, never through extraEnv.
  extraEnvAllowlist: [CI, DEBUG, DRY_RUN, NODE_ENV, NO_COLOR, FORCE_COLOR]

  allowInline: false    # allow inline:<plaintext> refs. Dev only; startup warning.

  maskTail: 0           # secret_probe mask keeps the last N chars. 0 = no value
                        # fragments at all. Only raise if you need "…ends with abcd".

  execTimeoutSeconds: 120   # shell_exec / shell_session_send hard timeout
  sessionTtlSeconds: 900    # idle TTL for persistent sessions
  maxOutputBytes: 1048576   # per-stream output cap → truncated: true
  maxConcurrentExecs: 8     # excess concurrent shell_exec calls are rejected
  proxyTtlSeconds: 300      # credential proxy auto-stop TTL

# Credential proxies (see §6 "High-sensitivity APIs"). headerTemplate must
# contain ${value}; upstreamHost is http(s)://host[:port] with no path.
proxies:
  - id: stripe
    upstreamHost: https://api.stripe.com
    secretRef: STRIPE_KEY
    headerTemplate: "Authorization: Bearer ${value}"
```

Generate a master key (encrypted-file backend, `env:MASTER_KEY` source):

```bash
openssl rand -hex 32        # put the 64-char result in your client's env block
```

### 2.2 rules.yaml — complete annotated example

```yaml
version: 1

# The secret registry: names → refs. Refs only — never values.
secrets:
  - name: PROD_DB_URL                 # no ref → default backend, encfile://PROD_DB_URL
  - name: NPM_TOKEN
    ref: keychain://vaultshell/NPM_TOKEN     # macOS keychain, service/account
  - name: LOCAL_TOKEN
    ref: file://~/.secrets/local_token       # first line of a 0600 file
  - name: CI_DEPLOY_KEY
    ref: env://CI_DEPLOY_KEY                 # from the MCP server's own env

rules:
  # Evaluated top to bottom. The FIRST matching rule wins (mergeStrategy
  # "override"); its inject list is what the child process gets.
  - id: work-proj-a
    match:
      cwd: ["~/work/proj-a/**"]       # glob on the working directory, ~ expanded
      command: ["pnpm *", "node *"]   # optional: command prefix globs
      profiles: [dev]                 # optional: only when profile=dev is passed
    inject: [PROD_DB_URL, LOCAL_TOKEN]
    onMiss: fail                      # fail | skip | warn — see §5.3

  - id: npm-work
    match:
      cwd: ["~/work/**"]
      command: ["npm *", "pnpm *", "npx *"]
    inject: [NPM_TOKEN]

  # Catch-all: matches every directory. rule_list will flag it with a warning.
  - id: default-safe
    match:
      cwd: ["**"]
    inject: [LOCAL_TOKEN]
```

### 2.3 security section (dangerous-command policy)

```yaml
security:
  dangerousCommands:
    # block (default): matching commands are hard-blocked before execution.
    # warn: they run, but the response carries a warning and the audit entry
    #       gets dangerousCommand: true. Output is still redacted either way.
    mode: block
    # Extra regexes matched against the whole command string, on top of the
    # built-in list (env, printenv, bare set, export -p, declare -x,
    # compgen -e, /proc/*/environ, ps eww, ...). YAML single quotes keep
    # regex backslashes literal.
    extraPatterns:
      - '^mysecretprinter\b'
```

Invalid regexes in `extraPatterns` fail config loading with a clear error.

## 3. Backends

Full matrix and plugin API: [docs/backends.md](backends.md). The short version:

### encrypted-file (default)

Zero-dependency AES-256-GCM file store. Setup:

```bash
export MASTER_KEY=$(openssl rand -hex 32)   # or use keySource: keychain on macOS
```

Then `secret_set` from your MCP client stores values encrypted at
`~/.vaultshell/secrets.enc` (mode 0600). With `keySource: keychain` (macOS),
the master key is auto-generated on first use and stored in your login
keychain under service `vaultshell`, account `encfile-master-key`.

### local-keychain (macOS)

Store and read secrets with the system `security` CLI:

```bash
security add-generic-password -s vaultshell -a NPM_TOKEN -w 'the-secret-value' -U
security find-generic-password -s vaultshell -a NPM_TOKEN -w    # verify (prints the value!)
```

Reference it as `keychain://vaultshell/NPM_TOKEN`, or set
`storage.backend: local-keychain` and skip the ref (service defaults to
`vaultshell`, account = secret name). On Linux/Windows this backend reports a
clear "not implemented" error (libsecret / Credential Manager support is
planned).

### env:// and file:// refs

- `env://NAME` — read from the MCP server process environment. Read-only.
  Handy in CI: export secrets into the server process, reference them by name.
- `file://path` — first line of a file. The file must be `chmod 600` (or
  stricter) or vaultshell refuses to read it. Read-only.

### inline: (plaintext — avoid)

`inline:<value>` puts the secret directly in rules.yaml. It is **disabled by
default**; enabling requires `defaults.allowInline: true` and prints a
startup warning. Only for local development throwaway values.

### External platforms via CLI (1Password / Vault / Infisical / Doppler)

Read-only backends that spawn the platform's own CLI (no new npm
dependencies). Authenticate the CLI first; vaultshell never touches their
credentials itself.

| Ref | Resolves via | Auth prerequisite |
|---|---|---|
| `op://Personal/stripe/key` | `op read op://Personal/stripe/key` | `op` CLI signed in |
| `vault://secret/data/prod/db#password` | `vault kv get -field=password -format=json secret/data/prod/db` | `VAULT_ADDR`+`VAULT_TOKEN` or `vault login` |
| `infisical://proj-id/prod/API_KEY` | `infisical secrets get API_KEY --projectId=proj-id --env=prod --plain --silent` | `INFISICAL_TOKEN` or `infisical login` |
| `doppler://backend/prd/STRIPE_KEY` | `doppler secrets get STRIPE_KEY --project=backend --config=prd --plain` | `DOPPLER_TOKEN` or `doppler login` |

Use them as refs in `rules.yaml`:

```yaml
secrets:
  - name: STRIPE_KEY
    ref: op://Personal/stripe/key
```

If the CLI is missing from PATH, times out (10s), or isn't authenticated,
you get an actionable error naming the fix. `secret_set`/`secret_delete` are
**not supported** for these backends — manage values with the platform's own
tooling (the error message links to it).

## 4. Connecting your MCP client

### Claude Desktop

Edit `claude_desktop_config.json` (macOS: `~/Library/Application
Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "vaultshell": {
      "command": "npx",
      "args": ["-y", "vaultshell"],
      "env": {
        "MASTER_KEY": "<64 hex chars from openssl rand -hex 32>"
      }
    }
  }
}
```

Restart Claude Desktop. The `vaultshell` tools appear in the tool list.

### Cursor

Settings → MCP → add server (or edit `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "vaultshell": {
      "command": "npx",
      "args": ["-y", "vaultshell"],
      "env": { "MASTER_KEY": "<64 hex chars>" }
    }
  }
}
```

If you built from source, point `command` at `node` and `args` at
`["/absolute/path/to/vaultshell/dist/index.js"]`.

## 5. Writing rules

### 5.1 Matching

- **cwd globs** use [minimatch](https://github.com/isaacs/minimatch) syntax.
  `~/work/x/**` matches `~/work/x` itself and everything below it. `~` is
  expanded. Patterns are matched against the absolute, `~`-expanded cwd.
- **command globs** match the whole command string, so `pnpm *` means
  "commands starting with pnpm".
- **profiles** match only when the caller passes `profile: "<name>"` to
  `shell_exec`. A rule with `profiles` never fires without a profile.
- All conditions in a rule must hold (AND); entries inside one condition are
  OR-ed.

### 5.2 Order and merge strategy

Rules are evaluated **in file order; the first match wins**
(`mergeStrategy: override`, the default) — later rules are ignored, so you
can never "accidentally accumulate" more secrets by matching more rules.
Put specific rules above general ones.

If a rule declares `mergeStrategy: union` and it is the first match, the
inject lists of **all** matching rules are unioned. Use sparingly — that is
exactly the "matching more = getting more" escalation override exists to
prevent.

### 5.3 onMiss — what if a secret can't be resolved?

- `fail` (default): refuse to run. The command never executes; you get an
  error naming the unresolvable secret. Safest.
- `warn`: run without that secret, and say so in the response `warnings`.
- `skip`: run without that secret, silently.

### 5.4 requireConfirm — interactive approval for high-risk rules

```yaml
  - id: payment-scope
    match: { cwd: ["~/work/payments/**"] }
    inject: [STRIPE_KEY]
    requireConfirm: true
```

When the first matching rule has `requireConfirm: true`, vaultshell asks for
confirmation through the client before executing (MCP elicitation). If the
client does not support elicitation, the command is **refused** with a
message telling you to remove `requireConfirm` or switch clients — it is
never silently allowed.

**Client support requirement**: elicitation is a client capability. The
client must declare the `elicitation` capability at handshake and implement
an `elicitation/create` handler for the confirmation request to reach the
user. Known status (trust the actual error; any message containing
`the MCP client does not support elicitation` means unsupported):

- ✅ Supported: self-built clients that declare `elicitation` in their
  `capabilities`; recent Claude Desktop / VS Code builds do support it
  (check their release notes).
- ❌ Not supported: MCP Inspector (verified up to 0.15.0 — its proxy does
  not declare the capability). **While debugging with the Inspector, rules
  with `requireConfirm` are always refused.**

Wiring up a self-built client takes two steps (TypeScript SDK):

```ts
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const client = new Client({ name: "my-client", version: "1.0.0" }, {
  capabilities: { elicitation: {} },                       // 1. declare capability
});
client.setRequestHandler(ElicitRequestSchema, async (req) => {
  // render req.params.message + req.params.requestedSchema, collect the choice
  return { action: "accept", content: { confirm: true } }; // 2. accept / decline
});
```

Debugging tip: when working in clients without elicitation support (e.g.
the Inspector), temporarily set `requireConfirm: false` on the rule (the
Web UI Rules page edits it in place, effective on save), verify everything
else, then turn it back on.

### 5.5 ttlSeconds — session idle TTL per rule

`ttlSeconds` on a rule overrides `defaults.sessionTtlSeconds` (900s) for
sessions opened under it. When a session idles past its TTL, vaultshell
kills the process — injected secrets exist only as long as the process does.

### 5.6 Static validation

`rule_validate` returns structured findings (severity `high`/`warn`/`info`):

- `unknown-secret` — inject references a name not in the secrets registry
- `inject-everywhere` (high) — rule matches every directory and injects
  non-empty secrets
- `unreachable` — shadowed by an earlier match-everything rule or an earlier
  rule with identical match conditions (first match wins)
- `require-confirm` — capability note (clients without elicitation refuse)
- `union-strategy` — privilege-creep risk of `mergeStrategy: union`
- `empty-inject` — rule injects nothing

These are heuristics, not proofs — glob containment is not decidable in
general. `rule_list` still gives a per-rule summary view.

## 5.7 Persistent sessions

```text
shell_session_open  { "cwd": "~/work/proj-a" }
→ { "ok": true, "sessionId": "…", "injected": ["PROD_DB_URL"], "pty": true, "ttlSeconds": 900 }

shell_session_send  { "sessionId": "…", "command": "pnpm run migrate" }
→ { "ok": true, "output": "…(redacted)…", "exitCode": 0 }

shell_session_list  → metadata of live sessions (never values)
shell_session_revoke { "sessionId": "…" } → kills it, returns a NEW session without secrets
shell_session_close  { "sessionId": "…" }
```

Notes:

- Sessions use a real PTY when `node-pty` is installed and loadable
  (optional dependency; native build). Otherwise vaultshell falls back to a
  plain `child_process` shell and the open response says `pty: false` —
  injection and redaction behave the same, only interactivity is degraded.
- Session output merges stdout/stderr into one `output` field (PTY
  semantics). In PTY mode the output contains terminal echo/prompt noise;
  secrets in it are still masked.
- State persists across sends (`cd`, shell variables). Sending `exit` kills
  the session itself.
- The same deny-list and redaction apply to session sends; audit entries
  carry `sessionId`.
- Do not hand-type `export SECRET=…` into a session — vaultshell cannot
  intercept that; it's covered by audit + prompts only.

## 6. Everyday operations

All of these are MCP tools — you (or the agent) call them from the client.

**Store a secret**

```
secret_set { "name": "PROD_DB_URL", "value": "postgres://…" }
```

The value is written to the default backend, never echoed back, and the name
is registered in `rules.yaml` (ref only).

**Verify a secret resolves**

```
secret_probe { "name": "PROD_DB_URL" }
→ { "ok": true, "masked": "****" }
```

**Run something**

```
shell_exec { "command": "pnpm run migrate", "cwd": "~/work/proj-a" }
→ { "exitCode": 0, "stdout": "…", "injected": ["PROD_DB_URL"], "ruleId": "work-proj-a", … }
```

If the command prints the secret (directly, URL-encoded, or Base64), the
output contains `[REDACTED:PROD_DB_URL]` instead.

**Review what happened**

```
audit_query { "limit": 20 }
```

Entries: `{ts, event, ruleId, cwd, command (redacted), injectedNames,
exitCode, redactedCount}` — names only, never values.

**Delete a secret**

```
secret_delete { "name": "PROD_DB_URL" }
```

**Preview before running (dry run)**

```
shell_exec { "command": "pnpm run migrate", "cwd": "~/work/proj-a", "dryRun": true }
→ { "dryRun": true, "ruleId": "work-proj-a", "injected": ["PROD_DB_URL"],
    "envKeys": ["HOME", "PATH", "PROD_DB_URL", …], "denied": null }
```

Nothing executes; you see which rule wins, which secrets would be injected,
the final env **key** list (never values), and the deny-list verdict.

**Timeouts and limits**

- `shell_exec { …, "timeoutSeconds": 30 }` — kill after N seconds (default
  `defaults.execTimeoutSeconds` = 120, cap 3600); result has
  `timedOut: true`.
- Output per stream is capped at `defaults.maxOutputBytes` (1 MiB); beyond
  that you get a truncation notice and `truncated: true`. Truncation happens
  after the Redactor, so it can't bypass masking.
- More than `defaults.maxConcurrentExecs` (8) concurrent `shell_exec` calls
  are rejected with a clear error — no queue.

**High-sensitivity APIs without env vars (credential proxy)**
Declare once in `config.yaml`:

```yaml
proxies:
  - id: stripe
    upstreamHost: https://api.stripe.com
    secretRef: STRIPE_KEY
    headerTemplate: "Authorization: Bearer ${value}"
```

Then:

```
shell_proxy_start { "id": "stripe" }
→ { "ok": true, "proxyId": "…", "port": 51743, "expiresAt": "…" }

shell_exec { "command": "curl http://127.0.0.1:51743/v1/charges", "cwd": "~" }
```

The proxy injects `Authorization: Bearer <STRIPE_KEY>` in memory and forwards
to `https://api.stripe.com` — the secret never lands in the command's env,
command line, or any response. The proxy auto-stops after its TTL (default
`defaults.proxyTtlSeconds` = 300s; override per call with `ttlSeconds`), or
early via `shell_proxy_stop`. `shell_proxy_list` shows metadata only. Audit
records the upstream host and secret **name**, never the header value.

Boundaries: `http://`/`https://` upstreams only; no CONNECT tunneling, no
TLS termination; the client→proxy leg is plaintext loopback (same-UID local
processes could sniff it — the documented OS-level boundary). Secrets whose
resolved value contains CR/LF are rejected (header-injection guard).

**Managing everything from a browser (web config UI)**

```bash
vaultshell web            # random loopback port, prints a one-time-token URL
vaultshell web --port 5317
```

Open the printed URL (it carries a one-time token, moved to sessionStorage
on load and stripped from the address bar). Four pages:

- **Secrets** — list names/refs/resolvability, probe, delete, and a
  write-only "store" form (the value is never displayed again).
- **Rules** — card editor for every rule field, reorder with ↑/↓ (order is
  semantics), live static findings (the same checks as `rule_validate`), and
  a matcher dry-run box.
- **Config** — form over every `config.yaml` section; saving is
  schema-validated and atomic (tmp file + rename). Invalid input is rejected
  **without touching the file**.
- **Audit** — per-day JSONL viewer, newest first.

Security properties: loopback only, per-process random token (Bearer on
every API call), mutations require same-origin `application/json` requests,
strict CSP, no third-party JS — and the iron rule holds: no endpoint returns
secret values. The UI process and the MCP server process share the same
files (`rules.yaml` is re-read per operation, so edits apply to the next
`shell_exec` immediately). Do not port-forward the port. Full design and
threat model: `docs/web-config-ui-design.md`.

## 7. Troubleshooting FAQ

**`failed to resolve secret "X": secret "X" not found in encrypted file`**
The name is in a rule's `inject` but no value is stored. Run `secret_set`,
or check with `secret_probe`. If you renamed the secret in rules.yaml, the
stored name must match exactly.

**`master key env var MASTER_KEY is not set`**
The MCP client spawns vaultshell with its own environment — exporting
`MASTER_KEY` in your shell is not enough. Put it in the client's `env` block
(see §4), or switch to `keySource: keychain` on macOS.

**`failed to decrypt "X" (wrong master key or corrupted store)`**
The `MASTER_KEY` changed after secrets were written. There is no recovery —
the old key is the only key. Re-set the secrets with `secret_set`.

**`refusing to read … permissions 644 are too open`**
`chmod 600` the file (secrets.enc or a `file://` target). vaultshell refuses
group/world-readable secret stores on purpose.

**`command blocked by deny-list: …`**
You (or the agent) tried `env`, `printenv`, bare `set`, `export -p`,
`declare -x`, `compgen -e`, reading `/proc/*/environ`, or `ps` with the BSD
`e` flag. These dump process environments and are hard-blocked — that is the
feature, not a bug. Use the specific command you actually need
(e.g. `echo $PATH` is fine). To tune the policy, see
`security.dangerousCommands` (§2.3): add `extraPatterns`, or set
`mode: warn` to allow-with-audit instead of blocking.

**`shell_session_open` says `pty: false`**
`node-pty` failed to load or spawn, so vaultshell fell back to a plain pipe
shell — everything still works, just without terminal interactivity. Common
causes: node-pty isn't installed (it's an optional dependency), its native
build failed (install Xcode CLT on macOS / `build-essential` + python3 on
Linux and reinstall), or its `spawn-helper` lost the executable bit
(`chmod +x node_modules/node-pty/prebuilds/*/spawn-helper` fixes that).

**A session disappeared on its own**
It hit its idle TTL (`ttlSeconds` on the rule, else
`defaults.sessionTtlSeconds`, default 900s) and was recycled — the audit log
has a `session_expired` entry. Open a new one.

**A rule with `requireConfirm` always refuses to run**
Your MCP client doesn't support elicitation. vaultshell fails closed here by
design — remove `requireConfirm` from the rule or use a client that supports
elicitation (support matrix and self-built wiring guide in §5.4; MCP
Inspector ≤0.15.0 is known unsupported).

**Secrets aren't injected (`injected: []`)**
No rule matched. Check `rule_list`, confirm the cwd glob matches the
absolute path (`~` expansion, symlinks resolved via `realpath`-style
normalization), and remember: first match wins — a broad rule above your
specific one shadows it.

**`local-keychain backend is only implemented on macOS`**
Correct — Linux (libsecret) and Windows (Credential Manager) support is
planned but not implemented. Use `encrypted-file` meanwhile.

**`CLI not found in PATH: "op" / "vault" / "infisical" / "doppler"`**
The external backends spawn the platform CLI. Install it and authenticate
(`op signin`, `vault login` / `VAULT_TOKEN`, `infisical login` /
`INFISICAL_TOKEN`, `doppler login` / `DOPPLER_TOKEN`) in the environment of
the MCP server process. These backends are read-only — `secret_set` against
an `op://`/`vault://`/`infisical://`/`doppler://` ref always fails by design.

**`shell_proxy_start` fails with "no proxies entry with id …"**
Declare the proxy in `config.yaml` under `proxies:` first. If it fails with
"CR/LF … refused", the resolved secret contains a newline — the proxy
rejects it as a header-injection guard; check for a trailing newline in the
stored value.

**My command needs an env var that isn't there**
Children only get `defaults.envPassthrough` + injected secrets + allowlisted
`extraEnv`. Add what you need to `envPassthrough` (ordinary vars) or inject
it as a secret.

**The output says `[output truncated at 1MiB]`**
Each stream is capped at 1 MiB. Pipe large outputs to a file and read the
parts you need.

**Does vaultshell protect me from a malicious process running as my user?**
No — that is an OS-level boundary (such a process can read
`/proc/<pid>/environ` while the child runs). vaultshell shrinks exposure
(per-command injection, no plaintext at rest outside the backends) but
cannot fix the OS. See the threat model in the README.
