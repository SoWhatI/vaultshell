# vaultshell

English | [简体中文](README.zh-CN.md)

[![CI](https://github.com/SoWhatI/vaultshell/actions/workflows/ci.yml/badge.svg)](https://github.com/SoWhatI/vaultshell/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/vaultshell)](https://www.npmjs.com/package/vaultshell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Available on the official MCP Registry: `io.github.SoWhatI/vaultshell`

An MCP server that stores secrets in local secure storage, injects them into
shell child processes **at exec time** based on rules, and guarantees secret
plaintext **never reaches the model context** — not in tool responses, not in
logs, not in audit records.

The closed loop: **reference-based storage + conditional injection +
mandatory output redaction**.

> Status: M3 — one-shot commands + persistent sessions + credential proxy +
> external CLI backends. See
> [CHANGELOG](CHANGELOG.md) and [docs/design-spec.md](docs/design-spec.md).

## The iron rule

- No MCP tool returns secret plaintext — ever. Responses contain only names,
  masks (`[REDACTED:NAME]`), and redacted output.
- Resolvers are only invoked inside the launcher; values go straight into the
  child process `env` and never pass through the tool layer.
- `shell_exec` has **no** free-form `env` parameter. Secrets enter by rule
  reference only.
- Redactor failures are fail-closed: output is discarded, never returned raw.

## Quick start

Requires Node.js 20+.

### Install from GitHub (no npm registry account needed)

```bash
# Run on demand directly from the repo (npm installs devDependencies and
# builds dist/ via the `prepare` script):
npx -y github:SoWhatI/vaultshell

# Or install globally:
npm i -g github:SoWhatI/vaultshell
```

This is the same code as the npm registry package, installed from git —
npm clones the repo, runs `prepare` (→ `npm run build`) and links the
`vaultshell` bin. Pin a tag for reproducibility:
`npx -y github:SoWhatI/vaultshell#v0.1.1`.

### Docker (ghcr.io)

```bash
docker run -i --rm \
  -e MASTER_KEY=<64 hex chars> \
  -v ~/.vaultshell:/home/node/.vaultshell \
  ghcr.io/sowhati/vaultshell:latest
```

MCP client config using Docker:

```json
{
  "mcpServers": {
    "vaultshell": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "MASTER_KEY=<64 hex chars>",
        "-v", "~/.vaultshell:/home/node/.vaultshell",
        "ghcr.io/sowhati/vaultshell:latest"
      ]
    }
  }
}
```

The image runs as the non-root `node` user (`HOME=/home/node`), so the data
volume mounts at `/home/node/.vaultshell`. node-pty is excluded from the
image — sessions automatically fall back to pipe mode (`pty: false`) in
containers; injection and redaction are unchanged. The `web` subcommand
passes through (`docker run … ghcr.io/sowhati/vaultshell web` — loopback
inside the container, of limited use).

### From source

```bash
# Run via npx (after publish) or from source:
npm install && npm run build

# 1. Create a master key for the encrypted-file backend
export MASTER_KEY=$(openssl rand -hex 32)

# 2. Create ~/.vaultshell/config.yaml and ~/.vaultshell/rules.yaml
#    (full annotated examples: docs/user-guide.md)

# 3. Store a secret (never echoed back) and run with injection
#    via your MCP client's tools: secret_set, then shell_exec
```

Claude Desktop (`claude_desktop_config.json`):

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

**Full setup, configuration reference, rule-writing guide, client
integration, and FAQ: [docs/user-guide.md](docs/user-guide.md).**

## MCP tools

| Tool | Purpose | Returns |
|---|---|---|
| `shell_exec` | Run a one-shot command with per-rule injection. Params: `command`, `cwd?`, `profile?`, `extraEnv?` (allowlist), `dryRun?`, `timeoutSeconds?` (≤3600) | `{exitCode, stdout, stderr}` (redacted), `injected:[names]`, `ruleId`, `redactedCount`, `timedOut`, `truncated`, `warnings`; dryRun → `{dryRun:true, ruleId, injected, envKeys, denied}` |
| `shell_session_open` | Open a persistent session; secrets injected once at creation | `{sessionId, cwd, injected:[names], pty, ttlSeconds}` |
| `shell_session_send` | Send a command to a session | `{output}` (merged, redacted), `exitCode`, `redactedCount` |
| `shell_session_close` | Kill a session; secrets die with the process | `{ok}` |
| `shell_session_list` | List live sessions | metadata only |
| `shell_session_revoke` | Kill and rebuild the session **without secrets** | `{sessionId}` (new) |
| `shell_proxy_start` | Start a credential-injecting reverse proxy on 127.0.0.1 | `{proxyId, port, expiresAt, upstreamHost}` |
| `shell_proxy_stop` | Stop a proxy | `{ok}` |
| `shell_proxy_list` | List running proxies | metadata only (incl. secret **name**, never value) |
| `secret_list` | List names + metadata (backend ref, resolvable) | never values |
| `secret_set` | Write to backend; persisted, never echoed | `{name, ok}` |
| `secret_delete` | Delete and unregister | `{name, ok}` |
| `secret_probe` | Check a ref resolves | `{ok, masked:"****"}` |
| `rule_list` | Rules + static warnings (e.g. inject-everywhere) | — |
| `rule_validate` | Static findings: unknown secrets, unreachable rules, inject-everywhere, union risk, requireConfirm capability | `{ok, findings[]}` |
| `audit_query` | Read audit entries | names + redacted commands only |

## Execution limits (M3)

- `dryRun: true` on `shell_exec` reports the would-be `ruleId`, `injected`
  names, final env **key** list (never values) and the deny-list verdict —
  without executing anything.
- `timeoutSeconds` (default `defaults.execTimeoutSeconds` = 120, capped at
  3600) kills the command and returns `timedOut: true`.
- `defaults.maxOutputBytes` (default 1 MiB) truncates each output stream and
  sets `truncated: true`. Truncation happens **after** the Redactor — it can
  never bypass redaction.
- `defaults.maxConcurrentExecs` (default 8) rejects excess concurrent
  `shell_exec` calls with a clear error (no queue).
- All of the above are recorded in the audit log (`dryRun` / `timedOut` /
  `truncated` flags).

## Web config UI

```bash
vaultshell web            # loopback-only HTTP UI on a random port
vaultshell web --port 5317
```

Prints a one-time-token URL like `http://127.0.0.1:5317/?token=…` — open it
to manage secrets (write-only), edit rules with live static-validation
warnings and a matcher dry-run, edit config, and browse the redacted audit
log. The token dies with the process; every API call needs it, mutations
require same-origin `application/json` requests, and **no endpoint can ever
return a secret value**. Do not port-forward it. Design & threat model:
[docs/web-config-ui-design.md](docs/web-config-ui-design.md).

## Credential proxy (M3)

For high-sensitivity API tokens, prefer **not landing the secret in env at
all**. Declare a proxy in `config.yaml`:

```yaml
proxies:
  - id: stripe
    upstreamHost: https://api.stripe.com
    secretRef: STRIPE_KEY                          # registry name or full ref
    headerTemplate: "Authorization: Bearer ${value}"
```

Then `shell_proxy_start { "id": "stripe" }` → `{ port, expiresAt }`, and
commands call `http://127.0.0.1:<port>/v1/charges` instead of
`https://api.stripe.com/v1/charges`. The proxy injects the header **in
memory only** and auto-stops after its TTL (default 300s). Audit records the
host and secret name, never the header value.

Boundaries: `http://`/`https://` upstreams only (proxy→upstream TLS is
properly validated; no CONNECT tunneling, no TLS termination); the
client→proxy leg is plaintext on 127.0.0.1, which inherits the same-UID
local-process boundary from the threat model.

## Persistent sessions (M2)

`shell_session_open` spawns a long-lived shell with the matched rule's
secrets injected at creation. The session is recycled after an idle TTL
(`defaults.sessionTtlSeconds`, default 900s, overridable per rule via
`ttlSeconds` or per call) — when the process dies, the secrets die with it.
`shell_session_revoke` kills a possibly-compromised session immediately and
rebuilds one **without** any secrets.

Sessions use a real PTY via [`node-pty`](https://github.com/microsoft/node-pty)
(an **optional dependency** — native build, needs Xcode CLT on macOS /
build-essential + python3 on Linux). If node-pty cannot be loaded or spawned,
vaultshell automatically falls back to a plain `child_process` shell and the
`shell_session_open` response says `pty: false`; injection and redaction
behave identically, only interactivity is degraded. Session output merges
stdout/stderr (PTY semantics) and passes through the same Redactor.

## Backend support matrix

| Backend | Ref scheme | Status | Platforms | Notes |
|---|---|---|---|---|
| Encrypted file | `encfile://NAME` | ✅ Implemented | all | AES-256-GCM; master key from `env:MASTER_KEY` or macOS keychain; default |
| Local keychain | `keychain://svc/acct` | ⚠️ macOS only | macOS | spawns `security` CLI; Linux/Windows give a clear error |
| Process env | `env://NAME` | ✅ Implemented | all | read-only; good for CI |
| File | `file://path` | ✅ Implemented | all | first line; refuses permissions > 0600 |
| Inline | `inline:` | ⚠️ Restricted | all | plaintext in config; disabled by default, startup warning when enabled |
| 1Password | `op://vault/item/field` | ✅ via CLI | all | needs authenticated `op` CLI; read-only |
| Vault | `vault://path#field` | ✅ via CLI | all | needs authenticated `vault` CLI; read-only |
| Infisical | `infisical://proj/env/KEY` | ✅ via CLI | all | needs authenticated `infisical` CLI; read-only |
| Doppler | `doppler://proj/config/KEY` | ✅ via CLI | all | needs authenticated `doppler` CLI; read-only |

Details, per-backend setup, and how to register a plugin resolver:
[docs/backends.md](docs/backends.md).

## Threat model

| Threat | Mitigation |
|---|---|
| Model-context leakage | Structural: values never cross the tool layer; only names and masks |
| Command output echoing secrets | Mandatory redaction (exact + URL/Base64 variants + generic patterns), fail-closed |
| Agent dumping env (`env`, `printenv`, `/proc/*/environ`, …) | Hard-blocked deny-list (configurable via `security.dangerousCommands`: extra patterns, or `mode: warn` to allow-with-audit) + `shell_exec_blocked` audit events |
| Same-UID local process reading `/proc/PID/environ` | OS-level limit, cannot be fully fixed; per-command injection shrinks the window. **Explicit boundary.** |
| Long secret residency | Per-command injection by default; sessions have idle-TTL recycling + instant `revoke` |
| Misconfigured rule causing inject-everywhere | `rule_validate` / `rule_list` static warnings; `mergeStrategy` defaults to `override`; `requireConfirm` rules demand interactive approval (fail-closed without elicitation) |
| Config files leaking | Config stores refs only, never values; `inline:` disabled by default; store files forced to 0600 |

Full discussion: [docs/design-spec.md](docs/design-spec.md) §7.
Report vulnerabilities privately per [SECURITY.md](SECURITY.md).

## Data layout

```
~/.vaultshell/
  config.yaml     # main config
  rules.yaml      # injection rules + secret refs (refs only, never values)
  secrets.enc     # encrypted-file backend (0600)
  audit/          # JSONL audit, redacted
```

`VAULTSHELL_HOME` overrides the data directory (used by tests).

## Development

```bash
npm run build   # tsc
npm test        # vitest — redactor property tests, backend round-trips,
                # rule matching, shell_exec end-to-end
```

See [CONTRIBUTING.md](CONTRIBUTING.md) — including the security red lines
every PR must respect.

## License

[MIT](LICENSE) © 2026 vaultshell contributors
