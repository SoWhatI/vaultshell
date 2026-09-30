# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-30

First public release: M1 MVP + M2 (sessions, rules) + M3 (hardening,
credential proxy) + web config UI.

### Added
- Persistent shell sessions (M2): `shell_session_open` / `shell_session_send`
  / `shell_session_close` / `shell_session_list` / `shell_session_revoke`.
  Secrets are injected once at creation and snapshotted as names; idle
  sessions are recycled after a TTL (`defaults.sessionTtlSeconds`, default
  900s, overridable per rule via `ttlSeconds` or per call); `revoke` kills a
  session and rebuilds it **without** secrets. Session output merges
  stdout/stderr and passes through the Redactor; audit entries carry
  `sessionId`.
- PTY support via `node-pty` as an **optional dependency** (runtime dynamic
  import); when unavailable, sessions fall back to a plain `child_process`
  shell and `shell_session_open` reports `pty: false`.
- `requireConfirm` rules now enforced via MCP elicitation; clients without
  elicitation support cause a refusal to execute (fail-closed, never a
  silent allow).
- `rule_validate` tool: static findings for unknown secret refs, unreachable
  rules, inject-everywhere rules (high severity), requireConfirm capability
  notes, and `union` merge-strategy risk notes.
- Configurable dangerous-command policy: `security.dangerousCommands.mode`
  (`block` default / `warn` = allow with a response warning and
  `dangerousCommand: true` in audit) and `security.dangerousCommands
  .extraPatterns` (extra regexes, validated at config load).
- External backends via platform CLIs, no new npm dependencies (M3):
  `op://vault/item/field` (`op read`), `vault://path/to/secret#field`
  (`vault kv get -field=<field> -format=json`),
  `infisical://projectId/env/KEY`, `doppler://project/config/KEY`. Read-only;
  missing CLI / auth failure / 10s timeout produce actionable errors;
  `secret_set`/`secret_delete` against them fail pointing at platform docs.
- `shell_exec` hardening (M3): `dryRun: true` (reports ruleId / injected
  names / env **key** list / deny verdict without executing),
  `timeoutSeconds` (default 120, capped 3600, `timedOut: true` on kill),
  `defaults.maxOutputBytes` (1 MiB, post-Redactor truncation with
  `truncated: true`), `defaults.maxConcurrentExecs` (8, reject — no queue).
  All recorded in audit (`dryRun` / `timedOut` / `truncated` flags).
- Credential proxy (M3, minimal): `shell_proxy_start` / `shell_proxy_stop` /
  `shell_proxy_list`. Declared via `proxies` in config.yaml
  (`{id, upstreamHost, secretRef, headerTemplate}`); the proxy listens on
  127.0.0.1 (random port), injects the resolved secret into the configured
  header **in memory only**, forwards to `http(s)://` upstreams, and
  auto-stops after `defaults.proxyTtlSeconds` (300s). Audit/logs record host
  and secret name only — never the header value. CR/LF in resolved values is
  rejected (header-injection guard).
- Web config UI (`vaultshell web [--port N]`, W1+W2 of
  `docs/web-config-ui-design.md`): loopback-only local HTTP server with a
  one-time random token (printed to console), four pages (Secrets write-only
  management, Rules editor with live static findings + matcher dry-run,
  Config form, Audit viewer). Security: Bearer token on every API call,
  same-origin + JSON-Content-Type mutation checks, Host-header DNS-rebinding
  guard, strict CSP, zero third-party JS/CDN, atomic schema-validated YAML
  writes (invalid input never touches the file). No endpoint returns secret
  plaintext — same iron rule as the MCP surface.

- `shell_exec` MCP tool: one-shot command execution with per-rule secret
  injection; streaming redaction of stdout/stderr (exact values +
  URL-encoded/Base64 variants + generic patterns for `sk-` keys, JWTs, AWS
  access key IDs, PEM blocks); fail-closed on redactor errors.
- Backends: `encrypted-file` (AES-256-GCM, master key from `env:MASTER_KEY`
  or macOS keychain), `local-keychain` (macOS `security` CLI), `env://`,
  `file://` (first line, permissions must be ≤0600). `inline:` disabled by
  default. Plugin interface (`ResolverRegistry`) for `op://`,
  `infisical://`, `vault://` (not implemented).
- Tools: `secret_list`, `secret_set`, `secret_delete`, `secret_probe`,
  `rule_list` (with static full-injection warnings), `audit_query`.
- Rule matching by cwd glob (with `~` expansion), command prefix globs and
  profiles; first match wins (`override`) or `union`; `onMiss: fail|skip|warn`.
- Dangerous-command deny-list, hard-blocked (`env`, `printenv`, bare `set`,
  `export -p`, `declare -x`, `compgen -e`, `/proc/*/environ`, `ps eww`, …).
- JSONL audit log (`~/.vaultshell/audit/`) with redacted commands; no
  plaintext ever recorded.
- Test suite: redactor leak property tests, encrypted-file round-trips,
  rule-matching edge cases, `shell_exec` end-to-end with a fake master key.
