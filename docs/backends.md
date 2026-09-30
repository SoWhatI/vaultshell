# Backend Support Matrix

Status legend: ✅ implemented · ⚠️ restricted/partial · 🔌 interface only (plugin point)

| Backend | Ref scheme | Status | macOS | Linux | Windows | External deps | Read | Write (secret_set) | Notes |
|---|---|---|---|---|---|---|---|---|---|
| Encrypted file | `encfile://NAME` | ✅ | ✅ | ✅ | ✅ | none | ✅ | ✅ | AES-256-GCM, per-record IV. Master key: `env:MASTER_KEY` (hex/base64) or macOS keychain (auto-generated). Store file must be ≤0600. **Default backend.** |
| Local keychain | `keychain://service/account` | ⚠️ macOS only | ✅ | ❌ clear error | ❌ clear error | macOS `security(1)` | ✅ | ✅ | Spawns `security` CLI — no native modules. Linux (libsecret/`secret-tool`) and Windows (Credential Manager) planned; today they fail with an explicit "not implemented" message. Default service is `vaultshell` when a secret has no explicit ref. |
| Process env | `env://NAME` | ✅ | ✅ | ✅ | ✅ | none | ✅ | ❌ read-only | Reads the MCP server process environment. Good for CI. |
| File | `file://path` | ✅ | ✅ | ✅ | ✅ | none | ✅ | ❌ read-only | First line of the file; refuses files with permissions > 0600. `~` expanded. |
| Inline | `inline:<value>` | ⚠️ restricted | ✅ | ✅ | ✅ | none | ✅ | ❌ read-only | Plaintext in `rules.yaml`. **Disabled by default**; requires `defaults.allowInline: true`, prints a startup warning. Dev only. |
| 1Password | `op://vault/item/field` | ✅ via CLI | ✅ | ✅ | ✅ | `op` CLI, authenticated | ✅ | ❌ | Runs `op read <ref>`. Write via the 1Password app/CLI; `secret_set` reports a clear error pointing at platform docs. |
| Vault | `vault://path/to/secret#field` | ✅ via CLI | ✅ | ✅ | ✅ | `vault` CLI (`VAULT_ADDR`/`VAULT_TOKEN` or `vault login`) | ✅ | ❌ | Runs `vault kv get -field=<field> -format=json <path>`. `#field` omitted → `value`. Write unsupported (platform docs pointed). |
| Infisical | `infisical://projectId/env/KEY` | ✅ via CLI | ✅ | ✅ | ✅ | `infisical` CLI (`INFISICAL_TOKEN` or `infisical login`) | ✅ | ❌ | Runs `infisical secrets get <KEY> --projectId=<id> --env=<env> --plain --silent`. Write unsupported. |
| Doppler | `doppler://project/config/KEY` | ✅ via CLI | ✅ | ✅ | ✅ | `doppler` CLI (`DOPPLER_TOKEN` or `doppler login`) | ✅ | ❌ | Runs `doppler secrets get <KEY> --project=<p> --config=<c> --plain`. Write unsupported. |

All four CLI backends share the same contract: 10s timeout, missing CLI /
auth failure produce an actionable error naming the install/auth docs, and
write/delete operations always fail with a pointer to the platform's own
tooling. No new npm dependencies — they spawn the platform CLIs.

## Plugin interface

Backends implement the `Resolver` interface (`src/resolver/types.ts`):

```ts
interface Resolver {
  readonly scheme: string;
  get(ref: ParsedRef): Promise<string>;       // required
  set?(ref: ParsedRef, value: string): Promise<void>;
  delete?(ref: ParsedRef): Promise<void>;
  list?(): Promise<string[]>;                  // names only, never values
}
```

Register at startup (see `src/context.ts`):

```ts
resolvers.register(new OnePasswordResolver()); // scheme "op"
```

Contract for plugin authors (security red lines, from CONTRIBUTING.md):

- `get` is only ever called from the launcher; **never** log or return the
  value anywhere else.
- Errors must be `SecretResolutionError` with a message that never includes
  the secret value (and ideally not the full ref if it could embed one).
- Respect fail-closed: throw on uncertainty, never return a best-effort
  empty string.
