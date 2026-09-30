# Contributing

Thanks for helping improve vaultshell.

## Development Setup

- **Node.js 20+** (see `.nvmrc`; `nvm use` picks it up)
- Install dependencies: `npm install`
  (if your npm is older and chokes on vitest 5's peer tree, use
  `npm install --legacy-peer-deps`)

## Commands

```bash
npm run build   # type-check + compile with tsc → dist/
npm test        # vitest: redactor property tests, backend round-trips,
                # rule matching, shell_exec end-to-end
npm run dev     # run the server from source via tsx
```

Tests never touch your real keychain or `~/.vaultshell/` — they use
`VAULTSHELL_HOME` pointed at a temp directory and a fake `MASTER_KEY`.
Keep it that way.

## Code Style

- TypeScript, strict mode, ESM (`NodeNext` modules, `.js` import suffixes).
- Match the surrounding code: comments are welcome where the *why* is
  non-obvious (especially security invariants); keep them truthful when you
  change behavior.
- Minimal diffs: no drive-by refactors or reformatting.

## Security Red Lines (non-negotiable in any PR)

1. **No plaintext across trust boundaries.** Secret values must never appear
   in MCP tool responses, logs, or audit records — including error paths.
   Only names and `[REDACTED:NAME]` masks.
2. **Resolvers stay below the Tool layer.** Resolved values go straight into
   the child process env in `launcher.ts`; they must not flow into tool
   handler return values. (`secret_probe` resolves only to return
   `{ok, masked}` and discards the value immediately.)
3. **Fail-closed.** Redactor errors discard output rather than returning it
   raw. Backend permission checks refuse rather than warn-and-continue.
4. **No free-form env passthrough.** `shell_exec` must not gain a generic
   `env` parameter; secrets enter by rule reference only.
5. If you change anything covered by the threat model, update the threat
   model table in `README.md` in the same PR.

## Tests for Security-Critical Changes

- Redactor changes require property-style tests: random secret values,
  random chunk splits, assert zero occurrences of the value and its
  URL-encoded / Base64 variants in outputs.
- New dangerous-command blocks go in `policy.ts` with both blocked and
  allowed test cases.
- New backends need round-trip tests and permission/error-path tests.
