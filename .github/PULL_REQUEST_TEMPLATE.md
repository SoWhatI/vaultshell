## What

<!-- What does this PR change and why? Link issues. -->

## Security checklist (required)

- [ ] No code path can return secret plaintext in tool responses, logs, or audit records (including error paths)
- [ ] Redactor stays fail-closed; no new fail-open behavior
- [ ] `shell_exec` did not gain a free-form env parameter
- [ ] Threat-model-relevant changes are reflected in `README.md`'s threat model table

## Verification

- [ ] `npm run build` passes
- [ ] `npx vitest run` passes
- [ ] New behavior is covered by tests
