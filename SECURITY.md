# Security Policy

vaultshell is a security tool: its entire reason to exist is keeping secret
plaintext out of LLM contexts, logs, and audit files. We take reports about
its own security especially seriously.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via GitHub's private vulnerability reporting
("Security" tab → "Report a vulnerability") on the project repository. If that
channel is unavailable, open a minimal public issue asking for a private
contact — do not include any details of the vulnerability.

Please include:

- A description of the issue and its impact (e.g. "secret value X can reach
  the MCP client via Y").
- Steps to reproduce, ideally a minimal command sequence or test case.
- Whether any plaintext secret actually crossed a trust boundary
  (tool response / log / audit file) in your repro.

We aim to acknowledge reports within 7 days.

## Threat Model

The project's threat model — what we defend against, and the explicit
boundaries (e.g. same-UID malicious local processes are an OS-level
limitation) — is documented in
[README.md § Threat model](README.md#threat-model) and in the
[design spec](docs/design-spec.md) (§7). Please read it before reporting;
issues outside the documented boundaries are still welcome, but may be
triaged as documentation or hardening work rather than vulnerabilities.

## The Iron Rule

No MCP tool may ever return secret plaintext — in responses, logs, or audit
records. Any code path that violates this (including error paths and
fail-open behavior) is treated as a security bug. The Redactor is
fail-closed by design; keep it that way.

## Supported Versions

Only the latest release receives security fixes.
