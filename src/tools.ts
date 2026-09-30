import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { shellExec } from "./launcher.js";
import { upsertSecretEntry, removeSecretEntry } from "./config.js";
import { SecretResolutionError, type SecretEntry } from "./resolver/types.js";
import { validateRules } from "./validate.js";
import type { ServerContext } from "./context.js";

/**
 * Tool 层。设计铁律：不存在任何返回密钥明文的工具。
 * 返回值只含变量名、掩码、脱敏后的输出。
 */

function text(payload: unknown): { content: Array<{ type: "text"; text: string }> } {
  return { content: [{ type: "text", text: JSON.stringify(payload, null, 2) }] };
}

async function resolvable(ctx: ServerContext, entry: SecretEntry): Promise<boolean> {
  try {
    await ctx.resolvers.getValue(entry);
    return true;
  } catch {
    return false;
  }
}

export async function secretSet(
  ctx: ServerContext,
  input: { name: string; value: string; ref?: string },
): Promise<{ name: string; ok: boolean }> {
  const entry: SecretEntry = input.ref ? { name: input.name, ref: input.ref } : { name: input.name };
  await ctx.resolvers.setValue(entry, input.value);
  // 登记进 rules.yaml 的 secrets 列表（只存 ref，不存值），rules 里的 inject 才能引用
  upsertSecretEntry(entry, ctx.home);
  ctx.audit.write({
    ts: new Date().toISOString(),
    event: "secret_set",
    ruleId: null,
    cwd: "",
    command: `secret_set ${input.name}`,
    injectedNames: [],
    exitCode: 0,
    redactedCount: 0,
  });
  return { name: input.name, ok: true };
}

export async function secretDelete(
  ctx: ServerContext,
  input: { name: string },
): Promise<{ name: string; ok: boolean }> {
  const { secrets } = ctx.loadRules();
  const entry: SecretEntry = secrets.find((s) => s.name === input.name) ?? { name: input.name };
  await ctx.resolvers.deleteValue(entry);
  removeSecretEntry(input.name, ctx.home);
  ctx.audit.write({
    ts: new Date().toISOString(),
    event: "secret_delete",
    ruleId: null,
    cwd: "",
    command: `secret_delete ${input.name}`,
    injectedNames: [],
    exitCode: 0,
    redactedCount: 0,
  });
  return { name: input.name, ok: true };
}

export function registerTools(server: McpServer, ctx: ServerContext): void {
  // requireConfirm 规则走 MCP elicitation；客户端不支持时返回 "unsupported"，
  // launcher/session 会拒绝执行（绝不静默放行）。
  ctx.confirm = async (message) => {
    try {
      const result = await server.server.elicitInput({
        message,
        requestedSchema: {
          type: "object",
          properties: {
            confirm: { type: "boolean", title: "Allow this injection", default: false },
          },
        },
      });
      return result.action === "accept" ? "accepted" : "declined";
    } catch (e) {
      if (e instanceof Error && /elicitation/i.test(e.message)) return "unsupported";
      throw e;
    }
  };

  server.registerTool(
    "shell_exec",
    {
      description:
        "Execute a one-shot shell command with secrets injected per matching rule. " +
        "Output is redacted: injected secret values never appear in the response. " +
        "Dangerous commands (env, printenv, export -p, /proc/*/environ, ...) are hard-blocked. " +
        "There is no free-form env parameter; secrets are only injected by reference via rules.",
      inputSchema: {
        command: z.string().describe("shell command to execute"),
        cwd: z.string().optional().describe("working directory (~ is expanded); default: server cwd"),
        profile: z.string().optional().describe("optional profile name for rule matching"),
        extraEnv: z
          .record(z.string(), z.string())
          .optional()
          .describe("non-secret env vars, keys must be in defaults.extraEnvAllowlist"),
      },
    },
    async (input) => text(await shellExec(input, ctx)),
  );

  server.registerTool(
    "secret_list",
    {
      description: "List registered secret names with metadata (backend ref, resolvable). Never returns values.",
      inputSchema: {},
    },
    async () => {
      const { secrets } = ctx.loadRules();
      const items = await Promise.all(
        secrets.map(async (s) => ({
          name: s.name,
          ref: s.ref ?? `(default backend: ${ctx.defaultBackend.scheme})`,
          resolvable: await resolvable(ctx, s),
        })),
      );
      return text({ secrets: items });
    },
  );

  server.registerTool(
    "secret_set",
    {
      description:
        "Store a secret value into the configured backend. The value is persisted, never echoed back, " +
        "and the name is registered in rules.yaml (ref only).",
      inputSchema: {
        name: z.string().describe("secret name, e.g. PROD_DB_URL"),
        value: z.string().describe("secret value; stored only, never returned"),
        ref: z
          .string()
          .optional()
          .describe("optional explicit ref, e.g. keychain://svc/account; default: configured backend"),
      },
    },
    async (input) => {
      try {
        return text(await secretSet(ctx, input));
      } catch (e) {
        return text({ ok: false, error: (e as Error).message });
      }
    },
  );

  server.registerTool(
    "secret_delete",
    {
      description: "Delete a secret from the backend and unregister it from rules.yaml.",
      inputSchema: { name: z.string() },
    },
    async (input) => {
      try {
        return text(await secretDelete(ctx, input));
      } catch (e) {
        return text({ ok: false, error: (e as Error).message });
      }
    },
  );

  server.registerTool(
    "secret_probe",
    {
      description:
        "Check whether a secret ref can be resolved. Returns only {ok, masked}; " +
        "masked never contains value fragments unless defaults.maskTail > 0.",
      inputSchema: { name: z.string() },
    },
    async (input) => {
      const { secrets } = ctx.loadRules();
      const entry: SecretEntry = secrets.find((s) => s.name === input.name) ?? { name: input.name };
      try {
        const value = await ctx.resolvers.getValue(entry);
        const tail = ctx.config.defaults.maskTail;
        return text({ name: input.name, ok: true, masked: tail > 0 ? `****${value.slice(-tail)}` : "****" });
      } catch (e) {
        const error = e instanceof SecretResolutionError ? e.message : (e as Error).message;
        return text({ name: input.name, ok: false, error });
      }
    },
  );

  server.registerTool(
    "rule_list",
    {
      description:
        "List injection rules with static warnings (e.g. rules matching every directory → " +
        "potential unintended full injection).",
      inputSchema: {},
    },
    async () => {
      const { rules, secrets } = ctx.loadRules();
      const known = new Set(secrets.map((s) => s.name));
      const items = rules.map((r) => {
        const warnings: string[] = [];
        const cwdPatterns = r.match.cwd ?? [];
        const matchesEverything =
          (!r.match.cwd || r.match.cwd.length === 0) &&
          (!r.match.command || r.match.command.length === 0) &&
          (!r.match.profiles || r.match.profiles.length === 0);
        if (matchesEverything || cwdPatterns.some((p) => p === "**" || p === "/**")) {
          warnings.push("matches every directory: injects everywhere (potential unintended full injection)");
        }
        for (const name of r.inject) {
          if (!known.has(name)) warnings.push(`inject references unregistered secret "${name}"`);
        }
        if (r.requireConfirm) warnings.push("requireConfirm is enforced via MCP elicitation; clients without it will refuse");
        return {
          id: r.id,
          match: r.match,
          inject: r.inject,
          onMiss: r.onMiss,
          mergeStrategy: r.mergeStrategy,
          warnings,
        };
      });
      return text({ rules: items });
    },
  );

  server.registerTool(
    "audit_query",
    {
      description:
        "Query recent audit entries (newest last). Entries contain names and redacted commands only, never values.",
      inputSchema: {
        limit: z.number().int().min(1).max(500).optional().describe("max entries, default 50"),
      },
    },
    async (input) => text({ entries: ctx.audit.query(input.limit ?? 50) }),
  );

  server.registerTool(
    "shell_session_open",
    {
      description:
        "Open a persistent shell session (PTY when node-pty is available, plain child_process otherwise — " +
        "the response's `pty` field says which). Secrets are injected once at creation per matching rule; " +
        "idle sessions are killed after ttlSeconds (rule ttlSeconds overrides defaults.sessionTtlSeconds).",
      inputSchema: {
        cwd: z.string().optional().describe("working directory (~ is expanded); default: server cwd"),
        profile: z.string().optional().describe("optional profile name for rule matching"),
        ttlSeconds: z.number().int().positive().optional().describe("idle TTL override (seconds)"),
      },
    },
    async (input) => text(await ctx.sessions.open(input)),
  );

  server.registerTool(
    "shell_session_send",
    {
      description:
        "Send a command to a persistent session. Output (merged stdout/stderr) is redacted before returning. " +
        "Dangerous commands are blocked per security.dangerousCommands. Returns {output, exitCode}.",
      inputSchema: {
        sessionId: z.string(),
        command: z.string(),
      },
    },
    async (input) => text(await ctx.sessions.send(input.sessionId, input.command)),
  );

  server.registerTool(
    "shell_session_close",
    {
      description: "Close a session: kill the process; injected secrets die with it.",
      inputSchema: { sessionId: z.string() },
    },
    async (input) => text(ctx.sessions.close(input.sessionId)),
  );

  server.registerTool(
    "shell_session_list",
    {
      description: "List live sessions (metadata only: id, cwd, injected names, pty, ttl, timestamps).",
      inputSchema: {},
    },
    async () => text({ sessions: ctx.sessions.list() }),
  );

  server.registerTool(
    "shell_session_revoke",
    {
      description:
        "Immediately kill a session and rebuild a fresh one WITHOUT any injected secrets. " +
        "Use when a session may have been compromised. Returns the new sessionId.",
      inputSchema: { sessionId: z.string() },
    },
    async (input) => text(await ctx.sessions.revoke(input.sessionId)),
  );

  server.registerTool(
    "rule_validate",
    {
      description:
        "Statically validate rules.yaml and return findings: unknown secret refs, unreachable rules " +
        "(shadowed by earlier ones), inject-everywhere rules (high severity), requireConfirm capability " +
        "notes, union mergeStrategy risk notes.",
      inputSchema: {},
    },
    async () => {
      const findings = validateRules(ctx.loadRules());
      return text({
        ok: !findings.some((f) => f.severity === "high"),
        findings,
      });
    },
  );

  server.registerTool(
    "shell_proxy_start",
    {
      description:
        "Start a credential-injecting reverse proxy on 127.0.0.1 (random port) for a `proxies` entry in " +
        "config.yaml. Point commands at http://127.0.0.1:<port> instead of the real API host; the proxy " +
        "injects the secret into the configured header in memory only. Auto-stops after its TTL " +
        "(default defaults.proxyTtlSeconds=300s). The secret value is never returned anywhere.",
      inputSchema: {
        id: z.string().describe("proxies entry id from config.yaml"),
        ttlSeconds: z.number().int().positive().optional().describe("TTL override (seconds)"),
      },
    },
    async (input) => text(await ctx.proxies.start(input)),
  );

  server.registerTool(
    "shell_proxy_stop",
    {
      description: "Stop a running credential proxy.",
      inputSchema: { proxyId: z.string() },
    },
    async (input) => text(ctx.proxies.stop(input.proxyId)),
  );

  server.registerTool(
    "shell_proxy_list",
    {
      description:
        "List running credential proxies (metadata only: id, port, upstreamHost, secret NAME, expiry, " +
        "request count). Never includes values.",
      inputSchema: {},
    },
    async () => text({ proxies: ctx.proxies.list() }),
  );
}
