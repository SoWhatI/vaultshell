import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { RedactorError, StreamRedactor, redactText } from "./redactor.js";
import { checkDenied, matchRules, normalizeCwd } from "./policy.js";
import { SecretResolutionError, type SecretEntry } from "./resolver/types.js";
import type { AuditLog } from "./audit.js";
import type { Config, RulesFile } from "./config.js";
import type { ResolverRegistry } from "./resolver/types.js";

/**
 * Launcher 上下文：Resolver 只在这里被调用，明文不过 Tool 层。
 * confirm 由 Tool 层注入（MCP elicitation）；未注入时 requireConfirm 规则一律拒绝执行。
 */
export interface LauncherContext {
  home: string;
  config: Config;
  loadRules: () => RulesFile;
  resolvers: ResolverRegistry;
  audit: AuditLog;
  confirm?: ConfirmFn;
  /** shell_exec 并发计数（maxConcurrentExecs 用） */
  execSlots: { active: number };
}

export type ConfirmOutcome = "accepted" | "declined" | "unsupported";
export type ConfirmFn = (message: string) => Promise<ConfirmOutcome>;

export interface ShellExecInput {
  command: string;
  cwd?: string;
  profile?: string;
  /** 仅允许白名单内的普通变量；密钥一律走规则 inject，不提供自由 env 字段 */
  extraEnv?: Record<string, string>;
  /** 只报告匹配结果（ruleId/injected/envKeys/deny 判定），不执行命令 */
  dryRun?: boolean;
  /** 单次超时（秒），默认 defaults.execTimeoutSeconds，上限 3600 */
  timeoutSeconds?: number;
}

export interface ShellExecResult {
  ok: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  injected: string[];
  ruleId: string | null;
  redactedCount: number;
  warnings: string[];
  timedOut: boolean;
  truncated: boolean;
  error?: string;
  /** dryRun 模式专有 */
  dryRun?: boolean;
  envKeys?: string[];
  denied?: string | null;
}

export function pickPassthrough(allow: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of allow) {
    const v = process.env[key];
    if (v !== undefined) env[key] = v;
  }
  return env;
}

export interface PrepareInput {
  cwd?: string;
  /** 规则 command 匹配与审计用；会话 open 时传 "" */
  command: string;
  profile?: string;
  /** dryRun：deny-list block 模式下也只报告不失败 */
  reportOnly?: boolean;
}

export interface PreparedInjection {
  ok: true;
  cwd: string;
  /** envPassthrough 白名单 + resolvedSecrets（extraEnv 由调用方另行合并） */
  env: Record<string, string>;
  resolved: Map<string, string>;
  injected: string[];
  ruleId: string | null;
  /** 规则级 ttlSeconds（会话用）；未设置为空 */
  ttlSeconds: number | undefined;
  warnings: string[];
  /** deny-list warn 模式下被放行的原因；block 模式不会走到这里 */
  dangerousCommand: string | null;
}

export interface PrepareFailure {
  ok: false;
  error: string;
  cwd: string;
  ruleId: string | null;
  injected: string[];
  /** deny-list block 模式拦截 */
  blocked: boolean;
}

/**
 * 注入准备管线（shell_exec 与 shell_session_open 共用）：
 * deny-list → 规则匹配 → 解析密钥（onMiss）→ requireConfirm（elicitation）。
 */
export async function prepareInjection(
  ctx: LauncherContext,
  input: PrepareInput,
): Promise<PreparedInjection | PrepareFailure> {
  const cwd = normalizeCwd(input.cwd ?? process.cwd());
  const fail = (error: string, opts?: { ruleId?: string | null; injected?: string[]; blocked?: boolean }): PrepareFailure => ({
    ok: false,
    error,
    cwd,
    ruleId: opts?.ruleId ?? null,
    injected: opts?.injected ?? [],
    blocked: opts?.blocked ?? false,
  });

  // 1. 危险命令：block → hard-block（reportOnly 时只报告）；warn → 放行但标记
  const denied = checkDenied(input.command, ctx.config.security.dangerousCommands.extraPatterns);
  let dangerousCommand: string | null = null;
  if (denied) {
    if (ctx.config.security.dangerousCommands.mode === "block" && !input.reportOnly) {
      return fail(`command blocked by deny-list: ${denied}`, { blocked: true });
    }
    dangerousCommand = denied;
  }

  // 2. 规则匹配（按顺序取第一条命中；mergeStrategy 默认 override）
  const { rules, secrets } = ctx.loadRules();
  const match = matchRules(rules, { cwd, command: input.command, profile: input.profile });
  const ruleId = match.rule?.id ?? null;
  const onMiss = match.rule?.onMiss ?? "fail";

  // 3. 解析密钥（Resolver 只在此处调用）
  const resolved = new Map<string, string>();
  const warnings: string[] = [];
  for (const name of match.inject) {
    const entry: SecretEntry = secrets.find((s) => s.name === name) ?? { name };
    try {
      resolved.set(name, await ctx.resolvers.getValue(entry));
    } catch (e) {
      const reason = e instanceof SecretResolutionError ? e.message : (e as Error).message;
      if (onMiss === "fail") {
        return fail(`failed to resolve secret "${name}": ${reason}`, { ruleId });
      }
      if (onMiss === "warn") {
        warnings.push(`secret "${name}" skipped: ${reason}`);
      }
    }
  }
  const injected = [...resolved.keys()];

  // 4. requireConfirm：走 MCP elicitation；不支持时拒绝执行，绝不静默放行
  if (match.rule?.requireConfirm) {
    if (!ctx.confirm) {
      return fail(
        `rule "${ruleId}" has requireConfirm: true, but no confirmation channel is available; ` +
          `refusing to execute. Use a client with elicitation support or remove requireConfirm.`,
        { ruleId, injected },
      );
    }
    const redactedCommand = redactText(resolved, input.command).text;
    const outcome = await ctx.confirm(
      `vaultshell: rule "${ruleId}" wants to inject [${injected.join(", ") || "(none)"}] ` +
        `into command "${redactedCommand}" (cwd: ${cwd}). Allow?`,
    );
    if (outcome === "unsupported") {
      return fail(
        `rule "${ruleId}" has requireConfirm: true, but the MCP client does not support elicitation; ` +
          `refusing to execute. Remove requireConfirm from the rule or use a capable client.`,
        { ruleId, injected },
      );
    }
    if (outcome !== "accepted") {
      return fail(`rule "${ruleId}" requires confirmation and the user declined`, { ruleId, injected });
    }
  }

  return {
    ok: true,
    cwd,
    env: {
      ...pickPassthrough(ctx.config.defaults.envPassthrough),
      ...Object.fromEntries(resolved),
    },
    resolved,
    injected,
    ruleId,
    ttlSeconds: match.rule?.ttlSeconds,
    warnings,
    dangerousCommand,
  };
}

export async function shellExec(input: ShellExecInput, ctx: LauncherContext): Promise<ShellExecResult> {
  const prepared = await prepareInjection(ctx, {
    cwd: input.cwd,
    command: input.command,
    profile: input.profile,
    reportOnly: input.dryRun ?? false,
  });
  const base: ShellExecResult = {
    ok: true,
    exitCode: null,
    stdout: "",
    stderr: "",
    injected: prepared.injected,
    ruleId: prepared.ruleId,
    redactedCount: 0,
    warnings: [],
    timedOut: false,
    truncated: false,
  };
  const auditBase = {
    ruleId: prepared.ruleId,
    cwd: prepared.cwd,
    injectedNames: prepared.injected,
  };
  const auditFail = (event: "shell_exec" | "shell_exec_blocked", extra?: object): void => {
    ctx.audit.write({
      ts: new Date().toISOString(),
      event,
      ...auditBase,
      command: prepared.ok ? redactText(prepared.resolved, input.command).text : input.command,
      exitCode: null,
      redactedCount: 0,
      ...(input.dryRun ? { dryRun: true } : {}),
      ...extra,
    });
  };

  if (!prepared.ok) {
    auditFail(prepared.blocked ? "shell_exec_blocked" : "shell_exec");
    return { ...base, ok: false, error: prepared.error };
  }

  base.warnings = [...prepared.warnings];
  const resolved = prepared.resolved;

  // extraEnv 白名单校验
  const allowlist = new Set(ctx.config.defaults.extraEnvAllowlist);
  for (const [key, value] of Object.entries(input.extraEnv ?? {})) {
    const reject = (error: string): ShellExecResult => {
      auditFail("shell_exec");
      return { ...base, ok: false, error };
    };
    if (!allowlist.has(key)) {
      return reject(`extraEnv key "${key}" is not in defaults.extraEnvAllowlist`);
    }
    if (resolved.has(key)) {
      return reject(`extraEnv key "${key}" collides with an injected secret name`);
    }
    for (const secret of resolved.values()) {
      if (secret && value.includes(secret)) {
        return reject(`extraEnv value for "${key}" contains a resolved secret; refused`);
      }
    }
  }

  // env = passthrough 白名单 + resolvedSecrets + extraEnv
  const env: Record<string, string> = { ...prepared.env, ...(input.extraEnv ?? {}) };

  // dryRun：只报告匹配结果，不执行（deny 判定结果一并返回）
  if (input.dryRun) {
    auditFail("shell_exec");
    return {
      ...base,
      dryRun: true,
      denied: prepared.dangerousCommand,
      envKeys: Object.keys(env).sort(),
      warnings: base.warnings,
    };
  }

  if (prepared.dangerousCommand) {
    base.warnings.push(`dangerous command allowed by security.dangerousCommands.mode=warn: ${prepared.dangerousCommand}`);
  }

  // 并发上限：超限直接拒绝（不排队）
  const maxConcurrent = ctx.config.defaults.maxConcurrentExecs;
  if (ctx.execSlots.active >= maxConcurrent) {
    auditFail("shell_exec");
    return {
      ...base,
      ok: false,
      error: `too many concurrent executions (${ctx.execSlots.active}/${maxConcurrent}); try again later`,
    };
  }

  const timeoutSeconds = Math.min(input.timeoutSeconds ?? ctx.config.defaults.execTimeoutSeconds, 3600);

  ctx.execSlots.active++;
  let run: RunOutcome;
  try {
    // 执行 + 流式脱敏（fail-closed）
    run = await runProcess(input.command, prepared.cwd, env, timeoutSeconds, ctx.config.defaults.maxOutputBytes, resolved);
  } finally {
    ctx.execSlots.active--;
  }

  if (run.redactorFailed) {
    // fail-closed：丢弃全部输出
    auditFail("shell_exec");
    return {
      ...base,
      ok: false,
      exitCode: run.exitCode,
      error: `redactor failed (${run.redactorFailed}); output discarded (fail-closed)`,
    };
  }

  base.exitCode = run.exitCode;
  base.stdout = run.stdout;
  base.stderr = run.stderr;
  base.redactedCount = run.redactedCount;
  base.timedOut = run.timedOut;
  base.truncated = run.truncated;
  base.ok = run.exitCode === 0;
  if (run.timedOut) {
    base.ok = false;
    base.error = `command timed out after ${timeoutSeconds}s`;
  }

  // 审计（command 先过 Redactor，审计里不允许有明文）
  ctx.audit.write({
    ts: new Date().toISOString(),
    event: "shell_exec",
    ...auditBase,
    command: redactText(resolved, input.command).text,
    exitCode: base.exitCode,
    redactedCount: base.redactedCount,
    ...(prepared.dangerousCommand ? { dangerousCommand: true } : {}),
    ...(run.timedOut ? { timedOut: true } : {}),
    ...(run.truncated ? { truncated: true } : {}),
  });
  return base;
}

interface RunOutcome {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  redactedCount: number;
  timedOut: boolean;
  truncated: boolean;
  redactorFailed: string | null;
}

function runProcess(
  command: string,
  cwd: string,
  env: Record<string, string>,
  timeoutSeconds: number,
  maxOutputBytes: number,
  secrets: Map<string, string>,
): Promise<RunOutcome> {
  return new Promise((resolvePromise) => {
    const shell = process.env.SHELL ?? "/bin/bash";
    // 注意：用 -c 而非 -lc。login shell 会 source 用户 profile，把无关输出
    // 混进 stdout/stderr，污染脱敏后的结果。
    const child = spawn(shell, ["-c", command], {
      env,
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });

    // 每条流独立 Redactor：flush 尾部各自归属，不串流
    const outRedactor = new StreamRedactor(secrets);
    const errRedactor = new StreamRedactor(secrets);
    const outDecoder = new StringDecoder("utf8");
    const errDecoder = new StringDecoder("utf8");
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let redactorFailed: string | null = null;
    let truncated = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutSeconds * 1000);

    const failClosed = (e: unknown): void => {
      redactorFailed = e instanceof RedactorError ? e.message : (e as Error).message;
      clearTimeout(timer);
      child.kill("SIGKILL");
    };

    // 截断发生在 Redactor 之后（push 先过脱敏再拼接），超出的字节直接丢弃，
    // 永远不会绕过脱敏。
    child.stdout.on("data", (chunk: Buffer) => {
      if (redactorFailed) return;
      if (stdout.length < maxOutputBytes) {
        try {
          stdout += outRedactor.push(outDecoder.write(chunk));
        } catch (e) {
          failClosed(e);
        }
      } else if (!truncated) {
        truncated = true;
        stdout += `\n[output truncated at ${maxOutputBytes} bytes]`;
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      if (redactorFailed) return;
      if (stderr.length < maxOutputBytes) {
        try {
          stderr += errRedactor.push(errDecoder.write(chunk));
        } catch (e) {
          failClosed(e);
        }
      } else if (!truncated) {
        truncated = true;
        stderr += `\n[output truncated at ${maxOutputBytes} bytes]`;
      }
    });

    child.on("error", (e) => {
      clearTimeout(timer);
      resolvePromise({
        exitCode: null,
        stdout: "",
        stderr: `spawn failed: ${e.message}`,
        redactedCount: 0,
        timedOut,
        truncated,
        redactorFailed: null,
      });
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      if (redactorFailed) {
        resolvePromise({ exitCode: code, stdout: "", stderr: "", redactedCount: 0, timedOut, truncated, redactorFailed });
        return;
      }
      try {
        stdout += outRedactor.push(outDecoder.end()) + outRedactor.flush();
        stderr += errRedactor.push(errDecoder.end()) + errRedactor.flush();
      } catch (e) {
        redactorFailed = e instanceof RedactorError ? e.message : (e as Error).message;
        resolvePromise({ exitCode: code, stdout: "", stderr: "", redactedCount: 0, timedOut, truncated, redactorFailed });
        return;
      }
      resolvePromise({
        exitCode: code,
        stdout,
        stderr,
        redactedCount: outRedactor.count + errRedactor.count,
        timedOut,
        truncated,
        redactorFailed,
      });
    });
  });
}
