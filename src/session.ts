import { randomBytes } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { RedactorError, StreamRedactor, redactText } from "./redactor.js";
import { checkDenied } from "./policy.js";
import { prepareInjection, pickPassthrough, type LauncherContext } from "./launcher.js";

/**
 * 持久 shell 会话（M2）。
 * - 优先 node-pty（optionalDependency，原生编译）；加载失败自动降级到纯
 *   child_process 管道模式（牺牲交互性，注入与脱敏行为一致），返回值里标注 pty:false。
 * - 创建时注入 env 并快照 injectedNames；TTL 空闲回收，到期 kill 进程，密钥随进程消失。
 * - revoke：立即 kill 并重建【无密钥】会话。
 * - 所有会话输出过 Redactor；审计照常记录（含 sessionId）。铁律不变：返回值不含明文。
 *
 * 会话输出语义：stdout/stderr 合并为单一 output（PTY 本来如此，降级模式用
 * `2>&1` 对齐）。PTY 模式下会带上终端回显与 prompt 噪音，属预期。
 */

/** node-pty 的最小结构类型（不 import 其类型，optionalDependency 缺席时 tsc 也能编译） */
export interface PtyLike {
  pid: number;
  write(data: string): void;
  kill(): void;
  onData(listener: (data: string) => void): void;
  onExit(listener: (e: { exitCode: number }) => void): void;
}

export interface PtyModuleLike {
  spawn(
    file: string,
    args: string[],
    options: { name: string; cols: number; rows: number; cwd: string; env: Record<string, string> },
  ): PtyLike;
}

export type PtyLoader = () => Promise<PtyModuleLike | null>;

/** 默认加载器：动态 import node-pty，任何失败都降级（返回 null） */
export const defaultPtyLoader: PtyLoader = async () => {
  try {
    const mod = (await import("node-pty")) as unknown as PtyModuleLike;
    return mod;
  } catch {
    return null;
  }
};

export interface SessionInfo {
  sessionId: string;
  cwd: string;
  injected: string[];
  pty: boolean;
  ttlSeconds: number;
  ruleId: string | null;
  createdAt: string;
  lastActivityAt: string;
}

interface Session {
  id: string;
  cwd: string;
  injectedNames: string[];
  ruleId: string | null;
  pty: boolean;
  ttlSeconds: number;
  createdAt: Date;
  lastActivity: Date;
  secrets: Map<string, string>;
  proc: PtyLike | ChildProcess;
  /** 已脱敏的输出滚动缓冲（明文只存在于 redactor 内部尾部，且随 flush 收敛） */
  buffer: string;
  redactor: StreamRedactor;
  decoder: StringDecoder | null;
  timer: NodeJS.Timeout;
  alive: boolean;
}

export interface SessionOpenInput {
  cwd?: string;
  profile?: string;
  ttlSeconds?: number;
}

export interface SessionOpenResult {
  ok: boolean;
  sessionId?: string;
  cwd?: string;
  injected?: string[];
  pty?: boolean;
  ttlSeconds?: number;
  warnings?: string[];
  error?: string;
}

export interface SessionSendResult {
  ok: boolean;
  output: string;
  exitCode: number | null;
  redactedCount: number;
  timedOut: boolean;
  warnings: string[];
  error?: string;
}

const MAX_BUFFER_CHARS = 4 * 1024 * 1024;
const MARKER_PREFIX = "__VAULTSHELL_DONE_";

export class SessionManager {
  private readonly sessions = new Map<string, Session>();

  constructor(
    private readonly ctx: LauncherContext,
    private readonly ptyLoader: PtyLoader = defaultPtyLoader,
  ) {}

  async open(input: SessionOpenInput): Promise<SessionOpenResult> {
    // 会话 open 无具体命令，command 传 "" 仅用于 cwd/profiles 匹配
    const prepared = await prepareInjection(this.ctx, {
      cwd: input.cwd,
      command: "",
      profile: input.profile,
    });
    if (!prepared.ok) {
      this.audit("session_open", null, prepared.cwd, prepared.ruleId, prepared.injected, "", null, 0);
      return { ok: false, error: prepared.error };
    }

    const ttlSeconds =
      input.ttlSeconds ?? prepared.ttlSeconds ?? this.ctx.config.defaults.sessionTtlSeconds;
    return this.spawnSession({
      cwd: prepared.cwd,
      env: prepared.env,
      secrets: prepared.resolved,
      ruleId: prepared.ruleId,
      ttlSeconds,
      warnings: prepared.warnings,
      auditEvent: "session_open",
    });
  }

  /** revoke：kill 原会话，同 cwd 重建一个【零注入】会话 */
  async revoke(sessionId: string): Promise<SessionOpenResult> {
    const session = this.sessions.get(sessionId);
    if (!session) return { ok: false, error: `session not found: ${sessionId}` };
    const cwd = session.cwd;
    this.killSession(session);
    this.audit("session_revoke", sessionId, cwd, session.ruleId, session.injectedNames, "", null, 0);
    // 无密钥重建：只带 passthrough env，不走规则注入
    return this.spawnSession({
      cwd,
      env: pickPassthrough(this.ctx.config.defaults.envPassthrough),
      secrets: new Map(),
      ruleId: null,
      ttlSeconds: session.ttlSeconds,
      warnings: ["session revoked: rebuilt WITHOUT any injected secrets"],
      auditEvent: "session_open",
    });
  }

  private async spawnSession(opts: {
    cwd: string;
    env: Record<string, string>;
    secrets: Map<string, string>;
    ruleId: string | null;
    ttlSeconds: number;
    warnings: string[];
    auditEvent: "session_open";
  }): Promise<SessionOpenResult> {
    const id = randomBytes(8).toString("hex");
    const shell = process.env.SHELL ?? "/bin/bash";
    const redactor = new StreamRedactor(opts.secrets);
    const session: Session = {
      id,
      cwd: opts.cwd,
      injectedNames: [...opts.secrets.keys()],
      ruleId: opts.ruleId,
      pty: false,
      ttlSeconds: opts.ttlSeconds,
      createdAt: new Date(),
      lastActivity: new Date(),
      secrets: opts.secrets,
      proc: undefined as unknown as ChildProcess,
      buffer: "",
      redactor,
      decoder: null,
      timer: undefined as unknown as NodeJS.Timeout,
      alive: true,
    };

    const ptyMod = await this.ptyLoader();
    if (ptyMod) {
      try {
        const proc = ptyMod.spawn(shell, [], {
          name: "xterm-256color",
          cols: 200,
          rows: 50,
          cwd: opts.cwd,
          env: { ...opts.env, TERM: "xterm-256color" },
        });
        session.proc = proc;
        session.pty = true;
        proc.onData((data) => this.feed(session, data));
        proc.onExit(() => {
          if (session.alive) this.expire(session, false);
        });
      } catch {
        // PTY spawn 失败同样降级
        this.spawnPipe(session, shell, opts.env, opts.cwd);
      }
    } else {
      this.spawnPipe(session, shell, opts.env, opts.cwd);
    }

    session.timer = setTimeout(() => this.expire(session, true), opts.ttlSeconds * 1000);
    session.timer.unref();
    this.sessions.set(id, session);
    this.audit(opts.auditEvent, id, opts.cwd, opts.ruleId, session.injectedNames, "", null, 0);
    return {
      ok: true,
      sessionId: id,
      cwd: opts.cwd,
      injected: session.injectedNames,
      pty: session.pty,
      ttlSeconds: opts.ttlSeconds,
      warnings: opts.warnings,
    };
  }

  /** 降级路径：纯 child_process 管道 shell（无 PTY，stderr 并入 2>&1 在写入时处理） */
  private spawnPipe(session: Session, shell: string, env: Record<string, string>, cwd: string): void {
    const child = spawn(shell, [], { env, cwd, stdio: ["pipe", "pipe", "pipe"] });
    session.proc = child;
    session.pty = false;
    session.decoder = new StringDecoder("utf8");
    child.stdout.on("data", (chunk: Buffer) => this.feed(session, session.decoder!.write(chunk)));
    child.stderr.on("data", (chunk: Buffer) => this.feed(session, session.decoder!.write(chunk)));
    child.on("close", () => {
      if (session.alive) this.expire(session, false);
    });
    child.on("error", () => {
      if (session.alive) this.expire(session, false);
    });
  }

  /** 会话输出入口：统一过 Redactor；Redactor 出错 fail-closed（杀会话、丢弃缓冲） */
  private feed(session: Session, text: string): void {
    if (!session.alive) return;
    try {
      session.buffer += session.redactor.push(text);
      if (session.buffer.length > MAX_BUFFER_CHARS) {
        session.buffer = session.buffer.slice(-MAX_BUFFER_CHARS);
      }
    } catch {
      // fail-closed：丢弃缓冲并杀掉会话
      session.buffer = "";
      this.killSession(session);
      this.sessions.delete(session.id);
    }
  }

  async send(sessionId: string, command: string): Promise<SessionSendResult> {
    const session = this.sessions.get(sessionId);
    const base: SessionSendResult = {
      ok: false,
      output: "",
      exitCode: null,
      redactedCount: 0,
      timedOut: false,
      warnings: [],
    };
    if (!session || !session.alive) {
      return { ...base, error: `session not found or expired: ${sessionId}` };
    }

    // 危险命令检查与 shell_exec 同策略（block/warn）
    const denied = checkDenied(command, this.ctx.config.security.dangerousCommands.extraPatterns);
    let dangerous = false;
    if (denied) {
      if (this.ctx.config.security.dangerousCommands.mode === "block") {
        this.audit("session_send", sessionId, session.cwd, session.ruleId, session.injectedNames, command, null, 0);
        return { ...base, error: `command blocked by deny-list: ${denied}` };
      }
      dangerous = true;
      base.warnings.push(`dangerous command allowed by security.dangerousCommands.mode=warn: ${denied}`);
    }

    session.lastActivity = new Date();
    session.timer.refresh();

    const token = randomBytes(6).toString("hex");
    const marker = `${MARKER_PREFIX}${token}__`;
    const markerRe = new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(\\d+)", "g");
    const baseline = session.buffer.length;
    const redactorCountBefore = session.redactor.count;

    // 分组执行以保留 cd 等状态；stderr 合并进 stdout（对齐 PTY 语义）
    const payload = `{\n${command}\n} 2>&1\necho "${marker}$?"\n`;
    if (session.pty) {
      (session.proc as PtyLike).write(payload);
    } else {
      (session.proc as ChildProcess).stdin!.write(payload);
    }

    const timeoutMs = this.ctx.config.defaults.execTimeoutSeconds * 1000;
    const deadline = Date.now() + timeoutMs;
    const tailRe = new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "(\\d+)");
    let exitCode: number | null = null;
    while (Date.now() < deadline) {
      markerRe.lastIndex = baseline;
      let m = markerRe.exec(session.buffer);
      if (!m) {
        // 哨兵可能还躺在 redactor 的尾部缓冲里（流式 keepLen 未 emit）。
        // 命令的全部输出都在哨兵之前，此时 flush 不会切断任何命令输出。
        if (tailRe.test(session.redactor.peekTail())) {
          try {
            session.buffer += session.redactor.flush();
          } catch {
            this.killSession(session);
            this.sessions.delete(session.id);
            return { ...base, error: "redactor failed; session killed (fail-closed)" };
          }
          markerRe.lastIndex = baseline;
          m = markerRe.exec(session.buffer);
        }
      }
      if (m) {
        exitCode = parseInt(m[1]!, 10);
        break;
      }
      if (!session.alive) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    const timedOut = exitCode === null && session.alive;

    // 取本次输出：从 baseline 起，剔除包含 marker 的行（PTY 回显行 + 真实哨兵行）
    const raw = session.buffer.slice(baseline);
    const output = raw
      .split("\n")
      .filter((line) => !line.includes(marker))
      .join("\n")
      .replace(/^\r?\n+/, "");

    base.ok = !timedOut && session.alive;
    base.output = output;
    base.exitCode = exitCode;
    base.timedOut = timedOut;
    base.redactedCount = session.redactor.count - redactorCountBefore;
    if (timedOut) {
      base.error = `command timed out after ${this.ctx.config.defaults.execTimeoutSeconds}s (session still alive)`;
    }
    if (!session.alive) {
      base.error = "session terminated during command";
    }
    this.audit(
      "session_send",
      sessionId,
      session.cwd,
      session.ruleId,
      session.injectedNames,
      redactText(session.secrets, command).text,
      exitCode,
      base.redactedCount,
      dangerous,
    );
    return base;
  }

  close(sessionId: string): { ok: boolean; error?: string } {
    const session = this.sessions.get(sessionId);
    if (!session) return { ok: false, error: `session not found: ${sessionId}` };
    this.killSession(session);
    this.sessions.delete(sessionId);
    this.audit("session_close", sessionId, session.cwd, session.ruleId, session.injectedNames, "", null, 0);
    return { ok: true };
  }

  list(): SessionInfo[] {
    return [...this.sessions.values()].map((s) => ({
      sessionId: s.id,
      cwd: s.cwd,
      injected: s.injectedNames,
      pty: s.pty,
      ttlSeconds: s.ttlSeconds,
      ruleId: s.ruleId,
      createdAt: s.createdAt.toISOString(),
      lastActivityAt: s.lastActivity.toISOString(),
    }));
  }

  /** 测试与服务退出时清理全部会话 */
  dispose(): void {
    for (const s of this.sessions.values()) this.killSession(s);
    this.sessions.clear();
  }

  private expire(session: Session, byTtl: boolean): void {
    if (!this.sessions.has(session.id)) return;
    this.killSession(session);
    this.sessions.delete(session.id);
    if (byTtl) {
      this.audit("session_expired", session.id, session.cwd, session.ruleId, session.injectedNames, "", null, 0);
    }
  }

  private killSession(session: Session): void {
    if (!session.alive) return;
    session.alive = false;
    clearTimeout(session.timer);
    try {
      session.proc.kill();
    } catch {
      // 已退出
    }
    if (session.proc && "stdin" in session.proc && session.proc.stdin) {
      try {
        (session.proc as ChildProcess).stdin!.end();
      } catch {
        // ignore
      }
    }
  }

  private audit(
    event: "session_open" | "session_send" | "session_close" | "session_revoke" | "session_expired",
    sessionId: string | null,
    cwd: string,
    ruleId: string | null,
    injectedNames: string[],
    command: string,
    exitCode: number | null,
    redactedCount: number,
    dangerousCommand: boolean = false,
  ): void {
    this.ctx.audit.write({
      ts: new Date().toISOString(),
      event,
      ruleId,
      cwd,
      command,
      injectedNames,
      exitCode,
      redactedCount,
      ...(sessionId ? { sessionId } : {}),
      ...(dangerousCommand ? { dangerousCommand: true } : {}),
    });
  }
}
