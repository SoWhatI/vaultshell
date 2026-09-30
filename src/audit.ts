import { appendFileSync, existsSync, mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * 审计 JSONL：~/.vaultshell/audit/YYYY-MM-DD.jsonl 追加写。
 * 铁律：command 字段写入前必须已过 Redactor，审计里不允许出现明文。
 */
export type AuditEvent =
  | "shell_exec"
  | "shell_exec_blocked"
  | "secret_set"
  | "secret_delete"
  | "session_open"
  | "session_send"
  | "session_close"
  | "session_revoke"
  | "session_expired"
  | "proxy_start"
  | "proxy_stop"
  | "proxy_expired";

export interface AuditEntry {
  ts: string;
  event: AuditEvent;
  ruleId: string | null;
  cwd: string;
  /** 已过 Redactor 的命令原文 */
  command: string;
  injectedNames: string[];
  exitCode: number | null;
  redactedCount: number;
  /** 持久会话 ID（会话相关事件） */
  sessionId?: string;
  /** warn 模式下被放行的危险命令 */
  dangerousCommand?: boolean;
  /** dryRun：只报告匹配结果，未执行 */
  dryRun?: boolean;
  /** 超时被 kill */
  timedOut?: boolean;
  /** 输出达到 maxOutputBytes 被截断 */
  truncated?: boolean;
}

export class AuditLog {
  constructor(
    private readonly dir: string,
    private readonly enabled: boolean = true,
  ) {}

  private fileFor(date: Date): string {
    return join(this.dir, `${date.toISOString().slice(0, 10)}.jsonl`);
  }

  write(entry: AuditEntry): void {
    if (!this.enabled) return;
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    appendFileSync(this.fileFor(new Date()), JSON.stringify(entry) + "\n", { mode: 0o600 });
  }

  /** 可用的审计日期（YYYY-MM-DD，新→旧） */
  dates(): string[] {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir)
      .filter((f) => f.endsWith(".jsonl"))
      .map((f) => f.slice(0, -".jsonl".length))
      .sort()
      .reverse();
  }

  /** 最近的 limit 条（可选指定日期 YYYY-MM-DD），按时间升序返回 */
  query(limit: number = 50, date?: string): AuditEntry[] {
    if (!existsSync(this.dir)) return [];
    const files = date
      ? [`${date}.jsonl`].filter((f) => existsSync(join(this.dir, f)))
      : readdirSync(this.dir)
          .filter((f) => f.endsWith(".jsonl"))
          .sort()
          .reverse();
    const entries: AuditEntry[] = [];
    for (const file of files) {
      const lines = readFileSync(join(this.dir, file), "utf8").split("\n").filter(Boolean);
      for (let i = lines.length - 1; i >= 0 && entries.length < limit; i--) {
        try {
          entries.push(JSON.parse(lines[i]!) as AuditEntry);
        } catch {
          // 跳过坏行
        }
      }
      if (entries.length >= limit) break;
    }
    return entries.reverse().slice(-limit);
  }
}
