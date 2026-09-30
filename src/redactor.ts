/**
 * Redactor：整个项目的安全基石。
 *
 * - 精确值匹配 + 变体（URL-encode、Base64），掩码格式 [REDACTED:NAME]，不保留任何值片段。
 * - 通用正则兜底：sk- API key、JWT、AWS Access Key ID、PEM 私钥块。
 * - 流式：保留滑动尾部缓冲（keepLen ≥ 最长待匹配模式），防止密钥被 chunk 切断后泄漏；
 *   PEM 块在未见到 END 前从 BEGIN 起挂起，不提前 emit。
 * - fail-closed：内部任何异常 → RedactorError，调用方必须丢弃输出而不是原样返回。
 */

export class RedactorError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "RedactorError";
  }
}

export function maskFor(label: string): string {
  return `[REDACTED:${label}]`;
}

const PEM_BEGIN = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const PEM_BLOCK =
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,16384}?-----END [A-Z0-9 ]*PRIVATE KEY-----/g;

interface GenericPattern {
  label: string;
  re: RegExp;
}

/** 长度均有上界，保证 keepLen 能覆盖跨 chunk 的部分前缀 */
const GENERIC_PATTERNS: GenericPattern[] = [
  { label: "pem", re: PEM_BLOCK },
  { label: "jwt", re: /eyJ[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{8,1024}/g },
  { label: "aws-ak", re: /(?:AKIA|ASIA)[0-9A-Z]{16}/g },
  { label: "sk", re: /sk-[A-Za-z0-9]{20,512}/g },
];

interface LiteralPattern {
  label: string;
  text: string;
}

interface Match {
  s: number;
  e: number;
  label: string;
}

export interface RedactorOptions {
  /** 通用正则兜底，默认 true */
  generic?: boolean;
}

export class StreamRedactor {
  private readonly literals: LiteralPattern[] = [];
  private readonly generic: boolean;
  private readonly keepLen: number;
  private buf = "";
  private replacements = 0;
  private poisoned = false;

  constructor(secrets: Iterable<[string, string]>, opts: RedactorOptions = {}) {
    const seen = new Set<string>();
    for (const [name, value] of secrets) {
      if (!value) continue;
      for (const text of [value, encodeURIComponent(value), Buffer.from(value, "utf8").toString("base64")]) {
        if (!text || seen.has(text)) continue;
        seen.add(text);
        this.literals.push({ label: name, text });
      }
    }
    // 最长优先：左端点相同时取最长匹配（一个值是另一个值前缀的场景）
    this.literals.sort((a, b) => b.text.length - a.text.length);
    this.generic = opts.generic ?? true;
    this.keepLen = Math.max(1024, ...this.literals.map((l) => l.text.length));
  }

  get count(): number {
    return this.replacements;
  }

  /**
   * 查看尚未 emit 的尾部缓冲（明文！）。
   * 仅供 Launcher/Session 内部做哨兵检测；严禁把返回值交给 Tool 层。
   */
  peekTail(): string {
    return this.buf;
  }

  push(chunk: string): string {
    if (this.poisoned) {
      throw new RedactorError("redactor is in failed state; refusing further input (fail-closed)");
    }
    try {
      if (typeof chunk !== "string") {
        throw new TypeError(`redactor expects string chunks, got ${typeof chunk}`);
      }
      this.buf += chunk;
      return this.process(false);
    } catch (e) {
      this.poisoned = true;
      if (e instanceof RedactorError) throw e;
      throw new RedactorError(`redactor failed: ${(e as Error).message}`, { cause: e });
    }
  }

  flush(): string {
    if (this.poisoned) {
      throw new RedactorError("redactor is in failed state; refusing flush (fail-closed)");
    }
    try {
      const out = this.process(true);
      this.buf = "";
      return out;
    } catch (e) {
      this.poisoned = true;
      if (e instanceof RedactorError) throw e;
      throw new RedactorError(`redactor failed: ${(e as Error).message}`, { cause: e });
    }
  }

  /**
   * 处理缓冲：emit 覆盖输入区间 [0, limit)。
   * 非 final 时 limit = buf.length - keepLen：任何起点在 limit 之前的匹配，
   * 其全长必在缓冲内（keepLen ≥ 最长模式），不存在"部分匹配被提前 emit"的窗口。
   */
  private process(final: boolean): string {
    const buf = this.buf;
    let limit = final ? buf.length : Math.max(0, buf.length - this.keepLen);
    if (!final && this.generic) {
      const begin = PEM_BEGIN.exec(buf);
      if (begin) {
        PEM_BLOCK.lastIndex = 0;
        const block = PEM_BLOCK.exec(buf);
        if (!block || block.index > begin.index) {
          limit = Math.min(limit, begin.index);
        }
      }
    }
    let out = "";
    let cursor = 0;
    for (;;) {
      const m = this.findLeftmost(cursor, limit);
      if (!m) break;
      out += buf.slice(cursor, m.s) + maskFor(m.label);
      this.replacements++;
      cursor = m.e;
    }
    out += buf.slice(cursor, limit);
    this.buf = buf.slice(limit);
    return out;
  }

  private findLeftmost(cursor: number, limit: number): Match | null {
    let best: Match | null = null;
    const consider = (s: number, e: number, label: string): void => {
      if (s < 0 || s >= limit || e <= s) return;
      if (!best || s < best.s || (s === best.s && e > best.e)) best = { s, e, label };
    };
    for (const lit of this.literals) {
      const s = this.buf.indexOf(lit.text, cursor);
      consider(s, s + lit.text.length, lit.label);
    }
    if (this.generic) {
      for (const g of GENERIC_PATTERNS) {
        g.re.lastIndex = cursor;
        const m = g.re.exec(this.buf);
        if (m) consider(m.index, m.index + m[0].length, g.label);
      }
    }
    return best;
  }
}

/** 一次性脱敏（命令回显、审计字段等） */
export function redactText(
  secrets: Iterable<[string, string]>,
  text: string,
  opts: RedactorOptions = {},
): { text: string; count: number } {
  const r = new StreamRedactor(secrets, opts);
  const out = r.push(text) + r.flush();
  return { text: out, count: r.count };
}
