import { describe, expect, it } from "vitest";
import { RedactorError, StreamRedactor, redactText } from "../src/redactor.js";

/** 确定性 PRNG，属性测试可复现 */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-%$@!.,:;#";

function randomSecret(rand: () => number, minLen = 16, maxLen = 64): string {
  const len = minLen + Math.floor(rand() * (maxLen - minLen));
  let s = "";
  for (let i = 0; i < len; i++) s += CHARSET[Math.floor(rand() * CHARSET.length)];
  return s;
}

function variantsOf(value: string): string[] {
  return [...new Set([value, encodeURIComponent(value), Buffer.from(value, "utf8").toString("base64")])];
}

function runChunked(secrets: Map<string, string>, chunks: string[]): { out: string; count: number } {
  const r = new StreamRedactor(secrets);
  let out = "";
  for (const c of chunks) out += r.push(c);
  out += r.flush();
  return { out, count: r.count };
}

describe("StreamRedactor 精确值匹配", () => {
  it("单次输出中的明文被替换为 [REDACTED:NAME]，不保留任何值片段", () => {
    const secrets = new Map([["PROD_DB_URL", "postgres://u:p@db.internal:5432/prod"]]);
    const { text, count } = redactText(secrets, "connecting to postgres://u:p@db.internal:5432/prod ... ok");
    expect(text).toBe("connecting to [REDACTED:PROD_DB_URL] ... ok");
    expect(count).toBe(1);
  });

  it("URL-encode 与 Base64 变体同样被脱敏", () => {
    const value = "p@ss w/rd+特=";
    const secrets = new Map([["PW", value]]);
    const url = encodeURIComponent(value);
    const b64 = Buffer.from(value, "utf8").toString("base64");
    expect(redactText(secrets, `curl "${url}"`).text).toBe('curl "[REDACTED:PW]"');
    expect(redactText(secrets, `token=${b64}`).text).toBe("token=[REDACTED:PW]");
  });

  it("一个值是另一个值前缀时按最长匹配", () => {
    const secrets = new Map([
      ["SHORT", "abc123"],
      ["LONG", "abc123XYZ"],
    ]);
    expect(redactText(secrets, "abc123XYZ").text).toBe("[REDACTED:LONG]");
    expect(redactText(secrets, "abc123.").text).toBe("[REDACTED:SHORT].");
  });

  it("同一输出中多个密钥各自掩码", () => {
    const secrets = new Map([
      ["A", "alpha-value-1"],
      ["B", "beta-value-2"],
    ]);
    const { text, count } = redactText(secrets, "alpha-value-1 then beta-value-2 then alpha-value-1");
    expect(text).toBe("[REDACTED:A] then [REDACTED:B] then [REDACTED:A]");
    expect(count).toBe(3);
  });

  it("空值与重复变体不会导致死循环", () => {
    const secrets = new Map([
      ["EMPTY", ""],
      ["PLAIN", "abcdef"], // url-encode 与原文相同，去重
    ]);
    expect(redactText(secrets, "abcdef").text).toBe("[REDACTED:PLAIN]");
  });
});

describe("StreamRedactor 流式跨 chunk", () => {
  it("密钥在每个可能的切分点都被完整脱敏", () => {
    const value = "super-secret-token-0123456789abcdef";
    const secrets = new Map([["TOK", value]]);
    const full = `prefix ${value} suffix`;
    for (let cut = 0; cut <= full.length; cut++) {
      const { out } = runChunked(secrets, [full.slice(0, cut), full.slice(cut)]);
      expect(out).toBe("prefix [REDACTED:TOK] suffix");
      expect(out).not.toContain(value);
    }
  });

  it("Base64 变体跨 chunk 切断也能脱敏", () => {
    const value = "chunky-secret-value/+=?";
    const b64 = Buffer.from(value, "utf8").toString("base64");
    const secrets = new Map([["V", value]]);
    for (let cut = 0; cut <= b64.length; cut++) {
      const { out } = runChunked(secrets, [b64.slice(0, cut), b64.slice(cut)]);
      expect(out).toBe("[REDACTED:V]");
    }
  });

  it("多段小 chunk 拼接后零泄露", () => {
    const value = "slice-me-into-tiny-pieces-42";
    const secrets = new Map([["S", value]]);
    const full = `>>${value}<<`;
    for (let size = 1; size <= 7; size++) {
      const chunks: string[] = [];
      for (let i = 0; i < full.length; i += size) chunks.push(full.slice(i, i + size));
      const { out } = runChunked(secrets, chunks);
      expect(out).toBe(">>[REDACTED:S]<<");
    }
  });
});

describe("StreamRedactor 通用正则", () => {
  it("sk- API key", () => {
    const { text } = redactText(new Map(), "key is sk-abcdefghijklmnopqrstuvwxyz123456 ok");
    expect(text).toBe("key is [REDACTED:sk] ok");
  });

  it("JWT", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c";
    const { text } = redactText(new Map(), `auth: ${jwt}!`);
    expect(text).toBe("auth: [REDACTED:jwt]!");
  });

  it("AWS Access Key ID", () => {
    const { text } = redactText(new Map(), "AKIAIOSFODNN7EXAMPLE was here");
    expect(text).toBe("[REDACTED:aws-ak] was here");
  });

  it("PEM 私钥块", () => {
    const pem =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7\n+b64lines==\n-----END RSA PRIVATE KEY-----";
    const { text } = redactText(new Map(), `before ${pem} after`);
    expect(text).toBe("before [REDACTED:pem] after");
  });

  it("PEM 块跨 chunk（BEGIN 到达后挂起，不提前泄漏）", () => {
    const pem =
      "-----BEGIN PRIVATE KEY-----\nABCDEFGHIJKLMNOP0123456789==\n-----END PRIVATE KEY-----";
    const full = `x${pem}y`;
    for (let cut = 0; cut <= full.length; cut++) {
      const { out } = runChunked(new Map(), [full.slice(0, cut), full.slice(cut)]);
      expect(out).toBe("x[REDACTED:pem]y");
      expect(out).not.toContain("ABCDEFGHIJKLMNOP");
    }
  });

  it("通用正则可关闭", () => {
    const { text } = redactText(new Map(), "sk-abcdefghijklmnopqrstuvwxyz123456", { generic: false });
    expect(text).toContain("sk-");
  });
});

describe("StreamRedactor fail-closed", () => {
  it("内部出错时抛 RedactorError 并永久拒绝后续输入", () => {
    const r = new StreamRedactor(new Map([["A", "secret"]]));
    expect(() => r.push(123 as unknown as string)).toThrow(RedactorError);
    expect(() => r.push("secret")).toThrow(RedactorError);
    expect(() => r.flush()).toThrow(RedactorError);
  });
});

describe("泄露属性测试（随机密钥 × 随机场景，零命中明文及变体）", () => {
  const rand = mulberry32(0x5eed);

  it("200 轮随机密钥：响应中不出现明文、URL 编码或 Base64 变体", () => {
    for (let iter = 0; iter < 200; iter++) {
      const name = `SECRET_${iter}`;
      const value = randomSecret(rand);
      const secrets = new Map([[name, value]]);
      const noiseA = randomSecret(rand, 0, 40);
      const noiseB = randomSecret(rand, 0, 40);
      const mode = iter % 4;
      let payload: string;
      if (mode === 0) payload = value;
      else if (mode === 1) payload = encodeURIComponent(value);
      else if (mode === 2) payload = Buffer.from(value, "utf8").toString("base64");
      else payload = `${value} ${encodeURIComponent(value)}`;
      const full = `${noiseA}${payload}${noiseB}`;

      // 随机切 chunk
      const chunks: string[] = [];
      let i = 0;
      while (i < full.length) {
        const step = 1 + Math.floor(rand() * 9);
        chunks.push(full.slice(i, i + step));
        i += step;
      }
      const { out, count } = runChunked(secrets, chunks);
      for (const v of variantsOf(value)) {
        expect(out).not.toContain(v);
      }
      expect(out).toContain(`[REDACTED:${name}]`);
      expect(count).toBeGreaterThan(0);
    }
  });

  it("长输出（>keepLen 多倍）中的密钥被增量替换", () => {
    const value = "long-output-secret-9876543210";
    const secrets = new Map([["L", value]]);
    const filler = "x".repeat(200_000);
    const full = `${filler}${value}${filler}${value}`;
    const chunks: string[] = [];
    for (let i = 0; i < full.length; i += 4096) chunks.push(full.slice(i, i + 4096));
    const { out, count } = runChunked(secrets, chunks);
    expect(out).not.toContain(value);
    expect(count).toBe(2);
    expect(out.length).toBeLessThan(full.length);
  });

  it("输出不含密钥时原样通过（不误伤）", () => {
    const secrets = new Map([["K", "some-secret-value"]]);
    const benign = "totally benign output, no secrets here 12345";
    const { text, count } = redactText(secrets, benign);
    expect(text).toBe(benign);
    expect(count).toBe(0);
  });
});
