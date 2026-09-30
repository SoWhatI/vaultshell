import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { homedir } from "node:os";
import { randomBytes } from "node:crypto";
import { parse, stringify } from "yaml";
import { z } from "zod";
import { expandTilde, type SecretEntry } from "./resolver/types.js";

/** 数据根目录：默认 ~/.vaultshell，测试可用 VAULTSHELL_HOME 覆盖 */
export function vaultshellHome(): string {
  return process.env.VAULTSHELL_HOME ?? join(homedir(), ".vaultshell");
}

const proxyEntrySchema = z.object({
  id: z.string().min(1),
  /** upstream 根地址，仅 http/https，如 https://api.stripe.com */
  upstreamHost: z.string().regex(/^https?:\/\/[^/]+$/, "upstreamHost must be http(s)://host[:port] without path"),
  /** 注册表里的 secret 名，或完整 ref（keychain://… 等） */
  secretRef: z.string().min(1),
  /** 如 "Authorization: Bearer ${value}"；必须含 ${value} 占位 */
  headerTemplate: z.string().min(1),
});

const configSchema = z.object({
  version: z.literal(1).default(1),
  storage: z
    .object({
      backend: z.enum(["local-keychain", "encrypted-file"]).default("encrypted-file"),
      encryptedFile: z
        .object({
          path: z.string().default("~/.vaultshell/secrets.enc"),
          keySource: z.string().default("env:MASTER_KEY"),
        })
        .default({ path: "~/.vaultshell/secrets.enc", keySource: "env:MASTER_KEY" }),
    })
    .default({ backend: "encrypted-file", encryptedFile: { path: "~/.vaultshell/secrets.enc", keySource: "env:MASTER_KEY" } }),
  defaults: z
    .object({
      redact: z.boolean().default(true),
      audit: z.boolean().default(true),
      envPassthrough: z
        .array(z.string())
        .default(["PATH", "HOME", "USER", "LANG", "SHELL", "TERM", "TMPDIR"]),
      /** extraEnv 允许传入的变量名白名单（仅普通变量，密钥一律走引用） */
      extraEnvAllowlist: z
        .array(z.string())
        .default(["CI", "DEBUG", "DRY_RUN", "NODE_ENV", "NO_COLOR", "FORCE_COLOR"]),
      /** inline: 明文引用，默认禁用（仅 dev） */
      allowInline: z.boolean().default(false),
      /** secret_probe 掩码是否保留值后 N 位；默认 0 = 不保留任何值片段 */
      maskTail: z.number().int().min(0).max(8).default(0),
      /** shell_exec / shell_session_send 单次命令超时（秒） */
      execTimeoutSeconds: z.number().int().positive().default(120),
      /** 持久会话空闲回收 TTL（秒）；规则级 ttlSeconds 可覆盖 */
      sessionTtlSeconds: z.number().int().positive().default(900),
      /** shell_exec 单条流输出上限（字节），超出截断并标注 truncated */
      maxOutputBytes: z.number().int().positive().default(1024 * 1024),
      /** shell_exec 最大并发数，超限直接拒绝（不排队） */
      maxConcurrentExecs: z.number().int().positive().default(8),
      /** credential proxy 默认 TTL（秒） */
      proxyTtlSeconds: z.number().int().positive().default(300),
    })
    .default({
      redact: true,
      audit: true,
      envPassthrough: ["PATH", "HOME", "USER", "LANG", "SHELL", "TERM", "TMPDIR"],
      extraEnvAllowlist: ["CI", "DEBUG", "DRY_RUN", "NODE_ENV", "NO_COLOR", "FORCE_COLOR"],
      allowInline: false,
      maskTail: 0,
      execTimeoutSeconds: 120,
      sessionTtlSeconds: 900,
      maxOutputBytes: 1024 * 1024,
      maxConcurrentExecs: 8,
      proxyTtlSeconds: 300,
    }),
  security: z
    .object({
      dangerousCommands: z
        .object({
          /** block（默认）：hard-block；warn：放行但审计记 dangerousCommand: true */
          mode: z.enum(["block", "warn"]).default("block"),
          /** 额外的危险命令正则（对整条命令匹配），如 ["^mysecretprinter\\b"] */
          extraPatterns: z.array(z.string()).default([]),
        })
        .default({ mode: "block", extraPatterns: [] }),
    })
    .default({ dangerousCommands: { mode: "block", extraPatterns: [] } }),
  /** credential proxy 定义（shell_proxy_start 引用 id） */
  proxies: z.array(proxyEntrySchema).default([]),
});

const ruleSchema = z.object({
  id: z.string().min(1),
  match: z
    .object({
      cwd: z.array(z.string()).optional(),
      command: z.array(z.string()).optional(),
      profiles: z.array(z.string()).optional(),
    })
    .default({}),
  inject: z.array(z.string()).default([]),
  ttlSeconds: z.number().int().positive().optional(),
  onMiss: z.enum(["fail", "skip", "warn"]).default("fail"),
  requireConfirm: z.boolean().default(false),
  /** override（默认）：只取第一条命中规则；union：合并所有命中规则的 inject */
  mergeStrategy: z.enum(["override", "union"]).default("override"),
});

const secretEntrySchema = z.object({
  name: z.string().min(1),
  ref: z.string().optional(),
});

const rulesFileSchema = z.object({
  version: z.literal(1).default(1),
  secrets: z.array(secretEntrySchema).default([]),
  rules: z.array(ruleSchema).default([]),
});

export type Config = z.infer<typeof configSchema>;
export type Rule = z.infer<typeof ruleSchema>;
export interface RulesFile {
  secrets: SecretEntry[];
  rules: Rule[];
}

/** 校验 config 数据（Web PUT 与 loadConfig 共用；抛 Error 带全部 issue） */
export function validateConfigData(raw: unknown): Config {
  const result = configSchema.safeParse(raw ?? {});
  if (!result.success) {
    throw new Error(result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  }
  result.data.storage.encryptedFile.path = expandTilde(result.data.storage.encryptedFile.path);
  // 校验 security.dangerousCommands.extraPatterns 是合法正则（配置错误要尽早暴露）
  for (const p of result.data.security.dangerousCommands.extraPatterns) {
    try {
      new RegExp(p);
    } catch (e) {
      throw new Error(`security.dangerousCommands.extraPatterns entry ${JSON.stringify(p)} is not a valid regex: ${(e as Error).message}`);
    }
  }
  // 校验 proxies 条目：headerTemplate 必须含 ${value} 且无 CRLF（防 header 注入）
  for (const p of result.data.proxies) {
    if (!p.headerTemplate.includes("${value}")) {
      throw new Error(`proxies entry "${p.id}" headerTemplate must contain \${value}`);
    }
    if (/[\r\n]/.test(p.headerTemplate) || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+\s*:/.test(p.headerTemplate)) {
      throw new Error(`proxies entry "${p.id}" headerTemplate must be "Header-Name: ...\${value}..."`);
    }
  }
  return result.data;
}

/** 校验 rules 数据（Web PUT 与 loadRules 共用） */
export function validateRulesData(raw: unknown): RulesFile {
  const result = rulesFileSchema.safeParse(raw ?? {});
  if (!result.success) {
    throw new Error(result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  }
  return { secrets: result.data.secrets, rules: result.data.rules };
}

export function loadConfig(home: string = vaultshellHome()): Config {
  const path = join(home, "config.yaml");
  if (!existsSync(path)) return validateConfigData({});
  try {
    return validateConfigData(parse(readFileSync(path, "utf8")));
  } catch (e) {
    throw new Error(`invalid ${path}: ${(e as Error).message}`);
  }
}

export function loadRules(home: string = vaultshellHome()): RulesFile {
  const path = join(home, "rules.yaml");
  if (!existsSync(path)) return { secrets: [], rules: [] };
  try {
    return validateRulesData(parse(readFileSync(path, "utf8")));
  } catch (e) {
    throw new Error(`invalid ${path}: ${(e as Error).message}`);
  }
}

/** 原子写：临时文件 + rename，避免半截文件；0600 权限 */
export function writeFileAtomic(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${randomBytes(6).toString("hex")}`;
  writeFileSync(tmp, content, { mode: 0o600 });
  renameSync(tmp, path);
}

/** secret_set 时把名字登记进 rules.yaml 的 secrets 列表（只存 ref，不存值） */
export function upsertSecretEntry(entry: SecretEntry, home: string = vaultshellHome()): void {
  const path = join(home, "rules.yaml");
  const current = loadRules(home);
  const idx = current.secrets.findIndex((s) => s.name === entry.name);
  if (idx >= 0) current.secrets[idx] = entry;
  else current.secrets.push(entry);
  writeRulesFile(current, home);
}

export function removeSecretEntry(name: string, home: string = vaultshellHome()): void {
  const current = loadRules(home);
  if (!current.secrets.some((s) => s.name === name)) return;
  writeRulesFile(
    { secrets: current.secrets.filter((s) => s.name !== name), rules: current.rules },
    home,
  );
}

/** 整体写回 rules.yaml（原子写；注释不保留——校验不过不落盘） */
export function writeRulesFile(data: RulesFile, home: string = vaultshellHome()): void {
  writeFileAtomic(join(home, "rules.yaml"), stringify({ version: 1, secrets: data.secrets, rules: data.rules }));
}

/** 整体写回 config.yaml（原子写；注释不保留） */
export function writeConfigFile(config: Config, home: string = vaultshellHome()): void {
  writeFileAtomic(join(home, "config.yaml"), stringify(config));
}
