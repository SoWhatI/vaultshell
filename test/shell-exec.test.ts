import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildContext, type ServerContext } from "../src/context.js";
import { shellExec } from "../src/launcher.js";

const SECRET_VALUE = "integration-secret-AbC123+/=_x9";
const MASTER_KEY = "0123456789abcdef".repeat(4); // 64 hex = 32 bytes

describe("shell_exec 端到端（encrypted-file + 假 MASTER_KEY）", () => {
  let home: string;
  let workDir: string;
  let missFailDir: string;
  let missWarnDir: string;
  let ctx: ServerContext;

  beforeEach(async () => {
    home = mkdtempSync(join(tmpdir(), "vaultshell-home-"));
    workDir = mkdtempSync(join(tmpdir(), "vaultshell-work-"));
    missFailDir = mkdtempSync(join(tmpdir(), "vaultshell-missfail-"));
    missWarnDir = mkdtempSync(join(tmpdir(), "vaultshell-misswarn-"));
    process.env.VAULTSHELL_HOME = home;
    process.env.MASTER_KEY = MASTER_KEY;

    writeFileSync(
      join(home, "config.yaml"),
      [
        "version: 1",
        "storage:",
        "  backend: encrypted-file",
        "  encryptedFile:",
        `    path: ${join(home, "secrets.enc")}`,
        "    keySource: env:MASTER_KEY",
        "defaults:",
        "  envPassthrough: [PATH, HOME, LANG]",
        "  execTimeoutSeconds: 10",
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(home, "rules.yaml"),
      [
        "version: 1",
        "secrets:",
        "  - name: MY_SECRET",
        "  - name: WARN_MISSING",
        "    ref: encfile://DOES_NOT_EXIST",
        "rules:",
        "  - id: work-rule",
        `    match: { cwd: ["${workDir}/**"] }`,
        "    inject: [MY_SECRET]",
        "  - id: miss-fail-rule",
        `    match: { cwd: ["${missFailDir}/**"] }`,
        "    inject: [WARN_MISSING]",
        "    onMiss: fail",
        "  - id: miss-warn-rule",
        `    match: { cwd: ["${missWarnDir}/**"] }`,
        "    inject: [WARN_MISSING]",
        "    onMiss: warn",
        "",
      ].join("\n"),
    );

    ctx = buildContext(home);
    // 直接经 Resolver 写入（绕过 Tool 层，等价于 secret_set 的落盘部分）
    await ctx.resolvers.setValue({ name: "MY_SECRET" }, SECRET_VALUE);
  });

  afterEach(() => {
    delete process.env.VAULTSHELL_HOME;
    delete process.env.MASTER_KEY;
    rmSync(home, { recursive: true, force: true });
    rmSync(workDir, { recursive: true, force: true });
    rmSync(missFailDir, { recursive: true, force: true });
    rmSync(missWarnDir, { recursive: true, force: true });
  });

  it("注入 → 执行 → 输出无明文：echo $MY_SECRET 返回 [REDACTED:MY_SECRET]", async () => {
    const r = await shellExec({ command: "echo $MY_SECRET", cwd: workDir }, ctx);
    expect(r.ok).toBe(true);
    expect(r.exitCode).toBe(0);
    expect(r.stdout).toBe("[REDACTED:MY_SECRET]\n");
    expect(r.stdout).not.toContain(SECRET_VALUE);
    expect(r.injected).toEqual(["MY_SECRET"]);
    expect(r.ruleId).toBe("work-rule");
    expect(r.redactedCount).toBe(1);
  });

  it("输出 Base64 变体同样被脱敏", async () => {
    const r = await shellExec({ command: 'printf %s "$MY_SECRET" | base64', cwd: workDir }, ctx);
    expect(r.stdout).toContain("[REDACTED:MY_SECRET]");
    expect(r.stdout).not.toContain(SECRET_VALUE);
    expect(r.stdout).not.toContain(Buffer.from(SECRET_VALUE).toString("base64"));
  });

  it("stderr 也脱敏", async () => {
    const r = await shellExec({ command: "echo $MY_SECRET 1>&2", cwd: workDir }, ctx);
    expect(r.stderr).toBe("[REDACTED:MY_SECRET]\n");
    expect(r.stderr).not.toContain(SECRET_VALUE);
  });

  it("未命中规则的目录不注入", async () => {
    const outside = mkdtempSync(join(tmpdir(), "vaultshell-outside-"));
    try {
      const r = await shellExec({ command: 'echo "[$MY_SECRET]"', cwd: outside }, ctx);
      expect(r.injected).toEqual([]);
      expect(r.ruleId).toBeNull();
      expect(r.stdout).toBe("[]\n");
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });

  it("onMiss: fail → 解析失败即拒绝执行", async () => {
    
    const r = await shellExec({ command: "echo should-not-run", cwd: missFailDir }, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/failed to resolve secret "WARN_MISSING"/);
    expect(r.stdout).toBe("");
  });

  it("onMiss: warn → 跳过该密钥、带告警继续执行", async () => {
    
    const r = await shellExec({ command: "echo ran", cwd: missWarnDir }, ctx);
    expect(r.ok).toBe(true);
    expect(r.stdout).toBe("ran\n");
    expect(r.warnings.some((w) => w.includes("WARN_MISSING"))).toBe(true);
    expect(r.injected).toEqual([]);
  });

  it("危险命令被 hard-block（env / printenv / cat /proc/self/environ）", async () => {
    for (const command of ["env", "printenv", "cat /proc/self/environ", "export -p"]) {
      const r = await shellExec({ command, cwd: workDir }, ctx);
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/blocked by deny-list/);
      expect(r.stdout).not.toContain(SECRET_VALUE);
    }
  });

  it("extraEnv 只允许白名单普通变量", async () => {
    const okRes = await shellExec(
      { command: "echo $DRY_RUN", cwd: workDir, extraEnv: { DRY_RUN: "1" } },
      ctx,
    );
    expect(okRes.stdout).toBe("1\n");

    const bad = await shellExec(
      { command: "echo hi", cwd: workDir, extraEnv: { EVIL: "x" } },
      ctx,
    );
    expect(bad.ok).toBe(false);
    expect(bad.error).toMatch(/extraEnvAllowlist/);
  });

  it("审计 JSONL：含 ruleId/injectedNames/exitCode，且无明文", async () => {
    await shellExec({ command: "echo $MY_SECRET", cwd: workDir }, ctx);
    const auditDir = join(home, "audit");
    const files = readdirSync(auditDir).filter((f) => f.endsWith(".jsonl"));
    expect(files.length).toBe(1);
    const raw = readFileSync(join(auditDir, files[0]!), "utf8");
    expect(raw).not.toContain(SECRET_VALUE);
    expect(raw).not.toContain(Buffer.from(SECRET_VALUE).toString("base64"));
    const entry = JSON.parse(raw.trim().split("\n")[0]!);
    expect(entry.event).toBe("shell_exec");
    expect(entry.ruleId).toBe("work-rule");
    expect(entry.injectedNames).toEqual(["MY_SECRET"]);
    expect(entry.exitCode).toBe(0);
    expect(entry.redactedCount).toBe(1);
  });

  it("命令里手误写入明文时，审计中的 command 也已脱敏", async () => {
    const r = await shellExec({ command: `echo ${SECRET_VALUE}`, cwd: workDir }, ctx);
    expect(r.stdout).toBe("[REDACTED:MY_SECRET]\n");
    const entries = ctx.audit.query(10);
    const last = entries[entries.length - 1]!;
    expect(last.command).toBe("echo [REDACTED:MY_SECRET]");
    expect(last.command).not.toContain(SECRET_VALUE);
  });

  it("命令退出码透传", async () => {
    const r = await shellExec({ command: "exit 3", cwd: workDir }, ctx);
    expect(r.exitCode).toBe(3);
    expect(r.ok).toBe(false);
  });

  it("命令本身失败时输出仍脱敏", async () => {
    const r = await shellExec({ command: "echo $MY_SECRET; exit 1", cwd: workDir }, ctx);
    expect(r.exitCode).toBe(1);
    expect(r.stdout).toBe("[REDACTED:MY_SECRET]\n");
  });
});
