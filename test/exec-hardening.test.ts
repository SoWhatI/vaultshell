import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildContext, type ServerContext } from "../src/context.js";
import { shellExec } from "../src/launcher.js";

const SECRET_VALUE = "hardening-secret-QwErTy99";
const MASTER_KEY = "0123456789abcdef".repeat(4);

describe("shell_exec 加固（M3）", () => {
  let home: string;
  let workDir: string;
  let ctx: ServerContext;

  async function setup(extraConfig: string[] = []): Promise<void> {
    home = mkdtempSync(join(tmpdir(), "vaultshell-home-"));
    workDir = mkdtempSync(join(tmpdir(), "vaultshell-work-"));
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
        "  envPassthrough: [PATH, HOME]",
        "  execTimeoutSeconds: 10",
        ...extraConfig,
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(home, "rules.yaml"),
      [
        "version: 1",
        "secrets:",
        "  - name: MY_SECRET",
        "rules:",
        "  - id: hard-rule",
        `    match: { cwd: ["${workDir}/**"] }`,
        "    inject: [MY_SECRET]",
        "",
      ].join("\n"),
    );
    ctx = buildContext(home);
    await ctx.resolvers.setValue({ name: "MY_SECRET" }, SECRET_VALUE);
  }

  afterEach(() => {
    ctx?.sessions.dispose();
    delete process.env.VAULTSHELL_HOME;
    delete process.env.MASTER_KEY;
    rmSync(home, { recursive: true, force: true });
    rmSync(workDir, { recursive: true, force: true });
  });

  it("dryRun：报告 ruleId/injected/envKeys/deny 判定，不执行命令、不含值", async () => {
    await setup();
    const r = await shellExec(
      { command: "echo $MY_SECRET > /tmp/vaultshell-should-not-exist", cwd: workDir, dryRun: true },
      ctx,
    );
    expect(r.ok).toBe(true);
    expect(r.dryRun).toBe(true);
    expect(r.ruleId).toBe("hard-rule");
    expect(r.injected).toEqual(["MY_SECRET"]);
    expect(r.envKeys).toContain("MY_SECRET");
    expect(r.envKeys).toContain("PATH");
    expect(r.denied).toBeNull();
    expect(r.exitCode).toBeNull();
    // 响应整体不含明文
    expect(JSON.stringify(r)).not.toContain(SECRET_VALUE);
    // 审计有 dryRun 标记
    const last = ctx.audit.query(5).at(-1)!;
    expect(last.dryRun).toBe(true);
  });

  it("dryRun：危险命令在 block 模式下也只报告不失败", async () => {
    await setup();
    const r = await shellExec({ command: "env", cwd: workDir, dryRun: true }, ctx);
    expect(r.ok).toBe(true);
    expect(r.dryRun).toBe(true);
    expect(r.denied).toMatch(/env.*blocked/);
  });

  it("timeoutSeconds：超时 kill 并返回 timedOut: true + 审计标记", async () => {
    await setup();
    const r = await shellExec({ command: "sleep 5", cwd: workDir, timeoutSeconds: 1 }, ctx);
    expect(r.ok).toBe(false);
    expect(r.timedOut).toBe(true);
    expect(r.error).toMatch(/timed out after 1s/);
    const last = ctx.audit.query(5).at(-1)!;
    expect(last.timedOut).toBe(true);
  });

  it("timeoutSeconds 上限 3600（超出被 clamp）", async () => {
    await setup();
    // clamp 行为：传 99999 不报错，按 3600 执行（用快命令验证不炸即可）
    const r = await shellExec({ command: "echo ok", cwd: workDir, timeoutSeconds: 99999 }, ctx);
    expect(r.ok).toBe(true);
    expect(r.stdout).toBe("ok\n");
  });

  it("maxOutputBytes：超出截断并标注 truncated，截断不绕过脱敏", async () => {
    await setup(["  maxOutputBytes: 4096"]);
    const r = await shellExec(
      { command: `printf '=%.0s' {1..8000}; echo; echo $MY_SECRET`, cwd: workDir },
      ctx,
    );
    expect(r.truncated).toBe(true);
    expect(r.stdout).toContain("[output truncated at 4096 bytes]");
    expect(JSON.stringify(r)).not.toContain(SECRET_VALUE);
    const last = ctx.audit.query(5).at(-1)!;
    expect(last.truncated).toBe(true);
  });

  it("maxConcurrentExecs：超限直接拒绝（不排队）", async () => {
    await setup(["  maxConcurrentExecs: 1"]);
    // 占住唯一的槽位
    ctx.execSlots.active = 1;
    const r = await shellExec({ command: "echo hi", cwd: workDir }, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/too many concurrent executions \(1\/1\)/);
    // 槽位释放后恢复
    ctx.execSlots.active = 0;
    const ok = await shellExec({ command: "echo hi", cwd: workDir }, ctx);
    expect(ok.ok).toBe(true);
  });

  it("并发槽位在命令结束后正确释放", async () => {
    await setup(["  maxConcurrentExecs: 5"]);
    const results = await Promise.all([
      shellExec({ command: "echo a", cwd: workDir }, ctx),
      shellExec({ command: "echo b", cwd: workDir }, ctx),
      shellExec({ command: "echo c", cwd: workDir }, ctx),
    ]);
    expect(results.every((r) => r.ok)).toBe(true);
    expect(ctx.execSlots.active).toBe(0);
  });
});
