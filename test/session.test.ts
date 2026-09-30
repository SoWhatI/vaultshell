import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildContext, type ServerContext } from "../src/context.js";
import { defaultPtyLoader } from "../src/session.js";

const SECRET_VALUE = "session-secret-XyZ789+/=_q3";
const MASTER_KEY = "0123456789abcdef".repeat(4);

let ptyAvailable = false;

beforeAll(async () => {
  ptyAvailable = (await defaultPtyLoader()) !== null;
});

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("持久会话（M2）", () => {
  let home: string;
  let workDir: string;
  let ctx: ServerContext;

  async function setup(ptyLoader?: () => Promise<never>): Promise<void> {
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
        "  envPassthrough: [PATH, HOME, LANG, TERM]",
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
        "rules:",
        "  - id: sess-rule",
        `    match: { cwd: ["${workDir}/**"] }`,
        "    inject: [MY_SECRET]",
        "",
      ].join("\n"),
    );
    ctx = ptyLoader ? buildContext(home, ptyLoader) : buildContext(home);
    await ctx.resolvers.setValue({ name: "MY_SECRET" }, SECRET_VALUE);
  }

  afterEach(() => {
    ctx?.sessions.dispose();
    delete process.env.VAULTSHELL_HOME;
    delete process.env.MASTER_KEY;
    rmSync(home, { recursive: true, force: true });
    rmSync(workDir, { recursive: true, force: true });
  });

  it("open → send 注入生效且输出脱敏 → close 后不可用", async () => {
    await setup();
    const opened = await ctx.sessions.open({ cwd: workDir });
    expect(opened.ok).toBe(true);
    expect(opened.sessionId).toBeTruthy();
    expect(opened.injected).toEqual(["MY_SECRET"]);
    if (ptyAvailable) expect(opened.pty).toBe(true);
    expect(opened.ttlSeconds).toBe(900);

    const r = await ctx.sessions.send(opened.sessionId!, "echo $MY_SECRET");
    expect(r.ok).toBe(true);
    expect(r.exitCode).toBe(0);
    expect(r.output).toContain("[REDACTED:MY_SECRET]");
    expect(r.output).not.toContain(SECRET_VALUE);

    // session_list 只含元数据
    const list = ctx.sessions.list();
    expect(list).toHaveLength(1);
    expect(list[0]!.sessionId).toBe(opened.sessionId);
    expect(JSON.stringify(list)).not.toContain(SECRET_VALUE);

    expect(ctx.sessions.close(opened.sessionId!).ok).toBe(true);
    const after = await ctx.sessions.send(opened.sessionId!, "echo hi");
    expect(after.ok).toBe(false);
    expect(after.error).toMatch(/not found or expired/);
  });

  it("审计记录会话事件且含 sessionId、无明文", async () => {
    await setup();
    const opened = await ctx.sessions.open({ cwd: workDir });
    await ctx.sessions.send(opened.sessionId!, "echo $MY_SECRET");
    ctx.sessions.close(opened.sessionId!);
    const entries = ctx.audit.query(20);
    const events = entries.map((e) => e.event);
    expect(events).toContain("session_open");
    expect(events).toContain("session_send");
    expect(events).toContain("session_close");
    for (const e of entries) {
      expect(e.sessionId).toBe(opened.sessionId);
    }
    expect(JSON.stringify(entries)).not.toContain(SECRET_VALUE);
  });

  it("revoke：kill 后重建无密钥会话，旧密钥不再可用", async () => {
    await setup();
    const opened = await ctx.sessions.open({ cwd: workDir });
    const before = await ctx.sessions.send(opened.sessionId!, "echo $MY_SECRET");
    expect(before.output).toContain("[REDACTED:MY_SECRET]");

    const revoked = await ctx.sessions.revoke(opened.sessionId!);
    expect(revoked.ok).toBe(true);
    expect(revoked.sessionId).not.toBe(opened.sessionId);
    expect(revoked.injected).toEqual([]);

    // 旧会话已死
    const old = await ctx.sessions.send(opened.sessionId!, "echo x");
    expect(old.ok).toBe(false);

    // 新会话无密钥
    const after = await ctx.sessions.send(revoked.sessionId!, 'echo "[$MY_SECRET]"');
    expect(after.ok).toBe(true);
    expect(after.output).toContain("[]");
    expect(after.output).not.toContain(SECRET_VALUE);

    const events = ctx.audit.query(20).map((e) => e.event);
    expect(events).toContain("session_revoke");
  });

  it("TTL 空闲回收：到期会话被 kill", async () => {
    await setup();
    const opened = await ctx.sessions.open({ cwd: workDir, ttlSeconds: 1 });
    expect(opened.ttlSeconds).toBe(1);
    await sleep(1400);
    expect(ctx.sessions.list()).toHaveLength(0);
    const r = await ctx.sessions.send(opened.sessionId!, "echo hi");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/expired/);
    expect(ctx.audit.query(20).map((e) => e.event)).toContain("session_expired");
  });

  it("降级路径：node-pty 加载失败时 pty:false 且功能可用、仍脱敏", async () => {
    await setup(async () => null);
    const opened = await ctx.sessions.open({ cwd: workDir });
    expect(opened.ok).toBe(true);
    expect(opened.pty).toBe(false);
    const r = await ctx.sessions.send(opened.sessionId!, "echo $MY_SECRET");
    expect(r.exitCode).toBe(0);
    expect(r.output).toContain("[REDACTED:MY_SECRET]");
    expect(r.output).not.toContain(SECRET_VALUE);
  });

  it("会话内 cd 状态跨 send 持久", async () => {
    await setup();
    mkdirSync(join(workDir, "subdir"), { recursive: true });
    const opened = await ctx.sessions.open({ cwd: workDir });
    await ctx.sessions.send(opened.sessionId!, "cd subdir");
    const r = await ctx.sessions.send(opened.sessionId!, "pwd");
    expect(r.output).toContain(join(workDir, "subdir"));
  });

  it("会话内危险命令同样被 deny-list 拦截", async () => {
    await setup();
    const opened = await ctx.sessions.open({ cwd: workDir });
    for (const cmd of ["env", "printenv", "cat /proc/self/environ"]) {
      const r = await ctx.sessions.send(opened.sessionId!, cmd);
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/blocked by deny-list/);
      expect(r.output).not.toContain(SECRET_VALUE);
    }
  });

  it("会话输出 exitCode 透传非零", async () => {
    await setup();
    const opened = await ctx.sessions.open({ cwd: workDir });
    const r = await ctx.sessions.send(opened.sessionId!, "false");
    expect(r.exitCode).toBe(1);
  });
});
