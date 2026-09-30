import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildContext, type ServerContext } from "../src/context.js";

const SECRET_VALUE = "proxy-secret-token-AbC123xyz";
const MASTER_KEY = "0123456789abcdef".repeat(4);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function httpGet(port: number, path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolvePromise, reject) => {
    fetch(`http://127.0.0.1:${port}${path}`, { headers })
      .then(async (res) => resolvePromise({ status: res.status, body: await res.text() }))
      .catch(reject);
  });
}

describe("credential proxy（M3 最小版）", () => {
  let home: string;
  let ctx: ServerContext;
  let upstream: Server;
  let upstreamPort: number;
  let lastAuth: string | null;
  let lastPath: string | null;

  beforeEach(async () => {
    lastAuth = null;
    lastPath = null;
    // 本地 upstream：记录 Authorization，回显固定 JSON（不回显 header）
    upstream = createServer((req, res) => {
      lastAuth = (req.headers.authorization as string) ?? null;
      lastPath = req.url ?? null;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    upstreamPort = await new Promise<number>((r) => {
      upstream.listen(0, "127.0.0.1", () => r((upstream.address() as AddressInfo).port));
    });

    home = mkdtempSync(join(tmpdir(), "vaultshell-home-"));
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
        "proxies:",
        "  - id: test-api",
        `    upstreamHost: http://127.0.0.1:${upstreamPort}`,
        "    secretRef: API_TOKEN",
        "    headerTemplate: 'Authorization: Bearer ${value}'",
        "",
      ].join("\n"),
    );
    ctx = buildContext(home);
    await ctx.resolvers.setValue({ name: "API_TOKEN" }, SECRET_VALUE);
  });

  afterEach(() => {
    ctx?.proxies.dispose();
    ctx?.sessions.dispose();
    upstream.close();
    delete process.env.VAULTSHELL_HOME;
    delete process.env.MASTER_KEY;
    rmSync(home, { recursive: true, force: true });
  });

  it("start → 请求转发并注入 header → upstream 收到密钥 → 响应原样返回且无泄露", async () => {
    const started = await ctx.proxies.start({ id: "test-api" });
    expect(started.ok).toBe(true);
    expect(started.port).toBeGreaterThan(0);
    // 返回值里不含明文
    expect(JSON.stringify(started)).not.toContain(SECRET_VALUE);

    const res = await httpGet(started.port!, "/v1/charges?amount=100");
    expect(res.status).toBe(200);
    // upstream 收到了注入的 header
    expect(lastAuth).toBe(`Bearer ${SECRET_VALUE}`);
    expect(lastPath).toBe("/v1/charges?amount=100");
    // 响应来自 upstream，不含明文
    expect(res.body).toContain('"ok":true');
    expect(res.body).not.toContain(SECRET_VALUE);

    // list 只含元数据
    const list = ctx.proxies.list();
    expect(list).toHaveLength(1);
    expect(list[0]!.requestCount).toBe(1);
    expect(list[0]!.secretName).toBe("API_TOKEN");
    expect(JSON.stringify(list)).not.toContain(SECRET_VALUE);

    // 审计：proxy_start 只记 host 与变量名
    const entries = ctx.audit.query(10);
    expect(entries.map((e) => e.event)).toContain("proxy_start");
    expect(JSON.stringify(entries)).not.toContain(SECRET_VALUE);
    expect(JSON.stringify(entries)).not.toContain("Bearer");
  });

  it("stop 后端口关闭", async () => {
    const started = await ctx.proxies.start({ id: "test-api" });
    expect(ctx.proxies.stop(started.proxyId!).ok).toBe(true);
    await expect(httpGet(started.port!, "/")).rejects.toThrow();
    expect(ctx.audit.query(10).map((e) => e.event)).toContain("proxy_stop");
  });

  it("TTL 到期自动关闭", async () => {
    const started = await ctx.proxies.start({ id: "test-api", ttlSeconds: 1 });
    expect(ctx.proxies.list()).toHaveLength(1);
    await sleep(1300);
    expect(ctx.proxies.list()).toHaveLength(0);
    await expect(httpGet(started.port!, "/")).rejects.toThrow();
    expect(ctx.audit.query(10).map((e) => e.event)).toContain("proxy_expired");
  });

  it("未知 proxies id 报错", async () => {
    const r = await ctx.proxies.start({ id: "nope" });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no proxies entry/);
  });

  it("secretRef 解析失败时不启动且错误不含值", async () => {
    // 删secret 再起
    await ctx.resolvers.deleteValue({ name: "API_TOKEN" });
    const r = await ctx.proxies.start({ id: "test-api" });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/failed to resolve secretRef/);
    expect(JSON.stringify(r)).not.toContain(SECRET_VALUE);
  });

  it("headerTemplate 缺 ${value} 在配置加载期报错", async () => {
    writeFileSync(
      join(home, "config.yaml"),
      [
        "version: 1",
        "proxies:",
        "  - id: bad",
        "    upstreamHost: http://127.0.0.1:1",
        "    secretRef: X",
        "    headerTemplate: 'Authorization: Bearer static'",
        "",
      ].join("\n"),
    );
    expect(() => buildContext(home)).toThrow(/\$\{value\}/);
  });

  it("upstreamHost 只允许 http(s)://host 形式", async () => {
    writeFileSync(
      join(home, "config.yaml"),
      [
        "version: 1",
        "proxies:",
        "  - id: bad",
        "    upstreamHost: http://127.0.0.1:1/some/path",
        "    secretRef: X",
        "    headerTemplate: 'Authorization: Bearer ${value}'",
        "",
      ].join("\n"),
    );
    expect(() => buildContext(home)).toThrow(/upstreamHost/);
  });
});
