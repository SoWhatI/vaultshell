import { mkdtempSync, readFileSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildContext, type ServerContext } from "../src/context.js";
import { startWebServer, type WebServerHandle } from "../src/web/server.js";
import { shellExec } from "../src/launcher.js";

const SECRET_VALUE = "web-ui-secret-Zx9Qw8";
const MASTER_KEY = "0123456789abcdef".repeat(4);

describe("Web 配置界面（W1+W2）", () => {
  let home: string;
  let ctx: ServerContext;
  let web: WebServerHandle;
  let base: string;
  let token: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "vaultshell-web-"));
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
        "",
      ].join("\n"),
    );
    writeFileSync(
      join(home, "rules.yaml"),
      ["version: 1", "secrets:", "  - name: WEB_SECRET", "rules:", "  - id: r1", '    match: { cwd: ["**"] }', "    inject: [WEB_SECRET]", ""].join("\n"),
    );
    ctx = buildContext(home);
  });

  afterEach(async () => {
    await web?.close();
    ctx?.sessions.dispose();
    ctx?.proxies.dispose();
    delete process.env.VAULTSHELL_HOME;
    delete process.env.MASTER_KEY;
    rmSync(home, { recursive: true, force: true });
  });

  async function start(): Promise<void> {
    web = await startWebServer(ctx);
    base = `http://127.0.0.1:${web.port}`;
    token = web.token;
  }

  const api = (method: string, path: string, opts: { token?: string | null; body?: unknown; origin?: string; contentType?: string } = {}) => {
    const headers: Record<string, string> = {};
    if (opts.token !== null) headers.authorization = `Bearer ${opts.token ?? token}`;
    if (opts.body !== undefined) headers["content-type"] = opts.contentType ?? "application/json";
    if (opts.origin) headers.origin = opts.origin;
    return fetch(base + path, {
      method,
      headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  };

  // ---- token / CSRF --------------------------------------------------------

  it("token 校验：缺失/错误 → 401，正确 → 200", async () => {
    await start();
    expect((await api("GET", "/api/secrets", { token: null })).status).toBe(401);
    expect((await api("GET", "/api/secrets", { token: "wrong" })).status).toBe(401);
    expect((await api("GET", "/api/secrets")).status).toBe(200);
    // query token 也可用（页面首次载入）
    expect((await fetch(`${base}/api/secrets?token=${token}`)).status).toBe(200);
  });

  it("CSRF：mutation 带跨站 Origin → 403；无 Origin + Bearer（非浏览器）→ 放行；同源 → 放行", async () => {
    await start();
    const body = { value: "x" };
    expect((await api("PUT", "/api/secrets/CSRF_TEST", { body, origin: "https://evil.example" })).status).toBe(403);
    expect((await api("PUT", "/api/secrets/CSRF_TEST", { body })).status).toBe(200);
    expect((await api("PUT", "/api/secrets/CSRF_TEST2", { body, origin: `http://127.0.0.1:${web.port}` })).status).toBe(200);
  });

  it("mutation 必须 application/json（防简单跨站表单）", async () => {
    await start();
    const res = await api("PUT", "/api/secrets/CT_TEST", { body: { value: "x" }, contentType: "text/plain" });
    expect(res.status).toBe(415);
  });

  it("Host 头校验（DNS rebinding）", async () => {
    await start();
    // undici(fetch) 不允许覆盖 Host，用裸 http.request 模拟恶意 Host
    const { request } = await import("node:http");
    const status = await new Promise<number>((resolveReq, rejectReq) => {
      const r = request(
        { host: "127.0.0.1", port: web.port, path: `/api/secrets?token=${token}`, headers: { host: "evil.example" } },
        (res) => resolveReq(res.statusCode ?? 0),
      );
      r.on("error", rejectReq);
      r.end();
    });
    expect(status).toBe(403);
  });

  it("静态页面可匿名访问且带 CSP，API 404 不泄露信息", async () => {
    await start();
    const page = await fetch(`${base}/`);
    expect(page.status).toBe(200);
    expect(page.headers.get("content-security-policy")).toContain("default-src 'self'");
    const js = await fetch(`${base}/app.js`);
    expect(js.status).toBe(200);
    expect((await api("GET", "/api/nope")).status).toBe(404);
  });

  // ---- secrets -------------------------------------------------------------

  it("secret_set 落盘且响应无值；secrets 列表无明文", async () => {
    await start();
    const put = await api("PUT", "/api/secrets/WEB_SECRET", { body: { value: SECRET_VALUE } });
    expect(put.status).toBe(200);
    const putJson = await put.json();
    expect(JSON.stringify(putJson)).not.toContain(SECRET_VALUE);
    expect(putJson).toEqual({ name: "WEB_SECRET", ok: true });

    // 值真的落了盘（经 resolver 可读）
    expect(await ctx.resolvers.getValue({ name: "WEB_SECRET" })).toBe(SECRET_VALUE);

    const list = await (await api("GET", "/api/secrets")).json();
    expect(JSON.stringify(list)).not.toContain(SECRET_VALUE);
    expect(list.secrets[0].name).toBe("WEB_SECRET");
    expect(list.secrets[0].resolvable).toBe(true);

    const probeRes = await (await api("POST", "/api/secrets/WEB_SECRET/probe")).json();
    expect(probeRes.ok).toBe(true);
    expect(probeRes.masked).toBe("****");
    expect(JSON.stringify(probeRes)).not.toContain(SECRET_VALUE);
  });

  it("secret 名非法字符拒绝", async () => {
    await start();
    const res = await api("PUT", "/api/secrets/bad%2Fname", { body: { value: "x" } });
    expect(res.status).toBe(400);
  });

  // ---- rules / config 保存 --------------------------------------------------

  it("PUT /api/rules：合法保存 + findings 返回；坏 schema 拒绝且原文件不动", async () => {
    await start();
    const before = readFileSync(join(home, "rules.yaml"), "utf8");

    const good = await api("PUT", "/api/rules", {
      body: { rules: [{ id: "r2", match: { cwd: ["~/x/**"] }, inject: ["WEB_SECRET"] }] },
    });
    expect(good.status).toBe(200);
    const goodJson = await good.json();
    expect(goodJson.ok).toBe(true);
    // 表单路径保留服务端 secrets 列表
    const saved = readFileSync(join(home, "rules.yaml"), "utf8");
    expect(saved).toContain("WEB_SECRET");
    expect(saved).toContain("r2");
    expect(saved).not.toContain("r1");

    // 坏 schema：inject 不是数组
    const bad = await api("PUT", "/api/rules", { body: { rules: [{ id: "x", inject: "nope" }] } });
    expect(bad.status).toBe(400);
    expect(readFileSync(join(home, "rules.yaml"), "utf8")).toBe(saved); // 原文件不动

    // 坏 YAML
    const badYaml = await api("PUT", "/api/rules", { body: { yaml: "rules: [unclosed" } });
    expect(badYaml.status).toBeOneOf([400, 500]);
    expect(readFileSync(join(home, "rules.yaml"), "utf8")).toBe(saved);
  });

  it("PUT /api/config：合法保存生效；非法值拒绝且原文件不动", async () => {
    await start();
    const before = readFileSync(join(home, "config.yaml"), "utf8");
    const cfg = (await (await api("GET", "/api/config")).json()).config;
    cfg.defaults.execTimeoutSeconds = 42;
    const good = await api("PUT", "/api/config", { body: { config: cfg } });
    expect(good.status).toBe(200);
    expect(readFileSync(join(home, "config.yaml"), "utf8")).toContain("execTimeoutSeconds: 42");

    cfg.security.dangerousCommands.extraPatterns = ["["]; // 非法正则
    const bad = await api("PUT", "/api/config", { body: { config: cfg } });
    expect(bad.status).toBe(400);
    expect((await bad.json()).error.message).toMatch(/not a valid regex/);
    expect(readFileSync(join(home, "config.yaml"), "utf8")).toContain("execTimeoutSeconds: 42");
    expect(readFileSync(join(home, "config.yaml"), "utf8")).not.toContain('"["');
    void before;
  });

  it("原子写：写完后不存在 .tmp 残留", async () => {
    await start();
    await api("PUT", "/api/rules", { body: { rules: [] } });
    const leftovers = readdirSync(home).filter((f) => f.includes(".tmp-"));
    expect(leftovers).toEqual([]);
  });

  it("POST /api/rules/evaluate：保存规则与 draft 预览", async () => {
    await start();
    const r1 = await (await api("POST", "/api/rules/evaluate", { body: { cwd: "/anywhere", command: "ls" } })).json();
    expect(r1.ruleId).toBe("r1");
    expect(r1.inject).toEqual(["WEB_SECRET"]);

    const r2 = await (await api("POST", "/api/rules/evaluate", {
      body: { cwd: "/anywhere", command: "ls", draft: { version: 1, secrets: [], rules: [] } },
    })).json();
    expect(r2.ruleId).toBeNull();
  });

  // ---- audit ---------------------------------------------------------------

  it("GET /api/audit：按日期列文件 + 倒序记录，无明文", async () => {
    await start();
    // 造一条审计记录
    await ctx.resolvers.setValue({ name: "WEB_SECRET" }, SECRET_VALUE);
    await shellExec({ command: "echo $WEB_SECRET", cwd: "/tmp" }, ctx);

    const res = await api("GET", "/api/audit?limit=10");
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.dates.length).toBeGreaterThan(0);
    const execEntry = data.entries.find((e: { event: string }) => e.event === "shell_exec");
    expect(execEntry).toBeTruthy();
    expect(execEntry.injectedNames).toEqual(["WEB_SECRET"]);
    expect(JSON.stringify(data)).not.toContain(SECRET_VALUE);

    const byDate = await (await api("GET", `/api/audit?date=${data.dates[0]}`)).json();
    expect(byDate.entries.length).toBeGreaterThan(0);

    const badDate = await api("GET", "/api/audit?date=../../etc");
    expect(badDate.status).toBe(400);
  });

  it("铁律抽查：所有端点响应整体无明文", async () => {
    await start();
    await api("PUT", "/api/secrets/WEB_SECRET", { body: { value: SECRET_VALUE } });
    await shellExec({ command: "echo $WEB_SECRET", cwd: "/tmp" }, ctx);
    const endpoints: Array<[string, string, unknown?]> = [
      ["GET", "/api/config"],
      ["GET", "/api/rules"],
      ["GET", "/api/secrets"],
      ["POST", "/api/secrets/WEB_SECRET/probe"],
      ["GET", "/api/audit"],
      ["POST", "/api/rules/evaluate", { cwd: "/tmp", command: "echo x" }],
    ];
    for (const [method, path, body] of endpoints) {
      const res = await api(method, path, { body });
      const text = await res.text();
      expect(text, `${method} ${path}`).not.toContain(SECRET_VALUE);
      expect(text, `${method} ${path}`).not.toContain(Buffer.from(SECRET_VALUE).toString("base64"));
    }
  });
});
