import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as yamlParse, stringify as yamlStringify } from "yaml";
import {
  loadConfig,
  loadRules,
  validateConfigData,
  validateRulesData,
  writeConfigFile,
  writeRulesFile,
} from "../config.js";
import { matchRules } from "../policy.js";
import { validateRules } from "../validate.js";
import { secretDelete, secretSet } from "../tools.js";
import { SecretResolutionError } from "../resolver/types.js";
import type { ServerContext } from "../context.js";

/**
 * Web 配置界面（设计文档 docs/web-config-ui-design.md 的 W1+W2 实现）。
 *
 * 安全模型：
 * - 只绑 127.0.0.1；一次性随机 token（query 首次载入后转 Bearer header）。
 * - CSRF：mutation 必须 Content-Type: application/json + Origin/Referer 同源
 *   （存在时校验，缺失视为非浏览器客户端放行——它们带 Bearer 才能进来）。
 * - Host 头校验（DNS rebinding）。
 * - 铁律延伸：没有任何端点返回密钥明文；secret_set 只写不回显。
 * - 写回 YAML：zod 校验不过不落盘；原子写（tmp + rename）；注释不保留（文档注明）。
 */

export interface WebServerHandle {
  port: number;
  token: string;
  url: string;
  close: () => Promise<void>;
}

const WEB_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "web");
const MAX_BODY = 1024 * 1024;

interface Route {
  method: string;
  /** path 正则，捕获组为路径参数 */
  pattern: RegExp;
  handler: (req: IncomingMessage, res: ServerResponse, params: string[], query: URLSearchParams) => Promise<void>;
}

export async function startWebServer(
  ctx: ServerContext,
  opts: { port?: number } = {},
): Promise<WebServerHandle> {
  const token = randomBytes(24).toString("base64url");

  const json = (res: ServerResponse, status: number, payload: unknown): void => {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
      "content-type": "application/json; charset=utf-8",
      "content-security-policy": "default-src 'none'",
    });
    res.end(body);
  };
  const fail = (res: ServerResponse, status: number, code: string, message: string): void => {
    json(res, status, { error: { code, message } });
  };
  const readBody = async (req: IncomingMessage): Promise<unknown> => {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > MAX_BODY) throw new Error("request body too large");
      chunks.push(chunk as Buffer);
    }
    const text = Buffer.concat(chunks).toString("utf8");
    return text ? JSON.parse(text) : {};
  };

  const probe = async (name: string): Promise<{ ok: boolean; masked?: string; error?: string }> => {
    const { secrets } = ctx.loadRules();
    const entry = secrets.find((s) => s.name === name) ?? { name };
    try {
      const value = await ctx.resolvers.getValue(entry);
      const tail = ctx.config.defaults.maskTail;
      return { ok: true, masked: tail > 0 ? `****${value.slice(-tail)}` : "****" };
    } catch (e) {
      return { ok: false, error: e instanceof SecretResolutionError ? e.message : (e as Error).message };
    }
  };

  const routes: Route[] = [
    {
      method: "GET",
      pattern: /^\/api\/config$/,
      handler: async (_req, res) => {
        const config = loadConfig(ctx.home);
        const path = join(ctx.home, "config.yaml");
        let yaml: string | null = null;
        try {
          yaml = readFileSync(path, "utf8");
        } catch {
          // 文件不存在（全默认）
        }
        json(res, 200, { config, yaml });
      },
    },
    {
      method: "PUT",
      pattern: /^\/api\/config$/,
      handler: async (req, res) => {
        const body = (await readBody(req)) as { config?: unknown; yaml?: string };
        const raw = body.yaml !== undefined ? yamlParse(body.yaml) : body.config;
        let validated;
        try {
          validated = validateConfigData(raw);
        } catch (e) {
          return fail(res, 400, "invalid_config", (e as Error).message);
        }
        writeConfigFile(validated, ctx.home);
        ctx.config = validated; // web 进程内的后续请求用新配置
        json(res, 200, { ok: true });
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/rules$/,
      handler: async (_req, res) => {
        const rulesFile = ctx.loadRules();
        const path = join(ctx.home, "rules.yaml");
        let yaml: string | null = null;
        try {
          yaml = readFileSync(path, "utf8");
        } catch {
          // 不存在
        }
        json(res, 200, { ...rulesFile, findings: validateRules(rulesFile), yaml });
      },
    },
    {
      // 只替换 rules 数组；secrets 列表由 /api/secrets 端点管理，避免旧快照误删
      method: "PUT",
      pattern: /^\/api\/rules$/,
      handler: async (req, res) => {
        const body = (await readBody(req)) as { rules?: unknown; yaml?: string };
        const current = ctx.loadRules();
        const raw = body.yaml !== undefined ? yamlParse(body.yaml) : { version: 1, secrets: current.secrets, rules: body.rules };
        let validated;
        try {
          validated = validateRulesData(raw);
        } catch (e) {
          return fail(res, 400, "invalid_rules", (e as Error).message);
        }
        if (body.yaml === undefined) {
          // 表单路径：强制保留服务端 secrets，防旧快照覆盖
          validated.secrets = current.secrets;
        }
        writeRulesFile(validated, ctx.home);
        json(res, 200, { ok: true, findings: validateRules(validated) });
      },
    },
    {
      method: "POST",
      pattern: /^\/api\/rules\/evaluate$/,
      handler: async (req, res) => {
        const body = (await readBody(req)) as {
          cwd?: string;
          command?: string;
          profile?: string;
          draft?: unknown;
        };
        let rulesFile;
        if (body.draft !== undefined) {
          try {
            rulesFile = validateRulesData(body.draft);
          } catch (e) {
            return fail(res, 400, "invalid_rules", (e as Error).message);
          }
        } else {
          rulesFile = ctx.loadRules();
        }
        const m = matchRules(rulesFile.rules, {
          cwd: body.cwd ?? process.cwd(),
          command: body.command ?? "",
          profile: body.profile,
        });
        json(res, 200, { ruleId: m.rule?.id ?? null, inject: m.inject, matchedIds: m.matchedIds });
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/secrets$/,
      handler: async (_req, res) => {
        const { secrets } = ctx.loadRules();
        const items = await Promise.all(
          secrets.map(async (s) => ({
            name: s.name,
            ref: s.ref ?? `(default backend: ${ctx.defaultBackend.scheme})`,
            resolvable: (await probe(s.name)).ok,
          })),
        );
        json(res, 200, { secrets: items });
      },
    },
    {
      method: "PUT",
      pattern: /^\/api\/secrets\/([^/]+)$/,
      handler: async (req, res, params) => {
        const name = decodeURIComponent(params[0]!);
        if (!/^[\w.-]+$/.test(name)) return fail(res, 400, "invalid_name", "secret name must be [\\w.-]+");
        const body = (await readBody(req)) as { value?: unknown; ref?: unknown };
        if (typeof body.value !== "string" || body.value.length === 0) {
          return fail(res, 400, "invalid_value", "value must be a non-empty string");
        }
        try {
          // 只写不回显：响应永不含 value
          const result = await secretSet(ctx, {
            name,
            value: body.value,
            ...(typeof body.ref === "string" && body.ref ? { ref: body.ref } : {}),
          });
          json(res, 200, result);
        } catch (e) {
          fail(res, 400, "set_failed", (e as Error).message);
        }
      },
    },
    {
      method: "DELETE",
      pattern: /^\/api\/secrets\/([^/]+)$/,
      handler: async (_req, res, params) => {
        const name = decodeURIComponent(params[0]!);
        try {
          json(res, 200, await secretDelete(ctx, { name }));
        } catch (e) {
          fail(res, 400, "delete_failed", (e as Error).message);
        }
      },
    },
    {
      method: "POST",
      pattern: /^\/api\/secrets\/([^/]+)\/probe$/,
      handler: async (_req, res, params) => {
        const name = decodeURIComponent(params[0]!);
        const r = await probe(name);
        json(res, 200, { name, ...r });
      },
    },
    {
      method: "GET",
      pattern: /^\/api\/audit$/,
      handler: async (_req, res, _params, query) => {
        const limit = Math.min(parseInt(query.get("limit") ?? "50", 10) || 50, 500);
        const date = query.get("date") ?? undefined;
        if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) {
          return fail(res, 400, "invalid_date", "date must be YYYY-MM-DD");
        }
        json(res, 200, { entries: ctx.audit.query(limit, date), dates: ctx.audit.dates() });
      },
    },
  ];

  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const host = (req.headers.host ?? "").split(":")[0];

      // DNS rebinding：Host 必须是 loopback
      if (host !== "127.0.0.1" && host !== "localhost" && host !== "[::1]") {
        return fail(res, 403, "bad_host", "loopback Host header required");
      }

      // 静态资源（不含任何敏感数据，token 经 URL query 进入页面后转 sessionStorage）
      if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
        return serveStatic(res, "index.html", "text/html; charset=utf-8");
      }
      if (req.method === "GET" && url.pathname === "/app.js") {
        return serveStatic(res, "app.js", "text/javascript; charset=utf-8");
      }

      // API：token 校验
      const auth = req.headers.authorization;
      const presented =
        (auth?.startsWith("Bearer ") ? auth.slice(7) : null) ?? url.searchParams.get("token");
      if (presented !== token) {
        return fail(res, 401, "unauthorized", "missing or invalid token");
      }

      const route = routes.find((r) => r.method === req.method && r.pattern.test(url.pathname));
      if (!route) return fail(res, 404, "not_found", `${req.method} ${url.pathname}`);

      // CSRF 纵深：带 body 的 mutation 必须 application/json + Origin/Referer（存在时）同源。
      // 无 body 的 POST（如 probe）由 Bearer token 兜底，不强要 Content-Type。
      if (req.method !== "GET") {
        const hasBody = Number(req.headers["content-length"] ?? 0) > 0 || "transfer-encoding" in req.headers;
        const ct = req.headers["content-type"] ?? "";
        if (hasBody && !ct.startsWith("application/json")) {
          return fail(res, 415, "bad_content_type", "mutations with a body require Content-Type: application/json");
        }
        const origin = (req.headers.origin ?? "") || (req.headers.referer ?? "");
        if (origin) {
          let originHost: string;
          try {
            originHost = new URL(origin).hostname;
          } catch {
            return fail(res, 403, "bad_origin", "unparseable Origin/Referer");
          }
          if (originHost !== "127.0.0.1" && originHost !== "localhost") {
            return fail(res, 403, "bad_origin", "cross-origin mutations rejected");
          }
        }
      }

      const m = route.pattern.exec(url.pathname)!;
      await route.handler(req, res, m.slice(1), url.searchParams);
    })().catch((e) => {
      if (!res.headersSent) {
        fail(res, 500, "internal", (e as Error).message);
      } else {
        res.end();
      }
    });
  });

  const port = await new Promise<number>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(opts.port ?? 0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") resolveListen(addr.port);
      else rejectListen(new Error("failed to bind"));
    });
  });

  return {
    port,
    token,
    url: `http://127.0.0.1:${port}/?token=${token}`,
    close: () => new Promise((r) => server.close(() => r())),
  };
}

function serveStatic(res: ServerResponse, file: string, contentType: string): void {
  let body: string;
  try {
    body = readFileSync(join(WEB_ROOT, file), "utf8");
  } catch {
    res.writeHead(500, { "content-type": "text/plain" });
    res.end(`static asset missing: web/${file} (incomplete install?)`);
    return;
  }
  res.writeHead(200, {
    "content-type": contentType,
    // 无第三方 JS、无 CDN；样式内联在 index.html（style-src 放宽仅限样式）
    "content-security-policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
  });
  res.end(body);
}
