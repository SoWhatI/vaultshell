import { createServer, request as httpRequest, type Server } from "node:http";
import { request as httpsRequest } from "node:https";
import { randomBytes } from "node:crypto";
import type { LauncherContext } from "./launcher.js";
import type { Config } from "./config.js";

/**
 * credential proxy（M3 最小可用版）：认证注入反向代理。
 *
 * 用法：命令里用 http://127.0.0.1:<port> 替代真实 API 地址；代理把
 * secretRef 解析出的值按 headerTemplate 注入请求头转发到 upstreamHost。
 * 密钥只经内存进 upstream 请求头——不进任何返回值、日志、审计。
 *
 * 边界（文档明示）：
 * - 只支持 http:// / https:// upstream（proxy→upstream 用 Node TLS，正常校验证书）；
 *   不做 CONNECT 隧道（那会绕过 header 注入），不做 TLS 终止。
 * - client→proxy 段是 127.0.0.1 明文 HTTP：同 UID 本地进程可嗅探 loopback，
 *   与主威胁模型的 OS 层边界一致；代理 TTL 到期自动关闭收敛暴露面。
 */

type ProxyConfigEntry = Config["proxies"][number];

export interface ProxyInfo {
  proxyId: string;
  configId: string;
  port: number;
  upstreamHost: string;
  secretName: string;
  expiresAt: string;
  requestCount: number;
}

interface ProxyInstance {
  info: ProxyInfo;
  server: Server;
  timer: NodeJS.Timeout;
}

export interface ProxyStartResult {
  ok: boolean;
  proxyId?: string;
  port?: number;
  expiresAt?: string;
  upstreamHost?: string;
  error?: string;
}

/** hop-by-hop 与伪认证头不转发；模板目标头也先删后设（防调用方伪造） */
const HOP_BY_HOP = new Set([
  "host",
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "content-length",
]);

export class ProxyManager {
  private readonly instances = new Map<string, ProxyInstance>();

  constructor(private readonly ctx: LauncherContext) {}

  async start(input: { id: string; ttlSeconds?: number }): Promise<ProxyStartResult> {
    const cfg = this.ctx.config.proxies.find((p) => p.id === input.id);
    if (!cfg) {
      return { ok: false, error: `no proxies entry with id "${input.id}" in config.yaml` };
    }
    // 解析密钥（只进内存，绝不外发）
    const secretName = cfg.secretRef;
    let value: string;
    try {
      const isRef = /^[a-z][a-z0-9+.-]*:\/\//i.test(secretName) || secretName.startsWith("inline:");
      value = await this.ctx.resolvers.getValue(
        isRef ? { name: cfg.id, ref: secretName } : { name: secretName },
      );
    } catch (e) {
      this.audit("proxy_start", cfg, null, null);
      return { ok: false, error: `failed to resolve secretRef for proxy "${cfg.id}": ${(e as Error).message}` };
    }
    if (/[\r\n]/.test(value)) {
      // CRLF → header 注入风险，拒绝启动（错误信息不含值）
      this.audit("proxy_start", cfg, null, null);
      return { ok: false, error: `resolved value for proxy "${cfg.id}" contains CR/LF; refused (header injection risk)` };
    }

    const [headerName, headerValueTemplate] = splitTemplate(cfg.headerTemplate);
    const headerValue = headerValueTemplate.split("${value}").join(value);

    const server = createServer((req, res) => {
      instance.info.requestCount++;
      forward(cfg, req.headers, req, res, headerName, headerValue);
    });

    const port = await new Promise<number>((resolveListen, rejectListen) => {
      server.once("error", rejectListen);
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        if (addr && typeof addr === "object") resolveListen(addr.port);
        else rejectListen(new Error("failed to bind"));
      });
    }).catch((e: Error) => ({ ok: false as const, error: e.message }));
    if (typeof port !== "number") return port;

    const ttlSeconds = input.ttlSeconds ?? this.ctx.config.defaults.proxyTtlSeconds;
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
    const instance: ProxyInstance = {
      info: {
        proxyId: randomBytes(8).toString("hex"),
        configId: cfg.id,
        port,
        upstreamHost: cfg.upstreamHost,
        secretName,
        expiresAt: expiresAt.toISOString(),
        requestCount: 0,
      },
      server,
      timer: undefined as unknown as NodeJS.Timeout,
    };
    instance.timer = setTimeout(() => this.expire(instance.info.proxyId), ttlSeconds * 1000);
    instance.timer.unref();
    this.instances.set(instance.info.proxyId, instance);
    this.audit("proxy_start", cfg, port, expiresAt);
    return {
      ok: true,
      proxyId: instance.info.proxyId,
      port,
      expiresAt: expiresAt.toISOString(),
      upstreamHost: cfg.upstreamHost,
    };
  }

  stop(proxyId: string): { ok: boolean; error?: string } {
    const inst = this.instances.get(proxyId);
    if (!inst) return { ok: false, error: `proxy not found: ${proxyId}` };
    this.teardown(inst);
    this.audit("proxy_stop", null, inst.info.port, null, inst.info);
    return { ok: true };
  }

  list(): ProxyInfo[] {
    return [...this.instances.values()].map((i) => ({ ...i.info }));
  }

  dispose(): void {
    for (const inst of this.instances.values()) this.teardown(inst);
    this.instances.clear();
  }

  private expire(proxyId: string): void {
    const inst = this.instances.get(proxyId);
    if (!inst) return;
    this.teardown(inst);
    this.audit("proxy_expired", null, inst.info.port, null, inst.info);
  }

  private teardown(inst: ProxyInstance): void {
    clearTimeout(inst.timer);
    inst.server.close();
    this.instances.delete(inst.info.proxyId);
  }

  /** 审计只记 host / 端口 / 变量名，永不记 header 名之外的任何值 */
  private audit(
    event: "proxy_start" | "proxy_stop" | "proxy_expired",
    cfg: ProxyConfigEntry | null,
    port: number | null,
    expiresAt: Date | null,
    info?: ProxyInfo,
  ): void {
    const configId = cfg?.id ?? info?.configId ?? "";
    const upstreamHost = cfg?.upstreamHost ?? info?.upstreamHost ?? "";
    const secretName = cfg?.secretRef ?? info?.secretName ?? "";
    this.ctx.audit.write({
      ts: new Date().toISOString(),
      event,
      ruleId: null,
      cwd: "",
      command: `proxy ${configId} → ${upstreamHost} (secret: ${secretName}, port: ${port ?? "-"}, expiresAt: ${expiresAt?.toISOString() ?? "-"})`,
      injectedNames: secretName ? [secretName] : [],
      exitCode: null,
      redactedCount: 0,
    });
  }
}

function splitTemplate(template: string): [string, string] {
  const idx = template.indexOf(":");
  return [template.slice(0, idx).trim(), template.slice(idx + 1).trim()];
}

function forward(
  cfg: ProxyConfigEntry,
  incomingHeaders: Record<string, string | string[] | undefined>,
  clientReq: NodeJS.ReadableStream,
  clientRes: import("node:http").ServerResponse,
  headerName: string,
  headerValue: string,
): void {
  const upstream = new URL(cfg.upstreamHost);
  const headers: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(incomingHeaders)) {
    if (v === undefined) continue;
    const lk = k.toLowerCase();
    if (HOP_BY_HOP.has(lk)) continue;
    if (lk === headerName.toLowerCase()) continue; // 模板头先删后设
    headers[k] = v;
  }
  headers[headerName] = headerValue;

  const reqFn = upstream.protocol === "https:" ? httpsRequest : httpRequest;
  const upstreamReq = reqFn(
    {
      hostname: upstream.hostname,
      port: upstream.port || (upstream.protocol === "https:" ? 443 : 80),
      // clientReq.url 即原始请求路径（含 query）
      path: (clientReq as import("node:http").IncomingMessage).url ?? "/",
      method: (clientReq as import("node:http").IncomingMessage).method ?? "GET",
      headers,
      timeout: 30_000,
    },
    (upstreamRes) => {
      clientRes.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
      upstreamRes.pipe(clientRes);
    },
  );
  upstreamReq.on("timeout", () => {
    upstreamReq.destroy();
    if (!clientRes.headersSent) clientRes.writeHead(504);
    clientRes.end("upstream timeout");
  });
  upstreamReq.on("error", (e) => {
    // 错误信息只含网络层细节，不含密钥
    if (!clientRes.headersSent) clientRes.writeHead(502);
    clientRes.end(`upstream error: ${e.message}`);
  });
  clientReq.pipe(upstreamReq);
}
