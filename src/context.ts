import { join } from "node:path";
import { AuditLog } from "./audit.js";
import { loadConfig, loadRules, vaultshellHome, type Config, type RulesFile } from "./config.js";
import { EncryptedFileResolver } from "./resolver/encrypted-file.js";
import { EnvResolver } from "./resolver/env.js";
import { FileResolver } from "./resolver/file.js";
import { InlineResolver } from "./resolver/inline.js";
import { KeychainResolver } from "./resolver/keychain.js";
import { ResolverRegistry, type Resolver } from "./resolver/types.js";
import { OnePasswordResolver } from "./resolver/onepassword.js";
import { VaultResolver } from "./resolver/vault.js";
import { InfisicalResolver } from "./resolver/infisical.js";
import { DopplerResolver } from "./resolver/doppler.js";
import type { LauncherContext } from "./launcher.js";
import { SessionManager, type PtyLoader } from "./session.js";
import { ProxyManager } from "./proxy.js";

export interface ServerContext extends LauncherContext {
  config: Config;
  defaultBackend: Resolver;
  sessions: SessionManager;
  proxies: ProxyManager;
}

/**
 * 组装运行上下文。rules.yaml 每次操作重新加载（secret_set/delete 会改它），
 * config.yaml 启动时加载一次。ptyLoader 可注入（测试降级路径用）。
 */
export function buildContext(home: string = vaultshellHome(), ptyLoader?: PtyLoader): ServerContext {
  const config = loadConfig(home);
  const defaultBackend: Resolver =
    config.storage.backend === "local-keychain"
      ? new KeychainResolver()
      : new EncryptedFileResolver({
          path: config.storage.encryptedFile.path,
          keySource: config.storage.encryptedFile.keySource,
        });

  const resolvers = new ResolverRegistry(defaultBackend);
  resolvers.register(new EnvResolver());
  resolvers.register(new FileResolver());
  resolvers.register(new InlineResolver(config.defaults.allowInline));
  if (defaultBackend.scheme !== "keychain") resolvers.register(new KeychainResolver());
  // 外部 CLI 后端（M3）：spawn op/vault/infisical/doppler，CLI 缺失或认证失败时
  // 给出可操作报错；写操作不支持（指向平台文档）。
  resolvers.register(new OnePasswordResolver());
  resolvers.register(new VaultResolver());
  resolvers.register(new InfisicalResolver());
  resolvers.register(new DopplerResolver());

  const audit = new AuditLog(join(home, "audit"), config.defaults.audit);
  const ctx: ServerContext = {
    home,
    config,
    loadRules: (): RulesFile => loadRules(home),
    resolvers,
    audit,
    defaultBackend,
    execSlots: { active: 0 },
    sessions: undefined as unknown as SessionManager,
    proxies: undefined as unknown as ProxyManager,
  };
  ctx.sessions = new SessionManager(ctx, ptyLoader);
  ctx.proxies = new ProxyManager(ctx);
  return ctx;
}
