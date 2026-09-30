/**
 * Resolver 接口：所有密钥后端的统一抽象。
 * 铁律：Resolver 只在 Launcher 内部被调用，返回的明文直接进子进程 env，
 * 永不经过 Tool 层。
 */

export interface SecretEntry {
  name: string;
  /** 引用，如 keychain://svc/account、file://path、env://NAME；缺省时走默认后端 */
  ref?: string;
}

export interface ParsedRef {
  scheme: string;
  /** scheme 之后的路径段（keychain://svc/account → ["svc","account"]） */
  parts: string[];
  raw: string;
}

export class SecretResolutionError extends Error {
  constructor(
    message: string,
    readonly ref?: string,
  ) {
    super(message);
    this.name = "SecretResolutionError";
  }
}

export function parseRef(ref: string): ParsedRef {
  const inline = ref.match(/^inline:(.*)$/s);
  if (inline) {
    return { scheme: "inline", parts: [inline[1] ?? ""], raw: ref };
  }
  const m = ref.match(/^([a-z][a-z0-9+.-]*):\/\/(.*)$/is);
  if (!m) {
    throw new SecretResolutionError(`invalid secret ref: ${JSON.stringify(ref)}`, ref);
  }
  const scheme = m[1]!.toLowerCase();
  const rest = m[2] ?? "";
  const parts = scheme === "file" ? [rest] : rest.split("/").filter((p) => p.length > 0);
  return { scheme, parts, raw: ref };
}

export interface Resolver {
  readonly scheme: string;
  get(ref: ParsedRef): Promise<string>;
  set?(ref: ParsedRef, value: string): Promise<void>;
  delete?(ref: ParsedRef): Promise<void>;
  /** 返回后端中已有的密钥名（永不含值） */
  list?(): Promise<string[]>;
}

/** 已注册 scheme → Resolver；未实现的 scheme（op/infisical/vault）留给插件注册 */
export class ResolverRegistry {
  private readonly byScheme = new Map<string, Resolver>();

  constructor(readonly defaultResolver: Resolver) {
    this.register(defaultResolver);
  }

  register(resolver: Resolver): void {
    this.byScheme.set(resolver.scheme, resolver);
  }

  has(scheme: string): boolean {
    return this.byScheme.has(scheme);
  }

  refFor(entry: SecretEntry): ParsedRef {
    if (entry.ref) return parseRef(entry.ref);
    // 无 ref：走默认后端。keychain 需要 service/account 两段，service 固定为 vaultshell。
    const parts =
      this.defaultResolver.scheme === "keychain" ? ["vaultshell", entry.name] : [entry.name];
    return { scheme: this.defaultResolver.scheme, parts, raw: entry.name };
  }

  resolverFor(scheme: string): Resolver {
    const r = this.byScheme.get(scheme);
    if (!r) {
      throw new SecretResolutionError(
        `unknown secret ref scheme "${scheme}://". ` +
          `Implemented: encfile, keychain (macOS), env, file, inline (disabled by default), ` +
          `op, vault, infisical, doppler (via CLI). See docs/backends.md.`,
      );
    }
    return r;
  }

  async getValue(entry: SecretEntry): Promise<string> {
    const ref = this.refFor(entry);
    return this.resolverFor(ref.scheme).get(ref);
  }

  async setValue(entry: SecretEntry, value: string): Promise<void> {
    const ref = this.refFor(entry);
    const r = this.resolverFor(ref.scheme);
    if (!r.set) {
      throw new SecretResolutionError(`backend "${ref.scheme}" is read-only`, ref.raw);
    }
    await r.set(ref, value);
  }

  async deleteValue(entry: SecretEntry): Promise<void> {
    const ref = this.refFor(entry);
    const r = this.resolverFor(ref.scheme);
    if (!r.delete) {
      throw new SecretResolutionError(`backend "${ref.scheme}" does not support delete`, ref.raw);
    }
    await r.delete(ref);
  }
}

export function expandTilde(p: string): string {
  const home = process.env.HOME ?? "";
  if (p === "~") return home;
  if (p.startsWith("~/")) return home + p.slice(1);
  return p;
}
