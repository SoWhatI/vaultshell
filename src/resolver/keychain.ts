import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { SecretResolutionError, type ParsedRef, type Resolver } from "./types.js";

const execFileAsync = promisify(execFile);

export interface KeychainOptions {
  /** 测试可注入；默认 process.platform */
  platform?: NodeJS.Platform;
}

/**
 * local-keychain 后端（ref: keychain://service/account）。
 * macOS：直接 spawn security(1)，避免 keytar 之类的原生依赖。
 * Linux/Windows：M1 不实现，给出清晰报错（libsecret / Credential Manager 留给后续）。
 */
export class KeychainResolver implements Resolver {
  readonly scheme = "keychain";
  private readonly platform: NodeJS.Platform;

  constructor(opts: KeychainOptions = {}) {
    this.platform = opts.platform ?? process.platform;
  }

  private guard(): void {
    if (this.platform !== "darwin") {
      throw new SecretResolutionError(
        `local-keychain backend is only implemented on macOS (M1); ` +
          `platform "${this.platform}" is not supported yet.`,
      );
    }
  }

  private parse(ref: ParsedRef): { service: string; account: string } {
    const [service, account] = ref.parts;
    if (!service || !account) {
      throw new SecretResolutionError(`keychain ref must be keychain://service/account, got ${ref.raw}`, ref.raw);
    }
    return { service, account };
  }

  async get(ref: ParsedRef): Promise<string> {
    this.guard();
    const { service, account } = this.parse(ref);
    try {
      const { stdout } = await execFileAsync("security", [
        "find-generic-password", "-s", service, "-a", account, "-w",
      ]);
      return stdout.replace(/\n$/, "");
    } catch {
      throw new SecretResolutionError(
        `keychain item not found (service=${service} account=${account})`, ref.raw,
      );
    }
  }

  async set(ref: ParsedRef, value: string): Promise<void> {
    this.guard();
    const { service, account } = this.parse(ref);
    await execFileAsync("security", [
      "add-generic-password", "-s", service, "-a", account, "-w", value, "-U",
    ]);
  }

  async delete(ref: ParsedRef): Promise<void> {
    this.guard();
    const { service, account } = this.parse(ref);
    try {
      await execFileAsync("security", ["delete-generic-password", "-s", service, "-a", account]);
    } catch {
      throw new SecretResolutionError(
        `keychain item not found (service=${service} account=${account})`, ref.raw,
      );
    }
  }
}
