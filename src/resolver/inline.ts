import { SecretResolutionError, type ParsedRef, type Resolver } from "./types.js";

/**
 * inline:<plaintext>：默认禁用。仅当配置 defaults.allowInline: true 时可用，
 * 启用时服务启动会打印告警（见 index.ts）。
 */
export class InlineResolver implements Resolver {
  readonly scheme = "inline";

  constructor(private readonly enabled: boolean) {}

  async get(ref: ParsedRef): Promise<string> {
    if (!this.enabled) {
      throw new SecretResolutionError(
        `inline: refs are disabled by default (plaintext in config). ` +
          `Set defaults.allowInline: true in config.yaml to enable (dev only).`,
        ref.raw,
      );
    }
    return ref.parts[0] ?? "";
  }
}
