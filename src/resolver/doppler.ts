import { SecretResolutionError, type ParsedRef } from "./types.js";
import { CliResolver, type CliSpawn } from "./cli.js";

/**
 * doppler://project/config/KEY →
 * `doppler secrets get <KEY> --project=<project> --config=<config> --plain`
 * 认证走 Doppler CLI 自己的环境（DOPPLER_TOKEN 或已登录会话），vaultshell 不接管。
 */
export class DopplerResolver extends CliResolver {
  readonly scheme = "doppler";
  protected readonly writeDocsUrl = "https://docs.doppler.com/docs/cli";

  constructor(spawn?: CliSpawn) {
    super(spawn);
  }

  async get(ref: ParsedRef): Promise<string> {
    const [project, config, key] = ref.parts;
    if (!project || !config || !key) {
      throw new SecretResolutionError(
        `doppler ref must be doppler://project/config/KEY, got ${ref.raw}`,
        ref.raw,
      );
    }
    try {
      return await this.run(
        "doppler",
        ["secrets", "get", key, `--project=${project}`, `--config=${config}`, "--plain"],
        ref,
      );
    } catch (e) {
      if (e instanceof SecretResolutionError && /not found in PATH/.test(e.message)) {
        throw new SecretResolutionError(
          `Doppler CLI "doppler" not found in PATH. Install: https://docs.doppler.com/docs/installation ` +
            `(auth via DOPPLER_TOKEN or \`doppler login\`)`,
          ref.raw,
        );
      }
      throw e;
    }
  }
}
