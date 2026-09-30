import { SecretResolutionError, type ParsedRef } from "./types.js";
import { CliResolver, type CliSpawn } from "./cli.js";

/**
 * infisical://projectId/env/KEY →
 * `infisical secrets get <KEY> --projectId=<projectId> --env=<env> --plain --silent`
 * 认证走 Infisical CLI 自己的环境（INFISICAL_TOKEN / 已登录会话），vaultshell 不接管。
 */
export class InfisicalResolver extends CliResolver {
  readonly scheme = "infisical";
  protected readonly writeDocsUrl = "https://infisical.com/docs/cli/overview";

  constructor(spawn?: CliSpawn) {
    super(spawn);
  }

  async get(ref: ParsedRef): Promise<string> {
    const [projectId, env, key] = ref.parts;
    if (!projectId || !env || !key) {
      throw new SecretResolutionError(
        `infisical ref must be infisical://projectId/env/KEY, got ${ref.raw}`,
        ref.raw,
      );
    }
    try {
      return await this.run(
        "infisical",
        ["secrets", "get", key, `--projectId=${projectId}`, `--env=${env}`, "--plain", "--silent"],
        ref,
      );
    } catch (e) {
      if (e instanceof SecretResolutionError && /not found in PATH/.test(e.message)) {
        throw new SecretResolutionError(
          `Infisical CLI "infisical" not found in PATH. Install: https://infisical.com/docs/cli/overview ` +
            `(auth via INFISICAL_TOKEN or \`infisical login\`)`,
          ref.raw,
        );
      }
      throw e;
    }
  }
}
