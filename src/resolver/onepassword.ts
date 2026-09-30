import { SecretResolutionError, type ParsedRef } from "./types.js";
import { CliResolver, type CliSpawn } from "./cli.js";

/** op://vault/item/field → `op read op://vault/item/field` */
export class OnePasswordResolver extends CliResolver {
  readonly scheme = "op";
  protected readonly writeDocsUrl = "https://developer.1password.com/docs/cli/secret-references/";

  constructor(spawn?: CliSpawn) {
    super(spawn);
  }

  async get(ref: ParsedRef): Promise<string> {
    if (ref.parts.length < 3) {
      throw new SecretResolutionError(`op ref must be op://vault/item/field, got ${ref.raw}`, ref.raw);
    }
    try {
      return await this.run("op", ["read", ref.raw], ref);
    } catch (e) {
      if (e instanceof SecretResolutionError && /not found in PATH/.test(e.message)) {
        throw new SecretResolutionError(
          `1Password CLI "op" not found in PATH. Install: https://developer.1password.com/docs/cli/get-started/`,
          ref.raw,
        );
      }
      throw e;
    }
  }
}
