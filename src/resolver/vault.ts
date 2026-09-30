import { SecretResolutionError, type ParsedRef } from "./types.js";
import { CliResolver, type CliSpawn } from "./cli.js";

/**
 * vault://path/to/secret#field → `vault kv get -field=<field> -format=json <path>`
 * （-format=json 与 -field 组合时 vault 直接输出该字段的纯文本值）。
 * 认证走 vault CLI 自己的环境（VAULT_ADDR / VAULT_TOKEN 或 ~/.vault-token），vaultshell 不接管。
 * ref 不带 #field 时默认 field=value。
 */
export class VaultResolver extends CliResolver {
  readonly scheme = "vault";
  protected readonly writeDocsUrl = "https://developer.hashicorp.com/vault/docs/commands";

  constructor(spawn?: CliSpawn) {
    super(spawn);
  }

  async get(ref: ParsedRef): Promise<string> {
    const rest = ref.raw.slice("vault://".length);
    const hashIdx = rest.indexOf("#");
    const path = (hashIdx >= 0 ? rest.slice(0, hashIdx) : rest).replace(/\/+$/, "");
    const field = hashIdx >= 0 ? rest.slice(hashIdx + 1) : "value";
    if (!path || !field) {
      throw new SecretResolutionError(`vault ref must be vault://path/to/secret#field, got ${ref.raw}`, ref.raw);
    }
    try {
      return await this.run("vault", ["kv", "get", `-field=${field}`, "-format=json", path], ref);
    } catch (e) {
      if (e instanceof SecretResolutionError && /not found in PATH/.test(e.message)) {
        throw new SecretResolutionError(
          `Vault CLI "vault" not found in PATH. Install: https://developer.hashicorp.com/vault/install ` +
            `(auth via VAULT_ADDR/VAULT_TOKEN or \`vault login\`)`,
          ref.raw,
        );
      }
      throw e;
    }
  }
}
