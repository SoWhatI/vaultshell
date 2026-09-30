import { SecretResolutionError, type ParsedRef, type Resolver } from "./types.js";

/** env://NAME：从 MCP 进程自身环境变量取（便于 CI）。只读。 */
export class EnvResolver implements Resolver {
  readonly scheme = "env";

  async get(ref: ParsedRef): Promise<string> {
    const name = ref.parts[0];
    if (!name) throw new SecretResolutionError("env ref must be env://NAME", ref.raw);
    const value = process.env[name];
    if (value === undefined) {
      throw new SecretResolutionError(`env var ${name} is not set on the MCP process`, ref.raw);
    }
    return value;
  }
}
