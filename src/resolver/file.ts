import { readFileSync, statSync } from "node:fs";
import { expandTilde, SecretResolutionError, type ParsedRef, type Resolver } from "./types.js";

/** file://path：读文件首行；权限必须 ≤0600 否则拒绝。只读。 */
export class FileResolver implements Resolver {
  readonly scheme = "file";

  async get(ref: ParsedRef): Promise<string> {
    const rawPath = ref.parts[0];
    if (!rawPath) throw new SecretResolutionError("file ref must be file://path", ref.raw);
    const path = expandTilde(rawPath);
    let mode: number;
    try {
      mode = statSync(path).mode & 0o777;
    } catch {
      throw new SecretResolutionError(`secret file not found: ${path}`, ref.raw);
    }
    if (mode & 0o077) {
      throw new SecretResolutionError(
        `refusing to read ${path}: permissions ${mode.toString(8)} are too open (must be 0600 or stricter)`,
        ref.raw,
      );
    }
    const content = readFileSync(path, "utf8");
    const firstLine = content.split(/\r?\n/, 1)[0] ?? "";
    if (firstLine.length === 0) {
      throw new SecretResolutionError(`secret file is empty: ${path}`, ref.raw);
    }
    return firstLine;
  }
}
