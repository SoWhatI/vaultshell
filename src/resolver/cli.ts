import { execFile } from "node:child_process";
import { SecretResolutionError, type ParsedRef, type Resolver } from "./types.js";

/**
 * 外部 CLI 后端的公共基座：spawn CLI（10s 超时），stdout 去尾换行为值。
 * 全部只读——写操作指向对应平台文档。
 * spawn 可注入（测试 mock）；真实路径用 defaultCliSpawn。
 */

export type CliSpawn = (cmd: string, args: string[]) => Promise<{ stdout: string; stderr: string }>;

export const CLI_TIMEOUT_MS = 10_000;

export const defaultCliSpawn: CliSpawn = (cmd, args) =>
  new Promise((resolvePromise, reject) => {
    execFile(cmd, args, { timeout: CLI_TIMEOUT_MS, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        const e = err as NodeJS.ErrnoException & { killed?: boolean };
        if (e.code === "ENOENT") {
          reject(new SecretResolutionError(`CLI not found in PATH: "${cmd}". Install it and authenticate first.`));
          return;
        }
        if (e.killed) {
          reject(new SecretResolutionError(`"${cmd}" timed out after ${CLI_TIMEOUT_MS / 1000}s`));
          return;
        }
        // stderr 可能含敏感信息也可能含可操作的认证提示；只透传首行
        const hint = stderr?.split("\n")[0]?.trim();
        reject(new SecretResolutionError(`"${cmd}" failed${hint ? `: ${hint}` : ""} (exit ${e.code ?? "?"})`));
        return;
      }
      resolvePromise({ stdout, stderr: stderr ?? "" });
    });
  });

export abstract class CliResolver implements Resolver {
  abstract readonly scheme: string;
  /** 写操作不支持时指向的文档 URL */
  protected abstract readonly writeDocsUrl: string;

  constructor(protected readonly spawn: CliSpawn = defaultCliSpawn) {}

  abstract get(ref: ParsedRef): Promise<string>;

  protected async run(cmd: string, args: string[], ref: ParsedRef): Promise<string> {
    const { stdout } = await this.spawn(cmd, args);
    const value = stdout.replace(/\r?\n$/, "");
    if (!value) {
      throw new SecretResolutionError(`${cmd} returned an empty value for ${ref.scheme}://…`, ref.raw);
    }
    return value;
  }

  async set(ref: ParsedRef): Promise<void> {
    throw new SecretResolutionError(
      `secret_set is not supported for ${this.scheme}:// refs; write secrets via the platform's own tooling. See ${this.writeDocsUrl}`,
      ref.raw,
    );
  }

  async delete(ref: ParsedRef): Promise<void> {
    throw new SecretResolutionError(
      `secret_delete is not supported for ${this.scheme}:// refs; manage secrets via the platform's own tooling. See ${this.writeDocsUrl}`,
      ref.raw,
    );
  }
}
