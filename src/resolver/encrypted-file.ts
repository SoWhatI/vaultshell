import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { expandTilde, SecretResolutionError, type ParsedRef, type Resolver } from "./types.js";

const execFileAsync = promisify(execFile);

const KEYCHAIN_SERVICE = "vaultshell";
const KEYCHAIN_ACCOUNT = "encfile-master-key";

interface EncryptedRecord {
  iv: string; // base64
  tag: string; // base64
  data: string; // base64
}

interface StoreFile {
  version: 1;
  secrets: Record<string, EncryptedRecord>;
}

export interface EncryptedFileOptions {
  path: string;
  /** "env:MASTER_KEY" | "keychain" */
  keySource: string;
  /** 测试可注入；默认 process.platform */
  platform?: NodeJS.Platform;
}

/**
 * encrypted-file 后端：AES-256-GCM，每条记录独立随机 IV。
 * 主密钥来源：env:VAR（hex/base64 的 32 字节）或 macOS keychain。
 * 存储文件权限必须 ≤0600，否则拒绝读写。
 */
export class EncryptedFileResolver implements Resolver {
  readonly scheme = "encfile";
  private readonly path: string;
  private readonly keySource: string;
  private readonly platform: NodeJS.Platform;
  private masterKey: Buffer | null = null;

  constructor(opts: EncryptedFileOptions) {
    this.path = expandTilde(opts.path);
    this.keySource = opts.keySource;
    this.platform = opts.platform ?? process.platform;
  }

  get filePath(): string {
    return this.path;
  }

  private async getMasterKey(): Promise<Buffer> {
    if (this.masterKey) return this.masterKey;
    if (this.keySource.startsWith("env:")) {
      const varName = this.keySource.slice(4);
      const raw = process.env[varName];
      if (!raw) {
        throw new SecretResolutionError(
          `master key env var ${varName} is not set (keySource: ${this.keySource})`,
        );
      }
      this.masterKey = decodeKey(raw, varName);
      return this.masterKey;
    }
    if (this.keySource === "keychain") {
      if (this.platform !== "darwin") {
        throw new SecretResolutionError(
          `keychain master-key source is only implemented on macOS; ` +
            `platform "${this.platform}" is not supported yet. Use keySource: env:MASTER_KEY instead.`,
        );
      }
      this.masterKey = await keychainMasterKey();
      return this.masterKey;
    }
    throw new SecretResolutionError(
      `unsupported keySource: ${this.keySource} (supported: env:MASTER_KEY, keychain)`,
    );
  }

  private checkPermissions(): void {
    if (!existsSync(this.path)) return;
    const mode = statSync(this.path).mode & 0o777;
    if (mode & 0o077) {
      throw new SecretResolutionError(
        `refusing to read ${this.path}: permissions ${mode.toString(8)} are too open (must be 0600 or stricter)`,
      );
    }
  }

  private load(): StoreFile {
    if (!existsSync(this.path)) return { version: 1, secrets: {} };
    this.checkPermissions();
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(this.path, "utf8"));
    } catch (e) {
      throw new SecretResolutionError(`failed to parse ${this.path}: ${(e as Error).message}`);
    }
    const store = parsed as StoreFile;
    if (store.version !== 1 || typeof store.secrets !== "object" || store.secrets === null) {
      throw new SecretResolutionError(`unsupported store format in ${this.path}`);
    }
    return store;
  }

  private save(store: StoreFile): void {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    writeFileSync(this.path, JSON.stringify(store, null, 2), { mode: 0o600 });
    chmodSync(this.path, 0o600);
  }

  async get(ref: ParsedRef): Promise<string> {
    const name = requireName(ref);
    const key = await this.getMasterKey();
    const rec = this.load().secrets[name];
    if (!rec) throw new SecretResolutionError(`secret "${name}" not found in encrypted file`, ref.raw);
    try {
      const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(rec.iv, "base64"));
      decipher.setAuthTag(Buffer.from(rec.tag, "base64"));
      return Buffer.concat([decipher.update(Buffer.from(rec.data, "base64")), decipher.final()]).toString("utf8");
    } catch {
      throw new SecretResolutionError(`failed to decrypt "${name}" (wrong master key or corrupted store)`, ref.raw);
    }
  }

  async set(ref: ParsedRef, value: string): Promise<void> {
    const name = requireName(ref);
    const key = await this.getMasterKey();
    const store = this.load();
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", key, iv);
    const data = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    store.secrets[name] = {
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      data: data.toString("base64"),
    };
    this.save(store);
  }

  async delete(ref: ParsedRef): Promise<void> {
    const name = requireName(ref);
    const store = this.load();
    if (!(name in store.secrets)) {
      throw new SecretResolutionError(`secret "${name}" not found in encrypted file`, ref.raw);
    }
    delete store.secrets[name];
    this.save(store);
  }

  async list(): Promise<string[]> {
    return Object.keys(this.load().secrets).sort();
  }
}

function requireName(ref: ParsedRef): string {
  const name = ref.parts[0];
  if (!name) throw new SecretResolutionError(`encfile ref needs a name: encfile://NAME`, ref.raw);
  return name;
}

function decodeKey(raw: string, varName: string): Buffer {
  const trimmed = raw.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, "hex");
  const b64 = Buffer.from(trimmed, "base64");
  if (b64.length === 32) return b64;
  throw new SecretResolutionError(
    `master key in ${varName} must be 32 bytes (64 hex chars or base64), got ${b64.length} bytes`,
  );
}

/** macOS keychain 中的主密钥：不存在则生成 32 字节随机密钥并写入 */
async function keychainMasterKey(): Promise<Buffer> {
  const args = ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w"];
  try {
    const { stdout } = await execFileAsync("security", args);
    const key = Buffer.from(stdout.trim(), "base64");
    if (key.length === 32) return key;
  } catch {
    // not found → generate below
  }
  const key = randomBytes(32);
  await execFileAsync("security", [
    "add-generic-password",
    "-s", KEYCHAIN_SERVICE,
    "-a", KEYCHAIN_ACCOUNT,
    "-w", key.toString("base64"),
    "-U",
  ]);
  return key;
}
