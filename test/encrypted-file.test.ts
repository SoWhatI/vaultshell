import { chmodSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { EncryptedFileResolver } from "../src/resolver/encrypted-file.js";
import { SecretResolutionError } from "../src/resolver/types.js";

const KEY_A = "a".repeat(64);
const KEY_B = "b".repeat(64);

describe("encrypted-file 后端", () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "vaultshell-encfile-"));
    file = join(dir, "secrets.enc");
    process.env.MASTER_KEY = KEY_A;
  });

  afterEach(() => {
    delete process.env.MASTER_KEY;
    rmSync(dir, { recursive: true, force: true });
  });

  const make = () => new EncryptedFileResolver({ path: file, keySource: "env:MASTER_KEY" });
  const ref = (name: string) => ({ scheme: "encfile", parts: [name], raw: name });

  it("set/get/delete/list 往返", async () => {
    const r = make();
    await r.set(ref("API_KEY"), "super-secret-value-123");
    expect(await r.get(ref("API_KEY"))).toBe("super-secret-value-123");
    await r.set(ref("OTHER"), "x".repeat(500));
    expect(await r.get(ref("OTHER"))).toBe("x".repeat(500));
    expect(await r.list!()).toEqual(["API_KEY", "OTHER"]);
    await r.delete!(ref("API_KEY"));
    await expect(r.get(ref("API_KEY"))).rejects.toThrow(SecretResolutionError);
    expect(await r.list!()).toEqual(["OTHER"]);
  });

  it("覆盖写同一名字（更新）", async () => {
    const r = make();
    await r.set(ref("K"), "v1");
    await r.set(ref("K"), "v2");
    expect(await r.get(ref("K"))).toBe("v2");
  });

  it("存储文件权限必须是 0600；被放宽后拒绝读", async () => {
    const r = make();
    await r.set(ref("K"), "v");
    chmodSync(file, 0o644);
    await expect(r.get(ref("K"))).rejects.toThrow(/permissions/);
    await expect(r.list!()).rejects.toThrow(/permissions/);
  });

  it("错误主密钥解密失败", async () => {
    await make().set(ref("K"), "v");
    process.env.MASTER_KEY = KEY_B;
    await expect(make().get(ref("K"))).rejects.toThrow(/decrypt|master key/i);
  });

  it("MASTER_KEY 缺失 / 长度非法给出清晰报错", async () => {
    delete process.env.MASTER_KEY;
    await expect(make().get(ref("K"))).rejects.toThrow(/MASTER_KEY is not set/);
    process.env.MASTER_KEY = "tooshort";
    await expect(make().get(ref("K"))).rejects.toThrow(/32 bytes/);
  });

  it("base64 形式的 32 字节主密钥也可用", async () => {
    process.env.MASTER_KEY = Buffer.alloc(32, 7).toString("base64");
    const r = make();
    await r.set(ref("K"), "v");
    expect(await r.get(ref("K"))).toBe("v");
  });

  it("keychain 主密钥源在非 macOS 上给出清晰报错", async () => {
    const r = new EncryptedFileResolver({ path: file, keySource: "keychain", platform: "linux" });
    await expect(r.get(ref("K"))).rejects.toThrow(/only implemented on macOS/);
  });

  it("不支持的 keySource 报错", async () => {
    const r = new EncryptedFileResolver({ path: file, keySource: "passphrase" });
    await expect(r.get(ref("K"))).rejects.toThrow(/unsupported keySource/);
  });
});
