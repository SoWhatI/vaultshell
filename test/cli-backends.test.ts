import { describe, expect, it } from "vitest";
import { OnePasswordResolver } from "../src/resolver/onepassword.js";
import { VaultResolver } from "../src/resolver/vault.js";
import { InfisicalResolver } from "../src/resolver/infisical.js";
import { DopplerResolver } from "../src/resolver/doppler.js";
import { parseRef, SecretResolutionError } from "../src/resolver/types.js";
import type { CliSpawn } from "../src/resolver/cli.js";

/** 记录调用参数并返回预设结果的 mock spawner */
function mockSpawn(handler: (cmd: string, args: string[]) => { stdout: string } | Error): {
  spawn: CliSpawn;
  calls: Array<{ cmd: string; args: string[] }>;
} {
  const calls: Array<{ cmd: string; args: string[] }> = [];
  const spawn: CliSpawn = async (cmd, args) => {
    calls.push({ cmd, args });
    const r = handler(cmd, args);
    if (r instanceof Error) throw r;
    return { stdout: r.stdout, stderr: "" };
  };
  return { spawn, calls };
}

describe("onepassword 后端（op CLI）", () => {
  it("op://vault/item/field → op read 原样引用，stdout 去尾换行", async () => {
    const { spawn, calls } = mockSpawn(() => ({ stdout: "s3cret-value\n" }));
    const r = new OnePasswordResolver(spawn);
    const value = await r.get(parseRef("op://Personal/stripe/key"));
    expect(value).toBe("s3cret-value");
    expect(calls).toEqual([{ cmd: "op", args: ["read", "op://Personal/stripe/key"] }]);
  });

  it("ref 段数不足时报错", async () => {
    const { spawn } = mockSpawn(() => ({ stdout: "x" }));
    const r = new OnePasswordResolver(spawn);
    await expect(r.get(parseRef("op://onlyvault"))).rejects.toThrow(/op:\/\/vault\/item\/field/);
  });

  it("op 不在 PATH → 指向安装文档", async () => {
    const { spawn } = mockSpawn(() => new SecretResolutionError('CLI not found in PATH: "op". Install it and authenticate first.'));
    const r = new OnePasswordResolver(spawn);
    await expect(r.get(parseRef("op://a/b/c"))).rejects.toThrow(/1Password CLI.*not found in PATH.*get-started/s);
  });

  it("写操作不支持并指向平台文档", async () => {
    const r = new OnePasswordResolver(mockSpawn(() => ({ stdout: "" })).spawn);
    await expect(r.set!(parseRef("op://a/b/c"), "v")).rejects.toThrow(/not supported.*developer\.1password\.com/s);
    await expect(r.delete!(parseRef("op://a/b/c"))).rejects.toThrow(/not supported/s);
  });
});

describe("vault 后端（vault CLI）", () => {
  it("vault://path/to/secret#field → vault kv get -field -format=json", async () => {
    const { spawn, calls } = mockSpawn(() => ({ stdout: "db-passw0rd\n" }));
    const r = new VaultResolver(spawn);
    const value = await r.get(parseRef("vault://secret/data/prod/db#password"));
    expect(value).toBe("db-passw0rd");
    expect(calls).toEqual([
      { cmd: "vault", args: ["kv", "get", "-field=password", "-format=json", "secret/data/prod/db"] },
    ]);
  });

  it("不带 #field 默认 value", async () => {
    const { spawn, calls } = mockSpawn(() => ({ stdout: "v" }));
    const r = new VaultResolver(spawn);
    await r.get(parseRef("vault://kv/myapp"));
    expect(calls[0]!.args).toContain("-field=value");
    expect(calls[0]!.args.at(-1)).toBe("kv/myapp");
  });

  it("CLI 缺失 → 报错含 VAULT_ADDR/VAULT_TOKEN 提示", async () => {
    const { spawn } = mockSpawn(() => new SecretResolutionError('CLI not found in PATH: "vault".'));
    const r = new VaultResolver(spawn);
    await expect(r.get(parseRef("vault://a#b"))).rejects.toThrow(/VAULT_ADDR\/VAULT_TOKEN/);
  });

  it("认证失败（非 ENOENT）原样透传 stderr 首行", async () => {
    const { spawn } = mockSpawn(() => new SecretResolutionError('"vault" failed: permission denied (exit 2)'));
    const r = new VaultResolver(spawn);
    await expect(r.get(parseRef("vault://a#b"))).rejects.toThrow(/permission denied/);
  });
});

describe("infisical 后端（infisical CLI）", () => {
  it("infisical://proj/env/KEY 参数构造正确", async () => {
    const { spawn, calls } = mockSpawn(() => ({ stdout: "tok_abc\n" }));
    const r = new InfisicalResolver(spawn);
    expect(await r.get(parseRef("infisical://proj-123/prod/API_KEY"))).toBe("tok_abc");
    expect(calls).toEqual([
      {
        cmd: "infisical",
        args: ["secrets", "get", "API_KEY", "--projectId=proj-123", "--env=prod", "--plain", "--silent"],
      },
    ]);
  });

  it("段数不足报错", async () => {
    const r = new InfisicalResolver(mockSpawn(() => ({ stdout: "" })).spawn);
    await expect(r.get(parseRef("infisical://proj/prod"))).rejects.toThrow(/projectId\/env\/KEY/);
  });

  it("CLI 缺失 → 报错含 INFISICAL_TOKEN 提示", async () => {
    const { spawn } = mockSpawn(() => new SecretResolutionError('CLI not found in PATH: "infisical".'));
    const r = new InfisicalResolver(spawn);
    await expect(r.get(parseRef("infisical://p/e/K"))).rejects.toThrow(/INFISICAL_TOKEN/);
  });
});

describe("doppler 后端（doppler CLI）", () => {
  it("doppler://project/config/KEY 参数构造正确", async () => {
    const { spawn, calls } = mockSpawn(() => ({ stdout: "dk_live_123\n" }));
    const r = new DopplerResolver(spawn);
    expect(await r.get(parseRef("doppler://backend/prd/STRIPE_KEY"))).toBe("dk_live_123");
    expect(calls).toEqual([
      {
        cmd: "doppler",
        args: ["secrets", "get", "STRIPE_KEY", "--project=backend", "--config=prd", "--plain"],
      },
    ]);
  });

  it("段数不足报错 + 写操作不支持", async () => {
    const { spawn } = mockSpawn(() => ({ stdout: "" }));
    const r = new DopplerResolver(spawn);
    await expect(r.get(parseRef("doppler://p/c"))).rejects.toThrow(/project\/config\/KEY/);
    await expect(r.set!(parseRef("doppler://p/c/K"), "v")).rejects.toThrow(/not supported.*docs\.doppler\.com/s);
  });

  it("CLI 缺失 → 报错含 DOPPLER_TOKEN 提示", async () => {
    const { spawn } = mockSpawn(() => new SecretResolutionError('CLI not found in PATH: "doppler".'));
    const r = new DopplerResolver(spawn);
    await expect(r.get(parseRef("doppler://p/c/K"))).rejects.toThrow(/DOPPLER_TOKEN/);
  });
});

describe("CliResolver 公共行为", () => {
  it("空输出视为解析失败", async () => {
    const r = new OnePasswordResolver(mockSpawn(() => ({ stdout: "" })).spawn);
    await expect(r.get(parseRef("op://a/b/c"))).rejects.toThrow(/empty value/);
  });
});
