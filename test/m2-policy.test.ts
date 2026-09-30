import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildContext, type ServerContext } from "../src/context.js";
import { shellExec } from "../src/launcher.js";
import { validateRules } from "../src/validate.js";
import type { RulesFile } from "../src/config.js";

const SECRET_VALUE = "confirm-secret-AbC123";
const MASTER_KEY = "0123456789abcdef".repeat(4);

function rulesYaml(extraRuleLines: string[] = []): string {
  return [
    "version: 1",
    "secrets:",
    "  - name: MY_SECRET",
    "rules:",
    ...extraRuleLines,
    "",
  ].join("\n");
}

describe("requireConfirm / deny-list warn / rule_validate（M2）", () => {
  let home: string;
  let workDir: string;
  let ctx: ServerContext;

  async function setup(opts: {
    /** 工厂函数：在 workDir 赋值之后才调用 */
    rules: () => string[];
    securityLines?: string[];
    confirm?: "accepted" | "declined" | "unsupported";
  }): Promise<void> {
    home = mkdtempSync(join(tmpdir(), "vaultshell-home-"));
    workDir = mkdtempSync(join(tmpdir(), "vaultshell-work-"));
    process.env.VAULTSHELL_HOME = home;
    process.env.MASTER_KEY = MASTER_KEY;
    writeFileSync(
      join(home, "config.yaml"),
      [
        "version: 1",
        "storage:",
        "  backend: encrypted-file",
        "  encryptedFile:",
        `    path: ${join(home, "secrets.enc")}`,
        "    keySource: env:MASTER_KEY",
        "defaults:",
        "  envPassthrough: [PATH, HOME]",
        "  execTimeoutSeconds: 10",
        ...(opts.securityLines ?? []),
        "",
      ].join("\n"),
    );
    writeFileSync(join(home, "rules.yaml"), rulesYaml(opts.rules()));
    ctx = buildContext(home);
    if (opts.confirm) ctx.confirm = async () => opts.confirm!;
    await ctx.resolvers.setValue({ name: "MY_SECRET" }, SECRET_VALUE);
  }

  afterEach(() => {
    ctx?.sessions.dispose();
    delete process.env.VAULTSHELL_HOME;
    delete process.env.MASTER_KEY;
    rmSync(home, { recursive: true, force: true });
    rmSync(workDir, { recursive: true, force: true });
  });

  function guardedRule(): string[] {
    return [
      "  - id: guarded",
      `    match: { cwd: ["${workDir}/**"] }`,
      "    inject: [MY_SECRET]",
      "    requireConfirm: true",
    ];
  }

  it("requireConfirm + elicitation 接受 → 执行并注入", async () => {
    await setup({ rules: guardedRule, confirm: "accepted" });
    const r = await shellExec({ command: "echo $MY_SECRET", cwd: workDir }, ctx);
    expect(r.ok).toBe(true);
    expect(r.stdout).toBe("[REDACTED:MY_SECRET]\n");
    expect(r.injected).toEqual(["MY_SECRET"]);
  });

  it("requireConfirm + 用户拒绝 → 不执行", async () => {
    await setup({ rules: guardedRule, confirm: "declined" });
    const r = await shellExec({ command: "echo $MY_SECRET", cwd: workDir }, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/declined/);
    expect(r.stdout).toBe("");
  });

  it("requireConfirm + 客户端不支持 elicitation → 拒绝执行并提示改配置", async () => {
    await setup({ rules: guardedRule, confirm: "unsupported" });
    const r = await shellExec({ command: "echo $MY_SECRET", cwd: workDir }, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/does not support elicitation/);
    expect(r.error).toMatch(/Remove requireConfirm/);
  });

  it("requireConfirm + 无 confirm 通道 → 拒绝执行（不静默放行）", async () => {
    await setup({ rules: guardedRule });
    const r = await shellExec({ command: "echo $MY_SECRET", cwd: workDir }, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/requireConfirm/);
  });

  it("requireConfirm 也约束 shell_session_open", async () => {
    await setup({ rules: guardedRule, confirm: "unsupported" });
    const r = await ctx.sessions.open({ cwd: workDir });
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/elicitation/);
  });

  it("deny-list warn 模式：放行但告警 + 审计 dangerousCommand: true，输出仍脱敏", async () => {
    await setup({
      rules: () => [
        "  - id: plain",
        `    match: { cwd: ["${workDir}/**"] }`,
        "    inject: [MY_SECRET]",
      ],
      securityLines: ["security:", "  dangerousCommands:", "    mode: warn"],
    });
    const r = await shellExec({ command: "printenv MY_SECRET", cwd: workDir }, ctx);
    // warn 模式放行；但输出仍过 Redactor
    expect(r.stdout).toContain("[REDACTED:MY_SECRET]");
    expect(r.stdout).not.toContain(SECRET_VALUE);
    expect(r.warnings.some((w) => w.includes("mode=warn"))).toBe(true);
    const last = ctx.audit.query(10).at(-1)!;
    expect(last.dangerousCommand).toBe(true);
    expect(last.event).toBe("shell_exec");
  });

  it("extraPatterns 追加自定义危险命令（block 模式）", async () => {
    await setup({
      rules: () => ["  - id: plain", `    match: { cwd: ["${workDir}/**"] }`, "    inject: [MY_SECRET]"],
      securityLines: ["security:", "  dangerousCommands:", "    extraPatterns:", "      - '^mysecretprinter\\b'"],
    });
    const r = await shellExec({ command: "mysecretprinter --all", cwd: workDir }, ctx);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/blocked by deny-list/);
    expect(r.error).toMatch(/extraPatterns/);
    const ok = await shellExec({ command: "echo fine", cwd: workDir }, ctx);
    expect(ok.ok).toBe(true);
  });

  it("extraPatterns 非法正则在配置加载期报错", async () => {
    home = mkdtempSync(join(tmpdir(), "vaultshell-home-"));
    process.env.VAULTSHELL_HOME = home;
    writeFileSync(
      join(home, "config.yaml"),
      ["version: 1", "security:", "  dangerousCommands:", "    extraPatterns:", '      - "["', ""].join("\n"),
    );
    expect(() => buildContext(home)).toThrow(/not a valid regex/);
  });

  it("rule_validate：各类告警与干净正例", () => {
    const dirty: RulesFile = {
      secrets: [{ name: "KNOWN" }],
      rules: [
        {
          id: "catch-all",
          match: { cwd: ["**"] },
          inject: ["KNOWN"],
          onMiss: "fail",
          requireConfirm: false,
          mergeStrategy: "override",
        },
        {
          id: "shadowed",
          match: { cwd: ["~/work/**"] },
          inject: ["GHOST"],
          onMiss: "fail",
          requireConfirm: false,
          mergeStrategy: "override",
        },
        {
          id: "risky-union",
          match: { cwd: ["~/x/**"] },
          inject: ["KNOWN"],
          onMiss: "fail",
          requireConfirm: true,
          mergeStrategy: "union",
        },
        {
          id: "pointless",
          match: { cwd: ["~/y/**"] },
          inject: [],
          onMiss: "fail",
          requireConfirm: false,
          mergeStrategy: "override",
        },
      ],
    };
    const findings = validateRules(dirty);
    const byCode = (code: string) => findings.filter((f) => f.code === code);

    expect(byCode("inject-everywhere")).toHaveLength(1);
    expect(byCode("inject-everywhere")[0]!.severity).toBe("high");
    expect(byCode("inject-everywhere")[0]!.ruleId).toBe("catch-all");

    // catch-all 在前 → 后三条全部不可达
    expect(byCode("unreachable").map((f) => f.ruleId).sort()).toEqual(["pointless", "risky-union", "shadowed"]);

    expect(byCode("unknown-secret")).toHaveLength(1);
    expect(byCode("unknown-secret")[0]!.message).toContain("GHOST");

    expect(byCode("require-confirm")[0]!.ruleId).toBe("risky-union");
    expect(byCode("union-strategy")[0]!.ruleId).toBe("risky-union");
    expect(byCode("empty-inject")[0]!.ruleId).toBe("pointless");

    // 正例：干净配置无 high/warn
    const clean: RulesFile = {
      secrets: [{ name: "A" }],
      rules: [
        {
          id: "scoped",
          match: { cwd: ["~/work/**"], command: ["pnpm *"] },
          inject: ["A"],
          onMiss: "fail",
          requireConfirm: false,
          mergeStrategy: "override",
        },
      ],
    };
    expect(validateRules(clean)).toEqual([]);
  });

  it("rule_validate：相同 match 的前序规则也判不可达", () => {
    const rf: RulesFile = {
      secrets: [{ name: "A" }, { name: "B" }],
      rules: [
        { id: "one", match: { cwd: ["~/a/**"] }, inject: ["A"], onMiss: "fail", requireConfirm: false, mergeStrategy: "override" },
        { id: "two", match: { cwd: ["~/a/**"] }, inject: ["B"], onMiss: "fail", requireConfirm: false, mergeStrategy: "override" },
      ],
    };
    const findings = validateRules(rf);
    expect(findings.some((f) => f.code === "unreachable" && f.ruleId === "two")).toBe(true);
  });
});
