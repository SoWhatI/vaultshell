import { describe, expect, it } from "vitest";
import { checkDenied, matchRules, normalizeCwd } from "../src/policy.js";
import type { Rule } from "../src/config.js";

const rule = (over: Partial<Rule>): Rule => ({
  id: "r",
  match: {},
  inject: [],
  onMiss: "fail",
  requireConfirm: false,
  mergeStrategy: "override",
  ...over,
});

describe("规则匹配", () => {
  it("按顺序取第一条命中规则（override 语义）", () => {
    const rules: Rule[] = [
      rule({ id: "first", match: { cwd: ["~/proj/**"] }, inject: ["A"] }),
      rule({ id: "second", match: { cwd: ["**"] }, inject: ["B"] }),
    ];
    const m = matchRules(rules, { cwd: "~/proj/sub", command: "ls" });
    expect(m.rule?.id).toBe("first");
    expect(m.inject).toEqual(["A"]);
  });

  it("第一条未命中则取后续命中", () => {
    const rules: Rule[] = [
      rule({ id: "first", match: { cwd: ["~/other/**"] }, inject: ["A"] }),
      rule({ id: "second", match: { cwd: ["**"] }, inject: ["B"] }),
    ];
    const m = matchRules(rules, { cwd: "~/proj", command: "ls" });
    expect(m.rule?.id).toBe("second");
    expect(m.inject).toEqual(["B"]);
  });

  it("union：合并全部命中规则的 inject", () => {
    const rules: Rule[] = [
      rule({ id: "a", match: { cwd: ["~/p/**"] }, inject: ["A", "B"], mergeStrategy: "union" }),
      rule({ id: "b", match: { cwd: ["**"] }, inject: ["B", "C"] }),
    ];
    const m = matchRules(rules, { cwd: "~/p/x", command: "ls" });
    expect(m.inject).toEqual(["A", "B", "C"]);
    expect(m.matchedIds).toEqual(["a", "b"]);
  });

  it("无命中 → 不注入", () => {
    const rules: Rule[] = [rule({ id: "a", match: { cwd: ["~/work/**"] }, inject: ["A"] })];
    const m = matchRules(rules, { cwd: "/tmp/elsewhere", command: "ls" });
    expect(m.rule).toBeNull();
    expect(m.inject).toEqual([]);
  });

  it("~ 展开 + glob 边界：目录本身与子目录", () => {
    const home = process.env.HOME!;
    const rules: Rule[] = [rule({ id: "a", match: { cwd: ["~/work/x/**"] }, inject: ["A"] })];
    expect(matchRules(rules, { cwd: "~/work/x/deep/dir", command: "ls" }).inject).toEqual(["A"]);
    expect(matchRules(rules, { cwd: "~/work/x", command: "ls" }).inject).toEqual(["A"]);
    expect(matchRules(rules, { cwd: "~/work/xy", command: "ls" }).inject).toEqual([]);
    expect(normalizeCwd("~/work/x")).toBe(`${home}/work/x`);
  });

  it("点目录默认也匹配（dot:true）", () => {
    const rules: Rule[] = [rule({ id: "a", match: { cwd: ["~/p/**"] }, inject: ["A"] })];
    expect(matchRules(rules, { cwd: "~/p/.hidden/sub", command: "ls" }).inject).toEqual(["A"]);
  });

  it("command 前缀通配与 profiles", () => {
    const rules: Rule[] = [
      rule({ id: "a", match: { command: ["pnpm *", "node *"], profiles: ["dev"] }, inject: ["A"] }),
    ];
    expect(matchRules(rules, { cwd: "/tmp", command: "pnpm run build", profile: "dev" }).inject).toEqual(["A"]);
    expect(matchRules(rules, { cwd: "/tmp", command: "npm run build", profile: "dev" }).inject).toEqual([]);
    expect(matchRules(rules, { cwd: "/tmp", command: "pnpm run build", profile: "prod" }).inject).toEqual([]);
    expect(matchRules(rules, { cwd: "/tmp", command: "pnpm run build" }).inject).toEqual([]);
  });
});

describe("危险命令 deny-list（hard-block）", () => {
  const blocked = [
    "env",
    "printenv",
    "FOO=bar env",
    "sudo env",
    "/usr/bin/env",
    "echo hi; env",
    "echo hi | env",
    "echo a && printenv PATH",
    "set",
    "export",
    "export -p",
    "declare",
    "declare -x",
    "typeset -p",
    "compgen -e",
    "cat /proc/self/environ",
    "cat /proc/1234/environ",
    "strings /proc/1/environ",
    "xargs -0 -a /proc/self/environ",
    "ps eww",
    "ps auxe",
    "$(env)",
    "echo `printenv`",
  ];
  for (const cmd of blocked) {
    it(`blocks: ${cmd}`, () => {
      expect(checkDenied(cmd)).not.toBeNull();
    });
  }

  const allowed = [
    "pnpm run build",
    "echo $HOME",
    "export FOO=1; echo hi",
    "set -e; echo ok",
    "ps aux",
    "ps -ef",
    "cat /proc/cpuinfo",
    "node -e 'console.log(1)'",
  ];
  for (const cmd of allowed) {
    it(`allows: ${cmd}`, () => {
      expect(checkDenied(cmd)).toBeNull();
    });
  }
});
