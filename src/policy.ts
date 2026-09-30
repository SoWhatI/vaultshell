import { minimatch } from "minimatch";
import { resolve } from "node:path";
import { expandTilde } from "./resolver/types.js";
import type { Rule } from "./config.js";

export interface MatchInput {
  cwd: string;
  command: string;
  profile?: string;
}

export interface MatchResult {
  /** 第一条命中的规则（审计用）；无命中为 null */
  rule: Rule | null;
  /** 最终注入名单（override=首命中规则的 inject；union=全部命中规则的并集） */
  inject: string[];
  matchedIds: string[];
}

export function normalizeCwd(cwd: string): string {
  return resolve(expandTilde(cwd));
}

function cwdMatches(cwd: string, pattern: string): boolean {
  const p = expandTilde(pattern);
  if (minimatch(cwd, p, { dot: true })) return true;
  // "~/work/x/**" 应同时覆盖 "~/work/x" 本身
  if (p.endsWith("/**") && cwd === p.slice(0, -3)) return true;
  return false;
}

function ruleMatches(rule: Rule, cwd: string, command: string, profile?: string): boolean {
  const m = rule.match;
  if (m.cwd && m.cwd.length > 0) {
    if (!m.cwd.some((p) => cwdMatches(cwd, p))) return false;
  }
  if (m.command && m.command.length > 0) {
    if (!m.command.some((p) => minimatch(command, p, { dot: true }))) return false;
  }
  if (m.profiles && m.profiles.length > 0) {
    if (!profile || !m.profiles.includes(profile)) return false;
  }
  return true;
}

/** 按顺序匹配；mergeStrategy 由第一条命中规则声明（默认 override） */
export function matchRules(rules: Rule[], input: MatchInput): MatchResult {
  const cwd = normalizeCwd(input.cwd);
  const matched = rules.filter((r) => ruleMatches(r, cwd, input.command, input.profile));
  const first = matched[0];
  if (!first) return { rule: null, inject: [], matchedIds: [] };
  if (first.mergeStrategy === "union") {
    return {
      rule: first,
      inject: [...new Set(matched.flatMap((r) => r.inject))],
      matchedIds: matched.map((r) => r.id),
    };
  }
  return { rule: first, inject: [...first.inject], matchedIds: [first.id] };
}

/**
 * 危险命令 deny-list：这些命令的唯一现实目的就是 dump 环境/密钥。
 * 宁可误伤也不放行；内置清单之外可用 config security.dangerousCommands.extraPatterns 追加正则。
 * block/warn 的处置由调用方（launcher/session）根据配置决定。
 */
const SEGMENT_SPLIT = /&&|\|\||[;|]/;

function basename(token: string): string {
  const i = token.lastIndexOf("/");
  return i >= 0 ? token.slice(i + 1) : token;
}

export function checkDenied(command: string, extraPatterns: string[] = []): string | null {
  for (const p of extraPatterns) {
    if (new RegExp(p).test(command)) {
      return `command matches security.dangerousCommands.extraPatterns entry ${JSON.stringify(p)}`;
    }
  }
  if (/\/proc\/[^/\s"'`]+\/environ/.test(command)) {
    return "reading /proc/*/environ is blocked (environment dump)";
  }
  if (/\$\(\s*(env|printenv|set)\s*\)|`\s*(env|printenv|set)\s*`/.test(command)) {
    return "command substitution of env/printenv/set is blocked (environment dump)";
  }
  for (const segment of command.split(SEGMENT_SPLIT)) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    let i = 0;
    if (tokens[i] === "sudo") i++;
    while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i]!)) i++;
    const cmd = basename(tokens[i] ?? "");
    if (!cmd) continue;
    const args = tokens.slice(i + 1);

    if (cmd === "env" || cmd === "printenv") {
      return `\`${cmd}\` is blocked (environment dump)`;
    }
    if (cmd === "set" && args.length === 0) {
      return "bare `set` is blocked (environment dump)";
    }
    if (cmd === "export" && (args.length === 0 || args.includes("-p"))) {
      return "`export`/`export -p` is blocked (environment dump)";
    }
    if (
      (cmd === "declare" || cmd === "typeset") &&
      (args.length === 0 || args.some((a) => a === "-x" || a === "-p"))
    ) {
      return `\`${cmd} ${args.join(" ")}\` is blocked (environment dump)`;
    }
    if (cmd === "compgen" && args.includes("-e")) {
      return "`compgen -e` is blocked (environment dump)";
    }
    if (cmd === "ps" && args.some((a) => /^[A-Za-z]*e[A-Za-z]*$/.test(a))) {
      return "`ps` with BSD 'e' flag is blocked (shows process environment)";
    }
  }
  return null;
}
