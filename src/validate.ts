import type { Rule, RulesFile } from "./config.js";

/**
 * rule_validate 的静态检查。都是启发式（glob 包含关系不可精确判定），
 * 目标是抓住最常见的配置事故，不是完备证明。
 */

export type FindingSeverity = "high" | "warn" | "info";

export interface RuleFinding {
  ruleId: string;
  severity: FindingSeverity;
  code:
    | "unknown-secret"
    | "inject-everywhere"
    | "unreachable"
    | "require-confirm"
    | "union-strategy"
    | "empty-inject";
  message: string;
}

/** 规则是否"匹配一切"：没有任何约束，或仅 cwd 为 ** 型通配 */
function matchesEverything(rule: Rule): boolean {
  const m = rule.match;
  if (m.command && m.command.length > 0) return false;
  if (m.profiles && m.profiles.length > 0) return false;
  if (!m.cwd || m.cwd.length === 0) return true;
  return m.cwd.some((p) => p === "**" || p === "/**" || p === "~/**");
}

function sameMatch(a: Rule, b: Rule): boolean {
  const norm = (r: Rule) =>
    JSON.stringify({
      cwd: [...(r.match.cwd ?? [])].sort(),
      command: [...(r.match.command ?? [])].sort(),
      profiles: [...(r.match.profiles ?? [])].sort(),
    });
  return norm(a) === norm(b);
}

export function validateRules(rulesFile: RulesFile): RuleFinding[] {
  const findings: RuleFinding[] = [];
  const known = new Set(rulesFile.secrets.map((s) => s.name));

  rulesFile.rules.forEach((rule, i) => {
    // 引用不存在的 secret 名
    for (const name of rule.inject) {
      if (!known.has(name)) {
        findings.push({
          ruleId: rule.id,
          severity: "warn",
          code: "unknown-secret",
          message: `inject references unregistered secret "${name}" (will resolve via default backend or fail)`,
        });
      }
    }

    // 意外全量注入（高危）
    if (rule.inject.length > 0 && matchesEverything(rule)) {
      findings.push({
        ruleId: rule.id,
        severity: "high",
        code: "inject-everywhere",
        message: `rule matches every directory and injects [${rule.inject.join(", ")}] everywhere; ` +
          `add a cwd/command/profiles constraint or move it last as an intentional catch-all`,
      });
    }

    // 不可达：被前序"匹配一切"或完全相同的规则遮蔽
    for (let j = 0; j < i; j++) {
      const prev = rulesFile.rules[j]!;
      if (matchesEverything(prev)) {
        findings.push({
          ruleId: rule.id,
          severity: "warn",
          code: "unreachable",
          message: `rule is unreachable: earlier rule "${prev.id}" matches everything (first match wins)`,
        });
        break;
      }
      if (sameMatch(prev, rule)) {
        findings.push({
          ruleId: rule.id,
          severity: "warn",
          code: "unreachable",
          message: `rule is unreachable: earlier rule "${prev.id}" has identical match conditions`,
        });
        break;
      }
    }

    // requireConfirm 能力提示
    if (rule.requireConfirm) {
      findings.push({
        ruleId: rule.id,
        severity: "info",
        code: "require-confirm",
        message: `requireConfirm needs an MCP client with elicitation support; ` +
          `clients without it will REFUSE to execute (fail-closed)`,
      });
    }

    // union 提权风险提示
    if (rule.mergeStrategy === "union") {
      findings.push({
        ruleId: rule.id,
        severity: "warn",
        code: "union-strategy",
        message: `mergeStrategy "union" merges inject lists of ALL matching rules — ` +
          `the broader the match, the more secrets get injected (privilege-creep risk). Prefer "override".`,
      });
    }

    // 空 inject（规则无意义）
    if (rule.inject.length === 0) {
      findings.push({
        ruleId: rule.id,
        severity: "info",
        code: "empty-inject",
        message: `rule injects nothing`,
      });
    }
  });

  return findings;
}
