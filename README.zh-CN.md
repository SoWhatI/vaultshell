# vaultshell

[English](README.md) | 简体中文

[![CI](https://github.com/SoWhatI/vaultshell/actions/workflows/ci.yml/badge.svg)](https://github.com/SoWhatI/vaultshell/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/vaultshell)](https://www.npmjs.com/package/vaultshell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

一个 MCP server：把密钥存放在本地安全存储中，按规则在**执行命令的那一刻**注入到 shell 子进程环境，并保证密钥明文**永不进入模型上下文**——不进工具返回值、不进日志、不进审计记录。

核心闭环：**引用式保管 + 条件化注入 + 输出强制脱敏**。

> 状态：M3——一次性命令 + 持久会话 + 凭证代理（credential proxy）+
> 外部 CLI 后端。见
> [CHANGELOG](CHANGELOG.md) 与 [docs/design-spec.md](docs/design-spec.md)。

## 铁律

- 不存在任何返回密钥明文的 MCP 工具——永远。返回值只含变量名、
  掩码（mask，`[REDACTED:NAME]`）和脱敏后的输出。
- 解析器（Resolver）只在启动器（launcher）内部被调用；解析出的值直接进子进程
  `env`，不经过工具层。
- `shell_exec` **没有**自由形式的 `env` 参数。密钥只能通过规则（rule）引用注入。
- 脱敏器（Redactor）出错时失败即关闭（fail-closed）：丢弃输出，绝不原样返回。

## 快速上手

需要 Node.js 20+。

```bash
# 通过 npx 运行（发布之后）或从源码构建：
npm install && npm run build

# 1. 为 encrypted-file 后端生成主密钥
export MASTER_KEY=$(openssl rand -hex 32)

# 2. 创建 ~/.vaultshell/config.yaml 和 ~/.vaultshell/rules.yaml
#    （完整注释示例：docs/user-guide.zh-CN.md）

# 3. 存入一个密钥（永不回显），然后通过 MCP 客户端的工具注入执行：
#    先 secret_set，再 shell_exec
```

Claude Desktop（`claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "vaultshell": {
      "command": "npx",
      "args": ["-y", "vaultshell"],
      "env": { "MASTER_KEY": "<64 hex chars>" }
    }
  }
}
```

**完整安装、配置参考、规则编写指南、客户端接入与 FAQ：
[docs/user-guide.zh-CN.md](docs/user-guide.zh-CN.md)（[English](docs/user-guide.md)）。**

## MCP 工具

| 工具 | 作用 | 返回 |
|---|---|---|
| `shell_exec` | 执行一次性命令，按命中规则注入。参数：`command`、`cwd?`、`profile?`、`extraEnv?`（白名单）、`dryRun?`、`timeoutSeconds?`（≤3600） | `{exitCode, stdout, stderr}`（已脱敏）、`injected:[names]`、`ruleId`、`redactedCount`、`timedOut`、`truncated`、`warnings`；dryRun → `{dryRun:true, ruleId, injected, envKeys, denied}` |
| `shell_session_open` | 打开持久会话（session）；密钥在创建时一次性注入 | `{sessionId, cwd, injected:[names], pty, ttlSeconds}` |
| `shell_session_send` | 向会话发送命令 | `{output}`（合并流、已脱敏）、`exitCode`、`redactedCount` |
| `shell_session_close` | 杀掉会话；密钥随进程消失 | `{ok}` |
| `shell_session_list` | 列出存活会话 | 仅元数据 |
| `shell_session_revoke` | 立即杀掉并重建一个**无密钥**会话 | `{sessionId}`（新） |
| `shell_proxy_start` | 在 127.0.0.1 上启动凭证注入反向代理 | `{proxyId, port, expiresAt, upstreamHost}` |
| `shell_proxy_stop` | 停止代理 | `{ok}` |
| `shell_proxy_list` | 列出运行中的代理 | 仅元数据（含密钥**名**，永不含值） |
| `secret_list` | 列出变量名 + 元数据（后端引用、可解析性） | 永不含值 |
| `secret_set` | 写入后端；只落盘不回显 | `{name, ok}` |
| `secret_delete` | 删除并注销 | `{name, ok}` |
| `secret_probe` | 校验引用能否解析 | `{ok, masked:"****"}` |
| `rule_list` | 规则 + 静态告警（如全量注入） | — |
| `rule_validate` | 静态检查：未知密钥引用、不可达规则、全量注入、union 风险、requireConfirm 能力提示 | `{ok, findings[]}` |
| `audit_query` | 查询审计 | 只含变量名与已脱敏命令 |

## 执行限制（M3）

- `shell_exec` 传 `dryRun: true`：只返回将命中的 `ruleId`、`injected`
  变量名、最终 env 的**键名**清单（永不含值）以及 deny-list 判定结果——
  不执行任何命令。
- `timeoutSeconds`（默认 `defaults.execTimeoutSeconds` = 120，上限
  3600）：超时 kill 命令并返回 `timedOut: true`。
- `defaults.maxOutputBytes`（默认 1 MiB）：每条输出流超限截断并置
  `truncated: true`。截断发生在脱敏器**之后**——不可能绕过脱敏。
- `defaults.maxConcurrentExecs`（默认 8）：超出并发上限的
  `shell_exec` 调用直接被拒绝并给出清晰报错（不排队）。
- 以上全部记入审计日志（`dryRun` / `timedOut` / `truncated` 标记）。

## Web 配置界面

```bash
vaultshell web            # 仅 loopback 的 HTTP 界面，随机端口
vaultshell web --port 5317
```

启动时打印带一次性 token 的 URL，形如 `http://127.0.0.1:5317/?token=…`——
打开后可管理密钥（只写不读）、用实时静态校验告警和匹配器 dry-run 编辑规则、
编辑配置、浏览已脱敏的审计日志。token 随进程消亡；每个 API 调用都需携带；
变更类请求必须是同源的 `application/json`；**没有任何端点会返回密钥值**。
不要对该端口做端口转发。设计与威胁模型：
[docs/web-config-ui-design.md](docs/web-config-ui-design.md)。

## 凭证代理（credential proxy，M3）

对高敏感 API token，优先让密钥**完全不落 env**。在 `config.yaml` 里声明代理：

```yaml
proxies:
  - id: stripe
    upstreamHost: https://api.stripe.com
    secretRef: STRIPE_KEY                          # 注册表名或完整引用（ref）
    headerTemplate: "Authorization: Bearer ${value}"
```

然后 `shell_proxy_start { "id": "stripe" }` → `{ port, expiresAt }`，
命令里用 `http://127.0.0.1:<port>/v1/charges` 替代
`https://api.stripe.com/v1/charges`。代理**只在内存中**注入请求头，
并在 TTL（默认 300s）到期后自动关闭。审计只记录 host 与密钥名，
永不记录请求头的值。

边界：仅支持 `http://`/`https://` upstream（proxy→upstream 的 TLS 正常校验证书；
不做 CONNECT 隧道，不做 TLS 终止）；client→proxy 段是 127.0.0.1 上的明文 HTTP，
继承威胁模型中同 UID 本地进程的边界。

## 持久会话（M2）

`shell_session_open` 启动一个长驻 shell，在创建时注入命中规则的密钥。
会话在空闲 TTL 后被回收（`defaults.sessionTtlSeconds`，默认 900 秒，
可被规则的 `ttlSeconds` 或单次调用覆盖）——进程死亡，密钥随之消失。
`shell_session_revoke` 立即杀掉可能已泄露的会话并重建一个**不含任何密钥**的新会话。

会话通过 [`node-pty`](https://github.com/microsoft/node-pty) 使用真实 PTY
（**optional dependency**——原生编译，macOS 需要 Xcode CLT /
Linux 需要 build-essential + python3）。如果 node-pty 无法加载或启动，
vaultshell 自动降级为纯 `child_process` shell，且 `shell_session_open`
的返回会标注 `pty: false`；注入与脱敏行为完全一致，只是交互性降级。
会话输出合并 stdout/stderr（PTY 语义），并照常经过同一个脱敏器。

## 后端支持矩阵

| 后端（backend） | 引用（ref）scheme | 状态 | 平台 | 备注 |
|---|---|---|---|---|
| Encrypted file | `encfile://NAME` | ✅ 已实现 | 全部 | AES-256-GCM；主密钥来自 `env:MASTER_KEY` 或 macOS keychain；默认 |
| Local keychain | `keychain://svc/acct` | ⚠️ 仅 macOS | macOS | spawn `security` CLI；Linux/Windows 给出清晰报错 |
| Process env | `env://NAME` | ✅ 已实现 | 全部 | 只读；适合 CI |
| File | `file://path` | ✅ 已实现 | 全部 | 读文件首行；权限大于 0600 则拒绝 |
| Inline | `inline:` | ⚠️ 受限 | 全部 | 配置里的明文；默认禁用，启用时启动告警 |
| 1Password | `op://vault/item/field` | ✅ 经 CLI | 全部 | 需要已认证的 `op` CLI；只读 |
| Vault | `vault://path#field` | ✅ 经 CLI | 全部 | 需要已认证的 `vault` CLI；只读 |
| Infisical | `infisical://proj/env/KEY` | ✅ 经 CLI | 全部 | 需要已认证的 `infisical` CLI；只读 |
| Doppler | `doppler://proj/config/KEY` | ✅ 经 CLI | 全部 | 需要已认证的 `doppler` CLI；只读 |

各后端详细配置与插件解析器注册方法：
[docs/backends.md](docs/backends.md)（英文）。

## 威胁模型

| 威胁 | 缓解 |
|---|---|
| 模型上下文泄露 | 结构性：值永不跨越工具层；只给变量名与掩码 |
| 命令输出回显密钥 | 强制脱敏（精确值 + URL/Base64 变体 + 通用正则），失败即关闭 |
| Agent 主动 dump 环境（`env`、`printenv`、`/proc/*/environ`……） | deny-list 硬阻断（可用 `security.dangerousCommands` 配置：追加模式，或 `mode: warn` 放行但记审计）+ `shell_exec_blocked` 审计事件 |
| 同 UID 本地进程读 `/proc/PID/environ` | OS 层限制，无法根治；per-command 注入缩短暴露窗口。**明示边界。** |
| 密钥长期驻留 | 默认 per-command 注入；会话有空闲 TTL 回收 + 即时 `revoke` |
| 规则写错导致全量注入 | `rule_validate` / `rule_list` 静态告警；`mergeStrategy` 默认 `override`；`requireConfirm` 规则强制交互确认（无 elicitation 时失败即关闭） |
| 配置文件本身泄露 | 配置只存引用不存值；`inline:` 默认禁用；存储文件强制 0600 |

完整讨论：[docs/design-spec.md](docs/design-spec.md) §7。
漏洞报告请按 [SECURITY.md](SECURITY.md) 私下提交。

## 数据目录

```
~/.vaultshell/
  config.yaml     # 主配置
  rules.yaml      # 注入规则 + 密钥引用表（只存引用，绝不存值）
  secrets.enc     # encrypted-file 后端（0600）
  audit/          # JSONL 审计，已脱敏
```

`VAULTSHELL_HOME` 可覆盖数据目录（测试用）。

## 开发

```bash
npm run build   # tsc
npm test        # vitest——脱敏器属性测试、后端往返、
                # 规则匹配、shell_exec 端到端
```

见 [CONTRIBUTING.md](CONTRIBUTING.md)——包括每个 PR 都必须遵守的安全红线。

## 许可证

[MIT](LICENSE) © 2026 vaultshell contributors
