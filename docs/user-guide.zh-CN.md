# vaultshell 用户指南

[English](user-guide.md) | 简体中文

本指南带你从安装走到日常使用。假设你已经了解
[MCP](https://modelcontextprotocol.io) 是什么，并且有一个支持 MCP 的客户端
（Claude Desktop、Cursor……）。

目录：

1. [安装](#1-安装)
2. [首次配置](#2-首次配置)
3. [后端](#3-后端)
4. [接入 MCP 客户端](#4-接入-mcp-客户端)
5. [编写规则](#5-编写规则)
6. [日常操作](#6-日常操作)
7. [故障排查 FAQ](#7-故障排查-faq)

---

## 1. 安装

要求：**Node.js 20 或更新版本**。

```bash
# 方式 A：按需运行（包发布之后）
npx -y vaultshell

# 方式 B：全局安装
npm install -g vaultshell
vaultshell            # 在 stdio 上启动 MCP server

# 方式 C：从源码
git clone <repo-url> && cd vaultshell
npm install && npm run build
node dist/index.js
```

通常你不会手动运行 vaultshell——MCP 客户端会通过 stdio 拉起它。
直接运行也可以用于冒烟测试（它会停在那里等 JSON-RPC；Ctrl-C 退出）。

vaultshell 的所有数据都在 `~/.vaultshell/` 下。设置 `VAULTSHELL_HOME`
可以使用别的目录。

## 2. 首次配置

两个文件：`~/.vaultshell/config.yaml`（如何存储与运行）和
`~/.vaultshell/rules.yaml`（注入什么、在哪里注入）。两者都可缺省——
某个键或整个文件缺失时，应用下面展示的默认值。

### 2.1 config.yaml —— 完整注释示例

```yaml
version: 1

storage:
  # secret_set 默认写入哪个后端；不带 scheme 的引用（ref）也在这里解析。
  # 可选：encrypted-file | local-keychain
  backend: encrypted-file

  encryptedFile:
    # AES-256-GCM 存储文件的位置。文件权限必须是 0600 或更严，
    # 否则 vaultshell 拒绝读取。
    path: ~/.vaultshell/secrets.enc

    # 32 字节主密钥的来源：
    #   env:MASTER_KEY  → 从该环境变量读 hex（64 字符）或 base64
    #   keychain        → macOS 登录钥匙串（首次使用时自动生成）
    keySource: env:MASTER_KEY

defaults:
  redact: true          # 对命令输出中的注入密钥做脱敏。请保持 true。
  audit: true           # 向 ~/.vaultshell/audit/ 追加 JSONL 审计记录

  # 传给子进程的宿主环境变量。刻意保持精简：不在列表里的变量
  # 对子进程不存在（更少的宿主噪音，更少的泄露面）。
  envPassthrough: [PATH, HOME, USER, LANG, SHELL, TERM, TMPDIR]

  # shell_exec 调用方可以通过 extraEnv 设置的键名。只允许普通变量——
  # 密钥必须走规则，绝不走 extraEnv。
  extraEnvAllowlist: [CI, DEBUG, DRY_RUN, NODE_ENV, NO_COLOR, FORCE_COLOR]

  allowInline: false    # 允许 inline:<明文> 引用。仅限 dev；启用时启动告警。

  maskTail: 0           # secret_probe 掩码保留值的最后 N 个字符。0 = 不保留
                        # 任何值片段。只有确实需要"……以 abcd 结尾"时才调大。

  execTimeoutSeconds: 120   # shell_exec / shell_session_send 硬超时
  sessionTtlSeconds: 900    # 持久会话的空闲 TTL
  maxOutputBytes: 1048576   # 单条输出流上限 → truncated: true
  maxConcurrentExecs: 8     # 超出并发的 shell_exec 调用被拒绝
  proxyTtlSeconds: 300      # 凭证代理自动关闭 TTL

# 凭证代理（见 §6"高敏感 API"）。headerTemplate 必须含 ${value}；
# upstreamHost 是不带路径的 http(s)://host[:port]。
proxies:
  - id: stripe
    upstreamHost: https://api.stripe.com
    secretRef: STRIPE_KEY
    headerTemplate: "Authorization: Bearer ${value}"
```

生成主密钥（encrypted-file 后端，`env:MASTER_KEY` 来源）：

```bash
openssl rand -hex 32        # 把 64 字符的结果放进客户端配置的 env 块
```

### 2.2 rules.yaml —— 完整注释示例

```yaml
version: 1

# 密钥注册表：名字 → 引用（ref）。只存引用——绝不存值。
secrets:
  - name: PROD_DB_URL                 # 无 ref → 默认后端，encfile://PROD_DB_URL
  - name: NPM_TOKEN
    ref: keychain://vaultshell/NPM_TOKEN     # macOS 钥匙串，service/account
  - name: LOCAL_TOKEN
    ref: file://~/.secrets/local_token       # 0600 文件的首行
  - name: CI_DEPLOY_KEY
    ref: env://CI_DEPLOY_KEY                 # 来自 MCP server 进程自身的环境

rules:
  # 自上而下求值。第一条命中的规则胜出（mergeStrategy
  # "override"）；它的 inject 列表就是子进程拿到的全部。
  - id: work-proj-a
    match:
      cwd: ["~/work/proj-a/**"]       # 对工作目录的 glob，~ 会展开
      command: ["pnpm *", "node *"]   # 可选：命令前缀 glob
      profiles: [dev]                 # 可选：仅在传入 profile=dev 时命中
    inject: [PROD_DB_URL, LOCAL_TOKEN]
    onMiss: fail                      # fail | skip | warn —— 见 §5.3

  - id: npm-work
    match:
      cwd: ["~/work/**"]
      command: ["npm *", "pnpm *", "npx *"]
    inject: [NPM_TOKEN]

  # 兜底规则：匹配所有目录。rule_list 会对它给出告警。
  - id: default-safe
    match:
      cwd: ["**"]
    inject: [LOCAL_TOKEN]
```

### 2.3 security 节（危险命令策略）

```yaml
security:
  dangerousCommands:
    # block（默认）：命中的命令在执行前被硬阻断。
    # warn：放行，但响应携带告警，审计条目记 dangerousCommand: true。
    #      两种方式输出都照常脱敏。
    mode: block
    # 在内置清单（env、printenv、裸 set、export -p、declare -x、
    # compgen -e、/proc/*/environ、ps eww……）之上追加的正则，
    # 对整条命令匹配。YAML 单引号保持正则反斜杠为字面量。
    extraPatterns:
      - '^mysecretprinter\b'
```

`extraPatterns` 里的非法正则会让配置加载失败并给出清晰报错。

## 3. 后端

完整矩阵与插件 API：[docs/backends.md](backends.md)（英文）。简要版：

### encrypted-file（默认）

零依赖 AES-256-GCM 文件存储。初始化：

```bash
export MASTER_KEY=$(openssl rand -hex 32)   # 或在 macOS 上用 keySource: keychain
```

然后 MCP 客户端里的 `secret_set` 会把值加密存到
`~/.vaultshell/secrets.enc`（权限 0600）。用 `keySource: keychain`（macOS）时，
主密钥在首次使用时自动生成，存进登录钥匙串（service 为
`vaultshell`，account 为 `encfile-master-key`）。

### local-keychain（macOS）

用系统 `security` CLI 存取密钥：

```bash
security add-generic-password -s vaultshell -a NPM_TOKEN -w 'the-secret-value' -U
security find-generic-password -s vaultshell -a NPM_TOKEN -w    # 验证（会打印值！）
```

以 `keychain://vaultshell/NPM_TOKEN` 引用它；或者把
`storage.backend: local-keychain` 设为默认后端并省略 ref（service 默认
`vaultshell`，account = 密钥名）。在 Linux/Windows 上该后端会给出清晰的
"未实现"报错（libsecret / Credential Manager 支持在计划中）。

### env:// 与 file:// 引用

- `env://NAME`——读 MCP server 进程自身的环境变量。只读。
  适合 CI：把密钥 export 进 server 进程，按名引用。
- `file://path`——读文件首行。文件必须 `chmod 600`（或更严），
  否则 vaultshell 拒绝读取。只读。

### inline:（明文——避免使用）

`inline:<value>` 把密钥直接写进 rules.yaml。**默认禁用**；启用需要
`defaults.allowInline: true`，且启动时打印告警。只用于本地开发的一次性值。

### 外部平台（经 CLI：1Password / Vault / Infisical / Doppler）

只读后端，spawn 各平台自己的 CLI（不引入新的 npm 依赖）。
先认证好对应 CLI；vaultshell 本身绝不接触它们的凭证。

| 引用（ref） | 解析命令 | 认证前提 |
|---|---|---|
| `op://Personal/stripe/key` | `op read op://Personal/stripe/key` | `op` CLI 已登录 |
| `vault://secret/data/prod/db#password` | `vault kv get -field=password -format=json secret/data/prod/db` | `VAULT_ADDR`+`VAULT_TOKEN` 或 `vault login` |
| `infisical://proj-id/prod/API_KEY` | `infisical secrets get API_KEY --projectId=proj-id --env=prod --plain --silent` | `INFISICAL_TOKEN` 或 `infisical login` |
| `doppler://backend/prd/STRIPE_KEY` | `doppler secrets get STRIPE_KEY --project=backend --config=prd --plain` | `DOPPLER_TOKEN` 或 `doppler login` |

在 `rules.yaml` 里作为引用使用：

```yaml
secrets:
  - name: STRIPE_KEY
    ref: op://Personal/stripe/key
```

CLI 不在 PATH、超时（10 秒）或未认证时，你会得到指明修复方法的可操作报错。
这些后端**不支持** `secret_set`/`secret_delete`——请用平台自己的工具管理值
（报错信息里带文档链接）。

## 4. 接入 MCP 客户端

### Claude Desktop

编辑 `claude_desktop_config.json`（macOS：`~/Library/Application
Support/Claude/claude_desktop_config.json`）：

```json
{
  "mcpServers": {
    "vaultshell": {
      "command": "npx",
      "args": ["-y", "vaultshell"],
      "env": {
        "MASTER_KEY": "<openssl rand -hex 32 生成的 64 个 hex 字符>"
      }
    }
  }
}
```

重启 Claude Desktop。`vaultshell` 的工具会出现在工具列表里。

### Cursor

Settings → MCP → 添加 server（或编辑 `~/.cursor/mcp.json`）：

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

如果是源码构建，把 `command` 指向 `node`，`args` 指向
`["/absolute/path/to/vaultshell/dist/index.js"]`。

## 5. 编写规则

### 5.1 匹配

- **cwd glob** 用 [minimatch](https://github.com/isaacs/minimatch) 语法。
  `~/work/x/**` 匹配 `~/work/x` 本身及其下所有目录。`~` 会展开。
  模式匹配的是绝对、展开 `~` 后的 cwd。
- **command glob** 匹配整条命令字符串，所以 `pnpm *` 表示
  "以 pnpm 开头的命令"。
- **profiles** 仅在调用方给 `shell_exec` 传 `profile: "<名字>"` 时匹配。
  带 `profiles` 的规则在没有 profile 时永不命中。
- 一条规则内的所有条件必须同时成立（AND）；同一条件内的多个条目是
  或（OR）关系。

### 5.2 顺序与合并策略

规则**按文件顺序求值，第一条命中的胜出**
（`mergeStrategy: override`，默认值）——后面的规则被忽略，因此你
永远不会"匹配越多、意外累积越多密钥"。把具体的规则放在宽泛的规则之上。

如果第一条命中的规则声明了 `mergeStrategy: union`，则合并**所有**命中规则的
inject 并集。慎用——那正是 override 要防的"匹配越多得到越多"提权。

### 5.3 onMiss —— 密钥解析失败时怎么办？

- `fail`（默认）：拒绝执行。命令不会运行；报错会指出解析失败的密钥名。最安全。
- `warn`：不带该密钥继续执行，并在响应的 `warnings` 里说明。
- `skip`：不带该密钥静默执行。

### 5.4 requireConfirm —— 高危规则的交互确认

```yaml
  - id: payment-scope
    match: { cwd: ["~/work/payments/**"] }
    inject: [STRIPE_KEY]
    requireConfirm: true
```

第一条命中规则带 `requireConfirm: true` 时，vaultshell 会在执行前通过客户端
请求确认（MCP elicitation）。如果客户端不支持 elicitation，命令会被**拒绝**，
报错会提示你移除 `requireConfirm` 或更换客户端——绝不会静默放行。

**客户端支持要求**：elicitation 是客户端能力。客户端必须在握手时声明
`elicitation` capability 并实现 `elicitation/create` 处理器，确认请求才能
送达用户。已知情况（以实际报错为准，报错含
`the MCP client does not support elicitation` 即为不支持）：

- ✅ 支持：在 `capabilities` 中声明了 `elicitation` 的自研客户端；新版
  Claude Desktop / VS Code 已支持（以各自更新日志为准）。
- ❌ 不支持：MCP Inspector（实测至 0.15.0，其 proxy 未声明该 capability）——
  **用 Inspector 调试时，带 `requireConfirm` 的规则一律拒绝执行**。

自研客户端接入只需两步（TypeScript SDK）：

```ts
import { ElicitRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const client = new Client({ name: "my-client", version: "1.0.0" }, {
  capabilities: { elicitation: {} },                       // 1. 声明能力
});
client.setRequestHandler(ElicitRequestSchema, async (req) => {
  // 渲染 req.params.message + req.params.requestedSchema，收集用户选择
  return { action: "accept", content: { confirm: true } }; // 2. accept / decline
});
```

调试技巧：在 Inspector 等不支持的客户端里调试高危规则时，可临时把该规则的
`requireConfirm` 改为 `false`（Web UI 的 Rules 页可直接改，保存即生效），
其余逻辑不变；功能验证完毕再打开。

### 5.5 ttlSeconds —— 规则级会话空闲 TTL

规则上的 `ttlSeconds` 覆盖 `defaults.sessionTtlSeconds`（900 秒），作用于
该规则下打开的会话。会话空闲超过 TTL 后，vaultshell 杀掉进程——
注入的密钥只与进程同寿。

### 5.6 静态校验

`rule_validate` 返回结构化检查结果（严重级 `high`/`warn`/`info`）：

- `unknown-secret`——inject 引用了不在密钥注册表里的名字
- `inject-everywhere`（high）——规则匹配所有目录且 inject 非空
- `unreachable`——被前序"匹配一切"的规则、或 match 条件完全相同的前序规则遮蔽
  （首命中胜出）
- `require-confirm`——能力提示（不支持 elicitation 的客户端会拒绝执行）
- `union-strategy`——`mergeStrategy: union` 的提权风险
- `empty-inject`——规则没有注入任何东西

这些是启发式检查，不是证明——glob 包含关系一般不可判定。`rule_list`
仍提供逐规则的概要视图。

## 5.7 持久会话

```text
shell_session_open  { "cwd": "~/work/proj-a" }
→ { "ok": true, "sessionId": "…", "injected": ["PROD_DB_URL"], "pty": true, "ttlSeconds": 900 }

shell_session_send  { "sessionId": "…", "command": "pnpm run migrate" }
→ { "ok": true, "output": "…（已脱敏）…", "exitCode": 0 }

shell_session_list  → 存活会话的元数据（永不含值）
shell_session_revoke { "sessionId": "…" } → 杀掉它，返回一个无密钥的新会话
shell_session_close  { "sessionId": "…" }
```

注意：

- `node-pty` 安装且可加载时会话使用真实 PTY（optional dependency，原生编译）。
  否则 vaultshell 降级为纯 `child_process` shell，open 响应标注 `pty: false`——
  注入与脱敏行为一致，只是交互性降级。
- 会话输出把 stdout/stderr 合并为一个 `output` 字段（PTY 语义）。
  PTY 模式下输出含终端回显/prompt 噪音；其中的密钥仍会被掩码。
- 状态跨 send 持久（`cd`、shell 变量）。发送 `exit` 会杀掉会话自身。
- 会话 send 同样应用 deny-list 与脱敏；审计条目携带 `sessionId`。
- 不要在会话里手打 `export SECRET=…`——vaultshell 无法拦截；
  只能靠审计 + 提示覆盖。

## 6. 日常操作

以下都是 MCP 工具——你（或 Agent）从客户端调用。

**存入密钥**

```
secret_set { "name": "PROD_DB_URL", "value": "postgres://…" }
```

值被写入默认后端，永不回显；名字被登记进 `rules.yaml`（只存引用）。

**验证密钥可解析**

```
secret_probe { "name": "PROD_DB_URL" }
→ { "ok": true, "masked": "****" }
```

**执行命令**

```
shell_exec { "command": "pnpm run migrate", "cwd": "~/work/proj-a" }
→ { "exitCode": 0, "stdout": "…", "injected": ["PROD_DB_URL"], "ruleId": "work-proj-a", … }
```

如果命令打印了密钥（直接、URL 编码或 Base64），输出里出现的是
`[REDACTED:PROD_DB_URL]`。

**回看发生了什么**

```
audit_query { "limit": 20 }
```

条目：`{ts, event, ruleId, cwd, command（已脱敏）, injectedNames,
exitCode, redactedCount}`——只有名字，永不含值。

**删除密钥**

```
secret_delete { "name": "PROD_DB_URL" }
```

**执行前预览（dry run）**

```
shell_exec { "command": "pnpm run migrate", "cwd": "~/work/proj-a", "dryRun": true }
→ { "dryRun": true, "ruleId": "work-proj-a", "injected": ["PROD_DB_URL"],
    "envKeys": ["HOME", "PATH", "PROD_DB_URL", …], "denied": null }
```

什么都不执行；你能看到哪条规则会命中、会注入哪些密钥、最终 env 的
**键名**清单（永不含值），以及 deny-list 判定结果。

**超时与限制**

- `shell_exec { …, "timeoutSeconds": 30 }`——N 秒后 kill（默认
  `defaults.execTimeoutSeconds` = 120，上限 3600）；结果带
  `timedOut: true`。
- 每条输出流的上限是 `defaults.maxOutputBytes`（1 MiB）；超出会收到截断提示
  且 `truncated: true`。截断发生在脱敏器之后，不可能绕过掩码。
- 超过 `defaults.maxConcurrentExecs`（8）的并发 `shell_exec` 调用会被拒绝
  并给出清晰报错——没有排队。

**不落 env 的高敏感 API（凭证代理）**

在 `config.yaml` 里声明一次：

```yaml
proxies:
  - id: stripe
    upstreamHost: https://api.stripe.com
    secretRef: STRIPE_KEY
    headerTemplate: "Authorization: Bearer ${value}"
```

然后：

```
shell_proxy_start { "id": "stripe" }
→ { "ok": true, "proxyId": "…", "port": 51743, "expiresAt": "…" }

shell_exec { "command": "curl http://127.0.0.1:51743/v1/charges", "cwd": "~" }
```

代理在内存中注入 `Authorization: Bearer <STRIPE_KEY>` 并转发到
`https://api.stripe.com`——密钥不落命令的 env、命令行或任何响应。
代理在 TTL（默认 `defaults.proxyTtlSeconds` = 300 秒；单次调用可用
`ttlSeconds` 覆盖）到期后自动关闭，或用 `shell_proxy_stop` 提前关闭。
`shell_proxy_list` 只显示元数据。审计记录 upstream host 与密钥**名**，
永不记录请求头的值。

边界：仅支持 `http://`/`https://` upstream；不做 CONNECT 隧道，不做 TLS 终止；
client→proxy 段是明文 loopback（同 UID 本地进程可嗅探——文档明示的 OS 层边界）。
解析值含 CR/LF 的密钥会被拒绝（请求头注入防护）。

**在浏览器里管理一切（Web 配置界面）**

```bash
vaultshell web            # 随机 loopback 端口，打印带一次性 token 的 URL
vaultshell web --port 5317
```

打开打印出的 URL（URL 里带一次性 token，载入后移入 sessionStorage 并从地址栏抹掉）。
四个页面：

- **Secrets**——列出名称/引用/可解析性，probe、删除，以及只写的
  "store"表单（值提交后永不再显示）。
- **Rules**——每个规则字段的卡片编辑器，↑/↓ 调顺序（顺序即语义），
  实时静态检查结果（与 `rule_validate` 同一套检查），以及匹配器 dry-run 框。
- **Config**——覆盖 `config.yaml` 各节的表单；保存经过 schema 校验且原子写
  （临时文件 + rename）。非法输入会被拒绝，**且不改动原文件**。
- **Audit**——按日的 JSONL 查看器，最新在前。

安全特性：仅 loopback、每进程随机 token（每个 API 调用都要 Bearer）、
变更类请求必须是同源的 `application/json`、严格 CSP、零第三方 JS——
铁律同样成立：没有任何端点返回密钥值。UI 进程与 MCP server 进程共享同一批文件
（`rules.yaml` 每次操作重新读取，所以编辑对下一次 `shell_exec` 立即生效）。
不要对该端口做端口转发。完整设计与威胁模型：
[web-config-ui-design.md](web-config-ui-design.md)（英文）。

## 7. 故障排查 FAQ

**`failed to resolve secret "X": secret "X" not found in encrypted file`**
名字在某条规则的 `inject` 里，但没有存过值。运行 `secret_set`，或用
`secret_probe` 检查。如果你改了 rules.yaml 里的密钥名，存进去的名字必须
完全一致。

**`master key env var MASTER_KEY is not set`**
MCP 客户端用它自己的环境拉起 vaultshell——在你的 shell 里 export
`MASTER_KEY` 是不够的。把它放进客户端配置的 `env` 块（见 §4），
或者在 macOS 上改用 `keySource: keychain`。

**`failed to decrypt "X" (wrong master key or corrupted store)`**
写入密钥之后 `MASTER_KEY` 变了。没有恢复手段——旧密钥是唯一的密钥。
用 `secret_set` 重新写入这些密钥。

**`refusing to read … permissions 644 are too open`**
对文件（secrets.enc 或 `file://` 目标）执行 `chmod 600`。vaultshell 故意拒绝
group/other 可读的密钥存储。

**`command blocked by deny-list: …`**
你（或 Agent）尝试了 `env`、`printenv`、裸 `set`、`export -p`、
`declare -x`、`compgen -e`、读 `/proc/*/environ`，或带 BSD `e` 标志的 `ps`。
这些命令会 dump 进程环境，被硬阻断——这是特性，不是 bug。换成你真正需要的
具体命令（比如 `echo $PATH` 没问题）。要调整策略见
`security.dangerousCommands`（§2.3）：追加 `extraPatterns`，或设
`mode: warn` 改为放行但记审计。

**`shell_session_open` 返回 `pty: false`**
`node-pty` 加载或启动失败，vaultshell 降级为纯管道 shell——功能都正常，
只是没有终端交互能力。常见原因：node-pty 没装（它是 optional dependency）、
原生编译失败（macOS 装 Xcode CLT / Linux 装 `build-essential` + python3 后重装），
或它的 `spawn-helper` 丢了执行位
（`chmod +x node_modules/node-pty/prebuilds/*/spawn-helper` 可修复）。

**会话自己消失了**
它达到了空闲 TTL（规则上的 `ttlSeconds`，否则
`defaults.sessionTtlSeconds`，默认 900 秒）被回收——审计日志里有一条
`session_expired`。重新打开一个即可。

**带 `requireConfirm` 的规则总是拒绝执行**
你的 MCP 客户端不支持 elicitation。vaultshell 在这里按设计失败即关闭——
从规则里移除 `requireConfirm`，或换用支持 elicitation 的客户端（客户端
支持矩阵与自研接入要点见 §5.4；已知 MCP Inspector ≤0.15.0 不支持）。

**密钥没有被注入（`injected: []`）**
没有规则命中。检查 `rule_list`，确认 cwd glob 能匹配绝对路径（`~` 展开、
符号链接经 `realpath` 式规范化），并记住：首命中胜出——你的具体规则上方的
宽泛规则会遮蔽它。

**`local-keychain backend is only implemented on macOS`**
没错——Linux（libsecret）和 Windows（Credential Manager）支持在计划中但尚未实现。
这期间请用 `encrypted-file`。

**`CLI not found in PATH: "op" / "vault" / "infisical" / "doppler"`**
外部后端会 spawn 平台 CLI。在 MCP server 进程的环境里安装并认证它
（`op signin`、`vault login` / `VAULT_TOKEN`、`infisical login` /
`INFISICAL_TOKEN`、`doppler login` / `DOPPLER_TOKEN`）。这些后端是只读的——
对 `op://`/`vault://`/`infisical://`/`doppler://` 引用调用 `secret_set`
按设计必定失败。

**`shell_proxy_start` 报 "no proxies entry with id …"**
先在 `config.yaml` 的 `proxies:` 下声明该代理。如果报
"CR/LF … refused"，是解析出的密钥值含换行——代理将其作为请求头注入防护而拒绝；
检查存储的值是否带了尾部换行。

**我的命令需要的环境变量不存在**
子进程只拿到 `defaults.envPassthrough` + 注入的密钥 + 白名单内的
`extraEnv`。把需要的普通变量加进 `envPassthrough`，或作为密钥注入。

**输出里出现 `[output truncated at 1MiB]`**
每条流上限 1 MiB。把大输出重定向到文件，再读取需要的部分。

**vaultshell 能防住以我的用户身份运行的恶意进程吗？**
不能——这是 OS 层边界（这种进程可以在子进程运行期间读
`/proc/<pid>/environ`）。vaultshell 缩小暴露面（per-command 注入、
后端之外不存明文），但无法修补 OS。见 README 的威胁模型。
