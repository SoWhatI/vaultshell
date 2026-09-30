下面是一份可以直接开工的实现方案。我按"先定边界 → 再定架构 → 再定接口 → 最后排期"的顺序整理，你可以直接当 spec 用。

Shell MCP · 私密环境变量注入（Secrets Injection）设计方案

一句话定位

一个 MCP Server：把密钥存在本地安全存储里，按规则在执行命令的那一刻注入到 shell 子进程环境，并保证密钥明文永不进入模型上下文（包括命令输出）。

差异化不在"能注入"（Infisical / Doppler 早就能），而在三件事的闭环：引用式保管 + 条件化注入 + 输出强制脱敏。

目标与非目标

目标
G1：密钥值不出现在任何 MCP tool 的返回值、日志、审计记录中（只出现掩码）。
G2：支持持久 shell 会话（PTY），也支持一次性命令；两者都能注入。
G3：注入可按 工作目录 / 命令模式 / profile / TTL 条件生效，不做全量注入。
G4：命令 stdout/stderr 中出现密钥值时自动替换为 [REDACTED:name]。
G5：后端可插拔，默认零依赖本地存储，可选接 1Password / Infisical / Vault / Doppler。
G6：全量审计（谁、什么时候、注入了哪些变量名、执行了什么命令）。

非目标（明确不做，防止范围膨胀）
不做云端 secrets 平台，不做多用户 RBAC。
不做密钥轮换调度（交给后端）。
不承诺对抗"同 UID 下的恶意本地进程"（见 §7，这是 OS 层限制，只能缓解）。
不做 GUI。

架构

┌─────────────── MCP Client (Claude / Cursor / IDE) ───────────────┐
│  只看到：变量名、掩码、执行结果（已脱敏）                          │
└───────────────────────────┬──────────────────────────────────────┘
                            │ stdio / streamable HTTP
┌───────────────────────────▼──────────────────────────────────────┐
│  shell-mcp-secrets                                              │
│                                                                 │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  ┌──────────────────┐  │
│  │ Tool    │→ │ Policy   │→ │ Resolver  │→ │ Process Launcher │  │
│  │ Layer   │  │ Matcher  │  │ (Backend) │  │ (PTY / spawn)    │  │
│  └─────────┘  └──────────┘  └───────────┘  └────────┬─────────┘  │
│        ↑                                            │            │
│  ┌─────┴──────┐   ┌──────────────┐   ┌─────────────▼──────────┐  │
│  │ Config     │   │ Redactor     │←──│ stdout / stderr stream │  │
│  │ (rules)    │   │ (Aho-Corasick)│  └────────────────────────┘  │
│  └────────────┘   └──────────────┘                               │
│        │                     ┌──────────────┐                   │
│        └────────────────────→│ Audit Log    │                   │
│                              └──────────────┘                   │
└──────────────────────────────────────────────────────────────────┘
        │
        ▼
  Storage Backends: local-keychain | encrypted-file | 1password | infisical | vault | env

关键设计：Resolver 只在 Launcher 内部被调用，返回值直接进 child_process 的 env，不经过 Tool Layer，因此结构上就不可能泄露给模型。

配置与数据模型

3.1 目录布局

~/.shell-mcp/
  config.yaml          # 主配置：后端、默认策略
  rules.yaml           # 注入规则
  secrets.enc          # 加密文件后端（可选）
  audit/2026-09-28.jsonl
  cache/               # 后端解析缓存（TTL，明文，权限 0600，默认关闭）

3.2 config.yaml

version: 1
storage:
  backend: local-keychain        # local-keychain | encrypted-file | infisical | onepassword | vault | env
  encryptedFile:
    path: ~/.shell-mcp/secrets.enc
    keySource: keychain          # keychain | env:MASTER_KEY | passphrase
defaults:
  redact: true
  audit: true
  sessionTtlSeconds: 900         # 持久会话空闲回收
  envPassthrough: [PATH, HOME, USER, LANG, SHELL, TERM]  # 白名单，避免宿主环境噪音

3.3 rules.yaml（核心，条件化注入）

version: 1
secrets:
  name: PROD_DB_URL
    ref: keychain://shell-mcp/PROD_DB_URL
  name: STRIPE_KEY
    ref: op://Personal/stripe/key
  name: LOCAL_TOKEN
    ref: file://~/.secrets/local_token

rules:
  id: work-proj-a
    match:
      cwd: ["~/work/proj-a/**"]          # glob
      command: ["pnpm *", "node *", "make *"]
      profiles: [dev]
    inject: [PROD_DB_URL, LOCAL_TOKEN]
    ttlSeconds: 600
    onMiss: fail        # fail | skip | warn  —— 解析不到时怎么办
  id: payment-scope
    match:
      cwd: ["~/work/payments/**"]
    inject: [STRIPE_KEY]
    requireConfirm: true   # 需要客户端二次确认（走 elicitation / 人工批准）
  id: default-safe
    match: { cwd: ["**"] }
    inject: [LOCAL_TOKEN]

匹配语义：按顺序取第一条命中的规则；inject 为并集还是覆盖，用 mergeStrategy: override | union 显式声明（默认 override，避免"越匹配越多"的意外提权）。

3.4 引用格式（ref scheme）
scheme   含义   备注
keychain://svc/account   系统钥匙串   macOS security、Windows Credential Manager、Linux libsecret

file://path   读文件首行   校验权限 ≤0600，否则拒绝

env://NAME   从 MCP 进程环境取   便于 CI

op://vault/item/field   1Password CLI   需 op 在 PATH

infisical://proj/env/KEY   Infisical   需 token

inline:   明文   默认禁用，仅 dev，启动时告警

MCP Tool 面（工具清单）

设计铁律：不存在任何返回密钥明文的工具。
Tool   作用   返回
shell_exec   主入口：执行命令，按规则注入   {exitCode, stdout(脱敏), stderr(脱敏), injected:[names], ruleId}

shell_session_open   打开持久 PTY 会话   {sessionId, cwd, injected:[names]}

shell_session_send   向会话发命令   同上，脱敏后返回

shell_session_close / _list   生命周期管理   —

secret_list   列出变量名 + 元数据（后端、最后使用时间、是否可解析）   永不含值

secret_set   写入后端（值由客户端参数传入，只落盘不回显）   {name, ok}

secret_delete   删除   —

secret_probe   校验 ref 能否解析   {ok, masked:"****abcd"}

rule_list / rule_validate   查看/校验规则（含"是否会意外全量注入"的静态告警）   —

audit_query   查审计   只含变量名

shell_exec 的入参建议：

{
  "command": "pnpm run migrate",
  "cwd": "~/work/proj-a",
  "profile": "dev",
  "sessionId": null,
  "extraEnv": {"DRY_RUN": "1"}   // 只允许非密钥的普通变量，且需在 allowlist 内
}

注意：不要提供 env: Record<string,string> 这种自由传参字段（现有 shell MCP 的通病），否则用户会把密钥写进 prompt。若要支持，必须走 secretRefs: ["PROD_DB_URL"] 这种引用名形式。

注入实现细节

5.1 一次性命令
const env = pickPassthrough(process.env, cfg.envPassthrough)
                 resolvedSecrets   // Resolver 结果，仅此处存在
                 extraEnv;
const child = spawn(shell, ['-lc', cmd], { env, cwd, stdio: ['pipe','pipe','pipe'] });

5.2 持久会话
用 node-pty 起 PTY，创建时注入 env。要点：
会话创建时快照一份 injectedNames，session_close 或 TTL 到期即销毁进程（密钥随进程消失）。
提供 shell_session_revoke：立即 kill 并重建无密钥会话。
不要把密钥写进 shell 的 rc 文件或 history；PTY 里如果用户手打 export X=... 无法拦截，靠审计 + 提示。

5.3 更安全的替代路径（进阶，M3）
对数据库/云 API 这类，优先"不落 env"：
本地起一个 credential proxy（如本地 127.0.0.1 端口转发 DB / 签名代理），命令里只放 localhost:5432，密码由代理持有。
或把密钥写成 0600 临时文件，路径注入 env（--credentials-file=TMP），命令结束即删。
这两种能显著降低"env 被 dump"的风险，建议作为高敏感场景的推荐模式。

脱敏（Redactor）—— 最容易被低估、也最能形成差异的部分

构建匹配器：把本轮所有注入值 + 配置的通用正则（sk-[A-Za-z0-9]{20,}、JWT、AWS AK、PEM 块）装进 Aho–Corasick 自动机，对 stdout/stderr 做流式扫描。
流式边界问题：密钥可能被 chunk 切断。做法：保留 maxSecretLen 的滑动尾部缓冲，只在流结束或缓冲超阈值时 flush；对超长输出用增量替换。
变体覆盖：URL 编码、Base64、加引号、大小写、值被拆分拼接——至少覆盖 URL-encode 与 Base64（很多工具会打印编码后的值）。
命令回显也要脱敏：如果命令本身含明文（用户手误），回显和审计里都要掩码。
失败即安全：Redactor 抛错时，默认丢弃输出并报错，而不是原样返回（fail-closed）。
掩码格式：[REDACTED:PROD_DB_URL]，保留变量名便于调试，不保留任何值片段（连后 4 位都不放，除非显式开启 maskTail: 4）。

威胁模型（写进 README，别回避）
威胁   缓解
模型上下文泄露   结构上不给值；只给变量名与掩码

命令输出回显密钥   §6 强制脱敏，fail-closed

Agent 主动 env / printenv / cat /proc/self/environ / ps eww dump   危险命令拦截（deny-list，可配置为 hard-block）+ 审计告警

同 UID 本地进程读 /proc/PID/environ   OS 层无法根治；用 §5.3 的 proxy/文件方案规避，文档明示边界

密钥长期驻留   会话 TTL、revoke、per-command 注入优先于 session 注入

规则写错导致全量注入   rule_validate 静态检查 + requireConfirm 高危规则人工确认

配置文件本身泄露   配置只存 ref，不存值；inline: 默认禁用

危险命令 deny-list 起步建议：env、printenv、set、export -p、declare -x、cat /proc/*/environ、pse、strings /proc/*/environ、以及 curl 到非白名单域（可选）。

技术选型

语言：TypeScript / Node 20+（MCP 生态最顺，@modelcontextprotocol/sdk）。
PTY：node-pty（注意需要原生编译；提供纯 child_process 降级路径，牺牲交互式能力）。
钥匙串：优先直接 spawn 系统命令（security find-generic-password / cmdkey / secret-tool），避免 keytar 已废弃带来的维护风险；或 @napi-rs/keyring。
加密文件后端：node:crypto AES-256-GCM，主密钥来自 keychain 或 MASTER_KEY 环境变量。
匹配：minimatch（glob）+ 自研命令模式匹配（支持 pnpm * 前缀通配）。
脱敏：ahocorasick 类实现或自写（值数量通常 <100，自写足够）。
审计：JSONL 追加写，字段 {ts, sessionId, ruleId, cwd, commandHash, command, injectedNames, exitCode, redactedCount}——command 存原文但先过 Redactor。
分发：npm + npx shell-mcp-secrets，附 Docker 镜像；提供 Claude Desktop / Cursor / VS Code 的 mcp 配置片段。

里程碑

M0 · 可行性验证（1–2 天）
跑通：读 keychain 一个值 → spawn 注入 → 执行 echo X → 断言返回值里不含明文（被脱敏）。
验证 node-pty 在目标平台的可用性。

M1 · MVP（1 周）
后端：encrypted-file + local-keychain。
工具：shell_exec、secret_list/set/delete/probe。
规则：仅 cwd 匹配 + inject 列表。
脱敏：精确值匹配 + 3 条通用正则。
审计 JSONL。
交付：可在 Claude Desktop 里配好并用起来。

M2 · 规则与运维（1 周）
持久会话（PTY + TTL + revoke）。
规则扩展：command / profiles / ttlSeconds / onMiss / requireConfirm。
rule_validate 静态告警、危险命令拦截。
流式脱敏 + URL/Base64 变体。

M3 · 生态与加固（2 周+）
后端插件：1Password / Infisical / Vault / Doppler（做成 Resolver 接口，插件式注册）。
credential proxy 模式（DB / HTTP 签名代理）。
策略引擎外置（可选 OPA/Rego 或自研 DSL）。
并发多会话、超时、资源上限、--dry-run。

测试要点（这块决定可信度）

泄露属性测试（最重要）：随机生成密钥值 → 跑各种命令（正常/报错/超时/大输出/二进制输出）→ 断言所有 tool 响应、日志、审计文件中零命中该值及其 URL/Base64 变体。
规则匹配单测：glob 边界、多规则命中顺序、override vs union。
脱敏单测：跨 chunk 切断、超长输出、非 UTF-8 字节流。
集成测试：真实 keychain（CI 上用 encrypted-file + 假主密钥）。
红队用例：让 Agent 尝试 env、printenv、cat /proc/self/environ，验证拦截 + 告警。

需要你尽早拍板的 4 个决策

持久会话要不要进 MVP？不进能省掉 PTY 原生依赖和一大半安全复杂度，建议 M1 先只做一次性命令。
注入粒度默认值：per-command（更安全）还是 per-session（更好用）？建议默认 per-command，session 显式开启。
是否允许 requireConfirm 走 MCP elicitation？依赖客户端支持，不支持时降级为"拒绝执行 + 提示用户改配置"。
命名：shell-mcp-secrets / envsafe-mcp / secretshell——建议名字里带 shell + secret，便于在 MCP 目录站被搜到（这也是你查重要顺手做的事）。

开工第一步（今天就能做）

mkdir shell-mcp-secrets && cd shell-mcp-secrets
npm init -y
npm i @modelcontextprotocol/sdk zod minimatch
npm i -D typescript tsx vitest @types/node

然后先写三件事，顺序不要变：
Resolver 接口 + encrypted-file 实现（含加解密与权限校验）；
Redactor + 它的属性测试（先写测试再写实现，这是整个项目的安全基石）；
shell_exec 把 1 和 2 串起来，跑通"注入 → 执行 → 输出无明文"的端到端断言。

这三步跑通，项目的核心价值就成立了，剩下的都是工程增量。

需要的话，我可以接着帮你写：rules.yaml 的完整 JSON Schema、Resolver/Redactor 的 TypeScript 接口定义，或者 M1 的目录骨架代码。

你希望我优先帮你写哪一部分？
rules.yaml 的 JSON Schema（MCP 工具校验用）
Resolver / Redactor 的 TypeScript 接口定义
M1 的目录骨架代码（含 tsconfig、入口、基础配置）
