# syntax=docker/dockerfile:1
# vaultshell 多阶段构建：builder 跑 npm ci + tsc；runtime 只带 dist + 生产依赖。
#
# node-pty 决策：构建时 --omit=optional，镜像内不含 node-pty。
# 理由：容器里的 MCP stdio server 是无头环境，PTY 几乎没有收益；
# 而 node-pty 的 prebuild/spawn-helper 在容器构建中是最常见的失败点
# （参见 ci.yml 里 spawn-helper 执行位的坑）。会话（shell_session_*）
# 在镜像内自动降级为 child_process 管道模式（pty:false），注入与脱敏不变。

FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
# --ignore-scripts：npm ci 会触发本包的 prepare（tsc build），
# 此时 tsconfig/src 还没拷进来，必失败；build 在 COPY src 后显式跑。
RUN npm ci --legacy-peer-deps --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build \
  && npm prune --omit=dev --omit=optional

FROM node:22-bookworm-slim AS runtime
# MCP Registry 要求的所有权标注
LABEL io.modelcontextprotocol.server.name="io.github.SoWhatI/vaultshell"
ENV NODE_ENV=production \
    HOME=/home/node
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY web ./web
COPY package.json ./
USER node
# 数据目录（挂载示例：-v ~/.vaultshell:/home/node/.vaultshell）
VOLUME ["/home/node/.vaultshell"]
# 默认 stdio MCP server；`docker run <img> web --port 5317` 可透传 web 子命令
ENTRYPOINT ["node", "dist/index.js"]
