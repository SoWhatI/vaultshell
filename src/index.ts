#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildContext } from "./context.js";
import { registerTools } from "./tools.js";

// argv 分发：`vaultshell web [--port N]` 起 Web 配置界面；不带子命令 = MCP stdio
if (process.argv[2] === "web") {
  const { startWebServer } = await import("./web/server.js");
  const portIdx = process.argv.indexOf("--port");
  const port = portIdx >= 0 ? parseInt(process.argv[portIdx + 1] ?? "", 10) : undefined;
  if (port !== undefined && (!Number.isInteger(port) || port < 0 || port > 65535)) {
    console.error("[vaultshell] --port must be an integer 0-65535 (0 = random)");
    process.exit(2);
  }
  const ctx = buildContext();
  const handle = await startWebServer(ctx, port !== undefined ? { port } : {});
  console.error(`[vaultshell] web config UI listening (loopback only, token dies with this process):`);
  console.error(`  ${handle.url}`);
  console.error(`[vaultshell] do NOT port-forward or expose this port. Ctrl-C to stop.`);
} else {
  const ctx = buildContext();

  if (ctx.config.defaults.allowInline) {
    console.error(
      "[vaultshell] WARNING: defaults.allowInline is true — inline: refs carry PLAINTEXT " +
        "secrets in rules.yaml. This is intended for dev only.",
    );
  }

  const server = new McpServer({
    name: "vaultshell",
    version: "0.1.0",
  });

  registerTools(server, ctx);

  await server.connect(new StdioServerTransport());
  console.error(`[vaultshell] serving on stdio (home: ${ctx.home}, backend: ${ctx.defaultBackend.scheme})`);
}
