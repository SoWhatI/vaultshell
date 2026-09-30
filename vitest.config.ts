import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // 会话测试涉及真实 PTY/shell 启动与 TTL 等待，放宽超时
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
