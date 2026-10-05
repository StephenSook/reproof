import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: { tsconfigPaths: true },
  test: {
    include: ["tests/**/*.test.ts"],
    exclude: ["tests/e2e/**", "node_modules/**"],
    environment: "node",
  },
});
