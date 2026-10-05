import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const webRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");

describe("live probe", () => {
  it("exits 2 when the door URL is missing", () => {
    for (const args of [[], ["   "]]) {
      const result = spawnSync(process.execPath, ["scripts/agent-check.mjs", ...args], {
        cwd: webRoot,
        encoding: "utf8",
      });
      expect(result.status).toBe(2);
      expect(result.stderr).toContain("Usage: node scripts/agent-check.mjs <base-url>");
      expect(result.stdout).toBe("");
    }
  });
});
