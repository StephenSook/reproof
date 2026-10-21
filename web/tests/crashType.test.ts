import { describe, expect, it } from "vitest";

import { displayCrashType } from "@/lib/crashType";

describe("displayCrashType", () => {
  it("names ClusterFuzz's any-size marker in words", () => {
    expect(displayCrashType("Heap-buffer-overflow WRITE {*}")).toBe("Heap-buffer-overflow WRITE (any size)");
  });

  it("leaves a crash type with a size, or with no marker, unchanged", () => {
    expect(displayCrashType("Heap-buffer-overflow READ 1")).toBe("Heap-buffer-overflow READ 1");
    expect(displayCrashType("Stack-buffer-overflow")).toBe("Stack-buffer-overflow");
  });
});
