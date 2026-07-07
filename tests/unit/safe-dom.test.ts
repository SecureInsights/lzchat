import { describe, expect, it } from "vitest";
import { isSafeDatasetKey } from "../../client/src/security/safe-dom";

describe("safe DOM helpers", () => {
  it("accepts only safe dataset keys", () => {
    expect(isSafeDatasetKey("clientId")).toBe(true);
    expect(isSafeDatasetKey("peer1")).toBe(true);
    expect(isSafeDatasetKey("__proto__")).toBe(false);
    expect(isSafeDatasetKey("constructor")).toBe(false);
    expect(isSafeDatasetKey("bad-key")).toBe(false);
    expect(isSafeDatasetKey("1bad")).toBe(false);
  });
});
