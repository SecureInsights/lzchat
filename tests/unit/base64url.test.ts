import { describe, expect, it } from "vitest";
import { base64urlDecode, base64urlEncode, base64urlFromString, stringFromBase64url } from "../../client/src/crypto/base64url";

describe("base64url", () => {
  it("round-trips bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 253, 254, 255]);
    expect(base64urlDecode(base64urlEncode(bytes))).toEqual(bytes);
  });

  it("round-trips strings without padding", () => {
    const encoded = base64urlFromString("hello/安全");
    expect(encoded).not.toContain("=");
    expect(stringFromBase64url(encoded)).toBe("hello/安全");
  });

  it("rejects invalid alphabet", () => {
    expect(() => base64urlDecode("abc$")).toThrow();
  });
});
