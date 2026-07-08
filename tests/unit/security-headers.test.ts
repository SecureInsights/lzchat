import { describe, expect, it } from "vitest";
import { SECURITY_HEADERS as SERVER_SECURITY_HEADERS } from "../../server/src/security-headers";
import { SECURITY_HEADERS as WORKER_SECURITY_HEADERS } from "../../worker/src/security-headers";

describe("security headers", () => {
  it("allows same-origin camera and microphone for encrypted calls", () => {
    expect(SERVER_SECURITY_HEADERS["Permissions-Policy"]).toContain("camera=(self)");
    expect(SERVER_SECURITY_HEADERS["Permissions-Policy"]).toContain("microphone=(self)");
    expect(WORKER_SECURITY_HEADERS["Permissions-Policy"]).toContain("camera=(self)");
    expect(WORKER_SECURITY_HEADERS["Permissions-Policy"]).toContain("microphone=(self)");
  });

  it("keeps geolocation disabled", () => {
    expect(SERVER_SECURITY_HEADERS["Permissions-Policy"]).toContain("geolocation=()");
    expect(WORKER_SECURITY_HEADERS["Permissions-Policy"]).toContain("geolocation=()");
  });
});
