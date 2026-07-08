import { describe, expect, it } from "vitest";
import { sanitizeDownloadFileName } from "../../client/src/security/download";

describe("safe download names", () => {
  it("strips broad filename characters", () => {
    expect(sanitizeDownloadFileName("my report (final).txt")).toBe("my_report_final_.txt");
    expect(sanitizeDownloadFileName("../../secret.txt")).toBe("secret.txt");
  });

  it("neutralizes active content extensions", () => {
    expect(sanitizeDownloadFileName("payload.html")).toBe("payload.html.download");
    expect(sanitizeDownloadFileName("icon.svg")).toBe("icon.svg.download");
    expect(sanitizeDownloadFileName("script.js")).toBe("script.js.download");
  });
});
