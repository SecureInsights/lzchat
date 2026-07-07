import type { ServerResponse } from "node:http";

export const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self' ws: wss:",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'none'"
  ].join("; ")
};

export function applySecurityHeaders(res: ServerResponse, options: { upgradeInsecureRequests?: boolean } = {}): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (name === "Content-Security-Policy" && options.upgradeInsecureRequests) {
      res.setHeader(name, `${value}; upgrade-insecure-requests`);
    } else {
      res.setHeader(name, value);
    }
  }
  if (options.upgradeInsecureRequests) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}
