import type { ServerResponse } from "node:http";

const STRICT_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'"
].join("; ");

export const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(self), microphone=(self), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": STRICT_CSP
};

export function applySecurityHeaders(
  res: ServerResponse,
  options: { allowInsecureWebSocket?: boolean; upgradeInsecureRequests?: boolean } = {}
): void {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    if (name === "Content-Security-Policy") {
      const csp = options.allowInsecureWebSocket
        ? value.replace("connect-src 'self'", "connect-src 'self' ws: wss:")
        : value;
      res.setHeader(name, options.upgradeInsecureRequests ? `${csp}; upgrade-insecure-requests` : csp);
    } else {
      res.setHeader(name, value);
    }
  }
  if (options.upgradeInsecureRequests) {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
}
