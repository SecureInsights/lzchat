import { createReadStream } from "node:fs";
import { access, stat } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import path from "node:path";
import { applySecurityHeaders } from "./security-headers.js";

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon"
};

function isHttpsRequest(req: IncomingMessage): boolean {
  return req.headers["x-forwarded-proto"] === "https";
}

export function sendJson(req: IncomingMessage, res: ServerResponse, status: number, body: unknown): void {
  const isHttps = isHttpsRequest(req);
  applySecurityHeaders(res, { allowInsecureWebSocket: !isHttps, upgradeInsecureRequests: isHttps });
  res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(body));
}

function safePath(distDir: string, pathname: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
    if (decoded.includes("\0") || decoded.includes("..")) return null;
  } catch {
    return null;
  }
  const normalized = path.normalize(decoded).replace(/^(\.\.(\/|\\|$))+/u, "");
  const relative = normalized === "/" ? "index.html" : normalized.replace(/^[/\\]+/u, "");
  const resolved = path.resolve(distDir, relative);
  const root = path.resolve(distDir);
  return resolved === root || resolved.startsWith(`${root}${path.sep}`) ? resolved : null;
}

export async function serveHttp(req: IncomingMessage, res: ServerResponse, distDir: string): Promise<void> {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  if (url.pathname === "/api/health") {
    sendJson(req, res, 200, { ok: true, protocol: 3 });
    return;
  }
  if (url.pathname.startsWith("/api/")) {
    sendJson(req, res, 404, { error: "not_found" });
    return;
  }
  if (url.pathname === "/ws") {
    sendJson(req, res, 426, { error: "upgrade_required" });
    return;
  }
  const direct = safePath(distDir, url.pathname);
  const indexPath = path.resolve(distDir, "index.html");
  let filePath = direct;
  if (!filePath) {
    sendJson(req, res, 400, { error: "bad_path" });
    return;
  }
  try {
    const info = await stat(filePath);
    if (info.isDirectory()) {
      filePath = path.join(filePath, "index.html");
    }
    await access(filePath);
  } catch {
    filePath = indexPath;
  }
  try {
    const isHttps = isHttpsRequest(req);
    applySecurityHeaders(res, { allowInsecureWebSocket: !isHttps, upgradeInsecureRequests: isHttps });
    const ext = path.extname(filePath);
    res.writeHead(200, { "content-type": MIME_TYPES[ext] ?? "application/octet-stream" });
    createReadStream(filePath).pipe(res);
  } catch {
    sendJson(req, res, 404, { error: "not_found" });
  }
}
