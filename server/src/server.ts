import { createServer } from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RelayHub } from "./relay.js";
import { sendJson, serveHttp } from "./static.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const host = process.env.SECURE_CHAT_HOST ?? "127.0.0.1";
const port = Number.parseInt(process.env.SECURE_CHAT_PORT ?? "8088", 10);
const distDir = path.resolve(process.env.SECURE_CHAT_DIST ?? path.join(__dirname, "../../dist"));
const allowedOrigins = (process.env.SECURE_CHAT_ORIGINS ?? "").split(",").map(s => s.trim()).filter(Boolean);
const hub = new RelayHub(allowedOrigins);

const server = createServer((req, res) => {
  void serveHttp(req, res, distDir).catch(() => {
    if (!res.headersSent) {
      sendJson(req, res, 500, { error: "internal_error" });
    } else {
      res.destroy();
    }
  });
});

server.on("upgrade", (req, socket) => {
  hub.handleUpgrade(req, socket);
});

server.listen(port, host, () => {
  console.warn(`secure-chat local relay listening on http://${host}:${port}`);
});

function shutdown(): void {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5_000);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
