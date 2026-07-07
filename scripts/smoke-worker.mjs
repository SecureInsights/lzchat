const urlArg = process.argv.find((arg) => arg.startsWith("--url="));
const baseUrl = urlArg?.slice("--url=".length) ?? process.env.SECURE_CHAT_WORKER_URL;
if (!baseUrl) {
  throw new Error("usage: npm run smoke:worker -- --url=https://example.workers.dev");
}
const response = await fetch(`${baseUrl.replace(/\/$/u, "")}/api/health`);
if (!response.ok) {
  throw new Error(`health failed: ${response.status}`);
}
const body = await response.json();
if (!body.ok || body.protocol !== 3) {
  throw new Error(`unexpected health body: ${JSON.stringify(body)}`);
}
console.warn("worker smoke ok");
