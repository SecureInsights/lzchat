const baseUrl = process.env.SECURE_CHAT_SMOKE_URL ?? "http://127.0.0.1:8088";
const response = await fetch(`${baseUrl}/api/health`);
if (!response.ok) {
  throw new Error(`health failed: ${response.status}`);
}
const body = await response.json();
if (!body.ok || body.protocol !== 3) {
  throw new Error(`unexpected health body: ${JSON.stringify(body)}`);
}
console.warn("local smoke ok");
