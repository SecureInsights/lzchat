# Secure Chat

高保密临时端到端加密聊天系统。第一屏就是创建/加入房间入口，不做账号、历史消息、离线消息或服务端搜索。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/SecureInsights/lzchat)

## 当前实现范围

已实现 MVP 核心：

- 256-bit `roomSeed`，不从房间名或用户密码直接派生房间 ID。
- 单链接邀请和双通道邀请。
- URL fragment 读取后立即清理，秘密不进入 HTTP 请求。
- WebCrypto P-256 ECDH pairwise 会话。
- HKDF domain separation。
- 每个 peer 独立发送/接收 chain key。
- 每条 relay 消息独立 message key、AAD 绑定和 AES-GCM 加密。
- replay / out-of-order window 基础处理。
- profile 和文本消息加密。
- 成员安全码和房间安全码。
- Cloudflare Workers + Static Assets + Durable Objects 配置。
- 本地 Node 原生 WebSocket relay，无运行时依赖。
- CSP 和安全响应头不包含 `unsafe-inline`。
- Vitest 单元测试和 Playwright 空页面 E2E smoke。

协议类型已预留图片、文件和私聊 envelope。完整文件分片、图片压缩、长期 identity key、WebAuthn 设备记忆和 cover traffic 属于后续阶段。

## 规格优化

1. 邀请 KDF 的 MVP 默认实现为 WebCrypto 原生 `PBKDF2-SHA256`，迭代数 600,000。这样可以避免为了 Argon2id 引入运行时 WASM/CDN。协议类型保留 `argon2id`，后续可在锁定 WASM 依赖和审计 lockfile 后切换。
2. 本地 Node relay 使用原生 HTTP upgrade 和 WebSocket 帧解析。部署形态仍保留 Cloudflare Worker/Durable Object；本地 smoke 不依赖 `ws` 包安装。
3. 接收 ratchet 在解密失败时会把未接受的 skipped key 放回窗口，避免攻击者用未来序号坏密文让接收端永久失步。

## 安装与运行

需要 Node.js 22.12+。

```bash
npm install
npm run build
npm test
```

本地运行：

```bash
npm run dev:local
curl -i http://127.0.0.1:8088/api/health
```

浏览器 E2E 默认会优先使用系统 Chrome/Chromium。可手动指定：

```bash
PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium npm run test:e2e
```

如果系统没有浏览器，可使用国内镜像下载 Playwright Chromium：

```bash
npm run pw:install:mirror
```

Cloudflare：

```bash
npm run deploy
npm run smoke:worker -- --url=https://<worker-domain>
```

## 环境变量

```text
SECURE_CHAT_HOST=127.0.0.1
SECURE_CHAT_PORT=8088
SECURE_CHAT_DIST=./dist
SECURE_CHAT_DEBUG=0
```

## 安全边界

- Web E2EE 的前提是用户信任当前加载的前端代码。
- 临时聊天不是匿名通信网络。服务端仍可看到 IP、连接时间、消息大小、roomId 和房间活跃度。
- 安全码只能确认当前会话密钥或当前对端指纹，不能证明真实身份。
- 高保密使用时，应通过两条独立渠道分别发送邀请链接和口令。
- 部署方、恶意浏览器扩展、被控设备和同房间恶意成员不在 Web 页面可完全防御范围内。

## 部署结构

```text
browser client
  |
  | HTTPS static assets
  | WSS /ws?room=<roomId>
  v
Cloudflare Worker
  |
  | Durable Object namespace by roomId
  v
ChatRoom Durable Object
  |
  | encrypted relay only
  v
other browser clients
```

本地：

```text
browser client
  |
  | http://127.0.0.1:8088
  | ws://127.0.0.1:8088/ws?room=<roomId>
  v
Node static + WebSocket relay server
```

## 发布前检查

- `npm ci` 使用 lockfile。
- `npm audit --audit-level=moderate` 无 high/critical。
- `debug=false`。
- CSP 没有 `script-src 'unsafe-inline'`。
- 没有 console 输出明文和密钥。
- 没有 CDN 运行时依赖。
- Worker 和 Node 协议版本一致。
- E2E 双客户端测试通过。
- 邀请链接 fragment 不进入 HTTP 请求。
