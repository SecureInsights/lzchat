# Secure Chat

高保密临时端到端加密聊天系统。第一屏就是创建或加入房间入口，不做账号、历史消息、离线消息或服务端搜索。

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/SecureInsights/lzchat)

## 当前实现范围

已实现：

- 256-bit `roomSeed`，不从房间名或用户密码直接派生房间 ID。
- 隐私性双通道邀请和公开单链接邀请。
- 邀请弹窗支持本地二维码生成、扫码分享和点击复制二维码图片；隐私性邀请仍需单独复制安全秘钥。
- 邀请 URL fragment 读取后立即清理，秘密不进入 HTTP 请求。
- WebCrypto P-256 ECDH pairwise 会话。
- HKDF domain separation。
- 每个 peer 独立发送/接收 chain key。
- 每条 relay 消息独立 message key、AAD 绑定和 AES-GCM 加密。
- replay / out-of-order window 基础处理。
- profile、文本、私聊、图片和文件 envelope 加密。
- 图片粘贴、附件上传、图片消息直接预览和点击查看。
- 文件分片传输、大小限制、接收端队列配额和 SHA-256 完整性校验。
- 私聊和房间内实验性语音/视频通话、来电铃声、接听/拒绝/挂断状态同步和基础资源清理。
- 房间通话可邀请在线成员，接听者会加入同一场 callId，挂断只移除当前参与者；发起者结束或最后一个参与者离开时整场结束。
- 通话媒体 relay 使用独立密文大小上限、独立速率/字节窗口、控制消息重放窗口和端到端校验失败静默丢弃。
- WebSocket 客户端应用层心跳，降低长时间通话或空闲房间被 90 秒连接超时误踢的概率。
- 复杂 NAT 下不依赖点对点直连；实时媒体经现有 WebSocket `call-media` 中继逐个 peer 加密转发。
- 视频通话按参与者数量和 WebSocket 缓冲自动选择 640x360/480x270/360x202 档位，并在拥塞时跳帧降低发送压力。
- 可选桌面通知和声音提示；桌面通知不展示消息正文。
- 成员安全码和房间安全码展示。
- 本地 emoji 数据，不使用运行时 CDN。
- 桌面和移动端聊天界面适配，包括顶部横向成员列表、独立滚动消息区、固定输入栏和移动端通话全屏面板。
- 消息发送后输入框保持聚焦，桌面端连续输入不需要重新点击输入栏。
- Cloudflare Workers + Static Assets + Durable Objects 配置。
- 本地 Node 原生 WebSocket relay，无运行时依赖。
- CSP 和安全响应头不包含 `unsafe-inline`。
- Vitest 协议单元测试、Playwright 页面 smoke、local/worker health smoke。

仍未实现或仍需加强：

- Argon2id 邀请 KDF。
- 长期 identity key、签名身份和 WebAuthn 设备记忆。
- 可持久化的人工核对状态。
- cover traffic。
- 流式文件读写、附件进度和断点重试。
- 私聊、附件、篡改、重放、服务端滥用的完整 E2E 回归。
- 通话目前是实验性实时媒体能力，仍需要在真实移动网络、弱网和 Cloudflare 生产环境中继续压测。
- 专用 TURN/WebRTC SFU、MoQ/WebTransport 媒体服务和服务端混流/转码。

最新安全审计结论见 [SECURITY_AUDIT.md](./SECURITY_AUDIT.md)。

## 协议说明

1. 邀请 KDF 的当前实现为 WebCrypto 原生 `PBKDF2-SHA256`，默认迭代数 600,000，并允许后续 capsule 使用更高迭代数。这样可以避免为了 Argon2id 引入运行时 WASM/CDN。协议类型保留 `argon2id`，后续可在锁定 WASM 依赖和审计 lockfile 后切换。
2. 本地 Node relay 使用原生 HTTP upgrade 和 WebSocket 帧解析。部署形态仍保留 Cloudflare Worker/Durable Object；本地 smoke 不依赖 `ws` 包安装。
3. 接收 ratchet 在解密失败时会把未接受的 skipped key 放回窗口，避免攻击者用未来序号坏密文让接收端永久失步。
4. HKDF 调用必须显式传入 salt；房间派生使用固定 domain salt，消息 ratchet 使用独立 domain salt，pairwise/nonce 派生使用 room/transcript/AAD 上下文 salt。
5. 当前 ratchet 提供会话内消息链前向安全：泄露当前 chain key 不能反推已擦除的历史 message key。但它不是完整 Double Ratchet；如果同时泄露房间秘密、会话私钥并掌握历史密文，历史消息风险会显著上升。
6. 客户端已加入应用层 `ping` 心跳。Worker 和本地 Node relay 只验证版本、`roomId` 和 `clientId`，用于刷新连接活跃时间；服务端不会把心跳广播给其他成员，也不会接触任何明文聊天内容。
7. 语音/视频通话走 `call-control` 和 `call-media` envelope。控制消息有短窗口重放防护，媒体消息有独立密文大小上限和速率桶，避免实时媒体把普通聊天 relay 限流逻辑冲垮。
8. 房间通话不是 WebRTC mesh，也不需要 TURN。客户端对每个参与者单独加密并通过 Worker/Node relay 转发媒体，因此可以穿过复杂 NAT，但上行带宽会随参与者数量线性增加。

注意：HKDF salt 硬化会改变新版本的房间派生结果，旧版本生成的邀请链接不保证能与新版本互通。

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

## 自动部署

如果在 Cloudflare Workers 里连接 GitHub 仓库，后续更新流程是：

1. 修改代码并 push 到 GitHub 默认分支。
2. Cloudflare 检测到新的 commit。
3. Cloudflare 按项目设置执行安装和构建命令。
4. 构建成功后自动发布新 Worker 和静态资源。

推荐 Cloudflare 构建配置：

```text
Install command: npm ci
Build command: npm run build
Deploy command: npx wrangler deploy
Output directory: dist
```

`wrangler.toml` 已配置 Static Assets、`/ws*`、`/api/*` 和 Durable Objects。通常不需要额外配置前端路由。

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
- 安全码只能辅助核对当前会话密钥或当前对端指纹，不能证明真实身份。
- 隐私性模式使用时，应通过两条独立渠道分别发送邀请链接和口令。
- 二维码只用于分享邀请链接；隐私性模式的安全秘钥不能放进二维码，应继续通过另一渠道发送。
- 部署方、恶意浏览器扩展、被控设备和同房间恶意成员不在 Web 页面可完全防御范围内。
- 当前没有长期身份签名，恶意服务端或恶意前端替换成员公钥时，只能依赖用户通过外部渠道核对安全码发现异常。
- 开启桌面通知后，操作系统通知中心可能看到发送者名称、房间/私聊标记和消息类型；通知正文不会包含消息明文。

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
- `npm audit --audit-level=moderate` 无 moderate/high/critical。
- `npm run lint`、`npm test`、`npm run build`、`npm run test:e2e` 通过。
- `debug=false`。
- Vite `sourcemap=false`，除非确认 source map 不泄露敏感路径。
- CSP 没有 `script-src 'unsafe-inline'`。
- 没有 console 输出明文和密钥。
- 没有 CDN 运行时依赖。
- Worker 和 Node 协议版本一致。
- 邀请链接 fragment 不进入 HTTP 请求。

## 未来可增加的功能点

- 通话进阶：成员选择、通话中邀请新成员、专用 MoQ/WebTransport 媒体服务、服务端 SFU/混流和更细的弱网自适应。
