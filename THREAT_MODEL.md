# Threat Model

## Assets

- 文本消息。
- 图片和文件内容。
- 文件名、MIME、大小和 hash 等元数据。
- profile 显示名和头像种子。
- roomSeed、roomSecret、roomPsk、pairwise root key、chain key、message key。
- 邀请链接和双通道口令。

## Assumed Attacker Capabilities

攻击者可能：

- 监听网络流量。
- 控制或观察 Worker 日志。
- 连接同一个公开服务端。
- 构造恶意 WebSocket 消息。
- 重放、乱序、延迟、丢弃 relay 消息。
- 枚举 roomId。
- 发送超大 payload 或高频消息消耗资源。
- 尝试 XSS、文件名注入、HTML 注入、URL 注入。
- 获取用户复制出去的邀请链接。
- 作为恶意成员加入同一个房间。

## Server Boundary

服务端只允许：

- 校验路径、Upgrade、roomId、clientId、消息大小和消息类型。
- 维护在线成员列表。
- 广播临时公钥。
- 转发密文 envelope。
- 限流和关闭异常连接。
- 返回安全响应头和 `/api/health`。

服务端禁止：

- 接收房间明文名或用户密码。
- 生成、保存或派生聊天密钥。
- 解密消息。
- 保存聊天历史。
- 将密文内容写入日志。
- 将 query/hash 中的秘密写入日志。

## Client Boundary

客户端负责：

- 生成 256-bit roomSeed。
- 解析邀请并派生 room secret。
- 生成临时 ECDH key pair。
- 与每个 peer 建立 pairwise key。
- 持续演进消息 chain key。
- 加密 profile 和消息。
- 展示安全码。
- 清理 URL fragment。
- 使用安全 DOM API 渲染用户输入。

## Explicit Limitations

- Web E2EE 的前提是用户信任当前加载的前端代码。
- 临时聊天不是匿名通信网络，服务端仍可看到 IP、连接时间、消息大小和房间活跃度。
- 安全码只能确认当前会话或对端指纹，不能证明真实身份。
- 浏览器 JavaScript 不能保证强内存擦除。
- 如果最高保密需求不能接受这些风险，应改用原生客户端、可验证构建、代码签名、透明日志或专用匿名网络。

## KDF Decision

目标协议建议 Argon2id。当前 MVP 默认 PBKDF2-SHA256，是为了避免在未审计依赖和未锁定 WASM 加载策略前引入额外攻击面。`InviteCapsule.kdf` 已保留 `argon2id` 扩展，切换前必须完成：

- 固定依赖版本并提交 lockfile。
- 禁止 CDN 运行时代码。
- 确认 CSP 只允许同源 WASM。
- 添加 Argon2id 测试向量。
- 在 README 中标注内存和耗时参数。
