# Security Policy

## Supported Versions

当前仓库处于 MVP 开发阶段，只支持最新 `main`。

## Reporting

请不要在公开 issue 中提交可利用细节。漏洞报告应包含：

- 影响范围。
- 复现步骤。
- 预期行为和实际行为。
- PoC 是否会泄露明文、密钥、profile 或可加入房间的秘密。

## Cryptographic Notes

- MVP 双通道 invite 使用 WebCrypto `PBKDF2-SHA256`，迭代数 600,000。
- 消息层使用 P-256 ECDH、HKDF-SHA256 和 AES-GCM。
- 所有密钥派生使用 `secure-chat/v3/...` label 做 domain separation。
- 默认不持久化 roomSeed、roomSecret、roomPsk、session private key 或 chain key。
- 生产部署不得启用 source map，除非确认不泄露敏感路径。

## Out of Scope

- 恶意部署方替换前端 JavaScript。
- 用户设备被恶意软件控制。
- 浏览器扩展读取页面内容。
- 用户同时泄露链接和口令。
- 恶意成员截图、复制或转发明文。
- 通过流量大小、连接时间和房间人数做元数据分析。
