# Security Audit Report

审计日期：2026-07-07  
审计对象：当前工作树，基于 `19fa472` (`Add encrypted attachments and image viewer`)  
审计范围：浏览器端协议与 UI、Cloudflare Worker relay、本地 Node relay、测试与部署配置、公开文档。  
审计方式：手工代码审计、危险 API 搜索、协议路径检查、测试/构建/依赖审计。

## 总体结论

当前代码没有发现服务端接收明文消息、明文文件、房间密码或房间明文名的路径。Worker 和 Node relay 都只校验 envelope、成员状态、消息大小和速率，然后盲转发密文。前端没有发现 `innerHTML`、`eval`、`new Function`、`javascript:` URL 或运行时 CDN 依赖。

本次修复已关闭附件接收端资源配额、Worker roomId 防御检查、文件配置漂移、HKDF 隐式零 salt、PBKDF2 迭代不可升级、CSP、dataset key 和冗余 membership 判断等问题。仍未完全关闭的风险集中在身份认证能力、Argon2id KDF 和测试覆盖。

## 本次验证结果

| 命令 | 结果 | 说明 |
| --- | --- | --- |
| `npm run lint` | Pass | ESLint 通过 |
| `npm test` | Pass | 6 个测试文件、19 个用例通过 |
| `npm run build` | Pass | client、worker、server 构建通过；本机 Node 20.15.1 低于项目推荐版本，Vite 输出版本警告 |
| `npm audit --audit-level=moderate` | Pass | 0 vulnerabilities |
| `npm run test:e2e` | Not completed | 当前机器没有系统 Chrome/Chromium，Playwright 浏览器缓存也未安装；未作为通过项计入 |

## 风险概览

| ID | 等级 | 状态 | 问题 |
| --- | --- | --- | --- |
| SA-M01 | Medium | Open | 没有长期身份签名和持久化核对状态，安全码只能手工发现公钥替换 |
| SA-M02 | Medium | Fixed | 文件接收端已增加 per-peer/global 并发和 pending bytes 上限 |
| SA-M03 | Medium | Open | 双通道邀请使用 PBKDF2-SHA256，低熵用户口令在 capsule 泄露后仍有离线猜解风险 |
| SA-M04 | Medium | Fixed | HKDF 不再使用隐式零 salt，调用点改为显式 domain/context salt |
| SA-M05 | Medium | Fixed | PBKDF2 capsule 迭代数支持向上升级，并拒绝降级 |
| SA-L01 | Low | Open | 大文件分片和多成员房间容易触发 relay 速率限制，影响可用性 |
| SA-L02 | Low | Fixed | Worker Durable Object 已拒绝不一致 roomId |
| SA-L03 | Low | Fixed | 已删除未使用的旧文件分片配置 |
| SA-L04 | Low | Open | E2E/滥用测试不足，私聊、附件、篡改、重放没有完整自动化覆盖 |
| SA-L05 | Low | Fixed | 恶意附件 payload 的非法 base64url 长度已在 validator 层拒绝 |
| SA-L06 | Low | Fixed | P-256 无效公钥点由 WebCrypto importKey 拒绝，并补测试覆盖 |
| SA-L07 | Low | Fixed | 图片 MIME subtype 正则已收紧 |
| SA-L08 | Low | Fixed | Worker/生产 CSP 已移除 `ws:` 与 `upgrade-insecure-requests` 的冲突 |
| SA-L09 | Low | Fixed | `setDataset` 已增加 key 名称校验 |
| SA-L10 | Low | Fixed | relay 房间人数上限检查中的冗余条件已清理 |

## 已确认的安全控制

- 房间秘密由 32 字节随机 `roomSeed` 产生，不从房间显示名或用户口令直接派生。
- 邀请 secret 只放在 URL fragment，进入页面后会清理地址栏 fragment。
- 双通道邀请 capsule 使用独立口令派生 wrap key 后再 AES-GCM 加密。
- HKDF 调用必须显式传入 salt；房间、ratchet、pairwise、nonce 派生都有明确 domain/context salt。
- Pairwise 会话使用浏览器 WebCrypto P-256 ECDH、HKDF 和 AES-GCM。
- 每个 peer 维护独立发送/接收 chain key，消息密钥按序号演进。
- Relay AAD 绑定 `roomId`、`from`、`to`、`kind`、`seq` 和 transcript hash。
- 接收端有 replay/out-of-order window，解密失败不会把具体原因暴露为协议 oracle。
- profile、文本、私聊、图片、文件 metadata/chunk/done 都走加密 envelope。
- 图片只允许常见位图 MIME，不允许 SVG 作为内联预览。
- 文件接收端限制每个 peer 3 个、全局 12 个未完成文件，并限制全局预留大小和已缓存 chunk 字节数。
- 文件最终下载前校验 SHA-256，文件名通过安全下载封装处理。
- DOM 渲染使用 `textContent`、`createElement`、`addEventListener`，没有发现危险 HTML 注入路径。
- CSP 为 `script-src 'self'`、`style-src 'self'`，未使用 `unsafe-inline`。
- Vite 生产构建关闭 source map。
- Worker 和 Node relay 均校验 `roomId`、`clientId`、`from`、`to`、`kind`、`seq`、`nonce`、`ct`、房间人数和消息速率。
- 关闭连接时按 socket identity 删除成员，避免旧 socket 误删新连接。

## 详细发现

### SA-M01: 缺少可认证身份和持久化核对状态

当前成员安全码可以帮助用户通过外部渠道核对会话公钥，但代码没有长期 identity key、签名绑定，也没有“已核对”状态。恶意服务端、恶意前端或被控制的成员列表可以替换临时 `sessionPub`，用户只有主动比较安全码才能发现。

影响：不能抵抗恶意部署方或主动 MITM 的静默公钥替换。  
建议：增加可选长期 identity key，使用 Ed25519 或 WebCrypto 支持的签名方案绑定 session key；恢复本地“已核对”标记；在成员公钥变化时给出强提示。

### SA-M02: 文件接收端资源上限不足

状态：Fixed。

发送端限制单文件 25MB、单批 10 个、总大小 100MB，接收端也校验单文件大小和 chunk 大小。本次修复增加了接收端配额：每个 peer 最多 3 个未完成文件、全局最多 12 个未完成文件、全局预留大小 100MB、全局已缓存 chunk 64MB。超时、拒收、完整性失败和离开房间时会清理并尽量擦除已收到的 chunk。

剩余建议：后续可把文件接收改为流式或 OPFS/IndexedDB 临时存储，降低大文件内存峰值。

### SA-M03: 邀请 KDF 不是 Argon2id

协议设计保留 `argon2id`，当前实现为 PBKDF2-SHA256 600,000 次。对自动生成的高熵口令风险较低；如果用户输入低熵口令，一旦 capsule 泄露，攻击者可以进行离线猜解。

影响：低熵口令下双通道 capsule 抗离线暴力能力弱于设计目标。  
建议：默认继续生成高熵口令；UI 对短口令给出强警告；后续引入固定版本的 Argon2id WASM，禁止 CDN，并把 lockfile 纳入审计。

### SA-L01: 大文件分片可能触发速率限制

文件发送按 256KB 分片，并按成员数增加延迟。大文件、多成员或慢网络下，仍可能触发服务端 10 秒 100 条消息的限制，导致文件传输失败。

影响：可用性问题，不直接影响保密性。  
建议：实现基于服务端限制的发送队列和 backpressure；对大文件显示进度、暂停/重试；将文件 relay 速率和普通文本速率分桶。

### SA-L02: Worker `roomId` 字段建议防御式固定

状态：Fixed。

Durable Object 通过 `idFromName(roomId)` 绑定房间，正常情况下一个实例只处理一个房间。本次修复加入防御式检查：实例已绑定 `#roomId` 后，如果后续请求携带不同 roomId，会返回 `409 room_mismatch`。

### SA-L03: 文件配置存在漂移

状态：Fixed。

已删除 `client/src/config.ts` 中未使用的旧 `FILE_LIMITS` 配置，避免后续维护误读。

### SA-L04: 自动化测试覆盖不足

当前单元测试覆盖 base64url、invite、pairwise crypto、envelope validator、ratchet。Playwright E2E 目前只验证创建入口加载。私聊、图片、文件、剪贴板图片、篡改、重放、错误口令、服务端滥用场景还未形成完整自动化回归。

影响：新增功能回归风险较高，尤其是附件和私聊路径。  
建议：补充双客户端 E2E、附件 hash 校验、私聊第三方不可见、AAD/ciphertext 篡改、旧 seq 重放、错误口令、未 join relay、超大 payload、重复 clientId 等测试。

### SA-L05: 恶意附件 payload 非法 base64url 长度

状态：Fixed。

附件明文 payload 的 `bytes` 字段原先只校验 base64url 字符集和最大长度，未拒绝长度 `mod 4 == 1` 的非法 base64url 字符串。恶意成员可以发送可解密但字段非法的附件 payload，使接收端在后续解码时抛错。本次修复把非法长度拒绝前移到 `validatePlainPayload`，并在图片/文件处理路径保留受控解码兜底。

### SA-M04: HKDF 隐式零 salt

状态：Fixed。

`hkdf` 不再接受 `null` salt，也不再内部生成零字节默认 salt。房间秘密、roomId、roomPsk、rosterKey、fileKey、ratchet message key 和 chain key 都改为显式 domain/context salt。注意：此修复会改变新版本的房间派生结果，旧版本生成的邀请链接不保证能与新版本互通。

### SA-M05: PBKDF2 迭代次数不可升级

状态：Fixed。

双通道邀请仍默认使用 PBKDF2-SHA256 600,000 次，但 capsule 现在允许 `600,000..5,000,000` 范围内的安全迭代数。旧的 600,000 次 capsule 仍可打开，低于最小值的降级 capsule 会被拒绝。

### SA-L06: P-256 公钥点有效性

状态：Fixed。

客户端继续在导入前检查 raw P-256 公钥必须是 65 字节 uncompressed point，并依赖 WebCrypto `importKey` 对曲线成员进行验证。本次补充了无效零点被拒绝的单元测试。

### SA-L07: 图片 MIME subtype 正则过宽

状态：Fixed。

图片 payload MIME subtype 已从允许点号收紧为 `^image\/[A-Za-z0-9+-]{1,40}$`。内联预览仍有独立位图白名单，SVG 不会作为图片消息直接预览。

### SA-L08: CSP `upgrade-insecure-requests` 与 `ws:` 冲突

状态：Fixed。

Worker 和客户端 CSP 常量已将 `connect-src` 收紧为 `wss:`。本地 Node HTTP 场景仍保留 `ws:` 以支持本地开发；当 Node 通过 HTTPS 反代启用 `upgrade-insecure-requests` 时，会自动输出只包含 `wss:` 的 strict CSP。

### SA-L09: `setDataset` 未验证 key

状态：Fixed。

`setDataset` 现在会验证 dataset key 必须是受控 camelCase 名称，并拒绝 `__proto__`、`constructor`、`prototype` 等危险名称。

### SA-L10: relay membership 冗余检查

状态：Fixed。

Worker 和 Node relay 中房间人数上限检查已移除冗余 `!existing` 条件，保持逻辑更直接。

## 未发现高危项

- 未发现服务端保存聊天历史或密文内容的代码路径。
- 未发现服务端解密消息、文件或 profile 的代码路径。
- 未发现把 roomSeed、roomPsk、chain key、明文消息写入 localStorage/sessionStorage/IndexedDB 的路径。
- 未发现生产 HTML 中的内联脚本或内联事件。
- 未发现用户输入进入 `innerHTML` 的路径。
- 未发现运行时 CDN 脚本加载。

## 发布建议

发布前至少执行：

```bash
npm ci
npm run lint
npm test
npm run build
npm audit --audit-level=moderate
npm run test:e2e
```

修复优先级：

1. 先补 SA-L04 的私聊/附件/篡改/重放 E2E。
2. 然后处理 SA-M01 的身份签名和核对状态。
3. 最后评估 SA-M03 的 Argon2id WASM 方案。
