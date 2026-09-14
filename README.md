# Yuni Share — 独立部署与源码审查版

**源码公开供审查，非开源软件。Copyright (c) 2026 yuniaries. All rights reserved.**

允许阅读、保留未修改的本地副本用于阅读审查，以及 GitHub 条款允许的平台内 Fork。除此之外，未经书面授权，不授予运行部署、修改、再分发或商用等权利；法定权利及第三方许可不受影响。完整声明见 [LICENSE](LICENSE)。文中的部署与测试步骤仅用于解释实现，并供权利人或另获授权者使用，不构成额外授权。

本仓库从用户提供的 `YuniShare源码.zip` 整理而来。它是**经过裁剪的独立版本**，不是线上服务的逐字节镜像，也不是 Android 原生客户端源码。发布本仓库可以帮助他人审查实现，不能单独证明线上服务器实际运行的版本或承诺绝对安全。

## 保留的内容

- 浏览器端密钥派生、空间主密钥封装、每文件随机密钥、分片 AES-GCM、元数据加密与下载解密。
- 邮箱标识登录、密码哈希、会话、注册码注册、用户名修改、Web Passkey、文件及文件夹管理。
- Node.js / Express 服务端、SQLite、独立本地密文存储、配额和管理逻辑、必要前端资源。

## 不包含的内容

- 邮件服务、邮件发送网络实现、邮件模板、凭证；短信或替代发送服务也不包含。
- 支付网关实现、私有存储管理器实现、APK、应用更新清单、备份和实际用户数据。
- 线上域名、线上 Android 签名关联和个人头像。品牌图已替换为简单 SVG。

注册改用管理员生成的邮箱绑定一次性注册码；这**不证明邮箱所有权**。密码重置邮件、发起账户删除及商业支付接口返回 501，不会假装发送成功。通知适配点只返回未实现。旧恢复校验、配额/订阅数据结构和文件授权逻辑仍保留供审查，未接入外部服务。不要拿此版直接覆盖生产数据库。

## 启动

完整说明见 [DEPLOYMENT.md](DEPLOYMENT.md)。Docker 快速开始：

```sh
docker compose up -d --build
docker compose exec share node scripts/enroll.mjs person@example.com
```

打开 `http://localhost:8191`，注册最后一步输入管理员生成的注册码，不需要点击发信按钮。码有效期 15 分钟、单次使用、最多 5 次尝试；仅通过可信渠道交给目标用户。部署者自行设置自己的邮箱地址，不要使用示例地址建立公开账户。

```sh
docker compose exec share npm test
```

## 审查入口

- [SECURITY.md](SECURITY.md)：加密结构、元数据边界及待审查风险。
- `public/app.js`：检索 `derivePasswordWrappingKey`、`wrapVaultKey`、`encryptMetadata`、`prepareEncryptedUpload`、`encryptChunk`、`decodeFileChunk`。
- `server.mjs`：鉴权、密文存储、分片完整性、文件访问权限。
- `enrollment.mjs`：本版新增的无邮件注册授权。
- [CHANGES.md](CHANGES.md)：相对输入压缩包的变更。

## 发布前

不要上传 `.env`、`data/`、数据库、分片、测试账户资料或依赖目录。四份政策页面仅为占位说明，授权部署者需要自行填写。本项目不采用开源许可证，使用权限以 [LICENSE](LICENSE) 为准。源码内未包含第三方依赖代码，依赖及精确版本见 `package-lock.json`；依赖仍遵守各自的许可证。
