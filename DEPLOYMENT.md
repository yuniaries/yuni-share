# 部署说明

**仅供权利人或取得单独书面授权者执行。** 本文用于披露框架和部署逻辑，不授予运行、部署或修改许可；参见 [LICENSE](LICENSE)。普通读者可阅读源码与本文进行审查。

## 1. 隔离原则

此版只部署 Web + Node 后端 + 本地 SQLite/密文目录，不需要邮件、支付、私有存储服务。使用新目录、新数据卷，不导入线上数据库。原有配额清理逻辑会删除符合条件的密文，禁止以生产数据验证。

## 2. Docker Compose

要求 Docker Engine/Desktop 与 Compose。Windows 可在 Docker Desktop 的 Linux 容器模式使用。

```sh
docker compose up -d --build
docker compose logs --tail=50 share
```

默认仅映射本机 `127.0.0.1:8191`。容器内部以非 root 的 node 用户运行。`share-data` 卷保存 SQLite、密文、头像和注册码库；不要提交它。

复制 `.env.example` 为 `.env` 后修改：PowerShell 用 `Copy-Item .env.example .env`；Linux 用 `cp .env.example .env`。

- `PUBLIC_URL`：浏览器实际访问地址，本地为 `http://localhost:8191`。
- `ADMIN_PASSWORD`：默认空，管理密码登录不启用；若需要管理面板，设置独立强密码。
- `USER_QUOTA_BYTES`：新用户默认 5 GiB。

生成注册码：

```sh
docker compose exec share node scripts/enroll.mjs person@example.com
```

注册码只在命令终端显示，不发邮件；它绑定对应邮箱字符串，不是共享万能码。由用户在自己的浏览器设置登录密码和独立加密密码；不要让管理员代收加密密码。注册码成功验证后立即消耗，后续注册如果失败需要重新生成。

## 3. 不使用 Docker

要求 Node.js 22（建议至少 22.13）、npm；better-sqlite3 若不能获取预编译包，需要 Python 3、make 和 C++ 编译工具。

```sh
npm ci
npm test
npm start
```

另一终端执行 `node scripts/enroll.mjs person@example.com`。默认数据目录是工作目录下 `data/`。环境变量由调用环境传入；直接 `npm start` 不会自动读取 `.env`。始终在仓库根目录运行，前端资源路径依赖当前目录。

## 4. HTTPS 与反向代理

公网使用 HTTPS，将域名反代到本机 8191，并设置相同的 `PUBLIC_URL=https://你的域名`，重建容器应用配置。Web Crypto / Passkey 需要安全上下文，localhost 是开发例外，普通局域网 HTTP 不能替代 HTTPS。不要使用原站域名或证书关联配置。当前只信任网页自身 Origin，不包含 Android App 关联。

反向代理应限制请求大小、连接与请求速率，支持流式分片上传，不缓存 `/api/`，不把 API Cookie 写入公开日志。代码保留 `trust proxy = 1`；只适用于单层可信反代，部署者应依据真实链路调整，不能直接信任用户伪造的转发头。

## 5. 数据、备份与停止

停止用 `docker compose stop`；保留数据重启用 `docker compose up -d`。不要运行 `docker compose down -v`，它会删除数据卷。备份需要在应用停止后完整保存数据卷，或对 SQLite 使用一致性备份并协调密文文件快照；不能只复制正在使用的 share.db 而忽略 WAL 和密文。

文件存储在 `data/files/<user_id>/`。本地后端完成上传时可能将多个密文片拼接为一个 `.bin`，边界保存在数据库中；不能仅看磁盘文件数量推断分片数。没有用户密钥及加密元数据不能还原原文件，数据库和密文都需保留。

## 6. 验证与局限

运行 `npm test` 可测试实际前端分片函数的加解密、篡改/AAD 拒绝、密码派生和注册码行为。它不是完整安全审计，也不能代替真实浏览器 Passkey/文件预览与多设备测试。验证记录见 `VERIFICATION.md`。

运行 `node scripts/smoke.mjs` 会自动启动隔离服务并测试注册和完整分片传输，测试使用临时目录并自行清理；需保证 18292 端口空闲。

邮件恢复、支付和线上私有存储适配均不提供。可用接口不应因为缺少集成而默默绕过验证；本版相关入口明确失败。政策占位页不构成可直接使用的对外法律文本。
