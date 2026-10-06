# KeyRelay

KeyRelay 是一个运行在 Bot 所在电脑上的本地凭据代理。你把账号密码保存到加密保险箱，
Bot 只能请求执行某个预先授权的登录配方，API 永远不会返回明文凭据。

## 安全边界

- 凭据使用 AES-256-GCM 加密，密钥、管理令牌和 Bot 令牌以 `0600` 权限留在 `.data/`。
- 管理操作和 Bot 登录使用不同令牌；Bot 令牌不能读取网站列表、添加网站或删除网站。
- 登录地址只接受 HTTPS 公网地址，顶层导航被限制在明确允许的域名中。
- 不绕过验证码、MFA、Passkey 或网站的安全策略；这些步骤需在浏览器中手动完成。
- KeyRelay 应只监听 `127.0.0.1`。不要把端口直接公开到公网，也不要提交 `.data/`。

注意：任何能完全控制这台电脑或读取其进程内存的程序，理论上仍可能获取凭据。KeyRelay
解决的是“不给 Bot 明文密码和任意读取接口”，不是对已失陷设备提供保护。

## 安装与启动

需要 Python 3.11+：

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
playwright install chromium
keyrelay
```

打开 <http://127.0.0.1:43127>，从终端复制管理令牌，添加网站的登录地址、账号、密码和
CSS 选择器。令牌也分别保存在 `.data/admin.token` 和 `.data/bot.token`，文件内容是原始
随机字节，终端显示的是对应十六进制值。

## 给 Bot 的调用方式

只给 Bot `.data/bot.token` 的十六进制值和已授权网站 ID：

```bash
curl -X POST \
  -H "X-KeyRelay-Token: <BOT_TOKEN>" \
  http://127.0.0.1:43127/api/v1/login/<SITE_ID>
```

调用会在同一台电脑上启动 Chromium，填充凭据并提交。会话 Cookie 保存在
`.data/browser-profile/`，后续自动化可复用同一个浏览器配置目录。

如登录使用 Google、Microsoft 或其他 SSO，需要在“额外允许域名”中明确添加会发生顶层
跳转的主机名。第三方静态资源可以加载，但页面导航到未授权域名会被阻止。

## 无图形界面的机器

设置 `KEYRELAY_HEADLESS=true` 可启用无头浏览器：

```bash
KEYRELAY_HEADLESS=true keyrelay
```

涉及验证码或 MFA 时不要使用无头模式，否则无法手动接管。

## 测试

```bash
ruff check .
pytest
```

## License

[MIT](LICENSE)
