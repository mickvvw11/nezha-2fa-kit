# 哪吒面板 v2 防护层（隐藏面板 + 防爆破）

在哪吒 dashboard 前面加一层防护，配合**带原生 TOTP 的哪吒 dashboard** 使用：
- 登录 = 哪吒用户名 + 密码 + 哪吒自己的 TOTP 6 位码，验证器只需一个条目，防护层不保存任何密钥。
- 「登录前隐藏面板」（默认开）：未登录时哪吒的页面、API、登录接口、swagger、终端、WebSocket 全部访问不到，只看到一个无标识的登录页。
- 防爆破：三项必须一起提交、所有失败同一句报错（不泄露密码对错）、每次至少 1.2 秒；同 IP 错 5 次锁 15 分钟并逐次翻倍（最长 24 小时）；全网 10 分钟错 30 次锁 30 分钟；锁定记录重启不清零。
- 账号没开 TOTP 时拒绝登录（首次部署可临时放行，见下）。
- Agent 的 gRPC（HTTP/2）会被解析，只放行 `/proto.NezhaService/*`，不能借 HTTP/2 绕过防护层访问 API。
- 后台右下角「🛡 防护」：开关「登录前隐藏」和「公开状态页」。会削弱防护的操作需要重新输入密码 + 验证码，立即生效。

只用 Node.js 内置模块，没有第三方依赖。

> 官方 v2.7.0 没有原生 TOTP。本仓库**不提供**带 TOTP 的 dashboard 二进制，请自备（放成 `dashboard-custom.gz`，gzip 压缩的单个可执行文件），否则防护层会拒绝登录。

## 一、普通 VPS（有 root，systemd）
    CUSTOM_GZ=/root/dashboard.gz bash <(curl -fsSL https://raw.githubusercontent.com/mickvvw11/nezha-2fa-kit/main/install.sh) install 8008
国内机器加 `GH_PROXY=https://ghfast.top/`。

首次部署会临时允许无 TOTP 登录：用 admin / admin（验证码随便填 6 位数字）登录 → 立刻改密码 → 个人资料里开启 TOTP → 执行 `nezha-2fa bootstrap off`。

常用命令：
- `nezha-2fa unlock` 清除防爆破锁定
- `nezha-2fa shield off|on` 应急关闭/恢复防护层
- `nezha-2fa uninstall` 卸载

## 二、翼龙/Pterodactyl 的 Node.js 小鸡（如 Host-Ship，无 root）
1. 文件管理上传 `panel.js`、`gate.js`、`dashboard-custom.gz` 到根目录。
2. 启动文件改成 `panel.js`，镜像 Node.js 18 以上。
3. 首次部署：再建一个空文件 `shield-allow-no-totp.txt`，重启，登录后改密码、开 TOTP，然后删掉这个文件再重启。
4. 进不去时：把 `gate-off.txt` 放到根目录并重启 = 不带防护层的原生哪吒；删掉 `shield-lock.json` 并重启 = 清除锁定。

## 文件
- `shield.json`：开关状态（无密钥）。`shield-lock.json`：锁定记录。
- 使用 `dashboard-custom.gz` 时，首次替换会备份 `nezha/data/sqlite.db.bak-时间` 和官方二进制 `nezha/dashboard.official`。
- 哪吒本体只监听 127.0.0.1:18008。系统设置里「前端真实 IP 请求头」保持 `X-Real-Ip`。
- 主题：首次启动且密码仍为 admin/admin 时自动安装 Lotus（`THEME_REPO` 可换，`none` 跳过）。
- 可选：放 `cf-token.txt` 自动启动 Cloudflare Tunnel。
- 注意：能改服务器文件的人总能绕过任何网页防护。

旧版（自带 TOTP 密钥的 2FA 门禁）见提交 984d74d。
