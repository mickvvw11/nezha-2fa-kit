# 哪吒面板 v2 + 谷歌验证器 2FA 部署包

哪吒 v2.7.0 官方版没有 TOTP。这个包在面板前面加一层「二次验证」：
进后台、登录、终端/文件、所有写操作都要先输谷歌验证器 6 位码；前台状态页和 Agent 上报不受影响。
只用 Node.js 内置模块，没有第三方依赖。

## 一、普通 VPS（有 root，systemd）
一键安装：
    bash <(curl -fsSL https://raw.githubusercontent.com/mickvvw11/nezha-2fa-kit/main/install.sh) install 8008
国内机器：
    export GH_PROXY=https://ghfast.top/
    bash <(curl -fsSL ${GH_PROXY}https://raw.githubusercontent.com/mickvvw11/nezha-2fa-kit/main/install.sh) install 8008
或者下载 zip 后：
    unzip nezha-2fa-kit.zip && cd nezha-2fa-kit
    bash install.sh install 8008
国内机器拉 GitHub 慢：`GH_PROXY=https://ghfast.top/ bash install.sh install 8008`
装完会打印前台/后台地址和 2FA 密钥。常用命令：
- `nezha-2fa key`   查看绑定状态（未绑定时给一次性绑定链接）
- `nezha-2fa reset` 丢了手机时重置密钥
- `nezha-2fa uninstall` 卸载

## 二、翼龙/Pterodactyl 面板的 Node.js 小鸡（如 Host-Ship，无 root）
1. 文件管理里上传 `panel.js` 和 `gate.js` 到根目录。
2. Startup 里把启动文件（MAIN_FILE）改成 `panel.js`，镜像选 Node.js 18 以上。
3. 重启，控制台会打印 `[2FA] NOT BOUND YET` 和一条一次性绑定链接（把 `<your-host>` 换成服务器 IP），浏览器打开、扫码、输 6 位码即完成，链接随即失效。
4. 丢了手机：在文件管理删掉 `gate.json` 再重启，会生成新密钥。

## 主题
- 首次启动自动安装并启用 Lotus 前台主题（github.com/fl0w1nd/Lotus 最新版），官方主题保留，可在 系统设置 > 前端管理 切换。
- 换别的主题：安装时加 `THEME_REPO=https://github.com/作者/仓库`；不要主题填 `THEME_REPO=none`。
- 只在默认密码 admin/admin 时自动装；改过密码后请在后台「前端管理」里手动装。

## 使用
- 后台：`http://IP:端口/dashboard`，先过 2FA 页，再用 admin/admin 登录并立刻改密码。
- 后台右下角「🔐 2FA」= 设置页：查看密钥/二维码、更换密钥、设置免输天数（1–30 天）、让所有设备重新验证、关闭/开启 2FA。敏感操作都要当前 6 位码。
- 退出验证：`/__2fa/logout`
- 同一 IP 10 分钟内错 5 次会被暂时锁住。

## 说明
- 哪吒本体只监听 127.0.0.1:18008，外网只能经过 2FA 门。
- 安全：`gate.json` 里的 TOTP 密钥和会话密钥用 AES-256-GCM 加密，文件权限 600；控制台不再打印密钥。主密钥来自环境变量 `NEZHA_2FA_KEY`（一键脚本放在 `/etc/nezha-2fa.env`，root 600，和数据目录分开）；面板托管环境没有该变量时退回同目录的 `gate.key`。注意：能改服务器文件的人总能绕过任何网页 2FA。
- 密钥保存在 `gate.json`，哪吒数据在 `nezha/data/`，迁移时连同两者一起拷走。
- 系统设置里「前端真实 IP 请求头」请保持 `X-Real-Ip`，否则防火墙会把所有人当成 127.0.0.1。
- 可选：在目录放 `cf-token.txt`（Cloudflare Tunnel token）会自动启动 cloudflared 隧道。
