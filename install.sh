#!/usr/bin/env bash
# 哪吒面板 v2 + 防护层（隐藏面板 / 防爆破）一键部署（Linux VPS，需要 root，无需 Docker）
# 需要带原生 TOTP 的哪吒 dashboard：CUSTOM_GZ=/路径/dashboard.gz bash install.sh install 8008
# 用法：
#   bash install.sh install [端口]   安装或更新，默认端口 8008
#   bash install.sh bootstrap on|off 首次部署用：允许没开 TOTP 的账号登录（开完 TOTP 务必 off）
#   bash install.sh unlock           清除防爆破锁定记录并重启
#   bash install.sh shield off|on    应急：关闭/恢复防护层（off 时哪吒直接对外）
#   bash install.sh uninstall        卸载（保留 /opt/nezha-2fa 数据，需手动删）
# 一键：bash <(curl -fsSL https://raw.githubusercontent.com/mickvvw11/nezha-2fa-kit/main/install.sh) install 8008
# 换主题：THEME_REPO=https://github.com/作者/仓库 bash install.sh install（填 none 不装主题）
# 国内机器拉 GitHub 慢可以：GH_PROXY=https://ghfast.top/ bash install.sh install
set -e
DIR=/opt/nezha-2fa
SVC=nezha-2fa
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_VER=v20.18.1
RAW="${GH_PROXY:-}https://raw.githubusercontent.com/mickvvw11/nezha-2fa-kit/main"
red(){ echo -e "\033[31m$*\033[0m"; }; grn(){ echo -e "\033[32m$*\033[0m"; }

[ "$(id -u)" = 0 ] || { red "请用 root 运行"; exit 1; }

node_bin(){
  if command -v node >/dev/null 2>&1 && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 18 ]; then command -v node; return; fi
  if [ -x "$DIR/node/bin/node" ]; then echo "$DIR/node/bin/node"; return; fi
  case "$(uname -m)" in x86_64|amd64) A=x64;; aarch64|arm64) A=arm64;; *) red "不支持的架构 $(uname -m)"; exit 1;; esac
  echo "下载 Node.js $NODE_VER ..." >&2
  mkdir -p "$DIR/node"
  for base in https://nodejs.org/dist https://npmmirror.com/mirrors/node; do
    if curl -fsSL "$base/$NODE_VER/node-$NODE_VER-linux-$A.tar.xz" | tar -xJ -C "$DIR/node" --strip-components=1; then break; fi
  done
  [ -x "$DIR/node/bin/node" ] || { red "Node.js 下载失败"; exit 1; }
  echo "$DIR/node/bin/node"
}

case "${1:-install}" in
install)
  PORT="${2:-8008}"
  command -v systemctl >/dev/null || { red "需要 systemd"; exit 1; }
  for c in curl tar xz; do command -v $c >/dev/null || { (apt-get update -y && apt-get install -y curl tar xz-utils) >/dev/null 2>&1 || yum install -y curl tar xz >/dev/null 2>&1 || true; break; }; done
  mkdir -p "$DIR"
  if [ ! -f "$SRC/gate.js" ] || [ ! -f "$SRC/panel.js" ] || [ ! -f "$SRC/install.sh" ]; then
    SRC=$(mktemp -d)
    for f in panel.js gate.js install.sh; do curl -fsSL "$RAW/$f" -o "$SRC/$f" || { red "下载 $f 失败（国内可加 GH_PROXY=https://ghfast.top/）"; exit 1; }; done
  fi
  install -m 644 "$SRC/panel.js" "$DIR/panel.js"
  install -m 644 "$SRC/gate.js" "$DIR/gate.js"
  install -m 755 "$SRC/install.sh" /usr/local/bin/nezha-2fa
  cp -f "$SRC/panel.js" "$SRC/gate.js" "$SRC/install.sh" "$DIR/" 2>/dev/null || true
  if [ -n "${CUSTOM_GZ:-}" ]; then install -m 600 "$CUSTOM_GZ" "$DIR/dashboard-custom.gz"; fi
  FRESH=0; [ -f "$DIR/nezha/data/sqlite.db" ] || FRESH=1
  if [ ! -f "$DIR/dashboard-custom.gz" ]; then red "警告：没有提供带原生 TOTP 的 dashboard（CUSTOM_GZ），官方版没有 TOTP，防护层会拒绝登录。"; fi
  if [ $FRESH = 1 ]; then touch "$DIR/shield-allow-no-totp.txt"; fi
  N=$(node_bin)
  cat > /etc/systemd/system/$SVC.service <<UNIT
[Unit]
Description=Nezha Dashboard v2 with shield
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$DIR
Environment=SERVER_PORT=$PORT
Environment=GH_PROXY=${GH_PROXY:-}
Environment=THEME_REPO=${THEME_REPO:-https://github.com/fl0w1nd/Lotus}
ExecStart=$N $DIR/panel.js
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now $SVC >/dev/null 2>&1
  systemctl restart $SVC
  echo "启动中（首次会下载哪吒 dashboard）..."
  for i in $(seq 1 90); do journalctl -u $SVC -n 50 --no-pager 2>/dev/null | grep -q "Dashboard::START" && break; sleep 1; done
  IP=$(curl -fsS4 -m 5 https://ip.sb 2>/dev/null || hostname -I | awk '{print $1}')
  grn "完成！"
  echo "前台:  http://$IP:$PORT/"
  echo "登录:  http://$IP:$PORT/   （防护层登录页：用户名 + 密码 + 6 位验证码）"
  echo "Agent 对接地址填 $IP:$PORT（不开 TLS）"
  echo "防火墙记得放行 TCP $PORT"
  if [ $FRESH = 1 ]; then
    echo; red "首次部署：已临时允许无 TOTP 登录。用 admin / admin（验证码随便填 6 位数字）登录，立刻改密码并在个人资料里开启 TOTP，然后执行：nezha-2fa bootstrap off"
  fi
  echo; echo "以后：后台右下角「🛡 防护」可开关隐藏/公开状态页 · nezha-2fa unlock 解锁 · nezha-2fa shield off 应急关闭"
  ;;
bootstrap)
  if [ "$2" = on ]; then touch "$DIR/shield-allow-no-totp.txt"; red "已允许无 TOTP 登录（仅限首次部署）"; else rm -f "$DIR/shield-allow-no-totp.txt"; grn "已关闭无 TOTP 登录"; fi
  systemctl restart $SVC ;;
unlock) systemctl stop $SVC; rm -f "$DIR/shield-lock.json"; systemctl start $SVC; grn "已清除锁定" ;;
shield)
  if [ "$2" = off ]; then touch "$DIR/gate-off.txt"; red "防护层已关闭，哪吒直接对外"; else rm -f "$DIR/gate-off.txt"; grn "防护层已恢复"; fi
  systemctl restart $SVC ;;
uninstall)
  systemctl disable --now $SVC 2>/dev/null || true
  rm -f /etc/systemd/system/$SVC.service /usr/local/bin/nezha-2fa; systemctl daemon-reload
  grn "已卸载服务。数据还在 $DIR，确认不要了再 rm -rf $DIR" ;;
*) echo "用法: bash install.sh install [端口] | bootstrap on|off | unlock | shield off|on | uninstall" ;;
esac
