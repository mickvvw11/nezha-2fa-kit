#!/usr/bin/env bash
# 哪吒面板 v2 + 谷歌验证器 2FA 一键部署（Linux VPS，需要 root，无需 Docker）
# 用法：
#   bash install.sh install [端口]   安装或更新，默认端口 8008
#   bash install.sh key              显示 2FA 绑定状态（未绑定时给一次性绑定链接）
#   bash install.sh reset            重置 2FA（生成新密钥，所有设备重新验证）
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

show_key(){
  # 密钥加密存放，不再明文打印；未绑定时给出一次性绑定链接
  local IP PORT L
  IP=$(curl -fsS4 -m 5 https://ip.sb 2>/dev/null || hostname -I | awk '{print $1}')
  PORT=$(systemctl show $SVC -p Environment --value 2>/dev/null | tr ' ' '\n' | sed -n 's/^SERVER_PORT=//p')
  for i in $(seq 1 60); do L=$(journalctl -u $SVC --since "-10min" --no-pager 2>/dev/null | grep -o '__2fa/setup?t=[A-Za-z0-9_-]*' | tail -1); [ -n "$L" ] && break
    journalctl -u $SVC -n 30 --no-pager 2>/dev/null | grep -q '\[2FA\] enabled (key is encrypted' && break; sleep 1; done
  if [ -n "$L" ] && ! journalctl -u $SVC --since "-10min" --no-pager | grep -q '\[2FA\] bound from'; then
    echo "用浏览器打开这个一次性绑定链接，扫码并输入 6 位码完成绑定（用过即失效）："
    echo "  http://$IP:${PORT:-8008}/$L"
  else
    echo "2FA 已绑定。密钥加密存储，需要查看请在后台右下角「🔐 2FA」里输入当前验证码查看；丢了手机用 nezha-2fa reset。"
  fi
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
  N=$(node_bin)
  # 2FA 主密钥放在数据目录之外（root 600），用于加密 gate.json 中的密钥
  if [ ! -f /etc/nezha-2fa.env ]; then umask 077; echo "NEZHA_2FA_KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > /etc/nezha-2fa.env; fi
  chmod 600 /etc/nezha-2fa.env
  cat > /etc/systemd/system/$SVC.service <<UNIT
[Unit]
Description=Nezha Dashboard v2 with TOTP gate
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$DIR
Environment=SERVER_PORT=$PORT
EnvironmentFile=/etc/nezha-2fa.env
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
  echo "后台:  http://$IP:$PORT/dashboard   （默认账号 admin / admin，进去立刻改密码）"
  echo "Agent 对接地址填 $IP:$PORT（不开 TLS）"
  echo "防火墙记得放行 TCP $PORT"
  echo; show_key
  echo; echo "以后：nezha-2fa key 查看绑定状态/链接 · nezha-2fa reset 重置 2FA · 后台右下角「🔐 2FA」可改设置"
  ;;
key) show_key ;;
reset)
  systemctl stop $SVC; rm -f "$DIR/gate.json"; systemctl start $SVC
  grn "已重置，生成了新密钥："; sleep 3; show_key ;;
uninstall)
  systemctl disable --now $SVC 2>/dev/null || true
  rm -f /etc/systemd/system/$SVC.service /usr/local/bin/nezha-2fa; systemctl daemon-reload
  grn "已卸载服务。数据还在 $DIR，确认不要了再 rm -rf $DIR" ;;
*) echo "用法: bash install.sh install [端口] | key | reset | uninstall" ;;
esac
