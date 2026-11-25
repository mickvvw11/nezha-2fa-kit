#!/usr/bin/env bash
# 哪吒面板 v2 + 谷歌验证器 2FA 一键部署（Linux VPS，需要 root，无需 Docker）
# 用法：
#   bash install.sh install [端口]   安装或更新，默认端口 8008
#   bash install.sh key              显示当前 2FA 密钥
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
  local N; N=$(node_bin)
  for i in $(seq 1 60); do [ -f "$DIR/gate.json" ] && break; sleep 1; done
  [ -f "$DIR/gate.json" ] || { red "还没生成 gate.json，看日志：journalctl -u $SVC -n 50"; exit 1; }
  "$N" -e '
    const s=require(process.argv[1]);
    if(!s.enabled){console.log("2FA 当前已关闭，可在后台右下角「🔐 2FA」里开启");process.exit(0)}
    console.log("谷歌验证器 → ＋ → 输入设置密钥，类型「基于时间」：");
    console.log("  账号: Nezha:admin");
    console.log("  密钥: "+s.secret.replace(/(.{4})/g,"$1 ").trim());
    console.log("  otpauth://totp/Nezha:admin?secret="+s.secret+"&issuer=Nezha");' "$DIR/gate.json"
  command -v qrencode >/dev/null 2>&1 && "$N" -e 'const s=require(process.argv[1]);if(s.enabled)process.stdout.write("otpauth://totp/Nezha:admin?secret="+s.secret+"&issuer=Nezha")' "$DIR/gate.json" | qrencode -t ANSIUTF8 || true
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
  cat > /etc/systemd/system/$SVC.service <<UNIT
[Unit]
Description=Nezha Dashboard v2 with TOTP gate
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
  echo "后台:  http://$IP:$PORT/dashboard   （默认账号 admin / admin，进去立刻改密码）"
  echo "Agent 对接地址填 $IP:$PORT（不开 TLS）"
  echo "防火墙记得放行 TCP $PORT"
  echo; show_key
  echo; echo "以后：nezha-2fa key 查看密钥 · nezha-2fa reset 重置 2FA · 后台右下角「🔐 2FA」可改设置"
  ;;
key) show_key ;;
reset)
  systemctl stop $SVC; rm -f "$DIR/gate.json"; systemctl start $SVC
  grn "已重置，新密钥："; show_key ;;
uninstall)
  systemctl disable --now $SVC 2>/dev/null || true
  rm -f /etc/systemd/system/$SVC.service /usr/local/bin/nezha-2fa; systemctl daemon-reload
  grn "已卸载服务。数据还在 $DIR，确认不要了再 rm -rf $DIR" ;;
*) echo "用法: bash install.sh install [端口] | key | reset | uninstall" ;;
esac
