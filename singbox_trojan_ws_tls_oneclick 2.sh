#!/usr/bin/env bash
set -euo pipefail

# 轻量一键脚本：sing-box trojan + websocket(ws) + tls（原生证书路径）
# 适配 Cloudflare Origin Rule（按主机名重定向端口），适合 NAT/LXC 机器仅开放少量端口
# 说明：本脚本不使用 Caddy/Nginx，直接由 sing-box 终止 TLS
# 用法（在线执行示例）：
#   curl -sL https://raw.githubusercontent.com/<your-repo>/main/singbox_trojan_ws_tls_oneclick.sh | sudo bash
# 或上传到服务器：
#   sudo bash singbox_trojan_ws_tls_oneclick.sh
#
# 功能：安装/更新 sing-box、生成 trojan-ws-tls 配置（证书路径/可选 skip_cert_verify）、创建 systemd、生成 sb 快捷命令、显示 URI/二维码、卸载
#
# 参考原版脚本基础上做的修改：
#  - 去掉 Caddy 依赖，改为内置 TLS（certificate_path/key_path）
#  - 新增 Cloudflare Origin Cert 场景：可选择是否写入 "skip_cert_verify": true
#  - 菜单更简化，提供“一键完成”
#
# 作者：你

# ========== 路径 & 默认值 ==========
SINGBOX_BIN="/usr/local/bin/sing-box"
CONF_DIR="/usr/local/etc/sing-box"
CONF_FILE="$CONF_DIR/config.json"
SYSTEMD_UNIT="/etc/systemd/system/sing-box.service"
SB_CMD="/usr/local/bin/sb"

# 默认监听与参数（可在生成配置时交互修改）
DOMAIN=""
LISTEN_IP="0.0.0.0"     # 公网监听（由 CF 回源）；如反代/本机自用可改 127.0.0.1
LISTEN_PORT=8443        # 与 Cloudflare Origin Rule 对齐的端口
WS_PATH="/trojan"
PASSWORD="$(openssl rand -hex 16 2>/dev/null || echo change_me)"
CERT_FILE="/etc/ssl/certs/cert.pem"      # 你的证书（可用 CF Origin Cert）
KEY_FILE="/etc/ssl/private/key.pem"      # 你的私钥
SKIP_VERIFY="true"       # 使用 Cloudflare Origin Cert 时 推荐 true；若用公认 CA 证书可改为 false
ALPN="h2,http/1.1"

GREEN='\033[0;32m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; NC='\033[0m'
ok(){ echo -e "${GREEN}[OK]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR]${NC} $*"; }

need_root(){ if [ "$EUID" -ne 0 ]; then err "请用 root/sudo 运行"; exit 1; fi; }

arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64";;
    aarch64|arm64) echo "arm64";;
    armv7l|armv6l) echo "arm";;
    *) echo "amd64";;
  esac
}

install_singbox(){
  ok "安装/更新 sing-box ..."
  local a tag api url name tmp
  a=$(arch)
  api="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
  tag=$(curl -fsSL "$api" | grep -m1 '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/') || tag=""
  if [ -z "$tag" ]; then
    warn "GitHub API 获取失败，使用回退版本 v1.4.0（可自行修改）"
    tag="v1.4.0"
  fi
  name="sing-box-${tag}-linux-${a}"
  url="https://github.com/SagerNet/sing-box/releases/download/${tag}/${name}.tar.xz"
  tmp=$(mktemp -d); pushd "$tmp" >/dev/null
  curl -fsSLO "$url" || { err "下载失败: $url"; popd >/dev/null; rm -rf "$tmp"; return 1; }
  tar -xJf "${name}.tar.xz"
  install -m 0755 sing-box "$SINGBOX_BIN"
  popd >/dev/null; rm -rf "$tmp"
  ok "sing-box 已安装到 $SINGBOX_BIN"
}

gen_config(){
  mkdir -p "$CONF_DIR"

  # 交互设置（空回车=使用当前默认）
  read -rp "域名（SNI/展示用）: " in_domain || true
  DOMAIN="${in_domain:-$DOMAIN}"

  read -rp "监听 IP [默认 $LISTEN_IP]: " in_ip || true
  LISTEN_IP="${in_ip:-$LISTEN_IP}"

  read -rp "监听端口 [默认 $LISTEN_PORT]: " in_port || true
  LISTEN_PORT="${in_port:-$LISTEN_PORT}"

  read -rp "WS Path [默认 $WS_PATH]: " in_path || true
  WS_PATH="${in_path:-$WS_PATH}"

  read -rp "密码（留空随机/保持当前）: " in_pwd || true
  if [ -n "${in_pwd:-}" ]; then PASSWORD="$in_pwd"; fi

  read -rp "证书路径 [默认 $CERT_FILE]: " in_cert || true
  CERT_FILE="${in_cert:-$CERT_FILE}"

  read -rp "私钥路径 [默认 $KEY_FILE]: " in_key || true
  KEY_FILE="${in_key:-$KEY_FILE}"

  read -rp "使用 Cloudflare Origin 证书？(y/N) [影响 skip_cert_verify] : " in_cf || true
  if [[ "${in_cf:-}" =~ ^[Yy]$ ]]; then
    SKIP_VERIFY="true"
  else
    read -rp "skip_cert_verify 设为 true? (y/N): " in_skip || true
    if [[ "${in_skip:-}" =~ ^[Yy]$ ]]; then SKIP_VERIFY="true"; else SKIP_VERIFY="false"; fi
  fi

  # 生成配置
  cat > "$CONF_FILE" <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-ws-tls-in",
      "listen": "$LISTEN_IP",
      "listen_port": $LISTEN_PORT,
      "password": ["$PASSWORD"],
      "tls": {
        "enabled": true,
        "server_name": "$DOMAIN",
        "certificate_path": "$CERT_FILE",
        "key_path": "$KEY_FILE",
        "alpn": ["h2", "http/1.1"],
        "skip_cert_verify": ${SKIP_VERIFY}
      },
      "transport": {
        "type": "ws",
        "path": "$WS_PATH",
        "early_data": { "enabled": true, "max_size": 2048, "delay": 0 }
      }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF

  ok "已生成配置：$CONF_FILE"
  echo "  - 域名: $DOMAIN"
  echo "  - 监听: $LISTEN_IP:$LISTEN_PORT"
  echo "  - 证书: $CERT_FILE"
  echo "  - 私钥: $KEY_FILE"
  echo "  - WS 路径: $WS_PATH"
  echo "  - skip_cert_verify: $SKIP_VERIFY"
  echo
  warn "请在 Cloudflare 的 Origin Rules 中将 主机名=$DOMAIN 的回源端口重写为 $LISTEN_PORT；并在防火墙放行该端口。"
}

install_service(){
  cat > "$SYSTEMD_UNIT" <<EOF
[Unit]
Description=sing-box (trojan-ws-tls)
After=network.target

[Service]
Type=simple
ExecStart=$SINGBOX_BIN run -c $CONF_FILE
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now sing-box.service
  ok "systemd 已启用并启动 sing-box.service"
}

make_sb(){
  cat > "$SB_CMD" <<'EOF'
#!/usr/bin/env bash
CONF="/usr/local/etc/sing-box/config.json"
BIN="/usr/local/bin/sing-box"

if [ $# -eq 0 ]; then
  echo "用法：sb [run|check|api|help|...] （自动附带 -c $CONF）"
  exit 0
fi

exec "$BIN" "$@" -c "$CONF"
EOF
  chmod +x "$SB_CMD"
  ok "已创建 sb 快捷命令：$SB_CMD"
}

show_uri(){
  local host port path pass sni
  host="${DOMAIN:-your.domain.com}"
  port="$LISTEN_PORT"
  path="$WS_PATH"
  pass="$PASSWORD"
  sni="$host"
  local uri="trojan://${pass}@${host}:${port}?type=ws&host=${host}&path=${path}&security=tls&sni=${sni}&alpn=${ALPN}#${host}"
  ok "参考客户端 URI："
  echo "$uri"
  if command -v qrencode >/dev/null 2>&1; then
    echo "$uri" | qrencode -o - -t UTF8 || true
  else
    warn "未安装 qrencode（可 apt install qrencode）"
  fi
}

uninstall_all(){
  systemctl stop sing-box.service 2>/dev/null || true
  systemctl disable sing-box.service 2>/dev/null || true
  rm -f "$SYSTEMD_UNIT" "$SINGBOX_BIN" "$SB_CMD"
  rm -rf "$CONF_DIR"
  systemctl daemon-reload
  ok "已卸载（请自查残留）"
}

menu(){
  while true; do
    cat <<EOF

==== sing-box trojan + ws + tls（原生证书路径）====
1) 安装/更新 sing-box
2) 生成/更新 配置（域名/端口/证书/密码/路径/skip_verify）
3) 安装并启动 systemd 服务
4) 生成 sb 快捷命令
5) 显示客户端 URI（和二维码）
6) 一键完成（1->2->3->4）
7) 卸载
8) 退出
EOF
    read -rp "请选择 [1-8]: " op
    case "$op" in
      1) install_singbox ;;
      2) gen_config ;;
      3) install_service ;;
      4) make_sb ;;
      5) show_uri ;;
      6) install_singbox; gen_config; install_service; make_sb; ok "一键完成";;
      7) uninstall_all; break ;;
      8) break ;;
      *) warn "无效选项" ;;
    esac
  done
}

need_root
menu
