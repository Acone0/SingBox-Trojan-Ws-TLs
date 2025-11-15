#!/bin/bash
# === 全局变量与样式 ===
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
SINGBOX_BIN="/usr/local/bin/sing-box"; SINGBOX_DIR="/usr/local/etc/sing-box"
CONFIG_FILE="${SINGBOX_DIR}/config.json"; METADATA_FILE="${SINGBOX_DIR}/metadata.json"
LOG_FILE="/var/log/sing-box.log"; PID_FILE="/run/sing-box.pid"; ACME_SH_HOME="/root/.acme.sh"
INIT_SYSTEM=""; SERVICE_FILE=""; SCRIPT_VERSION="4.1"; server_ip=""

# === 工具函数 ===
_echo_style() { echo -e "${1}${2}${NC}"; }
_info() { _echo_style "$CYAN" "$1"; }; _success() { _echo_style "$GREEN" "$1"; }
_warning() { _echo_style "$YELLOW" "$1"; }; _error() { _echo_style "$RED" "$1"; return 1; }

_check_root() { [ "$(id -u)" -ne 0 ] && { _error "需要 root 权限"; exit 1; }; }
format_ipv6() { local ip="$1"; [[ "$ip" == *":"* ]] && [[ "$ip" != "["* ]] && echo "[${ip}]" || echo "$ip"; }
_url_encode() {
  if command -v jq &>/dev/null; then echo -n "$1" | jq -s -R -r @uri; else
    printf '%s' "$1" | sed 's/ /%20/g;s/!/%21/g;s/#/%23/g;s/$/%24/g;s/&/%26/g;s/'\''/%27/g;s/(/%28/g;s/)/%29/g;s/*/%2A/g;s/+/%2B/g;s/,/%2C/g;s/\//%2F/g;s/:/%3A/g;s/;/%3B/g;s/=/%3D/g;s/?/%3F/g;s/@/%40/g;s/\[/%5B/g;s/\]/%5D/g'
  fi
}
trap 'rm -f ${SINGBOX_DIR}/*.tmp ${PID_FILE}' EXIT

# === 依赖安装 ===
_install_dependencies() {
  local pkgs="curl jq openssl wget procps" pm="" to_install=""
  command -v apk &>/dev/null && { pm="apk"; pkgs="bash coreutils $pkgs"; }
  command -v apt-get &>/dev/null && pm="apt-get"
  command -v dnf &>/dev/null && pm="dnf"
  command -v yum &>/dev/null && pm="yum"
  [ -z "$pm" ] && { _warning "未识别包管理器"; return; }
  for p in $pkgs; do
    case $pm in
      apk) ! apk -e info "$p" &>/dev/null && to_install="$to_install $p" ;;
      apt-get) ! dpkg -s "$p" &>/dev/null 2>&1 && to_install="$to_install $p" ;;
      *) ! rpm -q "$p" &>/dev/null && to_install="$to_install $p" ;;
    esac
  done
  [ -n "$to_install" ] && { _info "安装依赖:$to_install"; $pm install -y $to_install || { _error "依赖安装失败"; exit 1; }; }
  _success "依赖已满足"
}

# === sing-box 安装 ===
_install_sing_box() {
  local arch=$(uname -m) tag=
  case $arch in x86_64|amd64) tag=amd64;; aarch64|arm64) tag=arm64;; armv7l) tag=armv7;; *) _error "不支持的架构"; exit 1;; esac
  local api="https://api.github.com/repos/SagerNet/sing-box/releases"
  local ver=$(curl -s "$api" | jq -r '.[0].tag_name')
  local url=$(curl -s "$api" | jq -r ".[0].assets[] | select(.name | contains(\"linux-${tag}.tar.gz\")) | .browser_download_url")
  [ -z "$url" ] && { _error "获取下载链接失败"; exit 1; }
  wget -qO sing-box.tar.gz "$url" || { _error "下载失败"; exit 1; }
  tar -xzf sing-box.tar.gz -C /tmp && mv /tmp/sing-box-*/sing-box ${SINGBOX_BIN} && chmod +x ${SINGBOX_BIN}
  rm -f sing-box.tar.gz; _success "sing-box 安装完成，版本：$(${SINGBOX_BIN} version | head -n1)"
}

# === systemd / openrc 服务 ===
_detect_init_system() {
  INIT_SYSTEM="direct"; SERVICE_FILE=""
  [ -f "/sbin/openrc-run" ] && { INIT_SYSTEM="openrc"; SERVICE_FILE="/etc/init.d/sing-box"; return; }
  [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null && { INIT_SYSTEM="systemd"; SERVICE_FILE="/etc/systemd/system/sing-box.service"; }
}
_create_systemd_service() {
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
After=network.target nss-lookup.target
[Service]
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload; systemctl enable sing-box
}
_create_openrc_service() {
  cat > "$SERVICE_FILE" <<'EOF'
#!/sbin/openrc-run
description="sing-box service"
command="/usr/local/bin/sing-box"
command_args="run -c /usr/local/etc/sing-box/config.json"
command_user="root"
pidfile="/run/sing-box.pid"
depend() { need net; after firewall; }
start() { ebegin "Starting sing-box"; start-stop-daemon --start --background --make-pidfile --pidfile ${pidfile} --exec ${command} -- ${command_args} >> /var/log/sing-box.log 2>&1; eend $?; }
stop()  { ebegin "Stopping sing-box";  start-stop-daemon --stop --pidfile ${pidfile}; eend $?; }
EOF
chmod +x "$SERVICE_FILE"; rc-update add sing-box default
}
_create_service_files() {
  [ "$INIT_SYSTEM" == "direct" ] && { _info "直接模式，无服务文件"; return; }
  [ -f "$SERVICE_FILE" ] && return
  _info "创建 ${INIT_SYSTEM} 服务"
  case "$INIT_SYSTEM" in
    systemd) _create_systemd_service ;;
    openrc)  _create_openrc_service ;;
  esac
}

# === 服务管理（带配置校验） ===
_manage_service() {
  local action="$1"
  if [[ "$action" == restart || "$action" == start ]]; then
    if ! ${SINGBOX_BIN} check -c ${CONFIG_FILE} >/dev/null 2>&1; then
      _error "配置校验失败，拒绝重启"; return 1
    fi
  fi
  case "$INIT_SYSTEM" in
    systemd) systemctl "$action" sing-box ;;
    openrc)  rc-service sing-box "$action" ;;
    direct)
      case "$action" in
        start|restart)
          [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null && { _warning "sing-box 已在运行"; return; }
          rm -f "$PID_FILE"; touch "$LOG_FILE"
          nohup ${SINGBOX_BIN} run -c ${CONFIG_FILE} >> "$LOG_FILE" 2>&1 & echo $! > "$PID_FILE"
          sleep 1; kill -0 "$(cat "$PID_FILE")" 2>/dev/null && _success "sing-box 已启动" || { _error "启动失败"; rm -f "$PID_FILE"; return 1; }
          ;;
        stop)
          [ -f "$PID_FILE" ] || { _warning "未找到 PID 文件"; return; }
          kill "$(cat "$PID_FILE")" 2>/dev/null && rm -f "$PID_FILE" && _success "sing-box 已停止" || _error "停止失败"
          ;;
      esac
      ;;
  esac
}

# === 证书续期（systemd-only） ===
_setup_cert_renewal() {
  [ "$INIT_SYSTEM" != "systemd" ] && { _warning "非 systemd，跳过 timer"; return; }
  local svc="/etc/systemd/system/acme-renew.service" timer="/etc/systemd/system/acme-renew.timer"
  cat > "$svc" <<EOF
[Unit]
Description=Renew Let's Encrypt certificates
After=network-online.target
[Service]
Type=oneshot
ExecStart=/bin/bash -c '${ACME_SH_HOME}/acme.sh --cron --home ${ACME_SH_HOME} && systemctl is-active --quiet sing-box && systemctl restart sing-box'
EOF
  cat > "$timer" <<'EOF'
[Unit]
Description=Daily renewal check
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now acme-renew.timer
  systemctl is-enabled acme-renew.timer &>/dev/null && _success "timer 已创建并启用" || _error "timer 启用失败"
}

# === 证书申请 ===
_auto_cert() {
  local domain="$1"
  _check_acme_sh || return 1
  if [ -z "$CF_Token" ] || [ -z "$CF_Zone_ID" ]; then
    read -p "CF_Token: " CF_Token; read -p "CF_Zone_ID: " CF_Zone_ID
    export CF_Token CF_Zone_ID
    echo "export CF_Token=\"$CF_Token\"" > ${SINGBOX_DIR}/cloudflare.conf
    echo "export CF_Zone_ID=\"$CF_Zone_ID\"" >> ${SINGBOX_DIR}/cloudflare.conf
  fi
  [ -f ${SINGBOX_DIR}/cloudflare.conf ] && source ${SINGBOX_DIR}/cloudflare.conf
  ${ACME_SH_HOME}/acme.sh --issue --dns dns_cf -d "$domain" --server letsencrypt || return 1
  local cert="${ACME_SH_HOME}/${domain}_ecc/fullchain.cer" key="${ACME_SH_HOME}/${domain}_ecc/${domain}.key"
  _success "证书申请成功"; _info "公钥: $cert"; _info "私钥: $key"
  _setup_cert_renewal
  # 返回路径供调用者使用
  echo "$cert"; echo "$key"
}

# === 添加 Trojan 节点 ===
_add_trojan_ws_tls() {
  _get_public_ip
  local client_ip; client_ip=$(curl -s4 icanhazip.com || curl -s6 icanhazip.com)
  client_ip=$(format_ipv6 "$client_ip")
  read -p "伪装域名 (必填): " domain
  read -p "端口: " port; read -p "密码 (回车随机): " pwd; [ -z "$pwd" ] && pwd=$(${SINGBOX_BIN} generate rand --base64 16)
  read -p "WS 路径 (回车随机): " path; [ -z "$path" ] && path="/$(${SINGBOX_BIN} generate rand --hex 8)"
  local cert_choice; read -p "证书 1)自动 2)自定义 (默认1): " cert_choice; cert_choice=${cert_choice:-1}
  local cert="" key=""; if [ "$cert_choice" == "1" ]; then
    mapfile -t CERT < <(_auto_cert "$domain"); cert=${CERT[0]}; key=${CERT[1]}
  else
    read -p "公钥文件路径: " cert; read -p "私钥文件路径: " key
    [ ! -f "$cert" -o ! -f "$key" ] && { _error "证书文件不存在"; return 1; }
  fi
  local tag="Trojan-ws-$port" name="Trojan-ws-$port"
  local inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg pwd "$pwd" --arg cert "$cert" --arg key "$key" --arg path "$path" --arg domain "$domain" '
  {type: "trojan", tag: $t, listen: "::", listen_port: ($p|tonumber), users: [{password: $pwd}],
   tls: {enabled: true, certificate_path: $cert, key_path: $key, server_name: $domain},
   transport: {type: "ws", path: $path, headers: {Host: $domain}}}')
  _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound]"
  local url="trojan://${pwd}@$(format_ipv6 "$client_ip"):$port?security=tls&sni=$domain&type=ws&path=$(_url_encode "$path")&host=$domain#$(_url_encode "$name")"
  _success "节点已添加"; _info "分享链接: $url"; _manage_service "restart"
}

# === 节点管理 ===
_view_nodes() {
  jq -r '.inbounds[] | "\(.tag) 端口:\(.listen_port)"' "$CONFIG_FILE" | cat -n
  jq -c '.inbounds[]' "$CONFIG_FILE" | while read -r node; do
    local tag=$(echo "$node" | jq -r '.tag') port=$(echo "$node" | jq -r '.listen_port')
    local pwd=$(echo "$node" | jq -r '.users[0].password')
    local path=$(echo "$node" | jq -r '.transport.path')
    local sni=$(echo "$node" | jq -r '.tls.server_name // .transport.headers.Host // empty')
    [ -z "$sni" ] && sni=$(curl -s4 icanhazip.com || curl -s6 icanhazip.com)
    sni=$(format_ipv6 "$sni")
    local url="trojan://${pwd}@$(format_ipv6 "$(curl -s4 icanhazip.com || curl -s6 icanhazip.com)"):$port?security=tls&sni=$sni&type=ws&path=$(_url_encode "$path")&host=$sni#$(_url_encode "$tag")"
    echo -e "  ${YELLOW}分享链接:${NC} $url"
  done
}
_delete_node() {
  local idx; jq -r '.inbounds[] | "\(.tag) 端口:\(.listen_port)"' "$CONFIG_FILE" | cat -n
  read -p "选择要删除的节点编号 (0 返回): " idx; [ "$idx" -eq 0 ] && return
  local tag=$(jq -r ".inbounds[$((idx-1))].tag" "$CONFIG_FILE")
  _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[$((idx-1))])" && _atomic_modify_json "$METADATA_FILE" "del(.\"$tag\")" && _success "节点已删除" && _manage_service "restart"
}

# === 修改节点 ===
_modify_node() {
  local idx; jq -r '.inbounds[] | "\(.tag) 端口:\(.listen_port)"' "$CONFIG_FILE" | cat -n
  read -p "选择要修改的节点编号 (0 返回): " idx; [ "$idx" -eq 0 ] && return
  local index=$((idx-1)) node=$(jq ".inbounds[$index]" "$CONFIG_FILE")
  local port=$(echo "$node" | jq -r '.listen_port') pwd=$(echo "$node" | jq -r '.users[0].password') path=$(echo "$node" | jq -r '.transport.path') cert_path=$(echo "$node" | jq -r '.tls.certificate_path') key_path=$(echo "$node" | jq -r '.tls.key_path') domain=$(echo "$node" | jq -r '.tls.server_name')
  _info "当前配置: 端口:$port 密码:$pwd 路径:$path 域名:$domain"
  read -p "新端口 (回车跳过): " new_port; [ -n "$new_port" ] && port=$new_port
  read -p "新密码 (回车跳过): " new_pwd; [ -n "$new_pwd" ] && pwd=$new_pwd
  read -p "新路径 (回车跳过): " new_path; [ -n "$new_path" ] && path=$new_path
  read -p "新域名 (回车跳过): " new_domain; [ -n "$new_domain" ] && {
    domain=$new_domain; mapfile -t CERT < <(_auto_cert "$domain"); cert_path=${CERT[0]}; key_path=${CERT[1]}
  }
  local tag="Trojan-ws-$port" inbound=$(jq -n --arg t "$tag" --arg p "$port" --arg pwd "$pwd" --arg cert "$cert_path" --arg key "$key_path" --arg path "$path" --arg dom "$domain" '
  {type: "trojan", tag: $t, listen: "::", listen_port: ($p|tonumber), users: [{password: $pwd}],
   tls: {enabled: true, certificate_path: $cert, key_path: $key, server_name: $dom},
   transport: {type: "ws", path: $path, headers: {Host: $dom}}}')
  _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index] = $inbound" && _success "节点已更新" && _manage_service "restart"
}

# === 更新 / 自启检查 ===
_update_sing_box() {
  local cur=$(${SINGBOX_BIN} version | head -n1 | sed 's/sing-box version //')
  local arch=$(uname -m) tag=$(case $arch in x86_64|amd64) echo amd64;; aarch64|arm64) echo arm64;; armv7l) echo armv7;; *) _error "架构不支持"; return 1;; esac)
  local api="https://api.github.com/repos/SagerNet/sing-box/releases"
  local ver=$(curl -s "$api" | jq -r '.[0].tag_name' | sed 's/^v//')
  [ "$cur" = "$ver" ] && { _success "已是最新"; return; }
  _info "发现新版本 $ver"; _manage_service "stop"; cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
  local url=$(curl -s "$api" | jq -r ".[0].assets[] | select(.name | contains(\"linux-${tag}.tar.gz\")) | .browser_download_url")
  wget -qO sing-box.tar.gz "$url" && tar -xzf sing-box.tar.gz -C /tmp && mv /tmp/sing-box-*/sing-box ${SINGBOX_BIN} && chmod +x ${SINGBOX_BIN}
  rm -f sing-box.tar.gz; ${SINGBOX_BIN} check -c "$CONFIG_FILE" && _success "更新完成" && _manage_service "start" || { _error "配置不兼容"; mv "${CONFIG_FILE}.bak" "$CONFIG_FILE"; _manage_service "start"; }
}
_check_autostart() {
  case "$INIT_SYSTEM" in
    systemd)
      systemctl is-enabled sing-box &>/dev/null && _success "sing-box 已开机自启" || { _warning "未自启"; read -p "启用自启？(y/N)" e; [[ $e == y|Y ]] && systemctl enable sing-box; }
      systemctl is-enabled acme-renew.timer &>/dev/null && _success "timer 已自启" || _warning "timer 未自启"
      ;;
    openrc)
      rc-update show | grep -q sing-box && _success "sing-box 已自启" || { _warning "未自启"; read -p "启用自启？(y/N)" e; [[ $e == y|Y ]] && rc-update add sing-box default; }
      ;;
    *) _warning "直接模式无自启" ;;
  esac
}

# === 主菜单 ===
_main_menu() {
  while true; do
    clear; cat <<EOF
====================================================
      sing-box 一键 Trojan 脚本 v${SCRIPT_VERSION}
====================================================
【节点管理】
  1) 添加 Trojan 节点
  2) 查看节点分享链接
  3) 删除节点
  4) 修改 Trojan 节点配置
【更新与维护】
  5) 更新 sing-box 程序
  6) 检查开机自启状态
  7) 卸载 sing-box 及脚本
  0) 退出脚本
====================================================
EOF
    read -p "请输入选项 [0-7]: " choice
    case $choice in
      1) _add_trojan_ws_tls ;;
      2) _view_nodes ;;
      3) _delete_node ;;
      4) _modify_node ;;
      5) _update_sing_box ;;
      6) _check_autostart ;;
      7) _uninstall ;;
      0) exit 0 ;;
      *) _error "无效输入" ;;
    esac
    read -n 1 -s -r -p "按任意键返回主菜单..."
  done
}

# === 入口 ===
main() {
  _check_root; _detect_init_system
  if [ ! -f "$SINGBOX_BIN" ]; then
    _install_dependencies; _install_sing_box; _initialize_config_files; _create_service_files
    _info "首次安装完成，正在启动..."; _manage_service "start"
  fi
  _get_public_ip; _main_menu
}
main "$@"
