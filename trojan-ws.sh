#!/usr/bin/env bash
set -euo pipefail

# 颜色定义

RED=’\033[0;31m’
GREEN=’\033[0;32m’
YELLOW=’\033[1;33m’
BLUE=’\033[0;36m’
NC=’\033[0m’

# 路径配置

WORK_DIR=”/etc/trojan-ws”
SINGBOX_BIN=”${WORK_DIR}/sing-box”
CONFIG_FILE=”${WORK_DIR}/config.json”
NODES_FILE=”${WORK_DIR}/nodes.json”

# 打印函数

info() { echo -e “${BLUE}[INFO]${NC} $*”; }
success() { echo -e “${GREEN}[✓]${NC} $*”; }
warn() { echo -e “${YELLOW}[!]${NC} $*”; }
error() { echo -e “${RED}[✗]${NC} $*”; exit 1; }

# 检测系统

detect_system() {
if [ -f /etc/os-release ]; then
. /etc/os-release
OS_ID=”${ID:-unknown}”
fi

```
if echo "$OS_ID" | grep -qi "alpine"; then
    SYSTEM="alpine"
    PKG_INSTALL="apk add --no-cache"
    SERVICE_CMD="rc-service"
    SERVICE_FILE="/etc/init.d/trojan-ws"
elif echo "$OS_ID" | grep -Ei "debian|ubuntu"; then
    SYSTEM="debian"
    PKG_INSTALL="apt-get install -y"
    SERVICE_CMD="systemctl"
    SERVICE_FILE="/etc/systemd/system/trojan-ws.service"
elif echo "$OS_ID" | grep -Ei "centos|rhel|fedora"; then
    SYSTEM="redhat"
    PKG_INSTALL="yum install -y"
    SERVICE_CMD="systemctl"
    SERVICE_FILE="/etc/systemd/system/trojan-ws.service"
else
    error "不支持的系统"
fi
```

}

# 检查root

check_root() {
[ “$(id -u)” != “0” ] && error “需要root权限”
}

# 安装依赖

install_deps() {
info “安装依赖…”
case “$SYSTEM” in
alpine) apk update && $PKG_INSTALL curl jq openssl bash openrc ;;
debian) apt-get update -y && $PKG_INSTALL curl jq openssl ;;
*) $PKG_INSTALL curl jq openssl ;;
esac
}

# 安装sing-box

install_singbox() {
if [ -f “$SINGBOX_BIN” ]; then
local ver=$($SINGBOX_BIN version 2>/dev/null | head -1 || echo “unknown”)
info “当前版本: $ver”
return
fi

```
info "下载 sing-box..."
local arch=$(uname -m)
case $arch in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    armv7l) arch="armv7" ;;
    *) error "不支持的架构: $arch" ;;
esac

local url=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r ".assets[] | select(.name | contains(\"linux-${arch}.tar.gz\")) | .browser_download_url")
[ -z "$url" ] && error "获取下载链接失败"

local tmp=$(mktemp -d)
curl -sL "$url" | tar -xz -C "$tmp"
mv "$tmp"/sing-box-*/sing-box "$SINGBOX_BIN"
chmod +x "$SINGBOX_BIN"
rm -rf "$tmp"

success "sing-box 已安装: $($SINGBOX_BIN version | head -1)"
```

}

# 更新sing-box

update_singbox() {
info “检查更新…”
local current=$($SINGBOX_BIN version 2>/dev/null | awk ‘{print $3}’ || echo “0”)
local latest=$(curl -s “https://api.github.com/repos/SagerNet/sing-box/releases/latest” | jq -r .tag_name | sed ‘s/v//’)

```
if [ "$current" = "$latest" ]; then
    success "已是最新版本: $current"
    return
fi

info "发现新版本: $latest (当前: $current)"
read -p "是否更新? (y/N): " confirm
[[ ! "$confirm" =~ ^[Yy]$ ]] && return

rm -f "$SINGBOX_BIN"
install_singbox
restart_service
```

}

# 获取公网IP

get_public_ip() {
SERVER_IP=$(curl -s4 –max-time 3 icanhazip.com 2>/dev/null || curl -s6 –max-time 3 icanhazip.com 2>/dev/null)
[ -z “$SERVER_IP” ] && error “无法获取公网IP”
}

# 初始化配置

init_config() {
mkdir -p “$WORK_DIR”
[ ! -f “$CONFIG_FILE” ] && echo ‘{“log”:{“level”:“info”},“inbounds”:[],“outbounds”:[{“type”:“direct”,“tag”:“direct”}]}’ > “$CONFIG_FILE”
[ ! -f “$NODES_FILE” ] && echo ‘[]’ > “$NODES_FILE”
}

# 添加节点

add_node() {
get_public_ip
info “添加 Trojan-WS 节点”

```
# 连接地址
info "客户端连接地址 (默认: ${SERVER_IP}):"
read -p "> " conn_addr
conn_addr=${conn_addr:-$SERVER_IP}
[[ "$conn_addr" == *":"* ]] && [[ "$conn_addr" != "["* ]] && conn_addr="[${conn_addr}]"

# 伪装域名
read -p "伪装域名 (与证书一致): " domain
[ -z "$domain" ] && error "域名不能为空"

# 端口
read -p "监听端口 [443]: " port
port=${port:-443}

# WS路径
read -p "WebSocket 路径 [随机]: " ws_path
[ -z "$ws_path" ] && ws_path="/$($SINGBOX_BIN generate rand --hex 8)"
[[ ! "$ws_path" =~ ^/ ]] && ws_path="/${ws_path}"

# 密码
read -p "密码 [随机]: " password
password=${password:-$($SINGBOX_BIN generate rand --hex 16)}

# 证书路径
info "Cloudflare 源服务器证书配置:"
read -p "证书文件路径 (.pem/.crt): " cert_path
[ ! -f "$cert_path" ] && error "证书不存在: $cert_path"

read -p "私钥文件路径 (.key): " key_path
[ ! -f "$key_path" ] && error "私钥不存在: $key_path"

# 生成tag
local tag="trojan-ws-${port}"

# 添加inbound
local inbound=$(jq -n \
    --arg tag "$tag" \
    --argjson port "$port" \
    --arg pwd "$password" \
    --arg cert "$cert_path" \
    --arg key "$key_path" \
    --arg path "$ws_path" \
    '{type:"trojan",tag:$tag,listen:"::",listen_port:$port,users:[{password:$pwd}],tls:{enabled:true,certificate_path:$cert,key_path:$key},transport:{type:"ws",path:$path}}')

jq ".inbounds += [$inbound]" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"

# 保存节点信息
local node=$(jq -n \
    --arg tag "$tag" \
    --arg conn "$conn_addr" \
    --arg domain "$domain" \
    --argjson port "$port" \
    --arg pwd "$password" \
    --arg path "$ws_path" \
    '{tag:$tag,connection:$conn,domain:$domain,port:$port,password:$pwd,path:$path}')

jq ". += [$node]" "$NODES_FILE" > "${NODES_FILE}.tmp" && mv "${NODES_FILE}.tmp" "$NODES_FILE"

success "节点添加成功: $tag"
restart_service
show_node_info "$tag"
```

}

# 显示节点信息

show_node_info() {
local tag=”$1”
local node=$(jq -r “.[] | select(.tag=="$tag")” “$NODES_FILE”)
[ -z “$node” ] && return

```
local conn=$(echo "$node" | jq -r .connection)
local domain=$(echo "$node" | jq -r .domain)
local port=$(echo "$node" | jq -r .port)
local pwd=$(echo "$node" | jq -r .password)
local path=$(echo "$node" | jq -r .path)

local encoded_path=$(echo -n "$path" | jq -sRr @uri)
local url="trojan://${pwd}@${conn}:${port}?security=tls&type=ws&host=${domain}&sni=${domain}&path=${encoded_path}&allowInsecure=1#${tag}"

echo ""
info "节点: $tag"
echo "  连接: $conn:$port"
echo "  域名: $domain"
echo "  密码: $pwd"
echo "  路径: $path"
echo ""
echo "分享链接:"
echo "$url"
echo ""
```

}

# 查看所有节点

view_nodes() {
local count=$(jq ‘length’ “$NODES_FILE”)
[ “$count” -eq 0 ] && warn “无节点” && return

```
info "当前节点 ($count 个):"
jq -r '.[] | "\(.tag) - \(.domain):\(.port)"' "$NODES_FILE" | nl
echo ""
read -p "查看详情 [输入序号/0返回]: " num

[[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
[ "$num" -gt "$count" ] && warn "无效序号" && return

local tag=$(jq -r ".[$((num-1))].tag" "$NODES_FILE")
show_node_info "$tag"
```

}

# 删除节点

delete_node() {
local count=$(jq ‘length’ “$NODES_FILE”)
[ “$count” -eq 0 ] && warn “无节点” && return

```
info "当前节点:"
jq -r '.[] | "\(.tag)"' "$NODES_FILE" | nl

read -p "删除序号 [0取消]: " num
[[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
[ "$num" -gt "$count" ] && warn "无效序号" && return

local tag=$(jq -r ".[$((num-1))].tag" "$NODES_FILE")
read -p "确认删除 $tag? (y/N): " confirm
[[ ! "$confirm" =~ ^[Yy]$ ]] && return

jq "del(.inbounds[] | select(.tag==\"$tag\"))" "$CONFIG_FILE" > "${CONFIG_FILE}.tmp" && mv "${CONFIG_FILE}.tmp" "$CONFIG_FILE"
jq "del(.[$((num-1))])" "$NODES_FILE" > "${NODES_FILE}.tmp" && mv "${NODES_FILE}.tmp" "$NODES_FILE"

success "已删除: $tag"
restart_service
```

}

# 创建服务

create_service() {
if [ “$SERVICE_CMD” = “systemctl” ]; then
cat > “$SERVICE_FILE” <<EOF
[Unit]
Description=Trojan-WS Service
After=network.target
[Service]
Type=simple
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable trojan-ws
else
cat > “$SERVICE_FILE” <<EOF
#!/sbin/openrc-run
description=“Trojan-WS Service”
command=”${SINGBOX_BIN}”
command_args=“run -c ${CONFIG_FILE}”
command_background=“yes”
pidfile=”/run/trojan-ws.pid”
depend() { need net; }
EOF
chmod +x “$SERVICE_FILE”
rc-update add trojan-ws default
fi
}

# 服务管理

start_service() {
if [ “$SERVICE_CMD” = “systemctl” ]; then
systemctl start trojan-ws
else
rc-service trojan-ws start
fi
success “服务已启动”
}

stop_service() {
if [ “$SERVICE_CMD” = “systemctl” ]; then
systemctl stop trojan-ws
else
rc-service trojan-ws stop
fi
success “服务已停止”
}

restart_service() {
if [ “$SERVICE_CMD” = “systemctl” ]; then
systemctl restart trojan-ws
else
rc-service trojan-ws restart
fi
success “服务已重启”
}

status_service() {
if [ “$SERVICE_CMD” = “systemctl” ]; then
systemctl status trojan-ws –no-pager
else
rc-service trojan-ws status
fi
}

# 卸载

uninstall() {
warn “将删除所有配置和服务!”
read -p “确认卸载? (y/N): “ confirm
[[ ! “$confirm” =~ ^[Yy]$ ]] && return

```
if [ "$SERVICE_CMD" = "systemctl" ]; then
    systemctl stop trojan-ws 2>/dev/null || true
    systemctl disable trojan-ws 2>/dev/null || true
    systemctl daemon-reload
else
    rc-service trojan-ws stop 2>/dev/null || true
    rc-update del trojan-ws default 2>/dev/null || true
fi

rm -rf "$WORK_DIR" "$SERVICE_FILE"
success "卸载完成"
exit 0
```

}

# 主菜单

main_menu() {
while true; do
clear
echo “==========================================”
info “  Trojan-WS 管理脚本”
echo “==========================================”
echo “ 1. 添加节点”
echo “ 2. 查看节点”
echo “ 3. 删除节点”
echo “ 4. 更新 sing-box”
echo “ 5. 重启服务”
echo “ 6. 查看状态”
echo “ 7. 卸载”
echo “ 0. 退出”
echo “==========================================”
read -p “选择 [0-7]: “ choice

```
    case $choice in
        1) add_node ;;
        2) view_nodes ;;
        3) delete_node ;;
        4) update_singbox ;;
        5) restart_service ;;
        6) status_service ;;
        7) uninstall ;;
        0) exit 0 ;;
        *) warn "无效选项" ;;
    esac
    
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
done
```

}

# 入口

check_root
detect_system

if [ ! -f “$SINGBOX_BIN” ]; then
install_deps
install_singbox
init_config
create_service
start_service
success “初始化完成”
fi

main_menu
