#!/bin/bash

# --- 全局变量和样式 ---
# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 文件路径常量
SINGBOX_BIN="/usr/local/bin/sing-box"
SINGBOX_DIR="/usr/local/etc/sing-box"
CONFIG_FILE="${SINGBOX_DIR}/config.json"
CLASH_YAML_FILE="${SINGBOX_DIR}/clash.yaml"
METADATA_FILE="${SINGBOX_DIR}/metadata.json"
YQ_BINARY="/usr/local/bin/yq"
SELF_SCRIPT_PATH="$0"
LOG_FILE="/var/log/sing-box.log"
PID_FILE="/run/sing-box.pid"

# Caddy 相关路径
CADDY_BIN="/usr/local/bin/caddy"
CADDY_DIR="/etc/caddy"
CADDY_CONF_DIR="${CADDY_DIR}/233boy"
CADDY_FILE="${CADDY_DIR}/Caddyfile"
CADDY_SERVICE_FILE="/lib/systemd/system/caddy.service"

# 系统特定变量
INIT_SYSTEM="" # 将存储 'systemd', 'openrc' 或 'direct'
SERVICE_FILE="" # 将根据 INIT_SYSTEM 设置

# 脚本元数据
SCRIPT_VERSION="3.0"

# 全局状态变量
server_ip=""

# --- 工具函数 ---

# 打印消息
_echo_style() {
    local color_prefix="$1"
    local message="$2"
    echo -e "${color_prefix}${message}${NC}"
}

_info() { _echo_style "${CYAN}" "$1"; }
_success() { _echo_style "${GREEN}" "$1"; }
_warning() { _echo_style "${YELLOW}" "$1"; }
_error() { _echo_style "${RED}" "$1"; }

# 捕获退出信号，清理临时文件
trap 'rm -f ${SINGBOX_DIR}/*.tmp' EXIT

# 检查root权限
_check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        _error "错误：本脚本需要以 root 权限运行！"
        exit 1
    fi
}

# URL编码
_url_encode() {
    echo -n "$1" | jq -s -R -r @uri
}
export -f _url_encode

# 获取公网IP
_get_public_ip() {
    _info "正在获取服务器公网 IP..."
    server_ip=$(curl -s4 --max-time 2 icanhazip.com || curl -s4 --max-time 2 ipinfo.io/ip)
    if [ -z "$server_ip" ]; then
        server_ip=$(curl -s6 --max-time 2 icanhazip.com || curl -s6 --max-time 2 ipinfo.io/ip)
    fi
    if [ -z "$server_ip" ]; then
        _error "无法获取本机的公网 IP 地址！请检查网络连接。"
        exit 1
    fi
    _success "获取成功: ${server_ip}"
}

# --- 系统环境适配 ---

_detect_init_system() {
    if [ -f "/sbin/openrc-run" ]; then
        INIT_SYSTEM="openrc"
        SERVICE_FILE="/etc/init.d/sing-box"
    elif [ -d "/run/systemd/system" ] && command -v systemctl &>/dev/null; then
        INIT_SYSTEM="systemd"
        SERVICE_FILE="/etc/systemd/system/sing-box.service"
    else
        INIT_SYSTEM="direct"
        SERVICE_FILE="" # 在直接管理模式下无服务文件
        _warning "未检测到 systemd 或 OpenRC。将使用直接进程管理模式。"
        _warning "注意：在此模式下，sing-box 服务无法开机自启。"
    fi
    _info "检测到管理模式为: ${INIT_SYSTEM}"
}

_install_dependencies() {
    _info "正在检查并安装所需依赖..."
    local pkgs_to_install=""
    local required_pkgs="curl jq openssl wget procps"
    local pm=""

    if command -v apk &>/dev/null; then
        pm="apk"
        required_pkgs="bash coreutils ${required_pkgs}"
    elif command -v apt-get &>/dev/null; then pm="apt-get";
    elif command -v dnf &>/dev/null; then pm="dnf";
    elif command -v yum &>/dev/null; then pm="yum";
    else _warning "未能识别的包管理器, 无法自动安装依赖。"; fi

    if [ -n "$pm" ]; then
        if [ "$pm" == "apk" ]; then
            for pkg in $required_pkgs; do ! apk -e info "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            if [ -n "$pkgs_to_install" ]; then
                _info "正在安装缺失的依赖:$pkgs_to_install"
                apk update && apk add --no-cache $pkgs_to_install || { _error "依赖安装失败"; exit 1; }
            fi
        else # for apt, dnf, yum
            if [ "$pm" == "apt-get" ]; then
                for pkg in $required_pkgs; do ! dpkg -s "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            else
                for pkg in $required_pkgs; do ! rpm -q "$pkg" >/dev/null 2>&1 && pkgs_to_install="$pkgs_to_install $pkg"; done
            fi

            if [ -n "$pkgs_to_install" ]; then
                _info "正在安装缺失的依赖:$pkgs_to_install"
                [ "$pm" == "apt-get" ] && $pm update -y
                $pm install -y $pkgs_to_install || { _error "依赖安装失败"; exit 1; }
            fi
        fi
    fi

    if ! command -v yq &>/dev/null; then
        _info "正在安装 yq (用于YAML处理)..."
        local arch=$(uname -m)
        local yq_arch_tag
        case $arch in
            x86_64|amd64) yq_arch_tag='amd64' ;;
            aarch64|arm64) yq_arch_tag='arm64' ;;
            armv7l) yq_arch_tag='arm' ;;
            *) _error "yq 安装失败: 不支持的架构：$arch"; exit 1 ;;
        esac
        
        wget -qO ${YQ_BINARY} "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${yq_arch_tag}" || { _error "yq 下载失败"; exit 1; }
        chmod +x ${YQ_BINARY}
    fi
    _success "所有依赖均已满足。"
}

_install_sing_box() {
    _info "正在安装最新稳定版 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; exit 1 ;;
    esac
    
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    
    if [ -z "$download_url" ]; then _error "无法获取 sing-box 下载链接。"; exit 1; fi
    
    wget -qO sing-box.tar.gz "$download_url" || { _error "下载失败!"; exit 1; }
    
    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    mv "$temp_dir/sing-box-"*"/sing-box" ${SINGBOX_BIN}
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x ${SINGBOX_BIN}
    
    _success "sing-box 安装成功, 版本: $(${SINGBOX_BIN} version)"
}

# --- Caddy 相关功能整合 ---

# 检查并安装 Caddy
_install_caddy() {
    if [ -f "${CADDY_BIN}" ]; then
        _info "Caddy 已安装，跳过安装步骤。"
        return 0
    fi
    
    _info "正在安装 Caddy..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; exit 1 ;;
    esac
    
    local api_url="https://api.github.com/repos/caddyserver/caddy/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    
    if [ -z "$download_url" ]; then _error "无法获取 Caddy 下载链接。"; exit 1; fi
    
    wget -qO caddy.tar.gz "$download_url" || { _error "Caddy 下载失败!"; exit 1; }
    
    local temp_dir=$(mktemp -d)
    tar -xzf caddy.tar.gz -C "$temp_dir"
    
    mkdir -p $(dirname ${CADDY_BIN})
    cp -f "$temp_dir/caddy" ${CADDY_BIN}
    chmod +x ${CADDY_BIN}
    
    rm -rf caddy.tar.gz "$temp_dir"
    _success "Caddy 安装成功: $(${CADDY_BIN} version)"
    return 0
}

# 创建 Caddy systemd 服务
_create_caddy_service() {
    if [ "$INIT_SYSTEM" != "systemd" ]; then
        _warning "非 systemd 系统，跳过 Caddy 服务创建。"
        return 0
    fi
    
    if [ -f "${CADDY_SERVICE_FILE}" ]; then
        _info "Caddy 服务文件已存在。"
        return 0
    fi
    
    _info "正在创建 Caddy systemd 服务..."
    
    cat > "${CADDY_SERVICE_FILE}" <<EOF
[Unit]
Description=Caddy
Documentation=https://caddyserver.com/docs/
After=network.target network-online.target
Requires=network-online.target

[Service]
Type=notify
User=root
Group=root
ExecStart=${CADDY_BIN} run --environ --config ${CADDY_FILE}
ExecReload=${CADDY_BIN} reload --config ${CADDY_FILE}
TimeoutStopSec=5s
LimitNPROC=10000
LimitNOFILE=1048576
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable caddy
    _success "Caddy 服务创建并启用成功。"
}

# 管理 Caddy 服务
_manage_caddy_service() {
    local action="$1"
    [ "$action" == "status" ] || _info "正在执行 Caddy: $action..."

    case "$INIT_SYSTEM" in
        systemd)
            systemctl "$action" caddy
            ;;
        openrc)
            rc-service caddy "$action"
            ;;
        direct)
            case "$action" in
                start)
                    if pgrep -f "${CADDY_BIN}" > /dev/null; then
                        _warning "Caddy 似乎已在运行。"
                        return
                    fi
                    nohup ${CADDY_BIN} run --config ${CADDY_FILE} >> /var/log/caddy.log 2>&1 &
                    _success "Caddy 启动成功。"
                    ;;
                stop)
                    pkill -f "${CADDY_BIN}"
                    _success "Caddy 已停止。"
                    ;;
                restart)
                    _manage_caddy_service "stop"
                    sleep 2
                    _manage_caddy_service "start"
                    ;;
                status)
                    if pgrep -f "${CADDY_BIN}" > /dev/null; then
                        _success "Caddy 正在运行。"
                    else
                        _error "Caddy 未运行。"
                    fi
                    ;;
            esac
            ;;
    esac
}

# 初始化 Caddy 配置
_initialize_caddy_config() {
    if [ -f "${CADDY_FILE}" ]; then
        _info "Caddy 配置文件已存在。"
        return 0
    fi
    
    _info "正在初始化 Caddy 配置..."
    
    mkdir -p "${CADDY_DIR}" "${CADDY_CONF_DIR}"
    
    cat > "${CADDY_FILE}" <<EOF
# Caddy 主配置文件
# 自动管理 TLS 证书
{
    admin off
    email your-email@example.com  # 建议替换为你的邮箱
}

# 导入所有站点配置
import ${CADDY_CONF_DIR}/*.conf
EOF
    
    _success "Caddy 配置文件初始化完成。"
}

# --- 服务与配置管理 ---

_create_systemd_service() {
    if [ "$INIT_SYSTEM" == "direct" ]; then
        _info "在直接管理模式下，无需创建服务文件。"
        return
    fi
    if [ -f "$SERVICE_FILE" ]; then return; fi
    
    _info "正在创建 ${INIT_SYSTEM} 服务文件..."
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target
[Service]
ExecStart=${SINGBOX_BIN} run -c ${CONFIG_FILE}
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable sing-box
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        cat > "$SERVICE_FILE" <<EOF
#!/sbin/openrc-run

description="sing-box service"
command="${SINGBOX_BIN}"
command_args="run -c ${CONFIG_FILE}"
command_user="root"
pidfile="${PID_FILE}"

depend() {
    need net
    after firewall
}

start() {
    ebegin "Starting sing-box"
    start-stop-daemon --start --background \\
        --make-pidfile --pidfile \${pidfile} \\
        --exec \${command} -- \${command_args} >> "${LOG_FILE}" 2>&1
    eend \$?
}

stop() {
    ebegin "Stopping sing-box"
    start-stop-daemon --stop --pidfile \${pidfile}
    eend \$?
}
EOF
        chmod +x "$SERVICE_FILE"
        rc-update add sing-box default
    fi
    _success "${INIT_SYSTEM} 服务创建并启用成功。"
}

_manage_service() {
    local action="$1"
    [ "$action" == "status" ] || _info "正在使用 ${INIT_SYSTEM} 执行: $action..."

    case "$INIT_SYSTEM" in
        systemd)
            case "$action" in
                start|stop|restart|enable|disable) systemctl "$action" sing-box ;;
                status) systemctl status sing-box --no-pager -l; return ;;
                *) _error "无效的服务管理命令: $action"; return ;;
            esac
            ;;
        openrc)
             if [ "$action" == "status" ]; then
                rc-service sing-box status
                return
             fi
             rc-service sing-box "$action"
            ;;
        direct)
            case "$action" in
                start)
                    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _warning "sing-box 似乎已在运行。"
                        return
                    fi
                    touch "$LOG_FILE"
                    nohup ${SINGBOX_BIN} run -c ${CONFIG_FILE} >> ${LOG_FILE} 2>&1 &
                    echo $! > ${PID_FILE}
                    sleep 1
                    if ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _success "sing-box 启动成功, PID: $(cat ${PID_FILE})。"
                    else
                        _error "sing-box 启动失败，请检查日志: ${LOG_FILE}"
                        rm -f ${PID_FILE}
                    fi
                    ;;
                stop)
                    if [ ! -f "$PID_FILE" ]; then
                        _warning "未找到 PID 文件，可能未在运行。"
                        return
                    fi
                    local pid=$(cat "$PID_FILE")
                    if ps -p $pid > /dev/null; then
                        kill $pid
                        sleep 1
                        if ps -p $pid > /dev/null; then
                           _warning "无法正常停止，正在强制终止..."
                           kill -9 $pid
                        fi
                    else
                        _warning "PID 文件中的进程 ($pid) 不存在。"
                    fi
                    rm -f ${PID_FILE}
                    ;;
                restart)
                    _manage_service "stop"
                    _manage_service "start"
                    ;;
                status)
                    if [ -f "$PID_FILE" ] && ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _success "sing-box 正在运行, PID: $(cat ${PID_FILE})。"
                    else
                        _error "sing-box 未运行。"
                    fi
                    return
                    ;;
                 *) _error "无效的命令: $action"; return ;;
            esac
            ;;
    esac
    _success "sing-box 服务已 $action"
}

_view_log() {
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _info "按 Ctrl+C 退出日志查看。"
        journalctl -u sing-box -f --no-pager
    else # 适用于 openrc 和 direct 模式
        if [ ! -f "$LOG_FILE" ]; then
            _warning "日志文件 ${LOG_FILE} 不存在。"
            return
        fi
        _info "按 Ctrl+C 退出日志查看 (日志文件: ${LOG_FILE})。"
        tail -f "$LOG_FILE"
    fi
}

_uninstall() {
    _warning "！！！警告！！！"
    _warning "本操作将停止并禁用 sing-box 服务，删除所有相关文件以及本脚本自身。"
    read -p "$(echo -e ${YELLOW}"确定要执行卸载吗? (y/N): "${NC})" confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        _manage_service "stop"
        if [ "$INIT_SYSTEM" == "systemd" ]; then
            systemctl disable sing-box >/dev/null 2>&1
            systemctl daemon-reload
        elif [ "$INIT_SYSTEM" == "openrc" ]; then
            rc-update del sing-box default >/dev/null 2>&1
        fi
        
        # 停止 Caddy
        _manage_caddy_service "stop"
        if [ "$INIT_SYSTEM" == "systemd" ]; then
            systemctl disable caddy >/dev/null 2>&1
            systemctl daemon-reload
        elif [ "$INIT_SYSTEM" == "openrc" ]; then
            rc-update del caddy default >/dev/null 2>&1
        fi
        
        rm -rf ${SINGBOX_BIN} ${SINGBOX_DIR} ${SERVICE_FILE} ${YQ_BINARY} ${LOG_FILE} ${PID_FILE}
        rm -rf ${CADDY_BIN} ${CADDY_DIR} ${CADDY_SERVICE_FILE}
        _success "清理完成。脚本已自毁。再见！"
        rm -f "${SELF_SCRIPT_PATH}"
        exit 0
    else
        _info "卸载已取消。"
    fi
}

_initialize_config_files() {
    mkdir -p ${SINGBOX_DIR}
    [ -s "$CONFIG_FILE" ] || echo '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$CONFIG_FILE"
    [ -s "$METADATA_FILE" ] || echo "{}" > "$METADATA_FILE"
    if [ ! -s "$CLASH_YAML_FILE" ]; then
        _info "正在创建全新的 clash.yaml 配置文件..."
        cat > "$CLASH_YAML_FILE" << 'EOF'
port: 7890
socks-port: 7891
mixed-port: 7892
allow-lan: false
bind-address: '*'
mode: rule
log-level: info
ipv6: false
find-process-mode: strict
external-controller: '127.0.0.1:9090'
profile:
  store-selected: true
  store-fake-ip: true
unified-delay: true
tcp-concurrent: true
ntp:
  enable: true
  write-to-system: false
  server: ntp.aliyun.com
  port: 123
  interval: 30
dns:
  enable: true
  respect-rules: true
  use-systems-hosts: true
  prefer-h3: false
  listen: '0.0.0.0:1053'
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  use-hosts: true
  fake-ip-filter:
    - +.lan
    - +.local
    - localhost.ptlogin2.qq.com
    - +.msftconnecttest.com
    - +.msftncsi.com
  nameserver:
    - 1.1.1.1
    - 8.8.8.8
    - 'https://1.1.1.1/dns-query'
    - 'https://dns.quad9.net/dns-query'
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  fallback:
    - 'https://1.0.0.1/dns-query'
    - 'https://9.9.9.10/dns-query'
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4
tun:
  enable: true
  stack: system
  auto-route: true
  auto-detect-interface: true
  strict-route: false
  dns-hijack:
    - 'any:53'
  device: SakuraiTunnel
  endpoint-independent-nat: true
proxies: []
proxy-groups:
  - name: 节点选择
    type: select
    proxies: []
rules:
  - GEOIP,PRIVATE,DIRECT,no-resolve
  - GEOIP,CN,DIRECT
  - MATCH,节点选择
EOF
    fi
}

_generate_self_signed_cert() {
    local domain="$1"
    local cert_path="$2"
    local key_path="$3"

    _info "正在为 ${domain} 生成自签名证书..."
    openssl ecparam -genkey -name prime256v1 -out "$key_path" >/dev/null 2>&1
    openssl req -new -x509 -days 3650 -key "$key_path" -out "$cert_path" -subj "/CN=${domain}" >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        _error "为 ${domain} 生成证书失败！"
        rm -f "$cert_path" "$key_path"
        return 1
    fi
    _success "证书 ${cert_path} 和私钥 ${key_path} 已成功生成。"
    return 0
}

_atomic_modify_json() {
    local file_path="$1"
    local jq_filter="$2"
    cp "$file_path" "${file_path}.tmp"
    if jq "$jq_filter" "${file_path}.tmp" > "$file_path"; then
        rm "${file_path}.tmp"
    else
        _error "修改JSON文件 '$file_path' 失败！配置已回滚。"
        mv "${file_path}.tmp" "$file_path"
        return 1
    fi
}

_atomic_modify_yaml() {
    local file_path="$1"
    local yq_filter="$2"
    cp "$file_path" "${file_path}.tmp"
    if ${YQ_BINARY} eval "$yq_filter" -i "$file_path"; then
        rm "${file_path}.tmp"
    else
        _error "修改YAML文件 '$file_path' 失败！配置已回滚。"
        mv "${file_path}.tmp" "$file_path"
        return 1
    fi
}

_add_node_to_yaml() {
    local proxy_json="$1"
    local proxy_name=$(echo "$proxy_json" | jq -r .name)
    _atomic_modify_yaml "$CLASH_YAML_FILE" ".proxies |= . + [${proxy_json}] | .proxies |= unique_by(.name)"
    _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= . + ["'${proxy_name}'"] | .proxies |= unique)'
}

_remove_node_from_yaml() {
    local proxy_name="$1"
    _atomic_modify_yaml "$CLASH_YAML_FILE" 'del(.proxies[] | select(.name == "'${proxy_name}'"))'
    _atomic_modify_yaml "$CLASH_YAML_FILE" '.proxy-groups[] |= (select(.name == "节点选择") | .proxies |= del(.[] | select(. == "'${proxy_name}'")))'
}

# --- 核心功能：添加 Trojan (WebSocket+TLS) 节点，集成 Caddy ---

_add_trojan_ws_tls() {
    _info "--- Trojan (WebSocket+TLS) 设置向导 [Caddy 反向代理模式] ---"
    
    # 步骤 0: 安装并初始化 Caddy
    _install_caddy
    _initialize_caddy_config
    _create_caddy_service
    
    # 步骤 1: 获取连接地址
    _info "请输入客户端用于“连接”的地址:"
    _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
    _info "  - (其他)   您也可以手动输入一个IP或域名 (用于 Cloudflare 优选)"
    read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
    
    local client_server_addr=${connection_address:-$server_ip}
    
    if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
         client_server_addr="[${client_server_addr}]"
    fi

    # 步骤 2: 获取伪装域名 (用于 TLS 证书)
    _info "请输入您的“伪装域名”，必须是能解析到本机的域名。"
    _info "  - 用于申请 Let's Encrypt 证书"
    _info "  - Cloudflare 的 SNI 也会使用此域名"
    read -p "请输入伪装域名: " camouflage_domain
    [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

    # 步骤 3: 端口 - 这是关键！Caddy 和 sing-box 共用此端口
    _info "请输入监听端口 (该端口将被 Caddy 监听并反代到 sing-box)"
    read -p "请输入端口 (建议 10000-65535): " port
    [[ -z "$port" ]] && _error "端口不能为空" && return 1
    
    # 检查端口是否被占用 (排除 80/443)
    if [[ "$port" != "80" && "$port" != "443" ]]; then
        if ss -tuln | grep -q ":${port}"; then
            _warning "端口 ${port} 已被占用，可能被其他服务使用。"
        fi
    fi

    # 步骤 4: 密码
    read -p "请输入密码 (默认随机生成): " password
    if [ -z "$password" ]; then
        password=$(${SINGBOX_BIN} generate rand --base64 16)
        _info "已为您生成随机密码: ${password}"
    fi

    # 步骤 5: WebSocket 路径
    read -p "请输入 WebSocket 路径 (回车则随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已为您生成随机 WebSocket 路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    # 步骤 6: 配置 sing-box 入站 (监听本地回环地址)
    local tag="trojan-ws-in-${port}"
    local name="Trojan-WS-${port}"
    
    # sing-box 配置，监听 127.0.0.1:PORT (明文 WebSocket)
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg wsp "$ws_path" \
        '{
            "type": "trojan",
            "tag": $t,
            "listen": "127.0.0.1",
            "listen_port": ($p|tonumber),
            "users": [{"password": $pw}],
            "transport": {
                "type": "ws",
                "path": $wsp
            }
        }')
    
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    # 步骤 7: 配置 Caddy (监听 0.0.0.0:PORT，自动管理 TLS)
    _info "正在为域名 ${camouflage_domain} 配置 Caddy (监听 0.0.0.0:${port})..."
    
    mkdir -p "${CADDY_CONF_DIR}"
    local caddy_site_conf="${CADDY_CONF_DIR}/${camouflage_domain}.conf"
    
    # Caddy 配置：接收外部 TLS 流量，终止 TLS，反代到本地 sing-box
    cat > "${caddy_site_conf}" <<EOF
${camouflage_domain}:${port} {
    tls {
        protocols tls1.2 tls1.3
    }
    @ws {
        path ${ws_path}
        header Connection *Upgrade*
        header Upgrade websocket
    }
    reverse_proxy @ws 127.0.0.1:${port}
    
    # 健康检查或其他路径处理
    handle {
        respond "Service Running" 200
    }
}
EOF
    
    _success "Caddy 站点配置已生成: ${caddy_site_conf}"
    
    # 步骤 8: 临时停止 sing-box 以释放端口，启动 Caddy 申请证书
    _info "临时停止 sing-box 服务以释放端口 ${port}..."
    _manage_service "stop"
    
    sleep 2
    
    _info "启动 Caddy 以申请 TLS 证书 (需要 80/443 端口)..."
    _manage_caddy_service "stop" 2>/dev/null
    _manage_caddy_service "start"
    
    # 等待 Caddy 启动并申请证书
    _info "等待 Caddy 申请证书 (约 10-30 秒)..."
    sleep 30
    
    # 检查证书是否成功申请
    local cert_dir="/root/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/${camouflage_domain}"
    if [ -d "$cert_dir" ]; then
        _success "证书申请成功！证书路径: ${cert_dir}"
    else
        _warning "证书申请可能失败，请检查 Caddy 日志。"
        _warning "你也可以使用 CF Origin CA 证书或自签名证书。"
    fi
    
    # 步骤 9: 重启 sing-box (监听 127.0.0.1:PORT)
    _info "重启 sing-box 服务 (监听 127.0.0.1:${port})..."
    _manage_service "start"
    
    sleep 2
    
    # 步骤 10: 生成代理配置 (Clash YAML)
    local proxy_json=$(jq -n \
            --arg n "$name" \
            --arg s "$client_server_addr" \
            --arg p "$port" \
            --arg pw "$password" \
            --arg sn "$camouflage_domain" \
            --arg wsp "$ws_path" \
            '{
                "name": $n,
                "type": "trojan",
                "server": $s,
                "port": ($p|tonumber),
                "password": $pw,
                "sni": $sn,
                "skip-cert-verify": false,
                "network": "ws",
                "ws-opts": {
                    "path": $wsp,
                    "headers": {
                        "Host": $sn
                    }
                }
            }')
            
    _add_node_to_yaml "$proxy_json"
    
    # 步骤 11: 显示完整配置信息
    _success "Trojan (WebSocket+TLS) 节点添加成功!"
    _info "--- 配置摘要 ---"
    _info "节点名称: ${name}"
    _info "客户端连接地址: ${client_server_addr}"
    _info "端口: ${port} (Caddy 和 sing-box 共用)"
    _info "伪装域名: ${camouflage_domain}"
    _info "密码: ${password}"
    _info "WebSocket 路径: ${ws_path}"
    _info ""
    _info "--- 工作原理 ---"
    _info "1. Caddy 监听 0.0.0.0:${port}，提供 TLS 终止"
    _info "2. Caddy 将 WebSocket 流量反代到 127.0.0.1:${port}"
    _info "3. sing-box 监听 127.0.0.1:${port}，接收明文 WebSocket"
    _info "4. Cloudflare Origin Rule: 域名 → ${server_ip}:${port}"
    _info ""
    _info "--- 客户端配置 ---"
    _info "地址: ${client_server_addr}"
    _info "端口: ${port}"
    _info "密码: ${password}"
    _info "SNI: ${camouflage_domain}"
    _info "WebSocket 路径: ${ws_path}"
    
    # 步骤 12: 生成分享链接
    local encoded_path=$(_url_encode "$ws_path")
    local url="trojan://${password}@${client_server_addr}:${port}?security=tls&sni=${camouflage_domain}&type=ws&path=${encoded_path}#$(_url_encode "${name}")"
    _info ""
    _info "分享链接: ${url}"
}

_view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    
    _info "--- 当前节点信息 (共 $(jq '.inbounds | length' "$CONFIG_FILE") 个) ---"
    jq -c '.inbounds[]' "$CONFIG_FILE" | while read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') type=$(echo "$node" | jq -r '.type') port=$(echo "$node" | jq -r '.listen_port')
        
        local proxy_name_to_find=""
        local proxy_obj_by_port=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}')' ${CLASH_YAML_FILE} | head -n 1)

        if [ -n "$proxy_obj_by_port" ]; then
             proxy_name_to_find=$(echo "$proxy_obj_by_port" | ${YQ_BINARY} eval '.name' -)
        fi

        if [[ -z "$proxy_name_to_find" ]]; then
            proxy_name_to_find=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port}' or .port == 443) | .name' ${CLASH_YAML_FILE} | head -n 1)
        fi

        local display_server=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .server' ${CLASH_YAML_FILE} | head -n 1)
        local display_sni=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .sni' ${CLASH_YAML_FILE} | head -n 1)
        
        echo "-------------------------------------"
        _info " 节点: ${tag}"
        local url=""
        case "$type" in
            "trojan")
                local password=$(echo "$node" | jq -r '.users[0].password')
                local server_addr=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .server' ${CLASH_YAML_FILE} | head -n 1)
                local host_header=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .ws-opts.headers.Host' ${CLASH_YAML_FILE} | head -n 1)
                local client_port=$(${YQ_BINARY} eval '.proxies[] | select(.name == "'${proxy_name_to_find}'") | .port' ${CLASH_YAML_FILE} | head -n 1)
                local ws_path=$(echo "$node" | jq -r '.transport.path')
                local encoded_path=$(_url_encode "$ws_path")
                
                url="trojan://${password}@${server_addr}:${client_port}?security=tls&sni=${display_sni}&type=ws&path=${encoded_path}#$(_url_encode "$tag")"
                ;;
        esac
        [ -n "$url" ] && echo -e "  ${YELLOW}分享链接:${NC} ${url}"
    done
    echo "-------------------------------------"
}

_delete_node() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    _info "--- 节点删除 ---"
    jq -r '.inbounds[] | "\(.tag) (\(.type)) @ \(.listen_port)"' "$CONFIG_FILE" | cat -n
    read -p "请输入要删除的节点编号 (输入 0 返回): " num
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    local count=$(jq '.inbounds | length' "$CONFIG_FILE")
    if [ "$num" -gt "$count" ]; then _error "编号超出范围。"; return; fi

    local index=$((num - 1))
    local node_to_del_obj=$(jq ".inbounds[$index]" "$CONFIG_FILE")
    local tag_to_del=$(echo "$node_to_del_obj" | jq -r ".tag")
    local port_to_del=$(echo "$node_to_del_obj" | jq -r ".listen_port")

    local proxy_name_to_del=$(${YQ_BINARY} eval '.proxies[] | select(.port == '${port_to_del}') | .name' ${CLASH_YAML_FILE} | head -n 1)

    read -p "$(echo -e ${YELLOW}"确定要删除节点 ${tag_to_del} 吗? (y/N): "${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "删除已取消。"
        return
    fi
    
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[${index}])" || return
    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_del\")" || return
    if [ -n "$proxy_name_to_del" ]; then
        _remove_node_from_yaml "$proxy_name_to_del"
    fi
    
    # 删除对应的 Caddy 配置
    local caddy_conf_file="${CADDY_CONF_DIR}/*.conf"
    for conf in ${caddy_conf_file}; do
        if [[ -f "$conf" ]] && grep -q "127.0.0.1:${port_to_del}" "$conf"; then
            rm -f "$conf" "${conf}.add"
            _info "已删除相关 Caddy 配置: $conf"
            break
        fi
    done
    
    _success "节点 ${tag_to_del} 已删除！"
    _manage_service "restart"
    _manage_caddy_service "restart"
}

_check_config() {
    _info "正在检查 sing-box 配置文件..."
    local result=$(${SINGBOX_BIN} check -c ${CONFIG_FILE})
    if [[ $? -eq 0 ]]; then
        _success "配置文件 (${CONFIG_FILE}) 格式正确。"
    else
        _error "配置文件检查失败:"
        echo "$result"
    fi
}

# 新增：一键更新 sing-box 程序
_update_sing_box() {
    _warning "即将更新 sing-box 程序到最新稳定版..."
    _warning "当前版本: $(${SINGBOX_BIN} version)"
    read -p "$(echo -e ${YELLOW}"确定要继续吗? (y/N): "${NC})" confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "更新已取消。"
        return
    fi
    
    _info "正在停止 sing-box 服务..."
    _manage_service "stop"
    
    _info "正在备份当前配置文件..."
    cp "$CONFIG_FILE" "${CONFIG_FILE}.backup"
    cp "$CLASH_YAML_FILE" "${CLASH_YAML_FILE}.backup"
    
    _info "正在下载最新版 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; return 1 ;;
    esac
    
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
    local download_url=$(curl -s "$api_url" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    
    if [ -z "$download_url" ]; then
        _error "无法获取 sing-box 下载链接。"
        _manage_service "start"
        return 1
    fi
    
    if wget -qO sing-box.tar.gz "$download_url"; then
        local temp_dir=$(mktemp -d)
        tar -xzf sing-box.tar.gz -C "$temp_dir"
        
        mv "$temp_dir/sing-box-"*"/sing-box" ${SINGBOX_BIN}
        chmod +x ${SINGBOX_BIN}
        
        rm -rf sing-box.tar.gz "$temp_dir"
        
        _success "sing-box 更新成功！"
        _success "新版本: $(${SINGBOX_BIN} version)"
        
        _info "正在检查配置文件兼容性..."
        if ${SINGBOX_BIN} check -c ${CONFIG_FILE} >/dev/null 2>&1; then
            _success "配置文件检查通过。"
        else
            _warning "配置文件可能存在兼容性问题，请检查。"
        fi
        
        _info "正在重启 sing-box 服务..."
        _manage_service "start"
        
        _success "sing-box 更新完成！"
    else
        _error "下载失败，已回滚到旧版本。"
        mv "${CONFIG_FILE}.backup" "$CONFIG_FILE" 2>/dev/null
        mv "${CLASH_YAML_FILE}.backup" "$CLASH_YAML_FILE" 2>/dev/null
        _manage_service "start"
    fi
}

_main_menu() {
    while true; do
        clear
        echo "===================================================="
        _info "      sing-box 全功能管理脚本 v${SCRIPT_VERSION}"
        echo "===================================================="
        _info "【节点管理】"
        echo "  1) 添加 Trojan 节点 (Caddy 反代模式)"
        echo "  2) 查看节点分享链接"
        echo "  3) 删除节点"
        echo "----------------------------------------------------"
        _info "【服务控制】"
        echo "  4) 重启 sing-box"
        echo "  5) 停止 sing-box"
        echo "  6) 查看 sing-box 运行状态"
        echo "  7) 查看 sing-box 实时日志"
        echo "  a) 重启 Caddy 服务"
        echo "  b) 查看 Caddy 运行状态"
        echo "----------------------------------------------------"
        _info "【更新与维护】"
        echo "  8) 检查配置文件"
        echo "  9) 更新 sing-box 程序"
        echo "----------------------------------------------------"
        echo " 10) 卸载 sing-box 及脚本"
        echo "  0) 退出脚本"
        echo "===================================================="
        read -p "请输入选项 [0-10]: " choice

        case $choice in
            1) _add_trojan_ws_tls ;;
            2) _view_nodes ;;
            3) _delete_node ;;
            4) _manage_service "restart" ;;
            5) _manage_service "stop" ;;
            6) _manage_service "status" ;;
            7) _view_log ;;
            a) _manage_caddy_service "restart" ;;
            b) _manage_caddy_service "status" ;;
            8) _check_config ;;
            9) _update_sing_box ;;
           10) _uninstall ;;
            0) exit 0 ;;
            *) _error "无效输入，请重试。" ;;
        esac
        echo
        read -n 1 -s -r -p "按任意键返回主菜单..."
    done
}

# --- 脚本入口 ---

main() {
    _check_root
    _detect_init_system
    
    if [ ! -f "${SINGBOX_BIN}" ]; then
        _install_dependencies
        _install_sing_box
        _initialize_config_files
        _create_service_files
        _info "首次安装完成！正在启动 sing-box 服务..."
        _manage_service "start"
    fi
    
    _get_public_ip
    _main_menu
}

main
