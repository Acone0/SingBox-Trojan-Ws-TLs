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
METADATA_FILE="${SINGBOX_DIR}/metadata.json"
SELF_SCRIPT_PATH="$0"
LOG_FILE="/var/log/sing-box.log"
PID_FILE="/run/sing-box.pid"
ACME_SH_HOME="/root/.acme.sh"

# 系统特定变量
INIT_SYSTEM="" # 将存储 'systemd', 'openrc' 或 'direct'
SERVICE_FILE="" # 将根据 INIT_SYSTEM 设置

# 脚本元数据
SCRIPT_VERSION="4.0"

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
    _success "所有依赖均已满足。"
}

_install_sing_box() {
    _info "正在安装最新版本 sing-box..."
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; exit 1 ;;
    esac
    
    # 使用 releases 接口而非 latest，获取最新版本（包括预发行版）
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases"
    local release_info=$(curl -s "$api_url" | jq -r '.[0]')
    local version=$(echo "$release_info" | jq -r '.tag_name')
    local is_prerelease=$(echo "$release_info" | jq -r '.prerelease')
    
    if [ "$is_prerelease" == "true" ]; then
        _warning "检测到最新版本为预发行版: ${version}"
    else
        _info "检测到最新版本: ${version}"
    fi
    
    local download_url=$(echo "$release_info" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    
    if [ -z "$download_url" ]; then _error "无法获取 sing-box 下载链接。"; exit 1; fi
    
    _info "正在下载: $download_url"
    wget -qO sing-box.tar.gz "$download_url" || { _error "下载失败!"; exit 1; }
    
    local temp_dir=$(mktemp -d)
    tar -xzf sing-box.tar.gz -C "$temp_dir"
    mv "$temp_dir/sing-box-"*"/sing-box" ${SINGBOX_BIN}
    rm -rf sing-box.tar.gz "$temp_dir"
    chmod +x ${SINGBOX_BIN}
    
    _success "sing-box 安装成功, 版本: $(${SINGBOX_BIN} version)"
}

# --- 服务与配置管理 ---

_create_systemd_service() {
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
}

_create_openrc_service() {
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
}

_create_service_files() {
    if [ "$INIT_SYSTEM" == "direct" ]; then
        _info "在直接管理模式下，无需创建服务文件。"
        return
    fi
    if [ -f "$SERVICE_FILE" ]; then return; fi
    
    _info "正在创建 ${INIT_SYSTEM} 服务文件..."
    if [ "$INIT_SYSTEM" == "systemd" ]; then
        _create_systemd_service
        systemctl daemon-reload
        systemctl enable sing-box
    elif [ "$INIT_SYSTEM" == "openrc" ]; then
        touch "$LOG_FILE"
        _create_openrc_service
        rc-update add sing-box default
    fi
    _success "${INIT_SYSTEM} 服务创建并启用成功。"
}

# 简化后的服务管理，仅保留启动和重启
_manage_service() {
    local action="$1"
    
    case "$INIT_SYSTEM" in
        systemd)
            systemctl "$action" sing-box
            ;;
        openrc)
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
                restart)
                    if [ -f "$PID_FILE" ]; then
                        local pid=$(cat "$PID_FILE")
                        if ps -p $pid > /dev/null; then
                            kill $pid
                            sleep 1
                            if ps -p $pid > /dev/null; then
                               kill -9 $pid
                            fi
                        fi
                        rm -f ${PID_FILE}
                    fi
                    touch "$LOG_FILE"
                    nohup ${SINGBOX_BIN} run -c ${CONFIG_FILE} >> ${LOG_FILE} 2>&1 &
                    echo $! > ${PID_FILE}
                    sleep 1
                    if ps -p "$(cat "$PID_FILE")" > /dev/null; then
                        _success "sing-box 重启成功, PID: $(cat ${PID_FILE})。"
                    else
                        _error "sing-box 启动失败，请检查日志: ${LOG_FILE}"
                        rm -f ${PID_FILE}
                    fi
                    ;;
                 *) _error "无效的命令: $action"; return ;;
            esac
            ;;
    esac
}

_uninstall() {
    _warning "！！！警告！！！"
    _warning "本操作将停止并禁用 sing-box 服务，删除所有相关文件以及本脚本自身。"
    read -p "$(echo -e ${YELLOW}"确定要执行卸载吗? (y/N): "${NC})" confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        _manage_service "stop"
        
        # 移除服务
        if [ "$INIT_SYSTEM" == "systemd" ]; then
            systemctl disable sing-box >/dev/null 2>&1
            systemctl daemon-reload
            
            # 移除 acme.sh timer
            systemctl disable --now acme-renew.timer >/dev/null 2>&1
            rm -f /etc/systemd/system/acme-renew.service /etc/systemd/system/acme-renew.timer
            systemctl daemon-reload
        elif [ "$INIT_SYSTEM" == "openrc" ]; then
            rc-update del sing-box default >/dev/null 2>&1
        fi
        
        # 移除 cron 任务
        if command -v crontab &>/dev/null; then
            crontab -l 2>/dev/null | grep -v "acme.sh --cron" > /tmp/cron.tmp
            crontab /tmp/cron.tmp
            rm -f /tmp/cron.tmp
        fi
        
        # 删除所有相关文件和目录
        rm -rf ${SINGBOX_BIN} ${SINGBOX_DIR} ${SERVICE_FILE} ${LOG_FILE} ${PID_FILE}
        rm -rf ${ACME_SH_HOME}
        
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

# 检查并安装 acme.sh
_check_acme_sh() {
    if [ ! -f "${ACME_SH_HOME}/acme.sh" ]; then
        _info "正在安装 acme.sh..."
        if ! curl https://get.acme.sh | sh; then
            _error "acme.sh 安装失败！"
            return 1
        fi
    fi
    return 0
}

# 设置证书自动续期（全平台强制 systemd-timer，无 systemd 再回退）
_setup_cert_renewal() {
    _info "设置 Let's Encrypt 证书自动续期..."

    # 1) 必须存在 systemd
    if [ "$INIT_SYSTEM" != "systemd" ]; then
        _warning "当前非 systemd，无法使用 timer；请手动执行 ${ACME_SH_HOME}/acme.sh --cron"
        return 0
    fi

    # 2) 单元文件路径
    local SERVICE_FILE="/etc/systemd/system/acme-renew.service"
    local TIMER_FILE="/etc/systemd/system/acme-renew.timer"

    # 3) 写入 service 单元（fullchain + 重启 sing-box）
    cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=Renew Let's Encrypt certificates
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '/root/.acme.sh/acme.sh --cron --home /root/.acme.sh \
&& systemctl is-active --quiet sing-box && systemctl restart sing-box'
EOF

    # 4) 写入 timer 单元（每天 00:00，错过开机补跑）
    cat > "$TIMER_FILE" <<'EOF'
[Unit]
Description=Daily renewal check

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
EOF

    # 5) 重载+启用+立即启动
    systemctl daemon-reload
    systemctl enable --now acme-renew.timer

    # 6) 验证
    if systemctl is-enabled acme-renew.timer &>/dev/null; then
        _success "systemd timer 已创建并设为开机自启"
        systemctl list-timers acme-renew.timer --no-pager
    else
        _error "timer 启用失败，请检查 systemd 是否正常运行"
    fi
}

# 自动申请 Let's Encrypt 证书
_auto_cert() {
    local domain="$1"
    
    _check_acme_sh || return 1
    
    if [ -z "$CF_Token" ] || [ -z "$CF_Zone_ID" ]; then
        _info "请设置 Cloudflare API 信息:"
        read -p "请输入 CF_Token (Global API Key 或 API Token): " CF_Token
        read -p "请输入 CF_Zone_ID: " CF_Zone_ID
        
        export CF_Token
        export CF_Zone_ID
        
        echo "export CF_Token=\"${CF_Token}\"" > ${SINGBOX_DIR}/cloudflare.conf
        echo "export CF_Zone_ID=\"${CF_Zone_ID}\"" >> ${SINGBOX_DIR}/cloudflare.conf
    fi
    
    if [ -f ${SINGBOX_DIR}/cloudflare.conf ]; then
        source ${SINGBOX_DIR}/cloudflare.conf
    fi
    
    _info "正在为域名 ${domain} 申请 Let's Encrypt 证书..."
    _info "使用 Cloudflare DNS 验证方式"
    
    ${ACME_SH_HOME}/acme.sh --issue --dns dns_cf -d "${domain}" --server letsencrypt
    
    if [ $? -eq 0 ]; then
        _success "证书申请成功！"
        
        local cert_path="${ACME_SH_HOME}/${domain}_ecc/fullchain.cer"
        local key_path="${ACME_SH_HOME}/${domain}_ecc/${domain}.key"
        
        _info "证书路径: ${cert_path}"
        _info "私钥路径: ${key_path}"
        
        _setup_cert_renewal
        
        return 0
    else
        _error "证书申请失败！请检查 Cloudflare API 配置和域名"
        return 1
    fi
}

_add_trojan_ws_tls() {
    _info "--- Trojan (WebSocket+TLS) 设置向导 ---"
    
    _info "请输入客户端用于“连接”的地址:"
    _info "  - (推荐) 直接回车, 使用VPS的公网 IP: ${server_ip}"
    _info "  - (其他)   您也可以手动输入一个IP或域名"
    read -p "请输入连接地址 (默认: ${server_ip}): " connection_address
    
    local client_server_addr=${connection_address:-$server_ip}
    
    if [[ "$client_server_addr" == *":"* ]] && [[ "$client_server_addr" != "["* ]]; then
         client_server_addr="[${client_server_addr}]"
    fi

    _info "请输入您的“伪装域名”，必须是证书对应的域名。"
    read -p "请输入伪装域名: " camouflage_domain
    [[ -z "$camouflage_domain" ]] && _error "伪装域名不能为空" && return 1

    read -p "请输入监听端口: " port
    [[ -z "$port" ]] && _error "端口不能为空" && return 1

    read -p "请输入密码 (默认随机生成): " password
    if [ -z "$password" ]; then
        password=$(${SINGBOX_BIN} generate rand --base64 16)
        _info "已为您生成随机密码: ${password}"
    fi

    read -p "请输入 WebSocket 路径 (回车则随机生成): " ws_path
    if [ -z "$ws_path" ]; then
        ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
        _info "已为您生成随机 WebSocket 路径: ${ws_path}"
    else
        [[ ! "$ws_path" == /* ]] && ws_path="/${ws_path}"
    fi

    local cert_path=""
    local key_path=""
    local cert_type="custom"
    
    _info "请选择证书获取方式:"
    _info "  1) 自动申请 Let's Encrypt 证书 (推荐)"
    _info "  2) 使用自定义证书路径"
    read -p "请选择 (1/2, 默认: 1): " cert_choice
    cert_choice=${cert_choice:-1}
    
    if [ "$cert_choice" == "1" ]; then
        if _auto_cert "${camouflage_domain}"; then
            cert_path="${ACME_SH_HOME}/${camouflage_domain}_ecc/${camouflage_domain}.cer"
            key_path="${ACME_SH_HOME}/${camouflage_domain}_ecc/${camouflage_domain}.key"
            cert_type="auto"
        else
            _error "证书申请失败, 请检查配置后重试"
            return 1
        fi
    else
        read -p "请输入证书文件 .pem/.crt 的完整路径: " cert_path
        [[ ! -f "$cert_path" ]] && _error "证书文件不存在: ${cert_path}" && return 1

        read -p "请输入私钥文件 .key 的完整路径: " key_path
        [[ ! -f "$key_path" ]] && _error "私钥文件不存在: ${key_path}" && return 1
    fi
    
    read -p "$(echo -e ${YELLOW}"是否使用 Cloudflare 源证书或自签名证书? (y/N): "${NC})" use_origin_cert
    local skip_verify=false
    if [[ "$use_origin_cert" == "y" || "$use_origin_cert" == "Y" ]]; then
        skip_verify=true
        _warning "已启用 'skip-cert-verify: true'。"
    fi

    local tag="Trojan-ws-${port}"
    local name="Trojan-ws-${port}"
    
    local inbound_json=$(jq -n \
        --arg t "$tag" \
        --arg p "$port" \
        --arg pw "$password" \
        --arg cp "$cert_path" \
        --arg kp "$key_path" \
        --arg wsp "$ws_path" \
        --arg cd "$camouflage_domain" \
        '{
            "type": "trojan",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"password": $pw}],
            "tls": {
                "enabled": true,
                "certificate_path": $cp,
                "key_path": $kp,
                "server_name": $cd
            },
            "transport": {
                "type": "ws",
                "path": $wsp,
                "headers": {
                    "Host": $cd
                }
            }
        }')
    _atomic_modify_json "$CONFIG_FILE" ".inbounds += [$inbound_json]" || return 1
    
    local metadata_json=$(jq -n \
        --arg cd "$camouflage_domain" \
        --arg ct "$cert_type" \
        '{
            "camouflage_domain": $cd,
            "cert_type": $ct
        }')
    _atomic_modify_json "$METADATA_FILE" ".\"$tag\" = $metadata_json" || return 1
    
    local sni_param="&sni=${camouflage_domain}"
    local ws_param="&type=ws&path=$(_url_encode "$ws_path")"
    local host_param="&host=${camouflage_domain}"
    local url="trojan://${password}@${client_server_addr}:${port}?security=tls${sni_param}${ws_param}${host_param}#$(_url_encode "$name")"
    
    _success "Trojan (WebSocket+TLS) 节点添加成功!"
    _success "客户端连接地址: ${client_server_addr}"
    _success "伪装域名: ${camouflage_domain}"
    _success "密码: ${password}"
    _success "证书类型: $([ "$cert_type" == "auto" ] && echo "Let's Encrypt (自动续期)" || echo "自定义证书")"
    _success "分享链接: ${url}"
}

# 逐项选择修改节点配置（每修改一项立即重启并显示信息）
_modify_node() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then 
        _warning "当前没有任何节点。"
        return
    fi
    
    _info "--- 选择要修改的节点 ---"
    jq -r '.inbounds[] | "\(.tag) (\(.type)) @ \(.listen_port)"' "$CONFIG_FILE" | cat -n
    read -p "请输入要修改的节点编号 (输入 0 返回): " num
    
    [[ ! "$num" =~ ^[0-9]+$ ]] || [ "$num" -eq 0 ] && return
    local count=$(jq '.inbounds | length' "$CONFIG_FILE")
    if [ "$num" -gt "$count" ]; then 
        _error "编号超出范围。"
        return
    fi

    local index=$((num - 1))
    local node_to_modify=$(jq ".inbounds[$index]" "$CONFIG_FILE")
    local tag_to_modify=$(echo "$node_to_modify" | jq -r ".tag")
    
    local current_port=$(echo "$node_to_modify" | jq -r '.listen_port')
    local current_password=$(echo "$node_to_modify" | jq -r '.users[0].password')
    local current_ws_path=$(echo "$node_to_modify" | jq -r '.transport.path')
    local current_cert_path=$(echo "$node_to_modify" | jq -r '.tls.certificate_path')
    local current_key_path=$(echo "$node_to_modify" | jq -r '.tls.key_path')
    local current_camouflage_domain=$(echo "$node_to_modify" | jq -r '.tls.server_name')
    local current_cert_type=$(jq -r ".\"$tag_to_modify\".cert_type // \"custom\"" "$METADATA_FILE")
    
    clear
    _info "--- 修改 Trojan 节点: ${tag_to_modify} ---"
    _info "当前配置:"
    _info "1) 端口: ${current_port}"
    _info "2) 密码: ${current_password}"
    _info "3) WebSocket 路径: ${current_ws_path}"
    _info "4) 伪装域名: ${current_camouflage_domain}"
    _info "5) 证书类型: $([ "$current_cert_type" == "auto" ] && echo "Let's Encrypt (自动续期)" || echo "自定义证书")"
    _info "6) 证书路径: ${current_cert_path}"
    _info "7) 私钥路径: ${current_key_path}"
    echo
    
    _info "请选择要修改的项:"
    echo "  1) 修改端口"
    echo "  2) 修改密码"
    echo "  3) 修改 WebSocket 路径"
    echo "  4) 修改伪装域名（将自动重新申请证书）"
    echo "  5) 修改证书路径（仅自定义证书）"
    echo "  0) 取消并返回"
    read -p "请输入选项 [0-5]: " modify_choice

    local new_port="$current_port"
    local new_password="$current_password"
    local new_ws_path="$current_ws_path"
    local new_camouflage_domain="$current_camouflage_domain"
    local new_cert_path="$current_cert_path"
    local new_key_path="$current_key_path"
    local new_cert_type="$current_cert_type"
    local new_tag="$tag_to_modify"
    local changed=false

    case $modify_choice in
        1)
            read -p "请输入新端口 (当前: ${current_port}): " new_port
            [[ -z "$new_port" ]] && new_port=$current_port
            _success "端口已修改为: ${new_port}"
            changed=true
            ;;
        2)
            read -p "请输入新密码 (当前: ${current_password}): " new_password
            if [ -z "$new_password" ]; then
                new_password=$(${SINGBOX_BIN} generate rand --base64 16)
                _info "已为您生成随机密码: ${new_password}"
            fi
            _success "密码已修改"
            changed=true
            ;;
        3)
            read -p "请输入新 WebSocket 路径 (当前: ${current_ws_path}): " new_ws_path
            if [ -z "$new_ws_path" ]; then
                new_ws_path="/"$(${SINGBOX_BIN} generate rand --hex 8)
                _info "已为您生成随机 WebSocket 路径: ${new_ws_path}"
            else
                [[ ! "$new_ws_path" == /* ]] && new_ws_path="/${new_ws_path}"
            fi
            _success "WebSocket 路径已修改为: ${new_ws_path}"
            changed=true
            ;;
        4)
            read -p "请输入新伪装域名 (当前: ${current_camouflage_domain}): " new_camouflage_domain
            [[ -z "$new_camouflage_domain" ]] && new_camouflage_domain=$current_camouflage_domain
            
            _info "伪装域名已修改为: ${new_camouflage_domain}"
            _info "正在自动申请新的 Let's Encrypt 证书..."
            
            if _auto_cert "${new_camouflage_domain}"; then
                # 修复：删除错误的变量引用，使用正确的 new_camouflage_domain
                new_cert_path="${ACME_SH_HOME}/${new_camouflage_domain}_ecc/${new_camouflage_domain}.cer"
                new_key_path="${ACME_SH_HOME}/${new_camouflage_domain}_ecc/${new_camouflage_domain}.key"
                new_camouflage_domain=$new_camouflage_domain
                new_cert_type="auto"
                _success "证书申请成功并已自动应用到节点配置"
                changed=true
            else
                _error "证书申请失败，保持原有证书配置"
                return 1
            fi
            ;;
        5)
            if [ "$current_cert_type" == "auto" ]; then
                _warning "当前使用的是 Let's Encrypt 自动证书，无需手动修改路径"
                return
            fi
            
            read -p "请输入新证书文件路径 (当前: ${current_cert_path}): " new_cert_path
            new_cert_path=${new_cert_path:-$current_cert_path}
            [[ ! -f "$new_cert_path" ]] && _error "证书文件不存在: ${new_cert_path}" && return
            
            read -p "请输入新私钥文件路径 (当前: ${current_key_path}): " new_key_path
            new_key_path=${new_key_path:-$current_key_path}
            [[ ! -f "$new_key_path" ]] && _error "私钥文件不存在: ${new_key_path}" && return
            
            _success "证书路径已更新"
            changed=true
            ;;
        0)
            _info "取消修改并返回主菜单。"
            return
            ;;
        *)
            _error "无效选项，请重新选择。"
            return
            ;;
    esac
    
    # 如果没有任何修改，直接返回
    [[ "$changed" != "true" ]] && return
    
    # 更新 tag（如果端口改变了）
    new_tag="Trojan-ws-${new_port}"
    
    # 构建新的入站配置
    local new_inbound=$(jq -n \
        --arg t "$new_tag" \
        --arg p "$new_port" \
        --arg pw "$new_password" \
        --arg cp "$new_cert_path" \
        --arg kp "$new_key_path" \
        --arg wsp "$new_ws_path" \
        --arg cd "$new_camouflage_domain" \
        '{
            "type": "trojan",
            "tag": $t,
            "listen": "::",
            "listen_port": ($p|tonumber),
            "users": [{"password": $pw}],
            "tls": {
                "enabled": true,
                "certificate_path": $cp,
                "key_path": $kp,
                "server_name": $cd
            },
            "transport": {
                "type": "ws",
                "path": $wsp,
                "headers": {
                    "Host": $cd
                }
            }
        }')
    
    _atomic_modify_json "$CONFIG_FILE" ".inbounds[$index] = $new_inbound" || return
    
    local metadata_json=$(jq -n \
        --arg cd "$new_camouflage_domain" \
        --arg ct "$new_cert_type" \
        '{
            "camouflage_domain": $cd,
            "cert_type": $ct
        }')
    _atomic_modify_json "$METADATA_FILE" ".\"$new_tag\" = $metadata_json" || return
    
    # 重启 sing-box 以应用更改
    _manage_service "restart"
    
    # 显示修改后的节点信息
    _success "节点配置修改成功并已重启服务！"
    _info "--- 修改后的节点信息 ---"
    _info "节点名称: ${new_tag}"
    _info "端口: ${new_port}"
    _info "密码: ${new_password}"
    _info "WebSocket 路径: ${new_ws_path}"
    _info "伪装域名: ${new_camouflage_domain}"
    _info "证书类型: $([ "$new_cert_type" == "auto" ] && echo "Let's Encrypt (自动续期)" || echo "自定义证书")"
    
    local sni_param="&sni=${new_camouflage_domain}"
    local ws_param="&type=ws&path=$(_url_encode "$new_ws_path")"
    local host_param="&host=${new_camouflage_domain}"
    local url="trojan://${new_password}@${server_ip}:${new_port}?security=tls${sni_param}${ws_param}${host_param}#$(_url_encode "$new_tag")"
    
    _success "分享链接: ${url}"
    
    read -n 1 -s -r -p "按任意键返回主菜单..."
}

_view_nodes() {
    if ! jq -e '.inbounds | length > 0' "$CONFIG_FILE" >/dev/null 2>&1; then _warning "当前没有任何节点。"; return; fi
    
    _info "--- 当前节点信息 (共 $(jq '.inbounds | length' "$CONFIG_FILE") 个) ---"
    jq -c '.inbounds[]' "$CONFIG_FILE" | while read -r node; do
        local tag=$(echo "$node" | jq -r '.tag') type=$(echo "$node" | jq -r '.type') port=$(echo "$node" | jq -r '.listen_port')
        
        echo "-------------------------------------"
        _info " 节点: ${tag}"
        
        local url=""
        case "$type" in
            "trojan")
                local password=$(echo "$node" | jq -r '.users[0].password')
                local ws_path=$(echo "$node" | jq -r '.transport.path')
                local sni=$(echo "$node" | jq -r '.tls.server_name // empty')
                [ -z "$sni" ] && sni=$(echo "$node" | jq -r '.transport.headers.Host // empty')
                [ -z "$sni" ] && sni=$server_ip
                
                local sni_param="&sni=${sni}"
                local ws_param="&type=ws&path=$(_url_encode "$ws_path")"
                local host_param="&host=${sni}"
                
                url="trojan://${password}@${server_ip}:${port}?security=tls${sni_param}${ws_param}${host_param}#$(_url_encode "$tag")"
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

    read -p "$(echo -e ${YELLOW}"确定要删除节点 ${tag_to_del} 吗? (y/N): "${NC})" confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        _info "删除已取消。"
        return
    fi
    
    _atomic_modify_json "$CONFIG_FILE" "del(.inbounds[${index}])" || return
    _atomic_modify_json "$METADATA_FILE" "del(.\"$tag_to_del\")" || return
    
    _success "节点 ${tag_to_del} 已删除！"
    _manage_service "restart"
}

# 更新 sing-box 程序
_update_sing_box() {
    _info "正在检查 sing-box 更新..."
    
    local current_version=$(${SINGBOX_BIN} version | head -n1 | sed 's/sing-box version //')
    _info "当前版本: ${current_version}"
    
    local arch=$(uname -m)
    local arch_tag
    case $arch in
        x86_64|amd64) arch_tag='amd64' ;;
        aarch64|arm64) arch_tag='arm64' ;;
        armv7l) arch_tag='armv7' ;;
        *) _error "不支持的架构：$arch"; return 1 ;;
    esac
    
    local api_url="https://api.github.com/repos/SagerNet/sing-box/releases"
    local release_info=$(curl -s "$api_url" | jq -r '.[0]')
    local latest_version=$(echo "$release_info" | jq -r '.tag_name' | sed 's/^v//')
    local is_prerelease=$(echo "$release_info" | jq -r '.prerelease')
    
    if [ "$is_prerelease" == "true" ]; then
        _info "最新版本: ${latest_version} (预发行版)"
    else
        _info "最新版本: ${latest_version}"
    fi
    
    if [ "$current_version" = "$latest_version" ]; then
        _success "当前已是最新版本,无需更新。"
        return 0
    fi

    if [ "$(printf '%s\n' "$current_version" "$latest_version" | sort -V | head -n1)" = "$current_version" ]; then
        _success "发现新版本: ${latest_version}"
    else
        _warning "检测到版本号异常 (当前: ${current_version}, 最新: ${latest_version}),跳过更新。"
        return 0
    fi
    
    _info "正在停止 sing-box 服务..."
    _manage_service "stop"
    
    _info "正在备份当前配置文件..."
    cp "$CONFIG_FILE" "${CONFIG_FILE}.backup"
    
    _info "正在下载新版本..."
    local download_url=$(echo "$release_info" | jq -r ".assets[] | select(.name | contains(\"linux-${arch_tag}.tar.gz\")) | .browser_download_url")
    
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
        _info "新版本: $(${SINGBOX_BIN} version | head -n1)"
        
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
        _manage_service "start"
    fi
}

# 检查开机自启状态
_check_autostart() {
    _info "--- 检查开机自启状态 ---"
    case "$INIT_SYSTEM" in
        systemd)
            if systemctl is-enabled sing-box &>/dev/null; then
                _success "sing-box 已设置为开机自启"
            else
                _warning "sing-box 未设置为开机自启"
                read -p "是否启用开机自启? (y/N): " enable_auto
                if [[ "$enable_auto" == "y" || "$enable_auto" == "Y" ]]; then
                    systemctl enable sing-box
                    _success "已启用开机自启"
                fi
            fi
            
            if systemctl is-enabled acme-renew.timer &>/dev/null 2>&1; then
                _success "证书续期服务已设置为开机自启"
            fi
            ;;
        openrc)
            if rc-update show | grep -q "sing-box.*default"; then
                _success "sing-box 已设置为开机自启"
            else
                _warning "sing-box 未设置为开机自启"
                read -p "是否启用开机自启? (y/N): " enable_auto
                if [[ "$enable_auto" == "y" || "$enable_auto" == "Y" ]]; then
                    rc-update add sing-box default
                    _success "已启用开机自启"
                fi
            fi
            ;;
        direct)
            _warning "直接管理模式下不支持开机自启"
            ;;
    esac
}

_main_menu() {
    while true; do
        clear
        echo "===================================================="
        _info "      sing-box 一键 Trojan 脚本 v${SCRIPT_VERSION}"
        echo "===================================================="
        _info "【节点管理】"
        echo "  1) 添加 Trojan 节点"
        echo "  2) 查看节点分享链接"
        echo "  3) 删除节点"
        echo "  4) 修改 Trojan 节点配置"
        echo "----------------------------------------------------"
        _info "【更新与维护】"
        echo "  5) 更新 sing-box 程序"
        echo "  6) 检查开机自启状态"
        echo "----------------------------------------------------"
        echo "  7) 卸载 sing-box 及脚本"
        echo "  0) 退出脚本"
        echo "===================================================="
        read -p "请输入选项 [0-7]: " choice

        case $choice in
            1) _add_trojan_ws_tls; [ $? -eq 0 ] && _manage_service "restart" ;;
            2) _view_nodes ;;
            3) _delete_node ;;
            4) _modify_node ;;
            5) _update_sing_box ;;
            6) _check_autostart ;;
            7) _uninstall ;;
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
