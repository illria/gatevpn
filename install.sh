#!/bin/sh
set -e
export DEBIAN_FRONTEND=noninteractive

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'

say() { printf '%b\n' "$*"; }
ask() {
    printf '%b' "$1"
    if [ -r /dev/tty ]; then
        IFS= read -r REPLY_VALUE </dev/tty || REPLY_VALUE=""
    else
        REPLY_VALUE=""
        printf '\n'
    fi
}

if [ "$(id -u)" != "0" ]; then
    say "${RED}错误: 必须以 root 权限运行此脚本。请使用 root/sudo 运行。${PLAIN}"
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_NAME="${PRETTY_NAME:-$OS_ID}"
    OS_LIKE="${ID_LIKE:-}"
else
    OS_ID="unknown"
    OS_NAME="unknown Linux"
    OS_LIKE=""
fi

ARCH_NAME="$(uname -m 2>/dev/null || echo unknown)"
say "${BLUE}==========================================================${PLAIN}"
say "${BLUE}        欢迎使用 Eianun免费聚合落地IP 一键源码部署与管理脚本${PLAIN}"
say "${BLUE}==========================================================${PLAIN}"
say "  -> 当前系统: ${GREEN}${OS_NAME}${PLAIN} (${ARCH_NAME})"

detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then echo apt
    elif command -v dnf >/dev/null 2>&1; then echo dnf
    elif command -v yum >/dev/null 2>&1; then echo yum
    elif command -v pacman >/dev/null 2>&1; then echo pacman
    elif command -v zypper >/dev/null 2>&1; then echo zypper
    elif command -v apk >/dev/null 2>&1; then echo apk
    elif command -v emerge >/dev/null 2>&1; then echo emerge
    elif command -v xbps-install >/dev/null 2>&1; then echo xbps
    else echo manual
    fi
}

detect_service_manager() {
    if command -v systemctl >/dev/null 2>&1; then echo systemd
    elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1; then echo openrc
    elif command -v sv >/dev/null 2>&1; then echo runit
    else echo manual
    fi
}

is_rhel_like() {
    case " $OS_ID $OS_LIKE " in
        *rhel*|*centos*|*fedora*|*rocky*|*almalinux*|*ol*) return 0 ;;
        *) return 1 ;;
    esac
}

install_base_dependencies() {
    PKG_MANAGER="$(detect_package_manager)"
    say "\n${YELLOW}[1/4] 正在安装系统基础依赖...${PLAIN}"
    say "  -> 检测到包管理器: ${GREEN}${PKG_MANAGER}${PLAIN}"
    case "$PKG_MANAGER" in
        apt)
            say "  -> 正在更新 APT 软件源..."
            apt-get update -q || true
            say "  -> 正在安装依赖: openvpn curl git ca-certificates iptables iproute2 psmisc procps python3 iputils-ping"
            apt-get install -y openvpn curl git ca-certificates iptables iproute2 psmisc procps python3 iputils-ping
            ;;
        dnf)
            if is_rhel_like; then
                say "  -> RHEL/Fedora 系发行版尝试启用 EPEL，便于安装 OpenVPN..."
                dnf -y install epel-release || true
            fi
            say "  -> 正在安装依赖: openvpn curl git ca-certificates iptables iproute procps-ng psmisc python3 iputils"
            dnf -y install openvpn curl git ca-certificates iptables iproute procps-ng psmisc python3 iputils
            ;;
        yum)
            if is_rhel_like; then
                say "  -> RHEL/CentOS 系发行版尝试启用 EPEL，便于安装 OpenVPN..."
                yum -y install epel-release || true
            fi
            say "  -> 正在安装依赖: openvpn curl git ca-certificates iptables iproute procps-ng psmisc python3 iputils"
            yum -y install openvpn curl git ca-certificates iptables iproute procps-ng psmisc python3 iputils
            ;;
        pacman)
            say "  -> 正在同步并安装依赖: openvpn curl git ca-certificates iptables iproute2 procps-ng psmisc python iputils"
            pacman -Sy --noconfirm --needed openvpn curl git ca-certificates iptables iproute2 procps-ng psmisc python iputils
            ;;
        zypper)
            say "  -> 正在刷新 Zypper 软件源..."
            zypper --non-interactive refresh || true
            say "  -> 正在安装依赖: openvpn curl git ca-certificates iptables iproute2 procps psmisc python3 iputils"
            zypper --non-interactive install -y openvpn curl git ca-certificates iptables iproute2 procps psmisc python3 iputils
            ;;
        apk)
            say "  -> Alpine Linux 检测通过，正在刷新 APK 索引..."
            apk update || true
            say "  -> 正在安装依赖: openvpn curl git ca-certificates iptables iproute2 psmisc procps python3 iputils openrc"
            apk add --no-cache openvpn curl git ca-certificates iptables iproute2 psmisc procps python3 iputils openrc
            update-ca-certificates >/dev/null 2>&1 || true
            ;;
        emerge)
            say "  -> Gentoo/Portage 检测通过，正在安装依赖..."
            emerge --ask=n net-vpn/openvpn net-misc/curl dev-vcs/git app-crypt/ca-certificates net-firewall/iptables sys-apps/iproute2 sys-process/psmisc sys-process/procps net-misc/iputils dev-lang/python || true
            ;;
        xbps)
            say "  -> Void Linux/XBPS 检测通过，正在安装依赖..."
            xbps-install -Sy openvpn curl git ca-certificates iptables iproute2 psmisc procps-ng python3 iputils runit || true
            ;;
        manual)
            say "${YELLOW}警告: 未检测到 apt/dnf/yum/pacman/zypper/apk/emerge/xbps，跳过自动安装，将直接进行工具检测。${PLAIN}"
            ;;
    esac
}

check_required_tools() {
    PYTHON_BIN="$(command -v python3 || true)"
    if [ -z "$PYTHON_BIN" ]; then PYTHON_BIN="$(command -v python || true)"; fi
    if [ -z "$PYTHON_BIN" ]; then
        say "${RED}错误: Python 未安装或不在 PATH 中。${PLAIN}"
        exit 1
    fi

    SERVICE_MANAGER="$(detect_service_manager)"
    if [ "$SERVICE_MANAGER" = "manual" ]; then
        say "${RED}错误: 未检测到 systemd / OpenRC / runit 服务管理器。${PLAIN}"
        say "${YELLOW}项目可以手动运行，但一键安装需要至少一种服务管理器来注册后台服务。${PLAIN}"
        exit 1
    fi

    missing=""
    for cmd in openvpn curl git ip ping iptables pkill; do
        if ! command -v "$cmd" >/dev/null 2>&1; then missing="$missing $cmd"; fi
    done
    case "$SERVICE_MANAGER" in
        systemd) command -v systemctl >/dev/null 2>&1 || missing="$missing systemctl" ;;
        openrc) command -v rc-service >/dev/null 2>&1 || missing="$missing rc-service"; command -v rc-update >/dev/null 2>&1 || missing="$missing rc-update" ;;
        runit) command -v sv >/dev/null 2>&1 || missing="$missing sv" ;;
    esac
    if [ -n "$missing" ]; then
        say "${RED}错误: 依赖工具仍缺失:${missing}${PLAIN}"
        say "${YELLOW}请检查发行版软件源是否可用；RHEL/CentOS/Alma/Rocky 若缺少 openvpn，请确认 EPEL 已启用。Alpine 请确认 apk 源可用。${PLAIN}"
        exit 1
    fi
    say "  -> 依赖检测通过: openvpn / curl / git / ip / ping / iptables / pkill / Python / ${SERVICE_MANAGER}"
    say "  -> Python: ${GREEN}${PYTHON_BIN}${PLAIN}"
}

DEFAULT_USER="illria"
DEFAULT_REPO="gatevpn"
GITHUB_USER="${1:-$DEFAULT_USER}"
GITHUB_REPO="${2:-$DEFAULT_REPO}"
GITHUB_URL="https://github.com/${GITHUB_USER}/${GITHUB_REPO}.git"
INSTALL_DIR="/opt/eianun-vpngate"
SERVICE_NAME="eianun-vpngate"

install_base_dependencies
check_required_tools

say "\n${YELLOW}[2/4] 正在从 GitHub 部署源代码到 ${INSTALL_DIR}...${PLAIN}"
if [ -f "${INSTALL_DIR}/.local_dev" ]; then
    say "${GREEN}检测到本地开发模式 (.local_dev)，跳过 git pull/reset 保持本地修改。${PLAIN}"
else
    if [ -d "${INSTALL_DIR}" ]; then
        say "  -> 目录 ${INSTALL_DIR} 已存在，正在更新并强制覆盖本地源码..."
        cd "${INSTALL_DIR}"
        if git remote get-url origin >/dev/null 2>&1; then
            git remote set-url origin "${GITHUB_URL}" || true
        else
            git remote add origin "${GITHUB_URL}" || true
        fi
        git fetch --all || true
        BRANCH="main"
        if git rev-parse --verify origin/main >/dev/null 2>&1; then BRANCH="main"; elif git rev-parse --verify origin/master >/dev/null 2>&1; then BRANCH="master"; fi
        say "  -> 正在强制重置本地源码至 origin/${BRANCH} ..."
        if git reset --hard "origin/${BRANCH}"; then
            say "${GREEN}  -> 源码更新成功！${PLAIN}"
        else
            if git pull; then say "${GREEN}  -> 源码更新成功！${PLAIN}"; else say "${YELLOW}  -> 警告: git pull/reset 失败，将保留当前本地源码并继续安装。${PLAIN}"; fi
        fi
    else
        say "  -> 正在克隆 GitHub 仓库 ${GITHUB_URL} ..."
        if git clone "${GITHUB_URL}" "${INSTALL_DIR}"; then
            say "${GREEN}  -> 克隆成功！${PLAIN}"
        else
            say "${RED}  -> 错误: 无法克隆仓库 ${GITHUB_URL}，请检查网络！${PLAIN}"
            exit 1
        fi
    fi
fi

configure_service() {
    SERVICE_MANAGER="$(detect_service_manager)"
    say "\n${YELLOW}[3/4] 正在配置系统服务 (${SERVICE_MANAGER})...${PLAIN}"
    case "$SERVICE_MANAGER" in
        systemd)
            SERVICE_FILE="/etc/systemd/system/eianun-vpngate.service"
            say "  -> 正在创建 systemd 服务: ${SERVICE_FILE}"
            cat > "$SERVICE_FILE" <<EOF_SERVICE
[Unit]
Description=Eianun免费聚合落地IP OpenVPN Manager with HTTP/SOCKS5 Proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${PYTHON_BIN} vpngate_manager.py
Restart=always
RestartSec=5
EnvironmentFile=-/etc/default/eianun-vpngate

[Install]
WantedBy=multi-user.target
EOF_SERVICE
            systemctl daemon-reload
            systemctl enable eianun-vpngate.service
            ;;
        openrc)
            SERVICE_FILE="/etc/init.d/eianun-vpngate"
            say "  -> 正在创建 OpenRC 服务: ${SERVICE_FILE}"
            cat > "$SERVICE_FILE" <<EOF_SERVICE
#!/sbin/openrc-run
name="Eianun免费聚合落地IP"
description="Eianun免费聚合落地IP OpenVPN Manager with HTTP/SOCKS5 Proxy"
directory="${INSTALL_DIR}"
command="${PYTHON_BIN}"
command_args="vpngate_manager.py"
command_background="yes"
pidfile="/run/eianun-vpngate.pid"
output_log="${INSTALL_DIR}/vpngate_data/vpngate.log"
error_log="${INSTALL_DIR}/vpngate_data/vpngate.log"

depend() {
    need net
}

start_pre() {
    checkpath --directory --mode 0755 "${INSTALL_DIR}/vpngate_data"
}
EOF_SERVICE
            chmod +x "$SERVICE_FILE"
            rc-update add eianun-vpngate default
            ;;
        runit)
            SERVICE_DIR="/etc/sv/eianun-vpngate"
            say "  -> 正在创建 runit 服务: ${SERVICE_DIR}"
            mkdir -p "$SERVICE_DIR" "${INSTALL_DIR}/vpngate_data"
            cat > "$SERVICE_DIR/run" <<EOF_SERVICE
#!/bin/sh
cd "${INSTALL_DIR}" || exit 1
exec ${PYTHON_BIN} vpngate_manager.py >> "${INSTALL_DIR}/vpngate_data/vpngate.log" 2>&1
EOF_SERVICE
            chmod +x "$SERVICE_DIR/run"
            if [ -d /var/service ]; then ln -sfn "$SERVICE_DIR" /var/service/eianun-vpngate; elif [ -d /etc/service ]; then ln -sfn "$SERVICE_DIR" /etc/service/eianun-vpngate; fi
            ;;
        *)
            say "${RED}错误: 未检测到可用服务管理器，无法注册后台服务。${PLAIN}"
            exit 1
            ;;
    esac
}

configure_service

say "\n${YELLOW}[4/4] 正在创建全局命令快捷接口 'en'...${PLAIN}"
say "  -> 正在写入管理脚本 /usr/bin/en ..."
cat > /usr/bin/en <<'EOF'
#!/usr/bin/env python3
import sys
import os
import socket
import subprocess
import time
import tty
import termios

INSTALL_DIR = "/opt/eianun-vpngate"
LOG_FILE = "/opt/eianun-vpngate/vpngate_data/vpngate.log"

SERVICE_NAME = "eianun-vpngate"
SYSTEMD_SERVICE = SERVICE_NAME + ".service"

def command_exists(name):
    from shutil import which
    return which(name) is not None

def detect_service_manager():
    if command_exists("systemctl"):
        return "systemd"
    if command_exists("rc-service"):
        return "openrc"
    if command_exists("sv"):
        return "runit"
    return "manual"

def run_service_action(action):
    mgr = detect_service_manager()
    try:
        if mgr == "systemd":
            return subprocess.run(["systemctl", action, SYSTEMD_SERVICE])
        if mgr == "openrc":
            return subprocess.run(["rc-service", SERVICE_NAME, action])
        if mgr == "runit":
            runit_action = {"start": "up", "stop": "down", "restart": "restart", "status": "status"}.get(action, action)
            return subprocess.run(["sv", runit_action, SERVICE_NAME])
        print("未检测到 systemd / OpenRC / runit，请手动管理服务进程。")
        return None
    except FileNotFoundError:
        print("服务管理命令不存在，请检查系统服务管理器。")
        return None


def generate_random_password():
    import random
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        if any(c.islower() for c in pwd) and any(c.isupper() for c in pwd) and any(c.isdigit() for c in pwd):
            return pwd

def generate_random_suffix():
    import random
    import string
    return "".join(random.choices(string.ascii_letters + string.digits, k=12))

def load_ui_cfg():
    import json
    path = "/opt/eianun-vpngate/vpngate_data/ui_auth.json"
    cfg = {"host": "0.0.0.0", "port": 8787, "secret_path": "EJsW2EeBo9lY", "password": "", "target_countries": "", "target_ip_types": "residential", "node_sources": "vpngate,vpnbook,ipspeed"}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in data.items():
                    cfg[k] = v
        except Exception:
            pass
    return cfg

def save_ui_cfg(cfg):
    import json
    path = "/opt/eianun-vpngate/vpngate_data/ui_auth.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

def load_state():
    import json
    path = "/opt/eianun-vpngate/vpngate_data/state.json"
    state = {"active_openvpn_node_id": "", "last_check_message": "", "is_connecting": False}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for k, v in data.items():
                    state[k] = v
        except Exception:
            pass
    return state

def get_active_node_info():
    import json
    path = "/opt/eianun-vpngate/vpngate_data/nodes.json"
    state = load_state()
    active_id = state.get("active_openvpn_node_id")
    if not active_id:
        return None, None
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                nodes = json.load(f)
                for n in nodes:
                    if n.get("id") == active_id:
                        ip = n.get("ip") or n.get("remote_host")
                        loc = n.get("location") or n.get("country") or "未知"
                        return ip, loc
        except Exception:
            pass
    return None, None

def ping_ip(ip):
    if not ip:
        return None
    try:
        # Run standard linux ping command with 1 packet and 2 seconds timeout
        res = subprocess.run(["ping", "-c", "1", "-W", "2", ip], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            out = res.stdout
            lines = out.splitlines()
            for line in lines:
                if "rtt" in line or "min/avg" in line:
                    parts = line.split("=")[1].strip().split("/")
                    if len(parts) >= 2:
                        avg_rtt = float(parts[1])
                        return f"{int(avg_rtt)} ms"
            return "已响应"
        else:
            return "检测超时"
    except Exception:
        return "无法连接"

def get_public_ip():
    path = "/opt/eianun-vpngate/vpngate_data/public_ip.txt"
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                ip = f.read().strip()
                if ip:
                    return ip
        except Exception:
            pass
    import urllib.request
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=1.5) as r:
            ip = r.read().decode().strip()
            if ip:
                try:
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(ip)
                except Exception:
                    pass
                return ip
    except Exception:
        pass
    return "您的服务器公网IP"

def check_port_listening(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except Exception:
        return False

def get_service_pid(service_name="eianun-vpngate.service"):
    try:
        for pid_dir in os.listdir('/proc'):
            if pid_dir.isdigit():
                try:
                    with open(os.path.join('/proc', pid_dir, 'cmdline'), 'r') as f:
                        cmd = f.read()
                        if 'vpngate_manager.py' in cmd:
                            return pid_dir
                except Exception:
                    continue
    except Exception:
        pass
    return None

def check_service_active(service_name="eianun-vpngate.service"):
    return get_service_pid(service_name) is not None

def check_openvpn_process():
    try:
        for pid_dir in os.listdir('/proc'):
            if pid_dir.isdigit():
                try:
                    with open(os.path.join('/proc', pid_dir, 'cmdline'), 'r') as f:
                        cmd = f.read().split('\x00')[0]
                        if 'openvpn' in cmd:
                            return True
                except Exception:
                    continue
    except Exception:
        pass
    return False

def get_display_width(s):
    import re
    ansi_escape = re.compile(r'\x1b\[[0-9;]*[mGKH]')
    s_clean = ansi_escape.sub('', s)
    width = 0
    for char in s_clean:
        if ord(char) > 127:
            width += 2
        else:
            width += 1
    return width

def format_line(label, value, target_width=26):
    prefix = "  ● "
    w = get_display_width(label)
    padding = " " * max(0, target_width - w)
    return f"{prefix}{label}{padding}:  {value}"

def print_line(text=""):
    print(f"{text}\033[K")

def print_status():
    cfg = load_ui_cfg()
    ui_port = cfg.get("port", 8787)
    secret_path = cfg.get("secret_path", "EJsW2EeBo9lY")
    state = load_state()
    is_connecting = state.get("is_connecting", False)
    
    gateway_ok = check_port_listening(7928)
    service_ok = check_service_active("eianun-vpngate.service")
    openvpn_ok = check_openvpn_process()
    pid = get_service_pid("eianun-vpngate.service")
    
    active_ip, active_loc = get_active_node_info()
    latency = state.get("active_node_latency", "测试中...") if active_ip else "无活动连接"
    
    green = "\033[1;32m"
    red = "\033[1;31m"
    reset = "\033[0m"
    bold = "\033[1m"
    yellow = "\033[1;33m"
    
    backend_status = f"{green}[已激活] (PID: {pid}){reset}" if (service_ok and pid) else f"{red}[未启动]{reset}"
    
    if is_connecting:
        gateway_status = f"{yellow}[切换中...]{reset}"
        openvpn_status = f"{yellow}[{state.get('active_node_latency') or '连接中'}...]{reset}"
    else:
        gateway_status = f"{green}[已激活]{reset}" if gateway_ok else f"{red}[未启动]{reset}"
        openvpn_status = f"{green}[已连接]{reset}" if openvpn_ok else f"{red}[未连接]{reset}"
    
    print_line("=======================================================")
    print_line(f"               {bold}Eianun免费聚合落地IP 管理终端 v2.0{reset}                  ")
    print_line("=======================================================")
    print_line("【核心服务状态】")
    print_line(format_line("代理网关 (Port 7928)", gateway_status))
    print_line(format_line(f"管理后台 (Port {ui_port})", backend_status))
    print_line(format_line("连接核心 (OpenVPN)", openvpn_status))
    
    login_ip = "127.0.0.1" if cfg.get("host") == "127.0.0.1" else get_public_ip()
    print_line(format_line("网页登录地址", f"{yellow}http://{login_ip}:{ui_port}/{secret_path}/{reset}"))
    print_line(format_line("网页管理账号", cfg.get("username", "未配置")))
    curr_pwd = cfg.get("password", "")
    masked_pwd = curr_pwd if len(curr_pwd) <= 4 else curr_pwd[:3] + "********" + curr_pwd[-2:]
    print_line(format_line("网页管理密码", masked_pwd))
    print_line(format_line("节点拉取来源", cfg.get("node_sources", "vpngate,vpnbook,ipspeed") or "vpngate,vpnbook,ipspeed"))
    print_line(format_line("节点拉取地区", cfg.get("target_countries", "") or "全部地区"))
    print_line(format_line("自动IP优先级", cfg.get("target_ip_types", "residential") or "全部类型"))
    print_line()
    print_line("【活动节点状态】")
    if is_connecting:
        connecting_msg = state.get('last_check_message') or '正在建立加密隧道并验证路由规则...'
        print_line(format_line("节点状态", f"{yellow}{connecting_msg}{reset}"))
    elif active_ip:
        proxy_ip = state.get("proxy_ip", "-")
        proxy_latency = state.get("proxy_latency_ms", 0)
        proxy_ok = state.get("proxy_ok", False)
        
        print_line(format_line("节点 IP (入口)", active_ip))
        print_line(format_line("节点地区", active_loc))
        print_line(format_line("节点延迟 (直连测试)", latency))
        if proxy_ok and proxy_ip and proxy_ip != "-":
            print_line(format_line("出口 IP (出站)", proxy_ip))
            print_line(format_line("本地代理延迟", f"{proxy_latency} ms" if proxy_latency else "检测中..."))
        else:
            print_line(format_line("出口 IP (出站)", f"{red}[检测中/未就绪]{reset}"))
    else:
        print_line(format_line("节点状态", "无活动连接"))
    print_line()
    print_line("【使用方法】")
    print_line(f"  export http_proxy=socks5://127.0.0.1:7928")
    print_line(f"  export https_proxy=socks5://127.0.0.1:7928")
    print_line("【常用指令】en status | en update | en restart | en country | en iptype | en password")
    print_line("=======================================================")

def start_service():
    print("正在启动 Eianun免费聚合落地IP 服务...", flush=True)
    run_service_action("start")
    print("已发送启动指令。")
    time.sleep(1)

def stop_service():
    print("正在停止 Eianun免费聚合落地IP 服务...", flush=True)
    run_service_action("stop")
    print("已发送停止指令。")
    time.sleep(1)

def restart_service():
    print("正在重启 Eianun免费聚合落地IP 服务...", flush=True)
    run_service_action("restart")
    print("已发送重启指令。")
    time.sleep(1)

def show_logs():
    print("正在查看 Eianun免费聚合落地IP 日志 (按 Ctrl+C 退出)...", flush=True)
    mgr = detect_service_manager()
    try:
        if mgr == "systemd" and command_exists("journalctl"):
            subprocess.run(["journalctl", "-u", SYSTEMD_SERVICE, "-f", "-n", "80"])
            return
        if os.path.exists(LOG_FILE):
            subprocess.run(["tail", "-f", "-n", "50", LOG_FILE])
            return
        logs_dir = os.path.join(INSTALL_DIR, "vpngate_data", "logs")
        if os.path.isdir(logs_dir):
            files = sorted([os.path.join(logs_dir, f) for f in os.listdir(logs_dir) if f.endswith(".json")])
            if files:
                subprocess.run(["tail", "-f", "-n", "80", files[-1]])
                return
        run_service_action("status")
    except KeyboardInterrupt:
        pass

def update_service():
    print("正在获取远程更新并检测版本...", flush=True)
    if os.path.exists(INSTALL_DIR):
        try:
            os.chdir(INSTALL_DIR)
            if not os.path.exists(".git"):
                print("错误: 当前安装目录不是 Git 仓库，无法通过 Git 更新。")
                time.sleep(3)
                return
            
            # Fetch remote origin updates
            subprocess.run(["git", "fetch", "--all"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Detect remote branch (check origin/main, then origin/master)
            branch = "main"
            for b in ["main", "master"]:
                chk = subprocess.run(["git", "rev-parse", "--verify", f"origin/{b}"], capture_output=True, text=True)
                if chk.returncode == 0:
                    branch = b
                    break
            
            local_commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            remote_commit = subprocess.run(["git", "rev-parse", f"origin/{branch}"], capture_output=True, text=True).stdout.strip()
            
            if local_commit == remote_commit:
                print("\n【版本状态】当前已是最新版本，无需更新！")
                override = input("是否强制重新拉取代码并覆盖安装？(y/N): ").strip().lower()
                if override != 'y':
                    print("已取消更新。")
                    time.sleep(1.5)
                    return
            else:
                print(f"\n【检测到更新】本地版本: {local_commit[:8]}，远程最新版本: {remote_commit[:8]}")
                confirm = input("是否确认开始更新并重启服务？(Y/n): ").strip().lower()
                if confirm not in ('', 'y', 'yes'):
                    print("已取消更新。")
                    time.sleep(1.5)
                    return
            
            print(f"\n正在强制重置本地代码至 origin/{branch} ...", flush=True)
            subprocess.run(["git", "reset", "--hard", f"origin/{branch}"], check=True)
            
            # Clean up python cache files
            print("正在清理 Python 缓存 (pycache)...", flush=True)
            subprocess.run(["find", ".", "-type", "d", "-name", "__pycache__", "-exec", "rm", "-rf", "{}", "+"], check=False)
            
            print("代码拉取成功，正在重新运行安装脚本...", flush=True)
            subprocess.run(["sh", "install.sh"])
            print("更新已完成！")
            time.sleep(2)
        except Exception as e:
            print(f"更新失败: {e}")
            time.sleep(4)
    else:
        print(f"未找到安装目录: {INSTALL_DIR}")
        time.sleep(2)

def uninstall_service():
    confirm = input("确定要完全卸载 Eianun免费聚合落地IP 吗？(y/N): ")
    if confirm.lower() == 'y':
        print("正在完全卸载 Eianun免费聚合落地IP...", flush=True)
        mgr = detect_service_manager()
        if mgr == "systemd":
            subprocess.run(["systemctl", "stop", SYSTEMD_SERVICE])
            subprocess.run(["systemctl", "disable", SYSTEMD_SERVICE])
            for p in ["/etc/systemd/system/eianun-vpngate.service", "/lib/systemd/system/eianun-vpngate.service"]:
                try:
                    os.unlink(p)
                except Exception:
                    pass
            subprocess.run(["systemctl", "daemon-reload"])
        elif mgr == "openrc":
            subprocess.run(["rc-service", SERVICE_NAME, "stop"])
            subprocess.run(["rc-update", "del", SERVICE_NAME, "default"])
            try:
                os.unlink("/etc/init.d/eianun-vpngate")
            except Exception:
                pass
        elif mgr == "runit":
            subprocess.run(["sv", "down", SERVICE_NAME])
            for p in ["/var/service/eianun-vpngate", "/etc/service/eianun-vpngate"]:
                try:
                    os.unlink(p)
                except Exception:
                    pass
            subprocess.run(["rm", "-rf", "/etc/sv/eianun-vpngate"])
        for p in ["/usr/bin/en", "/usr/bin/eianun", "/usr/bin/ml"]:
            try:
                os.unlink(p)
            except Exception:
                pass
        subprocess.run(["rm", "-rf", INSTALL_DIR])
        print("Eianun免费聚合落地IP 已卸载！")
        sys.exit(0)
    else:
        print("已取消卸载。")
        time.sleep(1)

def ask_restart():
    ans = input("配置已保存。是否立即重启服务生效？(Y/n): ").strip().lower()
    if ans in ('', 'y', 'yes'):
        print("正在重启 Eianun免费聚合落地IP 服务...", flush=True)
        run_service_action("restart")
        print("服务已重启。")
        time.sleep(1.5)

def configure_web():
    cfg = load_ui_cfg()
    while True:
        print("\033[H\033[J", end="")
        print("=======================================================")
        print("               网页绑定与地址后缀配置                  ")
        print("=======================================================")
        print(f"  [1] 切换绑定地址 (当前: {cfg.get('host', '0.0.0.0')})")
        print(f"  [2] 随机重置安全后缀 (当前: {cfg.get('secret_path', '')})")
        print("  [3] 返回主菜单")
        print("=======================================================")
        print("请直接输入数字键 [1-3] 快速执行：", end="", flush=True)
        
        key = getch()
        if key == '1':
            print("\033[H\033[J", end="")
            print("选择网页登录绑定地址：")
            print("  1. 仅允许本地登录 (127.0.0.1 - 更安全)")
            print("  2. 允许公网IP登录 (0.0.0.0 - 方便远程)")
            sel = input("请选择 (1 或 2, 默认2): ").strip()
            if sel == '1':
                cfg['host'] = "127.0.0.1"
            else:
                cfg['host'] = "0.0.0.0"
            save_ui_cfg(cfg)
            print(f"绑定地址已更新为: {cfg['host']}")
            ask_restart()
            break
        elif key == '2':
            print("\033[H\033[J", end="")
            new_path = generate_random_suffix()
            cfg['secret_path'] = new_path
            save_ui_cfg(cfg)
            print("安全登录后缀已随机重置成功！")
            print(f"您的全新安全登录后缀为: {new_path}")
            print(f"新的访问路径为: http://{cfg['host']}:{cfg['port']}/{new_path}/")
            ask_restart()
            break
        elif key == '3' or key == 'q' or key == '\x03':
            break

def configure_port():
    cfg = load_ui_cfg()
    print("\033[H\033[J", end="")
    print("=======================================================")
    print("                      管理端口配置                     ")
    print("=======================================================")
    print(f"当前网页管理端口为: {cfg.get('port', 8787)}")
    try:
        val = input("请输入新的管理端口 (1-65535, 按回车取消): ").strip()
        if val:
            port = int(val)
            if 1 <= port <= 65535:
                cfg['port'] = port
                save_ui_cfg(cfg)
                print(f"管理端口已更新为: {port}")
                ask_restart()
            else:
                print("错误: 端口范围必须在 1 至 65535 之间。")
                time.sleep(2)
    except ValueError:
        print("错误: 输入必须是数字。")
        time.sleep(2)

def configure_credentials():
    cfg = load_ui_cfg()
    while True:
        print("\033[H\033[J", end="")
        print("=======================================================")
        print("                    管理账号密码管理                   ")
        print("=======================================================")
        curr_uname = cfg.get('username', '未配置')
        curr_pwd = cfg.get('password', '')
        masked_pwd = curr_pwd if len(curr_pwd) <= 4 else curr_pwd[:3] + "********" + curr_pwd[-2:]
        print(f"当前管理账号: {curr_uname}")
        print(f"当前管理密码: {masked_pwd}")
        print("  [1] 自定义修改账号密码")
        print("  [2] 随机重置安全密码")
        print("  [3] 返回主菜单")
        print("=======================================================")
        print("请直接输入数字键 [1-3] 快速执行：", end="", flush=True)
        
        key = getch()
        if key == '1':
            print("\033[H\033[J", end="")
            new_uname = input(f"请输入新管理账号 (回车默认 {curr_uname}): ").strip()
            if not new_uname:
                new_uname = curr_uname
            new_pwd = input("请输入新管理密码 (不能为空): ").strip()
            if not new_pwd:
                print("错误: 密码不能为空！")
                time.sleep(2)
                continue
            cfg['username'] = new_uname
            cfg['password'] = new_pwd
            save_ui_cfg(cfg)
            print("账号密码修改成功！")
            print(f"您的新管理账号: {new_uname}")
            print(f"您的新管理密码: {new_pwd}")
            input("\n按任意键返回菜单...")
        elif key == '2':
            print("\033[H\033[J", end="")
            new_pwd = generate_random_password()
            cfg['password'] = new_pwd
            save_ui_cfg(cfg)
            print("密码随机重置成功！")
            print(f"您的全新12位安全密码为: {new_pwd}")
            print("密码已保存在本地，不需要重启服务，刷新浏览器即可登录。")
            input("\n按任意键返回菜单...")
        elif key == '3' or key == 'q' or key == '\x03':
            break


def configure_source():
    cfg = load_ui_cfg()
    current = cfg.get('node_sources', 'vpngate,vpnbook,ipspeed') or 'vpngate,vpnbook,ipspeed'
    print("\033[H\033[J", end="")
    print("=======================================================")
    print("                    节点来源配置                       ")
    print("=======================================================")
    print(f"当前节点来源: {current}")
    print("  [1] VPNGate + VPNBook + IPSpeed（推荐）")
    print("  [2] VPNGate + IPSpeed")
    print("  [3] VPNGate + VPNBook")
    print("  [4] 仅 VPNGate")
    print("  [5] 仅 VPNBook")
    print("  [6] 仅 IPSpeed")
    print("  [7] 返回主菜单")
    key = getch()
    if key == '1':
        cfg['node_sources'] = 'vpngate,vpnbook,ipspeed'
    elif key == '2':
        cfg['node_sources'] = 'vpngate,ipspeed'
    elif key == '3':
        cfg['node_sources'] = 'vpngate,vpnbook'
    elif key == '4':
        cfg['node_sources'] = 'vpngate'
    elif key == '5':
        cfg['node_sources'] = 'vpnbook'
    elif key == '6':
        cfg['node_sources'] = 'ipspeed'
    else:
        return
    save_ui_cfg(cfg)
    print(f"节点来源已更新为: {cfg['node_sources']}")
    ask_restart()

def configure_country():
    cfg = load_ui_cfg()
    print("\033[H\033[J", end="")
    print("=======================================================")
    print("                    节点拉取地区配置                   ")
    print("=======================================================")
    print(f"当前拉取地区: {cfg.get('target_countries', '') or '全部地区'}")
    print("说明: 支持国家简称/英文名/中文名，多个地区用逗号分隔，例如 JP,日本,US,美国。")
    val = input("请输入新的拉取地区 (留空表示全部地区): ").strip()
    cfg['target_countries'] = val
    save_ui_cfg(cfg)
    print(f"节点拉取地区已更新为: {val or '全部地区'}")
    ask_restart()

def configure_iptype():
    cfg = load_ui_cfg()
    print("\033[H\033[J", end="")
    print("=======================================================")
    print("                    自动IP类型优先级配置               ")
    print("=======================================================")
    current = cfg.get('target_ip_types', 'residential') or 'all'
    print(f"当前自动IP优先级: {current}")
    print("  [1] 住宅优先（推荐）")
    print("  [2] 移动优先")
    print("  [3] 普通/未知优先")
    print("  [4] 不限类型")
    print("  [5] 自定义优先级，例如 residential,mobile,normal")
    sel = input("请选择 [1-5, 回车默认1]: ").strip() or '1'
    mapping = {
        '1': 'residential',
        '2': 'mobile,residential',
        '3': 'normal,residential,mobile',
        '4': 'all',
    }
    if sel == '5':
        val = input("请输入IP类型优先级 (residential,mobile,normal,hosting,proxy,all): ").strip() or 'residential'
    else:
        val = mapping.get(sel, 'residential')
    cfg['target_ip_types'] = val
    save_ui_cfg(cfg)
    print(f"自动IP类型优先级已更新为: {val}")
    print("说明: 这是优先级，不是硬过滤；代理/Tor 默认排在最后，避免自动故障转移停摆。")
    ask_restart()

def getch():
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except termios.error:
        return sys.stdin.read(1)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def getch_timeout(timeout=1.0):
    import select
    fd = sys.stdin.fileno()
    try:
        old_settings = termios.tcgetattr(fd)
    except termios.error:
        try:
            r, _, _ = select.select([sys.stdin], [], [], timeout)
            if r:
                ch = sys.stdin.read(1)
                if not ch:
                    time.sleep(timeout)
                    return None
                return ch
        except Exception:
            time.sleep(timeout)
        return None
    try:
        tty.setraw(fd)
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        if r:
            ch = sys.stdin.read(1)
            if not ch:
                return None
            return ch
        return None
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def get_status_state():
    cfg = load_ui_cfg()
    state = load_state()
    return (
        cfg.get("port", 8787),
        cfg.get("secret_path", "EJsW2EeBo9lY"),
        cfg.get("username", "未配置"),
        cfg.get("password", ""),
        cfg.get("host", "0.0.0.0"),
        state.get("is_connecting", False),
        state.get("active_openvpn_node_id", ""),
        state.get("last_check_message", ""),
        state.get("active_node_latency", ""),
        state.get("proxy_ip", "-"),
        state.get("proxy_latency_ms", 0),
        state.get("proxy_ok", False),
        check_port_listening(7928),
        check_service_active("eianun-vpngate.service"),
        check_openvpn_process(),
        get_service_pid("eianun-vpngate.service")
    )

def main():
    if os.geteuid() != 0:
        print("错误: 必须以 root 权限运行此命令。")
        sys.exit(1)
        
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "start":
            start_service()
        elif cmd == "stop":
            stop_service()
        elif cmd == "restart":
            restart_service()
        elif cmd == "status":
            print("\033[?1049h\033[?25l\033[H\033[J", end="", flush=True)
            try:
                last_state = None
                while True:
                    current_state = get_status_state()
                    if current_state != last_state:
                        print("\033[H", end="")
                        print_status()
                        print_line("\n\033[1;33m提示: 正在实时监控状态，自动更新。按任意键或 Ctrl+C 退出...\033[0m")
                        print("\033[J", end="", flush=True)
                        last_state = current_state
                    key = getch_timeout(1.5)
                    if key is not None:
                        break
            except KeyboardInterrupt:
                pass
            finally:
                print("\033[?1049l\033[?25h", end="", flush=True)
        elif cmd == "logs":
            show_logs()
        elif cmd == "update":
            update_service()
        elif cmd == "uninstall":
            uninstall_service()
        elif cmd == "web":
            configure_web()
        elif cmd == "port":
            configure_port()
        elif cmd == "password":
            configure_credentials()
        elif cmd == "source":
            configure_source()
        elif cmd == "country":
            configure_country()
        elif cmd in ("iptype", "ip-type", "type"):
            configure_iptype()
        else:
            print("未知命令。可用命令: start, stop, restart, status, logs, update, uninstall, web, port, password, source, country, iptype")
        sys.exit(0)
        
    options = {
        '1': ("启动服务 (en start)", start_service),
        '2': ("停止服务 (en stop)", stop_service),
        '3': ("重启服务 (en restart)", restart_service),
        '4': ("日志监控 (en logs)", show_logs),
        '5': ("网页配置 (en web)", configure_web),
        '6': ("端口配置 (en port)", configure_port),
        '7': ("账号密码 (en password)", configure_credentials),
        '8': ("节点来源 (en source)", configure_source),
        '9': ("地区过滤 (en country)", configure_country),
        'a': ("自动IP类型 (en iptype)", configure_iptype),
        'u': ("一键更新 (en update)", update_service),
        'x': ("完全卸载 (en uninstall)", uninstall_service),
        '0': ("退出终端", None)
    }
    
    # Enter alternate buffer and hide cursor
    print("\033[?1049h\033[?25l\033[H\033[J", end="", flush=True)
    try:
        last_state = None
        while True:
            current_state = get_status_state()
            if current_state != last_state:
                print("\033[H", end="")
                print_status()
                
                bold = "\033[1m"
                reset = "\033[0m"
                green = "\033[1;32m"
                
                print_line(f"【{bold}终端指令菜单栏{reset}】")
                for key in sorted(options.keys()):
                    if key == '0':
                        continue
                    name, _ = options[key]
                    print_line(f"  {green}[{key}]{reset} {name}")
                print_line(f"  {green}[0]{reset} {options['0'][0]}")
                print_line("=======================================================")
                print("请直接输入数字键 [0-9/a/u/x] 快速选择执行：\033[K", end="", flush=True)
                print("\033[J", end="", flush=True)
                last_state = current_state
                
            try:
                key = getch_timeout(1.0)
            except KeyboardInterrupt:
                break
                
            if key is None:
                continue
                
            if key == '\x03' or key == 'q' or key == 'Q':
                break
                
            if key == '0':
                break
                
            if key in ('\r', '\n', '\x0a', '\x0d'):
                last_state = None
                continue
                
            if key in options:
                name, func = options[key]
                if func is None:
                    break
                    
                # Temporarily restore normal terminal scrollback and show cursor
                print("\033[?1049l\033[?25h", end="", flush=True)
                print(f"正在执行: {name}...\n")
                
                try:
                    func()
                except Exception as e:
                    print(f"执行出错: {e}")
                    
                if func not in (start_service, stop_service, restart_service,
                                configure_web, configure_port, configure_credentials, configure_source, configure_country, configure_iptype, show_logs, update_service):
                    input("\n操作已完成，按回车键返回主菜单...")
                    
                # Re-enter alternate buffer and hide cursor
                print("\033[?1049h\033[?25l\033[H\033[J", end="", flush=True)
                last_state = None
    finally:
        # Exit alternate buffer and show cursor on exit
        print("\033[?1049l\033[?25h", end="", flush=True)

if __name__ == "__main__":
    main()
EOF
chmod +x /usr/bin/en
ln -sf /usr/bin/en /usr/bin/eianun
rm -f /usr/bin/ml

AUTH_FILE="${INSTALL_DIR}/vpngate_data/ui_auth.json"
mkdir -p "${INSTALL_DIR}/vpngate_data"

# 每次安装/更新都允许自定义面板参数；选择否则保留已有配置或生成默认配置。
UI_PORT="$(${PYTHON_BIN} -c "import json,sys; p='$AUTH_FILE';
try:
 d=json.load(open(p,encoding='utf-8')); print(d.get('port',8787))
except Exception: print(8787)" 2>/dev/null || echo 8787)"
SECRET_PATH="$(${PYTHON_BIN} -c "import json,sys,random,string; p='$AUTH_FILE';
try:
 d=json.load(open(p,encoding='utf-8')); v=d.get('secret_path') or ''; print(v if v else ''.join(random.choices(string.ascii_letters+string.digits,k=12)))
except Exception: print(''.join(random.choices(string.ascii_letters+string.digits,k=12)))" 2>/dev/null)"
UI_USERNAME="$(${PYTHON_BIN} -c "import json,random,string; p='$AUTH_FILE'
def gen():
 chars=string.ascii_letters+string.digits
 while True:
  u=''.join(random.choices(chars,k=12))
  if u[0].isalpha() and any(c.islower() for c in u) and any(c.isupper() for c in u) and any(c.isdigit() for c in u): return u
try:
 d=json.load(open(p,encoding='utf-8')); print(d.get('username') or gen())
except Exception: print(gen())" 2>/dev/null)"
UI_PASSWORD="$(${PYTHON_BIN} -c "import json,random,string; p='$AUTH_FILE'
def gen():
 chars=string.ascii_letters+string.digits
 while True:
  p=''.join(random.choices(chars,k=12))
  if any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p): return p
try:
 d=json.load(open(p,encoding='utf-8')); print(d.get('password') or gen())
except Exception: print(gen())" 2>/dev/null)"
TARGET_COUNTRIES_INPUT="$(${PYTHON_BIN} -c "import json; p='$AUTH_FILE'
try:
 d=json.load(open(p,encoding='utf-8')); print(d.get('target_countries',''))
except Exception: print('')" 2>/dev/null || echo '')"
TARGET_IP_TYPES_INPUT="$(${PYTHON_BIN} -c "import json; p='$AUTH_FILE'
try:
 d=json.load(open(p,encoding='utf-8')); print(d.get('target_ip_types','residential'))
except Exception: print('residential')" 2>/dev/null || echo 'residential')"
NEED_WRITE=0
[ ! -f "$AUTH_FILE" ] && NEED_WRITE=1

say "
${YELLOW}是否需要自定义配置网页面板参数？${PLAIN}"
say "  -> 当前端口: ${GREEN}${UI_PORT}${PLAIN}"
say "  -> 当前账号: ${GREEN}${UI_USERNAME}${PLAIN}"
say "  -> 当前安全后缀: ${GREEN}${SECRET_PATH}${PLAIN}"
say "  -> 当前节点来源: ${GREEN}${NODE_SOURCES_INPUT:-vpngate,vpnbook,ipspeed}${PLAIN}"
say "  -> 当前拉取地区: ${GREEN}${TARGET_COUNTRIES_INPUT:-全部地区}${PLAIN}"
say "  -> 当前自动IP类型: ${GREEN}${TARGET_IP_TYPES_INPUT:-residential}${PLAIN}"
ask "是否现在配置端口/安全后缀/登录账号密码/拉取地区/IP类型？[y/N]: "
is_custom="$REPLY_VALUE"

case "$is_custom" in
    y|Y)
        NEED_WRITE=1
        while :; do
            ask "请输入自定义管理端口 [1-65535, 默认 ${UI_PORT}]: "
            input_port="$REPLY_VALUE"
            if [ -z "$input_port" ]; then break; fi
            case "$input_port" in
                *[!0-9]*|'') say "${RED}输入错误: 端口必须是 1 到 65535 之间的数字！${PLAIN}" ;;
                *) if [ "$input_port" -ge 1 ] && [ "$input_port" -le 65535 ]; then UI_PORT="$input_port"; break; else say "${RED}输入错误: 端口必须是 1 到 65535 之间的数字！${PLAIN}"; fi ;;
            esac
        done
        while :; do
            ask "请输入网页登录自定义安全后缀 [字母与数字组合, 默认 ${SECRET_PATH}]: "
            input_suffix="$REPLY_VALUE"
            if [ -z "$input_suffix" ]; then break; fi
            case "$input_suffix" in
                *[!A-Za-z0-9]* ) say "${RED}输入错误: 后缀仅能由英文字母和数字组成！${PLAIN}" ;;
                * ) SECRET_PATH="$input_suffix"; break ;;
            esac
        done
        ask "请输入登录账号 [默认 ${UI_USERNAME}]: "
        input_user="$REPLY_VALUE"
        if [ -n "$input_user" ]; then UI_USERNAME="$input_user"; fi
        while :; do
            ask "请输入登录密码 [默认保留当前/随机密码，至少4位]: "
            input_pass="$REPLY_VALUE"
            if [ -z "$input_pass" ]; then break; fi
            if [ ${#input_pass} -ge 4 ]; then UI_PASSWORD="$input_pass"; break; else say "${RED}输入错误: 密码长度不能少于 4 位！${PLAIN}"; fi
        done
        ask "请输入节点拉取地区 [留空=全部地区，例如 JP,日本,US]: "
        TARGET_COUNTRIES_INPUT="$REPLY_VALUE"
        ask "请输入自动IP类型优先级 [默认 residential，可填 all/mobile,residential/normal,residential,mobile]: "
        iptype_input="$REPLY_VALUE"
        if [ -n "$iptype_input" ]; then TARGET_IP_TYPES_INPUT="$iptype_input"; fi
        ;;
esac

if [ "$NEED_WRITE" = "1" ]; then
    AUTH_FILE="$AUTH_FILE" UI_PORT="$UI_PORT" SECRET_PATH="$SECRET_PATH" UI_USERNAME="$UI_USERNAME" UI_PASSWORD="$UI_PASSWORD" TARGET_COUNTRIES_INPUT="$TARGET_COUNTRIES_INPUT" TARGET_IP_TYPES_INPUT="$TARGET_IP_TYPES_INPUT" ${PYTHON_BIN} - <<'PY_SAVE_AUTH'
import json
import os
cfg = {
    'host': '0.0.0.0',
    'port': int(os.environ.get('UI_PORT') or 8787),
    'secret_path': os.environ.get('SECRET_PATH') or 'EJsW2EeBo9lY',
    'username': os.environ.get('UI_USERNAME') or 'admin',
    'password': os.environ.get('UI_PASSWORD') or 'admin',
    'target_countries': os.environ.get('TARGET_COUNTRIES_INPUT') or '',
    'node_sources': os.environ.get('NODE_SOURCES_INPUT') or 'vpngate,vpnbook,ipspeed',
    'target_ip_types': os.environ.get('TARGET_IP_TYPES_INPUT') or 'residential',
}
with open(os.environ['AUTH_FILE'], 'w', encoding='utf-8') as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
PY_SAVE_AUTH
    say "${GREEN}面板配置已保存。${PLAIN}"
else
    say "${GREEN}已保留现有面板配置。${PLAIN}"
fi

restart_registered_service() {
    SERVICE_MANAGER="$(detect_service_manager)"
    case "$SERVICE_MANAGER" in
        systemd) systemctl restart eianun-vpngate.service || true ;;
        openrc) rc-service eianun-vpngate restart || rc-service eianun-vpngate start || true ;;
        runit) sv restart eianun-vpngate || sv up eianun-vpngate || true ;;
    esac
}

say "\n正在启动 Eianun免费聚合落地IP 服务并初始化网络..."
restart_registered_service

say "\n正在等待 Eianun免费聚合落地IP 首次获取节点并建立加密通道 (此过程可能需要 5-30 秒)..."
ACTIVE_ID=""
LAST_MSG=""
i=1
while [ "$i" -le 90 ]; do
    if [ -f "${INSTALL_DIR}/vpngate_data/state.json" ]; then
        ACTIVE_ID="$(${PYTHON_BIN} -c "import json; print(json.load(open('${INSTALL_DIR}/vpngate_data/state.json')).get('active_openvpn_node_id', ''))" 2>/dev/null || echo "")"
        IS_CONN="$(${PYTHON_BIN} -c "import json; print(json.load(open('${INSTALL_DIR}/vpngate_data/state.json')).get('is_connecting', False))" 2>/dev/null || echo "False")"
        CUR_MSG="$(${PYTHON_BIN} -c "import json; print(json.load(open('${INSTALL_DIR}/vpngate_data/state.json')).get('last_check_message', ''))" 2>/dev/null || echo "")"
        if [ "$IS_CONN" = "False" ] || [ "$IS_CONN" = "false" ]; then
            if [ -n "$ACTIVE_ID" ]; then
                say "  -> ${GREEN}[已就绪]${PLAIN} 首次节点连接成功，活动节点: ${GREEN}$ACTIVE_ID${PLAIN}"
                break
            else
                if [ -n "$CUR_MSG" ] && [ "$CUR_MSG" != "$LAST_MSG" ]; then say "  -> 提示: ${YELLOW}${CUR_MSG}${PLAIN}"; LAST_MSG="$CUR_MSG"; fi
                case "$CUR_MSG" in
                    *后台*|*Fetched*|*首批节点*)
                        say "  -> ${YELLOW}[后台运行]${PLAIN} 节点检测/优选会继续在后台进行，安装流程先完成。"
                        break
                        ;;
                esac
            fi
        else
            if [ -n "$CUR_MSG" ] && [ "$CUR_MSG" != "$LAST_MSG" ]; then say "  -> 状态: ${YELLOW}${CUR_MSG}${PLAIN}"; LAST_MSG="$CUR_MSG"; fi
        fi
    else
        printf '.'
    fi
    i=$((i + 1))
    sleep 1
done
if [ -z "$ACTIVE_ID" ]; then say "  -> ${YELLOW}[加载超时]${PLAIN} 首次节点获取或连接超时，将在后台继续尝试..."; fi

SECRET_PATH="EJsW2EeBo9lY"
USERNAME="未配置"
PASSWORD="未配置"
UI_PORT=8787
AUTH_FILE="${INSTALL_DIR}/vpngate_data/ui_auth.json"
if [ -f "$AUTH_FILE" ]; then
    SECRET_PATH="$(${PYTHON_BIN} -c "import json; print(json.load(open('$AUTH_FILE')).get('secret_path', 'EJsW2EeBo9lY'))" 2>/dev/null || echo "EJsW2EeBo9lY")"
    USERNAME="$(${PYTHON_BIN} -c "import json; print(json.load(open('$AUTH_FILE')).get('username', '未配置'))" 2>/dev/null || echo "未配置")"
    PASSWORD="$(${PYTHON_BIN} -c "import json; print(json.load(open('$AUTH_FILE')).get('password', '未配置'))" 2>/dev/null || echo "未配置")"
    UI_PORT="$(${PYTHON_BIN} -c "import json; print(json.load(open('$AUTH_FILE')).get('port', 8787))" 2>/dev/null || echo "8787")"
fi

say "正在获取 VPS 公网 IP..."
PUBLIC_IP="$(curl -s --max-time 3 https://api.ipify.org || curl -s --max-time 3 https://ifconfig.me || curl -s --max-time 3 icanhazip.com || echo "您的服务器公网IP")"
printf '%s' "$PUBLIC_IP" > "${INSTALL_DIR}/vpngate_data/public_ip.txt"

say "\n${GREEN}==========================================================${PLAIN}"
say "${GREEN}             Eianun免费聚合落地IP 源码一键部署已完成！${PLAIN}"
say "${GREEN}==========================================================${PLAIN}"
say "  * 网页控制面板:  ${BLUE}http://${PUBLIC_IP}:${UI_PORT}/${SECRET_PATH}/${PLAIN}"
say "  * 网页管理账号:  ${YELLOW}${USERNAME}${PLAIN}"
say "  * 网页管理密码:  ${YELLOW}${PASSWORD}${PLAIN}"
say "  * HTTP/SOCKS5 代理端口:  ${BLUE}http://127.0.0.1:7928/${PLAIN}"
say " --------------------------------------------------------"
say "  * 快速状态指令:   ${YELLOW}en status${PLAIN}  兼容旧命令  ${YELLOW}eianun${PLAIN}"
say "  * 查看实时日志:   ${YELLOW}en logs${PLAIN}"
say "  * 停止服务:       ${YELLOW}en stop${PLAIN}"
say "  * 重启服务:       ${YELLOW}en restart${PLAIN}"
say "  * 设置节点来源:   ${YELLOW}en source${PLAIN}"
say "  * 设置拉取地区:   ${YELLOW}en country${PLAIN}"
say "  * 设置自动IP类型: ${YELLOW}en iptype${PLAIN}"
say "=========================================================="
