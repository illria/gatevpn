#!/usr/bin/env python3
from __future__ import annotations

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# Force socket to resolve IPv4 only to avoid slow AAAA (IPv6) DNS resolution timeouts (e.g. in WSL)
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        family = socket.AF_INET
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

import vpn_utils
import proxy_server

API_URL = "https://www.vpngate.net/api/iphone/"
VPNBOOK_OPENVPN_URL = os.environ.get("VPNBOOK_OPENVPN_URL", "https://www.vpnbook.com/freevpn/openvpn")
IPSPEED_OPENVPN_URL = os.environ.get("IPSPEED_OPENVPN_URL", "https://ipspeed.info/free-openvpn.php")
VPNBOOK_TEMPLATE_OVPN_URLS = os.environ.get(
    "VPNBOOK_TEMPLATE_OVPN_URLS",
    "https://raw.githubusercontent.com/Sadaqaty/VPNed-Wifi-Access-Point/refs/heads/main/vpnbook-openvpn-us16/vpnbook-us16-tcp443.ovpn"
)
_vpnbook_template_config_cache = ""
NODE_SOURCES_ENV = os.environ.get("NODE_SOURCES") or os.environ.get("VPN_NODE_SOURCES") or ""
# 默认启用 VPNGate + VPNBook；可在面板里调整为 vpngate / vpnbook / vpngate,vpnbook。
DEFAULT_NODE_SOURCES = os.environ.get("DEFAULT_NODE_SOURCES", "vpngate,vpnbook,ipspeed")
# VPNBook 的免费节点经常推送较激进的路由/认证参数；默认只抓取 TCP 443，避免一次性生成太多待测节点。
VPNBOOK_PROTOCOLS = os.environ.get("VPNBOOK_PROTOCOLS", "tcp443")
# VPNBook 自动检测默认关闭：混合来源时只把 VPNBook 放入节点池，不在启动阶段批量跑 OpenVPN 握手。
# 这样可以避免部分 VPS 在检测 VPNBook 节点时 SSH 卡死。需要时可以在面板单个检测/手动切换，或显式开启。
VPNBOOK_AUTO_TEST = os.environ.get("VPNBOOK_AUTO_TEST", "0").strip().lower() in {"1", "true", "yes", "on"}
VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT = max(1, int(os.environ.get("VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT", "1")))
# VPNBook 的 .ovpn 配置和服务端推送参数比较激进，单个“检测”也可能改系统路由拖死 SSH。
# 默认对 VPNBook 使用安全检测：只做 TCP/风控，不启动 OpenVPN 握手；真正连接时再启动 OpenVPN，且会禁止 OpenVPN 写系统路由。
VPNBOOK_SAFE_TEST_ONLY = os.environ.get("VPNBOOK_SAFE_TEST_ONLY", "1").strip().lower() in {"1", "true", "yes", "on"}
VPNBOOK_CONNECT_TIMEOUT_SECONDS = int(os.environ.get("VPNBOOK_CONNECT_TIMEOUT_SECONDS", "25"))
FETCH_INTERVAL_SECONDS = int(os.environ.get("FETCH_INTERVAL_SECONDS", "960"))
CHECK_INTERVAL_SECONDS = int(os.environ.get("CHECK_INTERVAL_SECONDS", "960"))
TARGET_VALID_NODES = int(os.environ.get("TARGET_VALID_NODES", "3"))
MAX_SCAN_ROWS = int(os.environ.get("MAX_SCAN_ROWS", "300"))
OPENVPN_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_TEST_TIMEOUT_SECONDS", "35"))
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "7928"))
UI_HOST = os.environ.get("UI_HOST", "0.0.0.0")
UI_PORT = int(os.environ.get("UI_PORT", "8787"))
INVALID_BACKOFF_SECONDS = int(os.environ.get("INVALID_BACKOFF_SECONDS", str(30 * 60)))
# 1 = 手动选择某个地区节点后，故障转移只在同地区内切换；0 = 同地区无可用时允许跨地区兜底。
STRICT_COUNTRY_FAILOVER = os.environ.get("STRICT_COUNTRY_FAILOVER", "1").strip().lower() not in {"0", "false", "no", "off"}
TARGET_COUNTRIES_ENV = os.environ.get("VPNGATE_TARGET_COUNTRIES") or os.environ.get("TARGET_COUNTRIES") or os.environ.get("TARGET_COUNTRY") or ""
# 风控策略：默认“优先干净，但不断线”。
# strict   = 自动故障转移只选低风险干净 IP；没有干净节点就等待补充。
# balanced = 默认模式，先选干净 IP；如果同地区全是高欺诈值/代理节点，则选择综合风险最低的可用节点兜底。
# loose    = 自动故障转移只按连通性和延迟排序，风控仅作展示。
MAX_AUTO_FRAUD_SCORE = int(os.environ.get("MAX_AUTO_FRAUD_SCORE", "25"))
AUTO_RISK_MODE = os.environ.get("AUTO_RISK_MODE", "balanced").strip().lower()
if AUTO_RISK_MODE not in {"strict", "balanced", "loose"}:
    AUTO_RISK_MODE = "balanced"
AUTO_MIN_KEEP_RUNNING = os.environ.get("AUTO_MIN_KEEP_RUNNING", "1").strip().lower() not in {"0", "false", "no", "off"}
ALLOW_RISKY_IP_CONNECT = os.environ.get("ALLOW_RISKY_IP_CONNECT", "0").strip().lower() in {"1", "true", "yes", "on"}
ALLOW_MANUAL_RISKY_CONNECT = os.environ.get("ALLOW_MANUAL_RISKY_CONNECT", "1").strip().lower() not in {"0", "false", "no", "off"}
# 自动选择/故障转移的 IP 类型优先级。默认住宅 IP 优先，但不会把自动保活卡死；
# 没有首选类型时会按 住宅 -> 移动 -> 普通/未知 -> 机房 -> 代理/Tor 逐级兜底。
# 可用值：residential, mobile, normal, hosting, proxy, tor, unknown, all。
# 只有用户显式设置环境变量时才覆盖面板保存值。
TARGET_IP_TYPES_ENV = os.environ.get("TARGET_IP_TYPES") or os.environ.get("AUTO_IP_TYPES") or os.environ.get("TARGET_IP_TYPE") or ""
# 1 = 恢复旧逻辑，把 TARGET_IP_TYPES 当作硬过滤；0 = 默认，将其作为优先级，必要时兜底到代理 IP 保持运行。
STRICT_IP_TYPE_FILTER = os.environ.get("STRICT_IP_TYPE_FILTER", "0").strip().lower() in {"1", "true", "yes", "on"}

# 自动节点检测策略。默认会检测本轮拉取/缓存中的全部非活动节点，
# 但会限制并发数量，避免一次性拉起过多 OpenVPN 进程导致 VPS 卡死。
AUTO_TEST_ALL_NODES = os.environ.get("AUTO_TEST_ALL_NODES", "1").strip().lower() not in {"0", "false", "no", "off"}
AUTO_TEST_MAX_NODES = int(os.environ.get("AUTO_TEST_MAX_NODES", "0"))  # 0 = 不额外限制，最多受 MAX_SCAN_ROWS 影响
AUTO_TEST_WORKERS = max(1, int(os.environ.get("AUTO_TEST_WORKERS", "8")))
# 首次启动/更新时先同步检测少量节点，避免安装脚本和面板长时间停在 0/N。
# 剩余节点会转入后台继续检测，并在检测完成后参与自动优选。
AUTO_TEST_INITIAL_BATCH = max(1, int(os.environ.get("AUTO_TEST_INITIAL_BATCH", "8")))
OPENVPN_BATCH_TEST_TIMEOUT_SECONDS = int(os.environ.get("OPENVPN_BATCH_TEST_TIMEOUT_SECONDS", "12"))
# 首次没有活动连接时，先做一轮质量扫描再连接，避免刚安装只测前几个节点就连到代理/高风险 IP。
# 0 = 不限制，等待本轮全部可完整检测节点；默认 80，兼顾质量和启动速度。
INITIAL_QUALITY_SCAN_BEFORE_CONNECT = os.environ.get("INITIAL_QUALITY_SCAN_BEFORE_CONNECT", "1").strip().lower() not in {"0", "false", "no", "off"}
INITIAL_QUALITY_SCAN_MAX_NODES = int(os.environ.get("INITIAL_QUALITY_SCAN_MAX_NODES", "80"))

# 自动优选策略：全部节点检测完成后，主动从已检测可用节点中按地区、IP类型、风控、延迟重新选择更优节点。
# 这不是只在断线时才切换；如果当前节点明显比候选节点差，也会自动换到更优节点。
# AUTO_SELECT_BEST_NODE 环境变量存在时优先级最高；未设置时可在 Web 面板里开关。
AUTO_SELECT_BEST_NODE_ENV = os.environ.get("AUTO_SELECT_BEST_NODE")
AUTO_SELECT_BEST_NODE = (AUTO_SELECT_BEST_NODE_ENV or "1").strip().lower() not in {"0", "false", "no", "off"}
AUTO_SELECT_COOLDOWN_SECONDS = int(os.environ.get("AUTO_SELECT_COOLDOWN_SECONDS", "600"))
AUTO_SWITCH_MIN_FRAUD_DELTA = int(os.environ.get("AUTO_SWITCH_MIN_FRAUD_DELTA", "20"))
AUTO_SWITCH_MIN_LATENCY_DELTA_MS = int(os.environ.get("AUTO_SWITCH_MIN_LATENCY_DELTA_MS", "300"))
# 非中断检测：定时检测只更新节点池和风控信息；当前出口正常时，不因为发现更优节点而主动断开重连。
# 如果想恢复“检测到更优节点就主动跳转”，可设置 AUTO_SELECT_ALLOW_ACTIVE_SWITCH=1。
AUTO_SELECT_ALLOW_ACTIVE_SWITCH = os.environ.get("AUTO_SELECT_ALLOW_ACTIVE_SWITCH", "0").strip().lower() in {"1", "true", "yes", "on"}
# 代理健康检查保护：OpenVPN 刚建立后，tun0/策略路由/本地代理有短暂稳定期。
# 在保护期内或连续失败次数未达到阈值时，不会把当前节点判死并强制断开，避免“已连接 -> 立即清理 -> 反复重连”。
PROXY_FAIL_GRACE_SECONDS = int(os.environ.get("PROXY_FAIL_GRACE_SECONDS", "75"))
PROXY_FAIL_AUTO_SWITCH_THRESHOLD = max(1, int(os.environ.get("PROXY_FAIL_AUTO_SWITCH_THRESHOLD", "3")))
AUTO_SWITCH_RETRY_COOLDOWN_SECONDS = max(10, int(os.environ.get("AUTO_SWITCH_RETRY_COOLDOWN_SECONDS", "45")))

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"

lock = threading.RLock()
active_sessions: dict[str, float] = {}
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = True
last_active_ping_time = 0.0
last_active_latency = 0

def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True)
    CONFIG_DIR.mkdir(exist_ok=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": "0.0.0.0",
            "port": 8787,
            "target_countries": TARGET_COUNTRIES_ENV,
            "target_ip_types": TARGET_IP_TYPES_ENV or "residential",
            "auto_select_best_node": AUTO_SELECT_BEST_NODE,
            "node_sources": NODE_SOURCES_ENV or DEFAULT_NODE_SOURCES,
            "auto_select_allow_active_switch": AUTO_SELECT_ALLOW_ACTIVE_SWITCH
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                if normalize_node_sources_input(config.get("node_sources")) == "vpngate,vpnbook" and not NODE_SOURCES_ENV:
                    config["node_sources"] = DEFAULT_NODE_SOURCES
                    updated = True
            except Exception:
                pass
        if TARGET_COUNTRIES_ENV:
            config["target_countries"] = TARGET_COUNTRIES_ENV
        if TARGET_IP_TYPES_ENV:
            config["target_ip_types"] = TARGET_IP_TYPES_ENV
        if AUTO_SELECT_BEST_NODE_ENV is not None and AUTO_SELECT_BEST_NODE_ENV.strip():
            config["auto_select_best_node"] = AUTO_SELECT_BEST_NODE
        if NODE_SOURCES_ENV:
            config["node_sources"] = NODE_SOURCES_ENV
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                auth_file.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
                
        return config


def split_target_countries(value: Any) -> list[str]:
    if isinstance(value, list):
        raw = ",".join(str(item) for item in value)
    else:
        raw = str(value or "")
    return [item.strip() for item in re.split(r"[,，;；|/\s]+", raw) if item.strip()]

def normalize_country_token(value: Any) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", str(value or "").strip().lower())


COUNTRY_CANONICAL_ALIASES: dict[str, list[str]] = {
    "US": ["United States", "USA", "United States of America", "America", "美国", "美國"],
    "JP": ["Japan", "日本"],
    "KR": ["Korea Republic of", "Korea", "Republic of Korea", "South Korea", "韩国", "韓國", "南韩", "南韓"],
    "GB": ["United Kingdom", "UK", "Great Britain", "Britain", "England", "英国", "英國"],
    "CA": ["Canada", "加拿大"],
    "DE": ["Germany", "德国", "德國"],
    "FR": ["France", "法国", "法國"],
    "NL": ["Netherlands", "荷兰", "荷蘭"],
    "RU": ["Russian Federation", "Russia", "Russian", "俄罗斯", "俄羅斯"],
    "AU": ["Australia", "澳大利亚", "澳洲"],
    "TW": ["Taiwan", "Taiwan Province of China", "台湾", "台灣"],
    "HK": ["Hong Kong", "香港"],
    "SG": ["Singapore", "新加坡"],
    "TH": ["Thailand", "泰国", "泰國"],
    "VN": ["Viet Nam", "Vietnam", "越南"],
    "CN": ["China", "中国", "中國"],
    "PL": ["Poland", "波兰", "波蘭"],
    "RO": ["Romania", "罗马尼亚", "羅馬尼亞"],
    "CO": ["Colombia", "哥伦比亚", "哥倫比亞"],
    "ID": ["Indonesia", "印度尼西亚", "印尼"],
    "PE": ["Peru", "秘鲁", "秘魯"],
    "MM": ["Myanmar", "Burma", "缅甸", "緬甸"],
    "IN": ["India", "印度"],
    "MY": ["Malaysia", "马来西亚", "馬來西亞"],
    "PH": ["Philippines", "菲律宾", "菲律賓"],
    "BR": ["Brazil", "巴西"],
    "AR": ["Argentina", "阿根廷"],
    "CL": ["Chile", "智利"],
    "MX": ["Mexico", "墨西哥"],
    "ES": ["Spain", "西班牙"],
    "IT": ["Italy", "意大利"],
    "SE": ["Sweden", "瑞典"],
    "NO": ["Norway", "挪威"],
    "FI": ["Finland", "芬兰", "芬蘭"],
    "DK": ["Denmark", "丹麦", "丹麥"],
    "CH": ["Switzerland", "瑞士"],
    "BE": ["Belgium", "比利时", "比利時"],
    "AT": ["Austria", "奥地利", "奧地利"],
    "IE": ["Ireland", "爱尔兰", "愛爾蘭"],
    "PT": ["Portugal", "葡萄牙"],
    "GR": ["Greece", "希腊", "希臘"],
    "CZ": ["Czech Republic", "Czechia", "捷克"],
    "HU": ["Hungary", "匈牙利"],
    "TR": ["Turkey", "Türkiye", "土耳其"],
    "UA": ["Ukraine", "乌克兰", "烏克蘭"],
}
COUNTRY_CODE_TO_EN: dict[str, str] = {code: aliases[0] for code, aliases in COUNTRY_CANONICAL_ALIASES.items()}
_COUNTRY_ALIAS_INDEX: dict[str, str] = {}
for _code, _aliases in COUNTRY_CANONICAL_ALIASES.items():
    _COUNTRY_ALIAS_INDEX[normalize_country_token(_code)] = _code
    for _alias in _aliases:
        _COUNTRY_ALIAS_INDEX[normalize_country_token(_alias)] = _code

def canonical_country_code(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        token = normalize_country_token(text)
        if token in _COUNTRY_ALIAS_INDEX:
            return _COUNTRY_ALIAS_INDEX[token]
        if len(text) == 2 and text.upper() in COUNTRY_CODE_TO_EN:
            return text.upper()
    return ""

def canonical_country_display(country_short: Any = "", country_value: Any = "") -> str:
    code = canonical_country_code(country_short, country_value)
    if code:
        english = COUNTRY_CODE_TO_EN.get(code, code)
        return vpn_utils.COUNTRY_TRANSLATIONS.get(english, english)
    country = str(country_value or "").strip()
    return vpn_utils.COUNTRY_TRANSLATIONS.get(country, vpn_utils.COUNTRY_TRANSLATIONS.get(country.strip(), country))

def canonicalize_country_fields(country_short: Any = "", country_value: Any = "") -> tuple[str, str]:
    code = canonical_country_code(country_short, country_value)
    display = canonical_country_display(code or country_short, country_value)
    return code or str(country_short or "").strip(), display

def normalize_target_countries_input(value: Any) -> str:
    # Accept ISO country codes (JP/US/KR), English names, or Chinese names.
    # Keep the saved value readable while deduplicating normalized tokens.
    result: list[str] = []
    seen: set[str] = set()
    for item in split_target_countries(value):
        token = normalize_country_token(item)
        if token and token not in seen:
            result.append(item)
            seen.add(token)
    return ",".join(result)


def split_node_sources(value: Any) -> list[str]:
    raw = str(value or "")
    aliases = {
        "vpngate": "vpngate", "vpn_gate": "vpngate", "gate": "vpngate", "vg": "vpngate", "筑波": "vpngate",
        "vpnbook": "vpnbook", "book": "vpnbook", "vb": "vpnbook",
        "ipspeed": "ipspeed", "ip_speed": "ipspeed", "speed": "ipspeed", "is": "ipspeed",
    }
    result: list[str] = []
    seen: set[str] = set()
    for part in re.split(r"[,，;；|/\s]+", raw):
        token = part.strip().lower().replace("-", "_")
        if not token:
            continue
        canonical = aliases.get(token, token)
        if canonical in {"all", "全部", "*"}:
            canonical = "vpngate,vpnbook,ipspeed"
        for item in str(canonical).split(","):
            item = item.strip()
            if item in {"vpngate", "vpnbook", "ipspeed"} and item not in seen:
                result.append(item)
                seen.add(item)
    return result or ["vpngate", "vpnbook", "ipspeed"]

def normalize_node_sources_input(value: Any) -> str:
    return ",".join(split_node_sources(value))

def get_node_sources() -> list[str]:
    cfg = load_ui_config()
    return split_node_sources(NODE_SOURCES_ENV or cfg.get("node_sources") or DEFAULT_NODE_SOURCES)

def node_sources_display(value: Any) -> str:
    labels = {"vpngate": "VPNGate", "vpnbook": "VPNBook", "ipspeed": "IPSpeed"}
    return " + ".join(labels.get(x, x) for x in split_node_sources(value))

def get_target_countries() -> list[str]:
    cfg = load_ui_config()
    return split_target_countries(cfg.get("target_countries") or TARGET_COUNTRIES_ENV)

IP_TYPE_ALIASES: dict[str, tuple[str, ...]] = {
    "residential": ("residential", "住宅", "家宽", "原生", "home", "isp", "clean_residential"),
    "mobile": ("mobile", "移动", "手机", "蜂窝"),
    "normal": ("normal", "普通", "unknown", "未知", "空", "未识别", ""),
    "hosting": ("hosting", "datacenter", "data_center", "dc", "机房", "数据中心", "服务器", "vps", "cloud"),
    "proxy": ("proxy", "代理", "vpn"),
    "tor": ("tor", "洋葱"),
}

def normalize_ip_type_token(value: Any) -> str:
    token = str(value or "").strip().lower().replace(" ", "_").replace("-", "_")
    if token in {"all", "any", "全部", "不限", "任意", "*"}:
        return "all"
    for canonical, aliases in IP_TYPE_ALIASES.items():
        if token in {str(a).strip().lower().replace(" ", "_").replace("-", "_") for a in aliases}:
            return canonical
    return token

def split_target_ip_types(value: Any) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        raw_parts = [str(x).strip() for x in value]
    else:
        raw_parts = re.split(r"[,，;；\s]+", str(value or ""))
    result: list[str] = []
    seen: set[str] = set()
    for part in raw_parts:
        token = normalize_ip_type_token(part)
        if not token:
            continue
        if token == "all":
            return []
        if token not in seen:
            result.append(token)
            seen.add(token)
    return result

def normalize_target_ip_types_input(value: Any) -> str:
    # Preserve explicit all/全部 so the UI can distinguish it from an empty default.
    if isinstance(value, str):
        raw_parts = re.split(r"[,，;；\s]+", value)
        if any(normalize_ip_type_token(part) == "all" for part in raw_parts if part.strip()):
            return "all"
    types = split_target_ip_types(value)
    return ",".join(types)

def get_target_ip_types() -> list[str]:
    cfg = load_ui_config()
    return split_target_ip_types(cfg.get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential")

def ip_type_display(value: Any) -> str:
    token = normalize_ip_type_token(value)
    return {
        "residential": "住宅IP",
        "mobile": "移动IP",
        "normal": "普通/未知",
        "hosting": "机房IP",
        "proxy": "代理IP",
        "tor": "Tor出口",
    }.get(token, str(value or ""))


def parse_bool_setting(value: Any, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "enable", "enabled", "开启"}:
        return True
    if text in {"0", "false", "no", "off", "disable", "disabled", "关闭"}:
        return False
    return default

def get_auto_select_best_node() -> bool:
    if AUTO_SELECT_BEST_NODE_ENV is not None and AUTO_SELECT_BEST_NODE_ENV.strip():
        return AUTO_SELECT_BEST_NODE
    cfg = load_ui_config()
    return parse_bool_setting(cfg.get("auto_select_best_node"), AUTO_SELECT_BEST_NODE)

def get_auto_select_allow_active_switch() -> bool:
    cfg = load_ui_config()
    return parse_bool_setting(cfg.get("auto_select_allow_active_switch"), AUTO_SELECT_ALLOW_ACTIVE_SWITCH)

def active_connection_looks_healthy(active_node: dict[str, Any] | None = None) -> bool:
    if not active_openvpn_running():
        return False
    state = read_json(STATE_FILE, {})
    now = time.time()
    connected_at = float(state.get("active_connected_at") or 0)
    # 刚连接成功后的保护期内，不因代理探测暂时失败而判定当前节点已死。
    if connected_at and now - connected_at < PROXY_FAIL_GRACE_SECONDS:
        return True
    fail_count = int(state.get("proxy_fail_count") or 0)
    # 单次代理出口探测失败不能代表节点已死。免费 VPN 出口常有短暂抖动，
    # 只有连续失败达到阈值后才允许故障转移，避免正常住宅/移动节点被误切到代理 IP。
    if fail_count >= PROXY_FAIL_AUTO_SWITCH_THRESHOLD:
        return False
    if active_node and str(active_node.get("probe_status") or "available").lower() == "unavailable":
        return False
    return True

def target_ip_types_display(value: Any) -> str:
    types = split_target_ip_types(value)
    if not types:
        return "全部类型"
    label = "、".join(ip_type_display(t) for t in types)
    if STRICT_IP_TYPE_FILTER:
        return f"{label}硬过滤"
    return f"{label}优先"

def node_matches_target_ip_types(node: dict[str, Any], target_types: list[str]) -> bool:
    if not target_types:
        return True
    ip_type = normalize_ip_type_token(node.get("ip_type") or "unknown")
    quality = normalize_ip_type_token(node.get("quality") or "")
    node_tokens = {ip_type, quality}
    if quality in {"clean_residential", "residential"}:
        node_tokens.add("residential")
    if quality in {"datacenter", "hosting"}:
        node_tokens.add("hosting")
    if not node_has_risk_data(node) and "normal" in target_types:
        node_tokens.add("normal")
    return any(t in node_tokens for t in target_types)

def row_country_tokens(row: dict[str, str]) -> set[str]:
    country_long = (row.get("CountryLong") or "").strip()
    country_short = (row.get("CountryShort") or "").strip()
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    tokens = {country_short, country_long, country_zh}
    code = canonical_country_code(country_short, country_long, country_zh)
    if code:
        tokens.add(code)
        tokens.update(COUNTRY_CANONICAL_ALIASES.get(code, []))
    return {normalize_country_token(token) for token in tokens if token}

def row_matches_target_countries(row: dict[str, str], targets: list[str]) -> bool:
    if not targets:
        return True
    row_tokens = row_country_tokens(row)
    for target in targets:
        token = normalize_country_token(target)
        if token and token in row_tokens:
            return True
    return False


def node_country_tokens(node: dict[str, Any]) -> set[str]:
    """Return normalized country tokens for a cached/tested node."""
    country_short = str(node.get("country_short") or "").strip()
    country = str(node.get("country") or "").strip()
    tokens = {country_short, country}
    reverse_translations = {normalize_country_token(v): k for k, v in vpn_utils.COUNTRY_TRANSLATIONS.items()}
    if normalize_country_token(country) in reverse_translations:
        tokens.add(reverse_translations[normalize_country_token(country)])
    code = canonical_country_code(country_short, country)
    if code:
        tokens.add(code)
        tokens.update(COUNTRY_CANONICAL_ALIASES.get(code, []))
    return {normalize_country_token(token) for token in tokens if token}

def node_matches_target_countries(node: dict[str, Any], targets: list[str]) -> bool:
    if not targets:
        return True
    node_tokens = node_country_tokens(node)
    for target in targets:
        token = normalize_country_token(target)
        if token and token in node_tokens:
            return True
    return False

def node_has_risk_data(node: dict[str, Any]) -> bool:
    risk_level = str(node.get("risk_level") or "").lower()
    return bool(
        risk_level in {"clean", "low", "medium", "high", "blocked"}
        or node.get("risk_sources")
        or node.get("fraud_flags")
        or node.get("blacklist_hits")
    )

def node_fraud_score(node: dict[str, Any], unknown: int = 50) -> int:
    val = node.get("fraud_score")
    if val in (None, ""):
        return unknown
    return parse_int(val)

def node_is_clean_for_connect(node: dict[str, Any]) -> bool:
    if ALLOW_RISKY_IP_CONNECT:
        return True
    if not node_has_risk_data(node):
        return False
    if parse_int(node.get("blacklist_count")) > 0:
        return False
    if node_fraud_score(node, unknown=100) > MAX_AUTO_FRAUD_SCORE:
        return False
    if str(node.get("risk_level") or "").lower() in {"medium", "high", "blocked"}:
        return False
    if str(node.get("ip_type") or "").lower() in {"proxy", "hosting", "tor"}:
        return False
    return True

def node_ip_priority_rank(node: dict[str, Any]) -> int:
    """Lower is better. Prefer clean residential IPs; deprioritize risky or blacklisted IPs."""
    ip_type = str(node.get("ip_type") or "").strip().lower()
    quality = str(node.get("quality") or "").strip().lower()
    risk_level = str(node.get("risk_level") or "").strip().lower()
    blacklist_count = parse_int(node.get("blacklist_count"))
    fraud_score = node_fraud_score(node, unknown=50)

    if blacklist_count > 0 or risk_level in {"high", "blocked"}:
        return 99
    if fraud_score > MAX_AUTO_FRAUD_SCORE and not ALLOW_RISKY_IP_CONNECT:
        return 90
    if ip_type == "residential" and quality in {"clean_residential", "", "normal", "residential"} and risk_level in {"clean", ""}:
        return 0
    if ip_type == "residential":
        return 1
    if ip_type == "mobile" or quality == "mobile":
        return 2
    if quality in {"", "normal"} and ip_type in {"", "unknown"}:
        return 5
    if ip_type == "hosting" or quality in {"hosting", "datacenter"}:
        return 8
    if ip_type in {"proxy", "tor"} or quality in {"proxy", "risky"}:
        return 9
    return 6

def node_sort_key(node: dict[str, Any]) -> tuple[int, int, int, int, int]:
    return (
        node_ip_priority_rank(node),
        node_fraud_score(node, unknown=50),
        parse_int(node.get("latency_ms")) or 999999,
        parse_int(node.get("ping")) or 999999,
        -parse_int(node.get("score")),
    )

def node_auto_fallback_key(node: dict[str, Any]) -> tuple[int, int, int, int, int, int]:
    """Lower is better for emergency failover. Risk is a ranking factor, not a hard block."""
    risk_level = str(node.get("risk_level") or "unknown").lower()
    ip_type = normalize_ip_type_token(node.get("ip_type") or "unknown")
    blacklist_count = parse_int(node.get("blacklist_count"))
    fraud_score = node_fraud_score(node, unknown=80)

    risk_rank = 0
    if blacklist_count > 0:
        risk_rank += 80 + min(blacklist_count, 9)
    if risk_level == "blocked":
        risk_rank += 70
    elif risk_level == "high":
        risk_rank += 45
    elif risk_level == "medium":
        risk_rank += 25
    elif risk_level in {"unknown", ""}:
        risk_rank += 15
    if ip_type in {"proxy", "tor"}:
        risk_rank += 35
    elif ip_type in {"hosting", "datacenter"}:
        risk_rank += 20
    elif ip_type == "mobile":
        risk_rank += 5
    elif ip_type == "residential":
        risk_rank -= 10

    return (
        risk_rank,
        fraud_score,
        node_ip_priority_rank(node),
        parse_int(node.get("latency_ms")) or 999999,
        parse_int(node.get("ping")) or 999999,
        -parse_int(node.get("score")),
    )

DEFAULT_IP_TYPE_FALLBACK_ORDER = ["residential", "mobile", "normal", "hosting", "proxy", "tor"]

def ip_type_preference_order(preferred_types: list[str]) -> list[str]:
    """Return preferred IP type order with safe auto-fallback tiers appended.

    TARGET_IP_TYPES is treated as preference by default, not a hard filter. For example,
    residential means: residential first, then mobile, normal/unknown, hosting, proxy, tor.
    Set STRICT_IP_TYPE_FILTER=1 to restore hard filtering.
    """
    if not preferred_types:
        return list(DEFAULT_IP_TYPE_FALLBACK_ORDER)
    order: list[str] = []
    seen: set[str] = set()
    for item in preferred_types:
        token = normalize_ip_type_token(item)
        if token and token != "all" and token not in seen:
            order.append(token)
            seen.add(token)
    if STRICT_IP_TYPE_FILTER:
        return order
    for item in DEFAULT_IP_TYPE_FALLBACK_ORDER:
        if item not in seen:
            order.append(item)
            seen.add(item)
    return order

def tiered_ip_type_candidates(candidates: list[dict[str, Any]], preferred_types: list[str]) -> tuple[list[dict[str, Any]], str]:
    """Choose the first available IP-type tier, sorted by risk/latency.

    This prevents auto failover from stopping when a country has no residential IP, while still
    making proxy/Tor the last resort.
    """
    if not candidates:
        return [], "无候选节点"
    if not preferred_types:
        pool = list(candidates)
        pool.sort(key=node_auto_fallback_key)
        return pool, "全部类型按综合风险/延迟排序"

    if STRICT_IP_TYPE_FILTER:
        pool = [n for n in candidates if node_matches_target_ip_types(n, preferred_types)]
        pool.sort(key=node_auto_fallback_key)
        return pool, f"严格 IP 类型过滤：{target_ip_types_display(preferred_types)}"

    used_ids: set[str] = set()
    for ip_type in ip_type_preference_order(preferred_types):
        tier = []
        for node in candidates:
            node_key = str(node.get("id") or id(node))
            if node_key in used_ids:
                continue
            if node_matches_target_ip_types(node, [ip_type]):
                tier.append(node)
                used_ids.add(node_key)
        if tier:
            tier.sort(key=node_auto_fallback_key)
            return tier, f"IP 类型优先级命中：{ip_type_display(ip_type)}"

    pool = list(candidates)
    pool.sort(key=node_auto_fallback_key)
    return pool, "未识别 IP 类型，按综合风险/延迟兜底"

def choose_auto_failover_candidates(scoped_candidates: list[dict[str, Any]], all_candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
    """Pick automatic failover candidates.

    Country remains the main scope. IP type is a preference chain, not a dead-end filter:
    residential -> mobile -> normal/unknown -> hosting/datacenter -> proxy/Tor. Risk scoring
    is used for ranking. It only becomes a hard block when strict mode and keep-running are disabled.
    """
    target_ip_types = get_target_ip_types()
    ip_type_label = target_ip_types_display(target_ip_types)

    if STRICT_IP_TYPE_FILTER:
        scoped_pool = [n for n in scoped_candidates if node_matches_target_ip_types(n, target_ip_types)] if target_ip_types else list(scoped_candidates)
        all_pool = [n for n in all_candidates if node_matches_target_ip_types(n, target_ip_types)] if target_ip_types else list(all_candidates)
    else:
        scoped_pool = list(scoped_candidates)
        all_pool = list(all_candidates)

    clean_scoped = [n for n in scoped_pool if node_is_clean_for_connect(n)]
    clean_all = [n for n in all_pool if node_is_clean_for_connect(n)]

    if AUTO_RISK_MODE == "loose" or ALLOW_RISKY_IP_CONNECT:
        candidates, tier_reason = tiered_ip_type_candidates(scoped_pool, target_ip_types)
        if not candidates and not STRICT_COUNTRY_FAILOVER:
            candidates, tier_reason = tiered_ip_type_candidates(all_pool, target_ip_types)
            if candidates:
                return candidates, f"宽松模式跨地区兜底；{tier_reason}"
        if candidates:
            return candidates, f"宽松模式：{tier_reason}"
        return [], f"没有可用节点；IP 类型策略 {ip_type_label}"

    clean_candidates, clean_tier_reason = tiered_ip_type_candidates(clean_scoped, target_ip_types)
    if clean_candidates:
        clean_candidates.sort(key=node_sort_key)
        return clean_candidates, f"优先选择同地区干净节点；{clean_tier_reason}"

    if not STRICT_COUNTRY_FAILOVER:
        clean_cross, cross_reason = tiered_ip_type_candidates(clean_all, target_ip_types)
        if clean_cross:
            clean_cross.sort(key=node_sort_key)
            return clean_cross, f"同地区无干净节点，跨地区选择干净节点；{cross_reason}"

    if AUTO_RISK_MODE == "strict" and not AUTO_MIN_KEEP_RUNNING:
        return [], f"严格模式：没有符合阈值的干净节点；IP 类型策略 {ip_type_label}"

    fallback_pool = scoped_pool
    fallback_candidates, fallback_reason = tiered_ip_type_candidates(fallback_pool, target_ip_types)
    if fallback_candidates:
        return fallback_candidates, f"保活兜底：无干净 IP，按同地区 IP 类型优先级逐级选择；{fallback_reason}"

    if not STRICT_COUNTRY_FAILOVER:
        fallback_candidates, fallback_reason = tiered_ip_type_candidates(all_pool, target_ip_types)
        if fallback_candidates:
            return fallback_candidates, f"跨地区保活兜底：按 IP 类型优先级逐级选择；{fallback_reason}"

    return [], "没有可用节点；将继续后台拉取/检测"

def get_failover_targets(active_node: dict[str, Any] | None = None) -> list[str]:
    """Return the country scope used by auto failover.

    Priority:
    1) Explicit 拉取地区过滤 in settings/env;
    2) The country of the last manually connected node;
    3) The currently active node country.
    """
    configured = get_target_countries()
    if configured:
        return configured
    state = read_json(STATE_FILE, {})
    saved = state.get("failover_country_short") or state.get("failover_country") or ""
    if saved:
        return split_target_countries(saved)
    if active_node:
        country_short = active_node.get("country_short") or ""
        country = active_node.get("country") or ""
        return split_target_countries(country_short or country)
    return []

def set_failover_scope_from_node(node: dict[str, Any]) -> None:
    country_short = str(node.get("country_short") or "").strip()
    country = str(node.get("country") or "").strip()
    set_state(
        failover_country_short=country_short,
        failover_country=country,
        failover_country_display=country or country_short or "未固定",
        strict_country_failover=STRICT_COUNTRY_FAILOVER,
    )



def auto_selection_key_summary(node: dict[str, Any]) -> str:
    return (
        f"IP类型 {ip_type_display(node.get('ip_type') or node.get('quality') or 'unknown')} / "
        f"欺诈值 {node.get('fraud_score', '未知')} / "
        f"黑名单 {node.get('blacklist_count', 0)} / "
        f"延迟 {node.get('latency_ms') or node.get('ping') or '-'} ms"
    )

def should_switch_to_better_node(active_node: dict[str, Any] | None, best_node: dict[str, Any]) -> tuple[bool, str]:
    """Return whether an already-running connection should be replaced by a better tested node.

    The goal is to use full-node detection results, but avoid unstable constant switching.
    We switch when the candidate has a clearly better IP tier/risk score/fraud score,
    or a meaningfully lower latency.
    """
    if not active_node:
        return True, "当前没有活动节点"
    if best_node.get("id") == active_node.get("id"):
        return False, "当前节点已经是本轮优选节点"

    active_status = str(active_node.get("probe_status") or "").lower()
    if active_status not in {"available", ""}:
        return True, "当前活动节点状态异常"

    active_blacklist = parse_int(active_node.get("blacklist_count"))
    best_blacklist = parse_int(best_node.get("blacklist_count"))
    if best_blacklist < active_blacklist:
        return True, f"候选节点黑名单命中更少：{active_blacklist} -> {best_blacklist}"

    active_ip_rank = node_ip_priority_rank(active_node)
    best_ip_rank = node_ip_priority_rank(best_node)
    if best_ip_rank + 1 < active_ip_rank:
        return True, f"候选节点 IP 类型/风控等级明显更优：{auto_selection_key_summary(active_node)} -> {auto_selection_key_summary(best_node)}"

    active_fraud = node_fraud_score(active_node, unknown=80)
    best_fraud = node_fraud_score(best_node, unknown=80)
    if active_fraud - best_fraud >= AUTO_SWITCH_MIN_FRAUD_DELTA:
        return True, f"候选节点欺诈值明显更低：{active_fraud} -> {best_fraud}"

    active_risk = str(active_node.get("risk_level") or "unknown").lower()
    best_risk = str(best_node.get("risk_level") or "unknown").lower()
    risk_order = {"clean": 0, "low": 1, "unknown": 2, "medium": 3, "high": 4, "blocked": 5}
    if risk_order.get(best_risk, 2) + 1 < risk_order.get(active_risk, 2):
        return True, f"候选节点风险等级明显更低：{active_risk} -> {best_risk}"

    # Only use latency to switch when the risk/IP tier is not worse, and improvement is obvious.
    active_latency = parse_int(active_node.get("latency_ms")) or parse_int(active_node.get("ping")) or 999999
    best_latency = parse_int(best_node.get("latency_ms")) or parse_int(best_node.get("ping")) or 999999
    if best_ip_rank <= active_ip_rank and best_fraud <= active_fraud and active_latency - best_latency >= AUTO_SWITCH_MIN_LATENCY_DELTA_MS:
        return True, f"候选节点延迟明显更低：{active_latency} ms -> {best_latency} ms"

    return False, "候选节点没有明显优于当前活动节点，避免频繁跳节点"

def optimize_active_node_after_tests(reason: str = "") -> str:
    """After batch testing, actively select the best available node from all tested nodes.

    This closes the gap where the panel showed tested residential/mobile nodes but the service
    stayed on an older proxy/high-risk node until failure. Automatic selection still respects
    country scope and IP-type preference, but it is not a dead-end filter.
    """
    if not get_auto_select_best_node():
        return "自动优选已关闭"

    with lock:
        nodes = read_json(NODES_FILE, [])
        active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id or n.get("active")), None)
        available = [n for n in nodes if n.get("probe_status") == "available"]

    if not available:
        msg = "自动优选：暂无已检测可用节点"
        set_state(last_auto_select_message=msg)
        return msg

    failover_targets = get_failover_targets(active_node)
    scoped = [n for n in available if node_matches_target_countries(n, failover_targets)] if failover_targets else list(available)
    candidates, candidate_reason = choose_auto_failover_candidates(scoped, available)
    if not candidates:
        msg = f"自动优选：没有符合当前地区/IP策略的可用节点；{candidate_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    best_node = candidates[0]
    should_switch, switch_reason = should_switch_to_better_node(active_node, best_node)
    if not should_switch:
        msg = f"自动优选：保持当前节点；{switch_reason}；策略：{candidate_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    if active_connection_looks_healthy(active_node) and not get_auto_select_allow_active_switch():
        msg = (
            f"非中断检测：发现更优节点 {best_node.get('id')}，但当前出口正常运行，"
            "不会为了检测/优选而主动断开重连；仅在当前节点失效时自动故障转移。"
        )
        set_state(last_auto_select_message=msg, last_check_message=msg)
        return msg

    state = read_json(STATE_FILE, {})
    now = time.time()
    last_switch = float(state.get("last_auto_select_switch_at") or 0)
    if active_openvpn_running() and last_switch > 0 and now - last_switch < AUTO_SELECT_COOLDOWN_SECONDS:
        left = int(AUTO_SELECT_COOLDOWN_SECONDS - (now - last_switch))
        msg = f"自动优选：发现更优节点 {best_node.get('id')}，但冷却中，约 {left} 秒后再自动切换；原因：{switch_reason}"
        set_state(last_auto_select_message=msg)
        return msg

    clean_ok = node_is_clean_for_connect(best_node)
    msg = (
        f"自动优选：从全部已检测节点中选择 {best_node.get('id')}；"
        f"{auto_selection_key_summary(best_node)}；原因：{switch_reason}；策略：{candidate_reason}"
    )
    print(f"[自动优选] {msg}", flush=True)
    log_to_json("INFO", "VPN", msg)
    set_state(last_auto_select_message=msg, last_check_message=msg, last_auto_select_switch_at=now)
    try:
        return connect_node(best_node["id"], update_failover_scope=False, allow_auto_risky=not clean_ok)
    except Exception as e:
        err = f"自动优选切换失败：{e}"
        print(f"[自动优选] {err}", flush=True)
        log_to_json("WARNING", "VPN", err)
        set_state(last_auto_select_message=err, last_check_message=err)
        return err

def get_session_token(password: str, username: str = "admin") -> str:
    salt = "eianun_vpngate_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

def cleanup_old_logs(logs_dir: Path) -> None:
    try:
        now = time.time()
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    state.setdefault("local_proxy", f"http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}")
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    
    # Pre-populate settings inputs in UI
    ui_cfg = load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8787)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    target_countries = normalize_target_countries_input(ui_cfg.get("target_countries") or TARGET_COUNTRIES_ENV)
    target_ip_types = normalize_target_ip_types_input(ui_cfg.get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential")
    state["target_countries"] = target_countries
    state["target_countries_display"] = target_countries or "全部地区"
    state["target_ip_types"] = target_ip_types
    state["target_ip_types_display"] = target_ip_types_display(target_ip_types)
    state["node_sources"] = normalize_node_sources_input(ui_cfg.get("node_sources") or NODE_SOURCES_ENV or DEFAULT_NODE_SOURCES)
    state["node_sources_display"] = node_sources_display(state["node_sources"])
    state.setdefault("failover_country_short", "")
    state.setdefault("failover_country", "")
    state.setdefault("failover_country_display", target_countries or "未固定")
    state["strict_country_failover"] = STRICT_COUNTRY_FAILOVER
    state["max_auto_fraud_score"] = MAX_AUTO_FRAUD_SCORE
    state["auto_risk_mode"] = AUTO_RISK_MODE
    state["auto_min_keep_running"] = AUTO_MIN_KEEP_RUNNING
    state["strict_ip_type_filter"] = STRICT_IP_TYPE_FILTER
    state["allow_risky_ip_connect"] = ALLOW_RISKY_IP_CONNECT
    state["allow_manual_risky_connect"] = ALLOW_MANUAL_RISKY_CONNECT
    state["auto_test_all_nodes"] = AUTO_TEST_ALL_NODES
    state["auto_test_max_nodes"] = AUTO_TEST_MAX_NODES
    state["auto_test_workers"] = AUTO_TEST_WORKERS
    state["vpnbook_auto_test"] = VPNBOOK_AUTO_TEST
    state["vpnbook_protocols"] = VPNBOOK_PROTOCOLS
    state["openvpn_batch_test_timeout_seconds"] = OPENVPN_BATCH_TEST_TIMEOUT_SECONDS
    state["auto_select_best_node"] = get_auto_select_best_node()
    state["auto_select_allow_active_switch"] = get_auto_select_allow_active_switch()
    state["auto_select_cooldown_seconds"] = AUTO_SELECT_COOLDOWN_SECONDS
    state["auto_switch_min_fraud_delta"] = AUTO_SWITCH_MIN_FRAUD_DELTA
    state["auto_switch_min_latency_delta_ms"] = AUTO_SWITCH_MIN_LATENCY_DELTA_MS
    state.setdefault("auto_test_total", 0)
    state.setdefault("auto_test_done", 0)
    state.setdefault("last_auto_select_switch_at", 0)
    state.setdefault("last_auto_select_message", "")
    state.setdefault("active_connected_at", 0)
    state.setdefault("proxy_fail_count", 0)
    state.setdefault("last_auto_switch_attempt_at", 0)
    state["proxy_fail_grace_seconds"] = PROXY_FAIL_GRACE_SECONDS
    state["proxy_fail_auto_switch_threshold"] = PROXY_FAIL_AUTO_SWITCH_THRESHOLD
    state["auto_switch_retry_cooldown_seconds"] = AUTO_SWITCH_RETRY_COOLDOWN_SECONDS
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def resolve_ip_for_risk(host: str) -> str:
    host = str(host or "").strip()
    if not host:
        return ""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host

def http_get_bytes(url: str, timeout: int = 15, accept: str = "*/*") -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 eianun-vpngate-manager/2.0",
            "Accept": accept,
            "Referer": VPNBOOK_OPENVPN_URL if "vpnbook.com" in url else (IPSPEED_OPENVPN_URL if "ipspeed.info" in url else API_URL),
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()

def fetch_api_text() -> str:
    return http_get_bytes(API_URL, timeout=12, accept="text/plain,*/*").decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    return {}

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    pass

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "source": "vpngate",
        "country": country_zh,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "auth_user": OPENVPN_AUTH_USER,
        "auth_pass": OPENVPN_AUTH_PASS,
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_vpngate_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 2
    log_to_json("INFO", "Main", f"开始拉取 VPNGate API 节点，地区过滤: {target_display} (最大尝试次数: {max_attempts})...")
    for i in range(max_attempts):
        if i > 0:
            time.sleep(1.5)
        try:
            api_text = fetch_api_text()
            rows = parse_vpngate_rows(api_text)
            matched_rows = 0
            filtered_rows = 0
            for row in rows:
                if not row_matches_target_countries(row, target_countries):
                    filtered_rows += 1
                    continue
                matched_rows += 1
                if matched_rows > MAX_SCAN_ROWS:
                    break
                ip = row.get("IP", "")
                if not ip or ip in seen_keys:
                    continue
                encoded = row.get("OpenVPN_ConfigData_Base64", "")
                if not encoded:
                    continue
                config_text = decode_config(encoded)
                node = row_to_node(row, config_text)
                node["source"] = "vpngate"
                candidates.append(node)
                seen_keys.add(ip)
            if target_countries:
                log_to_json("INFO", "Main", f"VPNGate 地区过滤 {target_display}: 匹配 {matched_rows} 行，跳过 {filtered_rows} 行")
            break
        except Exception as e:
            print(f"[fetch_vpngate_candidates] Fetch {i+1} failed: {e}", flush=True)
            log_to_json("WARNING", "Main", f"第 {i+1} 次拉取 VPNGate 节点失败: {e}")
            if i == max_attempts - 1:
                log_to_json("ERROR", "Main", f"VPNGate 节点拉取失败: {e}")
    return candidates

VPNBOOK_COUNTRIES: dict[str, tuple[str, str]] = {
    "us": ("US", "United States"),
    "ca": ("CA", "Canada"),
    "uk": ("GB", "United Kingdom"),
    "gb": ("GB", "United Kingdom"),
    "de": ("DE", "Germany"),
    "fr": ("FR", "France"),
    "pl": ("PL", "Poland"),
}

def vpnbook_protocol_parts(proto_name: str) -> tuple[str, int, str]:
    token = str(proto_name or "").strip().lower().replace("_", "").replace("-", "")
    if token in {"tcp443", "443", "tcp"}:
        return "tcp", 443, "tcp443"
    if token in {"tcp80", "80"}:
        return "tcp", 80, "tcp80"
    if token in {"udp53", "53", "udp"}:
        return "udp", 53, "udp53"
    if token in {"udp25000", "25000"}:
        return "udp", 25000, "udp25000"
    m = re.match(r"^(tcp|udp)(\d+)$", token)
    if m:
        return m.group(1), int(m.group(2)), f"{m.group(1)}{m.group(2)}"
    return "tcp", 443, "tcp443"

def extract_vpnbook_credentials(page_text: str) -> tuple[str, str]:
    username = "vpnbook"
    password = ""
    text = re.sub(r"<[^>]+>", " ", page_text)
    text = re.sub(r"\s+", " ", text)
    m_user = re.search(r"Username\s*(vpnbook)", text, re.I) or re.search(r"用户名\s*(vpnbook)", text, re.I)
    if m_user:
        username = m_user.group(1).strip()
    m_pass = re.search(r"Password\s*([A-Za-z0-9]{4,32})", text, re.I) or re.search(r"密码\s*([A-Za-z0-9]{4,32})", text, re.I)
    if m_pass:
        password = m_pass.group(1).strip()
    return username, password

def fetch_vpnbook_page() -> str:
    for url in [VPNBOOK_OPENVPN_URL, "https://www.vpnbook.com/zh/freevpn/openvpn"]:
        try:
            return http_get_bytes(url, timeout=15, accept="text/html,*/*").decode("utf-8", errors="replace")
        except Exception as exc:
            log_to_json("WARNING", "VPNBook", f"读取 VPNBook 页面失败 {url}: {exc}")
    return ""

def parse_vpnbook_servers(page_text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[str] = set()
    for host in re.findall(r"\b((?:us|ca|uk|gb|de|fr|pl)\d+\.vpnbook\.com)\b", page_text, flags=re.I):
        host = host.lower()
        if host in seen:
            continue
        seen.add(host)
        prefix_match = re.match(r"([a-z]+)", host)
        prefix = prefix_match.group(1) if prefix_match else ""
        country_short, country_long = VPNBOOK_COUNTRIES.get(prefix, (prefix.upper() or "XX", prefix.upper() or "Unknown"))
        found.append({"host": host, "country_short": country_short, "country_long": country_long})
    return found

def looks_like_openvpn_config(text: str) -> bool:
    lower = (text or "").lower()
    return "client" in lower[:800] and "remote" in lower and ("<ca>" in lower or "-----begin certificate-----" in lower)

def sanitize_openvpn_config_for_eianun(config_text: str) -> str:
    """Remove local OpenVPN directives that can hijack the VPS default route or run scripts.

    Eianun uses --route-nopull/--route-noexec plus policy routing. Free templates, especially
    VPNBook templates copied from the web, often contain redirect-gateway, route or script hooks.
    Leaving those directives in the file can make a manual test or connect rewrite the host routing
    table and freeze SSH.
    """
    dangerous_prefixes = (
        "redirect-gateway",
        "route",
        "route-ipv6",
        "dhcp-option",
        "pull-filter",
        "up",
        "down",
        "route-up",
        "iproute",
        "script-security",
        "block-outside-dns",
    )
    kept: list[str] = []
    for raw in config_text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        stripped = raw.strip()
        lower = stripped.lower()
        if not stripped or stripped.startswith(("#", ";")):
            kept.append(raw)
            continue
        key = lower.split(None, 1)[0]
        if key in dangerous_prefixes:
            kept.append(f"# eianun removed unsafe directive: {stripped}")
            continue
        kept.append(raw)
    return "\n".join(kept).strip() + "\n"

def normalize_vpnbook_config_text(config_text: str, host: str, proto: str, port: int) -> str:
    text = sanitize_openvpn_config_for_eianun(config_text).replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
    text = re.sub(r"(?m)^proto\s+\S+", f"proto {proto}", text)
    if re.search(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", text):
        text = re.sub(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", f"remote {host} {port}", text, count=1)
    else:
        text = f"remote {host} {port}\n" + text
    if re.search(r"(?m)^auth-user-pass(?:\s+.+)?$", text):
        text = re.sub(r"(?m)^auth-user-pass(?:\s+.+)?$", "auth-user-pass", text, count=1)
    else:
        text = "auth-user-pass\n" + text
    return text

def fetch_vpnbook_template_config() -> str:
    global _vpnbook_template_config_cache
    if _vpnbook_template_config_cache:
        return _vpnbook_template_config_cache
    urls = [u.strip() for u in re.split(r"[,，;；\s]+", VPNBOOK_TEMPLATE_OVPN_URLS or "") if u.strip()]
    for url in urls:
        try:
            text = http_get_bytes(url, timeout=20, accept="application/x-openvpn-profile,text/plain,*/*").decode("utf-8", errors="replace")
            if looks_like_openvpn_config(text):
                _vpnbook_template_config_cache = text
                log_to_json("INFO", "VPNBook", f"已加载 VPNBook 模板配置: {url}")
                return text
            log_to_json("WARNING", "VPNBook", f"VPNBook 模板不像有效 OpenVPN 配置: {url}")
        except Exception as exc:
            log_to_json("WARNING", "VPNBook", f"加载 VPNBook 模板失败 {url}: {exc}")
    return ""

def try_download_vpnbook_config(host: str, proto_key: str) -> str:
    short_host = host.split(".")[0].lower()
    proto, port, normalized_proto_key = vpnbook_protocol_parts(proto_key)
    filename = f"vpnbook-{short_host}-{normalized_proto_key}.ovpn"
    quoted_host = urllib.parse.quote(short_host)
    quoted_proto = urllib.parse.quote(normalized_proto_key)
    # VPNBook 现在的页面是“选择服务器 + 协议后下载”，页面结构会变化；
    # 这里先尝试多个常见官方下载路径，失败时再用公开模板配置替换 remote/proto。
    urls = [
        f"https://www.vpnbook.com/freevpn/openvpn/{filename}",
        f"https://www.vpnbook.com/freevpn/openvpn/download/{filename}",
        f"https://www.vpnbook.com/free-openvpn-account/{filename}",
        f"https://www.vpnbook.com/free-openvpn-account/{filename}?download=1",
        f"https://www.vpnbook.com/openvpn/{filename}",
        f"https://www.vpnbook.com/{filename}",
        f"https://www.vpnbook.com/freevpn/openvpn/download?server={quoted_host}&protocol={quoted_proto}",
        f"https://www.vpnbook.com/freevpn/openvpn/download?server={quoted_host}.vpnbook.com&protocol={quoted_proto}",
        f"https://www.vpnbook.com/api/openvpn/config?server={quoted_host}&protocol={quoted_proto}",
    ]
    for url in urls:
        try:
            data = http_get_bytes(url, timeout=20, accept="application/x-openvpn-profile,text/plain,application/octet-stream,*/*")
            text = data.decode("utf-8", errors="replace")
            if looks_like_openvpn_config(text):
                return normalize_vpnbook_config_text(text, host, proto, port)
            if text.strip().lower().startswith("<!doctype") or "<html" in text[:500].lower():
                continue
        except Exception:
            continue

    template = fetch_vpnbook_template_config()
    if template:
        log_to_json("WARNING", "VPNBook", f"官方配置下载失败，使用 VPNBook 模板生成配置: {host} {normalized_proto_key}")
        return normalize_vpnbook_config_text(template, host, proto, port)
    return ""

def vpnbook_row_to_node(server: dict[str, str], proto_name: str, config_text: str, auth_user: str, auth_pass: str) -> dict[str, Any]:
    host = server["host"]
    proto, port, proto_key = vpnbook_protocol_parts(proto_name)
    country_short = server.get("country_short") or "XX"
    country_long = server.get("country_long") or country_short
    country_short, country_zh = canonicalize_country_fields(country_short, country_long)
    # 确保 config 内写入当前选择的 remote/proto，并让 OpenVPN 使用统一认证文件。
    text = sanitize_openvpn_config_for_eianun(config_text)
    text = re.sub(r"(?m)^proto\s+\S+", f"proto {proto}", text)
    text = re.sub(r"(?m)^remote\s+\S+\s+\d+(?:\s+\S+)?", f"remote {host} {port}", text)
    if re.search(r"(?m)^auth-user-pass(?:\s+.+)?$", text):
        text = re.sub(r"(?m)^auth-user-pass(?:\s+.+)?$", "auth-user-pass", text)
    else:
        text = "auth-user-pass\n" + text
    remote_host, remote_port, parsed_proto = vpn_utils.parse_remote(text, host)
    node_id = safe_name("_".join(["VPNBOOK", country_short, host, str(remote_port or port), parsed_proto or proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    return {
        "id": node_id,
        "source": "vpnbook",
        "country": country_zh,
        "country_short": country_short,
        "host_name": host,
        "auth_user": auth_user or "vpnbook",
        "auth_pass": auth_pass,
        "ip": host,
        "score": 0,
        "ping": 0,
        "speed": 0,
        "sessions": 0,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": text,
        "proto": parsed_proto or proto,
        "remote_host": remote_host or host,
        "remote_port": remote_port or port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": f"VPNBook source; auth user {auth_user}; password auto-fetched" if auth_pass else "VPNBook source; password fetch failed",
        "probed_at": 0,
    }

def fetch_vpnbook_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    page = fetch_vpnbook_page()
    if not page:
        return candidates
    auth_user, auth_pass = extract_vpnbook_credentials(page)
    if not auth_pass:
        log_to_json("WARNING", "VPNBook", "未能从 VPNBook 页面解析到密码，VPNBook 节点可能无法通过认证")
    servers = parse_vpnbook_servers(page)
    protocols = [p for p in re.split(r"[,，;；\s]+", VPNBOOK_PROTOCOLS) if p.strip()] or ["tcp443"]
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    log_to_json("INFO", "VPNBook", f"解析到 VPNBook OpenVPN 服务器 {len(servers)} 个，地区过滤: {target_display}")
    for server in servers:
        pseudo_row = {"CountryShort": server.get("country_short", ""), "CountryLong": server.get("country_long", "")}
        if not row_matches_target_countries(pseudo_row, target_countries):
            continue
        for proto_name in protocols:
            proto, port, proto_key = vpnbook_protocol_parts(proto_name)
            key = f"vpnbook:{server['host']}:{proto_key}"
            if key in seen_keys:
                continue
            config_text = try_download_vpnbook_config(server["host"], proto_key)
            if not config_text:
                log_to_json("WARNING", "VPNBook", f"未能下载 VPNBook 配置: {server['host']} {proto_key}")
                continue
            node = vpnbook_row_to_node(server, proto_key, config_text, auth_user, auth_pass)
            candidates.append(node)
            seen_keys.add(key)
            if len(candidates) >= MAX_SCAN_ROWS:
                break
        if len(candidates) >= MAX_SCAN_ROWS:
            break
    log_to_json("INFO", "VPNBook", f"成功获取 VPNBook 候选节点 {len(candidates)} 个")
    return candidates


IPSPEED_COUNTRY_CODES: dict[str, str] = {
    "canada": "CA", "colombia": "CO", "indonesia": "ID", "japan": "JP", "peru": "PE",
    "romania": "RO", "russian federation": "RU", "russia": "RU", "south korea": "KR",
    "korea republic of": "KR", "usa": "US", "united states": "US", "vietnam": "VN",
    "viet nam": "VN", "thailand": "TH", "united kingdom": "GB", "uk": "GB",
    "germany": "DE", "france": "FR", "netherlands": "NL", "australia": "AU",
}

def ipspeed_country_code(country_name: str) -> str:
    name = re.sub(r"\s+", " ", str(country_name or "").strip())
    return canonical_country_code(name) or IPSPEED_COUNTRY_CODES.get(name.lower(), name[:2].upper() if name else "XX")

def parse_ipspeed_rows(page_text: str) -> list[dict[str, Any]]:
    """Parse IPSpeed free OpenVPN table rows.

    The page exposes downloadable /ovpn/<ip>.ovpn links and text columns:
    LOCATION, UPTIME, PING. We parse table rows first and fall back to a text regex.
    """
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_row(country: str, href: str, ip: str, uptime: Any = 0, ping: Any = 0) -> None:
        ip = str(ip or "").strip()
        if not ip or ip in seen:
            return
        seen.add(ip)
        country = re.sub(r"\s+", " ", str(country or "Unknown")).strip() or "Unknown"
        rows.append({
            "country_long": country,
            "country_short": ipspeed_country_code(country),
            "ip": ip,
            "url": urllib.parse.urljoin(IPSPEED_OPENVPN_URL, href),
            "uptime_days": parse_int(uptime),
            "ping": parse_int(ping),
        })

    for row_html in re.findall(r"<tr[^>]*>(.*?)</tr>", page_text, flags=re.I | re.S):
        if ".ovpn" not in row_html.lower():
            continue
        link = re.search(r"href=[\"'](?P<href>[^\"']+\.ovpn)[\"'][^>]*>\s*(?P<label>[^<]*?(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\.ovpn)", row_html, flags=re.I | re.S)
        if not link:
            continue
        href = link.group("href")
        ip = link.group("ip")
        text = re.sub(r"<[^>]+>", " ", row_html)
        text = re.sub(r"\s+", " ", text).strip()
        country = "Unknown"
        uptime = 0
        ping = 0
        m = re.search(r"^\s*\d+\s+(?P<country>.+?)\s+" + re.escape(ip) + r"\.ovpn\s+(?P<uptime>\d+)\s*day\(s\)\s+(?P<ping>\d+|-)\s*ms", text, flags=re.I)
        if m:
            country = m.group("country")
            uptime = m.group("uptime")
            ping = m.group("ping")
        else:
            # Best effort: first text cell after row number and before the ovpn filename.
            before = text.split(f"{ip}.ovpn", 1)[0]
            before = re.sub(r"^\s*\d+\s+", "", before).strip()
            if before:
                country = before
            tail = text.split(f"{ip}.ovpn", 1)[-1]
            m_tail = re.search(r"(?P<uptime>\d+)\s*day\(s\)\s+(?P<ping>\d+|-)\s*ms", tail, flags=re.I)
            if m_tail:
                uptime = m_tail.group("uptime")
                ping = m_tail.group("ping")
        add_row(country, href, ip, uptime, ping)

    if rows:
        return rows

    # Fallback for simplified/parsed HTML text.
    pattern = re.compile(
        r"(?P<country>[A-Za-z][A-Za-z\s]+?)\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\.ovpn\s+(?P<uptime>\d+)\s*day\(s\)\s*(?P<ping>\d+|-)?\s*ms",
        re.I,
    )
    for m in pattern.finditer(re.sub(r"<[^>]+>", " ", page_text)):
        ip = m.group("ip")
        add_row(m.group("country"), f"/ovpn/{ip}.ovpn", ip, m.group("uptime"), m.group("ping"))

    # Last fallback: extract links even if uptime/ping columns are not parseable.
    if not rows:
        for href, ip in re.findall(r"href=[\"']([^\"']*?(\d{1,3}(?:\.\d{1,3}){3})\.ovpn)[\"']", page_text, flags=re.I):
            add_row("Unknown", href, ip, 0, 0)
    return rows

def ipspeed_row_to_node(row: dict[str, Any], config_text: str) -> dict[str, Any]:
    ip = str(row.get("ip") or "")
    country_long = str(row.get("country_long") or "Unknown")
    country_short = str(row.get("country_short") or ipspeed_country_code(country_long) or "XX")
    country_short, country_zh = canonicalize_country_fields(country_short, country_long)
    text = sanitize_openvpn_config_for_eianun(config_text)
    remote_host, remote_port, proto = vpn_utils.parse_remote(text, ip)
    if not remote_host:
        remote_host = ip
    if not remote_port:
        remote_port = 443
    node_id = safe_name("_".join(["IPSPEED", country_short, ip or remote_host, str(remote_port), proto or "ovpn"]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    return {
        "id": node_id,
        "source": "ipspeed",
        "country": country_zh,
        "country_short": country_short,
        "host_name": ip,
        "auth_user": OPENVPN_AUTH_USER,
        "auth_pass": OPENVPN_AUTH_PASS,
        "ip": ip,
        "score": parse_int(row.get("uptime_days")),
        "ping": parse_int(row.get("ping")),
        "speed": 0,
        "sessions": 0,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "IPSpeed source; OpenVPN config fetched from ipspeed.info",
        "probed_at": 0,
    }

def fetch_ipspeed_candidates(target_countries: list[str], seen_keys: set[str]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    try:
        page_text = http_get_bytes(IPSPEED_OPENVPN_URL, timeout=18, accept="text/html,*/*").decode("utf-8", errors="replace")
        rows = parse_ipspeed_rows(page_text)
        matched = 0
        filtered = 0
        for row in rows:
            country_row = {"CountryShort": row.get("country_short", ""), "CountryLong": row.get("country_long", "")}
            if not row_matches_target_countries(country_row, target_countries):
                filtered += 1
                continue
            matched += 1
            if matched > MAX_SCAN_ROWS:
                break
            ip = str(row.get("ip") or "")
            key = f"ipspeed:{ip}"
            if not ip or key in seen_keys or ip in seen_keys:
                continue
            try:
                text = http_get_bytes(str(row.get("url")), timeout=18, accept="application/x-openvpn-profile,text/plain,*/*").decode("utf-8", errors="replace")
                if not looks_like_openvpn_config(text):
                    log_to_json("WARNING", "IPSpeed", f"下载到的配置不像 OpenVPN 文件: {row.get('url')}")
                    continue
                node = ipspeed_row_to_node(row, text)
                candidates.append(node)
                seen_keys.add(key)
            except Exception as exc:
                log_to_json("WARNING", "IPSpeed", f"下载 OpenVPN 配置失败 {ip}: {exc}")
        log_to_json("INFO", "IPSpeed", f"IPSpeed 地区过滤 {target_display}: 匹配 {matched} 行，跳过 {filtered} 行，成功 {len(candidates)} 个")
    except Exception as exc:
        log_to_json("ERROR", "IPSpeed", f"IPSpeed 节点拉取失败: {exc}")
    return candidates

def fetch_candidates(target_override: list[str] | None = None) -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    target_countries = target_override if target_override is not None else get_target_countries()
    target_display = normalize_target_countries_input(target_countries) or "全部地区"
    sources = get_node_sources()
    source_counts: dict[str, int] = {}
    for source in sources:
        before = len(candidates)
        try:
            if source == "vpngate":
                candidates.extend(fetch_vpngate_candidates(target_countries, seen_keys))
            elif source == "vpnbook":
                candidates.extend(fetch_vpnbook_candidates(target_countries, seen_keys))
            elif source == "ipspeed":
                candidates.extend(fetch_ipspeed_candidates(target_countries, seen_keys))
        except Exception as exc:
            log_to_json("ERROR", "Main", f"节点来源 {source} 拉取失败: {exc}")
        source_counts[source] = len(candidates) - before
    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok" if candidates else "empty",
        last_fetch_message=f"来源 {node_sources_display(','.join(sources))}，地区 {target_display}: fetched {len(candidates)} candidates. {source_counts}",
        blacklisted_nodes=len(blacklist),
        target_countries=normalize_target_countries_input(target_countries),
        target_countries_display=target_display,
        node_sources=normalize_node_sources_input(','.join(sources)),
        node_sources_display=node_sources_display(','.join(sources)),
    )
    log_to_json("INFO", "Main", f"成功获取候选节点 {len(candidates)} 个，来源 {source_counts}，地区 {target_display}")
    return candidates

def cached_nodes() -> list[dict[str, Any]]:
    return read_json(NODES_FILE, [])

_openvpn_version = None

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
        res = subprocess.run([cmd[0], "--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def auth_file_for_node(node: dict[str, Any] | None) -> Path:
    ensure_dirs()
    if not node:
        return AUTH_FILE
    user = str(node.get("auth_user") or OPENVPN_AUTH_USER or "vpn")
    pwd = str(node.get("auth_pass") or OPENVPN_AUTH_PASS or "vpn")
    node_id = safe_name(str(node.get("id") or node.get("remote_host") or "node"))
    path = CONFIG_DIR / f"{node_id}.auth"
    try:
        path.write_text(f"{user}\n{pwd}\n", encoding="utf-8")
        path.chmod(0o600)
    except Exception:
        return AUTH_FILE
    return path

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0", auth_file: str | Path | None = None) -> list[str]:
    command = shlex.split(OPENVPN_CMD, posix=False) or ["openvpn"]
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--pull-filter",
            "ignore",
            "redirect-gateway",
            "--pull-filter",
            "ignore",
            "route",
            "--pull-filter",
            "ignore",
            "dhcp-option",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(auth_file or AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
    except Exception:
        pass
        
    if route_nopull:
        # route-nopull 只阻止服务端 push 的路由；部分 VPNBook 配置文件自身包含
        # redirect-gateway/route，仍可能改默认路由导致 SSH 断连。route-noexec 会让
        # OpenVPN 不执行任何路由添加，后续统一由本程序的策略路由接管。
        command.extend(["--route-nopull", "--route-noexec"])
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        # Terminate existing openvpn processes managing tun0 or using our vpngate configuration
        subprocess.run(["pkill", "-f", "openvpn.*tun0"], capture_output=True, timeout=2)
        subprocess.run(["pkill", "-f", "openvpn.*vpngate_data"], capture_output=True, timeout=2)
        print("[Cleanup] Terminated existing Eianun免费聚合落地IP OpenVPN processes.", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0", auth_file: str | Path | None = None) -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev, auth_file=auth_file),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "openvpn command not found", None
    except OSError as exc:
        return False, f"openvpn start failed: {exc}", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            if not startup_done[0]:
                lines.put(line.rstrip())
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line.rstrip()}", flush=True)
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-8:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    if not ok and tail:
        message = tail[-1][-220:]
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[policy_routing] Failed to enable policy routing after 3 attempts", flush=True)

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    cleanup_policy_routing()
    config_to_delete = None
    if active_openvpn_node_id:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
        if node:
            config_to_delete = node.get("config_file")
            
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    kill_existing_openvpn_processes()
    
    if config_to_delete:
        try:
            path = Path(config_to_delete)
            if path.exists():
                path.unlink()
        except Exception:
            pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=node_sort_key
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "not_checked" and not n.get("active")],
        key=lambda n: (node_ip_priority_rank(n), -parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (node_ip_priority_rank(n), -parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

active_test_indexes = set()
test_indexes_lock = threading.Lock()
auto_test_background_lock = threading.Lock()
auto_test_background_running = False

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        return 99

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def safe_test_vpnbook_node_by_id(node_id: str, node: dict[str, Any]) -> dict[str, Any]:
    """Safe manual test for VPNBook nodes.

    VPNBook tests do not start OpenVPN by default because even a single handshake can run local
    routing directives from downloaded/template configs on some VPS images. This test verifies the
    server TCP port and performs IP risk enrichment, then lets manual switching do the real connect.
    """
    h = str(node.get("remote_host") or node.get("host_name") or node.get("ip") or "")
    p = parse_int(node.get("remote_port")) or 443
    fallback_ping = parse_int(node.get("ping"))
    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    risk_ip = resolve_ip_for_risk(h)
    ok = latency > 0
    temp_node = {
        "id": node_id,
        "ip": risk_ip,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
    }
    if risk_ip:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_json(NODES_FILE, [])
        current = next((item for item in nodes if item.get("id") == node_id), None)
        if current:
            current["ip"] = risk_ip or current.get("ip") or h
            current["latency_ms"] = latency
            current["probe_status"] = "available" if ok else "unavailable"
            current["probe_message"] = (
                "VPNBook 安全检测通过：TCP 端口可达，已跳过 OpenVPN 握手以避免 VPS 路由/SSH 卡死；点击切换才会真正尝试连接。"
                if ok else
                "VPNBook 安全检测失败：TCP 端口不可达或超时；未启动 OpenVPN 握手。"
            )
            current["probed_at"] = time.time()
            for key in [
                "owner", "asn", "as_name", "location", "ip_type", "quality", "fraud_score",
                "clean_score", "risk_level", "fraud_flags", "risk_sources", "blacklist_hits",
                "blacklist_count", "ip_clean",
            ]:
                current[key] = temp_node.get(key, current.get(key))
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            return next((item for item in sorted_nodes if item.get("id") == node_id), current)
    return {}

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        config_file = str(node["config_file"])
        config_text = node.get("config_text") or ""
        h = str(node.get("remote_host") or node.get("ip"))
        p = parse_int(node.get("remote_port"))
        fallback_ping = parse_int(node.get("ping"))
        node_source = str(node.get("source") or "").lower()

    if node_source == "vpnbook" and VPNBOOK_SAFE_TEST_ONLY:
        return safe_test_vpnbook_node_by_id(node_id, node)

    temp_path = Path(config_file)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(sanitize_openvpn_config_for_eianun(config_text), encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    
    idx = get_free_test_index()
    try:
        ok, message, _ = run_openvpn_until_ready(config_file, keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}", auth_file=auth_file_for_node(node))
    finally:
        release_test_index(idx)
    
    try:
        if temp_path.exists():
            temp_path.unlink()
    except Exception:
        pass

    risk_ip = resolve_ip_for_risk(h)
    temp_node = {
        "id": node_id,
        "ip": risk_ip,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "fraud_score": 0,
        "clean_score": 0,
        "risk_level": "unknown",
        "fraud_flags": [],
        "risk_sources": [],
        "blacklist_hits": [],
        "blacklist_count": 0,
        "ip_clean": False,
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]
                for risk_key in ["fraud_score", "clean_score", "risk_level", "fraud_flags", "risk_sources", "blacklist_hits", "blacklist_count", "ip_clean"]:
                    node[risk_key] = temp_node.get(risk_key, [] if risk_key.endswith("hits") or risk_key.endswith("flags") or risk_key.endswith("sources") else False if risk_key == "ip_clean" else 0)
            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def update_node_result_in_store(result: dict[str, Any]) -> tuple[int, int]:
    """Write one tested node result immediately so UI progress and auto selection can see it."""
    with lock:
        current_nodes = read_json(NODES_FILE, [])
        rid = result.get("id")
        for n in current_nodes:
            if n.get("id") == rid:
                n.update(result)
                break
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        available_count = len([n for n in sorted_nodes if n.get("probe_status") == "available"])
        unavailable_count = len([n for n in sorted_nodes if n.get("probe_status") == "unavailable"])
    return available_count, unavailable_count


def test_multiple_nodes(node_ids: list[str], progress_prefix: str = "正在自动检测节点") -> list[dict[str, Any]]:
    with lock:
        nodes = read_json(NODES_FILE, [])
        requested = set(node_ids)
        to_test = [n for n in nodes if n.get("id") in requested]

    if not to_test:
        return []

    total = len(to_test)
    worker_count = min(AUTO_TEST_WORKERS, total)
    set_state(
        last_check_message=f"{progress_prefix} 0/{total}，并发 {worker_count}，请稍候...",
        auto_test_total=total,
        auto_test_done=0,
        auto_test_workers=worker_count,
    )
        
    def test_worker(n_info: dict[str, Any]) -> dict[str, Any]:
        node_id = n_info["id"]
        config_file = n_info["config_file"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))
        
        temp_path = Path(config_file)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception:
            pass
            
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        idx = get_free_test_index()
        try:
            ok, message, _ = run_openvpn_until_ready(
                config_file,
                keep_alive=False,
                route_nopull=True,
                timeout=OPENVPN_BATCH_TEST_TIMEOUT_SECONDS,
                dev=f"tun{idx}",
                auth_file=auth_file_for_node(n_info),
            )
        finally:
            release_test_index(idx)
        
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass
            
        temp_node = {
            "id": node_id,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
            "fraud_score": 0,
            "clean_score": 0,
            "risk_level": "unknown",
            "fraud_flags": [],
            "risk_sources": [],
            "blacklist_hits": [],
            "blacklist_count": 0,
            "ip_clean": False,
        }
        if ok:
            ip_to_enrich = {
                "ip": resolve_ip_for_risk(h),
                "remote_host": h,
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
                "fraud_score": 0,
                "clean_score": 0,
                "risk_level": "unknown",
                "fraud_flags": [],
                "risk_sources": [],
                "blacklist_hits": [],
                "blacklist_count": 0,
                "ip_clean": False,
            }
            vpn_utils.enrich_ip_info([ip_to_enrich])
            temp_node.update(ip_to_enrich)
        return temp_node

    updated_nodes_map = {}
    completed = 0
    available_count = 0
    unavailable_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = {executor.submit(test_worker, n): n["id"] for n in to_test}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                res = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0,
                    "probed_at": time.time(),
                    "fraud_score": 0,
                    "clean_score": 0,
                    "risk_level": "unknown",
                    "fraud_flags": [],
                    "risk_sources": [],
                    "blacklist_hits": [],
                    "blacklist_count": 0,
                    "ip_clean": False,
                }
                updated_nodes_map[nid] = res
            completed += 1
            # 逐个节点写入，避免面板长时间显示全部未检/0 进度。
            available_count, unavailable_count = update_node_result_in_store(res)
            set_state(
                last_check_message=f"{progress_prefix} {completed}/{total}，可用 {available_count} 个，不可用 {unavailable_count} 个...",
                auto_test_total=total,
                auto_test_done=completed,
                auto_test_workers=worker_count,
            )

    set_state(
        last_check_message=f"{progress_prefix}完成：共检测 {total} 个，可用 {available_count} 个，不可用 {unavailable_count} 个。",
        auto_test_total=total,
        auto_test_done=total,
        auto_test_workers=worker_count,
    )
    return list(updated_nodes_map.values())


def run_remaining_tests_background(node_ids: list[str]) -> None:
    global auto_test_background_running, is_connecting
    if not node_ids:
        return
    with auto_test_background_lock:
        if auto_test_background_running:
            return
        auto_test_background_running = True

    def worker() -> None:
        global auto_test_background_running, is_connecting
        try:
            set_state(
                last_check_message=f"首批节点检测完成，正在后台继续检测剩余 {len(node_ids)} 个节点...",
                background_auto_test_total=len(node_ids),
                background_auto_test_done=0,
            )
            test_multiple_nodes(node_ids, progress_prefix="正在后台检测剩余节点")
            set_state(last_check_message="后台节点检测完成，已更新节点质量；当前连接正常时不会主动断开重连。")
            # 后台检测完成后，如果还没有活动连接则立即故障转移；已有连接则按开关决定是否主动优选。
            try:
                is_connecting = False
                if not active_openvpn_running():
                    auto_switch_node()
                elif get_auto_select_best_node():
                    optimize_active_node_after_tests("background_batch_finished")
            except Exception as e:
                set_state(last_check_message=f"后台优选节点失败: {e}")
        finally:
            with auto_test_background_lock:
                auto_test_background_running = False

    threading.Thread(target=worker, daemon=True).start()


def run_vpnbook_safe_tests_background(node_ids: list[str]) -> None:
    """Safely classify VPNBook nodes without starting OpenVPN.

    VPNBook nodes are intentionally excluded from automatic OpenVPN batch tests because some
    downloaded/template configs can destabilize VPS routing. This background pass only performs
    TCP reachability and IP risk enrichment, so the panel no longer keeps VPNBook rows stuck at
    "未检" after 更新节点.
    """
    node_ids = [str(x) for x in node_ids if x]
    if not node_ids:
        return

    def worker() -> None:
        total = len(node_ids)
        done = 0
        set_state(
            last_check_message=f"正在后台安全检测 VPNBook 节点 0/{total}：仅检测 TCP 可达和 IP 风控，不会断开当前连接...",
            vpnbook_safe_test_total=total,
            vpnbook_safe_test_done=0,
        )
        for node_id in node_ids:
            try:
                with lock:
                    nodes = read_json(NODES_FILE, [])
                    node = next((item for item in nodes if item.get("id") == node_id), None)
                if node and str(node.get("source") or "").lower() == "vpnbook":
                    safe_test_vpnbook_node_by_id(node_id, node)
            except Exception as exc:
                with lock:
                    nodes = read_json(NODES_FILE, [])
                    for item in nodes:
                        if item.get("id") == node_id:
                            item["probe_status"] = "unavailable"
                            item["probe_message"] = f"VPNBook 安全检测异常：{exc}"
                            item["probed_at"] = time.time()
                            break
                    write_json(NODES_FILE, sort_all_nodes(nodes))
            done += 1
            set_state(
                last_check_message=f"正在后台安全检测 VPNBook 节点 {done}/{total}：仅检测 TCP 可达和 IP 风控，不会断开当前连接...",
                vpnbook_safe_test_total=total,
                vpnbook_safe_test_done=done,
            )
        set_state(last_check_message=f"VPNBook 安全检测完成：已更新 {total} 个节点状态；当前连接保持不变。")

    threading.Thread(target=worker, daemon=True).start()

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        set_state(last_check_message="自动切换连续失败，将等待下一轮节点维护")
        return
    if is_connecting:
        set_state(last_check_message="当前正在建立连接，暂不触发新的自动切换")
        return
    state = read_json(STATE_FILE, {})
    now = time.time()
    last_attempt = float(state.get("last_auto_switch_attempt_at") or 0)
    if active_openvpn_running() and last_attempt and now - last_attempt < AUTO_SWITCH_RETRY_COOLDOWN_SECONDS:
        left = int(AUTO_SWITCH_RETRY_COOLDOWN_SECONDS - (now - last_attempt))
        set_state(last_check_message=f"自动切换冷却中，当前连接暂保留，约 {left} 秒后再评估")
        return
    set_state(last_auto_switch_attempt_at=now)
        
    with lock:
        nodes = read_json(NODES_FILE, [])
        active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id or n.get("active")), None)
        failover_targets = get_failover_targets(active_node)
        all_candidates = [
            n for n in nodes 
            if n.get("probe_status") == "available" 
            and not n.get("active")
        ]
        scoped_candidates = [n for n in all_candidates if node_matches_target_countries(n, failover_targets)] if failover_targets else all_candidates
        candidates, candidate_reason = choose_auto_failover_candidates(scoped_candidates, all_candidates)
        scope_display = normalize_target_countries_input(failover_targets) if failover_targets else "全部地区"
        ip_type_scope_display = target_ip_types_display(get_target_ip_types())

    # auto_switch_node 只负责“当前出口真的坏了”的保活切换。
    # 如果当前 OpenVPN 仍在运行且代理失败次数未达到阈值，就保持当前节点，
    # 防止定时拉取/瞬时探测失败把用户手动选中的住宅 IP 切成代理 IP。
    if active_openvpn_running() and active_connection_looks_healthy(active_node):
        msg = f"当前节点仍在健康保护状态，暂不自动切换；固定地区 {scope_display} / IP 类型 {ip_type_scope_display} 的备用节点仅作为候选保留。"
        set_state(last_check_message=msg)
        return
        
    if candidates:
        next_node = candidates[0]
        clean_ok = node_is_clean_for_connect(next_node)
        ip_kind = f"干净度 {next_node.get('clean_score', 0)} / 欺诈值 {next_node.get('fraud_score', 0)} / 黑名单 {next_node.get('blacklist_count', 0)}"
        msg = f"当前连接已失效或代理连通性检测失败，正在按固定地区 {scope_display} / IP 类型 {ip_type_scope_display} 自动切换: {next_node['id']} ({ip_kind})；策略: {candidate_reason}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"], update_failover_scope=False, allow_auto_risky=not clean_ok)
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1)
    else:
        # 没有备用节点时不要直接清理当前连接。免费节点池波动大，
        # 直接 stop 会造成“连接成功 -> 没备用 -> 立即断开 -> 反复重连”。
        if active_openvpn_running() and active_node:
            if failover_targets:
                msg = f"固定地区 {scope_display} / IP 类型 {ip_type_scope_display} 当前没有可用备用节点，已保留当前连接，后台继续拉取同地区新节点..."
            else:
                msg = "当前没有可用备用节点，已保留当前连接，后台继续补充节点池..."
            print(f"[自动切换] {msg}", flush=True)
            log_to_json("WARNING", "VPN", msg)
            set_state(last_check_message=msg)
        else:
            if failover_targets:
                msg = f"固定地区 {scope_display} / IP 类型 {ip_type_scope_display} 当前没有可用备用节点，后台拉取同地区新节点..."
            else:
                msg = "没有可用的备选节点，将在后台异步获取新节点..."
            print(f"[自动切换] {msg}", flush=True)
            log_to_json("WARNING", "VPN", msg)
            with lock:
                nodes = read_json(NODES_FILE, [])
                for item in nodes:
                    item["active"] = False
                write_json(NODES_FILE, nodes)
            set_state(active_openvpn_node_id="", last_check_message=msg)
        
        def bg_fetch_and_switch():
            try:
                maintain_valid_nodes(force=False, target_override=failover_targets if failover_targets else None)
                auto_switch_node()
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)
        
        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def connect_node(node_id: str, update_failover_scope: bool = True, allow_manual_risky: bool = False, allow_auto_risky: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            return "Already connecting"
        is_connecting = True
        active_openvpn_node_id = node_id
        set_state(active_openvpn_node_id=node_id, is_connecting=True, active_node_latency="正在连接", last_check_message="正在初始化连接配置...")
        
    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")
        nodes = read_json(NODES_FILE, [])
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
        if not node_is_clean_for_connect(node):
            reason = f"该节点未通过干净 IP 优选阈值：欺诈值 {node.get('fraud_score', '未知')}，黑名单命中 {node.get('blacklist_count', 0)}，风险等级 {node.get('risk_level', 'unknown')}。"
            if not (allow_auto_risky or (ALLOW_MANUAL_RISKY_CONNECT and allow_manual_risky)):
                set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="已阻止", last_check_message=reason + " 如需手动强制切换可设置 ALLOW_MANUAL_RISKY_CONNECT=1。")
                with lock:
                    active_openvpn_node_id = ""
                raise RuntimeError(reason + " 自动默认会优先选干净 IP；手动切换可在面板确认后强制尝试。")
            if allow_auto_risky:
                warn_msg = reason + " 自动故障转移进入保活兜底模式：没有更干净的可用节点，先连接综合风险最低的可用节点，后续维护线程会继续寻找更干净节点。"
                print(f"[Auto Risk Fallback] {warn_msg}", flush=True)
            else:
                warn_msg = reason + " 已按手动确认继续尝试连接，自动故障转移会优先选择低风险干净 IP。"
                print(f"[Manual Override] {warn_msg}", flush=True)
            log_to_json("WARNING", "VPN", warn_msg)
            set_state(last_check_message=warn_msg)
        
        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(sanitize_openvpn_config_for_eianun(node.get("config_text") or ""), encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        connect_timeout = VPNBOOK_CONNECT_TIMEOUT_SECONDS if str(node.get("source") or "").lower() == "vpnbook" else None
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True, timeout=connect_timeout, auth_file=auth_file_for_node(node))
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        active_openvpn_process = process
        active_openvpn_node_id = node_id
        if update_failover_scope:
            set_failover_scope_from_node(node)
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")
        set_state(active_connected_at=time.time(), proxy_fail_count=0, proxy_error="", last_auto_switch_attempt_at=0)
        
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
            
        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                item["probe_message"] = f"Active node. HTTP proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error=""
            )
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )
            
        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    finally:
        with lock:
            is_connecting = False

def maintain_valid_nodes(force: bool = False, target_override: list[str] | None = None) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    is_connecting = True
    try:
        if force:
            with lock:
                stop_active_openvpn()
        elif not active_openvpn_running():
            has_active_id = False
            with lock:
                if active_openvpn_node_id:
                    has_active_id = True
                    stop_active_openvpn()
            if has_active_id:
                print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                is_connecting = False
                auto_switch_node()
                is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates(target_override=target_override)
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=str(exc))
            candidates = []

        if not candidates:
            is_connecting = False
            return "没有拉取到新节点"

        with lock:
            active_node = None
            if active_openvpn_node_id:
                current_nodes = read_json(NODES_FILE, [])
                active_node = next((n for n in current_nodes if n.get("id") == active_openvpn_node_id), None)
                
            merged: list[dict[str, Any]] = []
            seen_ids: set[str] = set()
            
            if active_node:
                merged.append(active_node)
                seen_ids.add(active_node["id"])
                
            for cand in candidates:
                if cand["id"] not in seen_ids:
                    merged.append(cand)
                    seen_ids.add(cand["id"])
                    
            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)

        # 自动检测节点：VPNGate 可批量检测；VPNBook 默认不参与启动/后台批量 OpenVPN 检测。
        # 原因：部分 VPNBook 节点会在握手/推送路由阶段导致低配 VPS 网络栈或 SSH 卡死。
        # 混合来源时，VPNBook 只进入节点池供手动单个检测/强制切换；如果用户只选择 VPNBook，则只安全检测 1 个节点。
        with lock:
            current_nodes = read_json(NODES_FILE, [])
            raw_test_candidates = [n for n in current_nodes if not n.get("active")]
            selected_sources = get_node_sources()
            vpnbook_only = selected_sources == ["vpnbook"]
            skipped_vpnbook_auto = 0
            safe_vpnbook_ids: list[str] = []
            if VPNBOOK_AUTO_TEST:
                test_candidates = raw_test_candidates
            elif vpnbook_only:
                vpnbook_candidates = [n for n in raw_test_candidates if n.get("source") == "vpnbook"]
                test_candidates = vpnbook_candidates[:VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT]
                safe_vpnbook_ids = [n["id"] for n in vpnbook_candidates[VPNBOOK_ONLY_SAFE_AUTO_TEST_LIMIT:]]
                skipped_vpnbook_auto = max(0, len(vpnbook_candidates) - len(test_candidates))
            else:
                test_candidates = [n for n in raw_test_candidates if n.get("source") != "vpnbook"]
                vpnbook_candidates = [n for n in raw_test_candidates if n.get("source") == "vpnbook"]
                safe_vpnbook_ids = [n["id"] for n in vpnbook_candidates]
                skipped_vpnbook_auto = len(vpnbook_candidates)

            if AUTO_TEST_ALL_NODES:
                to_test = test_candidates
                if AUTO_TEST_MAX_NODES > 0:
                    to_test = to_test[:AUTO_TEST_MAX_NODES]
            else:
                to_test = test_candidates[:10]
            total_candidates = len(raw_test_candidates)
            no_active_for_initial_quality = not active_openvpn_running()
            if AUTO_TEST_ALL_NODES and INITIAL_QUALITY_SCAN_BEFORE_CONNECT and no_active_for_initial_quality:
                if INITIAL_QUALITY_SCAN_MAX_NODES <= 0:
                    sync_count = len(to_test)
                else:
                    sync_count = min(len(to_test), max(AUTO_TEST_INITIAL_BATCH, INITIAL_QUALITY_SCAN_MAX_NODES))
            else:
                sync_count = min(len(to_test), AUTO_TEST_INITIAL_BATCH if AUTO_TEST_ALL_NODES else len(to_test))
            sync_test = to_test[:sync_count]
            rest_test = to_test[sync_count:]
            sync_test_ids = [n["id"] for n in sync_test]
            rest_test_ids = [n["id"] for n in rest_test]
            to_test_ids = sync_test_ids + rest_test_ids

        vpnbook_skip_note = f"，VPNBook {skipped_vpnbook_auto} 个转安全检测" if skipped_vpnbook_auto else ""
        initial_scan_note = "；首次连接前质量扫描" if (not active_openvpn_running() and INITIAL_QUALITY_SCAN_BEFORE_CONNECT and sync_test_ids) else ""
        print(f"[维护线程] 首批检测节点: {len(sync_test_ids)}/{len(to_test_ids)}，剩余 {len(rest_test_ids)} 个转后台{vpnbook_skip_note}{initial_scan_note}，并发 {min(AUTO_TEST_WORKERS, max(1, len(sync_test_ids)))}", flush=True)
        set_state(
            is_connecting=True,
            last_check_message=f"正在检测首批节点 0/{len(sync_test_ids)}，剩余 {len(rest_test_ids)} 个将后台检测{vpnbook_skip_note}{initial_scan_note}...",
            auto_test_total=len(sync_test_ids),
            auto_test_done=0,
            auto_test_workers=min(AUTO_TEST_WORKERS, max(1, len(sync_test_ids))) if sync_test_ids else 0,
            vpnbook_auto_skipped=skipped_vpnbook_auto,
            vpnbook_safe_test_total=len(safe_vpnbook_ids),
            vpnbook_safe_test_done=0,
        )
        if sync_test_ids:
            test_multiple_nodes(sync_test_ids, progress_prefix="正在检测首批节点")
        elif skipped_vpnbook_auto:
            set_state(last_check_message=f"VPNBook 节点已加入节点池，正在后台做安全检测：只测 TCP 可达和 IP 风控，不会启动 OpenVPN。")

        if safe_vpnbook_ids:
            run_vpnbook_safe_tests_background(safe_vpnbook_ids)
        
        is_connecting = False
        
        with lock:
            merged = read_json(NODES_FILE, [])
            available_candidates = [n for n in merged if n.get("probe_status") == "available"]

        if available_candidates:
            if not active_openvpn_running():
                auto_switch_node()
            elif get_auto_select_best_node():
                # 首批检测后，如果已有明显更优节点，也可以先优化一次。
                optimize_active_node_after_tests("initial_batch_finished")

        if rest_test_ids:
            run_remaining_tests_background(rest_test_ids)

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} of {total_candidates} nodes. Auto select: {'on' if get_auto_select_best_node() else 'off'}."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        is_connecting = False
        raise e


def collector_loop() -> None:
    while True:
        success = False
        try:
            res = maintain_valid_nodes(force=False)
            if "没有拉取到新节点" not in res:
                success = True
        except Exception as exc:
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Eianun免费聚合落地IP - 安全登录</title>
  <link rel="icon" type="image/png" href="data:image/png;base64,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K2ecdeRnv/71utdffz2F+qR96/R5X5s+Gq9lB/QgjFeQhrPdQuY96QfHd4l2bLtHdUkfTYHrbr112sc/c8pnttph1yt33efAP+2274HX7b7PAX/ZY78D/vKe/Q64bvf9DvjLbvsf+Nf37H/gdTvsvufPvvb1sw/DgLFWA+Ca2g/95k833LDJYcee8NFNt5n1w1332f/2g4465qV/PfTEsgefeOK5Rx594vpHnnjq5488/u9vwD3t0SeeOhVy+kOPPf71R5584oJHn/rPH275xx1PfOvbl67Y+8Ajnt9xt72v3Xbn3c74znd+MGtNda9t+nW33dbwic9+/nPb7rL75dvs8O6f7Ljrey7fdrudL3/3Hntfvv2ue12+5S7vuXzWrnv/eLd93/vTnd69+0+32Wa7C6699tq911Tvww8/nP7S175+2E7v2ed7s9691x0f+NhnFj7w5GOv3P/QI9c//PjjP33qv89d9OR/np1z/yOPX/zAw4/9/rEnn33lC6d/eskOe+4/d6e9D/jtF884+5N33HHH+muqZ7Dpb7311oy9Dzrk07vsve83t9xpl3M23X6HczZvl60R3n7X3c/Zepddztlml13mbLnDTud854c/nD3YuvpT7qFnnpmy2177n7zje/b6xazd9756p732uxr+q3bde7+r8VxftfOe+1y13S67XbXNu3f/3Z4HHPiLQ2af8OnXFi2a2h/d5Xkee+yxSbvtc+AZO79nvyt32mvvq3fZc5+rd91j76tFfyx77XPVjnvt87ud9tznt9vusuuvttpx53Ov+etfNyvX0ZN/7ty51b/89e+O3nSrbS7cY98D7v3kYbPnP/TgE2899NiTtz7y2L9/+OgT/z4PctZjTz4159Enn/rBo//+z9+f/8/c5R/93Jde23rH3W46/LgTzr72xht3w7vk96Rf40YeASX0ke+DbhY4hB3W5w5u+4eL2+7toVHt4GUPrvjxFec8+PCDP5m5/gafSKdSx6dT6WNTmdQxiVTqmGQqdWwqlTomncrMTqZTx9bX13/277fc8pvzLrroBJQd0udR9C1evLj65jvu2OhDH/vURd869/wb589fdAXs+koimT4gX4g2SKQDP1WVpEx1FVVVVVE6nSbYRekM4qpSVF2ToWQySXUT6mnq9GlUU1frJ9L+Rpnq9Am1dbUX/e6aP/z14COO+vYD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">
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #060b12;
      --bg-surface: rgba(13, 20, 32, 0.72);
      --border-color: rgba(136, 171, 206, 0.16);
      --text-primary: #f3f8fe;
      --text-secondary: #9fb0c4;
      --primary: #84bff1;
      --primary-gradient: linear-gradient(135deg, #9ed1fb 0%, #78b6eb 100%);
      --primary-hover: linear-gradient(135deg, #8fc8f6 0%, #5f99c7 100%);
      --success: #49c6a1;
      --danger: #ef6a7b;
      --accent: #f0c255;
    }

    body {
      margin: 0;
      padding: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(132, 191, 241, 0.18) 0px, transparent 46%),
        radial-gradient(at 100% 0%, rgba(240, 194, 85, 0.09) 0px, transparent 44%),
        radial-gradient(at 50% 100%, rgba(73, 198, 161, 0.05) 0px, transparent 50%);
      height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      overflow: hidden;
    }

    .login-container {
      width: 100%;
      max-width: 400px;
      padding: 24px;
      box-sizing: border-box;
    }

    .login-card {
      background: var(--bg-surface);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      padding: 40px 32px;
      box-shadow: 0 28px 70px rgba(0, 0, 0, 0.42), inset 0 1px 0 rgba(255,255,255,0.04);
      text-align: center;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .brand-logo {
      width: 104px;
      height: 104px;
      background: linear-gradient(180deg, rgba(158, 209, 251, 0.16), rgba(120, 182, 235, 0.08));
      border: 1px solid rgba(132, 191, 241, 0.24);
      border-radius: 28px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 22px auto;
      color: var(--primary);
      position: relative;
      box-shadow: 0 20px 50px rgba(4, 12, 20, 0.35), inset 0 1px 0 rgba(255,255,255,0.05);
    }

    .brand-logo-img {
      width: 76px;
      height: 76px;
      object-fit: contain;
      position: relative;
      z-index: 1;
      filter: drop-shadow(0 10px 24px rgba(132, 191, 241, 0.18));
    }

    .brand-chip {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      margin: 0 auto 14px auto;
      padding: 7px 12px;
      border-radius: 999px;
      border: 1px solid rgba(132, 191, 241, 0.14);
      background: rgba(255,255,255,0.03);
      color: var(--text-secondary);
      font-size: 12px;
      letter-spacing: 0.4px;
    }

    .brand-logo::after {
      content: '';
      position: absolute;
      width: 100%;
      height: 100%;
      border-radius: 16px;
      border: 1px solid rgba(240, 194, 85, 0.9);
      opacity: 0.5;
      animation: ripple 2s infinite ease-out;
    }

    @keyframes ripple {
      0% { transform: scale(1); opacity: 0.5; }
      100% { transform: scale(1.3); opacity: 0; }
    }

    .login-title {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
      text-shadow: 0 6px 20px rgba(132, 191, 241, 0.18);
      margin: 0 0 8px 0;
      letter-spacing: 0.5px;
    }

    .login-subtitle {
      font-size: 14px;
      color: var(--text-secondary);
      margin: 0 0 32px 0;
    }

    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }

    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }

    .input-wrapper {
      position: relative;
    }

    .input-field {
      width: 100%;
      height: 48px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      padding: 0 16px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 15px;
      outline: none;
      transition: all 0.2s ease;
    }

    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(132, 191, 241, 0.18);
      background: rgba(10, 18, 30, 0.68);
    }

    .error-message {
      color: var(--danger);
      font-size: 13px;
      margin-top: 8px;
      min-height: 18px;
      text-align: left;
      margin-left: 4px;
      display: none;
    }

    .login-btn {
      width: 100%;
      height: 48px;
      background: var(--primary-gradient);
      border: none;
      border-radius: 10px;
      color: white;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(132, 191, 241, 0.24);
    }

    .login-btn:hover {
      background: var(--primary-hover);
      transform: translateY(-1px);
      box-shadow: 0 6px 16px rgba(132, 191, 241, 0.34);
    }

    .login-btn:active {
      transform: translateY(1px);
    }

    .login-btn:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none !important;
    }


    .login-progress {
      display: none;
      margin-top: 16px;
      text-align: left;
    }

    .login-progress-text {
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .login-progress-track {
      height: 8px;
      border-radius: 999px;
      overflow: hidden;
      background: rgba(152, 186, 220, 0.08);
      border: 1px solid rgba(152, 186, 220, 0.10);
    }

    .login-progress-bar {
      width: 0%;
      height: 100%;
      border-radius: 999px;
      background: var(--primary-gradient);
      transition: width 0.35s ease;
    }

    @media (max-width: 640px) {
      .brand-head {
        gap: 10px;
      }
      .brand-mark {
        width: 40px;
        height: 40px;
        border-radius: 14px;
      }
      .brand-mark img {
        width: 28px;
        height: 28px;
      }
      .brand-kicker {
        font-size: 10px;
      }
      h1 {
        font-size: 17px;
      }
      .brand-logo {
        width: 88px;
        height: 88px;
      }
      .brand-logo-img {
        width: 64px;
        height: 64px;
      }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="brand-logo">
        <img src="data:image/png;base64,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K2ecdeRnv/71utdffz2F+qR96/R5X5s+Gq9lB/QgjFeQhrPdQuY96QfHd4l2bLtHdUkfTYHrbr112sc/c8pnttph1yt33efAP+2274HX7b7PAX/ZY78D/vKe/Q64bvf9DvjLbvsf+Nf37H/gdTvsvufPvvb1sw/DgLFWA+Ca2g/95k833LDJYcee8NFNt5n1w1332f/2g4465qV/PfTEsgefeOK5Rx594vpHnnjq5488/u9vwD3t0SeeOhVy+kOPPf71R5584oJHn/rPH275xx1PfOvbl67Y+8Ajnt9xt72v3Xbn3c74znd+MGtNda9t+nW33dbwic9+/nPb7rL75dvs8O6f7Ljrey7fdrudL3/3Hntfvv2ue12+5S7vuXzWrnv/eLd93/vTnd69+0+32Wa7C6699tq911Tvww8/nP7S175+2E7v2ed7s9691x0f+NhnFj7w5GOv3P/QI9c//PjjP33qv89d9OR/np1z/yOPX/zAw4/9/rEnn33lC6d/eskOe+4/d6e9D/jtF884+5N33HHH+muqZ7Dpb7311oy9Dzrk07vsve83t9xpl3M23X6HczZvl60R3n7X3c/Zepddztlml13mbLnDTud854c/nD3YuvpT7qFnnpmy2177n7zje/b6xazd9756p732uxr+q3bde7+r8VxftfOe+1y13S67XbXNu3f/3Z4HHPiLQ2af8OnXFi2a2h/d5Xkee+yxSbvtc+AZO79nvyt32mvvq3fZc5+rd91j76tFfyx77XPVjnvt87ud9tznt9vusuuvttpx53Ov+etfNyvX0ZN/7ty51b/89e+O3nSrbS7cY98D7v3kYbPnP/TgE2899NiTtz7y2L9/+OgT/z4PctZjTz4159Enn/rBo//+z9+f/8/c5R/93Jde23rH3W46/LgTzr72xht3w7vk96Rf40YeASX0ke+DbhY4hB3W5w5u+4eL2+7toVHt4GUPrvjxFec8+PCDP5m5/gafSKdSx6dT6WNTmdQxiVTqmGQqdWwqlTomncrMTqZTx9bX13/277fc8pvzLrroBJQd0udR9C1evLj65jvu2OhDH/vURd869/wb589fdAXs+koimT4gX4g2SKQDP1WVpEx1FVVVVVE6nSbYRekM4qpSVF2ToWQySXUT6mnq9GlUU1frJ9L+Rpnq9Am1dbUX/e6aP/z14COO+vYD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" alt="Eianun Logo" class="brand-logo-img">
      </div>
      <div class="brand-chip">Eianun Brand Panel</div>
      <h2 class="login-title">Eianun免费聚合落地IP</h2>
      <p class="login-subtitle">请输入您的管理账号和安全密码以继续</p>
      
      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label" for="username">管理账号</label>
          <div class="input-wrapper">
            <input type="text" id="username" class="input-field" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label class="form-label" for="password">安全密码</label>
          <div class="input-wrapper">
            <input type="password" id="password" class="input-field" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        
        <button type="submit" id="submit_btn" class="login-btn">
          <span>登录</span>
        </button>

        <div id="login_progress" class="login-progress">
          <div class="login-progress-text">
            <span id="login_progress_text">正在准备登录...</span>
            <span id="login_progress_percent">0%</span>
          </div>
          <div class="login-progress-track"><div id="login_progress_bar" class="login-progress-bar"></div></div>
        </div>
      </form>
    </div>
  </div>

  <script>
    function setLoginProgress(text, percent) {
      const box = document.getElementById("login_progress");
      const textEl = document.getElementById("login_progress_text");
      const percentEl = document.getElementById("login_progress_percent");
      const bar = document.getElementById("login_progress_bar");
      box.style.display = "block";
      textEl.textContent = text;
      percentEl.textContent = `${percent}%`;
      bar.style.width = `${percent}%`;
    }

    function resetLoginButton() {
      const submitBtn = document.getElementById("submit_btn");
      submitBtn.disabled = false;
      submitBtn.querySelector("span").textContent = "登录";
    }

    async function handleLogin(e) {
      e.preventDefault();
      const uname = document.getElementById("username").value;
      const pwd = document.getElementById("password").value;
      const errorText = document.getElementById("error_text");
      const submitBtn = document.getElementById("submit_btn");
      
      errorText.style.display = "none";
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证";
      setLoginProgress("1/3 正在验证账号密码...", 28);
      
      try {
        const response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd }),
          cache: "no-store"
        });
        setLoginProgress("2/3 正在建立管理会话...", 58);
        
        let data;
        try {
          data = await Promise.race([
            response.json(),
            new Promise((_, reject) => setTimeout(() => reject(new Error("login response parse timeout")), 3000))
          ]);
        } catch (parseErr) {
          if (response.ok) {
            // 兼容少数环境下登录响应正文被代理/浏览器卡住的情况：
            // 只要 HTTP 状态已经成功，Cookie 已经写入，就直接进入面板。
            data = { ok: true };
          } else {
            throw parseErr;
          }
        }
        if (response.ok && data.ok) {
          submitBtn.querySelector("span").textContent = "验证成功";
          setLoginProgress("3/3 登录成功，正在加载面板与节点状态...", 86);
          setTimeout(() => {
            setLoginProgress("正在进入控制面板，请稍候...", 100);
          }, 250);
          setTimeout(() => {
            window.location.replace(window.location.href.split("#")[0]);
          }, 650);
        } else {
          setLoginProgress("验证失败，请检查账号密码", 100);
          errorText.textContent = data.error || "账号或密码不正确，请重新输入";
          errorText.style.display = "block";
          resetLoginButton();
        }
      } catch (err) {
        setLoginProgress("连接服务器失败，请稍后重试", 100);
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.style.display = "block";
        resetLoginButton();
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Eianun免费聚合落地IP 节点池管理系统</title>
  <link rel="icon" type="image/png" href="data:image/png;base64,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K2ecdeRnv/71utdffz2F+qR96/R5X5s+Gq9lB/QgjFeQhrPdQuY96QfHd4l2bLtHdUkfTYHrbr112sc/c8pnttph1yt33efAP+2274HX7b7PAX/ZY78D/vKe/Q64bvf9DvjLbvsf+Nf37H/gdTvsvufPvvb1sw/DgLFWA+Ca2g/95k833LDJYcee8NFNt5n1w1332f/2g4465qV/PfTEsgefeOK5Rx594vpHnnjq5488/u9vwD3t0SeeOhVy+kOPPf71R5584oJHn/rPH275xx1PfOvbl67Y+8Ajnt9xt72v3Xbn3c74znd+MGtNda9t+nW33dbwic9+/nPb7rL75dvs8O6f7Ljrey7fdrudL3/3Hntfvv2ue12+5S7vuXzWrnv/eLd93/vTnd69+0+32Wa7C6699tq911Tvww8/nP7S175+2E7v2ed7s9691x0f+NhnFj7w5GOv3P/QI9c//PjjP33qv89d9OR/np1z/yOPX/zAw4/9/rEnn33lC6d/eskOe+4/d6e9D/jtF884+5N33HHH+muqZ7Dpb7311oy9Dzrk07vsve83t9xpl3M23X6HczZvl60R3n7X3c/Zepddztlml13mbLnDTud854c/nD3YuvpT7qFnnpmy2177n7zje/b6xazd9756p732uxr+q3bde7+r8VxftfOe+1y13S67XbXNu3f/3Z4HHPiLQ2af8OnXFi2a2h/d5Xkee+yxSbvtc+AZO79nvyt32mvvq3fZc5+rd91j76tFfyx77XPVjnvt87ud9tznt9vusuuvttpx53Ov+etfNyvX0ZN/7ty51b/89e+O3nSrbS7cY98D7v3kYbPnP/TgE2899NiTtz7y2L9/+OgT/z4PctZjTz4159Enn/rBo//+z9+f/8/c5R/93Jde23rH3W46/LgTzr72xht3w7vk96Rf40YeASX0ke+DbhY4hB3W5w5u+4eL2+7toVHt4GUPrvjxFec8+PCDP5m5/gafSKdSx6dT6WNTmdQxiVTqmGQqdWwqlTomncrMTqZTx9bX13/277fc8pvzLrroBJQd0udR9C1evLj65jvu2OhDH/vURd869/wb589fdAXs+koimT4gX4g2SKQDP1WVpEx1FVVVVVE6nSbYRekM4qpSVF2ToWQySXUT6mnq9GlUU1frJ9L+Rpnq9Am1dbUX/e6aP/z14COO+vYD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" />
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    
    :root {
      --bg-dark: #060b12;
      --bg-surface: rgba(13, 20, 32, 0.78);
      --bg-surface-hover: rgba(19, 30, 46, 0.96);
      --border-color: rgba(136, 171, 206, 0.14);
      --border-color-hover: rgba(132, 191, 241, 0.34);
      --text-primary: #eef5fb;
      --text-secondary: #9fb0c4;
      --primary: #84bff1;
      --primary-gradient: linear-gradient(135deg, #9ed1fb 0%, #78b6eb 100%);
      --primary-hover: linear-gradient(135deg, #8fc8f6 0%, #5f99c7 100%);
      --success: #49c6a1;
      --success-gradient: linear-gradient(135deg, #65d7b4 0%, #2ea884 100%);
      --danger: #ef6a7b;
      --danger-gradient: linear-gradient(135deg, #ff8fa0 0%, #d94c62 100%);
      --warning: #f0c255;
      --warning-gradient: linear-gradient(135deg, #f5cf6a 0%, #dca63b 100%);
      --active-row-bg: rgba(132, 191, 241, 0.08);
      --active-row-border: rgba(132, 191, 241, 0.24);
      --accent: #f0c255;
    }

    body {
      margin: 0;
      font-family: 'Outfit', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(at 0% 0%, rgba(132, 191, 241, 0.18) 0px, transparent 44%),
        radial-gradient(at 100% 0%, rgba(240, 194, 85, 0.08) 0px, transparent 42%),
        radial-gradient(at 50% 100%, rgba(73, 198, 161, 0.05) 0px, transparent 48%);
      background-attachment: fixed;
      color: var(--text-primary);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 16px 32px;
      background: rgba(7, 12, 20, 0.78);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-bottom: 1px solid var(--border-color);
      box-shadow: 0 12px 40px rgba(0,0,0,0.18);
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .brand {
      display: flex;
      flex-direction: column;
    }

    .brand-head {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .brand-mark {
      width: 48px;
      height: 48px;
      border-radius: 16px;
      background: linear-gradient(180deg, rgba(158, 209, 251, 0.18), rgba(120, 182, 235, 0.08));
      border: 1px solid rgba(132, 191, 241, 0.2);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 12px 28px rgba(4, 12, 20, 0.28), inset 0 1px 0 rgba(255,255,255,0.05);
      flex-shrink: 0;
    }

    .brand-mark img {
      width: 34px;
      height: 34px;
      object-fit: contain;
      filter: drop-shadow(0 8px 18px rgba(132, 191, 241, 0.12));
    }

    .brand-text {
      display: flex;
      flex-direction: column;
      min-width: 0;
    }

    .brand-kicker {
      color: var(--text-secondary);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1.2px;
      margin-bottom: 2px;
    }

    h1 {
      font-size: 20px;
      font-weight: 700;
      margin: 0;
      background: linear-gradient(135deg, #eef7ff 0%, #84bff1 60%, #f0c255 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      letter-spacing: -0.5px;
      display: flex;
      align-items: center;
      gap: 8px;
      line-height: 1.15;
    }

    .status {
      font-size: 13px;
      color: var(--text-secondary);
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--success);
      box-shadow: 0 0 10px var(--success);
      display: inline-block;
    }

    .btn-group {
      display: flex;
      gap: 12px;
    }

    button {
      height: 38px;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      font-weight: 600;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      background: rgba(255, 255, 255, 0.03);
      color: var(--text-primary);
    }

    button:hover {
      background: rgba(152, 186, 220, 0.10);
      border-color: rgba(255, 255, 255, 0.15);
      transform: translateY(-1px);
    }

    .btn-primary {
      background: var(--primary-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(132, 191, 241, 0.18);
    }

    .btn-primary:hover {
      background: var(--primary-hover);
      box-shadow: 0 6px 16px rgba(132, 191, 241, 0.34);
    }

    .btn-danger {
      background: var(--danger-gradient);
      color: white;
      border: none;
      box-shadow: 0 4px 12px rgba(244, 63, 94, 0.2);
    }

    .btn-danger:hover {
      opacity: 0.95;
      box-shadow: 0 6px 16px rgba(244, 63, 94, 0.35);
    }

    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    main {
      padding: 24px 32px;
      max-width: 1400px;
      margin: 0 auto;
    }

    .active-card {
      background: linear-gradient(135deg, rgba(132, 191, 241, 0.14) 0%, rgba(79, 70, 229, 0.04) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(132, 191, 241, 0.24);
      border-radius: 16px;
      padding: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 24px;
      box-shadow: 0 8px 32px rgba(132, 191, 241, 0.14);
      transition: all 0.3s ease;
      width: 100%;
      box-sizing: border-box;
    }
    
    .active-card-info {
      display: flex;
      align-items: center;
      gap: 20px;
      flex-wrap: wrap;
    }
    
    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    
    .active-card-title {
      font-size: 14px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #a5b4fc;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .active-card-value {
      font-size: 24px;
      font-weight: 700;
      color: var(--text-primary);
    }
    
    .active-card-meta {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-secondary);
      flex-wrap: wrap;
    }

    .active-card-meta span strong {
      color: var(--text-primary);
    }

    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .stat {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 20px;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .stat:hover {
      background: var(--bg-surface-hover);
      border-color: var(--border-color-hover);
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(132, 191, 241, 0.10);
    }

    .stat-info {
      display: flex;
      flex-direction: column;
    }

    .stat strong {
      font-size: 32px;
      font-weight: 700;
      display: block;
      margin-bottom: 4px;
      background: linear-gradient(135deg, #ffffff 0%, #cbd5e1 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }

    .stat span {
      font-size: 13px;
      color: var(--text-secondary);
      font-weight: 500;
    }

    .stat-icon-wrapper {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      background: rgba(255, 255, 255, 0.03);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid rgba(152, 186, 220, 0.08);
    }

    .stat-icon {
      width: 22px;
      height: 22px;
      color: var(--primary);
    }

    .stat:nth-child(2) .stat-icon { color: var(--warning); }
    .stat:nth-child(3) .stat-icon { color: var(--success); }


    .toolbar {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      align-items: center;
    }

    .toolbar select {
      width: 180px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .toolbar select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(132, 191, 241, 0.18);
      background: #0b1421;
    }

    .toolbar input {
      flex: 1;
      min-width: 250px;
      height: 42px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 16px;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      transition: all 0.2s ease;
    }

    .toolbar input:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 2px rgba(132, 191, 241, 0.18);
      background: rgba(10, 18, 30, 0.86);
    }

    .table-wrapper {
      background: var(--bg-surface);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }

    .table-container {
      overflow-x: auto;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      min-width: 1000px;
    }

    th, td {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border-color);
      font-size: 14px;
    }

    th {
      background: rgba(17, 24, 39, 0.4);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      color: var(--text-secondary);
    }

    tr {
      transition: background 0.2s ease;
    }

    tr:hover {
      background: rgba(255, 255, 255, 0.015);
    }

    .active-row {
      background: var(--active-row-bg) !important;
      outline: 2px solid var(--success) !important;
      outline-offset: -2px;
      position: relative;
      z-index: 5;
    }

    .active-row td {
      border-bottom: 1px solid var(--active-row-border);
      border-top: 1px solid var(--active-row-border);
    }

    .badge {
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid transparent;
    }

    .badge-pulse {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: currentColor;
      animation: pulse 1.5s infinite;
      display: inline-block;
    }

    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 1; }
      50% { transform: scale(1.6); opacity: 0.4; }
      100% { transform: scale(0.9); opacity: 1; }
    }

    @keyframes spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }

    .available {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
      border-color: rgba(16, 185, 129, 0.2);
    }

    .unavailable {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
      border-color: rgba(244, 63, 94, 0.2);
    }

    .not_checked {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
      border-color: rgba(245, 158, 11, 0.2);
    }

    .current-badge {
      background: rgba(132, 191, 241, 0.16);
      color: #818cf8;
      border-color: rgba(99, 102, 241, 0.3);
    }

    .table-actions {
      display: flex;
      gap: 8px;
    }

    .connect-btn {
      background: transparent;
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      transition: all 0.2s ease;
      cursor: pointer;
    }

    .connect-btn:hover:not(:disabled) {
      background: var(--primary-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(99, 102, 241, 0.3);
    }

    .connect-btn:disabled {
      opacity: 0.3;
      cursor: not-allowed;
    }

    .test-btn {
      background: transparent;
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      border-radius: 6px;
      padding: 0 12px;
      height: 30px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
    }

    .test-btn:hover:not(:disabled) {
      background: var(--success-gradient);
      color: white;
      border-color: transparent;
      box-shadow: 0 4px 10px rgba(16, 185, 129, 0.3);
    }

    .test-btn:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }

    .mono {
      font-family: 'JetBrains Mono', Consolas, monospace;
      font-size: 13px;
      color: #e2e8f0;
    }

    .latency-val {
      font-weight: 600;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 12px;
    }

    .latency-good {
      background: rgba(16, 185, 129, 0.1);
      color: #34d399;
    }
    
    .latency-medium {
      background: rgba(245, 158, 11, 0.1);
      color: #fbbf24;
    }
    
    .latency-poor {
      background: rgba(244, 63, 94, 0.1);
      color: #fb7185;
    }

    @media (max-width: 768px) {
      header {
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 20px;
      }
      .btn-group {
        width: 100%;
        margin-top: 12px;
      }
      .btn-group button {
        flex: 1;
      }
      main {
        padding: 16px 20px;
      }
      .active-card {
        flex-direction: column;
        align-items: flex-start;
        gap: 16px;
      }
      .active-card button {
        width: 100%;
      }
    }
    
    /* Admin dropdown styles */
    .dropdown {
      position: relative;
      display: inline-block;
    }
    .dropdown-content {
      display: none;
      position: absolute;
      right: 0;
      margin-top: 6px;
      min-width: 140px;
      background: rgba(13, 21, 34, 0.96);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.5);
      z-index: 1000;
      overflow: hidden;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }
    .dropdown-content a {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px 16px;
      color: var(--text-primary);
      text-decoration: none;
      font-size: 13px;
      font-weight: 500;
      transition: background 0.2s;
    }
    .dropdown-content a:hover {
      background: rgba(152,186,220,0.10);
    }
    
    /* Modal styles */
    .modal {
      display: none;
      position: fixed;
      z-index: 10000;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      overflow-y: auto;
      overflow-x: hidden;
      background-color: rgba(5, 10, 18, 0.74);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
      align-items: flex-start;
      justify-content: center;
      padding: 24px 16px;
      box-sizing: border-box;
      overscroll-behavior: contain;
    }
    .modal-content {
      background: rgba(22, 30, 49, 0.96);
      border: 1px solid var(--border-color);
      border-radius: 20px;
      width: min(92vw, 560px);
      max-width: 560px;
      max-height: calc(100vh - 48px);
      overflow-y: auto;
      overflow-x: hidden;
      padding: 28px;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.5);
      position: relative;
      box-sizing: border-box;
      animation: modalFadeIn 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      scrollbar-width: thin;
      scrollbar-color: rgba(99, 102, 241, 0.55) rgba(152, 186, 220, 0.08);
    }
    .modal-content::-webkit-scrollbar {
      width: 8px;
    }
    .modal-content::-webkit-scrollbar-track {
      background: rgba(255, 255, 255, 0.03);
      border-radius: 999px;
    }
    .modal-content::-webkit-scrollbar-thumb {
      background: rgba(99, 102, 241, 0.55);
      border-radius: 999px;
    }
    #settings_form > div:last-child {
      position: sticky;
      bottom: -28px;
      margin-left: -28px;
      margin-right: -28px;
      margin-bottom: -28px;
      padding: 14px 28px 18px;
      background: linear-gradient(180deg, rgba(22, 30, 49, 0.70) 0%, rgba(22, 30, 49, 0.98) 45%);
      border-top: 1px solid rgba(255, 255, 255, 0.07);
      backdrop-filter: blur(12px);
      -webkit-backdrop-filter: blur(12px);
      z-index: 2;
    }
    @keyframes modalFadeIn {
      from { transform: scale(0.95); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }

    @media (max-width: 640px) {
      .modal {
        padding: 12px 10px;
      }
      .modal-content {
        width: 100%;
        max-height: calc(100vh - 24px);
        padding: 20px;
        border-radius: 16px;
      }
      #settings_form > div:last-child {
        bottom: -20px;
        margin-left: -20px;
        margin-right: -20px;
        margin-bottom: -20px;
        padding: 12px 20px 14px;
        flex-direction: column-reverse;
      }
      #settings_form > div:last-child button {
        width: 100%;
      }
    }
    
    /* Inputs in settings */
    .form-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .form-label {
      display: block;
      font-size: 13px;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 8px;
      margin-left: 4px;
    }
    .input-field {
      width: 100%;
      height: 40px;
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0 12px;
      box-sizing: border-box;
      color: var(--text-primary);
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: all 0.2s ease;
    }
    .input-field:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(132, 191, 241, 0.18);
      background: rgba(10, 18, 30, 0.68);
    }


    .page-loading {
      position: fixed;
      inset: 0;
      z-index: 20000;
      display: flex;
      align-items: center;
      justify-content: center;
      background: rgba(5, 10, 18, 0.76);
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
    }

    .page-loading-card {
      width: min(420px, calc(100vw - 48px));
      background: rgba(13, 21, 34, 0.94);
      border: 1px solid var(--border-color);
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 18px 48px rgba(0, 0, 0, 0.38);
    }

    .page-loading-title {
      font-size: 18px;
      font-weight: 700;
      color: var(--text-primary);
      margin-bottom: 8px;
    }

    .page-loading-desc {
      font-size: 13px;
      color: var(--text-secondary);
      margin-bottom: 16px;
      line-height: 1.5;
    }

    .page-loading-track {
      height: 9px;
      border-radius: 999px;
      background: rgba(152, 186, 220, 0.08);
      overflow: hidden;
      border: 1px solid rgba(152, 186, 220, 0.10);
    }

    .page-loading-bar {
      width: 0%;
      height: 100%;
      border-radius: 999px;
      background: var(--primary-gradient);
      transition: width 0.35s ease;
    }

    .page-loading-meta {
      margin-top: 10px;
      font-size: 12px;
      color: var(--text-secondary);
      display: flex;
      justify-content: space-between;
      gap: 12px;
    }

    @media (max-width: 640px) {
      .brand-head {
        gap: 10px;
      }
      .brand-mark {
        width: 40px;
        height: 40px;
        border-radius: 14px;
      }
      .brand-mark img {
        width: 28px;
        height: 28px;
      }
      .brand-kicker {
        font-size: 10px;
      }
      h1 {
        font-size: 17px;
      }
      .brand-logo {
        width: 88px;
        height: 88px;
      }
      .brand-logo-img {
        width: 64px;
        height: 64px;
      }
    }

    .main-card, .active-card, .modal-content, .page-loading-card {
      box-shadow: 0 22px 70px rgba(0, 0, 0, 0.24), inset 0 1px 0 rgba(255,255,255,0.035);
    }

    .btn-primary {
      position: relative;
      overflow: hidden;
    }

    .btn-primary::after {
      content: '';
      position: absolute;
      inset: 0;
      background: linear-gradient(120deg, transparent 0%, rgba(255,255,255,0.18) 35%, transparent 70%);
      transform: translateX(-120%);
      transition: transform 0.5s ease;
      pointer-events: none;
    }

    .btn-primary:hover::after {
      transform: translateX(120%);
    }

    .badge.available, .badge.active, .clean-badge, .latency-val.good {
      box-shadow: 0 0 0 1px rgba(73, 198, 161, 0.08), 0 8px 22px rgba(73, 198, 161, 0.10);
    }

    .brand-mark, .brand-logo {
      background-image:
        linear-gradient(180deg, rgba(158, 209, 251, 0.18), rgba(120, 182, 235, 0.08)),
        radial-gradient(circle at 78% 82%, rgba(240, 194, 85, 0.22), transparent 35%);
    }
  </style>
</head>
<body>

<div id="page_loading" class="page-loading">
  <div class="page-loading-card">
    <div class="page-loading-title">正在加载控制面板</div>
    <div id="page_loading_desc" class="page-loading-desc">正在连接后端服务并读取节点状态...</div>
    <div class="page-loading-track"><div id="page_loading_bar" class="page-loading-bar"></div></div>
    <div class="page-loading-meta"><span id="page_loading_step">初始化</span><span id="page_loading_percent">0%</span></div>
  </div>
</div>
<header>
  <div class="brand">
    <div class="brand-head">
      <div class="brand-mark"><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAfQAAAH0CAYAAADL1t+KAAAQAElEQVR4AexdB2BkVdU+5773pqVuyVaK9M7SBKQjvS5NbNg7iiICCiIsIKBY8MeK2EARRZEiRQSkd0TAld5he82mTGbmvXv/77zJJJNskk2yySaTnLdz3u3nnvvd9+53y2TWkF6KgCKgCCgCioAiUPEIKKFXfBdqAxQBRUARUAQUAaLhJXRFWBFQBBQBRUARUATWCQJK6OsEZq1EEVAEFAFFQBEYXgQqmdCHFxnVrggoAoqAIqAIVBACSugV1FlqqiKgCCgCioAi0BsCSui9IaPxioAioAgoAopABSGghF5BnaWmKgKKgCKgCCgCvSGghN4bMsMbr9oVAUVAEVAEFIEhRUAJfUjhVGWKgCKgCCgCisDIIKCEPjK4D2+tql0RUAQUAUVg3CGghD7uulwbrAgoAoqAIjAWEVBCH4u9OrxtUu2KgCKgCCgCoxABJfRR2ClqkiKgCCgCioAiMFAElNAHipjmH14EVLsioAgoAorAoBBQQh8UbFpIEVAEFAFFQBEYXQgooY+u/lBrhhcB1a4IKAKKwJhFQAl9zHatNkwRUAQUAUVgPCGghD6eelvbOrwIqHZFQBFQBEYQASX0EQRfq1YEFAFFQBFQBIYKASX0oUJS9SgCw4uAalcEFAFFoE8ElND7hEcTFQFFQBFQBBSBykBACb0y+kmtVASGFwHVrggoAhWPgBJ6xXehNkARUAQUAUVAESBSQtenQBFQBIYbAdWvCCgC6wABJfR1ALJWoQgoAoqAIqAIDDcCSujDjbDqVwQUgeFFQLUrAopAjIASegyD3hQBRUARUAQUgcpGQAm9svtPrVcEFIHhRUC1KwIVg4ASesV0lRqqCCgCioAioAj0joASeu/YaIoioAgoAsOLgGpXBIYQASX0IQRTVSkCioAioAgoAiOFgBL6SCGv9SoCioAiMLwIqPZxhoAS+jjrcG2uIqAIKAKKwNhEQAl9bPartkoRUAQUgeFFQLWPOgSU0Eddl6hBioAioAgoAorAwBFQQh84ZlpCEVAEFAFFYHgRUO2DQEAJfRCgaRFFQBFQBBQBRWC0IaCEPtp6RO1RBBQBRUARGF4Exqh2JfQx2rHaLEVAEVAEFIHxhYAS+vjqb22tIqAIKAKKwPAiMGLaldBHDHqtWBFQBBQBRUARGDoElNCHDkvVpAgoAoqAIqAIDC8CfWhXQu8DHE1SBBQBRUARUAQqBQEl9ErpKbVTEVAEFAFFQBHoA4EhIPQ+tGuSIqAIKAKKgCKgCKwTBJTQ1wnMWokioAgoAoqAIjC8CIx6Qh/e5qt2RUARUAQUAUVgbCCghD42+lFboQgoAoqAIjDOERjnhD7Oe1+brwgoAoqAIjBmEFBCHzNdqQ1RBBQBRUARGM8IKKEPY++rakVAEVAEFAFFYF0hoIS+rpDWehQBRUARUAQUgWFEQAl9GMEdXtWqXRFQBBQBRUAR6ERACb0TC/UpAoqAIqAIKAIVi4ASesV23fAartoVAUVAEVAEKgsBJfTK6i+1VhFQBBQBRUAR6BEBJfQeYdHI4UVAtSsCioAioAgMNQJK6EONqOpTBBQBRUARUARGAAEl9BEAXascXgRUuyKgCCgC4xEBJfTx2OvaZkVAEVAEFIExh4AS+pjrUm3Q8CKg2hUBRUARGJ0IKKGPzn5RqxQBRUARUAQUgQEhoIQ+ILg0syIwvAiodkVAEVAEBouAEvpgkdNyioAioAgoAorAKEJACX0UdYaaoggMLwKqXRFQBMYyAkroY7l3tW2KgCKgCCgC4wYBJfRx09XaUEVgeBFQ7YqAIjCyCCihjyz+WrsioAgoAoqAIjAkCCihDwmMqkQRUASGFwHVrggoAmtCQAl9TQhpuiKgCCgCioAiUAEIKKFXQCepiYqAIjC8CKh2RWAsIKCEPhZ6UdugCCgCioAiMO4RUEIf94+AAqAIKALDi4BqVwTWDQJK6OsGZ61FEVAEFAFFQBEYVgSU0IcVXlWuCCgCisDwIqDaFYESAkroJSTUVQQUAUVAEVAEKhgBJfQK7jw1XRFQBBSB4UVAtVcSAkroldRbaqsioAgoAoqAItALAkrovQCj0YqAIqAIKALDi4BqH1oElNCHFk/VpggoAoqAIqAIjAgCSugjArtWqggoAoqAIjC8CIw/7Uro46/PtcWKgCKgCCgCYxABJfQx2KnaJEVAEVAEFIHhRWA0aldCH429ojYpAoqAIqAIKAIDREAJfYCAaXZFQBFQBBQBRWB4ERicdiX0weGmpRQBRUARUAQUgVGFgBL6qOoONUYRUAQUAUVAERgcAv0l9MFp11KKgCKgCCgCioAisE4QUEJfJzBrJYqAIqAIKAKKwPAiMDoIfXjbqNoVAUVAEVAEFIExj4AS+pjvYm2gIqAIKAKKwHhAYDwQ+njoR22jIqAIKAKKwDhHQAl9nD8A2nxFQBFQBBSBsYGAEvra9qOWVwQUAUVAEVAERgECSuijoBPUBEVAEVAEFAFFYG0RUEJfWwSHt7xqVwQUAUVAEVAE+oWAEnq/YNJMioAiMJoRcM6ZuXNd4p7XXUrcJ50LJG4026y2KQJDjYAS+lAjWkn61FZFYJQiADJmiP86CPrOV5fXXfufFe+65onWXX/x0MoTfvPv/CeuesbN+d69jT/71q1Lfn/O7Uv+fM4/Fv/1z28vvOFfL8y/8bp33r7xttvfvPHi21+94dLbXv7T1Y8s+uFfn5j3wX88t2Q6dHqjtMlqliKw1ggooa81hKpAEVAE1gYBkKyZu9hVP/1O2+Z3PbfyoF//68WPfvev//nmnGv/fe1fXnj7f/c+s2Lx0280vf7fRc2PvbYi+strjfSbN5rpvOW29gu2avJJLj35REpPOdZmph0OOcSmpx0WVk05PMxMPTqqmvL+t5uir760JPfHx557+/lLr3/0J/e9kd1obezVsorAaEVACX209kzl26UtGOcICFG/7Vz60WWu9rq5zdOuemzJ5lc8unyvXz3W9L6r/hOd8et/hz/9zu3vXH/JbfPu+Pu/F9xxy9zlNz78Rusf38nVXFmo3+CC1MzNTmjxqzZOTZqaqJ40iZK11ZSpy5DzCtSaayKPs5S0BUq1S9LmKAG/5yyxM2TJo2xoyGQmU96vJX/CBnXB1M0/f++zb1x70e3PffV151LjvIu0+WMMASX0Mdah2hxFYKQQEAJ/8o2W6Xe/1rjrlXe98KlLb3r2rN///fnf3fHwK3c+/dKiV19clH/xrRXugddX2OteXZa/9JVlbSc3BROPa6uacmCuatoeYWbKVmFm8uQwNSmR9TO8KvLJBilyfoJaIwsSb6OIHJrniOGmkj4ou0CeK5ChAuKiWAyoHJmQw6fQBdSSJ3KJWipwFa3IekRV03ZzyWk//Ptjy8+a61xC8qooAmMBASX0sdCL47EN2uZ1ggBImoX0XnCu5u633czf/7tx05/cPW+nn9yz8MhfPNJ4ys+faLro5082//G7/1pw1/n/ePOh219ceecDL7Ve/0au5ie56vUvbPYnn+jSDbsm66ZkqmonUSZdRckgQQnPxGJSIF1QahuH1ObylIcb+Y6M75EXIM0S5UNLPvuUCpJwPQqMTwGoPMqHFHLUIRHoPmRHIajcQoTe/USS2AvIWh+pKJ+sJccZspDFS3NfeeTR5b+86YUlNaSXIjAGEDBjoA3aBEVAERgCBIS8r3POexAEd+fzzdvd8EzjB390+8tn3Hrb65f95ZY3r77n3+889Pz87LMLCpl/L8xn/v56I1/+1kpz9vzW5Aeb/ckHtPqTd3e1M7YppCavZ9OTU4VEHQdVk4iTNRRyQAXrIExCtmSYjDHkHJMLHYFxEfbJNwH8TFHkyEVEnocVtbVIM/BDRy6kqACCx6odXE+WfQqRJzJe7FrotPCLEDMVsLInJtTrKAwtdEB3SGS8JCWr6upeX9R40qqWxMdIL0VgDCBgxkAbtAmKwFAjMOb0gazNMwtd1ZMtbvp1z7Rtcfn9b+/6I6yy/+/+ZZ/+0f3LL/revUt+/717l9756t1LHrvnTfvEQ2803/7U/LZfNgVTLsomJ58Mgj7Gr5m0YZCpTftBmvwgSWmsfhNBQMZGEEdprLzDXIS1M1NgPGIQeEQuJlM22D5HnBCt9XzKOwIZGwoKhlJhgtJRkpKFgLzQkB95FFiPPGugl8HHHvjeguQjYo+IDMgZZ+UhUvIcUJtJxJIHuecRDmGBpIWMvPhEsMPzmPyAKMSqPvCZbJRDClGqdrJ5c8GKr1x11yv7xxF6UwQqGAFTwbar6YqAItADAiBvlpX2Df9ZUf+PF/Oz/va/3Ie/e+vrF/7lkVd+eeM982945JVFD81vSj28zFX/fVFUdeViV3X2Cq49aaWpPaAlqN85l5qwRZiZONNlJlS3+Sk/BGGG2LaOYkIOyGJ17cCsDq5xljxHECs8G7ugS8LOd2wZuDd25WY5voPIxS0Kg/BFB5MFPVuUJzISh+TS4MTwsyuGiq74iyL1eJZQrlhWvhBnoEvEwxLfsIXeCDqj2CXChrwJoTEiscd6AVOqZtN5jasuEsyQoB9FoGIRkLeiYo1XwxWBikRgkEYLUct59jNNbsodr7stf/yvV/a87M43jvjBnW9+5rK73/nmj+9b/NMf3bfgH5fe+c4zL93+1kv/Xdg89/HXl9718tLsL9sStd/waqZ+KFk7abfqCQ2TElV1XlsYkQPhYe0bu+IvSczOwsYQ14NExpLkYbSFQeqxkAVpWkRD2v0M10i6uJA4DFJlCEGcyZP1cqi/0CGWQyoK9DiCvqKw9eH3SVyRwBKlojxW9zlKhzn4RbJws5TECrz4jfc8yD5PxHnoh14TQXdEoRdShDbkIkuUSFGBk9tl/rtMV+mkVyUjoIReyb2nto9pBITAn3zSBbc+37b59S+Gx37nn29ddP3tb/7iD3e+/MdHX1l624J83d1LeeLfl9CEXy6Oar+9KKw6ebmtPaQ1MWk7Vz11YxD4zIJfPbnNJTIhB1iXGmrLW2KsrhOJgNIJbJ1j1e1DDDFWsWBPbE8TVrY2KmBbukAGS2APYoioKJYkLMIgakTHH8eSSuTiEIE0xWPlRmBgkgtqxKGSKx7LEfJCTKcQ4qABeUOk2XZBkIt+gotQ/MFcgzxUU3Jlt0D0M1m0yMJmRyQRJJeL7bO4Wy7WgKN6CrH6z9RPyby1tOm9kktFEahUBIpvYaVar3YrAhWIAIg6Ps9+fJlb//t3vrnXxf98+/ALbnnzpDl/f/W0i//xzg9+eN/SG39w77KnL7l74Wu3L104/4k3Vzzx37dXXdMYpb7u0pM/nqqfcYBL1W1kg6okJ6rYJKvIJDPEQYqsCSgCh2VzBWpqyZLneYT6KJFIUHUqSSmfyeD82eXbyBXy8DN5EZNvTSwJ51HCepR0fiyBJcSLWLiWAqxofRGs7g3IH1VRaAxFIPRycTGVGlCnAbWa2O2IQ15COjkmAzIVNBSErAAAEABJREFUMjaYHIgUaRaUCxJ2sUTIFlFkCl0k9PJUwAo7j+OAgklSyCIB3KJEFFBEHupmcqB2qc8yk+ViDU48sCHwk1QIiZyfMUsacwfc8Urr+qSXIlChCJgKtVvNVgQqBgEQKl/36vK6P81dMes3/176pe/+65Xv/+XRZ/5w/YMvXTcvl7plOU28qTUz7fe5qhk/aE1MPq3RVc9u4upZOb/uXWGiZnLBr6rNcyLtZepN5CXZeinKg4Q9IaMIZAdBHSAuigk8AfJOpVKUyWTI+H5M6NZaCm0US+QsSdhHGoOUS2JcJ6TMTMwMpisNESUXeRzi4chHeFGCjm1cv4SLYklc0DGJ/tg+hwpESnXCb0lI1pAV8m0negeiFd0lET0lf8llqU3qhCkR7OwymYAeVyaEyQlh4iCuwYSFUJe4DpMYzxjgw9RasBR56R1ffWvRxqU61FUEKg2Bsre00kxXexWBkUUAJGWeXO7q7nrHbX7Vo0v2/96tL5944fX/O+WCG1+85Du3v/n77/1r0QPfvXvpmxf8Y8GyZ55rXfS/eeETb69K/CjH00/16zY7JlW34e6Z6vq6VDLpByBXHyREDhSI7W4Dikv4HgVYYQeeoYRhCkBgoGfsSIexOKy0Ex5TwnOgxZBc2EaFXJZy2VbKYwVeKOTiP9USspOveDvPJy+BlTxW8wUKCFqIPOFsB75zZKG/KETYcI8lMhSvwEPYFrJPOejItUseZCjn0MUyQuAWHVIUQxa0DHEWthVFvrBWElmNM0jWkU8hBxRxgiLYJEIugFHtAgM962FbvShB5GGXAGIZcYYI9ViOyHIIsXFY4ljqdURSR1E8MiBztj4ZmyCGGBC9LURkpB3skZ+pCVa0FN5PeikCFYqAqVC71WxFYFgRAFlzuxi43hVPPhlc9/Db6ZueemvG9U8u2P9v/136ze/f9uJVNz3wxl/ufmrxX19Yav+6giZek69Z7/KoesY3Wv1JJzWGmb1aqXoDl546IVE7I8nJCUHBpb08p9hSJiawhCfkEpELi+fVsmqWbfIIq+5cLkeoOxYsQsmGYewnkL7kC0DmiCSWMN5k3zck5C9pIkJUhImAuFHoqCWbo2w+h9U5KI+JyBPaBeuRJQeLOlba8DMz4hgpkgfCxTLFPESODDlGpVAjHyNqUM60l5A4EdEgrgHBiktIL7pEUoSgB7OJ9ijRJyLBossgfclj4IqIX+JESnUSdHavVzR0Fy5WCLyKKRJ2sEvw9vwEhSD8rOX3zHGorJhF74pARSFQfGsqymQ1VhEYOgScc/z3+S5zx0K30S1vuD0uuuXFD5x/44tfvPDWV+acf+vrP7nwjnf+dvGdCx5eumL9N19uSSx9dkninbnL+F9zF0Tfbks1nBTUTjkoVVuzXaq6ZmIyU+XL32cbLyAPK24vEZAD6zhQt3UhyRfMfKyIPRAfcwHEEpKV1Tg74da4Uc5hpUx4LY1PjJWwlVhTPAtm6JV0z4MSkDhZh5wMPchvGbwGQQxBnDAvXKhGOmLgSQYeCJ9JyNVnQnwEIVwGbnchlBaxcDultMIuuUKyIkWCLddB0AlhJmYmh4mFCDFshzjjxXEMMhZdYpNxNrZNcCoJs0N5RzGOgiUEmUQx4qDbEexD0Bm4XixiSzGWcFki4E1YxRelFC66vkyKgKVF/3iBT9ZPTtr6uVX1pJciUIEImAq0WU1WBPqNgHPOyJ96yX8S8uCSJTW3PPvmhGsffGvGHx5+54CrHlt22rdvn/+HB59465Y7H3v7hsdeWvHnpWH173JV037clpp5brOZeHI2MWV2a6Jh12xi0vTWoD6TC+o579dRQX4b3K+iCORkQSOxcJFTO7iVShfIA8TlQBwiQmLISSW3lGt1t7juJOgvyuo5BhLDjigW2CJ1i5/6uCS9VxEdJX1wRY3kFbcvKWEjbjGfjXGI7RGdkFJ80V39LmVFSilrrtcia+8ifYIMJDqtC7xUKqiWsIoiUGkIKKFXWo+pvf1C4KFX3JQ/PLrshHOve/Ybf/n7K7/+7R3zbrvrqcLcJ+YF77zUknjnjdbkXe80ux/46aoPpdNV+2fS1bP8wF+vrq4umU6nGUJVVVVkcL7KzMRgDfGLeFjeGmLy2NBwX5iQ9FpFX2m9FhriBLGhLxni6rqok3q7RKwp0I90dLUXOq+2H1k1iyIw6hAY/hFp1DVZDRqrCCxxrubu57IbXnbr62fd//z8m15axr+J6ja+MJfZ4KS21LT9CqkpG0RVUzNRZiLn/Ay1uYBC8sgLAkqlUtj+FmSYWlvbKIfza/kmuMSICHnEQhGJK3Hl6RLuSZi5p+g4jrn3tDiD3npEQPAX6TFxLSOZ2TBxci3VaHFFYEQQMCNSq1aqCAwhAvc45//2kTeP+un1/7nmwdeW/rs5mHRxPjNld66aUGPS1SaRTpCP82M5Vg6jNiqEbcTGkp+ULW2ccGPLOIwchTaKyT0IAvJwTi2rcdkaly1Zto5icURYrEOiWGgAl5CQyACKxFl7KtNTXJx5jN+Gq90lvQxC9x0nBgGjFlEERhwBJfQR7wI1YLAIYBDmP764avJDDy686IUV9rf+lE2O9OqmTMp7KaLAp3wUEYGAw0JE8idczubJeI5835B8ycpKImM9ZnwirMscG7I4apWVt0gk5cuNYySWhwfgh60dubv7JdybdBQaIU9vdpXiR8isYamWmUk+1pP/xmVYqlClisCwImCGVbsqVwSGEYG/v9K8z3/fXPmXFr/+a1Fm0qRVBeICCNx4lgzIO23ylDY5SrpWCmwrJbgQ/1KarL5DrMhb28L4fwKDl4TMgyBJQuSykpfVebxSJ8amPBN1IXNL6/oSAi3VWe4vxY0Hd7ja3VUvs2fIG3V4qkGKQD8QUELvB0iaZXQhgAGY73ott/3jc9+6koLa/fIFzzOconS6BityQ1G+AGKWPwkLSX5sxZCjACtwdo7ybQXKZ/NkyKcM8stiDPooElYnIou8nlcczwuFAmKo48w8DiBH0e0eX4pVdzgQkD4aDr096sTJS4/xGqkIjHIElNBHeQepeasjcOdruU0fnvvOL4PaGZukcNxZjX3ytCMyuRArc0e+nwAtyzZ6QBGI3nIAGk4iLkWeyVBgqshzKXIhk7MesSd54WcilsWZwxQA5G9M0SVcDP0i8HZ8mFGgI9SzR4hIpHuqxIkwMzH3Lt3LSZi5M7/oEJH4kki4u5TSSm739N7CzJ11Ma/uL+kTl7n39JJ+ySfSPSxxAxHm3uti7kzrj05mJulr2Z1hXCag8TYukl5jAwF9cMdGP46bVtz1/KpJz7z0zi+aqWpXStQbBvn62AEXKRKuAXljlc4iPggdLlbjEYRknEZ+eeg9a8izTDwGkAMHjYFW9N2E8jaW+0sTg97cvrX2mCrq/R5TNFIRGOUIyNg2yk1U8xSBIgIYtPmdxpYPZLlqD7+6gZvbsO0dEzURuLlI3sxwixLi6Q49otLvjcvPmxoKQeIhGRdBXLtiZATRk0gxZrW7nKsXxZDDZMFiciCyWsYBRqBNvZboK63XQmMsoRwDZiZm7mhheVpH5BB4OKLOSoZA37hXoQCsMwQwkq2zurQiRWCtELjmybf2eGdl7hyXqkuZwBB2xAmLcxCs3HH6HX9xLSLCiEzk4HbGC5lbpIsgheKwkXQa1CXkPqiCQ1yIeXXuYV49rrdqmZmYe5feypXimTvLluKG2u2JuEtxzJ31M6/uH6gtjAtzNV2hDxQ4zT8qEFBCHxXdoEasCYEXlriatxe3nlPg9LS2gqNsaxtlUijFeZBzRNYUQExF8aiAk/A8+baAVbhIRELyjh2FmAXkPUM5z6P4fwtjovgb7Axy70tk9d5NHEZ+GoKrRE7lqnqKK09X/9AgUI6zcLloxSOBj/hUKgABNbEMASX0MjDUO3oReH5x616UmLSLXzWJglSakh5TmMuSMxHJlrorDcHigTCW4QzXAwkbCMdSbB+iSci9GBrc3aI+kcGVHtulhCRLMhQtLRFtua6e4srTB+ov6TPw4PnwBlpe8ysCowEBJfTR0AtqQ58IyH+u8srbS49tLvgTm7MhCVnUpj0srLNxOYtzdOsCxEMoSeTS7QK/TRIjzbNe/CU43yK3Dcl3+XgVb+JN+1hNjzdGLhFnmIriwUXdLAJWp74v8AN2DrhXKZWWNvXkL8WNV1fwK7VdMBIphcvTSnFr68o8kB0eqLVVpOXHBgIV1gpTYfaqueMQgef+s3zTVTlzUrp6gkmlklRoy1EhzJGHVXoRDoYjjzLEGcKgDEIvxhkstwziOgQ5PedIBBQNsreIWfPHxEoJW/iS38IVf7GcpIlIqOSKvyQOW/PdpZTW6cL2ODBQNy602m3gZDfQeiW/YA1hgduSw5EF4KYubS1L62qkRVAETj8+5UTe3S/h3qQfqjuySN8Zsoy5m9cRqR5FoIIQkLeygsxVU8cbAhio+X/zWr5Aqeo0Y+kkPxTjew7Drk+hS4BJPJCrAWWCHFwEePJYDReIGCt5ypPFlrx8Ea4oRKBiCMdCDmyDklALYkcRVxSy8LRLMaclcTHYd3ElDqagfpQj6uJKXkSRg37LhkK4IRZ+4kbQgtzIb5ClXTDpcI7Jxfv4iENY8tCaXGjo7VNO6sCxSzZJE4nrgG3l9ZTsELc8Ps5bZo9DOYu2WbghW4oFLY4kzvhkjUdF3KN2NQ42oG24e2xJRHpEbCsJknr8iK3lUspUHteTv5SvN5fZkUgUFeAydm6YuNhBvRXReEVgqBAYcj3Ft2vI1apCRWBoEHhgIU2OkrW7Gj9JBYtBNwpBBI4cSMN5CRCxgVAsQg4dAkJnDNYdYSq/DAJFKRGJuIiMP+XEEEe032J18BddC1/x45jIFb1FF2RVDCJP7IeLFFnBgrJB5DYWIokv5qQ4H/wDdVFkSD5l9Ur7+2MPw/54VesIOx6W2IkQMckl+DJa3em3IH4HIQeyR//ZYkbJMEJii/UWOxR2WwiJza6YoHdFoLIQkLeusixWa8cVAkuaaRM/4U/zPKz2cP4tjTfGUDkBS9xQyEB1CpGHICb5tnwBNhXwNkUiIKoIJOEgRBEoDBMRzsPFMQEVhTlHzAXEFWB6uBaComv1Qd2wg7oJm57jy/MZCimw7RJZSqB/RAJLJD/0I7sXnvXBkB5E3ACuB8KEuKKfgMBamT/EhaXLmAgf0ksRqDgETLnF6lcERhsCCxcsXM9GbrLDwabYJmQuIj/TKSJxIgMlYynTkwxIjzMUby+D1IXcRYpbzO2aGcwmXrjICeqKEEIcwvDgg3NnaVcfIjrXKNDsBiOgrVg3LJElaXchZpAvOLi3dKQarMrl+whe7FqSEgyil3A7OcIyKIjv5cMNJmXATVKGU5iZmHsTTDTaKxdb272EjQfu8KtHEaggBMrfsAoyW00dLwg0rmyahLamIfGHmeMBWohXRCJLrvjXtQgh9lSnhV7FoXcAABAASURBVJ0WJFZyCeQfi8ThLD1iH5MBCHngDzNIwdY1dFkQ46AktgV1i62DkAhl4h0JjCLiWhYkLG4imLzgMJpA7sKQIg7hOI9MaORIhJAHuUfyA9OJXGw4jgxiS9AqKkbEQb0pApWDQPw8rxtztRZFYGAIgKg5ctFEbLczdnOJmSnCShDxsSLEr3HrXfL2JbGibrfy/N2SVguyo5gI5PxYtpgNwqZE3g4rQJwXk7ggbuQkB9dhuzmiJKguSQRSHbwQ2h+1i+vRRQX4WIh8ursUY0qwt2TzgFzYHmJiErJH4tr2iYVjIvltAMI0RfwWYReTOOpnkDi295nkqAFh5KFRc8XDIaOTcD4waoxSQxSBfiMQP8H9zq0ZFYF1iwAbL9iQmUm2143xQVou9osZzGAK8ayFMHOR1LrpKJF6t+guQVhFPiYYInJuLNvMnjUgeEMGpE0QR3JWLAKOcAmSv5ePKEEFkGBEHvIZnEPbwYsLKXAFSB4yUBdlLVECrCtn3tKGgbiMiUDIAbV5SSqYJOU5GberAGKXo4iSODLkEEfxFeIeISaMBYER/diO2mFj0e9gGKZlxYDeFYFKQsBUkrF92appYxIBrOu4KrREEZbocnbOzB0NFdLtCKylh3lweg2GfjlHjgV2ihaJk1UvgRkY6SXXg1+EYWsxHh6SkLyGgxEpXxIoj70Dc6V2BjEzJhfikvgh/XEljxUFJGtxD3eDFlO7AAzEULxDIZMZaZ9EUNziUq7OWBrRC3OaUv2Mh260mFWySV1FoF8I6IPbL5g000ghYJiqoygi3/cpDENi5niVzlx019YumRSUpKSLmeN6mIt1lNJ7ckuEViorruTDRjjsJCoUCpT0iDLGYiXcRhkuUMrlyCtEOP1GbpBnhNV6CBosF4kTcV5A1vgkfkkvgHlExB+ChEWLpPUmUrYkq+WBBQXoKKCdIqEx1F0izyORnuIJ+RNogh9GlAwdJa2jBMQLobUQ4lCBCGcmaJlHbD0i7FgwdidEooJP4sqkgMouwa4s2Ke3P3klT0l6UiY7P8zF/pa+Ys8Q+pR7yqtxisBoR8CMdgNHh31qxQghwA5cCA4boerXXC3soxDUZAlHAWTxLyIQQlzQwfpMAmScayLbuoQMxDXNo1S4nGq4CeFl5OWXkWlbSl5uBWQZpOiatuXwL0Na0e2eXgxLGqRtJXm9iMmuoF6lbRl5OZTvQzi7lEQM8oor0ulfQl52CaXzKyiVX0lJ1JWCrpqo2SYKja6waolLsSWD3RUHKWByIwRqPB9zgQRFIXdgFQM2wBvz2vNu/D0MqGFm8gKZZBj0pnxIL0Wg4hAwFWexGjzOEMBI295i1+52OrbTOwI+h7VnvLLF4jPEmxSJgBwikFjEESg+T75po6h1ScvETP6Hs95Ve9y266UO3GRytN9mDbTvNtPde3eYwQfvsAEfscN0Onr7me6oHWbycbNm0LE7rkezZ81wx+0wnU9E+AM7zqCTdliPvrjTTHPKDuvxyTvMoM/vONN8YdaMxOdmzUx8esfpwcdnzUx+ZIfpwcd2mJH45I4zEp/dYWbwlU5JnIG4r82anjwZ7md3mJH8fFx2On9+h+l0yqzp7vPbT6dPbD/DfXTWdPqkyPYz7Kd3nMmf2nEmfWGHGfxJ1PfJndanD6L+982awYfPmmn2324677fT+on37LR+atutpnqbbdeQnLH9pNTELSbWNEyv944OGxe/aVsbsUvBlAgMMAkpikKy6C8L/CgWBEboI5PFCDtAUr3BjgPmHey8ETZKjFFRBAaBgBlEGS0yxAiout4RiFe72Ja2XP6out4LDHEKM/eqUWyLBeO/uGJV7KKIFBP6alq1NJyQpt9vv8lG5xy23eQbjtppvbuP22n9+47ffsL979+h4Z7Z202685itp9x2zKyGvx+33bRbjkGeY7efeuPsbRtuPma7qTfM3n7SX47ZbsqfZ2/fcM0x20792eztJ//k2O2m/vyY7RuumL1dwy+O3X7SL4/dbtKvZ8+afNWx2038wzGzJl99zPaTfotyVx6z3eTLO2XS9xH3w2NnTfw53CuP2X7iFVI21rP9lJ8cs/1UhKf87tjtpv7+mO2n/Fbk2O2m/Xr2dlN+M3u7qb+QsMjsbaf96Zhtp/z12O2n3H7sdg33Hrd9w32Hb1336KHb1Pxv9s5TXjl0l4YFB+0ysfG43WqXfX6vqbfVZezPKGzJeySTG0tsIgpdCEKPiBlA9YpuMcE5RyUpxgztXXRH5ChCPaGzcMUudOjQVqPaFIF1gkD5KLlOKtRKFIGBIsBcGvhH5nFl5l7Jh7mYxlx0S20TYsfBMXnOvbXVJhv/aI/1ufhfw5UyjAOXme1Wm06/IxXYd/L5VVTIt2DHwpHxIgjFpC73kYLCsdRuiA222j1Mv0DqxhhWOie9KhQBU6F2q9n9RqDCMzrCsLt6G5h5nY+7zF1NMY5IxMPKzgMZeHB9sISByQYuYWeBIttWm6EVNE6vqpog66IQK3QmkCUxAzTsa8vK2HTDk0bgEjukWnFFZCLW1JLDIYrEqigClYWAqSxz1drxh4Dp8RkVXhhpLBhrTB/kVBQiL8Lq04owMcjcQDzPj1pbKDfSto5U/blWCvM5igK/inwvTTbyCEfomAgFRDispgFMy4Rwh6sdESZjmGqIel6xdFmPz5wkqigCoxkBfXBHc+9UgG3rwETbOejDiwqZR+6xZWZYUPbBypxB4iJlsSB0hJBmLbuCpXauQNw4+6SY2siYAviSwhBARESeSZLPWARHxf4cSUiKuwZMhph8PyA2Pq1oaTOklyJQgQjog1uBnTaeTGbLrcyGnItI/jkhAqx8rbXEzGuEgpnjfMw9uyUFzF3TS/GyKuwupbTYRTnLRPG33MVO+JnlBubCCp48j9J14olzj7sbqDEXsg0jtiR7Lb6fQH94JN8s9wMvxoMZeMW+4k3wLvpWv0vaQGR1DZ0x7ODHc4QTdDI2IlhJBTbsjPxyANL0owhUGAJK6BXWYePLXJIht8l2a7QQaLeotQ4KSZSUlPtLcT25ckwu8eJaYiq6Bq4l+eU4Eh5nZ5tD8UjO8SdJ8GTEZB0IXVrvsBYWfLFxgaBtFzgj/PFc0QAL+yLju2JI74pAZSGghF5Z/TUOre22fKs8BNykiMYtQTRVE/jcxO0XIpedllIXjlZYnGUdF0udpG5FIaAPbkV113g0Fnvtw9Ts7mqLhBNzT/ektQrnwvFL6FGOQoAn5w/xsYlgbLFaL63YkYb41TGXfJLGzMTcu0ieoRapbqh1qj5FYF0goIS+LlDWOgaLgGOq/G+IZ8cxoXstWKEzO3wo/qYgyLx4FGFxDhHzPI2yC8YOx6HOKGulmjMmEVBCH5PdOnYahbUbPsPXHmZMGXpRz9x7Wi9FyqI7vMNqf0cto9QzZVOybLCJTTb+XoFsuTNzvOoWk0srcfF3F0lbk3Qvs7ZhqQ9zDl5bPVpeERgJBJTQRwJ1rXMACDjZsu01PzPH5MDcs9trwXWXwGn5GvW6q2/U1STfZfdw6sCwjB2RDDrydThmRszIf4TER94KtUARWHsE5N1aey2qQREYLgQc90noQ1Et8+rEwrx63CDrcktasDwdZOHeilVK/GvYX/ewQjckeAqNFy1n5lELiuPY2KKhelcEKggBU0G2qqnjEAHGfq2soJgxykLEL8LM8ZepxD8U0h3aks7u8aUwc9GeUrjkMnPJG7vy9/KxZ5ze3kfkoigM5fzcEMNxJJgwe3AHDwozdPVDBlIDc1EnDgh4IOU0ryIwWhAwo8UQtUMR6AkB5nX3Lfee6l/bOGwxVyA5rG2ru5Z3jjmfz4PALRn5dRlniC0Tg9Qp3oDvmn+EQ8xMPMI2aPWKwKAQMIMqpYUUgXWEADZprayW11F1a1UN8+o84LCRsFZKK7+w40QyJADBzDGhM3NM7qO0Xx3ppQhUKAJK6BXacePdbObVyXOkMGHu3RZmthu30bgliX8uogx7qWryk0TGIyHx0v+yVvy5mZHqtd7rdW789lfvqGhKJSCghF4JvaQ2ViQCIHMSadp5aAnintdX1P/tmaYp1z3V1HDd/Qsa7nlx/uTH3nGTnndu0jvtMt+5yc+vKobfdm7im85NKMnrztW/6lzdy87VirzgXM1i56oXOlclgrIZEZRLlwRlUuWCcsmSzHUuUfKX53kG+p57o+W4vAu2ciYg+b9YClFxbiNb7yKjsGOly3gU2qUmKQJrREAJfY0QaYaRRAAPKD5dLZARV2JKrvhHWnq1xQ3tl7mffNIFL7y08O6X5i157qX5K557Mxc++8y88D+PvvLOU3fc8+aTf7nzVchL/77+7lefuvvJV5/6292vPvm3u158+MY7X37ohn++fP8N/3zlvhvveOWem//xyj9v+ccrt934j5du//vtL9581e0vXXfVbS/8+erbXvrTH25/4Q/X3PriVdfe9uJv/3jr87/+w81zr/zT35/7JeTKa2+Ce9P/fn7dTXN/8mfItTf/9/Lrb5p7+Z9ufv7HSP/5NTc9/8s/3fL8L/5689wrbrvtxWtXNEU/dX56AnsJcuzHK3RmBzeKhYYWHiJa+ydBV+hrj6FqGBkEVhssR8YMrVUR6BkB69ZuxBei7Ut6rnXtY6XOWAs7t4SouCyNI9buNq96aWpF3ts+SkyeSNUzJjd7E6Yt4wnrLYvqNlhm6961kie8q9GbtCHc9VdS/QZNPPFdzWbyFk3+5K2ag8nbwt2u2Z+yQ3MwZdcmv2HP1sS0PVpSU/drTk49rDU19Qj4j2xJTj22OT3thJbUlPdnMzM/mKtZ78O56vU+0lY1/aRczcyPtNXM+DjCn85Xr/fpML3eZ6PMzM/Z9PTP2NSMT7iqaR+hVMPHKD3po5SYeFQUZGpMIkkRyFww8Twv3rVwNiScpK8dGFpaEVAEuiCghN4FDg2MNgQcF8nQFp3RZl43e5iEtMojDRvXQMQ0RFeuNZUqeCkTmoBbC45CLw2yTFPBpMj61WSTtUSJWir4VZSjDOVMGlJFeRZX8mUo76WQPxPnkXyhV0MRyorYoIpsUAMpuhEX84obelVxfeJGfoacl4nr4qCWbKKKCGUj2FOAhLAngrCRc3Mi+Za7bLmX8JGz9JJ/iKAZMjWGyVAvl0YrAqMZAX1wR3PvqG0OK/Q2YkcMAbm3I1J8bIUUJG5tpF1hF0eIpiRdEnoISD5yBtvHmHlgr9Za2yUX7HddItYykPe8ZGQSTMaR71vybJ58V6CAIvJcSByFZMMCILPkAyaPHYkYbHSwsyhmieE3FMINUQZhG5FpFy9EnEgEvbaoNwHdoj+A/gDtK4mPSZZBHkb9jPJO/sKQLVlmypsEhcaQcdCD9AAs6XtSs6MQedn4ZNFxzEzMTAO94r4H3mtymTnWz8z9rkLM6ndmzagIjCIE8MqPImvUFEWgGwJMUfvXqCTB4jb8j6yQBColVJb0AAAQAElEQVTq56erPczdiMM5r5+K+pXNdyYDWkYlDvlDiGAiAi+VXPELhRNiOl2JtSgpsUWXQMkS201AyhKDuYA4mBzETsetVDaOkLzlEkcSRcDBEqOsxaQhhM+2p/TsMHPPCes81hCaM0LGrPPGaoVjDAEzxtqjzRlrCJgi5wyMZDtBkHJ9SWfOrj4p0zWm51Bv+TriZVncc9FBxVrDWPfamCAFGse4i9DA3QjlYsG5dgi/rKgL0F6I/V68wpa4kki8pEtYXBGLensSQny5YNVLIh2NBmsKc3aE4WFm3Ef+IxsuI2+FWqAIDBwBJfSBY6Yl1iUCDrvu2Fotr9J1C5enDaV/oPUw90RIxg3ll+ISXEhIG8vnCTGhouqBui4mXRTE9EB0EpgsduN4E6/u4zjEi25CfFwGYXFFiD1i5l6lqK+y7phrcGVZ3D9rNdfYR0AJfez3cWW3kLFc7KEFAyXbHlQMe1RsI7bch/JLcaFln0C1sjK3xPAZcu1EO1BXWIsdEY7iyYcuD37PGvJxSiCuCIO8RcQfC5bZHoRFqHjBS73WjUokvZiz886oS6QzpuhjRoGiV++KgCIwQATMAPNrdkVg3SLgnB3OCpmHhkCYi3qYi26HzVhK1/wbbNkRsXYeR6bKYo4DN1ZkQOlC6x5gGqhrUMajCMaJWLghpgYW0t2VOEuyRc7t+Y1QOMrTMFzMTMw8JJoddnP6kiGpRJUQkYIwGhBQQh8NvaA29IqAjMelRBmYS/6hdJnXjjz6tovD13YG6w6RwYY56bCejmCzrNKFyANXwKq6QAN1PSoQcaewCcl5IVlT6FEc8paEOI+yIQREj1U8tV8WUHYRTA9kOtCeTOwoFoohQVnq/WLmmNiZe3d7L60pisD4Q0AJffz1eUW1GAQAChh+k5l5UJX0TeaxSrBe7A7JLfT9REQe6NCHGMjaqTUxukKsIqKr5Ip/dSmhxFihr546NmIwP4lRGRutGRut0Fb0DwEl9P7hpLlGCgFDxvO8jtqZOV61CZEyc0d8bx5mjvMz9+xKOdElIn4R5p7zMnfGS76SMHPsFR0icQA38bMx4XM0dOwXOapiz6e2XIFCx1hJBxSaBEWQcjfkgAoiWM3nIaVwuRsxcMV5ubEB9SYJkybPJYgjn8j6xXyUiF0bot3WkcGsi9iSiEdMLowoDEMypmx4cfCLEBEzk9cutIZLMOxLmDnWx9yzW66eufc8Yqv8hgDjslG7oeWF1a8IVAACeMsqwEo1cdwiIENwJTeeiXhrCA3RFYURuNBRIpEg3/fIUfEVttyz6wwolkGyPbgOhF6eLv4OaU/L5nNUsBE5w+R5qA8uyeWZ2AZop/gHZSQPzkdiUkc+H/YIQUrWShNniSvNZrV3bRAYO2WLo8DYaY+2ZKwhwBheK7hN4LhoKFfoTDbhQJ7G5SjMtYI/81g5h0QRxEK6uYy8LL/g1kt85ELKcUgFuCJ5CikWxIlrEh6RzxRhBS7pkcuTiKUCWYu6OSJGF4kQ6iJZsaOIkH9xO7/vznMAqC/pu/TQpEr9Q6NJtSgCI4uAGdnqtXZFYE0IgFkIC9E1ZRul6bKcPo+Gzv4UhXk/bKUAhJ72HLauDRnGVji2t3tymZmYPDLd0pmL8Q4usUdQEgvH/lLYIwvT5adaowirdIpIiFp2BhjxESYQst0u4ntMPlbvMnlwkSXuD5vT6LwcWzM6LVOrKhGBdWmzPrjrEm2ta8AIyAJuwIVGUQFHlBtKc9JBON8vtLggbHEpE5IFqYaopDcpYMXcl0QRk8VZuEgENwqJbEHEwXWYPkC59TAl8Mg4Q1HBUgHn91EeGQtYnUuBsEAGBB/4Bk1FORvCLouYCGUwT4AKJIz6j67UR30XqYFrQEDewDVk0WRFYAQRiPdyR65+GeT7kjVZxobza8ozkPRUIffvFOf+R9kVq2zT4kavZekK07Ko0W9a2ljmrvCbl6yMw0V3JcIruHnhCq958XLEL0V4qd+yaCncJZAFftOSd/yWJW95rYvfQJ5XvZYlL3sti19IZJc8l8ovezqRXfaM17TocdO44KFkduldk/z8TetPTNzgufzcfFs2yre1kgO5Y3oQk7sQ/EDaNVJ5pW9Hqm6tVxFYewS6alBC74qHhkYRAszsyBk7ikwajClD+o4dMmtay+47bP6h3WZt+Yldt1z/4wds0fDRgzav/+QBW9Z88sAt6z5x4BZ1Hz9k87qPHrBl/ccO3rLu4wdtXvtx+D9+0JY1HzloywkfPXCLiScduEXtB9+7Zf0H99+89gP7b1X3vgO2mTD7vdvUHXbA5rWH7L959QGHbDph7wM3r93jwI2S7z50Fu3y7k2m737chjN23eaod+1x/rGb7HPuURsf9NX9G4757C6Z4zaf3nBkdU31T8i6NhdhWx5bKug3ki1+rpCVeXmnMhGT4yHtM9JLEVhHCOiDu46A1moGhwBIYZTTQud8w2JtGrcSW9O2nRMCnDuD4FwcP0S3fddP/veAdyVvOHDTqhv33rzqln03r/mbyH6b1t6wzxYSV3vLvptV3bzPprU37rNl7U3v3az2pn02r7sVBH7LfltU3b7/5vV3gbjveu8W9Xe/d7Oa+/bbpOqJ/Tetmbv/FrUvHLh5/Wv7bF21AP6l+287pXmP9dfPHr4Z57bdlvMnMkdoS2eD0Z7jt+Y3p25Q+42adOoFMj4hnRzO0p1jCqPVm41olOqiAuGR/0SxYYZgGeg8Wt3wkTdRLVAE1ojAUBP6GivUDIrAgBBgZ/vaFjXEoNGuwhiOexKsImk1odUvqU9EUoSg1iRCYMQeiThYY0HmlrHWI6IEhRbOmP58YiNuS/lmvnU+OT9B1piYzH34CXjEYpnIOUxvIpBmOyTODAgXZibmriL91JeUV1CerxTvHM75YzMMGU7E0da22xeH9KYIVA4C8aNcOeaqpeMNASYjq8J4IKf2Swbmdu9qTm9pvcWvpmAAETJpKGWPSMjKUcxbEgmykpfLFtoiCY51Cduy2Vw+pFwhoih04O6idLabO7yCUSlgMPkq+dfkDnUfOi4Sd2wP+qtUv8McsuRXVxGoJARkzKkce9XScYeAM1jW9dBqh2iRHpJWi+pvvtUKIkLK9iUEUpCN2g4BQQl1MQlZOPID+b/MoGiMf1KJIPR9n+TP2kqChTpaLTjA0Y8ioAgMOwJK6MMOsVawNgiwY6+n8szcZdUueYR4xS2XnuLK04fCX15H0V8kMQa519XURENRx2jXwR7n40mM/MmaCymyBbJRsenxtjawKG9DEafymP75B1uuf9rjXMx4tGKf3hSBCkNACb2zw9Q3ChGIIosxvOv2LTNG3HYRk5Eh3uIV/7oWqVvqFPKOBStz2UYWv2zCJ5N+m6SPdXFh5CIQeAcecf90Y/EhAkHqEBkidd3VDI/R3WvRsCIwDAgooQ8DqKpy6BDgsi33ngbxnuL6Wzsz9zfrwPJhG57A6PhQlCuEAytcmbmNZzwPcHqGyQeu4mdGBI5GcCfBg8ovnFlL39k4sTyh/34p3//c/c6JbhPD+51fMyoCowYBJfR11RVaz6AQAB/IiklktS32QSlsL8S8FkzSrkMcLv2OOVbmBJGzdDBC/AtpEnZRvrjvLJnHsmC/XQhWviEuIqv1MJS5TPH4oXvTi0Q+Oocfxn5Pd3s1rAhUAgKj842qBOTUxnWCgDygXLy61CfkIdIlsp8BqOtnzsFms6CEiMR24/tDM3MYrCnrqBxjumWMIRH5UlzgeRQYr7327qTO7fGj1GGWrhulxqlZikDvCOiD2zs2lZQy5m0dCHkLYZekJ2BEV7n0lEfiJI+4fQq2mB34qTNvvJlAUr+s0LFSLfRZfowkWlfciEB747bncjnyMJcp4lBsZPzdAuY4vRiz5jtzMT9zz265BuZinvK4NfmZZT3e+R0Ng7B12HZZU0FNVwRGIQJK6KOwU9SkTgQcc5EpOqPW6HOyTw9ZY8ZhzMDYfhf1oJg2cce6RNiUCG1xMiNb7ui3Lk2WY4guEaM4wBasPortU9MUgd4QUELvDRmN70RgBH0gRHyoyBQ92MHMPcQWo4TYi77hvMsrJNJLHS4a8ISkF02jO9p5jtgjNh5F6C5mjn9gZnQb3bN1jol7TtFYRWB0I9DHSDS6DVfrFIESAsxMzFwKjpBbepW62mG6BkfItuGv1hrjOzSWvYBkc8SLXddRMUiyw68eRUARGB4ESqPQ8GhXrYrAmhHoO4cb5eeZzsSb670Tljc+ztCJfAsQ5L81EZc9Q+T5XfrWcpegBhQBRWCIEcBbN8QaVZ0iMIQIgC87l3m96HVYEor0kjxs0eAvKpJU8TVyXCR3qdBRMQ67zy0SHuvCJkh4IPBSPzir7D3W+1zbN/oQaB91Rp9hapEiIAhwiSEk0IP0lczMRD2UWZdRjly4LusbibqeWbiwKh9GW5LxiNjDx4/P0aMK/V/LGJ1GeikCFYiAEnoFdtr4MhkE0dFgeVxtR6g3DzOPyJk6iCA2ybHYSVQMr9lequDr4bffTj/1YsspK5uyG0WRjdscYKVe3mvF5tnYkT9diz2j4FbsH2r/EaBOg3r7D4E6c6hPERidCBRHntFpm1qlCBBbYtnXZln5dWy+I7KdtGXbu7tY7HOXhAyTSPc8pTAzEzMPFmmUs7H4UBiTFVapzJ36QGxDeob+6DJXe8nNcz/73dte+dIlt750xsW3vvqNi2975cwOicOvnX3xbZBbXznnotte+dYlt79+nsjF/3j9fJGLbnvtgotve/X8b4vc+tqFF9366sUi377llYtEYv+tr34XeS4TueS21390yT/e+DHcn4tcesebv7j0rrev/MFd82+873nz7Px8zQVeOpM0VCDPWbL5HKHTyMPoEv8JG45ErHQkGJRxhmIgzMiBuL52WADsgD6iS6S8EDMT8+pSysPMsdcYQ1LW4oYJiXRqHK83RaCSEMArV0nmqq3jDQGM/TGNgwtGZdMx/sd2CS2ISEDYQPwxwfPQ/tnaghXRexup9ufN3oT/yyamXgq5pCUx7bsdkpyK8JSLWhKQ5LQLW4KpFzT5k+c0Bw1zWvyGc0VaE1O+1RxMObdVJNFwDvKeJdKanHq2SOxPTDkTeU5t8htObQomf6XJm/QluJ9f5U/6/Eoz8XOreOKnV5r62S1e/aZtXnUQYVfCoJNA0wQnJscObNpJsyMc9yh1EC2Ngqs0EEq/OWdLwVFgmZqgCPQfAX1w+4+V5lQEBoyAZcoNuFCpQA9uc0urDYIkFpTGeJ5H/RWDFWi59LdcEATk+34spTKih5ljQi73MxfjmLnDcuZOv0Q6rNZFxN8fkbx9SX90DDSPmDjQMppfERgNCJjRYITaoAj0hgBWe7KeE+kty6iLLycgJh7SX4pj9gqmnWCJmNZ0MTMx9y5CyGsS5mL58nzMxTjmTndNtmi6IqAIDC8CSujDi69qHycICIn31FRnYMTljAAAEABJREFU23/kvKfEQcRhBz8h59JEa/3q9qt2qcthySquiPhLIuE1KWHmNWUZdemYuFTUBHLUAagGjRgC62ZUGLHmacWKwLpFQMhuOGv0/KRnfI+w7CZLjrClT/29xDaR8vwS7kskr6SLK8LMBMJD9RwLreEqL1uetRTPXNTDzOXJ6lcEFIFBIKCEPgjQtMi6Q8AxMWoTgTM6PyVy6sk6Nka+I9dT0qDiQldIGeMTFs1Ebs2vL3Pv0DH3nlYyjpk7CFyIXISZiZlJLml7SSTcIT14mItlSklSruQXl7lrusSNhABbXaGPBPBa51ojsOYRYa2rUAWKwOARYIdl6OCLj3xJO7Rb7kuWr/Jy+ZBC+Y1Vr3+vL3ORKJm5g4iZud/YOGG4biLb7SKlNFEmfnF7EuZifcxFV/L0lV/SVRQBRWBgCPRvRBiYTs2tCAwhAoaEOEQhM2NlCoYHuUi4FC9+EWbuICwJiwhpiIi/J5E0kZ7S+opj7qyLmTuyMhf9zEWXnB3Sv0PPZvMJz/OJRGjNr6+0TaTDwG4eY0yMGTN3uOVZSmWZOY6WsAgzd6zcmYtphEvSRODt8pG4kpQSmDv7s3taKU8v7pBFS72iTJ4lwUJcT/7+TiJVFIEKQ8BUmL1qriJQEQiUiII8zg+lwc7ZjOzhy56wlfMI9jqImJlX8/dWt2ufFJVcySd+EfGLlPslrKIIKAKjGwEl9NHdP2pdhSDAzD1aarGh0GPCICPZM0kieW1FBqmkvZgQdrm0R1MprhQeb651zhtvbdb2jg0E1n5UGBs4aCsUgWFCwAZDrDiFhXn87Xb5hrvFSrtEwD25g6mbmTtW+oMpP5AyzJ11Ma/uH4iuIcrrDHM0RLpUjSKwThFQQl+ncGtlA0UAR7yyuywy0KLrJD8z91kPO092yPvMM5DEyJkUOby2wuoiaygsJN9XFmbuIG9m7ivr+EljGtI+6wacBhWBYUMAI8Ow6VbFisBQIVAxTNOdQA3ZIfvvU6Gb2VE6os75DTN3IWTmrmHpAJSLt9HFvyZhXr38msqMtXTZ9BhrbdL2jA8ElNDHRz9XbCutJa5Y42G446H9szWyNgW18YeZqUTWvblxxj5uvZUrxfdRdOwmOWcrtnFq+LhGQAl9XHd/5Ta+H7vNo6Jx7BKFITQEFF6oDhxUyjEvlusOy0n5xbjeXKm7hJXkKw+Lvz8i5WMhg72BrkKIK0p3TcKJIhSXCdknEYf8sS5GPKR7qXUZdtw5/NnyirksoTxe/YrAKEeg84ke5YaqeeMTAWbLBOKiLseaxce2fBBm5g6AmDv9HZG9eJiZmLmX1N6jhUBLIrkczKT4bFtsg8Av6YVoSFfoLkVZa/LLyaMcRS6PKrFKZ48I4iDdXQv2jCDiWpCpuB1hxLt2IaSJOLixMAFxR6X8ZIp/+x46IhELzgstk7U+2fa2OjTVOcauAZPlEEQekg8itxRQC/K1wk9BAnYzOWYyASYHqIfW4nIoP1hhZjJGbPAogt95Hkk/coHQStJrdQQ0ZpQjgJFnlFuo5ikCJQTYwtfzI+uco3JBxlHwMeT5MGyILGFmt/1mMy6t9bJ3m5bFj6bCpqcSbYufTmYXPxO0Lf4v3P8lsovnploXz0X4uWTbkuer7coXa6MVL1fZla/VRCvfgPsm3LfhzoMsyBRWLKwJVy6qLqxYUhWtXFYdy/JlVYUVyzLRyuU1tHJlrW1szBSWr4LuJuhsrrGrWkVS4crWZNSSTUTZfCJqDhO2xSaiVge/CAW2lbyohSjfSnX1REFAZCMin5g8dpRrzRbnajRyl3wfQX5MhgyT7GAIwZOzZuQs0poVgcEjoA/u4LHTkusCAa7swdU6LE2HEKeDNp/8/H7br/+B/XfY5MT9tp1ywnE7rnfC8Ts3nHDCzg3Hz96l4fij391wgsgx755y/LEIH7XTxONm7zzpuKN2nnjsUdtPPPZoyOxZE485EnLUDhNnH7fzpNlHbD9x9pE7Tzz66O3aZcfJR8/eqeHo4yDH7DDpqMO2m3jUEZDZO0076v3vmXnU0bMmH7nLDHvkem7+kZPD+UfWu0VH1dslR0OOrY+Wvq/erfhonV355dpo5Xl1UdNf7Yp5y11zSNyWJ861km9DSns+Bczk4lV918nYcEzMSjrLu0LiDNbiQugGhE7OkiFMGl2EW3lO9a8TBLSStUZACX2tIVQFw4mAo763P5mZmHk1E5i5x/jVMg5zhBHWGOI6dplRu3Tfmfz2vtP49e2m8qvbTEm9svWU1MuzGlIvlmT7yckXtpucfH7bScnntp6YnLvdxOSz205JPL3NlMR/tm5IPLVdQ+LJbScnnthicuLxbaYlHtt6UuLRraYGD8cyCS5ky4nBQ1tMDB6cNSV4YPspwf3bN/B9W03ge7dt4HsO3LLhnk8dusM9Xzh8y399+eDN/nnKIdvcfsrB2958yqGbX3/KwZv94SsHbfPjUw/e6oIvHrTeiZuvN+EYbl2xNEkRJdmRsZYojCgAqa/rAch12zBhxnOCOAM3irB9gAkG9uGHuMdUnSKwbhBY1+/TummV1jJmEGAifKhiL3bGq1jjh8BwxjHBTps2PGXy2YcCEKdnmGRVHIWWmDH84PydhvnqTuKrV4fNdhA5y3kAWZdJ+mD21XNpTEUjMC6Mxxs1LtqpjRyjCMhgLdK9eRIn0j1+XYet55Lrus7RVp83lQouapsXhiFF2M12XkAR++Rwmm6HebrW0zPQGSdELhMLwll+RGwikq336roaR3opAhWIgBJ6BXaamlw5CDjL4/4d24bIBolMszMBRSIg9BwoM2+lH0cYHuwaGIOTc5zre9g98Ay5CbVVoVimogj0G4FRknGE36ZRgoKaMWoRcEzcH+OYmZg7pT9l1kkeJn3HiFxorc1hdW59H6tzppCYyPewSqcRvwyeG1m1M8MmspRIyKHAiJulBigCA0bADLiEFlAE1iECbONRttcamZmYOU6XQbkkcQRuzBynM/fsds+PIl0+zD2XYy7GS2ZwlThxPaJPAgarPmbJ40IJj3eJXGQZBG6ZsP9uyU+AzLE6ZuYYN+ae3TXhxuSRCDkMZWUiceXSPT0OY65l2KNCoUCe55H0o8XUA2YVSC9FYPQg0G9L8Bb0O69mVARGLQIOo3BPxkl8X9JTmaGM0y33GE1ssDv5PRoEsM/OEWHNTiQuI0yDv0p9211DKb7k9pYex2MbKHaxOpc/o8OgCHuLMXpXBCoJATy7lWSu2jreEMBYy2tqswzaa8oz2HTR3Zf0pVfK4QS9qq884yWNnQsZhMkOq+GS2DyxWztCL8dP8BYpj+vTjxW9kwcMuwOSjzl+1JxhnAhIhIoiUGEIDIrQK6yNam4FI8Cu72PWAQ3gw4ADc0wCvWpmx9W9Jo6fBOc5sqWTaSF2D5xphpDMBUpmJmYWb4cwdw13JMDDLGmGjPysLZm4LLbdheN1yx346KfyEDCVZ7JaPJ4QcMZV5PZnaaLh2NWNp/7qra0RCJNw3i3pbB1W5kRMFMfCGdYPM6+mn7kY5ySFPbkTwwWhWwyKbXGE3hSBCkMAz+5os1jtUQTKEMDKriw0IC9zcdAeUKFBZmbuuS52Ztz/HbpAatmzEflEzsfGOwgULrmhG35kAlUuUmdJJL7kL7mlOOeYGETuLJPERVFkI6ZcKZ+6ikAlITB0b1QltVptrRgEmAgfGvDFPKhiA66npwJCDKV4WJEu+cezaymgCMQZsbgJcgg7rNjtWq7RBevBi5A45hiOKHSWbOQIdI6DfVownvtK2165CIw7Qq/crhqfljsyGG7b2x6v6Gx7oHeHGTTanszMxNy7tGcblMOwTF4gnA+TYxADS8jAYnFFJWw1Xr34xrsAK5yeEEidyRFjlS4YiRSRcWxJhJAiUsSTYizlCTAUgfojcriLSFzC5SgTLaGaaD7VdMg7VBO9Q7UQcTulmKcqWkhFWYyyiyhpl1MyWkGZwnJKiz+/POfnVswrWqV3RaCyEOh8oyrLbrV2nCDAoAGWQRwjvKzECBeDHZgZsVQ8i3VdXcIZbX+Fman8KtVRiisPMzMxcymJGPV4UYSNZMZ2LVOECQcj5ByRiwokf4uei9ykjgLj1MPosIRfcM62OIPZj5/wKVdoA5YACpgIkUcmIhEH16F/LQjeoofR/1jHM3kWu+Ag8PhnY7FdH+VzlMwtpcltz9MG4X9oM+852tx/jjY1c2ljfpo2dv+O3fXDJ2j96Clar/AUzQifppnhszS98F/IszS58DzVFl6k+ug1qs+/TJPaXqYNE/MbfdO4mPRSBCoQASX0Ie00VTbUCBhDDjpF4HR+MOZ3BkbYJ8ZZw4SzVwhjjWlA5kQOcYuWLZ95jwMDjbCNI1295wouBbKWlXYunyXfc8RYZuPTblr7UOTE5bjTCUhizhRPlhjb9SLORuS7VqoLltH09EKa1bCSdpi4hLafsCCWHeDuOAHxExeSuJK2I9J3nLyUdoLsMGkx7Th5Gc2avJx2QHjHyYvhLqKdJi6j7euW0MaJhbmt0qu8dqPUUQQqCgF5eyrKYDV2XCLAI9Vq5s6qnXMkUrLFgbBDvEEFz1IBZBXCjQzygKysB1LyDZlUavP5Ty2YVSozHl1gxrlsM7g8YmMtMXY1kp6HHQ5bhEPmOy5AOFkUhIEeOazSI8EXux5R/Nd/KfKiNkq7hTQ9+QJtUvMirZ94iWb6r9IM9wpNty/TdLgz6FWayW+QuOt7r9P65nVaz3uV1jOv0gYIr2depvU9rMbNc7SV/zRt4z1F2wRzaavEa7Sx9+bk6tb/6Z8aFntG7xWGAF6XCrN4HJs7LptusUwjcqOz7UJIYpojdpYMCJ8YBjPBaGwtcEBtLpjxxqLmc298vnm7V52rc855EGTFGcLobNRwWGUSqap64/lkjE++75MFsUcg9lJlbD0ikLpxHnA0xWh2ZOEtEFOBPHLAM8DWez0vo5mJN2n95OtUa+dTdbiUUoWFlC4soky0BLIMfolbQlXhMoSXxHkkX1W0iGqsxC+munA+1eReg7xCNeGbVIeJQq1dwVVtTai1aILeFYFKQkAf3ErqLbV1VCEgL4/vQgqiHCTEOS9oJ3RwkQJiCh1WlOnJXt5MOvrJl5c9+Lub37j2/JvfuPiiW9++8Du3Lzznu7e987Uf3vXmx656YuUJN7zqDrj5LffuW191m9/6upt21ztu0k1LXM3f57vMdXNd4sknXSCubN/PcS6eEJRcTBC4uwhQpTjxi0hY3HUtty+nKpuauGeBEtSWd8QmSSGW3n6Q6mKKce1BzHUMWSIOibyIImNJdkIQTUlqowmmkaZ5C2iifYfSnAXdMxkQPkNQgGJxhhgifkY8oz8Qg+16xnqfKWAiz8D1DMEhzCaImImMT+SlDOmlCFQgAvrgVmCnDY/JqrUnBJgZ4zyvlsTMiAcNuKg9zZIhR4w3irFaJ4QsMeXARInaiaElpO4AABAASURBVJSonVYbJSceRplpZ9jMjLNbvQlzmszESxZlUz99ZXnh1/99femf/v3S0psff2XxnY+/tPih++cuevTJJxY8+Z/nl/z7hYVLn7pt5eKnX1y05N8P/GvxkwbybYh398JHv3Pn/Ie/d9c8kYfE/f5d8+7/3l3v3Hfpne/c87275t3z/bsX/Avu3d+/e97d37t7/h3fueOtOy/5x5t3/ujehbde+ejyP/3mkYW/+e2D71z2mwffuvhX97997pX3vfmNK+9/4wyRX973+ld+ee8bJ19x/xufvuK+1z/2i3teO+mX97z+gSvufe19iD/2yvtePfx397188FX3vHrgb++dv/dvHnh7t1/d98aOV9/zyrZX3/fGVr+95/Utf3Xf/H3mPr3wW6022DUCkReEZJkpAjsbz4uxY5C3IeDINg6DiYmQjx0R9ujJmQJIHVFYp/vURjUmTxNdFqvwZuKoQBaTKiflCRf0kgiwj12ojZOwI+Ag1kVkbYEoFkwYDDoMjG7JIR53hg79KAIVigCe5gq1XM0eHwgYMCPJ6Eyj7rIwKwIpiYRwLc7NCctMx44cR+Tk500DogJIJ0TYSwQUesxZCaNdQToV1NVPqEqk0rWWgsnWedPYS27gJzIbJ1KZTVNVNZs7CrZ07G/jOLE18mwL/yzIjpb9nSKTenfOr9691dTtnvXq3wPZvdWr3yvrTdg769XvB9m3hWvEfW/Wm/DenD/hoFww8cA2f8KBywvpw+c1m/fPzyY+Ma8teeq8bOqs+W2J8+e3JS+Z15q8VGR+NvUjhH+6oDV55YJs6ncL2lK/R95rEX/dvGzib2+3pG59oyVzxyut6Ttfbk3c/0pT+pE3WlKPvAx5o9l/+O3W4KE3mqK7V4bJ0zlZkwiqiLwEx/xKINFcLhf3qQGhE4NkOUcWOFkQO4OUjZC6YMghEUjd2SyZqJVSQLbKJolyXlzeYVGNRThZrOQdWxIhZiIha8ki6RD20GMQ0y7YSkHfRBSingj5Q5TNc56ymVit3hSBikNACb3iuqwyDR6s1daxDMmDLT6s5cA5ZLGBaw1Ym/EqwVRmRwxSl1UnIdWBvgqFNnLOkfGZsFlOJjDkBQGFNqK2EIQSEeJxtowtaBMkUcJQwXIsDrq7CAcgrKIQ/BGnqOClKOQk5bECLrmRKcZbLx3H56xPrdaL89kEmBXsWkCZgslQwa+C1FAYVFOUqCObrIXUk0vVEaUnxq5LTYC/HlIenkg200Cuaiq5zCQRjtINyahqSrXNTKh36fqJftVE30vXoC0R2ZDIRY4oDCmV9IjRUgZGRA5+JLKsxEOECJfBQt0QASNDIXkgeqY8UdiGOZOlwKWRlgauBHEkPwwjGEfYHcFCHFodCJ3JwpHzehFJkwiHVTpKQL+FEPmeRwmIED0b1B+1WdJLEahABEwF2qwmjyMEnLOMK26xAymKX1wZoMUfJ/RwkzSRHpK6RImu8ohSGXFFJF2kPI/4Jc45JmKfnDUkfhdZEBa4ICYhSz7eLhx2k/EIlyOLeMIqkGK6CUlWoo5QFhMBB4mgL7SSKnE+WfLIcdG1oLyieHF8KQ0WkHHFlHIXhqCqiEquYUeYT8RaKArjeM+gHtQpthPsYNggIn4RibcWWdvzSFhE0kQs4sUOy9CDtmKhSw5n0owGS3tI9ItOEGjSc8Qg8iS2zQMh5kIL7MGqHLaTdeRA7hHEQiLoEv3GMfkRg7wdGRhisLXu+5YSCZ+yeSbiKjIuCTFAyqP4Drw8iPjJMuIMRNLEz8RERXFEWNDjVJ+JC8AjasOCPQ/JukwhhwjSSxGoOARMxVmsBo97BJgxCLdLEYyRuzNYTMQDqXvwg7cosARigIA0GKQk6WKhhc2EPASK6RQi1x4Wt4twMQ0qyDFIczWRdNE8MmLQHgMCZogH0jZkybiiLWKzLXqJEefJKhtEbuAaQkQ8sWnPAMcILtg7l3ZaKYwwW5+M4Bq7DNJmIIVVOhco9IgonjBQrJ+Rn3BJXXDKPqirPcQlF1HFfIhxUCRlUU8xDpk4QAJc/SgCFYaAEnqFddh4M9c567nisnDUNV0IwAM5BCADH+xVEiE1ERYiEpJyAaguwCo+QY7gxiJEwsXVIlINVqrYIEbYdkopTtxuQihTAsSyUKShgbowHSosSBIC/dBAYkf/3ZB8V6CEy8YS2BwFCPsgdwbJG7RWcEAl+FiIgxiycQt9irCSlhhCmG2AugOkYUcCEwVLchkyEi8SJjBJMljVh8ReK0V+WyzxeTnJJSUsSXh1CbvFO4SJHFou/UGUJMLxg4XrZCvfJYtmkV6KQGUhoIReWf017qxlXCPd6N7rx+uD1Z1FBsdCEPDg00Fi8SoUqXAlrkjYDvQVkQfi8yhC7tU/oktiu7qGJCwrWHEJZCR5RAzImMjSQF0pKwILybJogAzAlbLSJqmX45V3FNsgYWmv6KTYTuAkmUWAVwQijzigENvxjlliscr2yYtA6tYjQh6JBD3DLpTFpMhgJW0Q73GeAi9H1ssCjwjlCGK6icSVC9KJyvIw/B7EUHwx7iwowJUvOSTaQvj0owhUHALtT3TF2a0Gjy8E3GhsrhhV8IhyPlEervxSXGgstoOjmGwctoatKYDAIZzFlrGsZFso6ZpiSbgW0B1Wj7jb9lW2Ez+kN9cirVMIukPoHZwwoW6QmSvVPUA3Qv7Ybriig2CbiCWfLCxzEAvrHETixdo4P3YoQg4oiomdgBVSQeTsPJSAH6UtO7IgWSu6pbwj3B0FwDMwOfI4REHgCpInrOAJ5buIxJcLdkuoQxJEmDwQ0hl9RCYL03JFgW7SSxGoUASU0Cu048aL2c66LDNjOO/aYmzDYwt7teiumYY5VCScYiWOiWzRG9/jMOLELYq8aiJxMlaHRZcILktJiLgQI5pit5QGdxg/qJksbO2v65jJGSZmJkseRRALMi/q8GApk2M4iCMIO8KOhCXEYgVPHW2XPA6QWKI4zoOH490Gh/IhRcAgYqKQI4IKEvINqA3TgTymDA66UJiQgbpdUqFEobw4HRJnlRsEn474WHsETSHhUbO0sjrfmaY+RaByEJA3onKsVUvHHQIeswyulrlzBBYyHw1AyMvj25BK4oGMPDAPx0zlgSZwJowz2chlKKQMFThDeaqm0NXAX0eRq4qbISRmQI3i9iRxGtLFLRcpLKvkAlaxgxEpKzrKda7J77EDRdtYpKzoiLDSdiB1R4w2G3LoKmQDSVuQrgU+juKzdpunQMQVyLcR0rBDYEJig3wkGiJoiYhk9S0kDkKOkBZh/97KSppz5DN0AAs/wrl3lEApIueB8DukQNbLIy4Pt+iXsEjohYiLiiI60YGOsL3iAiiBwM8RW/JSBdJLEahABPBIV6DVavK4QcAY1+IbWxCSIKwKYxetj78nZx18tl3gdHzksS5JR+SQexjVG5CLEHnRX6pC6oZflp+xwQhjO5kgTigLZ8cxdYGICXlMTEtE4iJnmQsd+DDqIdQjbpHwEYmw5BWflOxN+o4vli7ebdGB3qKnv+FOK+K6wIfF8nEopngqi5M0Rh2CGTiVpE0S59C3pRqljRTjJikhvCFFIHZGZkyRKOEcyWpeUkWBkwkAdJa+DFeMi0Ej8YtYJlyWLGzpFMIuABO0EeGcnlCnYxfSNhQhs34UgYpDoPxtrDjj1eCxj8C2m2/YxIXmVs9jyoPAnWcoX8B46wyo0WsnPwfXYsVHEBOLwwgughiAZCDFj8OAXhSS8bsY2cNddgFEmJmYexcwBEqLfkOwgMQShxhUjwoi2BWRJytS8AROjcnnCHEF6CwQwRbJZ4njsqu7hhxIhlCiuzDaT8Cjs2aLXAMVmOBEDBX1MREMEn9vIumd4oC1jeuV/GIPoZ0iYrf8Xb0FN0aQkAMKGStq46FCJgcCR63EkUfOGiqwI/lTNEcEW3zycN7tOUPy9+c++p6NT/l8SGkQrx9FZHHW7SBEIfKjDFHRRRm2HnUXD3V0EVRkyFIe9oaEACZXjCfKUQE7Qs8hgvRSBCoOAVNxFqvB4wqBCdU0L2pduczIFi0Gdc8LKJlJU8LHcByBFGM0bHzvegM5dUT0lN6ROKQei2pFSkoZpFEUEI+QTyxiT0kkZ+k17O5KWt8CHqS1kb61rymV4qmI1C+TH4qv8nYRyZfGHcjbMYgbW/MW+EQgUMkvwg4RKCeOnJcTpgcGdMrOoF2GDCZT0IIcRAzSxQY5+cAUMwFyBnWxJcGXcHG5tJcv6el0CXqLQrh8HxoZFWKS4CxRkKhuZp4DHxL1owhUGAKmwuxVc8cZAjhiXWBbG5dSIUde5CjfVqAoX8CqDgspwkodeFgM9DICC1nEgrgSCcRe3BxGe4fBn0geeQgGfBJBWl8fIZ2+pK+y4yVN8OlvWweSt7tODxEMtmd26EULQUT8QX/GLm7SpyLwrukDNdgJkCeC46wRVvFsalvjgN4UgQpEoOxNqEDr1eQxj8B71qMV0yakHzW5NpLf7zJgZsZqj7E6CxLFgZgQR/Hwjse5fDCPCdy2Y1Ry24PqDAkCAyHo1fOiv7pY4RDq7CcE4o90I4sPHsaRBcsKXcLS7+X9LXEDECF0CgvkYUJInkf5yEBq5w5AhWZVBEYVAt3fqFFlnBqjCDCWY5tvMP2PUduqFpfLUuD5JL/lbR3OXG0BQzuTwyasA6HHgpE/Hucx+As9lPxdkAQJcLsQynVJ08CQIiAkXpJyxehXEpH+KfaBLU8mQv8RepeQoVReCNgg3sjODI5gCM8AEy70JZUEwYF85K8SSPbaUVfBec74kx4ZSHnNqwiMJgSU0EdTb6gtPSKw3lZ1cyfVBNf6Nu/kf9/K5yMqWIdxWDZhS49wyS1TgcE/JoWyKPWuOwRiwgbpCiH3VSs4u69kcsggOjC3w2o6IpbvIWC2xhASIu+zdG+JEo9JBHZ6yEVUCCOKTGJlsmbGi5KioghUIgI9jIKV2Ay1eSwjsC1zftP16u9IBLkmwmAeWku+nyE/UUUuXmHLYyxrNab4DB3e2AUoscvxyI8QkXiRTHoNLwJC5lKDuCLiLxchaBGK+689JZ6AtfvJtnukb4teNo4YBMwmRKlSuqRJnpJIuExEp0hZVFdvRELoofGdl6x9JFOzyRtd0zWkCFQOAvIWVI61aum4RaCu3rvf5le84VwWgzrGYPaprU3g6OkRbh/s+xzIWQqrDAMCzJ3YMnf6y6sSMhcpj+vuB38TM8pjFS5+I9M3ljPvCITOmJxJ34t0LzmAcARClzq8lHXp2id5/W2WD6B0r1k1QREYCQTW8m0YCZO1zvGIwJ7TahZPn5z8YbZl0TKyeTIspO5RiK1SD0+xjMlhWCDGVrzPpkgEAEpIoyQIdnyEIDwUYuY4L/Pg3A6FvXiYuSOlux3MnWkdmfrpYebY7n5m7zUb89DoKa+g1M6SW55W8jO31wuyJpF4RW6puKNSylV0mRksTquTAAAQAElEQVTb7g50bimVMmSjNsIdiYyHAA7BFadcZDIHsdjNIZQnY+JU2b4nI3+q5mFh3k7m5FHW+Vk/U3tfnElvikCFIlB8yivUeDV7fCGw666bXzuhyvw67YchhmQqtEVUnUmStSGFhRz5vqFEIkDYtv9pG2Ms75QuaLGLSaJLnAZGDAEh8s7KZYcFAkImUDfHhA+fswiFxDh2QfcRtcd3llvdZxIJciB1G4YkE4yOHJ5H7CeIgiS1Rh5Zr35hdabh0Y70Ue1R4xSBnhEwPUdrrCIw+hCQs/Rt15tyRdS05FmbbaPqtEe51hby2FIywCoOxJ5ry8YDdxAEFGDQLg76jMaIwOn2kUG+L+mWXYPDiIAr6yLx27K62BGI3EIKIPUILiKoeDkkSv4ugqQ4B8g8lG11w8SBT5LHRpYIUoiYLKWppZBYlaidcQHPOEr/Bh246adyEVBCr9y+G5eWH7l5/Wvr15mvuOySR72oxVUlPYrCPIX5fPzrcUkfKy8gE2+1YgXH7BHBJdAAouOPcxFIvyiEIT2O1NsIIwCSjftC3DJT4r7j9giksZB5SCRsLdKeUnSQXvR03C3InJmxy449HeNju152ZqAPz4WjJLXmky70JtxaO2GzG0ivGAG9VS4CSuiV23fj1vJP7b3JgxtNTnwzGS1/udDW6FI+U3VVGit1xpl6SMxMnhdQoVAgOSvvfMjFVxr0xRUhvUYlAl3ZWnrOgMUNttsJpE7YlelqdnlfdvqN55EHwTkMWUz6pIwnP/eK54NNkrJRTVP1pC1/ylP2b5Y0FUWgkhEwlWy82j5+EfjIHlPvmbXFtPcbm/1Lrq3F5rJNFILA5bzUIybfGGL2sBLHaixe5XVixeyIwfTMSOuMVt+IIGAGWKvFXktI5MqLdRI4xav88jQilpU5suAInvwgSSQasnnK5qLGdNWMs2u2+LD+mAxQWTcfrWU4ERjo2zSctqhuRaDfCDBY+eCNEk/vtPO7Tg1871eNK5a/JvSdyaSwGLOUy+WxYl/D473aKq/f1VdMRuBEfcmoaQgmWdSVpVczjYWRY8IGO8cusnTpQ4lHnHza46NQyL/I/gaTPPm2ewErdezeFNKZ+vOrd5r8C+BTVlAKqygClYnAGka8ymyUWj1+EDi0gRe894Cpp75n+82OyHDTz5vmv/qGaVvmahMheWErebYN2+4FwuEpCSE4xsYtJIJY48VAyRelxNOrixWdrOpcN1fKlETSREphVAivJdEZS3tZROJjywTeIfrE9TB11il+1BvHt7sEt1hd8dV3CEt6MQ6p4D4DssQGBnArxUKn5INE7FNJpGxnjjX5LEqXJIIf4kplYItj4jhoYD/CQsgxyTP60JBv0Z8gdMljUZokHXaSI5Js8vW2okTQUxTC1nyEMtLPBfKpzSUpG6aoMZ9+iaumfyKYvP/PmU+MSK8xg8B4bwjenPEOgba/0hHYgzl7whb8wmnvnfnFPbaYclRtYeEPCotfuL6Glv/Pyy5eGYTN1rN5igr5+Fw9wuBuOUH5iMl5PjmGC6aInCPrGDQBUgFpONmyhxuBIuJ4mQQgPXSEfHh1kA4fyoO4ZXJgAmLEsQNZUURQTbkwRxwk4npI0qzQoCM2lkKQFLPrFX5mGNVLasc385EFJpFotbC1JDJhiYWYImSQNohr4S8X+QldD9vQ7Jn4+wcE2xk4ONhmYBtbaDaCkU+RSVAbMMs7jzjlk7hQF9dKQE1EwuUii2KJZxAruZCMKyB/nnyXJwlHzsA+A1JGPSjoyCMCTq5jRmEoYZgCrKpTKE+WiYxHNsohHyZqaB/BXighIou0kIihmyQdruco54iylKRVUdWiRpryt6oZu30yvetF1/BG+7eRXorAGELAjKG2aFMUATpy1sS5p87e6RvH77vTJ47Y612HHL7rxu/edGpiVj01HTWjKrp0ZjXfkGhd9Fhh2dtz/dalL+eXvjWPmpas8LIrsl5bY97kV7pk2EJe1AIWWEWUbyU/zFJABUqA5HyQSgDXQDgKSUibQKcRiA+0TsxMHsiRKaQoQpl0hgoglELoyLGhIAhi/gkjh3weDdVluVMTeLEzICQXh2x8J4QlK7gaYUOeH9CqplaKUKi6uhqpjqy18d/zRyD3EFvWzEwtrc0U5rM0udajJCYjbcsbKSU/wQocHDBhEDZKQn3URcJ8jjxUmAg88kHMDkTsCoiD7kxAoNk8pUDuaUy4kthRSURt5BewsxI2kwlXkcuuJJdrIj9qCr2o0BTZVJR39VTw6on8emBaTSHXYfpUS2FUQ/l8xrXlUjZbqA7bovrGrJ3wajaaeGuUXP8T9dO32WfaZvt9IrPlSQ+RXorAgBEY/QXM6DdRLVQEBoYAM0dbNnDTFhmet/MUfuUDQvIHbnjLF/ec/PVT3lNz3HmHzdzjgE1Sux8+a8L+h81a/9i9Nm/4yBaT/JMb3IpT003vfDNofPuSZPOCy1Mti36XaFl0U1Wh8Z6qqPk/mULTm+mweUnGtramXav1bSsVsiA6EJQFudswIlsIQXwFElIUq3FW2/4ffxiQDpPFajciHwSKV88EICS4knGwghUuQQyouCRCriUpxYnrOUuwAKtki1Uy/A6VYiaQwaQD5oPYW4g9j4JMinIg2FaQMScYcRHVVQeU4ixlF86nTMtC2jCVc3WFZTblcgWPo9CjqM2nKOsb1+qJsF3pGbs8nfKXGBcusPnsPLb5t1O+/3o64b/GFL4UZlf9L5Nb/mQmv/iRqtziB6pyS+/JtC26K9228NZUbtHNydzCG1J2wXWBXXq1cat+V7C5n69sTfx4UVPNd+evmnLh/OZJ5725qua8+c215y3MN5y7ND/93GX5jb61MtryrCxvd3oY7PiJ5IR9D5q4286zJ+945u9Sm3zsJZ60O2ZpaLd+FIExiMBajiZjEBFt0phHgJntIbOmteyxfmbefpsknjh089StH9x1yu++fPjWP//GCTt/5xvHbf+tg2ZvffqHj9v6C589ZvOTjj90vWMPfXfDgdttnNp1+kSaNS2V32pGTX7Td9UXtt9wAh28Sb1/ysb13g8Q//uqaNlt3Dzvcde06HnTumyRza5q47DNpvCmyRe0QpC+wT60FyTIYcU+HGAbkLsH8hZhuCLil3jjijXGxI58mIEQFs5kPCYvERD5SWpqzVG2ENGECRMo6RnKrVxMtGrxKxvW8eFbrl+77YYT3eYbpPKbb1DvbbbBBG+zTep4040nRZttMjHafJMJ3hYb1Xubr1/nbbN+rbfdBmmetV5VbqdNpiR33vZdk9596C4Tdz9u38nvOf690/Y6/uAZ+33g0BmHvO/QDY44co8tjj7iiC2PPfbwjY8/9vDNPnjUITt++KhDd/roEUds9ckPHL7R54+bvc0pnzjykHP23m/3M7faZ9tvbnTQhXNm7H/Bhe866NsXbnDABRfO3Pfcb0+DTN/vnIun73f2pZP2OP3/anf+wg3pLU98nVnPyUmvUY/AUBhohkKJ6lAExgoCIHsHiXZhLmzE3DaFuXkT5sZt6nj5IZvWLP7ILg0LPrb3jLc+utu010/aZdp/P/PuqXd++t11P/ncLonTv7Jn9UfPPHjmke/bc/IBR+0488iDdtr4QxtP4M/VUPbvWMnahC1QgHV6kVwdOVkWDxFwDKIuSnHlLS+2IUclYZwzxwISZwhBWI4RTI7ybfL/kYRkMMloLTCZZDVVZ+op29hMrrkxWx22Xv3ujSd96lPvnnj7h3ao+d+Hd1//5dl7rP/KCe+e9tqHd5rwpshJsya9U5TMOx/bITPvUztVzRf5yC5VCz6x65SFH9quetHsjXnRrBpevCnz4s2Yl2zBvHR95uUbMq/YaAKvFJwRv2pL5qZtgbvILOYW5MluhL5AvxSYd4GcGMFvIdJXqwnppQiMUwTkvR+nTddmKwJDj4CQzLZTpjS/e8P61/acxv/6/G5Tr86Y3P8410IJjrDiZSKcHxPOnm189jy0NsgLLdKpFfVRUcB8ZRRfzIXTCQqwOhdbwnyBPORwhQIVmhuJW1c+sMHE5DFHHb35Z47Yuub+Tp3qUwQUgdGIQPGt7skyjVMEFIEhQcBEBSyUsQIGWZKNiKOIAmbysGomrJRpLa4iVXcqsFiTd4qsxQ1qMKjZxK5luO0SsUdh5JPhBPmOKe07qvLy2F6f1zKRV121784bfPDju0/6J1bKiOysQ32KgCIwOhFQQh+d/aJWjREErnPOy+WjjPF9tlgpw0+RIwqwve0QJjJD3lIHnUXxYyIXfwQSd9QZljiR0Bqs0AOSb67nls+PvOZ59+2/7bs2/upB63/ygPV5HumlCCgCFYPA0I8m/Wu65lIExgUCG4Ox8+QlC1gFRyZB1k+RDdLUXCByBn6sjHsDwsUr+N5Si/HMDh5LFnpEhKQtyDsixml9UZzxiP2ACjaiUL4k52Nj3TCJ/iBAfLbFmezy+Zs3JM85YKeZnzhkU17MjPkHNOtHEVAEKgcBJfTK6Su1tAIRSBGYldkI0UbY4o6YsfUNQpXTavhpLS8hZVHBzGSMISFvgp+FxCHEiCOiCNv8hJozKZ9sPkuF7CpKeY6yy+flGmr4t+/ZbsPdPrbHjO/sNi39OrLrRxFQBCoQgbFJ6BXYEWry2EXAi9fKlhgrbpYFNYiV4gVwHFirhjsXxeWZOXaF4FENVt8MceB2prCQI99YSnJEYHJKcY4mpLgQrnrnf++qt6fvNrX+tP3X43diBXpTBBSBikVACb1iu04NrwQEQKEBu6jKkGyEWzIgdw9iQMQG299FYl+7lrDMEjBBiHBibsHmRVJHSPwg89pMEiSOugstlAybKb9yYbaWsz/dd9tN9/rC/hv/ZJdNuHHtLNDSioAiMBoQUEIfeC9oCUWg3wiAKhNEXMcgb+NCEvFcgQKXw6Z7gRjxtBYXM8ercFFRJHKHMJHBGTk216k6HZDNNkFWUCpqaUnkV/xri+mZk3bdbvqc/TfilVJORRFQBMYGAkroY6MftRWjFAHjUxIL5zrHRCUZOlNtURW7okuWPLzRvufFLiPc2rSCAsqTbVm+eGpdcMaMQ7c8+MPvedffdpnIuipvR00dRWCsIGDGSkPGTDu0IWMKAWcosMZkIvYp7BBQrEli490Dya/9K1hamVPHBaIPC2TzbZSgqDETuD9v/a4Njttlj/V/fSLLQXpHRvUoAorAGEJg7UeTMQSGNkURGGoELJMfcZARvbJixkIdXrx2zpAjn2RxbRyi4g/iccou8UUphiVJ8hisuEUIrsQ5NhSJYPPeohzjzDzAtn4QZinIN5KXXfzKhGT+S0ftPfXjx+9Y+5D+QIygpqIIjF0EZMQYu63TlnVHQMPrGIElyyhIVjdUha3NlIiwYsYC2aeIKIzIcxQLg6CFsElI3gUI+cghJ+ABEXsUyS/ROJSxFhMAB+p2FNoCcZCgQpCipggaUDYd+OTnW63fXdySUwAAEABJREFUsuStDaqjXx2w44zZX9pvg2vkd9BJL0VAERjzCCihj/ku1gaOJAIvzF8erGzJpeUHXJIBk3yz3TCYnIgsCBpO+6f4KlqWoCPG+t2A2iWrw/Z5IpUkLwioLZ+Hm6B0uopWrVpFVLBU5eOg3lhqXbGYCk2L3txiWv2HP7bnzM/ss2HNcxx/BV50qigCisBYR8CM9QZq+9YhAlrVagjkswVDnu9zMk0htsbbsDK3IGvPYxKuxeKaSuKYsPrGyl3+FzSHbXObI9/lKZ1KUWtbSC1tlhJVE6gtZGpsaqFpE+uphvLEq5ZSIrvspQ0mJs7Yadupex2784SHVjNEIxQBRWDMI6CEPua7WBs4kgiYZII9P+GFxNQWERVwzm2NR84wRSB2IXGHc3BiixwhKD+PbfgC/I6IHbbbo3gln0ykyBhDuWwbpbC1Xp3OUMvKlRSuWGgnUtMd265Xd9Ln95r6/dlbNszXVTnppQiMSwSU0Mdlt1dkoyvS6LAQBW2FglewTNZPEIGYIxOAzIXQIWywsU4g8QhkXsCWfIEI5G4lxEkqmAQVrEEoomps2VcnHLlcC+VbVkV+ofXBzadlvrTbbpu87+htq54gvRQBRWBcI6CEPq67Xxs/3AiYfOgZF3lYNROW6iT/gYr8rjrW3hQkPCJXfAXB952mIE7CIsYPiHyfWrNZyhdylMIWe7hyoa12jXe9d6cZH/7we6b+fK8GbuosrD5FQBEYrwiY8dpwbbci0AWBYQpkks6mPRd6jJV1ZEm+4MY2ogBb7yJYt6NmgxV7QCEXxTHjLN1i1R4SoVwkvyaHM/i2Qr4t39J417bvmvTesw571xF7z+C3SC9FQBFQBNoRUEJvB0IdRWBYEChkicMcsfxvZzYknw2lfI98nJ+HbdmYuIv1yta7xPogdx/b8MVXM8q1UorzNmpZ1JZ2jVfsutUGJ52404T7mDkqltO7IqAIKAJFBIqjRtGvd0VAERhiBLyI88aGOVmZJwxTwEQ2zJPPjHNxIt95xJYhEcmX3gqOKcK5eeglKCTER81U4xp/v+cmNQefe9jGXz1wY15EeikCioAi0AMCpoc4jVIEFIEhQmDLbTdqDgwvTqfTFBYsFazD6tvHeTi21P0kBb4hE+Xh+iQ/4crsUUvzKorami23Lps3JZmfs/8O0089covaB5ix/z5EdqkaRUARGHsIKKGPvT7VFo0iBNJT6e1CmPtXLpdzBWeIE2kqcIJynKa88yjf3ES1qYDCXJ4Iq/MQq/fqJDdO8tt+vtdWkw//yv4bnr/jBF7ZZ5M0URFQBBQBIGAg+lEEFIFhQmAX5sLGMxvuDVx+VWBkE91SGBbIC6RCR5lMilatWERVQUR+2/LWqsKyN6f7zWceu/+Urx22cfJZyaWiCCgCikB/EFBC7w9KmkcRWAsEdgqqb0rZVeeGq+Y/Ry2LXU0QUtjWRFHYSk2tq8j3KMst8/48a0r05X23Suz+xX2nX7kZc24tqhzKoqpLEVAEKgQBJfQK6Sg1s3IR2HZbzp928CY/2X3zqcfMSOd+NMmsuItXvPbQ9Ex465Qq+/UNJycPOOLwLT597E7Tfr3/RlMW6ll55fa1Wq4IjCQCSugjib7WPW4QAEnbo7aue/kL+73rtC/uPfOgS07cYa9T9px05Cn7TL/0Y7tNfWRb5uZxA0Z5Q9WvCCgCQ4aAEvqQQamKFAFFQBFQBBSBkUNACX3ksNeaFQFFYHgRUO2KwLhCQAl9XHW3NlYRUAQUAUVgrCKghD5We1bbpQgoAsOLgGpXBEYZAkroo6xD1BxFQBFQBBQBRWAwCCihDwY1LaMIKAKKwPAioNoVgQEjoIQ+YMi0gCKgCCgCioAiMPoQUEIffX2iFikCioAiMLwIqPYxiYAS+pjsVm2UIqAIKAKKwHhDQAl9vPW4tlcRUAQUgeFFQLWPEAJK6CMEvFarCCgCioAioAgMJQJK6EOJpupSBBQBRUARGF4EVHuvCCih9wqNJigCioAioAgoApWDgBJ65fRVxVn61FNPNXxzzrd3ee/Bh5932NHHXXvM+97/10OOOPrPBx521Omf++IX93nyySfrKq5RarAioAiMZQQqum1K6BXdfaPT+Msvv7zh4u/98FNfPv0b19xx5933NbXm5yxatvID8xevOH5Fc+uJK5qav/fU3Of+8YWvnv7rCy659NMPPvhgzehsiVqlCCgCikDlIKCEvg776uGHH06fM+fCE/Y+4IA/7XvggX/f78DD/r7voYfdvO8hh92wzyGH3ihS7pfw3gcfcmMsBx5yw96QvQ44+G97HnjwjXsdePANIvsccPCN5bIv8uxz4CE37nvAoTfDfxP8NyH95tg98JBSOC4DXTfvc+ihN+998KG37nPwIbcV5dBb9zv40NtF9j/o0H8ceNiRf9p7v/1Ocs5xf6B6/vl3Jt1wyz/+euPNt/7US6QPrJvYkElX19CkyVOouqaOamon0sRJUymVrknX1NYfd+cdd/7klC+f+st77nlycn/0ax5FQBFQBCoWgWE2XAl9mAEuqb8Jq9BTv/71S++6++5fNbe2vb9g+chcVDgyly8clSsUjskXwtkiuTJ/HnFhZGfH4uwxISQid6x1bnZk+ZjIuWMKjmcXyM0ObdEtRIQ4O7tg3VGIP7oQuqPzzh4VuzYqhWcj3+xQ4gvRUYUoOrwQ2cNiCd3hudAdmi+4Q+EesnJl4/uzufDHRxx97En33HOPX2pPT+4PfvCD9c88+7Sf5QrRezLVNUnjBVywESXSaSpYS84wReSoUChQKpUSFZzKpJNVtXUf+NYFZ16gK3WBREURUAQUgcEhoIQ+ONwGXGrB8y+eWFtd96lMTU3dpMlYoVbVUrq6jqoyIjVwexYsb6knSVdVUzoD6cNNpasIxEqZqpoe3aoM4jMZ1J0p6oK+JPSJJKprKQUbayc20KSp0+vnvvjipW1huHtfDX/wkce+unTZ0vclEonA+B6RZ8jzPIqikDwUZBeRIfgNyD3MkWFHJpEkP5mhRKbqI2/PX3QIsulHEVAEFAFFYOAIkBL6IEAbVBF2My1zipwhx4Adru2AH+F+K5W8IlKg0y1uiIvuYnx/wsU8kr+riH2OmCwTgXJJdtsbGhqmekGqoWvOztCcOXPMysbG/WtqajiRSlJYsBSGYWcGtrGfHZzYLx5HbW1tFKTTZEOquuGmm/Z3zvW5C4DS+lEEFAFFQBHoAYESI/SQpFFDiQCISrAGRfaktUh2PaVQTPpC1CUByXJnTnaWBi+desp9sT5QucR5PhODhcNcnnLZZonqUaZMmbljS2t2piRabK/Lyly21WXSIGLRDotE8cMhxxyL8QMJog7muf977nO33HtvfRyhN0VAEVAEFIEBISAkM6ACA8msedeEgFDcmvJ0JfA15x66HIYsRYU82ahAvmew9Z/uVbnjcMsoijIQIWfyfT9efWMigxW+i4VA6iJOXOxQiBsEAeXzefKCBAXJhHfnLbds2WslmqAIKAKKgCLQKwJK6L1CMzIJDtvxXaSd/AgEWFzlCs0WZTgslAeiKLZDvXyJLYOzdmbLHZHdPKlEKkAe9nBmLit0ESF1LMPjGYkjWZETpggQaHEQUSHb8sxMxuB0HVv0zY3NW5BeioAioAgoAgNGQMbuARcaHQXGlxU9UilI3nGpCwfpig6ZNPQCZyKRIGamlpYWamltcb1ko8bGpvlYaeeZQdzOURjlScp2yR+zuCEmj5iLEiFOiF+IXaSqvn4x6aUIKAKKgCIwYATMgEtogWFCQLpCpKjegmRjwUrWQoqxnXfj2v1CyCB1h/xuMC7KEMqKWLidUtQvW+iyLS5uTbr333+pqko+1tbW1iikLGfnkr+5ufczdwv1In5cP5Hkr6urs7vO2vZJJOlHEVAEFAFFYIAIdDLIAAuO9ewV1T6QemzvYF0UFnKF0+UjcbIVLtvnQSJB+Sjqkl4e+NznPte40UYb/MfaKD5zTwY+VaWTxOSI2MGFI36Sq/jYyd26EOf0IWHH3aUzmb/uftJJyyWHiiKgCCgCisDAEJAxdWAlNPegELDCjmUlHbalRcqiil4hZZFiiORMWla9bB3JqtyXHrMhJQKPjEfEDMo0TJaLZ9Ml1yFOpBTu1W1flRPcolD7ZWJXbCxtiXs4H48je7ntuccev1q6dGlOyojNsur2QOYeE2x34PWIJEyw3+K8XNR4bBBHlMu2rfz8Zz559WbMOYlXUQQUAUVAERgYAsVRe2BlNPcgEMAKtKxUz14cJ6+WINvWtbW1FAQBMRg935Yj3zC1tbZQIdeGNW9EzkXEIPyeXBSBTgtChUOrux4xsZAure56zPFWuJTEGXouWgPZfuCEE/613XZbf3XFsmVLPDxZqaRHYR72wkpyBUwZHGzOU8L3KBkkKJBMWNEvXbxw2cT62l9ttuGG95BeioAioAgoAoNCAMPuoMppoUEgwCykyR0lmTv95WQuq+lSpkn1E6hlVRM1rVoZE7mQue8x1VSlKeV78epWVr3Cjb4hKrkGJF0eLsWLK/klXVys7UG0FnQOsgfhl4fl79FlVZ7P5ymbzb7g+f6LJbt6ctdff/3sH6+66uf1ddXnzXvnzZVLFi2i2poqyrY2kw+bU8mAUomAwkKObFigpQsX0Dtvvb5i9913Of3vf7vu7F122aW1J70apwgoAoqAIrBmBEABa86kOYYLgdXhLydzqXXFihWUSmM165t5K5YvfbaQyz67cunSZ5cuWfzfxpUrnm1tXPlsy6rGZ1atWv6fpsaV/xG3ubHx6aamFU8j/PSqxuVPN61cCXfZM00rVzyzqnHZs82NK59pWrVc3P82Ni7/L+Lnrlq17H9NjSv+17hyyXOrVix7buXKpc83rlz+4qrlS//X3Nj4ry9+8fOffe8ee7wmNq1J7rjlll999eSTd333TjucPXXyhL8X2rKPw8a5b7/xxty25sanm1eufHSj9Wbeuvvuu572kQ+8b7+fX375H5g5XJNeTVcEFAFFQBHoHYHVGaX3vJoyhAiAwMq09d4NQuYtTc00ZUrDz77+jTOOOPX0U4/45tdPP/zrXzv1iDPO/vIRXzn91MPPOOXkw77xlS8d+s3TvhK7XzvztMPOPOXkw792Btwvn3z4mZCzT/vK4SJfO/2rHe5ZX/3yEd887ctHnH76V48469QvHyny9a+ccZTImad/9egzTv/q7FO/duqRp3/lS0eedfrpT8BmV2Z0r17kK3z+859/+ac/+tElv/r5z48+7ZQvHgw58ryzzzvyK1/6wuEXnPvNA6+84idH/uSyH1z2zW9+81nkVzLvFU1NUAQUAUWgfwj0ziT9K6+5BoEACKyjVPlWe0dkmUe+kBZFBapKpRuPP/zwd0SOOuqoecccc8zbxx9+/Dsnwn/88ccvOO644xbPnj17kbgnHnHEQokrueJH2nwRyV9yRYfIiUcf/daxxy9tKmwAABAASURBVB77hsgJJxz5msiJs2e/Annxg4g/8cQTs50mDdyH8o2w4c3jjz8CcvyCQw45pGXgWrSEIqAIKAKKQF8IKKH3hc46SuuJ1OXLbCIusrEVcvYde/SmCCgCioAioAj0gIASeg+gjIao0ll65IqEbrxgNJg17DZoBYqAIqAIKAKDQ0AJfXC4DbiU/B26/H12ScoVME6mmeQPyCBsiCFETELqpe15+T11qrALbfUg/hrEW9fNgj0GEkCSc+bMqT3zzHO2OvXMs4776pnf+PzXzvrWJaef9a0fnHbWeZdBvnfqmed+58xzLvzWKaee+eFvzvn2Lvfcc0+1lINIu3hd2o46Bc9ykXaIlMeJ3wzELugVHcHbb7+dPvXUb2z8tbPOARbfPPkrXzvj7C+f/o3zTv/GOWeddva3TjrljDM2mTt3can966zfYB/3RwbS5rXJC1sEY+l/cUvSPbxW+KAOaXOvupFeShN3UP39unOpM+fMWe+0s845/CvfOPurp37jnDmnnX3uxXDPO/Xr3zztK2ecdeRnv/71utdffz2F+qR96/R5X5s+Gq9lB/QgjFeQhrPdQuY96QfHd4l2bLtHdUkfTYHrbr112sc/c8pnttph1yt33efAP+2274HX7b7PAX/ZY78D/vKe/Q64bvf9DvjLbvsf+Nf37H/gdTvsvufPvvb1sw/DgLFWA+Ca2g/95k833LDJYcee8NFNt5n1w1332f/2g4465qV/PfTEsgefeOK5Rx594vpHnnjq5488/u9vwD3t0SeeOhVy+kOPPf71R5584oJHn/rPH275xx1PfOvbl67Y+8Ajnt9xt72v3Xbn3c74znd+MGtNda9t+nW33dbwic9+/nPb7rL75dvs8O6f7Ljrey7fdrudL3/3Hntfvv2ue12+5S7vuXzWrnv/eLd93/vTnd69+0+32Wa7C6699tq911Tvww8/nP7S175+2E7v2ed7s9691x0f+NhnFj7w5GOv3P/QI9c//PjjP33qv89d9OR/np1z/yOPX/zAw4/9/rEnn33lC6d/eskOe+4/d6e9D/jtF884+5N33HHH+muqZ7Dpb7311oy9Dzrk07vsve83t9xpl3M23X6HczZvl60R3n7X3c/Zepddztlml13mbLnDTud854c/nD3YuvpT7qFnnpmy2177n7zje/b6xazd9756p732uxr+q3bde7+r8VxftfOe+1y13S67XbXNu3f/3Z4HHPiLQ2af8OnXFi2a2h/d5Xkee+yxSbvtc+AZO79nvyt32mvvq3fZc5+rd91j76tFfyx77XPVjnvt87ud9tznt9vusuuvttpx53Ov+etfNyvX0ZN/7ty51b/89e+O3nSrbS7cY98D7v3kYbPnP/TgE2899NiTtz7y2L9/+OgT/z4PctZjTz4159Enn/rBo//+z9+f/8/c5R/93Jde23rH3W46/LgTzr72xht3w7vk96Rf40YeASX0ke+DbhY4hB3W5w5u+4eL2+7toVHt4GUPrvjxFec8+PCDP5m5/gafSKdSx6dT6WNTmdQxiVTqmGQqdWwqlTomncrMTqZTx9bX13/277fc8pvzLrroBJQd0udR9C1evLj65jvu2OhDH/vURd869/wb589fdAXs+koimT4gX4g2SKQDP1WVpEx1FVVVVVE6nSbYRekM4qpSVF2ToWQySXUT6mnq9GlUU1frJ9L+Rpnq9Am1dbUX/e6aP/z14COO+vYD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" alt="Eianun Logo"></div>
      <div class="brand-text">
        <div class="brand-kicker">Eianun Network Panel</div>
        <h1>Eianun免费聚合落地IP 节点管理系统</h1>
      </div>
    </div>
    <div id="status" class="status"><span class="status-dot"></span>服务加载中...</div>
  </div>
  <div class="btn-group">
    <button id="refresh" class="btn-primary" style="background: var(--success-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      更新节点
    </button>
    <button id="check" class="btn-primary">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18.5" /></svg>
      非中断检测补齐
    </button>
    <div class="dropdown">
      <button id="admin_btn" class="btn-primary" style="background: rgba(152, 186, 220, 0.10); border: 1px solid var(--border-color); color: var(--text-primary);">
        <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg>
        管理员
        <svg xmlns="http://www.w3.org/2000/svg" style="width:12px; height:12px; margin-left: 2px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3"><path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" /></svg>
      </button>
      <div id="admin_dropdown" class="dropdown-content">
        <a href="javascript:void(0)" onclick="openSettingsModal()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          面板设置
        </a>
        <a href="javascript:void(0)" onclick="logoutAdmin()" style="color: var(--danger); border-top: 1px solid rgba(255,255,255,0.05);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>
          退出
        </a>
      </div>
    </div>
  </div>
</header>
<main>

  <!-- 当前连接活动节点卡片 -->
  <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
    <!-- Rendered dynamically by render() -->
  </section>

  <section class="stats">
    <div class="stat">
      <div class="stat-info">
        <strong id="total">0</strong>
        <span>可用节点池</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
      </div>
    </div>
    <div class="stat">
      <div class="stat-info">
        <strong id="target">3</strong>
        <span>目标储备数</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      </div>
    </div>
    <div class="stat">
      <div class="stat-info">
        <strong id="active">0</strong>
        <span>已激活连接</span>
      </div>
      <div class="stat-icon-wrapper">
        <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
      </div>
    </div>
  </section>

  <section class="proxy-test-section" style="margin-bottom: 24px;">
    <div class="stat" style="display: flex; flex-direction: row; justify-content: space-between; align-items: center; width: 100%; box-sizing: border-box; flex-wrap: wrap; gap: 16px;">
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
        <div class="stat-icon-wrapper" style="background: rgba(132, 191, 241, 0.10); border-color: rgba(132, 191, 241, 0.18);">
          <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary);"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
        </div>
        <div>
          <h3 style="margin: 0 0 4px 0; font-size: 16px; font-weight: 600; color: var(--text-primary);">本地代理出口检测 (Port 7928)</h3>
          <p style="margin: 0; font-size: 13px; color: var(--text-secondary);">
            测试本地 HTTP/SOCKS5 代理是否成功通过当前 VPN 节点出站，并获取实际出口公网 IP 和延迟。
          </p>
        </div>
      </div>
      <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-left: auto;">
        <div id="proxy_test_result" style="text-align: right;">
          <div style="font-size: 14px; font-weight: 500; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 8px;"></span>
          </div>
        </div>
        <button id="btn_test_proxy" class="btn-primary" style="height: 40px; padding: 0 16px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          测试代理
        </button>
      </div>
    </div>
  </section>

  <section class="toolbar">
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="mobile">移动IP</option>
      <option value="normal">普通/未知</option>
      <option value="hosting">机房IP</option>
      <option value="proxy">代理IP</option>
    </select>
    <input id="search" placeholder="输入国家、位置、IP、ASN、运营主体等过滤节点..." />
    <button id="btn_batch_test" class="btn-primary" style="height: 42px; padding: 0 20px; font-weight: 600; background: var(--primary-gradient);">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      批量测试本页
    </button>
  </section>
  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 110px;">状态</th>
            <th style="width: 100px;">延迟</th>
            <th style="width: 220px;">IP 地址 : 端口</th>
            <th>物理位置</th>
            <th style="width: 100px;">ASN</th>
            <th>运营主体 / ISP</th>
            <th style="width: 110px;">网络质量</th>
            <th style="width: 110px;">IP 类型</th>
            <th style="width: 100px;">欺诈值</th>
            <th style="width: 110px;">黑名单</th>
            <th style="width: 160px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div>

  <!-- Settings Modal -->
  <div id="settings_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          面板设置（账号 / 密码 / 端口 / 来源 / 地区）
        </h3>
        <button type="button" onclick="closeSettingsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='rgba(255,255,255,0.05)'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="settings_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="settings_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="settings_form" onsubmit="saveSettings(event)">
        <div style="border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 16px; margin-bottom: 16px;">
          <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); font-weight: 600; margin-bottom: 12px;">面板访问与节点拉取配置</div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_port">网页端口</label>
            <input type="number" id="settings_port" class="input-field" required min="1" max="65535" placeholder="8787">
          </div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_suffix">登录安全后缀 (仅字母数字)</label>
            <input type="text" id="settings_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_target_countries">拉取地区过滤 (留空 = 全部地区)</label>
            <input type="text" id="settings_target_countries" class="input-field" placeholder="例如：JP,日本,US,美国,GB,英国">
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">支持国家简称、英文名或中文名，多个地区用逗号分隔。保存后会按指定地区重新拉取节点。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_node_sources">节点来源</label>
            <select id="settings_node_sources" class="input-field">
              <option value="vpngate,vpnbook,ipspeed">VPNGate + VPNBook + IPSpeed（推荐）</option>
              <option value="vpngate,ipspeed">VPNGate + IPSpeed</option>
              <option value="vpngate,vpnbook">VPNGate + VPNBook</option>
              <option value="vpngate">仅 VPNGate</option>
              <option value="vpnbook">仅 VPNBook</option>
              <option value="ipspeed">仅 IPSpeed</option>
            </select>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">IPSpeed 会从 ipspeed.info 的 OpenVPN 列表读取 .ovpn 文件；VPNBook 密码会自动从官网读取。定时刷新只更新节点池，当前出口正常时不主动断线。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_target_ip_types">自动选择 IP 类型优先级</label>
            <select id="settings_target_ip_types" class="input-field">
              <option value="residential">住宅优先（推荐）</option>
              <option value="mobile,residential">移动优先</option>
              <option value="normal,residential,mobile">普通/未知优先</option>
              <option value="all">不限类型</option>
            </select>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">这是优先级，不是硬过滤。自动故障转移会先按所选类型找节点；没有合适节点时再逐级兜底，代理/Tor 默认排在最后，避免服务停摆。手动切换仍可确认后强制尝试。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_auto_select_best_node">检测完成后自动优选节点</label>
            <select id="settings_auto_select_best_node" class="input-field">
              <option value="1">开启：检测后主动切到更优节点（推荐）</option>
              <option value="0">关闭：只在断线/失效时故障转移</option>
            </select>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">对应 AUTO_SELECT_BEST_NODE。关闭后不会因为检测到住宅/移动等更优节点而主动跳转，但节点失效时仍会自动故障转移。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_auto_select_allow_active_switch">当前连接正常时是否主动切换更优节点</label>
            <select id="settings_auto_select_allow_active_switch" class="input-field">
              <option value="0">不主动切换：检测不中断当前出口（推荐）</option>
              <option value="1">允许主动切换：发现明显更优节点时会短暂断线</option>
            </select>
            <div style="font-size: 12px; color: var(--text-secondary); margin-top: 6px; line-height: 1.4;">对应 AUTO_SELECT_ALLOW_ACTIVE_SWITCH。推荐关闭：16 分钟定时检测只更新节点质量，不会因为优选而断开正在使用的代理。</div>
          </div>

          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_new_username">新管理账号 (留空则不修改)</label>
            <input type="text" id="settings_new_username" class="input-field" placeholder="留空则不修改">
          </div>
          
          <div class="form-group">
            <label class="form-label" for="settings_new_password">新安全密码 (留空则不修改)</label>
            <input type="password" id="settings_new_password" class="input-field" placeholder="留空则不修改">
          </div>
        </div>
        
        <div style="margin-bottom: 24px;">
          <div style="font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-secondary); font-weight: 600; margin-bottom: 12px;">安全验证 (必须输入当前账号密码)</div>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="settings_curr_username">当前管理账号</label>
            <input type="text" id="settings_curr_username" class="input-field" required placeholder="请输入当前管理账号">
          </div>
          
          <div class="form-group">
            <label class="form-label" for="settings_curr_password">当前安全密码</label>
            <input type="password" id="settings_curr_password" class="input-field" required placeholder="请输入当前安全密码">
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeSettingsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="settings_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>
</main>
<script>
let nodes=[], state={}, testingNodeIds = new Set();
let currentPage = 1;
const pageSize = 11;
let currentPageNodes = [];

const $=id=>document.getElementById(id);
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"clean_residential": "干净住宅", "normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端", "risky": "高风险"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP", "tor": "Tor 出口"};
  return dict[t] || t || "-";
};

const translateRiskLevel = r => {
  const dict = {"clean": "干净", "low": "低风险", "medium": "中风险", "high": "高风险", "unknown": "未检测"};
  return dict[r] || r || "未检测";
};

function isCleanNode(n) {
  if (state.allow_risky_ip_connect) return true;
  const riskLevel = String(n.risk_level || "unknown").toLowerCase();
  const ipType = String(n.ip_type || "").toLowerCase();
  const fraudScore = Number(n.fraud_score ?? 100);
  const maxScore = Number(state.max_auto_fraud_score ?? 25);
  const blacklistCount = Number(n.blacklist_count || 0);
  if (riskLevel === "unknown" || !n.risk_sources) return false;
  if (blacklistCount > 0) return false;
  if (fraudScore > maxScore) return false;
  if (["medium", "high", "blocked"].includes(riskLevel)) return false;
  if (["proxy", "hosting", "tor"].includes(ipType)) return false;
  return true;
}

function riskBadge(n) {
  const score = Number(n.fraud_score ?? 0);
  const clean = Number(n.clean_score ?? Math.max(0, 100 - score));
  const level = String(n.risk_level || "unknown").toLowerCase();
  const hits = Number(n.blacklist_count || 0);
  const title = [
    `风险等级: ${translateRiskLevel(level)}`,
    `干净度: ${clean}`,
    `欺诈值: ${score}`,
    `检测源: ${(n.risk_sources || []).join(", ") || "未检测"}`,
    `风险标记: ${(n.fraud_flags || []).join(", ") || "无"}`
  ].join("\n");
  let cls = "not_checked";
  if (hits > 0 || level === "high") cls = "unavailable";
  else if (level === "clean") cls = "available";
  else if (level === "low") cls = "not_checked";
  else if (level === "medium") cls = "unavailable";
  return `<span class="badge ${cls}" title="${esc(title)}">${score}</span>`;
}

const translateCountry = c => {
  const dict = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
    "United States of America": "美国",
    "USA": "美国",
    "America": "美国",
    "United Kingdom": "英国",
    "Russian Federation": "俄罗斯",
    "Russian": "俄罗斯",
    "Viet Nam": "越南",
    "Vietnam": "越南",
    "China": "中国",
    "Taiwan": "台湾",
    "Taiwan Province of China": "台湾",
    "Hong Kong": "香港",
    "Singapore": "新加坡",
    "Malaysia": "马来西亚",
    "Indonesia": "印度尼西亚",
    "India": "印度",
    "Philippines": "菲律宾",
    "Australia": "澳大利亚",
    "New Zealand": "新西兰",
    "Canada": "加拿大",
    "Ukraine": "乌克兰",
    "France": "法国",
    "Germany": "德国",
    "Netherlands": "荷兰",
    "Sweden": "瑞典",
    "Norway": "挪威",
    "Spain": "西班牙",
    "Turkey": "土耳其",
    "South Africa": "南非",
    "Brazil": "巴西",
    "Argentina": "阿根廷",
    "Chile": "智利",
    "Mexico": "墨西哥",
    "Egypt": "埃及",
    "Romania": "罗马尼亚",
    "Poland": "波兰",
    "Kazakhstan": "哈萨克斯坦",
    "Georgia": "格鲁吉亚",
    "Mongolia": "蒙古",
    "Saudi Arabia": "沙特阿拉伯",
    "Iran": "伊朗",
    "Iraq": "伊拉克",
    "Colombia": "哥伦比亚",
    "Cambodia": "柬埔寨",
    "Ireland": "爱尔兰",
    "Italy": "意大利",
    "Switzerland": "瑞士",
    "Belgium": "比利时",
    "Austria": "奥地利",
    "Denmark": "丹麦",
    "Finland": "芬兰",
    "Portugal": "葡萄牙",
    "Greece": "希腊",
    "Czech Republic": "捷克",
    "Hungary": "匈牙利",
    "Israel": "以色列",
    "United Arab Emirates": "阿联酋",
    "UAE": "阿联酋",
    "Macao": "澳门",
    "Macau": "澳门",
    "Iceland": "冰岛",
    "Luxembourg": "卢森堡"
  };
  return dict[c] || c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => translateCountry(n.country)).filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function canonicalIpType(v) {
  const raw = String(v || "").toLowerCase().replace(/[\s-]+/g, "_");
  if (["clean_residential", "residential", "home", "isp", "住宅", "家宽"].includes(raw)) return "residential";
  if (["mobile", "移动"].includes(raw)) return "mobile";
  if (["hosting", "datacenter", "data_center", "dc", "vps", "cloud", "机房", "数据中心"].includes(raw)) return "hosting";
  if (["proxy", "vpn", "代理"].includes(raw)) return "proxy";
  if (["tor"].includes(raw)) return "tor";
  return "normal";
}

function getFilteredNodes() {
  const q = $("search").value.toLowerCase();
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  return nodes.filter(n => {
    if (selectedCountry && translateCountry(n.country) !== selectedCountry) {
      return false;
    }
    if (selectedIpType && ![canonicalIpType(n.ip_type), canonicalIpType(n.quality)].includes(selectedIpType)) {
      return false;
    }
    const searchStr = [
      n.country, n.country_short, n.ip, n.remote_host, n.proto,
      translateQuality(n.quality), translateIpType(n.ip_type), translateRiskLevel(n.risk_level),
      n.source, n.location, n.owner, n.as_name, n.fraud_score, n.clean_score,
      (n.fraud_flags || []).join(" "), (n.blacklist_hits || []).join(" ")
    ].join(" ").toLowerCase();
    return searchStr.includes(q);
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if ((b.score || 0) !== (a.score || 0)) {
      return (b.score || 0) - (a.score || 0);
    }
    return a.id.localeCompare(b.id);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n.active || n.id === activeNodeId);
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
              <span style="margin-left: 12px;">风控: <strong>${esc(translateRiskLevel(activeNode.risk_level))}</strong> / 欺诈值 <strong>${esc(activeNode.fraud_score ?? "-")}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  const shown = getFilteredNodes();
  
  $("total").textContent=nodes.length; 
  $("target").textContent=state.target_valid_nodes||3;
  $("active").textContent=activeNode?1:0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const targetInfo = state.target_countries_display || state.target_countries || "全部地区";
  const ipTypeInfo = state.target_ip_types_display || "住宅IP";
  const failoverInfo = state.failover_country_display || targetInfo || "未固定";
  const sourceInfo = state.node_sources_display || state.node_sources || "VPNGate + VPNBook + IPSpeed";
  $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：http://127.0.0.1:7928 | 来源：${esc(sourceInfo)} | 拉取地区：${esc(targetInfo)} | 自动IP优先级：${esc(ipTypeInfo)} | 故障转移地区：${esc(failoverInfo)} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`;
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        if (state.last_check_message) {
          pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
        } else {
          pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
        }
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr><td colspan="11" style="text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      
      const isTesting = testingNodeIds.has(n.id);
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Always keep the manual switch button visible.
      // If the node has not been tested, clicking "切换" will guide the user to run detection first.
      const isUnavailable = n.probe_status === "unavailable";
      const riskSources = Array.isArray(n.risk_sources) ? n.risk_sources : [];
      const riskLevel = String(n.risk_level || "unknown").toLowerCase();
      const isUnknown = n.probe_status !== "available" || riskLevel === "unknown" || riskSources.length === 0;
      const cleanOk = isCleanNode(n);
      let switchTitle = "切换到该节点";
      if (state.is_connecting) switchTitle = "当前正在连接其它节点，请稍候";
      else if (isUnavailable) switchTitle = "该节点当前检测为不可用，可先重新检测";
      else if (isUnknown) switchTitle = "该节点尚未完成可用性和 IP 风控检测，点击后可先检测再切换";
      else if (!cleanOk) switchTitle = `IP 风控未通过：${translateRiskLevel(n.risk_level)}，欺诈值 ${n.fraud_score ?? "未知"}，黑名单 ${n.blacklist_count || 0}；手动确认后仍可尝试`;
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" title="${esc(switchTitle)}" ${state.is_connecting ? 'disabled style="opacity:0.45; cursor:not-allowed;"' : ''} onclick="handleSwitchClick('${esc(n.id)}')">切换</button>`;
      
      return `<tr ${rowClass}>
        <td><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td>${latencyText}</td>
        <td class="mono">${esc(n.ip||n.remote_host)}:${n.remote_port||""}<br><span style="font-size:11px; color:var(--text-secondary);">来源：${esc((n.source || "vpngate").toUpperCase())}</span></td>
        <td>${esc(displayLocation)}</td>
        <td class="mono" style="font-size:12px; color:var(--text-secondary);">${esc(n.asn||"-")}</td>
        <td>${esc(n.owner||n.as_name||"-")}</td>
        <td>${esc(translateQuality(n.quality))}</td>
        <td>${esc(translateIpType(n.ip_type))}</td>
        <td>${riskBadge(n)}</td>
        <td><span class="badge ${Number(n.blacklist_count || 0) > 0 ? 'unavailable' : (n.risk_level === 'unknown' ? 'not_checked' : 'available')}" title="${esc((n.blacklist_hits || []).join(', ') || '无命中')}">${Number(n.blacklist_count || 0) > 0 ? '命中 ' + Number(n.blacklist_count || 0) : (n.risk_level === 'unknown' ? '未检' : '干净')}</span></td>
        <td>
          <div class="table-actions">
            ${testBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event, options){
  if (event) event.stopPropagation();
  const opts = options || {};
  testingNodeIds.add(id);
  render();
  let updatedNode = null;
  
  try {
    const response = await fetch("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = await response.json();
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
      updatedNode = result.node;
    } else if (!opts.quiet) {
      alert("检测失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    if (!opts.quiet) alert("检测请求失败，请稍后重试");
  } finally {
    testingNodeIds.delete(id);
    render();
  }
  return updatedNode || nodes.find(n => n.id === id) || null;
}

function switchBlockReason(n) {
  if (!n) return "节点不存在";
  const riskLevel = String(n.risk_level || "unknown").toLowerCase();
  const riskSources = Array.isArray(n.risk_sources) ? n.risk_sources : [];
  if (n.probe_status !== "available") return "该节点还没有通过 OpenVPN 可用性检测";
  if (riskLevel === "unknown" || riskSources.length === 0) return "该节点还没有完成 IP 风控检测";
  if (Number(n.blacklist_count || 0) > 0) return `黑名单命中 ${n.blacklist_count || 0} 个: ${(n.blacklist_hits || []).join(", ")}`;
  if (Number(n.fraud_score ?? 100) > Number(state.max_auto_fraud_score ?? 25)) return `欺诈值 ${n.fraud_score ?? "未知"} 高于阈值 ${state.max_auto_fraud_score ?? 25}`;
  if (["medium", "high", "blocked"].includes(riskLevel)) return `风险等级为 ${translateRiskLevel(riskLevel)}`;
  if (["proxy", "hosting", "tor"].includes(String(n.ip_type || "").toLowerCase())) return `IP 类型为 ${translateIpType(n.ip_type)}，风险较高，自动切换会把它放在最后兜底`;
  return "";
}

async function handleSwitchClick(id) {
  if (state.is_connecting) return;
  let n = nodes.find(item => item.id === id);
  if (!n) {
    alert("节点不存在或列表已刷新，请重新加载后再试");
    return;
  }
  if (n.active || n.id === state.active_openvpn_node_id) return;

  const riskLevel = String(n.risk_level || "unknown").toLowerCase();
  const riskSources = Array.isArray(n.risk_sources) ? n.risk_sources : [];
  const needDetect = n.probe_status !== "available" || riskLevel === "unknown" || riskSources.length === 0;

  // 免费节点质量波动较大：检测与风控用于“自动优选”，但手动切换不做硬拦截。
  // 点确定 = 先检测再判断；点取消 = 直接尝试手动强制切换。
  if (n.probe_status === "unavailable") {
    const retry = confirm("该节点上次检测为不可用。\n\n点“确定”：重新检测，检测后再切换。\n点“取消”：不检测，直接尝试手动切换。\n\n节点: " + (n.ip || n.remote_host));
    if (retry) {
      n = await testNode(null, id, null, {quiet: false});
      if (!n) return;
    } else {
      connectNode(id, true);
      return;
    }
  } else if (needDetect) {
    const runDetect = confirm("该节点尚未完成可用性/IP 风控检测。\n\n点“确定”：先检测，检测后自动决定是否建议。\n点“取消”：跳过检测，直接尝试手动切换。");
    if (runDetect) {
      n = await testNode(null, id, null, {quiet: false});
      if (!n) return;
    } else {
      connectNode(id, true);
      return;
    }
  }

  if (!isCleanNode(n)) {
    const reason = switchBlockReason(n) || "该节点不符合自动优选规则";
    const force = confirm(
      "该节点不符合自动优选/干净 IP 规则：\n" + reason +
      "\n\n说明：自动故障转移仍会优先选择低风险、低欺诈值、无黑名单节点。" +
      "\n但免费 VPNGate 节点质量参差不齐，你可以手动强制尝试。" +
      "\n\n是否仍然手动切换到这个节点？"
    );
    if (!force) return;
    connectNode(id, true);
    return;
  }

  connectNode(id, false);
}

let pollInterval = null;

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const resp = await fetch("./api/nodes");
      const data = await resp.json();
      nodes = data.nodes || [];
      state = data.state || {};
      stableSortNodes();
      render();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          await fetch("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id, allowRisky){
  allowRisky = !!allowRisky;
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetch("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id, allow_risky: allowRisky})
    });
    const result = await r.json();
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误");
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetch("./api/disconnect", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      try {
        await fetch("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}

// Batch test button implementation
$("btn_batch_test").onclick = async () => {
  const pageNodes = currentPageNodes || [];
  if (pageNodes.length === 0) {
    alert("当前页面没有可供测试的备选节点");
    return;
  }
  
  const btn = $("btn_batch_test");
  btn.disabled = true;
  btn.innerHTML = `<svg style="animation: spin 1s linear infinite; width: 14px; height: 14px; display: inline-block; margin-right: 6px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>测试中...`;
  
  pageNodes.forEach(n => testingNodeIds.add(n.id));
  render();
  
  const testPromises = pageNodes.map(async (n) => {
    const id = n.id;
    try {
      const response = await fetch("./api/test_node", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id })
      });
      const result = await response.json();
      if (result.ok && result.node) {
        const idx = nodes.findIndex(item => item.id === id);
        if (idx !== -1) {
          nodes[idx] = result.node;
        }
      }
    } catch (e) {
    } finally {
      testingNodeIds.delete(id);
      render();
    }
  });
  
  try {
    await Promise.all(testPromises);
  } catch (e) {
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 批量测试本页`;
  }
};

function setPageLoading(text, percent, step) {
  const box = $("page_loading");
  const desc = $("page_loading_desc");
  const bar = $("page_loading_bar");
  const pct = $("page_loading_percent");
  const stepEl = $("page_loading_step");
  if (!box || !desc || !bar || !pct || !stepEl) return;
  box.style.display = "flex";
  desc.textContent = text;
  bar.style.width = `${percent}%`;
  pct.textContent = `${percent}%`;
  stepEl.textContent = step || "加载中";
}

function hidePageLoading() {
  const box = $("page_loading");
  if (box) box.style.display = "none";
}

async function load(){
  setPageLoading("正在连接后端服务...", 20, "连接服务");
  try {
    const r=await fetch("./api/nodes");
    setPageLoading("正在读取节点池和系统状态...", 55, "读取数据");
    const d=await r.json();
    nodes=d.nodes||[];
    state=d.state||{};
    setPageLoading("正在渲染控制面板...", 82, "渲染页面");
    stableSortNodes();
    updateCountryFilter();
    render();

    if (state.is_connecting) {
      setPageLoading("后端正在连接节点，面板将持续刷新状态...", 95, "连接节点");
      startConnectionPolling();
    } else {
      setPageLoading("加载完成", 100, "完成");
    }
    setTimeout(hidePageLoading, 350);
  } catch (e) {
    setPageLoading("面板加载失败：无法连接后端接口。请稍后刷新，或使用 en logs 查看服务日志。", 100, "加载失败");
    console.error(e);
  }
}

$("search").oninput=()=>{ currentPage = 1; render(); };
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };

$("refresh").onclick=async()=>{ 
  $("refresh").disabled=true; 
  $("refresh").textContent="正在后台更新..."; 
  try{await fetch("./api/refresh_nodes",{method:"POST"}); await load();} 
  catch(e){}
  setTimeout(()=>{
    $("refresh").disabled=false; 
    $("refresh").textContent="更新节点";
  }, 3000);
};
$("check").onclick=async()=>{ 
  $("check").disabled=true; 
  $("check").textContent="检测中..."; 
  try{await fetch("./api/check",{method:"POST"}); await load();} 
  finally{$("check").disabled=false; $("check").textContent="非中断检测补齐";}
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetch("./api/test_proxy", { method: "POST" });
    const result = await response.json();
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

// Admin dropdown toggle
const adminBtn = $("admin_btn");
const adminDropdown = $("admin_dropdown");
if (adminBtn && adminDropdown) {
  adminBtn.onclick = (e) => {
    e.stopPropagation();
    const isShow = adminDropdown.style.display === "block";
    adminDropdown.style.display = isShow ? "none" : "block";
  };
  document.addEventListener("click", () => {
    adminDropdown.style.display = "none";
  });
}

function openSettingsModal() {
  $("settings_error").style.display = "none";
  $("settings_success").style.display = "none";
  $("settings_form").reset();
  
  if (state) {
    $("settings_port").value = state.port || 8787;
    $("settings_suffix").value = state.secret_path || "EJsW2EeBo9lY";
    $("settings_target_countries").value = state.target_countries || "";
    $("settings_node_sources").value = state.node_sources || "vpngate,vpnbook,ipspeed";
    $("settings_auto_select_allow_active_switch").value = state.auto_select_allow_active_switch ? "1" : "0";
    const ipTypeValue = state.target_ip_types || "residential";
    const legacyIpTypeMap = {
      "residential,mobile": "residential",
      "residential,normal,mobile": "residential"
    };
    $("settings_target_ip_types").value = legacyIpTypeMap[ipTypeValue] || ipTypeValue;
    $("settings_auto_select_best_node").value = state.auto_select_best_node ? "1" : "0";
  }
  
  $("settings_modal").style.display = "flex";
  $("admin_dropdown").style.display = "none";
}

function closeSettingsModal() {
  $("settings_modal").style.display = "none";
}

async function saveSettings(e) {
  e.preventDefault();
  const errorDivEl = $("settings_error");
  const successDiv = $("settings_success");
  const submitBtn = $("settings_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const port = parseInt($("settings_port").value);
  const suffix = $("settings_suffix").value.trim();
  const targetCountries = $("settings_target_countries").value.trim();
  const nodeSources = $("settings_node_sources").value.trim();
  const targetIpTypes = $("settings_target_ip_types").value.trim();
  const autoSelectBestNode = $("settings_auto_select_best_node").value === "1";
  const autoSelectAllowActiveSwitch = $("settings_auto_select_allow_active_switch").value === "1";
  const newUsername = $("settings_new_username").value.trim();
  const newPassword = $("settings_new_password").value.trim();
  const currUsername = $("settings_curr_username").value.trim();
  const currPassword = $("settings_curr_password").value.trim();
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetch("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        port: port,
        secret_path: suffix,
        target_countries: targetCountries,
        node_sources: nodeSources,
        target_ip_types: targetIpTypes,
        auto_select_best_node: autoSelectBestNode,
        auto_select_allow_active_switch: autoSelectAllowActiveSwitch,
        new_username: newUsername,
        new_password: newPassword,
        curr_username: currUsername,
        curr_password: currPassword
      })
    });
    
    const data = await res.json();
    if (res.ok && data.ok) {
      successDiv.textContent = "保存成功！页面将在 4 秒内自动跳转至新地址...";
      successDiv.style.display = "block";
      
      const inputs = $("settings_form").querySelectorAll("input, select, button");
      inputs.forEach(el => el.disabled = true);
      
      setTimeout(() => {
        const protocol = window.location.protocol;
        const host = window.location.hostname;
        window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
      }, 4000);
    } else {
      errorDivEl.textContent = data.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

async function logoutAdmin() {
  try {
    const res = await fetch("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const r = await fetch("./api/nodes");
      const d = await r.json();
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      render();
    } catch(e) {}
  }
}, 10000);
</script>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.5)
    try:
        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
        s.close()
    except Exception as e:
        return {
            "ok": False,
            "error": f"代理服务未运行 (端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e})"
        }

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    cmd = [
        "curl", "-4", "-s",
        "-w", "\n%{time_total} %{http_code}",
        "-x", f"socks5h://127.0.0.1:{LOCAL_PROXY_PORT}",
        "http://ip.sb",
        "--max-time", "5"
    ]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            if len(lines) >= 2:
                ip = lines[0].strip()
                time_info = lines[1].strip().split()
                if len(time_info) == 2:
                    total_time_str, http_code = time_info
                    if http_code == "200" and ip:
                        latency_ms = int(float(total_time_str) * 1000)
                        return {"ok": True, "ip": ip, "latency_ms": latency_ms}
        
        # 如果 ip.sb 失败，使用备用地址 http://api.ipify.org
        cmd[7] = "http://api.ipify.org"
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        if res.returncode == 0:
            lines = res.stdout.strip().splitlines()
            if len(lines) >= 2:
                ip = lines[0].strip()
                time_info = lines[1].strip().split()
                if len(time_info) == 2:
                    total_time_str, http_code = time_info
                    if http_code == "200" and ip:
                        latency_ms = int(float(total_time_str) * 1000)
                        return {"ok": True, "ip": ip, "latency_ms": latency_ms}
                        
        return {"ok": False, "error": f"出口连接测试失败 (curl 返回码: {res.returncode}, stderr: {res.stderr.strip()})"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    time.sleep(2)
    while True:
        try:
            if is_connecting:
                time.sleep(5)
                continue
            if not active_openvpn_node_id or not active_openvpn_running():
                time.sleep(30)
                continue

            res = check_proxy_health()
            if res["ok"]:
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error="",
                    proxy_fail_count=0
                )
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                state = read_json(STATE_FILE, {})
                fail_count = int(state.get("proxy_fail_count") or 0) + 1
                connected_at = float(state.get("active_connected_at") or 0)
                in_grace = connected_at and time.time() - connected_at < PROXY_FAIL_GRACE_SECONDS
                print(f"[警告] 7928 端口本地代理当前不可用！第 {fail_count}/{PROXY_FAIL_AUTO_SWITCH_THRESHOLD} 次，原因: {error_msg}", flush=True)
                log_to_json("WARNING", "Proxy", f"代理不可用({fail_count}/{PROXY_FAIL_AUTO_SWITCH_THRESHOLD}): {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg,
                    proxy_fail_count=fail_count,
                    last_check_message=(
                        f"代理出口检测暂时失败 {fail_count}/{PROXY_FAIL_AUTO_SWITCH_THRESHOLD}：{error_msg}。"
                        + ("当前处于连接稳定保护期，不会立即断开。" if in_grace else "")
                    )
                )

                # OpenVPN 刚连上时，代理出口可能还在稳定；连续失败达到阈值后才触发故障转移。
                if in_grace or fail_count < PROXY_FAIL_AUTO_SWITCH_THRESHOLD:
                    time.sleep(30)
                    continue

                with lock:
                    nodes = read_json(NODES_FILE, [])
                    active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                    if active_node:
                        active_node["probe_message"] = f"代理连续失败 {fail_count} 次: {error_msg}"
                        # 不马上把当前节点标成 unavailable，避免节点池只有当前节点时前端看起来“明明可用却不能连”。
                        # 是否切换由 auto_switch_node 按备用节点情况决定。
                        write_json(NODES_FILE, nodes)
                auto_switch_node()
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global active_openvpn_node_id, is_connecting
    while True:
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        auth_file = DATA_DIR / "ui_auth.json"
        if not auth_file.exists():
            try:
                DATA_DIR.mkdir(exist_ok=True)
                auth_file.write_text(json.dumps({"secret_path": "EJsW2EeBo9lY"}), encoding="utf-8")
            except Exception:
                pass
            return "EJsW2EeBo9lY"
        try:
            creds = json.loads(auth_file.read_text(encoding="utf-8"))
            if "secret_path" in creds:
                return creds["secret_path"]
            elif "password" in creds:
                secret_path = creds["password"]
                try:
                    auth_file.write_text(json.dumps({"secret_path": secret_path}), encoding="utf-8")
                except Exception:
                    pass
                return secret_path
            return "EJsW2EeBo9lY"
        except Exception:
            return "EJsW2EeBo9lY"

    def is_authorized(self) -> bool:
        ui_cfg = load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            return True
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        if not secret_path:
            return self.path
        if self.path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if self.path.startswith(prefix):
            return "/" + self.path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def do_GET(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_json(NODES_FILE, [])
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                norm_short, norm_country = canonicalize_country_fields(stripped.get("country_short"), stripped.get("country"))
                if norm_country:
                    stripped["country"] = norm_country
                if norm_short:
                    stripped["country_short"] = norm_short
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_json(NODES_FILE, [])
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + 30 * 24 * 3600
                    body = json.dumps({"ok": True}, ensure_ascii=False).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Connection", "close")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                    self.close_connection = True
                else:
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        if effective_path == "/api/update_settings":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                
                curr_username = str(payload.get("curr_username") or "")
                curr_password = str(payload.get("curr_password") or "")
                
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                new_target_countries = normalize_target_countries_input(payload.get("target_countries") or "")
                new_node_sources = normalize_node_sources_input(payload.get("node_sources") or NODE_SOURCES_ENV or DEFAULT_NODE_SOURCES)
                new_target_ip_types = normalize_target_ip_types_input(payload.get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential")
                new_auto_select_best_node = parse_bool_setting(payload.get("auto_select_best_node"), True)
                new_auto_select_allow_active_switch = parse_bool_setting(payload.get("auto_select_allow_active_switch"), False)
                new_username = str(payload.get("new_username") or "").strip()
                new_password = str(payload.get("new_password") or "").strip()
                
                if not curr_username or not curr_password:
                    self.send_json({"ok": False, "error": "请输入当前账号和密码进行安全验证"}, HTTPStatus.FORBIDDEN)
                    return
                
                ui_cfg = load_ui_config()
                expected_uname = ui_cfg.get("username", "admin")
                expected_pwd = ui_cfg.get("password", "")
                
                if curr_username != expected_uname or curr_password != expected_pwd:
                    self.send_json({"ok": False, "error": "当前账号或密码不正确"}, HTTPStatus.FORBIDDEN)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                ui_cfg["target_countries"] = new_target_countries
                ui_cfg["node_sources"] = new_node_sources
                ui_cfg["target_ip_types"] = new_target_ip_types
                ui_cfg["auto_select_best_node"] = new_auto_select_best_node
                ui_cfg["auto_select_allow_active_switch"] = new_auto_select_allow_active_switch
                if new_username:
                    ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    auth_file.write_text(json.dumps(ui_cfg, ensure_ascii=False, indent=2), encoding="utf-8")
                
                self.send_json({"ok": True, "message": "配置更新成功，系统将在 2 秒内重启..."})
                
                def restart_server():
                    time.sleep(2)
                    print("[系统] 管理后台配置更新，进程即将退出以触发自动重启...", flush=True)
                    os._exit(0)
                
                threading.Thread(target=restart_server, daemon=True).start()
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                threading.Thread(target=maintain_valid_nodes, kwargs={"force": False}, daemon=True).start()
                self.send_json({"ok": True, "message": "已在后台启动非中断节点检测流程，当前连接会保持不变，面板会持续刷新检测进度"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                self.send_json({"ok": True, "message": "已在后台启动节点更新流程"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                stop_active_openvpn()
                with lock:
                    nodes = read_json(NODES_FILE, [])
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接", active_connected_at=0, proxy_fail_count=0, failover_country_short="", failover_country="", failover_country_display="未固定")
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                allow_risky = str(payload.get("allow_risky") or "").lower() in {"1", "true", "yes", "on"}
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""), allow_manual_risky=allow_risky)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                length = parse_int(self.headers.get("Content-Length"))
                if length > 0:
                    self.rfile.read(length)
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

def main() -> None:
    ensure_dirs()
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": True,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
            "target_countries": normalize_target_countries_input(load_ui_config().get("target_countries") or TARGET_COUNTRIES_ENV),
            "target_countries_display": normalize_target_countries_input(load_ui_config().get("target_countries") or TARGET_COUNTRIES_ENV) or "全部地区",
            "target_ip_types": normalize_target_ip_types_input(load_ui_config().get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential"),
            "target_ip_types_display": target_ip_types_display(load_ui_config().get("target_ip_types") or TARGET_IP_TYPES_ENV or "residential"),
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    for _ in range(30):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.5)
            s.connect((LOCAL_PROXY_HOST, LOCAL_PROXY_PORT))
            gateway_ready = True
            break
        except Exception:
            time.sleep(0.5)
        finally:
            try:
                s.close()
            except Exception:
                pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)

    threading.Thread(target=collector_loop, daemon=True).start()
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    threading.Thread(target=active_node_pinger, daemon=True).start()
    
    ui_cfg = load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = int(ui_cfg.get("port", UI_PORT))
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    ThreadingHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()