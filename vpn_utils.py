#!/usr/bin/env python3
from __future__ import annotations
import json
import os
import re
import socket
import subprocess
import time
import urllib.parse
import urllib.request
import threading
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = ROOT_DIR / "vpngate_data"
IP_CACHE_FILE = DATA_DIR / "ip_cache.json"

ip_cache_lock = threading.RLock()

COUNTRY_TRANSLATIONS = {
    "Japan": "日本",
    "Korea Republic of": "韩国",
    "Korea": "韩国",
    "Republic of Korea": "韩国",
    "Thailand": "泰国",
    "United States": "美国",
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
    "Luxembourg": "卢森堡",
}

def get_upstream_proxy() -> tuple[str | None, str | None, int | None]:
    """
    Returns (proxy_type, host, port) from environment variables.
    proxy_type is 'socks' or 'http'.
    """
    socks_env = os.environ.get("OPENVPN_UPSTREAM_SOCKS")
    if socks_env:
        if "://" in socks_env:
            parsed = urllib.parse.urlsplit(socks_env)
            if parsed.hostname and parsed.port:
                return "socks", parsed.hostname, parsed.port
        else:
            parts = socks_env.split(":")
            if len(parts) == 2:
                return "socks", parts[0], int(parts[1])
            elif len(parts) == 1:
                return "socks", parts[0], 10808

    http_env = os.environ.get("OPENVPN_UPSTREAM_HTTP")
    if http_env:
        if "://" in http_env:
            parsed = urllib.parse.urlsplit(http_env)
            if parsed.hostname and parsed.port:
                return "http", parsed.hostname, parsed.port
        else:
            parts = http_env.split(":")
            if len(parts) == 2:
                return "http", parts[0], int(parts[1])
            elif len(parts) == 1:
                return "http", parts[0], 10808

    for env_name in ["http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"]:
        val = os.environ.get(env_name)
        if not val:
            continue
        if "://" in val:
            parsed = urllib.parse.urlsplit(val)
            ptype = "socks" if parsed.scheme.startswith("socks") else "http"
            if parsed.hostname and parsed.port:
                return ptype, parsed.hostname, parsed.port
        else:
            parts = val.split(":")
            if len(parts) == 2:
                return "http", parts[0], int(parts[1])
    return None, None, None

def is_config_tcp(config_text: str) -> bool:
    try:
        for line in config_text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            parts = line.split()
            if parts[0].lower() == "proto" and len(parts) >= 2:
                if "tcp" in parts[1].lower():
                    return True
            elif parts[0].lower() == "remote" and len(parts) >= 4:
                if "tcp" in parts[3].lower():
                    return True
    except Exception:
        pass
    return False

def parse_remote(config_text: str, fallback_ip: str = "") -> tuple[str, int, str]:
    remote_host = fallback_ip
    remote_port = 0
    proto = "unknown"
    for raw_line in config_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        parts = line.split()
        if parts[0].lower() == "proto" and len(parts) >= 2:
            proto = parts[1].lower()
        elif parts[0].lower() == "remote" and len(parts) >= 3:
            remote_host = parts[1]
            remote_port = int(parts[2]) if parts[2].isdigit() else 0
    return remote_host, remote_port, proto

def get_physical_interface() -> str | None:
    try:
        res = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=2)
        if res.returncode == 0:
            routes = []
            for line in res.stdout.splitlines():
                if line.startswith("default via"):
                    parts = line.split()
                    try:
                        gw = parts[2]
                        dev = parts[parts.index("dev") + 1]
                        metric = 0
                        if "metric" in parts:
                            metric = int(parts[parts.index("metric") + 1])
                        routes.append((gw, dev, metric))
                    except (ValueError, IndexError):
                        continue
            if routes:
                routes.sort(key=lambda x: x[2], reverse=True)
                for gw, dev, metric in routes:
                    if not dev.startswith(("tun", "tap", "wg", "ppp")):
                        return dev
                return routes[0][1]
    except Exception:
        pass
    return None

def tcp_latency_ms(host: str, port: int, dev: str | None = None) -> int:
    started = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(5)
        if dev:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode("utf-8"))
            except OSError:
                pass
        s.connect((host, port))
        return max(1, int((time.time() - started) * 1000))
    except OSError:
        return 0
    finally:
        try:
            s.close()
        except Exception:
            pass

def ping_latency_ms(host: str, port: int, fallback_ping: int = 0) -> int:
    dev = get_physical_interface()
    # 1. Try ping with interface binding
    if dev:
        try:
            cmd = ["ping", "-c", "1", "-W", "2", "-I", dev, host]
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2
            )
            if res.returncode == 0:
                match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
                if match:
                    val = int(float(match.group(1)))
                    if val > 0:
                        return val
        except Exception:
            pass

    # 2. Try ping without interface binding
    try:
        cmd = ["ping", "-c", "1", "-W", "2", host]
        res = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2
        )
        if res.returncode == 0:
            match = re.search(r"time=([\d.]+)\s*ms", res.stdout)
            if match:
                val = int(float(match.group(1)))
                if val > 0:
                    return val
    except Exception:
        pass

    # 3. Try TCP latency check
    tcp_val = tcp_latency_ms(host, port, dev)
    if tcp_val > 0:
        return tcp_val

    # 4. Fallback
    if fallback_ping > 0:
        return fallback_ping
    return 0

def check_and_fix_dns() -> None:
    """
    Checks if DNS resolution is broken in WSL.
    If names fail but direct IP connections work, appends public DNS nameservers to /etc/resolv.conf.
    """
    try:
        socket.gethostbyname("www.vpngate.net")
        return
    except socket.gaierror:
        pass

    network_ok = False
    for ip in ["8.8.8.8", "1.1.1.1"]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.settimeout(2)
            s.connect((ip, 53))
            network_ok = True
            break
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    if not network_ok:
        return

    resolv_file = Path("/etc/resolv.conf")
    if resolv_file.exists():
        try:
            content = resolv_file.read_text(encoding="utf-8", errors="replace")
            if "nameserver 1.1.1.1" not in content and "nameserver 8.8.8.8" not in content:
                print("[dns_heal] Resolving names failed, but IP network is OK. Appending public DNS to /etc/resolv.conf...", flush=True)
                with open("/etc/resolv.conf", "a", encoding="utf-8") as f:
                    f.write("\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n")
        except Exception as e:
            print(f"[dns_heal] Failed to write DNS fallback: {e}", flush=True)

def load_ip_cache() -> dict[str, dict[str, Any]]:
    with ip_cache_lock:
        try:
            if IP_CACHE_FILE.exists():
                return json.loads(IP_CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

def save_ip_cache(cache: dict[str, dict[str, Any]]) -> None:
    with ip_cache_lock:
        try:
            DATA_DIR.mkdir(exist_ok=True)
            IP_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass


SUSPICIOUS_ASN_KEYWORDS = {
    "hosting", "host", "cloud", "vps", "server", "servers", "data center", "datacenter",
    "colo", "colocation", "dedicated", "virtual", "vpn", "proxy", "relay", "tor", "privacy",
    "digitalocean", "hetzner", "ovh", "aws", "amazon", "google cloud", "microsoft", "azure",
    "oracle", "linode", "akamai", "vultr", "contabo", "leaseweb", "m247", "choopa",
    "quadranet", "colo cross", "cogent", "sharktech", "psychz", "dedipath", "gcore",
}

DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "all.s5h.net",
]

def env_bool(name: str, default: bool = True) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() not in {"0", "false", "no", "off"}

def parse_asn_number(value: Any) -> str:
    text = str(value or "")
    match = re.search(r"AS\s*([0-9]+)", text, re.I)
    if match:
        return "AS" + match.group(1)
    match = re.search(r"\b([0-9]{2,})\b", text)
    return "AS" + match.group(1) if match else ""

def safe_json_request(url: str, timeout: float = 7.0) -> dict[str, Any]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "eianun-ip-risk/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def dnsbl_hits(ip: str, timeout: float = 1.2) -> list[str]:
    if not env_bool("IP_DNSBL_CHECK", True):
        return []
    try:
        socket.inet_aton(ip)
    except OSError:
        return []
    reversed_ip = ".".join(reversed(ip.split(".")))
    hits: list[str] = []
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for zone in DNSBL_ZONES:
            query = f"{reversed_ip}.{zone}"
            try:
                socket.gethostbyname(query)
                hits.append(zone)
            except Exception:
                pass
    finally:
        socket.setdefaulttimeout(old_timeout)
    return hits

def query_ipwhois(ip: str) -> dict[str, Any]:
    data = safe_json_request(f"http://ipwho.is/{urllib.parse.quote(ip)}?security=1", timeout=7)
    if not data or data.get("success") is False:
        return {}
    connection = data.get("connection") or {}
    security = data.get("security") or {}
    loc = " ".join(str(x) for x in [data.get("country"), data.get("region"), data.get("city")] if x)
    return {
        "source": "ipwho.is",
        "asn": parse_asn_number(connection.get("asn")),
        "as_name": connection.get("org") or connection.get("isp") or "",
        "owner": connection.get("isp") or connection.get("org") or "",
        "location": loc,
        "proxy": bool(security.get("proxy") or security.get("anonymous")),
        "vpn": bool(security.get("vpn")),
        "tor": bool(security.get("tor")),
        "hosting": bool(security.get("hosting")),
    }

def query_proxycheck(ip: str) -> dict[str, Any]:
    data = safe_json_request(f"http://proxycheck.io/v2/{urllib.parse.quote(ip)}?vpn=1&asn=1&risk=1&node=1&tag=eianun", timeout=8)
    item = data.get(ip) if isinstance(data, dict) else None
    if not isinstance(item, dict):
        return {}
    risk_raw = item.get("risk")
    try:
        risk = int(float(risk_raw))
    except Exception:
        risk = 0
    proxy_yes = str(item.get("proxy", "")).lower() == "yes"
    type_text = str(item.get("type") or "").lower()
    return {
        "source": "proxycheck.io",
        "asn": parse_asn_number(item.get("asn")),
        "as_name": item.get("provider") or item.get("organisation") or "",
        "owner": item.get("provider") or item.get("organisation") or "",
        "proxy": proxy_yes,
        "vpn": proxy_yes and "vpn" in type_text,
        "tor": proxy_yes and "tor" in type_text,
        "hosting": any(k in type_text for k in ["hosting", "server", "datacenter", "data center"]),
        "risk": risk,
        "type": item.get("type") or "",
    }


def _risk_classification_vote(
    *,
    proxy: bool = False,
    vpn: bool = False,
    tor: bool = False,
    hosting: bool = False,
    mobile: bool = False,
    type_text: str = "",
) -> str:
    """Reduce one provider's result to a conservative IP-quality vote."""

    normalized_type = str(type_text or "").strip().lower()
    if tor or vpn or proxy or any(token in normalized_type for token in ("proxy", "vpn", "tor")):
        return "proxy"
    if hosting or any(
        token in normalized_type
        for token in ("hosting", "server", "datacenter", "data center", "cloud")
    ):
        return "hosting"
    if mobile or "mobile" in normalized_type:
        return "mobile"
    return "residential"

def build_risk_profile(ip: str, ipapi_item: dict[str, Any] | None = None) -> dict[str, Any]:
    now = time.time()
    flags: list[str] = []
    sources: list[str] = []
    blacklist = dnsbl_hits(ip)
    owner = ""
    asn = ""
    as_name = ""
    location = ""
    proxy = False
    hosting = False
    mobile = False
    vpn = False
    tor = False
    external_risks: list[int] = []
    classification_votes: dict[str, str] = {}

    if ipapi_item:
        sources.append("ip-api.com")
        owner = ipapi_item.get("org") or ipapi_item.get("isp") or owner
        asn = ipapi_item.get("as") or asn
        as_name = ipapi_item.get("asname") or as_name
        location = " ".join(part for part in [ipapi_item.get("country"), ipapi_item.get("regionName"), ipapi_item.get("city")] if part)
        proxy = proxy or bool(ipapi_item.get("proxy"))
        hosting = hosting or bool(ipapi_item.get("hosting"))
        mobile = mobile or bool(ipapi_item.get("mobile"))
        classification_votes["ip-api.com"] = _risk_classification_vote(
            proxy=bool(ipapi_item.get("proxy")),
            hosting=bool(ipapi_item.get("hosting")),
            mobile=bool(ipapi_item.get("mobile")),
        )

    if env_bool("IPWHOIS_CHECK", True):
        info = query_ipwhois(ip)
        if info:
            sources.append(info.get("source", "ipwho.is"))
            owner = owner or info.get("owner", "")
            asn = asn or info.get("asn", "")
            as_name = as_name or info.get("as_name", "")
            location = location or info.get("location", "")
            proxy = proxy or bool(info.get("proxy"))
            hosting = hosting or bool(info.get("hosting"))
            vpn = vpn or bool(info.get("vpn"))
            tor = tor or bool(info.get("tor"))
            classification_votes["ipwho.is"] = _risk_classification_vote(
                proxy=bool(info.get("proxy")),
                vpn=bool(info.get("vpn")),
                tor=bool(info.get("tor")),
                hosting=bool(info.get("hosting")),
            )

    if env_bool("PROXYCHECK_CHECK", True):
        info = query_proxycheck(ip)
        if info:
            sources.append(info.get("source", "proxycheck.io"))
            owner = owner or info.get("owner", "")
            asn = asn or info.get("asn", "")
            as_name = as_name or info.get("as_name", "")
            proxy = proxy or bool(info.get("proxy"))
            hosting = hosting or bool(info.get("hosting"))
            vpn = vpn or bool(info.get("vpn"))
            tor = tor or bool(info.get("tor"))
            if info.get("risk"):
                external_risks.append(int(info.get("risk", 0)))
            classification_votes["proxycheck.io"] = _risk_classification_vote(
                proxy=bool(info.get("proxy")),
                vpn=bool(info.get("vpn")),
                tor=bool(info.get("tor")),
                hosting=bool(info.get("hosting")),
                type_text=str(info.get("type") or ""),
            )

    text_blob = " ".join([owner, as_name, asn]).lower()
    suspicious_asn = any(k in text_blob for k in SUSPICIOUS_ASN_KEYWORDS)

    score = 0
    if tor:
        score += 80
        flags.append("tor_exit")
    if proxy:
        score += 55
        flags.append("proxy_flag")
    if vpn:
        score += 45
        flags.append("vpn_flag")
    if hosting:
        score += 38
        flags.append("hosting_datacenter")
    if suspicious_asn:
        score += 25
        flags.append("suspicious_asn_keyword")
    if mobile:
        score += 8
        flags.append("mobile_network")
    if blacklist:
        score += min(65, 30 + 12 * (len(blacklist) - 1))
        flags.append("dnsbl_blacklist")
    if external_risks:
        score += max(external_risks) // 2
        flags.append("third_party_risk_score")

    score = max(0, min(100, score))
    clean_score = max(0, 100 - score)

    if blacklist or tor or score >= 70:
        risk_level = "high"
    elif score >= 40:
        risk_level = "medium"
    elif score >= 20:
        risk_level = "low"
    else:
        risk_level = "clean"

    if tor:
        ip_type = "tor"
        quality = "risky"
    elif proxy or vpn:
        ip_type = "proxy"
        quality = "proxy"
    elif hosting or suspicious_asn:
        ip_type = "hosting"
        quality = "datacenter"
    elif mobile:
        ip_type = "mobile"
        quality = "mobile"
    else:
        ip_type = "residential"
        quality = "clean_residential" if risk_level == "clean" else "normal"

    return {
        "owner": owner,
        "asn": asn,
        "as_name": as_name,
        "location": location,
        "ip_type": ip_type,
        "quality": quality,
        "fraud_score": score,
        "clean_score": clean_score,
        "risk_level": risk_level,
        "fraud_flags": flags,
        "risk_sources": sorted(set(sources + (["dnsbl"] if blacklist else []))),
        "classification_votes": classification_votes,
        "residential_votes": sorted(
            source for source, vote in classification_votes.items()
            if vote == "residential"
        ),
        "classification_vote_count": len(classification_votes),
        "residential_vote_count": sum(
            1 for vote in classification_votes.values() if vote == "residential"
        ),
        "blacklist_hits": blacklist,
        "blacklist_count": len(blacklist),
        "ip_clean": bool(risk_level == "clean" and not blacklist and ip_type == "residential"),
        "cached_at": now,
    }

def apply_ip_profile(node: dict[str, Any], profile: dict[str, Any]) -> None:
    for key in [
        "owner", "asn", "as_name", "location", "ip_type", "quality", "fraud_score",
        "clean_score", "risk_level", "fraud_flags", "risk_sources", "blacklist_hits",
        "blacklist_count", "ip_clean", "classification_votes", "residential_votes",
        "classification_vote_count", "residential_vote_count",
    ]:
        node[key] = profile.get(
            key,
            {} if key == "classification_votes" else []
            if key.endswith("hits") or key.endswith("flags") or key.endswith("sources")
            else ""
            if key in {"owner", "asn", "as_name", "location", "ip_type", "quality", "risk_level"}
            else 0,
        )

def enrich_ip_info(nodes: list[dict[str, Any]]) -> None:
    with ip_cache_lock:
        cache = load_ip_cache()

    ips_to_query: list[str] = []
    now = time.time()
    cache_ttl = int(os.environ.get("IP_RISK_CACHE_TTL_SECONDS", str(24 * 3600)))

    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if not ip:
            continue
        cached = cache.get(ip)
        # Profiles written before provider-vote provenance was added must be
        # refreshed once.  Otherwise PublicVPNList could make a decision from
        # an old aggregate ip_type without knowing how many providers voted.
        has_vote_provenance = (
            isinstance(cached, dict)
            and "classification_votes" in cached
            and "residential_vote_count" in cached
        )
        if cached and has_vote_provenance and now - cached.get("cached_at", 0) < cache_ttl:
            apply_ip_profile(node, cached)
        elif ip not in ips_to_query:
            ips_to_query.append(ip)

    if not ips_to_query:
        return

    ipapi_items: dict[str, dict[str, Any]] = {}
    chunk_size = 100
    for i in range(0, len(ips_to_query), chunk_size):
        chunk = ips_to_query[i : i + chunk_size]
        payload = json.dumps(chunk).encode("utf-8")
        request = urllib.request.Request(
            "http://ip-api.com/batch?lang=zh-CN&fields=status,message,query,country,regionName,city,isp,org,as,asname,proxy,hosting,mobile",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "eianun-ip-risk/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8", errors="replace"))
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get("status") == "success" and item.get("query"):
                            ipapi_items[item["query"]] = item
        except Exception as e:
            print(f"[enrich_ip_info] ip-api query failed: {e}", flush=True)

    new_entries: dict[str, dict[str, Any]] = {}
    max_workers = max(1, min(8, int(os.environ.get("IP_RISK_CHECK_WORKERS", "4"))))

    def build(ip: str) -> tuple[str, dict[str, Any]]:
        return ip, build_risk_profile(ip, ipapi_items.get(ip))

    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(build, ip) for ip in ips_to_query]
            for future in concurrent.futures.as_completed(futures):
                try:
                    ip, profile = future.result()
                    new_entries[ip] = profile
                except Exception as e:
                    print(f"[enrich_ip_info] risk profile failed: {e}", flush=True)
    except Exception as e:
        print(f"[enrich_ip_info] multi-source check failed: {e}", flush=True)
        for ip in ips_to_query:
            try:
                new_entries[ip] = build_risk_profile(ip, ipapi_items.get(ip))
            except Exception:
                pass

    if not new_entries:
        return

    with ip_cache_lock:
        cache = load_ip_cache()
        cache.update(new_entries)
        save_ip_cache(cache)

    for node in nodes:
        ip = node.get("ip") or node.get("remote_host")
        if ip in new_entries:
            apply_ip_profile(node, new_entries[ip])
