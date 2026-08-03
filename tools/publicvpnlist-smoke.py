#!/usr/bin/env python3
"""Validate one user-provided PublicVPNList snapshot/profile without OpenVPN."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> int:
    snapshot_url = os.environ.get("PUBLICVPNLIST_SNAPSHOT_URL", "").strip()
    if not snapshot_url:
        print("错误：请先设置 PUBLICVPNLIST_SNAPSHOT_URL 为用户生成的临时快照 URL。", file=sys.stderr)
        return 2

    # Smoke testing is explicitly URL-only even if a service environment also
    # has a local snapshot configured. Neither URL nor query parameters are
    # printed by this tool.
    os.environ["PUBLICVPNLIST_SNAPSHOT_FILE"] = ""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import vpngate_manager

    try:
        payload = vpngate_manager.fetch_publicvpnlist_snapshot()
        records = vpngate_manager.publicvpnlist_payload_records(payload)
    except Exception:
        print("失败：临时快照请求或 JSON 解析失败。", file=sys.stderr)
        return 1

    print(f"快照结构：有效记录数组，共 {len(records)} 条")
    selected = None
    for record in records:
        row = vpngate_manager.normalize_publicvpnlist_row(record)
        if not row or row.get("country_short") not in {"PH", "FR"}:
            continue
        if row.get("temporary_ovpn_url"):
            selected = row
            break
    if selected is None:
        print("失败：快照中没有带 temporary_ovpn_url 的 PH/FR 节点。", file=sys.stderr)
        return 1

    try:
        config_text = vpngate_manager.fetch_publicvpnlist_config(str(selected["temporary_ovpn_url"]))
    except Exception:
        print("失败：temporary_ovpn_url 请求、重定向或配置读取失败。", file=sys.stderr)
        return 1

    if not vpngate_manager.looks_like_openvpn_config(config_text):
        print("失败：临时链接内容不是 OpenVPN 配置。", file=sys.stderr)
        return 1
    node = vpngate_manager.publicvpnlist_row_to_node(selected, config_text)
    if not node:
        print("失败：remote、port、proto 不一致，或配置清理/校验失败。", file=sys.stderr)
        return 1

    # urllib follows ordinary HTTP redirects before fetch_publicvpnlist_config
    # validates the body. Do not start OpenVPN or print any signed URL.
    print(
        "通过：已验证 1 个 {country} 节点，remote={host}:{port} proto={proto}；"
        "配置已完成清理（未启动 OpenVPN）。".format(
            country=node.get("country_short", ""),
            host=node.get("remote_host", ""),
            port=node.get("remote_port", ""),
            proto=node.get("proto", ""),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
