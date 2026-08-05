#!/usr/bin/env python3
"""Bounded, redacted PublicVPNList API/config smoke check.

The default mode validates only the official API metadata path and never
starts OpenVPN. The --download option opts into at most the requested number
of short-lived configuration flows (one by default). Signed URLs, query
parameters, cookies, tokens, and response bodies are never printed or placed
in the JSON report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def _load_manager():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import vpngate_manager

    return vpngate_manager


def _redacted_error(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, urllib.error.HTTPError):
        status = int(getattr(exc, "code", 0) or 0)
        category = "rate_limited" if status == 429 else "http_error"
        return {"category": category, "status": status, "type": type(exc).__name__}
    if isinstance(exc, (urllib.error.URLError, TimeoutError, OSError)):
        return {"category": "network_error", "status": 0, "type": type(exc).__name__}
    return {"category": "schema_error", "status": 0, "type": type(exc).__name__}


def _api_path_url(manager, base_url: str, path: str, params: dict[str, Any] | None = None) -> str:
    base = base_url.rstrip("/") + "/"
    url = urllib.parse.urljoin(base, path.lstrip("/"))
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.urlencode(params or {})
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _get_json(manager, url: str, timeout: int, base_url: str) -> tuple[Any, dict[str, Any]]:
    metadata: dict[str, Any] = {}
    manager.publicvpnlist_validate_api_url(url, base_url)
    opener = urllib.request.build_opener(manager.PublicVPNListAPIRedirectHandler(base_url))
    body = manager.publicvpnlist_http_get(
        url,
        timeout=max(1, int(timeout)),
        max_bytes=manager.PUBLICVPNLIST_API_MAX_RESPONSE_BYTES,
        accept="application/json",
        opener=opener,
        metadata=metadata,
    )
    content_type = str(metadata.get("content_type") or "").split(";", 1)[0].strip().lower()
    if content_type != "application/json" and not content_type.endswith("+json"):
        raise ValueError("unexpected_json_content_type")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid_json") from exc
    return payload, metadata


def classify_api_result(
    metadata_records: list[dict[str, Any]],
    mapped_records: list[dict[str, Any]],
    errors: list[dict[str, Any]] | None = None,
) -> str:
    """Classify a smoke result without exposing any request detail."""

    errors = errors or []
    if errors:
        categories = {str(item.get("category") or "") for item in errors}
        if "rate_limited" in categories:
            return "rate_limited"
        if categories <= {"network_error", "http_error"}:
            return "github_runner_blocked"
        return "schema_error"
    if not metadata_records:
        return "metadata_empty"
    if not mapped_records:
        return "mapping_missing"
    return "api_success"


def _row_mapping(manager, raw: dict[str, Any]) -> bool:
    row = manager.normalize_publicvpnlist_row(raw)
    if not row:
        return False
    return bool(
        str(row.get("temporary_ovpn_url") or "").strip()
        or manager.publicvpnlist_web_download_id(row)
    )


def _select_records(manager, records: list[dict[str, Any]], countries: list[str], limit: int) -> list[dict[str, Any]]:
    allowed = {str(item).strip().upper() for item in countries if str(item).strip()}
    ordered = manager.publicvpnlist_order_api_candidate_records(records)
    selected: list[dict[str, Any]] = []
    for raw in ordered:
        row = manager.normalize_publicvpnlist_row(raw)
        if not row or row.get("country_short") not in allowed:
            continue
        selected.append(dict(raw))
        if len(selected) >= max(1, int(limit)):
            break
    return selected


def _download_one(manager, raw: dict[str, Any], timeout: int) -> dict[str, Any]:
    row = manager.normalize_publicvpnlist_row(raw)
    if not row:
        raise ValueError("row_not_normalizable")
    metadata: dict[str, Any] = {}
    manager.PUBLICVPNLIST_CONFIG_TIMEOUT_SECONDS = max(1, int(timeout))
    manager.PUBLICVPNLIST_API_TIMEOUT_SECONDS = max(1, int(timeout))
    temporary_url = str(row.get("temporary_ovpn_url") or "").strip()
    deadline = time.monotonic() + max(1, int(timeout))
    if temporary_url:
        config_text = manager.fetch_publicvpnlist_config(
            temporary_url,
            metadata=metadata,
            max_retries=1,
            deadline=deadline,
        )
    else:
        config_text = manager.fetch_publicvpnlist_official_config(
            row,
            metadata=metadata,
            deadline=deadline,
        )
    actual_hash = str(metadata.get("response_sha256") or "").strip().lower()
    expected_hash = str(row.get("config_sha256") or "").strip().lower()
    if expected_hash and actual_hash != expected_hash:
        raise ValueError("config_sha256_mismatch")
    node = manager.publicvpnlist_row_to_node(row, config_text)
    if not node:
        raise ValueError("endpoint_validation_failed")
    return {
        "country": str(node.get("country_short") or ""),
        "host": str(node.get("remote_host") or ""),
        "port": int(node.get("remote_port") or 0),
        "proto": str(node.get("proto") or ""),
        "response_sha256_present": bool(actual_hash),
        "config_sha256": hashlib.sha256(config_text.encode("utf-8")).hexdigest(),
        "redirect_count": int(metadata.get("redirect_count") or 0),
        "initial_download_host": str(metadata.get("initial_download_host") or ""),
        "final_download_host": str(metadata.get("final_download_host") or ""),
    }



def _run_snapshot_compat(manager) -> int:
    """Preserve the original two-phase temporary-snapshot smoke contract."""

    snapshot_url = os.environ.get("PUBLICVPNLIST_SNAPSHOT_URL", "").strip()
    if not snapshot_url:
        print("错误：请设置 PUBLICVPNLIST_SNAPSHOT_URL，或使用 --api。", file=sys.stderr)
        return 2
    os.environ["PUBLICVPNLIST_SNAPSHOT_FILE"] = ""
    try:
        payload = manager.fetch_publicvpnlist_snapshot()
        records = manager.publicvpnlist_payload_records(payload)
    except Exception:
        print("失败：临时快照请求或 JSON 解析失败。", file=sys.stderr)
        return 1
    selected = None
    for raw in records:
        row = manager.normalize_publicvpnlist_row(raw)
        if row and row.get("country_short") in {"PH", "FR"} and row.get("temporary_ovpn_url"):
            selected = row
            break
    if selected is None:
        print("失败：快照中没有带临时配置 URL 的 PH/FR 节点。", file=sys.stderr)
        return 1
    temporary_url = str(selected["temporary_ovpn_url"])
    try:
        discovered_host = manager.publicvpnlist_validate_download_url(
            temporary_url,
            require_allowlist=False,
        )
    except Exception:
        print("失败：temporary_ovpn_url 未通过 HTTPS/地址安全检查。", file=sys.stderr)
        return 1
    allowed_hosts = manager.publicvpnlist_allowed_download_hosts()
    if discovered_host not in allowed_hosts:
        print(
            f"发现阶段通过：download_host={discovered_host}；未请求配置。\n"
            "请将该 hostname 加入 PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS 后重试。",
            file=sys.stderr,
        )
        return 2
    metadata: dict[str, Any] = {}
    try:
        config_text = manager.fetch_publicvpnlist_config(
            temporary_url,
            metadata=metadata,
        )
    except Exception:
        rejected_host = str(metadata.get("rejected_download_host") or "").strip().lower()
        if rejected_host:
            print(
                f"失败：重定向目标 hostname={rejected_host} 不在允许列表；加入后重试。",
                file=sys.stderr,
            )
        else:
            print("失败：temporary_ovpn_url 请求、重定向或配置读取失败。", file=sys.stderr)
        return 1
    if not manager.looks_like_openvpn_config(config_text):
        print("失败：临时链接内容不是 OpenVPN 配置。", file=sys.stderr)
        return 1
    node = manager.publicvpnlist_row_to_node(selected, config_text)
    if not node:
        print("失败：remote、port、proto 不一致，或配置清理/校验失败。", file=sys.stderr)
        return 1
    print(
        "通过：country={country} remote={host}:{port} proto={proto} redirects={redirects} "
        "final_download_host={download_host} config=valid cleaned=true openvpn=not_started".format(
            country=node.get("country_short", ""),
            host=node.get("remote_host", ""),
            port=node.get("remote_port", ""),
            proto=node.get("proto", ""),
            redirects=metadata.get("redirect_count", 0),
            download_host=metadata.get("final_download_host", discovered_host),
        )
    )
    return 0

def run(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    manager = _load_manager()
    started = time.monotonic()
    countries = [
        str(item).strip().upper()
        for item in str(args.countries or "PH,FR,US").split(",")
        if str(item).strip()
    ]
    base_url = manager.publicvpnlist_api_base_url()
    report: dict[str, Any] = {
        "status": "not_started",
        "mode": "api",
        "countries": countries,
        "metadata_records": 0,
        "metadata_with_download_path": 0,
        "metadata_only_skipped": 0,
        "connectable_candidates": 0,
        "config_downloads": 0,
        "api_endpoints": [],
        "errors": [],
        "openvpn": "not_started",
        "redacted": True,
    }
    all_records: list[dict[str, Any]] = []
    endpoint_errors: list[dict[str, Any]] = []
    endpoint_specs: list[tuple[str, str, dict[str, Any] | None]] = [
        ("health", _api_path_url(manager, base_url, "health"), None),
        ("dataset", _api_path_url(manager, base_url, "dataset"), None),
    ]
    servers_url = manager.publicvpnlist_api_servers_url()
    for country in countries:
        endpoint_specs.append(
            (
                "servers/" + country,
                manager._publicvpnlist_api_request_url(servers_url, country, 1),
                None,
            )
        )
    try:
        for label, url, _params in endpoint_specs:
            try:
                payload, metadata = _get_json(manager, url, args.timeout, base_url)
                report["api_endpoints"].append(
                    {
                        "path": urllib.parse.urlsplit(url).path,
                        "status": int(metadata.get("status") or 200),
                        "content_type": str(metadata.get("content_type") or "").split(";", 1)[0].lower(),
                        "redirect_count": int(metadata.get("redirect_count") or 0),
                    }
                )
                if label.startswith("servers/"):
                    records = manager.publicvpnlist_payload_records(payload)
                    all_records.extend(record for record in records if isinstance(record, dict))
            except Exception as exc:
                safe_error = _redacted_error(exc)
                safe_error["endpoint"] = label
                endpoint_errors.append(safe_error)
    except Exception as exc:
        endpoint_errors.append(_redacted_error(exc))

    report["errors"] = endpoint_errors
    report["metadata_records"] = len(all_records)
    normalized_rows = [
        manager.normalize_publicvpnlist_row(record)
        for record in all_records
    ]
    normalized_rows = [row for row in normalized_rows if row and row.get("country_short") in set(countries)]
    report["metadata_with_download_path"] = sum(
        1 for raw in all_records if _row_mapping(manager, raw)
    )
    report["metadata_only_skipped"] = max(
        0,
        len(normalized_rows) - report["metadata_with_download_path"],
    )

    if endpoint_errors:
        report["status"] = classify_api_result(
            all_records,
            [raw for raw in all_records if _row_mapping(manager, raw)],
            endpoint_errors,
        )
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return 1, report

    mapped_records = [
        raw for raw in all_records
        if _row_mapping(manager, raw)
    ]
    report["status"] = classify_api_result(all_records, mapped_records)
    if args.download and mapped_records:
        # Detail enrichment is bounded by the manager's API request budget.
        detail_meta = {"request_count": 0}
        try:
            ranked = manager.publicvpnlist_order_api_candidate_records(all_records)
            enriched = manager.publicvpnlist_api_enrich_records_for_download(
                ranked[: max(1, int(args.max_profiles) * 2)],
                detail_meta,
            )
            candidates = _select_records(manager, enriched, countries, args.max_profiles)
            for raw in candidates[: max(1, int(args.max_profiles))]:
                try:
                    result = _download_one(manager, raw, args.timeout)
                    report["config_downloads"] += 1
                    report["connectable_candidates"] += 1
                    report["download_result"] = result
                    break
                except Exception as exc:
                    report["errors"].append(_redacted_error(exc))
            report["detail_requests"] = int(detail_meta.get("detail_requests") or 0)
            report["detail_successes"] = int(detail_meta.get("detail_successes") or 0)
            report["detail_failures"] = int(detail_meta.get("detail_failures") or 0)
        except Exception as exc:
            report["errors"].append(_redacted_error(exc))
        if report["config_downloads"]:
            report["status"] = "api_success"
        elif report["errors"]:
            report["status"] = "config_flow_failed"
        else:
            report["status"] = "mapping_missing"
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return 0, report


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PublicVPNList API/config smoke check")
    parser.add_argument("--api", action="store_true", help="validate API v1 (default)")
    parser.add_argument("--countries", default="PH,FR,US")
    parser.add_argument("--max-profiles", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--redact", action="store_true", help="keep all report fields redacted")
    parser.add_argument("--download", action="store_true", help="run at most max-profiles bounded config flow")
    parser.add_argument("--json-report", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:] if __name__ == "__main__" else []
    args = _parse_args(argv)
    manager = _load_manager()
    if not args.api and os.environ.get("PUBLICVPNLIST_SNAPSHOT_URL", "").strip():
        return _run_snapshot_compat(manager)
    try:
        code, report = run(args)
    except Exception as exc:
        report = {
            "status": "schema_error",
            "errors": [_redacted_error(exc)],
            "metadata_records": 0,
            "connectable_candidates": 0,
            "config_downloads": 0,
            "openvpn": "not_started",
            "redacted": True,
        }
        code = 1
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    print(serialized)
    if args.json_report:
        report_path = Path(args.json_report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(serialized + "\n", encoding="utf-8")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
