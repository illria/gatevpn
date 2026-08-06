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
import re
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


def _safe_reason_code(exc: BaseException) -> str:
    message = str(exc or "").lower()
    exception_name = type(exc).__name__
    if exception_name == "PublicVPNListConfigHashMismatch" or "config_sha256_mismatch" in message or "config_sha256 不匹配" in message:
        return "config_sha256_mismatch"
    known = (
        ("响应缺少原始字节", "config_sha256_unavailable"),
        ("实时检查未通过", "live_check_failed"),
        ("临时检查", "live_check_failed"),
        ("临时令牌响应缺少", "token_failed"),
        ("临时令牌", "token_failed"),
        ("配置下载 content-type", "profile_download_failed"),
        ("下载内容不像", "profile_not_openvpn"),
        ("remote/port/proto", "endpoint_mismatch"),
        ("端口", "endpoint_mismatch"),
        ("协议", "protocol_mismatch"),
        ("下载主机 dns 解析失败", "profile_download_failed"),
        ("下载主机没有可验证", "profile_download_failed"),
        ("主机不在", "profile_download_failed"),
        ("受限网络地址", "unsafe_config"),
        ("重定向次数超过", "profile_download_failed"),
        ("live flow 超过", "deadline_exceeded"),
        ("响应不是 json", "json_response_invalid"),
        ("响应 json 无效", "json_response_invalid"),
    )
    for marker, code in known:
        if marker in message:
            return code
    if re.search(r"\b(?:http|https)\b", message):
        return "http_request_failed"
    return exception_name
def _redacted_error(exc: BaseException) -> dict[str, Any]:
    flow = getattr(exc, "_pvl_flow", {})
    flow_summary = {}
    if isinstance(flow, dict):
        for key in (
            "status",
            "retry_after",
            "official_flow",
            "live_flow_deadline_exceeded",
            "live_check_succeeded",
            "live_check_status",
            "token_request_attempted",
            "token_generated",
            "profile_download_attempted",
            "profile_downloaded",
            "profile_validation_failed",
            "download_page_loaded",
            "download_page_status",
            "check_response_keys",
            "token_response_keys",
            "token_response_has_url",
            "token_response_has_token",
            "content_type",
            "body_kind",
            "download_page_content_type",
            "download_page_body_kind",
            "check_content_type",
            "check_body_kind",
            "token_content_type",
            "token_body_kind",
            "validation_stage",
            "expected_endpoint",
            "config_remotes",
            "hash_expected_present",
            "hash_response_present",
            "hash_matches",
        ):
            if key in flow and flow.get(key) not in (None, ""):
                flow_summary[key] = flow.get(key)
    if isinstance(exc, urllib.error.HTTPError):
        status = int(getattr(exc, "code", 0) or 0)
        if status == 429:
            category = "rate_limited"
        elif status in {401, 403, 407}:
            category = "github_runner_blocked"
        else:
            category = "http_error"
        return {
            "category": category,
            "status": status,
            "type": type(exc).__name__,
            "reason": _safe_reason_code(exc),
            "flow": flow_summary,
        }
    if isinstance(exc, (urllib.error.URLError, TimeoutError, OSError)):
        return {
            "category": "network_error",
            "status": 0,
            "type": type(exc).__name__,
            "reason": _safe_reason_code(exc),
            "flow": flow_summary,
        }
    return {
        "category": "schema_changed",
        "status": 0,
        "type": type(exc).__name__,
        "reason": _safe_reason_code(exc),
        "flow": flow_summary,
    }


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
        if "github_runner_blocked" in categories:
            return "github_runner_blocked"
        if categories <= {"network_error"}:
            return "network_error"
        if "schema_changed" in categories:
            return "schema_changed"
        return "http_error"
    if not metadata_records:
        return "metadata_empty"
    if not mapped_records:
        has_identity = any(
            str(record.get("id") or record.get("public_id") or "").strip()
            or str(record.get("hostname") or record.get("host") or "").strip()
            for record in metadata_records
            if isinstance(record, dict)
        )
        return "mapping_missing" if has_identity else "metadata_only"
    return "api_success"


def _row_mapping(manager, raw: dict[str, Any]) -> bool:
    row = manager.normalize_publicvpnlist_row(raw)
    if not row:
        return False
    return bool(
        str(row.get("temporary_ovpn_url") or "").strip()
        or manager.publicvpnlist_web_download_id(row)
    )


def _select_records(
    manager,
    records: list[dict[str, Any]],
    countries: list[str],
    limit: int,
    retry_cache: dict[str, Any] | None = None,
    blocked_endpoint_keys: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Return at most two stable, non-backoff candidates per country."""

    allowed = {str(item).strip().upper() for item in countries if str(item).strip()}
    per_country_limit = min(
        2,
        max(1, int(getattr(manager, "PUBLICVPNLIST_LIVE_FLOW_ATTEMPTS_PER_COUNTRY", 2))),
    )
    ordered = manager.publicvpnlist_order_api_candidate_records(
        records,
        retry_cache=retry_cache,
        now=time.time(),
    )
    selected: list[dict[str, Any]] = []
    selected_by_country: dict[str, int] = {}
    selected_endpoint_keys: set[str] = set()
    dns_cache: dict[str, str | None] = {}
    blocked = set(blocked_endpoint_keys or ())
    for raw in ordered:
        row = manager.normalize_publicvpnlist_row(raw)
        country = str(row.get("country_short") or "").upper() if row else ""
        if not row or country not in allowed:
            continue
        if selected_by_country.get(country, 0) >= per_country_limit:
            continue
        if retry_cache and manager.publicvpnlist_api_profile_retry_active(
            retry_cache,
            row,
            now=time.time(),
        ):
            continue
        try:
            aliases = set(manager.publicvpnlist_endpoint_aliases(row, dns_cache))
        except Exception:
            aliases = set()
        if aliases and aliases & (blocked | selected_endpoint_keys):
            continue
        selected.append(dict(raw))
        selected_by_country[country] = selected_by_country.get(country, 0) + 1
        selected_endpoint_keys.update(aliases)
        if len(selected) >= max(1, int(limit)):
            break
    return selected


def _record_country_reason(
    report: dict[str, Any],
    field: str,
    country: str,
    reason: str,
) -> None:
    country = str(country or "").upper()
    if country not in report.get(field, {}):
        return
    bucket = report[field][country]
    if isinstance(bucket, dict):
        bucket[reason] = int(bucket.get(reason) or 0) + 1


def _prepare_candidates(
    manager,
    records: list[dict[str, Any]],
    countries: list[str],
    limit: int,
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    """Apply mapping, retry, endpoint and US policy before live-flow attempts."""

    allowed = {str(item).strip().upper() for item in countries if str(item).strip()}
    per_country_limit = min(
        2,
        max(1, int(getattr(manager, "PUBLICVPNLIST_LIVE_FLOW_ATTEMPTS_PER_COUNTRY", 2))),
    )
    try:
        retry_cache = manager.load_publicvpnlist_api_cache()
    except Exception:
        retry_cache = {}
    now = time.time()
    ordered = manager.publicvpnlist_order_api_candidate_records(
        records,
        retry_cache=retry_cache,
        now=now,
    )
    normalized: list[tuple[int, dict[str, Any], dict[str, Any]]] = []
    us_rows: list[tuple[str, dict[str, Any]]] = []
    for index, raw in enumerate(ordered):
        row = manager.normalize_publicvpnlist_row(raw)
        if not row:
            continue
        country = str(row.get("country_short") or "").upper()
        if country not in allowed:
            continue
        normalized.append((index, row, dict(raw)))
        if country == "US":
            key = str(row.get("id") or row.get("public_id") or "").strip() or f"US:{index}"
            us_rows.append((key, row))
    classifications: dict[str, dict[str, Any]] = {}
    if us_rows:
        try:
            classifications, batch_failed = manager.publicvpnlist_enrich_us_rows(us_rows)
        except Exception:
            classifications = {}
            batch_failed = True
        report["us_classification_attempted"] += len(us_rows)
        if batch_failed and not classifications:
            for key, _row in us_rows:
                classifications[key] = manager.publicvpnlist_classification_defaults()
    endpoint_keys: set[str] = set()
    dns_cache: dict[str, str | None] = {}
    selected: list[dict[str, Any]] = []
    selected_by_country: dict[str, int] = {}
    for index, row, raw in normalized:
        country = str(row.get("country_short") or "").upper()
        config_url = str(row.get("temporary_ovpn_url") or "").strip()
        if not config_url and not manager.publicvpnlist_web_download_id(row):
            _record_country_reason(report, "skipped_by_country", country, "web_download_id_missing")
            continue
        if retry_cache and manager.publicvpnlist_api_profile_retry_active(
            retry_cache,
            row,
            now=now,
        ):
            _record_country_reason(report, "skipped_by_country", country, "profile_backoff")
            continue
        try:
            aliases = set(manager.publicvpnlist_endpoint_aliases(row, dns_cache))
        except Exception:
            aliases = set()
        if aliases and aliases & endpoint_keys:
            _record_country_reason(report, "skipped_by_country", country, "endpoint_duplicate")
            continue
        effective_raw = dict(raw)
        if country == "US":
            key = str(row.get("id") or row.get("public_id") or "").strip() or f"US:{index}"
            classification = manager.publicvpnlist_normalize_classification(
                classifications.get(key)
            )
            risk_sources = {
                str(item).strip().lower()
                for item in (classification or {}).get("risk_sources", [])
                if str(item).strip()
            }
            ip_type = manager.normalize_ip_type_token((classification or {}).get("ip_type"))
            if not classification or ip_type in {"", "unknown"} or not risk_sources:
                report["us_unclassified_rejected"] += 1
                _record_country_reason(report, "skipped_by_country", country, "us_unclassified")
                continue
            if not manager.publicvpnlist_us_classification_allowed(classification):
                report["us_nonresidential_rejected"] += 1
                _record_country_reason(report, "skipped_by_country", country, "us_nonresidential")
                continue
            report["us_residential_accepted"] += 1
            effective_raw.update(classification)
        if selected_by_country.get(country, 0) >= per_country_limit:
            _record_country_reason(report, "skipped_by_country", country, "country_attempt_limit")
            continue
        report["eligible_candidates_by_country"][country] += 1
        selected.append(effective_raw)
        selected_by_country[country] = selected_by_country.get(country, 0) + 1
        endpoint_keys.update(aliases)
        if len(selected) >= max(1, int(limit)):
            break
    report["available_countries"] = [
        country for country in countries
        if int(report["eligible_candidates_by_country"].get(country, 0) or 0) > 0
    ]
    return selected


def _account_flow_report(report: dict[str, Any], country: str, flow: dict[str, Any]) -> None:
    country = str(country or "").upper()
    if country not in report.get("attempts_by_country", {}):
        return
    if flow.get("live_check_succeeded"):
        report["live_check_succeeded_by_country"][country] += 1
    if flow.get("token_generated"):
        report["token_generated_by_country"][country] += 1
    if flow.get("profile_downloaded"):
        report["downloaded_by_country"][country] += 1

_FLOW_DIAGNOSTIC_KEYS = (
    "status",
    "retry_after",
    "live_check_succeeded",
    "live_check_status",
    "token_request_attempted",
    "token_generated",
    "profile_download_attempted",
    "profile_downloaded",
    "profile_validation_failed",
    "download_page_loaded",
    "download_page_status",
    "check_response_keys",
    "token_response_keys",
    "token_response_has_url",
    "token_response_has_token",
    "content_type",
    "body_kind",
    "download_page_content_type",
    "download_page_body_kind",
    "check_content_type",
    "check_body_kind",
    "token_content_type",
    "token_body_kind",
    "expected_endpoint",
    "config_remotes",
    "hash_expected_present",
    "hash_response_present",
    "hash_matches",
)


def _attach_flow_diagnostic(exc: BaseException, metadata: dict[str, Any], stage: str = "") -> None:
    summary = {
        key: metadata.get(key)
        for key in _FLOW_DIAGNOSTIC_KEYS
        if metadata.get(key) not in (None, "")
    }
    if stage:
        summary["validation_stage"] = stage
    setattr(exc, "_pvl_flow", summary)


def _download_one(manager, raw: dict[str, Any], timeout: int) -> dict[str, Any]:
    row = manager.normalize_publicvpnlist_row(raw)
    if not row:
        raise ValueError("row_not_normalizable")
    metadata: dict[str, Any] = {}
    manager.PUBLICVPNLIST_CONFIG_TIMEOUT_SECONDS = max(1, int(timeout))
    manager.PUBLICVPNLIST_API_TIMEOUT_SECONDS = max(1, int(timeout))
    temporary_url = str(row.get("temporary_ovpn_url") or "").strip()
    deadline = time.monotonic() + max(1, int(timeout))
    try:
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
    except Exception as exc:
        _attach_flow_diagnostic(exc, metadata)
        raise

    try:
        actual_hash = str(metadata.get("response_sha256") or "").strip().lower()
        expected_hash = str(row.get("config_sha256") or "").strip().lower()
        metadata["hash_expected_present"] = bool(expected_hash)
        metadata["hash_response_present"] = bool(actual_hash)
        metadata["hash_matches"] = bool(expected_hash and actual_hash == expected_hash) if expected_hash else True
        metadata["expected_endpoint"] = {
            "host": str(row.get("host") or row.get("ip") or ""),
            "port": int(row.get("port") or row.get("remote_port") or 0),
            "proto": str(row.get("proto") or row.get("transport") or ""),
        }
        try:
            remotes, global_proto = manager.parse_publicvpnlist_openvpn_remotes(config_text)
            metadata["config_remotes"] = [
                {
                    "host": str(remote.get("host") or ""),
                    "port": int(remote.get("port") or 0),
                    "proto": str(remote.get("proto") or global_proto or ""),
                }
                for remote in remotes
            ]
        except Exception:
            metadata["config_remotes"] = []
        if expected_hash and actual_hash != expected_hash:
            raise ValueError("config_sha256_mismatch")
        node = manager.publicvpnlist_row_to_node(row, config_text)
        if not node:
            raise ValueError("endpoint_validation_failed")
    except Exception as exc:
        stage = "config_sha256" if str(exc) == "config_sha256_mismatch" else "endpoint_validation"
        _attach_flow_diagnostic(exc, metadata, stage)
        raise

    flow_summary = {
        key: metadata.get(key)
        for key in _FLOW_DIAGNOSTIC_KEYS
        if metadata.get(key) not in (None, "")
    }
    return {
        "_flow": flow_summary,
        "country": str(node.get("country_short") or ""),
        "host": str(node.get("remote_host") or ""),
        "port": int(node.get("remote_port") or 0),
        "proto": str(node.get("proto") or ""),
        "response_sha256_present": bool(actual_hash),
        "config_sha256": actual_hash or hashlib.sha256(config_text.encode("utf-8")).hexdigest(),
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
        for item in str(
            args.countries
            or "US,FR,GB,ID,FI,DE,TW,AU,NL,PH"
        ).split(",")
        if str(item).strip()
    ]
    base_url = manager.publicvpnlist_api_base_url()
    report: dict[str, Any] = {
        "status": "not_started",
        "mode": "api",
        "countries": countries,
        "metadata_records": 0,
        "metadata_with_download_path": 0,
        "web_catalog_records": 0,
        "web_catalog_matches": 0,
        "metadata_only_skipped": 0,
        "metadata_records_by_country": {country: 0 for country in countries},
        "mapped_records_by_country": {country: 0 for country in countries},
        "available_countries": [],
        "eligible_candidates_by_country": {country: 0 for country in countries},
        "attempts_by_country": {country: 0 for country in countries},
        "live_check_succeeded_by_country": {country: 0 for country in countries},
        "token_generated_by_country": {country: 0 for country in countries},
        "downloaded_by_country": {country: 0 for country in countries},
        "validated_by_country": {country: 0 for country in countries},
        "connectable_by_country": {country: 0 for country in countries},
        "skipped_by_country": {country: {} for country in countries},
        "failed_candidates_by_country": {country: {} for country in countries},
        "us_classification_attempted": 0,
        "us_residential_accepted": 0,
        "us_nonresidential_rejected": 0,
        "us_unclassified_rejected": 0,
        "connectable_candidates": 0,
        "config_downloads": 0,
        "profiles_downloaded": 0,
        "profiles_validated": 0,
        "download_results": [],
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
    web_catalog_meta: dict[str, Any] = {}
    all_records = manager.publicvpnlist_attach_official_web_ids(
        all_records,
        web_catalog_meta,
    )
    report["web_catalog_records"] = int(
        web_catalog_meta.get("web_catalog_records") or 0
    )
    report["web_catalog_matches"] = int(
        web_catalog_meta.get("web_catalog_matches") or 0
    )
    if web_catalog_meta.get("web_catalog_error_code"):
        report["errors"].append(
            {
                "category": "web_catalog_error",
                "status": int(web_catalog_meta.get("web_catalog_status") or 0),
                "type": str(web_catalog_meta.get("web_catalog_error_code")),
            }
        )
    normalized_rows = [
        manager.normalize_publicvpnlist_row(record)
        for record in all_records
    ]
    normalized_rows = [row for row in normalized_rows if row and row.get("country_short") in set(countries)]
    for raw in all_records:
        row = manager.normalize_publicvpnlist_row(raw)
        if not row:
            continue
        country = str(row.get("country_short") or "").upper()
        if country not in report["metadata_records_by_country"]:
            continue
        report["metadata_records_by_country"][country] += 1
        if _row_mapping(manager, raw):
            report["mapped_records_by_country"][country] += 1
        else:
            report["skipped_by_country"][country]["metadata_only"] = (
                report["skipped_by_country"][country].get("metadata_only", 0) + 1
            )
    report["available_countries"] = [
        country
        for country in countries
        if report["metadata_records_by_country"].get(country, 0) > 0
    ]
    report["metadata_with_download_path"] = sum(
        report["mapped_records_by_country"].values()
    )
    report["metadata_only_skipped"] = sum(
        report["skipped_by_country"][country].get("metadata_only", 0)
        for country in countries
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
        # Candidate selection is also bounded to the first two ranked rows per
        # country, so the smoke exercises the same two-round policy as refresh.
        detail_meta = {"request_count": 0}
        try:
            retry_cache = manager.load_publicvpnlist_api_cache()
            ranked = manager.publicvpnlist_order_api_candidate_records(
                all_records,
                retry_cache=retry_cache,
                now=time.time(),
            )
            enriched = manager.publicvpnlist_api_enrich_records_for_download(
                ranked[: max(1, min(100, int(args.max_profiles) * 5))],
                detail_meta,
            )
            candidates = _prepare_candidates(
                manager,
                enriched,
                countries,
                args.max_profiles,
                report,
            )
            flow_deadline = started + max(1, int(args.timeout))
            for raw in candidates[: max(1, int(args.max_profiles))]:
                row = manager.normalize_publicvpnlist_row(raw)
                country = str(row.get("country_short") or "").upper() if row else ""
                if country not in report["attempts_by_country"]:
                    continue
                remaining = flow_deadline - time.monotonic()
                if remaining <= 0:
                    _record_country_reason(report, "skipped_by_country", country, "deadline_exceeded")
                    continue
                report["attempts_by_country"][country] += 1
                try:
                    result = _download_one(
                        manager,
                        raw,
                        max(1, min(int(args.timeout), int(remaining))),
                    )
                    flow = result.pop("_flow", {})
                    _account_flow_report(report, country, flow)
                    report["config_downloads"] += 1
                    report["profiles_downloaded"] += 1
                    report["profiles_validated"] += 1
                    report["connectable_by_country"][country] += 1
                    report["connectable_candidates"] += 1
                    report["download_results"].append(result)
                    report.setdefault("download_result", result)
                except Exception as exc:
                    flow = getattr(exc, "_pvl_flow", {})
                    if not isinstance(flow, dict):
                        flow = {}
                    _account_flow_report(report, country, flow)
                    if flow.get("profile_downloaded"):
                        report["profiles_downloaded"] += 1
                    reason = _safe_reason_code(exc)
                    _record_country_reason(
                        report,
                        "failed_candidates_by_country",
                        country,
                        reason,
                    )
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
    if args.download and (
        report["profiles_downloaded"] < 1
        or report["profiles_validated"] < 1
        or report["connectable_candidates"] < 1
    ):
        return 1, report
    return 0, report


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="PublicVPNList API/config smoke check")
    parser.add_argument("--api", action="store_true", help="validate API v1 (default)")
    parser.add_argument("--countries", default="US,FR,GB,ID,FI,DE,TW,AU,NL,PH")
    parser.add_argument("--max-profiles", type=int, default=20)
    parser.add_argument("--timeout", type=int, default=180)
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
            "profiles_downloaded": 0,
            "profiles_validated": 0,
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
