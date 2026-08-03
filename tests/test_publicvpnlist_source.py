import json
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

import vpngate_manager


OPENVPN_CONFIG = """client
dev tun
proto {proto}
remote {host} {port}
nobind
<ca>
-----BEGIN CERTIFICATE-----
FIXTURE
-----END CERTIFICATE-----
</ca>
"""


class PublicVPNListSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        data_dir = Path(self.temp_dir.name)
        self.cache_file = data_dir / "publicvpnlist_cache.json"

        def fixture_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if host == "fixture.invalid":
                return [(vpngate_manager.socket.AF_INET, vpngate_manager.socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
            return []

        self.patches = mock.patch.multiple(
            vpngate_manager,
            DATA_DIR=data_dir,
            CONFIG_DIR=data_dir / "configs",
            PUBLICVPNLIST_CACHE_FILE=self.cache_file,
            PUBLICVPNLIST_SNAPSHOT_URL="https://fixture.invalid/export-builder-snapshot.json?signature=fixture",
            PUBLICVPNLIST_SNAPSHOT_FILE="",
            PUBLICVPNLIST_REFRESH_SECONDS=3600,
            PUBLICVPNLIST_STALE_PROFILE_SECONDS=7 * 24 * 3600,
            PUBLICVPNLIST_CONFIG_TIMEOUT_SECONDS=45,
            PUBLICVPNLIST_MAX_NODES=100,
            PUBLICVPNLIST_MAX_SCAN_ROWS=500,
            PUBLICVPNLIST_MAX_RAW_ROWS=5000,
            PUBLICVPNLIST_MAX_RESPONSE_BYTES=1024 * 1024,
            PUBLICVPNLIST_MAX_RETRIES=1,
            PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS=frozenset({"fixture.invalid"}),
            _orig_getaddrinfo=fixture_getaddrinfo,
        )
        self.patches.start()
        self.addCleanup(self.patches.stop)

    @staticmethod
    def config(host, port, proto="tcp"):
        return OPENVPN_CONFIG.format(host=host, port=port, proto=proto)

    @staticmethod
    def _response(body):
        class Response:
            headers = {}

            def __init__(self, payload):
                self.payload = payload
                self.done = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                if self.done:
                    return b""
                self.done = True
                return self.payload

        return Response(body)

    @staticmethod
    def row(
        node_id,
        country,
        ip,
        port=443,
        proto="tcp",
        host=None,
        temporary=True,
        page=True,
    ):
        # This mirrors one Export Builder server record: server metadata lives
        # in the JSON snapshot, while the temporary profile URL is separate
        # from the HTML server page URL.
        row = {
            "id": node_id,
            "country": country,
            "countryName": country,
            "host": host or ip,
            "ip": ip,
            "port": port,
            "proto": proto,
            "speed": 12.5,
            "latency": 42,
            "checkedAt": "2026-08-03T00:00:00Z",
        }
        if temporary:
            row["temporary_ovpn_url"] = f"https://fixture.invalid/{node_id}.ovpn?token=short-lived"
        if page:
            row["download_page_url"] = f"https://fixture.invalid/servers/{node_id}"
        return row

    def fetch_rows(self, rows, target=None, enrich=None, snapshot=None, http_get=None):
        configs = {}
        pages = {}
        for row in rows:
            url = row.get("temporary_ovpn_url")
            if url:
                configs[url] = self.config(
                    row.get("host") or row.get("ip"),
                    row["port"],
                    row.get("proto", "tcp"),
                ).encode()
            if row.get("download_page_url"):
                pages[row["download_page_url"]] = b"<html><body>server page</body></html>"

        def fixture_http_get(url, timeout=15, max_bytes=None, accept=None, opener=None, metadata=None):
            if http_get is not None:
                return http_get(
                    url,
                    timeout=timeout,
                    max_bytes=max_bytes,
                    accept=accept,
                    opener=opener,
                    metadata=metadata,
                )
            if url in configs:
                return configs[url]
            if url in pages:
                return pages[url]
            raise AssertionError(f"unexpected fixture URL: {url}")

        snapshot = snapshot if snapshot is not None else {"data": rows}
        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", return_value=snapshot), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=fixture_http_get
        ), mock.patch.object(vpngate_manager.vpn_utils, "enrich_ip_info", side_effect=enrich) as enrich_mock:
            result = vpngate_manager.fetch_publicvpnlist_candidates(target or [], set())
        return result, enrich_mock

    def candidate(self, source, ip, port=443, proto="tcp", host=None):
        return {
            "id": f"{source}-{ip}-{port}-{proto}",
            "source": source,
            "ip": ip,
            "remote_host": host or ip,
            "host_name": host or ip,
            "remote_port": port,
            "proto": proto,
        }

    def test_default_source_order_excludes_publicvpnlist_but_alias_is_available(self):
        self.assertEqual(
            vpngate_manager.split_node_sources("all"),
            ["vpngate", "vpnbook", "ipspeed", "vpngate_scraper"],
        )
        self.assertEqual(vpngate_manager.split_node_sources("public_vpn_list,pvl"), ["publicvpnlist"])
        self.assertIn("PublicVPNList", vpngate_manager.node_sources_display("publicvpnlist"))

    def test_unconfigured_publicvpnlist_returns_empty_without_network(self):
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", ""), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", ""
        ), mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_snapshot", side_effect=AssertionError("network request")
        ), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=AssertionError("network request")
        ), mock.patch.object(vpngate_manager, "log_to_json") as log_mock:
            result = vpngate_manager.fetch_publicvpnlist_candidates([], set())
            display = vpngate_manager.node_sources_display("publicvpnlist")
        self.assertEqual(result, [])
        self.assertIn("未配置快照", display)
        messages = " ".join(str(call.args[2]) for call in log_mock.call_args_list if len(call.args) >= 3)
        self.assertIn("未配置快照", messages)

    def test_publicvpnlist_configuration_status_distinguishes_snapshot_and_download_hosts(self):
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", ""), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", ""
        ):
            self.assertEqual(vpngate_manager.publicvpnlist_configuration_status(), "snapshot_missing")
            self.assertIn("未配置快照", vpngate_manager.node_sources_display("publicvpnlist"))
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", "https://fixture.invalid/snapshot"), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", ""
        ), mock.patch.object(vpngate_manager, "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS", frozenset()):
            self.assertEqual(vpngate_manager.publicvpnlist_configuration_status(), "download_hosts_missing")
            self.assertIn("未配置下载域名", vpngate_manager.node_sources_display("publicvpnlist"))
        cache = vpngate_manager.publicvpnlist_cache_default("fixture")
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", "https://fixture.invalid/snapshot"), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS", frozenset({"fixture.invalid"})
        ):
            cache["cache_stale"] = True
            self.assertEqual(vpngate_manager.publicvpnlist_configuration_status(cache), "stale_cache")
            cache["refresh_failed"] = True
            self.assertEqual(vpngate_manager.publicvpnlist_configuration_status(cache), "refresh_failed")

    def test_missing_download_hosts_logs_once_and_cache_only_skips_refresh(self):
        row = self.row("cache-only-status", "PH", "198.51.100.55")
        first, _ = self.fetch_rows([row], target=["PH"])
        self.assertEqual(len(first), 1)
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS", frozenset()), mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_snapshot", side_effect=AssertionError("cache-only must not refresh")
        ), mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_config", side_effect=AssertionError("cache-only must not download")
        ), mock.patch.object(vpngate_manager, "log_to_json") as log_mock:
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
            status = vpngate_manager.publicvpnlist_configuration_status()
        self.assertEqual([node["ip"] for node in result], [row["ip"]])
        self.assertEqual(status, "cache_only")
        messages = [str(call.args[2]) for call in log_mock.call_args_list if len(call.args) >= 3]
        self.assertEqual(sum("仅使用缓存" in message for message in messages), 1)

    def test_missing_download_hosts_without_cache_returns_empty_with_one_clear_log(self):
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS", frozenset()), mock.patch.object(
            vpngate_manager, "log_to_json"
        ) as log_mock:
            result = vpngate_manager.fetch_publicvpnlist_candidates([], set())
        self.assertEqual(result, [])
        messages = [str(call.args[2]) for call in log_mock.call_args_list if len(call.args) >= 3]
        self.assertEqual(sum("未配置下载域名" in message for message in messages), 1)

    def test_local_snapshot_file_is_supported(self):
        snapshot_file = Path(self.temp_dir.name) / "export-builder.json"
        snapshot_file.write_text(json.dumps({"data": []}), encoding="utf-8")
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", ""), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", str(snapshot_file)
        ), mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=AssertionError("network request")):
            self.assertEqual(vpngate_manager.fetch_publicvpnlist_snapshot(), {"data": []})

    def test_unchanged_local_snapshot_does_not_reuse_expired_temporary_url(self):
        snapshot_file = Path(self.temp_dir.name) / "stable-export.json"
        row = self.row("local-stable", "PH", "198.51.100.64")
        snapshot_file.write_text(json.dumps({"data": [row]}), encoding="utf-8")
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", ""), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", str(snapshot_file)
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            return_value=self.config(row["host"], row["port"], row["proto"]).encode(),
        ) as http_get:
            first = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
            self.assertEqual(len(first), 1)
            cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
            cache["last_refresh_attempt_at"] = time.time() - 7200
            self.cache_file.write_text(json.dumps(cache), encoding="utf-8")
            http_get.reset_mock()
            with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", side_effect=AssertionError("unchanged file")), mock.patch.object(
                vpngate_manager, "fetch_publicvpnlist_config", side_effect=AssertionError("expired URL reused")
            ):
                second = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        self.assertEqual([node["ip"] for node in second], ["198.51.100.64"])
        self.assertEqual(http_get.call_count, 0)

    def test_changed_local_snapshot_refreshes_new_profiles_only(self):
        snapshot_file = Path(self.temp_dir.name) / "changing-export.json"
        first_row = self.row("local-first", "PH", "198.51.100.65")
        second_row = self.row("local-second", "FR", "198.51.100.66")
        snapshot_file.write_text(json.dumps({"data": [first_row]}), encoding="utf-8")
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", ""), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", str(snapshot_file)
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            return_value=self.config(first_row["host"], first_row["port"], first_row["proto"]).encode(),
        ):
            vpngate_manager.fetch_publicvpnlist_candidates([], set())
        snapshot_file.write_text(json.dumps({"data": [first_row, second_row]}), encoding="utf-8")
        os_stat = snapshot_file.stat()
        snapshot_file.touch()
        calls = []

        def changed_http_get(url, timeout=15, max_bytes=None, accept=None, **_kwargs):
            calls.append(url)
            return self.config(second_row["host"], second_row["port"], second_row["proto"]).encode()

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", ""), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", str(snapshot_file)
        ), mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=changed_http_get):
            result = vpngate_manager.fetch_publicvpnlist_candidates([], set())
        self.assertEqual([node["ip"] for node in result], ["198.51.100.65", "198.51.100.66"])
        self.assertEqual(calls, [second_row["temporary_ovpn_url"]])
        self.assertGreaterEqual(snapshot_file.stat().st_mtime_ns, os_stat.st_mtime_ns)

    def test_documented_snapshot_field_names_are_normalized(self):
        row = {
            "id": "documented-fields",
            "country_code": "PH",
            "country_name": "Philippines",
            "hostname": "198.51.100.19",
            "ip": "198.51.100.19",
            "protocol": "openvpn",
            "transport": "tcp",
            "port": 443,
            "speed_mbps": 12.5,
            "latency_ms": 37,
            "last_checked_at": "2026-08-03T00:00:00Z",
            "server_page_url": "https://fixture.invalid/server/documented-fields",
            "config_download_url": "https://fixture.invalid/documented-fields.ovpn?token=short-lived",
        }
        normalized = vpngate_manager.normalize_publicvpnlist_row(row)
        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual(normalized["country_short"], "PH")
        self.assertEqual(normalized["host"], "198.51.100.19")
        self.assertEqual(normalized["proto"], "tcp")
        self.assertEqual(normalized["ping"], 37)
        self.assertEqual(normalized["checked_at"], "2026-08-03T00:00:00Z")
        self.assertIn("short-lived", normalized["temporary_ovpn_url"])

    def test_allowed_ph_and_other_fixed_countries_are_accepted(self):
        countries = ["PH", "FR", "GB", "ID", "FI", "DE", "TW", "AU", "NL"]
        rows = [self.row(f"node-{country}", country, f"198.51.100.{index + 1}") for index, country in enumerate(countries)]
        result, enrich_mock = self.fetch_rows(rows)
        self.assertEqual({node["country_short"] for node in result}, set(countries))
        enrich_mock.assert_not_called()

    def test_fixed_country_filter_rejects_unlisted_countries(self):
        rows = [
            self.row("ph", "PH", "198.51.100.20"),
            self.row("jp", "JP", "198.51.100.21"),
            self.row("kr", "KR", "198.51.100.22"),
            self.row("ca", "CA", "198.51.100.23"),
        ]
        result, _ = self.fetch_rows(rows)
        self.assertEqual([node["country_short"] for node in result], ["PH"])

    def test_fixed_country_filter_and_eligible_scan_happen_before_config_download(self):
        jp_rows = [self.row(f"jp-{index}", "JP", f"198.51.{index // 250}.{index % 250 + 1}") for index in range(500)]
        ph = self.row("ph-after-jp", "PH", "198.51.200.1")
        calls = []

        def http_get(url, **_kwargs):
            calls.append(url)
            return self.config(ph["host"], ph["port"], ph["proto"]).encode()

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_MAX_SCAN_ROWS", 1), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_MAX_RAW_ROWS", 1000
        ):
            result, _ = self.fetch_rows(jp_rows + [ph], http_get=http_get)
        self.assertEqual([node["country_short"] for node in result], ["PH"])
        self.assertEqual(calls, [ph["temporary_ovpn_url"]])
        state = json.loads(self.cache_file.read_text(encoding="utf-8"))
        self.assertEqual(state["last_refresh_stats"]["fixed_country_filtered"], 500)
        self.assertEqual(state["last_refresh_stats"]["eligible_scanned"], 1)

    def test_raw_row_limit_is_independent_from_eligible_country_limit(self):
        rows = [self.row("jp-raw-0", "JP", "198.51.201.1"), self.row("jp-raw-1", "JP", "198.51.201.2")]
        ph = self.row("ph-after-raw-limit", "PH", "198.51.201.3")
        calls = []

        def http_get(url, **_kwargs):
            calls.append(url)
            return self.config(ph["host"], ph["port"], ph["proto"]).encode()

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_MAX_RAW_ROWS", 2), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_MAX_SCAN_ROWS", 10
        ):
            result, _ = self.fetch_rows(rows + [ph], http_get=http_get)
        self.assertEqual(result, [])
        self.assertEqual(calls, [])
        state = json.loads(self.cache_file.read_text(encoding="utf-8"))
        self.assertTrue(state["last_refresh_stats"]["raw_limit_hit"])

    def test_target_country_filter_is_intersection_with_fixed_policy(self):
        rows = [
            self.row("ph", "PH", "198.51.100.30"),
            self.row("fr", "FR", "198.51.100.31"),
            self.row("jp", "JP", "198.51.100.32"),
        ]
        result, _ = self.fetch_rows(rows, target=["FR", "JP"])
        self.assertEqual([node["country_short"] for node in result], ["FR"])

        empty, _ = self.fetch_rows(rows, target=["JP"])
        self.assertEqual(empty, [])

    def test_us_accepts_only_classified_residential(self):
        classifications = {
            "198.51.100.40": ("residential", ["ip-api.com"]),
            "198.51.100.41": ("mobile", ["ip-api.com"]),
            "198.51.100.42": ("hosting", ["ip-api.com"]),
            "198.51.100.43": ("proxy", ["ip-api.com"]),
            "198.51.100.44": ("residential", []),
        }
        rows = [self.row(f"us-{index}", "US", ip) for index, ip in enumerate(classifications, start=40)]

        def enrich(nodes):
            for node in nodes:
                node["ip_type"], node["risk_sources"] = classifications[node["ip"]]

        result, enrich_mock = self.fetch_rows(rows, target=["US"], enrich=enrich)
        self.assertEqual([node["ip"] for node in result], ["198.51.100.40"])
        self.assertEqual(enrich_mock.call_count, 1)
        self.assertEqual(len(enrich_mock.call_args.args[0]), len(rows))

    def test_us_residential_classification_is_written_to_final_node_and_sorting(self):
        row = self.row("us-full-classification", "US", "198.51.100.47")

        def enrich(nodes):
            nodes[0].update(
                ip_type="residential",
                risk_sources=["ip-api.com", "fraudguard"],
                owner="Fixture ISP",
                asn="AS64500",
                as_name="Fixture Residential",
                location="US",
                quality="clean_residential",
                fraud_score=2,
                clean_score=98,
                risk_level="clean",
                fraud_flags=[],
                blacklist_hits=[],
                blacklist_count=0,
                ip_clean=True,
            )

        with mock.patch.object(vpngate_manager, "log_to_json") as log_mock:
            result, _ = self.fetch_rows([row], target=["US"], enrich=enrich)
        self.assertEqual(len(result), 1)
        node = result[0]
        self.assertEqual(node["ip_type"], "residential")
        self.assertEqual(node["risk_sources"], ["ip-api.com", "fraudguard"])
        self.assertEqual(node["owner"], "Fixture ISP")
        self.assertEqual(node["asn"], "AS64500")
        self.assertTrue(node["ip_clean"])
        cached_state = json.loads(self.cache_file.read_text(encoding="utf-8"))
        cached_profile = next(iter(cached_state["profiles"].values()))
        self.assertEqual(cached_profile["ip_type"], "residential")
        self.assertEqual(cached_profile["risk_sources"], ["ip-api.com", "fraudguard"])
        self.assertEqual(vpngate_manager.node_ip_priority_rank(node), 0)
        messages = " ".join(str(call.args[2]) for call in log_mock.call_args_list if len(call.args) >= 3)
        self.assertIn("residential 保留 1", messages)

    def test_us_mobile_and_hosting_nodes_do_not_generate_profiles(self):
        rows = [
            self.row("us-mobile", "US", "198.51.100.48"),
            self.row("us-hosting", "US", "198.51.100.49"),
        ]

        def enrich(nodes):
            for node in nodes:
                node.update(
                    ip_type="mobile" if node["ip"] == rows[0]["ip"] else "hosting",
                    risk_sources=["ip-api.com"],
                )

        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_config") as config_builder:
            result, _ = self.fetch_rows(rows, target=["US"], enrich=enrich)
        self.assertEqual(result, [])
        config_builder.assert_not_called()

    def test_us_dnsbl_only_result_is_not_a_complete_classification(self):
        row = self.row("us-dnsbl", "US", "198.51.100.45")

        def enrich(nodes):
            nodes[0].update(ip_type="residential", risk_sources=["dnsbl"])

        result, _ = self.fetch_rows([row], target=["US"], enrich=enrich)
        self.assertEqual(result, [])

    def test_us_enrichment_failure_fails_closed(self):
        row = self.row("us-error", "US", "198.51.100.46")

        def fail(_nodes):
            raise OSError("fixture risk service unavailable")

        result, _ = self.fetch_rows([row], target=["US"], enrich=fail)
        self.assertEqual(result, [])

    def test_us_nonresidential_rows_are_rejected_before_any_config_download(self):
        rows = [self.row(f"us-hosting-precheck-{index}", "US", f"198.51.202.{index + 1}") for index in range(100)]
        calls = []

        def enrich(nodes):
            self.assertTrue(all(set(node) == {"ip", "remote_host", "country_short", "ip_type", "risk_sources"} for node in nodes))
            for node in nodes:
                node.update(ip_type="hosting", risk_sources=["ip-api.com"])

        def http_get(url, **_kwargs):
            calls.append(url)
            return b"unexpected configuration download"

        result, enrich_mock = self.fetch_rows(rows, target=["US"], enrich=enrich, http_get=http_get)
        self.assertEqual(result, [])
        self.assertEqual(calls, [])
        self.assertEqual(enrich_mock.call_count, 1)

    def test_only_residential_us_row_reaches_config_download(self):
        hosting_rows = [self.row(f"us-hosting-only-{index}", "US", f"198.51.203.{index + 1}") for index in range(99)]
        residential = self.row("us-residential-only", "US", "198.51.204.1")
        calls = []

        def enrich(nodes):
            for node in nodes:
                if node["ip"] == residential["ip"]:
                    node.update(ip_type="residential", risk_sources=["ip-api.com"])
                else:
                    node.update(ip_type="hosting", risk_sources=["ip-api.com"])

        def http_get(url, **_kwargs):
            calls.append(url)
            return self.config(residential["host"], residential["port"], residential["proto"]).encode()

        result, enrich_mock = self.fetch_rows(hosting_rows + [residential], target=["US"], enrich=enrich, http_get=http_get)
        self.assertEqual([node["ip"] for node in result], [residential["ip"]])
        self.assertEqual(calls, [residential["temporary_ovpn_url"]])
        self.assertEqual(enrich_mock.call_count, 1)

    def test_temporary_url_is_used_before_download_page_url(self):
        row = self.row("temporary-first", "PH", "198.51.100.50", page=True)
        calls = []

        def http_get(url, timeout=15, max_bytes=None, accept=None, **_kwargs):
            calls.append(url)
            return self.config(row["host"], row["port"], row["proto"]).encode()

        result, _ = self.fetch_rows([row], http_get=http_get)
        self.assertEqual(len(result), 1)
        self.assertEqual(calls, [row["temporary_ovpn_url"]])

    def test_download_page_url_html_is_skipped_without_config_build(self):
        row = self.row("html-page", "PH", "198.51.100.51", temporary=False, page=True)
        calls = []

        def http_get(url, timeout=15, max_bytes=None, accept=None, **_kwargs):
            calls.append(url)
            return b"<html><body>PublicVPNList server page</body></html>"

        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_config") as config_builder, mock.patch.object(
            vpngate_manager, "log_to_json"
        ) as log_mock:
            result, _ = self.fetch_rows([row], http_get=http_get)
        self.assertEqual(result, [])
        self.assertEqual(calls, [])
        config_builder.assert_not_called()
        messages = " ".join(str(call.args[2]) for call in log_mock.call_args_list if len(call.args) >= 3)
        self.assertIn("download_page_url", messages)
        self.assertIn("重新生成", messages)

    def test_expired_temporary_snapshot_profile_is_skipped(self):
        row = self.row("expired-profile", "PH", "198.51.100.61")
        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [row]}), mock.patch.object(
            vpngate_manager,
            "fetch_publicvpnlist_config",
            side_effect=vpngate_manager.PublicVPNListSnapshotError("HTTP 410 temporary URL expired"),
        ) as config_builder, mock.patch.object(vpngate_manager, "log_to_json") as log_mock:
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        self.assertEqual(result, [])
        config_builder.assert_called_once_with(row["temporary_ovpn_url"])
        messages = " ".join(str(call.args[2]) for call in log_mock.call_args_list if len(call.args) >= 3)
        self.assertIn("temporary_ovpn_url", messages)
        self.assertIn("重新生成", messages)

    def test_temporary_token_is_not_in_node_or_cache(self):
        row = self.row("cache-token", "PH", "198.51.100.52")
        row["download_page_url"] += "?token=page-token"
        result, _ = self.fetch_rows([row])
        self.assertEqual(len(result), 1)
        self.assertNotIn("temporary_ovpn_url", result[0])
        cached_text = self.cache_file.read_text(encoding="utf-8")
        self.assertNotIn("temporary_ovpn_url", cached_text)
        self.assertNotIn("short-lived", cached_text)
        self.assertNotIn("page-token", cached_text)
        self.assertIn("-----BEGIN CERTIFICATE-----", cached_text)

    def test_valid_cache_skips_snapshot_and_config_download(self):
        row = self.row("cache-hit", "PH", "198.51.100.53")
        first, _ = self.fetch_rows([row], target=["PH"])
        self.assertEqual(len(first), 1)
        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", side_effect=AssertionError("cache miss")), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=AssertionError("config download on cache hit")
        ):
            second = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        self.assertEqual([node["id"] for node in second], [node["id"] for node in first])

    def test_url_expiry_after_refresh_interval_keeps_validated_profiles(self):
        row = self.row("cache-expired", "PH", "198.51.100.54")
        first, _ = self.fetch_rows([row], target=["PH"])
        self.assertEqual(len(first), 1)
        cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
        cache["last_refresh_attempt_at"] = time.time() - 7200
        self.cache_file.write_text(json.dumps(cache), encoding="utf-8")
        with mock.patch.object(
            vpngate_manager,
            "fetch_publicvpnlist_snapshot",
            side_effect=vpngate_manager.PublicVPNListSnapshotError("HTTP 403 signed snapshot expired"),
        ) as snapshot, mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=AssertionError("no profile re-download")
        ):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        snapshot.assert_called_once()
        self.assertEqual([node["ip"] for node in result], ["198.51.100.54"])
        state = json.loads(self.cache_file.read_text(encoding="utf-8"))
        self.assertTrue(state["cache_stale"])
        self.assertTrue(state["refresh_failed"])
        self.assertIn("profiles", state)
        self.assertEqual(state["last_refresh_success_at"], cache["last_refresh_success_at"])

    def test_target_change_reuses_source_wide_cache_without_profile_download(self):
        ph = self.row("cache-ph", "PH", "198.51.100.56")
        fr = self.row("cache-fr", "FR", "198.51.100.57")
        first, _ = self.fetch_rows([ph, fr], target=["PH"])
        self.assertEqual([node["country_short"] for node in first], ["PH"])
        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", side_effect=AssertionError("target cache miss")), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=AssertionError("config download on target change")
        ):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["FR"], set())
        self.assertEqual([node["country_short"] for node in result], ["FR"])

    def test_empty_refresh_does_not_overwrite_old_profiles(self):
        row = self.row("empty-refresh", "PH", "198.51.100.63")
        first, _ = self.fetch_rows([row], target=["PH"])
        self.assertEqual(len(first), 1)
        cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
        cache["last_refresh_attempt_at"] = time.time() - 7200
        previous_success_at = cache["last_refresh_success_at"]
        previous_snapshot_at = cache["snapshot_fetched_at"]
        self.cache_file.write_text(json.dumps(cache), encoding="utf-8")
        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": []}):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        self.assertEqual([node["ip"] for node in result], ["198.51.100.63"])
        state = json.loads(self.cache_file.read_text(encoding="utf-8"))
        self.assertEqual(len(state["profiles"]), 1)
        self.assertTrue(state["cache_stale"])
        self.assertTrue(state["refresh_failed"])
        self.assertEqual(state["last_refresh_success_at"], previous_success_at)
        self.assertGreater(state["snapshot_fetched_at"], previous_snapshot_at)

    def test_partial_refresh_keeps_old_profile_and_updates_success_timestamp(self):
        old_row = self.row("partial-old", "PH", "198.51.205.1")
        self.fetch_rows([old_row], target=["PH"])
        state_before = json.loads(self.cache_file.read_text(encoding="utf-8"))
        old_success_at = state_before["last_refresh_success_at"]
        state_before["last_refresh_attempt_at"] = time.time() - 7200
        self.cache_file.write_text(json.dumps(state_before), encoding="utf-8")
        new_row = self.row("partial-new", "FR", "198.51.205.2")
        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [old_row, new_row]}), mock.patch.object(
            vpngate_manager,
            "fetch_publicvpnlist_config",
            side_effect=[vpngate_manager.PublicVPNListSnapshotError("temporary URL expired")],
        ):
            result = vpngate_manager.fetch_publicvpnlist_candidates([], set())
        self.assertEqual([node["ip"] for node in result], [old_row["ip"]])
        state_after = json.loads(self.cache_file.read_text(encoding="utf-8"))
        self.assertEqual(len(state_after["profiles"]), 1)
        self.assertTrue(state_after["cache_stale"])
        self.assertTrue(state_after["refresh_failed"])
        self.assertTrue(state_after["partial"])
        self.assertGreaterEqual(state_after["last_refresh_success_at"], old_success_at)

    def test_stale_profile_is_removed_after_retention_period(self):
        row = self.row("stale-profile", "PH", "198.51.100.62")
        self.fetch_rows([row], target=["PH"])
        cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
        profile_key = next(iter(cache["profiles"]))
        cache["profiles"][profile_key]["last_seen_at"] = time.time() - 7200
        cache["last_refresh_attempt_at"] = time.time() - 7200
        self.cache_file.write_text(json.dumps(cache), encoding="utf-8")
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_STALE_PROFILE_SECONDS", 3600), mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_snapshot", side_effect=vpngate_manager.PublicVPNListSnapshotError("expired")
        ):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        self.assertEqual(result, [])
        state = json.loads(self.cache_file.read_text(encoding="utf-8"))
        self.assertEqual(state["profiles"], {})

    def test_invalid_openvpn_config_is_rejected(self):
        row = self.row("bad-config", "PH", "198.51.100.58")
        result, _ = self.fetch_rows([row], http_get=lambda *args, **kwargs: b"not an OpenVPN profile")
        self.assertEqual(result, [])

    def test_remote_host_port_and_protocol_mismatch_is_rejected(self):
        row = self.row("mismatch", "PH", "198.51.100.59", port=443, proto="tcp")
        bad_config = self.config("198.51.100.250", 1194, "udp")
        result, _ = self.fetch_rows([row], http_get=lambda *args, **kwargs: bad_config.encode())
        self.assertEqual(result, [])

    def test_dangerous_route_directive_is_sanitized_before_node_is_returned(self):
        row = self.row("unsafe-directive", "PH", "198.51.100.60")
        config = self.config(row["host"], row["port"], row["proto"]) + "redirect-gateway def1\n"
        result, _ = self.fetch_rows([row], http_get=lambda *args, **kwargs: config.encode())
        self.assertEqual(len(result), 1)
        self.assertNotIn("\nredirect-gateway def1\n", result[0]["config_text"])

    def test_endpoint_protocol_aliases_normalize_to_tcp_or_udp(self):
        self.assertEqual(vpngate_manager.normalize_endpoint_proto("tcp-client"), "tcp")
        self.assertEqual(vpngate_manager.normalize_endpoint_proto("tcp4-client"), "tcp")
        self.assertEqual(vpngate_manager.normalize_endpoint_proto("udp4"), "udp")
        self.assertEqual(vpngate_manager.normalize_endpoint_proto("udp6"), "udp")

    def test_endpoint_dedupe_prefers_vpngate_over_ipspeed_and_publicvpnlist(self):
        nodes = [
            self.candidate("publicvpnlist", "198.51.100.70", proto="udp4"),
            self.candidate("ipspeed", "198.51.100.70", proto="tcp-client"),
            self.candidate("vpngate", "198.51.100.70", proto="tcp"),
        ]
        result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual(len(result), 2)
        self.assertEqual({node["source"] for node in result}, {"vpngate", "publicvpnlist"})

    def test_vpnbook_and_vpngate_same_endpoint_are_both_kept(self):
        nodes = [
            self.candidate("vpnbook", "198.51.100.74"),
            self.candidate("vpngate", "198.51.100.74"),
        ]
        result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual([node["source"] for node in result], ["vpnbook", "vpngate"])

    def test_vpngate_scraper_and_ipspeed_same_endpoint_are_both_kept(self):
        nodes = [
            self.candidate("vpngate_scraper", "198.51.100.75"),
            self.candidate("ipspeed", "198.51.100.75"),
        ]
        result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual([node["source"] for node in result], ["vpngate_scraper", "ipspeed"])

    def test_publicvpnlist_same_endpoint_loses_to_vpngate(self):
        nodes = [
            self.candidate("publicvpnlist", "198.51.100.76"),
            self.candidate("vpngate", "198.51.100.76"),
        ]
        result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual([node["source"] for node in result], ["vpngate"])

    def test_publicvpnlist_same_endpoint_loses_to_ipspeed(self):
        nodes = [
            self.candidate("publicvpnlist", "198.51.100.77"),
            self.candidate("ipspeed", "198.51.100.77"),
        ]
        result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual([node["source"] for node in result], ["ipspeed"])

    def test_hostname_resolving_to_same_ip_is_deduplicated(self):
        nodes = [
            self.candidate("publicvpnlist", "198.51.100.71", host="198.51.100.71"),
            self.candidate("ipspeed", "", host="vpn.example", port=443, proto="tcp"),
        ]
        with mock.patch.object(vpngate_manager.socket, "gethostbyname", return_value="198.51.100.71"):
            result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["source"], "ipspeed")

    def test_different_port_or_protocol_remains_distinct(self):
        nodes = [
            self.candidate("vpngate", "198.51.100.72", port=443, proto="tcp"),
            self.candidate("ipspeed", "198.51.100.72", port=1194, proto="tcp"),
            self.candidate("publicvpnlist", "198.51.100.72", port=443, proto="udp"),
        ]
        result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual(len(result), 3)

    def test_dns_failure_keeps_hostname_endpoint(self):
        node = self.candidate("publicvpnlist", "", host="temporary.example", port=443, proto="tcp")
        with mock.patch.object(vpngate_manager.socket, "gethostbyname", side_effect=OSError("DNS unavailable")):
            keys = vpngate_manager.normalize_endpoint_keys(node)
            result = vpngate_manager.deduplicate_candidates([node])
        self.assertEqual(keys, {"temporary.example:443:tcp"})
        self.assertEqual(result, [node])

    def test_explicit_ipv4_nodes_do_not_trigger_hostname_dns(self):
        nodes = [
            self.candidate(
                "ipspeed",
                f"198.51.{index // 250}.{index % 250 + 1}",
                host=f"node-with-ip-{index}.example",
            )
            for index in range(300)
        ]
        with mock.patch.object(vpngate_manager.socket, "gethostbyname", side_effect=AssertionError("explicit IP must skip DNS")) as resolver:
            result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual(len(result), 300)
        self.assertEqual([node["id"] for node in result], [node["id"] for node in nodes])
        resolver.assert_not_called()

    def test_large_hostname_dedupe_resolves_each_hostname_once_and_is_stable(self):
        nodes = [
            self.candidate("ipspeed", "", host=f"node-{index}.example", port=443, proto="tcp")
            for index in range(300)
        ]

        def resolve(host):
            index = int(host.removeprefix("node-").removesuffix(".example"))
            return f"198.18.{index // 256}.{index % 256}"

        with mock.patch.object(vpngate_manager.socket, "gethostbyname", side_effect=resolve) as resolver:
            result = vpngate_manager.deduplicate_candidates(nodes)
        self.assertEqual(len(result), 300)
        self.assertEqual([node["id"] for node in result], [node["id"] for node in nodes])
        self.assertEqual(resolver.call_count, 300)
        self.assertEqual({call.args[0] for call in resolver.call_args_list}, {f"node-{i}.example" for i in range(300)})

    def test_us_nonresidential_rows_do_not_consume_final_quota(self):
        us_rows = [self.row(f"us-hosting-{i}", "US", f"198.19.{i // 256}.{(i % 256) + 1}") for i in range(100)]
        other_rows = [
            self.row("ph-after-us", "PH", "198.20.0.1"),
            self.row("fr-after-us", "FR", "198.20.0.2"),
            self.row("gb-after-us", "GB", "198.20.0.3"),
        ]

        def enrich(nodes):
            for node in nodes:
                node["ip_type"] = "hosting"
                node["risk_sources"] = ["ip-api.com"]

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_MAX_NODES", 3), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_MAX_SCAN_ROWS", 500
        ):
            result, _ = self.fetch_rows(us_rows + other_rows, target=[], enrich=enrich)
        self.assertEqual([node["country_short"] for node in result], ["PH", "FR", "GB"])

    def test_max_nodes_stops_later_us_enrichment_and_config_download(self):
        rows = [self.row(f"us-window-{i}", "US", f"198.23.{i // 250}.{(i % 250) + 1}") for i in range(500)]
        config_calls = []

        def enrich(nodes):
            for node in nodes:
                node.update(ip_type="residential", risk_sources=["ip-api.com"])

        def http_get(url, **_kwargs):
            config_calls.append(url)
            first = rows[0]
            return self.config(first["host"], first["port"], first["proto"]).encode()

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_MAX_NODES", 1):
            result, enrich_mock = self.fetch_rows(rows, target=["US"], enrich=enrich, http_get=http_get)
        self.assertEqual(len(result), 1)
        self.assertEqual(enrich_mock.call_count, 1)
        self.assertEqual([len(call.args[0]) for call in enrich_mock.call_args_list], [100])
        self.assertEqual(config_calls, [rows[0]["temporary_ovpn_url"]])

    def test_windowed_us_enrichment_continues_after_hosting_batch(self):
        hosting_rows = [self.row(f"us-hosting-window-{i}", "US", f"198.24.{i // 250}.{(i % 250) + 1}") for i in range(100)]
        residential = self.row("us-residential-window", "US", "198.24.1.1")
        config_calls = []

        def enrich(nodes):
            for node in nodes:
                node.update(
                    ip_type="residential" if node["ip"] == residential["ip"] else "hosting",
                    risk_sources=["ip-api.com"],
                )

        def http_get(url, **_kwargs):
            config_calls.append(url)
            return self.config(residential["host"], residential["port"], residential["proto"]).encode()

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_MAX_NODES", 1):
            result, enrich_mock = self.fetch_rows(
                hosting_rows + [residential], target=["US"], enrich=enrich, http_get=http_get
            )
        self.assertEqual([node["ip"] for node in result], [residential["ip"]])
        self.assertEqual(enrich_mock.call_count, 2)
        self.assertEqual([len(call.args[0]) for call in enrich_mock.call_args_list], [100, 1])
        self.assertEqual(config_calls, [residential["temporary_ovpn_url"]])

    def test_windowed_mixed_countries_preserve_snapshot_order(self):
        us = self.row("us-order", "US", "198.25.0.1")
        rows = [self.row("ph-order", "PH", "198.25.0.2"), us, self.row("fr-order", "FR", "198.25.0.3")]

        def enrich(nodes):
            nodes[0].update(ip_type="residential", risk_sources=["ip-api.com"])

        result, _ = self.fetch_rows(rows, enrich=enrich)
        self.assertEqual([node["country_short"] for node in result], ["PH", "US", "FR"])

    def test_250_us_nodes_use_batches_of_at_most_100(self):
        rows = [self.row(f"us-batch-{i}", "US", f"198.21.{i // 256}.{(i % 256) + 1}") for i in range(250)]

        def enrich(nodes):
            for node in nodes:
                node["ip_type"] = "residential"
                node["risk_sources"] = ["ip-api.com"]

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_MAX_NODES", 300):
            result, enrich_mock = self.fetch_rows(rows, target=["US"], enrich=enrich)
        self.assertEqual(len(result), 250)
        self.assertEqual(enrich_mock.call_count, 3)
        self.assertEqual([len(call.args[0]) for call in enrich_mock.call_args_list], [100, 100, 50])

    def test_us_batch_failure_rejects_the_entire_batch(self):
        rows = [self.row(f"us-fail-{i}", "US", f"198.22.{i // 256}.{(i % 256) + 1}") for i in range(100)]
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_MAX_NODES", 200):
            result, enrich_mock = self.fetch_rows(rows, target=["US"], enrich=mock.Mock(side_effect=OSError("risk API down")))
        self.assertEqual(result, [])
        self.assertEqual(enrich_mock.call_count, 1)

    def test_cached_ip_profile_does_not_trigger_risk_network_request(self):
        now = time.time()
        node = {"ip": "198.51.100.67", "remote_host": "198.51.100.67"}
        cached_profile = {
            "cached_at": now,
            "ip_type": "residential",
            "risk_sources": ["ip-api.com"],
            "owner": "fixture ISP",
            "asn": "AS64500",
            "as_name": "fixture",
            "location": "PH",
            "quality": "clean_residential",
            "fraud_score": 0,
            "clean_score": 100,
            "risk_level": "clean",
            "fraud_flags": [],
            "blacklist_hits": [],
            "blacklist_count": 0,
            "ip_clean": True,
        }
        with mock.patch.object(vpngate_manager.vpn_utils, "load_ip_cache", return_value={node["ip"]: cached_profile}), mock.patch.object(
            vpngate_manager.vpn_utils.urllib.request, "urlopen", side_effect=AssertionError("cached IP must not query network")
        ) as urlopen:
            vpngate_manager.vpn_utils.enrich_ip_info([node])
        self.assertEqual(node["ip_type"], "residential")
        urlopen.assert_not_called()

    def test_publicvpnlist_speed_is_stored_in_bps(self):
        self.assertEqual(vpngate_manager.publicvpnlist_speed_bps(12.5), 12_500_000)
        self.assertEqual(vpngate_manager.publicvpnlist_speed_bps(0), 0)
        self.assertEqual(vpngate_manager.publicvpnlist_speed_bps("not-a-number"), 0)
        self.assertEqual(vpngate_manager.publicvpnlist_speed_bps("nan"), 0)
        row = self.row("speed-bps", "PH", "198.51.100.68")
        result, _ = self.fetch_rows([row])
        self.assertEqual(result[0]["speed"], 12_500_000)
        self.assertEqual(result[0]["score"], 12_500_000)

    def test_source_failure_does_not_stop_other_sources(self):
        healthy = self.candidate("vpngate", "198.51.100.73")
        with mock.patch.object(vpngate_manager, "get_node_sources", return_value=["publicvpnlist", "vpngate"]), mock.patch.object(
            vpngate_manager, "load_blacklist", return_value={}
        ), mock.patch.object(vpngate_manager, "fetch_publicvpnlist_candidates", side_effect=RuntimeError("fixture 429")), mock.patch.object(
            vpngate_manager, "fetch_vpngate_candidates", return_value=[healthy]
        ), mock.patch.object(vpngate_manager, "set_state"):
            result = vpngate_manager.fetch_candidates()
        self.assertEqual(result, [healthy])

    def test_snapshot_http_403_and_429_are_fail_closed(self):
        for status in (403, 429):
            with self.subTest(status=status), mock.patch.object(
                vpngate_manager,
                "publicvpnlist_http_get",
                side_effect=urllib.error.HTTPError(
                    vpngate_manager.PUBLICVPNLIST_SNAPSHOT_URL,
                    status,
                    "fixture",
                    {},
                    None,
                ),
            ), mock.patch.object(vpngate_manager.time, "sleep"):
                with self.assertRaises(vpngate_manager.PublicVPNListSnapshotError):
                    vpngate_manager.fetch_publicvpnlist_snapshot()

    def test_html_challenge_is_rejected_by_bounded_http_reader(self):
        class Response:
            headers = {}

            def __init__(self):
                self.done = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                if self.done:
                    return b""
                self.done = True
                return b"<html>challenge</html>"

        with mock.patch.object(vpngate_manager.urllib.request, "urlopen", return_value=Response()):
            with self.assertRaises(vpngate_manager.PublicVPNListSnapshotError):
                vpngate_manager.publicvpnlist_http_get(vpngate_manager.PUBLICVPNLIST_SNAPSHOT_URL)

    def test_doctype_html_is_rejected_by_bounded_http_reader(self):
        class Response:
            headers = {}

            def __init__(self):
                self.done = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                if self.done:
                    return b""
                self.done = True
                return b"<!doctype html><html><body>challenge</body></html>"

        with mock.patch.object(vpngate_manager.urllib.request, "urlopen", return_value=Response()):
            with self.assertRaises(vpngate_manager.PublicVPNListSnapshotError):
                vpngate_manager.publicvpnlist_http_get(vpngate_manager.PUBLICVPNLIST_SNAPSHOT_URL)

    def test_openvpn_config_starting_with_ca_is_not_mistaken_for_html(self):
        config = self.config("198.51.100.69", 443, "tcp")
        config = "<ca>\n-----BEGIN CERTIFICATE-----\nFIXTURE\n-----END CERTIFICATE-----\n</ca>\n" + config

        class Response:
            headers = {}

            def __init__(self):
                self.done = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                if self.done:
                    return b""
                self.done = True
                return config.encode()

        with mock.patch.object(vpngate_manager.urllib.request, "urlopen", return_value=Response()):
            body = vpngate_manager.publicvpnlist_http_get(
                "https://fixture.invalid/profile.ovpn",
                accept="application/x-openvpn-profile,text/plain",
            ).decode()
        self.assertTrue(body.startswith("<ca>"))
        self.assertTrue(vpngate_manager.looks_like_openvpn_config(body))

    def test_snapshot_and_config_use_distinct_accept_headers_and_config_timeout(self):
        snapshot_response = self._response(b'{"data": []}')
        config_response = self._response(self.config("198.51.100.70", 443, "tcp").encode())
        opened_config = []

        class ConfigOpener:
            def open(self, request, timeout):
                opened_config.append((request, timeout))
                return config_response

        with mock.patch.object(vpngate_manager.urllib.request, "urlopen", return_value=snapshot_response) as urlopen, mock.patch.object(
            vpngate_manager.urllib.request, "build_opener", return_value=ConfigOpener()
        ):
            self.assertEqual(vpngate_manager.fetch_publicvpnlist_snapshot(), {"data": []})
            self.assertTrue(vpngate_manager.fetch_publicvpnlist_config("https://fixture.invalid/profile.ovpn"))
        snapshot_request = urlopen.call_args.args[0]
        config_request, config_timeout = opened_config[0]
        self.assertEqual(snapshot_request.get_header("Accept"), "application/json")
        self.assertEqual(config_request.get_header("Accept"), "application/x-openvpn-profile,text/plain")
        self.assertEqual(config_timeout, 45)

    def test_temporary_profile_url_rejects_unsafe_schemes_and_private_hosts_before_open(self):
        urls = [
            "file:///etc/passwd",
            "ftp://fixture.invalid/profile.ovpn",
            "data:text/plain,profile",
            "http://fixture.invalid/profile.ovpn",
            "https://localhost/profile.ovpn",
            "https://user:pass@fixture.invalid/profile.ovpn",
        ]
        with mock.patch.object(vpngate_manager, "publicvpnlist_http_get") as http_get:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(vpngate_manager.PublicVPNListSnapshotError):
                    vpngate_manager.fetch_publicvpnlist_config(url)
        http_get.assert_not_called()

        for host in ("127.0.0.1", "169.254.169.254"):
            with self.subTest(host=host), mock.patch.object(
                vpngate_manager, "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS", frozenset({host})
            ), mock.patch.object(vpngate_manager, "publicvpnlist_http_get") as http_get:
                with self.assertRaises(vpngate_manager.PublicVPNListSnapshotError):
                    vpngate_manager.fetch_publicvpnlist_config(f"https://{host}/profile.ovpn")
                http_get.assert_not_called()

    def test_allowlisted_https_profile_download_uses_profile_accept_and_safe_metadata(self):
        config = self.config("198.51.206.1", 443, "tcp")
        metadata = {}
        with mock.patch.object(vpngate_manager, "publicvpnlist_http_get", return_value=config.encode()) as http_get:
            result = vpngate_manager.fetch_publicvpnlist_config("https://fixture.invalid/profile.ovpn", metadata=metadata)
        self.assertEqual(result, config)
        self.assertEqual(metadata["final_download_host"], "fixture.invalid")
        self.assertEqual(metadata["redirect_count"], 0)
        self.assertEqual(http_get.call_args.kwargs["accept"], "application/x-openvpn-profile,text/plain")
        self.assertIsNotNone(http_get.call_args.kwargs["opener"])

    def test_profile_redirect_to_private_host_is_rejected(self):
        handler = vpngate_manager.PublicVPNListRedirectHandler(max_redirects=5)
        request = urllib.request.Request("https://fixture.invalid/profile.ovpn")
        with mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS", frozenset({"fixture.invalid", "127.0.0.1"})
        ), self.assertRaises(vpngate_manager.PublicVPNListSnapshotError):
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "https://127.0.0.1/profile.ovpn",
            )
        self.assertEqual(handler.redirect_count, 0)

    def test_publicvpnlist_user_agent_is_dedicated(self):
        class Response:
            headers = {}

            def __init__(self):
                self.done = False

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                if self.done:
                    return b""
                self.done = True
                return b"{}"

        with mock.patch.object(vpngate_manager.urllib.request, "urlopen", return_value=Response()) as urlopen:
            vpngate_manager.publicvpnlist_http_get(vpngate_manager.PUBLICVPNLIST_SNAPSHOT_URL)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_header("User-agent"), "gatevpn-publicvpnlist/1.0")

    def test_payload_records_accepts_data_array(self):
        rows = [{"id": "one"}]
        self.assertEqual(vpngate_manager.publicvpnlist_payload_records({"data": rows}), rows)

    def test_max_nodes_limits_source_output(self):
        rows = [self.row(f"limited-{i}", "PH", f"198.51.101.{i}") for i in range(1, 5)]
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_MAX_NODES", 2):
            result, _ = self.fetch_rows(rows)
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
