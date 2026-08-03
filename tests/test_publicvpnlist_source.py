import json
import tempfile
import time
import unittest
import urllib.error
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
        self.patches = mock.patch.multiple(
            vpngate_manager,
            DATA_DIR=data_dir,
            CONFIG_DIR=data_dir / "configs",
            PUBLICVPNLIST_CACHE_FILE=self.cache_file,
            PUBLICVPNLIST_SNAPSHOT_URL="https://fixture.invalid/export-builder-snapshot.json?signature=fixture",
            PUBLICVPNLIST_SNAPSHOT_FILE="",
            PUBLICVPNLIST_REFRESH_SECONDS=3600,
            PUBLICVPNLIST_MAX_NODES=100,
            PUBLICVPNLIST_MAX_SCAN_ROWS=500,
            PUBLICVPNLIST_MAX_RESPONSE_BYTES=1024 * 1024,
            PUBLICVPNLIST_MAX_RETRIES=1,
        )
        self.patches.start()
        self.addCleanup(self.patches.stop)

    @staticmethod
    def config(host, port, proto="tcp"):
        return OPENVPN_CONFIG.format(host=host, port=port, proto=proto)

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
            "speed": 1000000,
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

        def fixture_http_get(url, timeout=15, max_bytes=None):
            if http_get is not None:
                return http_get(url, timeout=timeout, max_bytes=max_bytes)
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

    def test_local_snapshot_file_is_supported(self):
        snapshot_file = Path(self.temp_dir.name) / "export-builder.json"
        snapshot_file.write_text(json.dumps({"data": []}), encoding="utf-8")
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", ""), mock.patch.object(
            vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", str(snapshot_file)
        ), mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=AssertionError("network request")):
            self.assertEqual(vpngate_manager.fetch_publicvpnlist_snapshot(), {"data": []})

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
        self.assertEqual(enrich_mock.call_count, len(rows))

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

    def test_temporary_url_is_used_before_download_page_url(self):
        row = self.row("temporary-first", "PH", "198.51.100.50", page=True)
        calls = []

        def http_get(url, timeout=15, max_bytes=None):
            calls.append(url)
            return self.config(row["host"], row["port"], row["proto"]).encode()

        result, _ = self.fetch_rows([row], http_get=http_get)
        self.assertEqual(len(result), 1)
        self.assertEqual(calls, [row["temporary_ovpn_url"]])

    def test_download_page_url_html_is_skipped_without_config_build(self):
        row = self.row("html-page", "PH", "198.51.100.51", temporary=False, page=True)
        calls = []

        def http_get(url, timeout=15, max_bytes=None):
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

    def test_expired_cache_refreshes_snapshot(self):
        row = self.row("cache-expired", "PH", "198.51.100.54")
        self.fetch_rows([row], target=["PH"])
        cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
        cache["cached_at"] = time.time() - 7200
        self.cache_file.write_text(json.dumps(cache), encoding="utf-8")
        refreshed = self.row("cache-refreshed", "PH", "198.51.100.55")
        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [refreshed]}) as snapshot, mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            return_value=self.config(refreshed["host"], refreshed["port"], refreshed["proto"]).encode(),
        ):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        snapshot.assert_called_once()
        self.assertEqual([node["ip"] for node in result], ["198.51.100.55"])

    def test_target_change_does_not_reuse_previous_target_cache(self):
        ph = self.row("cache-ph", "PH", "198.51.100.56")
        self.fetch_rows([ph], target=["PH"])
        fr = self.row("cache-fr", "FR", "198.51.100.57")
        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [fr]}) as snapshot, mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            return_value=self.config(fr["host"], fr["port"], fr["proto"]).encode(),
        ):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["FR"], set())
        snapshot.assert_called_once()
        self.assertEqual([node["country_short"] for node in result], ["FR"])

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
