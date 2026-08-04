import io
import json
import tempfile
import unittest
import urllib.error
from email.message import Message
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import vpngate_manager


class PublicVPNListAPIV1Tests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        root = Path(self.temp_dir.name)
        self.api_cache_file = root / "publicvpnlist_api_cache.json"
        self.profile_cache_file = root / "publicvpnlist_cache.json"
        self.patches = mock.patch.multiple(
            vpngate_manager,
            DATA_DIR=root,
            CONFIG_DIR=root / "configs",
            PUBLICVPNLIST_API_CACHE_FILE=self.api_cache_file,
            PUBLICVPNLIST_CACHE_FILE=self.profile_cache_file,
            PUBLICVPNLIST_ENABLED=True,
            PUBLICVPNLIST_API_BASE_URL="https://api.fixture.invalid/api/v1",
            PUBLICVPNLIST_API_URL="https://api.fixture.invalid/api/v1/servers",
            PUBLICVPNLIST_SNAPSHOT_URL="",
            PUBLICVPNLIST_SNAPSHOT_FILE="",
            PUBLICVPNLIST_API_PER_PAGE=200,
            PUBLICVPNLIST_API_MAX_PAGES=5,
            PUBLICVPNLIST_API_MAX_RECORDS=20,
            PUBLICVPNLIST_API_MAX_RETRIES=2,
            PUBLICVPNLIST_API_MAX_REQUESTS_PER_REFRESH=20,
            PUBLICVPNLIST_API_REFRESH_SECONDS=900,
            PUBLICVPNLIST_API_MAX_STALE_SECONDS=21600,
            PUBLICVPNLIST_API_MAX_RESPONSE_BYTES=1024 * 1024,
            PUBLICVPNLIST_MAX_RETRIES=1,
            PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS=frozenset({"api.fixture.invalid"}),
        )
        self.patches.start()
        self.addCleanup(self.patches.stop)

    @staticmethod
    def record(node_id="ph-1", country="PH", page=1, with_config=True):
        row = {
            "id": node_id,
            "country_code": country,
            "country_name": "Fixture country",
            "hostname": f"{node_id}.fixture.invalid",
            "ip": "198.51.100.10",
            "protocol": "openvpn",
            "transport": "tcp",
            "port": 443,
            "speed_mbps": 12.5,
            "latency_ms": 42,
            "technical_quality_score": 91,
            "last_checked_at": "2026-08-04T00:00:00Z",
            "freshness_status": "fresh",
            "availability_status": "online",
            "source_name": "PublicVPNList",
            "redistribution_allowed": False,
            "server_page_url": f"https://api.fixture.invalid/servers/{node_id}",
            "risk_flags": [],
            "config_sha256": "a" * 64,
            "unknown_future_field": {"ignored": True},
            "page": page,
        }
        if with_config:
            row["config_download_url"] = (
                f"https://download.fixture.invalid/{node_id}.ovpn?signature=short-lived"
            )
        return row

    def api_response(self, records, *, page=1, total_pages=1):
        payload = {
            "data": records,
            "meta": {
                "current_page": page,
                "total_pages": total_pages,
                "dataset_version": "fixture-v1",
                "generated_at": "2026-08-04T00:00:00Z",
            },
            "links": {},
        }
        return json.dumps(payload).encode("utf-8")

    def test_default_api_source_is_enabled_without_manual_snapshot(self):
        with mock.patch.object(
            vpngate_manager, "load_ui_config", return_value={"node_sources": "vpngate,vpnbook,ipspeed,vpngate_scraper"}
        ):
            self.assertEqual(vpngate_manager.publicvpnlist_source(), ("api", "https://api.fixture.invalid/api/v1/servers"))
            self.assertIn("publicvpnlist", vpngate_manager.get_node_sources())

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_ENABLED", False):
            self.assertEqual(vpngate_manager.publicvpnlist_source(), ("", ""))
            self.assertNotIn("publicvpnlist", vpngate_manager.get_node_sources())

    def test_api_fetches_each_country_with_bounded_query_and_maps_known_fields(self):
        calls = []

        def http_get(url, metadata=None, extra_headers=None, **_kwargs):
            calls.append((url, dict(extra_headers or {})))
            query = parse_qs(urlsplit(url).query)
            self.assertEqual(query["protocol"], ["openvpn"])
            self.assertEqual(query["status"], ["online"])
            self.assertEqual(query["per_page"], ["200"])
            self.assertEqual(query["sort"], ["last_checked"])
            self.assertEqual(query["order"], ["desc"])
            self.assertEqual(query["page"], ["1"])
            self.assertIn(query["country"][0], {"PH", "FR"})
            metadata.update({"status": 200, "content_type": "application/json", "etag": '"fixture"'})
            return self.api_response([self.record(country=query["country"][0])])

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "FR"])

        self.assertEqual(payload["_api_meta"]["records_fetched"], 2)
        self.assertEqual({row["country_code"] for row in payload["data"]}, {"PH", "FR"})
        self.assertEqual(len(calls), 2)
        saved = json.loads(self.api_cache_file.read_text(encoding="utf-8"))
        encoded = json.dumps(saved, ensure_ascii=False)
        self.assertNotIn("config_download_url", encoded)
        self.assertNotIn("signature=short-lived", encoded)
        self.assertNotIn("unknown_future_field", encoded)

    def test_api_pagination_is_bounded_and_follows_same_origin_link(self):
        calls = []

        def http_get(url, metadata=None, **_kwargs):
            calls.append(url)
            page = int(parse_qs(urlsplit(url).query)["page"][0])
            metadata.update({"status": 200, "content_type": "application/json"})
            return self.api_response([self.record(f"ph-{page}", page=page)], page=page, total_pages=2)

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual(len(calls), 2)
        self.assertEqual([row["id"] for row in payload["data"]], ["ph-1", "ph-2"])

    def test_profile_refresh_keeps_api_metadata_cache_independent_of_target_country(self):
        with mock.patch.object(
            vpngate_manager,
            "fetch_publicvpnlist_snapshot",
            return_value={"data": []},
        ) as snapshot:
            vpngate_manager.refresh_publicvpnlist_cache(
                target_countries=["PH"],
            )
        snapshot.assert_called_once()
        self.assertIsNone(snapshot.call_args.kwargs["target_countries"])

    def test_api_304_reuses_metadata_and_sends_conditional_headers(self):
        cached = vpngate_manager.publicvpnlist_api_cache_default()
        cached.update(
            {
                "last_success_at": 1_000.0,
                "next_update_at": 0.0,
                "etag_by_query": {
                    "country=PH&protocol=openvpn&status=online&sort=last_checked&order=desc&page=1&per_page=200": '"old"'
                },
                "records_by_country": {"PH": [self.record(with_config=False)]},
            }
        )
        vpngate_manager.save_publicvpnlist_api_cache(cached)
        headers = Message()
        headers["ETag"] = '"old"'

        def http_get(_url, metadata=None, extra_headers=None, **_kwargs):
            self.assertEqual(extra_headers.get("If-None-Match"), '"old"')
            raise urllib.error.HTTPError(
                _url, 304, "not modified", headers, io.BytesIO()
            )

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual(payload["_api_meta"]["status"], 304)
        self.assertEqual(payload["data"][0]["id"], "ph-1")

    def test_rate_limit_sets_bounded_backoff_without_sleeping(self):
        headers = Message()
        headers["Retry-After"] = "3600"

        def http_get(url, **_kwargs):
            raise urllib.error.HTTPError(url, 429, "rate limited", headers, io.BytesIO())

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ), mock.patch.object(vpngate_manager.time, "sleep") as sleep:
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertTrue(payload["_api_meta"]["rate_limited"])
        self.assertLessEqual(
            payload["_api_meta"]["backoff_until"],
            vpngate_manager.time.time() + vpngate_manager.PUBLICVPNLIST_API_MAX_RETRY_AFTER_SECONDS,
        )
        sleep.assert_not_called()

    def test_metadata_only_record_is_not_treated_as_connectable(self):
        row = self.record(with_config=False)
        with mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [row]}
        ), mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_config", side_effect=AssertionError("metadata-only must not download")
        ), mock.patch.object(vpngate_manager, "log_to_json"):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        self.assertEqual(result, [])

    def test_source_url_is_direct_only_when_redistribution_is_allowed(self):
        row = self.record(with_config=False)
        row["source_url"] = "https://download.fixture.invalid/profile.ovpn"
        row["redistribution_allowed"] = True
        normalized = vpngate_manager.normalize_publicvpnlist_row(row)
        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["temporary_ovpn_url"], row["source_url"])

        row["source_url"] = "https://api.fixture.invalid/servers/ph-1?download=1"
        self.assertEqual(vpngate_manager.normalize_publicvpnlist_row(row)["temporary_ovpn_url"], "")

    def test_api_measurements_keep_raw_values_and_use_checker_priority(self):
        row = self.record(with_config=False)
        row.update(
            {
                "speed_mbps": 12.5,
                "latency_ms": 42,
                "checker_measured_throughput_mbps": 80.0,
                "checker_measured_tunnel_rtt_ms": 19,
            }
        )
        normalized = vpngate_manager.normalize_publicvpnlist_row(row)
        self.assertEqual(normalized["speed_mbps"], 80.0)
        self.assertEqual(normalized["source_reported_speed_mbps"], 12.5)
        self.assertEqual(normalized["latency_ms"], 19)
        self.assertEqual(normalized["source_reported_ping_ms"], 42)
        node = vpngate_manager.publicvpnlist_row_to_node(
            normalized,
            "client\ndev tun\nproto tcp\nremote ph-1.fixture.invalid 443\n<ca>\nCERT\n</ca>\n",
        )
        self.assertEqual(node["speed"], 80_000_000)

    def test_existing_node_is_enriched_without_replacing_its_source(self):
        node = {
            "source": "vpngate",
            "ip": "198.51.100.10",
            "remote_host": "ph-1.fixture.invalid",
            "remote_port": 443,
            "proto": "tcp",
            "config_text": "existing",
        }
        row = vpngate_manager.normalize_publicvpnlist_row(self.record(with_config=False))
        self.assertIsNotNone(row)
        vpngate_manager.publicvpnlist_enrich_existing_node(node, row)
        self.assertEqual(node["source"], "vpngate")
        self.assertIn("publicvpnlist", node["verification_sources"])
        self.assertEqual(node["pvl_public_id"], "ph-1")


if __name__ == "__main__":
    unittest.main()
