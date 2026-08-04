import io
import json
import tempfile
import time
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
        ip_octet = 10 + (sum(ord(char) for char in str(node_id)) % 200)
        row = {
            "id": node_id,
            "country_code": country,
            "country_name": "Fixture country",
            "hostname": f"{node_id}.fixture.invalid",
            "ip": f"198.51.100.{ip_octet}",
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
            country = query["country"][0]
            return self.api_response([self.record(node_id=f"{country.lower()}-1", country=country)])

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

    def _seed_page_cache(self, pages, *, country="PH"):
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        records_by_query = {}
        page_meta_by_query = {}
        etag_by_query = {}
        for page, records in pages.items():
            query_key = vpngate_manager._publicvpnlist_api_query_key(country, page)
            records_by_query[query_key] = records
            page_meta_by_query[query_key] = {
                "country": country,
                "page": page,
                "next_page": page + 1 if page < max(pages) else 0,
                "has_next": page < max(pages),
                "record_count": len(records),
                "etag": f'"page-{page}"',
                "last_modified": "",
            }
            etag_by_query[query_key] = f'"page-{page}"'
        cache.update(
            {
                "last_success_at": time.time(),
                "next_update_at": 0.0,
                "records_by_query": records_by_query,
                "page_meta_by_query": page_meta_by_query,
                "etag_by_query": etag_by_query,
            }
        )
        vpngate_manager.save_publicvpnlist_api_cache(cache)

    @staticmethod
    def _not_modified(url, etag):
        headers = Message()
        headers["ETag"] = etag
        return urllib.error.HTTPError(url, 304, "not modified", headers, io.BytesIO())

    def test_api_page_1_and_page_2_both_304_reuse_each_page(self):
        page_one = self.record("cached-p1", page=1, with_config=False)
        page_two = self.record("cached-p2", page=2, with_config=False)
        self._seed_page_cache({1: [page_one], 2: [page_two]})
        calls = []

        def http_get(url, metadata=None, extra_headers=None, **_kwargs):
            calls.append((int(parse_qs(urlsplit(url).query)["page"][0]), dict(extra_headers or {})))
            raise self._not_modified(url, f'"page-{calls[-1][0]}"')

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual([row["id"] for row in payload["data"]], ["cached-p1", "cached-p2"])
        self.assertEqual([page for page, _headers in calls], [1, 2])
        self.assertEqual(payload["_api_meta"]["etag_cache_hits"], 2)

    def test_api_page_1_200_page_2_304_keeps_new_page_1(self):
        old_page_two = self.record("old-p2", page=2, with_config=False)
        self._seed_page_cache({2: [old_page_two]})
        new_page_one = self.record("new-p1", page=1, with_config=False)
        calls = []

        def http_get(url, metadata=None, extra_headers=None, **_kwargs):
            page = int(parse_qs(urlsplit(url).query)["page"][0])
            calls.append((page, dict(extra_headers or {})))
            if page == 1:
                metadata.update({"status": 200, "content_type": "application/json", "etag": '"new-p1"'})
                return self.api_response([new_page_one], page=1, total_pages=2)
            raise self._not_modified(url, '"page-2"')

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual([row["id"] for row in payload["data"]], ["new-p1", "old-p2"])
        self.assertEqual([page for page, _headers in calls], [1, 2])

    def test_api_page_1_304_page_2_200_keeps_new_page_2(self):
        old_page_one = self.record("old-p1", page=1, with_config=False)
        self._seed_page_cache({1: [old_page_one]})
        page_one_key = vpngate_manager._publicvpnlist_api_query_key("PH", 1)
        cache = vpngate_manager.load_publicvpnlist_api_cache()
        cache["page_meta_by_query"][page_one_key].update({"next_page": 2, "has_next": True})
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        new_page_two = self.record("new-p2", page=2, with_config=False)
        calls = []

        def http_get(url, metadata=None, extra_headers=None, **_kwargs):
            page = int(parse_qs(urlsplit(url).query)["page"][0])
            calls.append((page, dict(extra_headers or {})))
            if page == 1:
                raise self._not_modified(url, '"page-1"')
            metadata.update({"status": 200, "content_type": "application/json", "etag": '"new-p2"'})
            return self.api_response([new_page_two], page=2, total_pages=2)

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual([row["id"] for row in payload["data"]], ["old-p1", "new-p2"])
        self.assertEqual([page for page, _headers in calls], [1, 2])

    def test_api_page_failure_reuses_only_that_page_cache(self):
        old_page_two = self.record("old-p2", page=2, with_config=False)
        self._seed_page_cache({2: [old_page_two]})
        new_page_one = self.record("new-p1", page=1, with_config=False)
        calls = []

        def http_get(url, metadata=None, **_kwargs):
            page = int(parse_qs(urlsplit(url).query)["page"][0])
            calls.append(page)
            if page == 1:
                metadata.update({"status": 200, "content_type": "application/json"})
                return self.api_response([new_page_one], page=1, total_pages=2)
            raise urllib.error.URLError("page two unavailable")

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ), mock.patch.object(vpngate_manager.time, "sleep"):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual([row["id"] for row in payload["data"]], ["new-p1", "old-p2"])
        self.assertEqual(calls, [1, 2, 2])

    def test_partial_429_preserves_data_and_backoff(self):
        calls = []
        headers = Message()
        headers["Retry-After"] = "120"

        def http_get(url, metadata=None, **_kwargs):
            country = parse_qs(urlsplit(url).query)["country"][0]
            calls.append(country)
            if country == "PH":
                metadata.update({"status": 200, "content_type": "application/json"})
                return self.api_response([self.record("ph-success", country="PH")])
            raise urllib.error.HTTPError(url, 429, "rate limited", headers, io.BytesIO())

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "US"])

        api_cache = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertEqual([row["id"] for row in payload["data"]], ["ph-success"])
        self.assertEqual(calls, ["PH", "US"])
        self.assertTrue(payload["_api_meta"]["rate_limited"])
        self.assertGreater(payload["_api_meta"]["backoff_until"], time.time())
        self.assertTrue(api_cache["rate_limited"])
        self.assertGreater(api_cache["backoff_until"], time.time())

        with mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=AssertionError("backoff must suppress requests")):
            cached = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "US"])
        self.assertEqual([row["id"] for row in cached["data"]], ["ph-success"])

        api_cache["next_update_at"] = 0.0
        api_cache["backoff_until"] = time.time() - 1
        api_cache["rate_limited"] = True
        vpngate_manager.save_publicvpnlist_api_cache(api_cache)
        def recovered_http_get(_url, metadata=None, **_kwargs):
            metadata.update({"status": 200, "content_type": "application/json"})
            return self.api_response([self.record("ph-recovered")])

        with mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=recovered_http_get):
            recovered = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        refreshed_cache = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertEqual(recovered["_api_meta"]["rate_limited"], False)
        self.assertEqual(refreshed_cache["rate_limited"], False)
        self.assertEqual(refreshed_cache["backoff_until"], 0.0)

    def test_failed_profile_download_retries_after_304_without_persisting_url(self):
        row = self.record("retry-profile", with_config=True)
        row["config_sha256"] = ""
        calls = []

        def first_http_get(url, metadata=None, **_kwargs):
            metadata.update({"status": 200, "content_type": "application/json", "etag": '"retry-v1"'})
            return self.api_response([row])

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=first_http_get
        ):
            vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        api_cache = vpngate_manager.load_publicvpnlist_api_cache()
        api_cache["next_update_at"] = 0.0
        vpngate_manager.save_publicvpnlist_api_cache(api_cache)

        with mock.patch.object(vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [row]}), mock.patch.object(
            vpngate_manager,
            "fetch_publicvpnlist_config",
            side_effect=vpngate_manager.PublicVPNListSnapshotError("temporary profile failure"),
        ), mock.patch.object(vpngate_manager, "log_to_json"):
            vpngate_manager.refresh_publicvpnlist_cache(
                cache=vpngate_manager.publicvpnlist_cache_default(vpngate_manager.publicvpnlist_source_hash()),
            )

        failed_cache = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertIn("retry-profile", failed_cache["profile_retry_public_ids"])
        failed_text = self.api_cache_file.read_text(encoding="utf-8")
        self.assertNotIn("config_download_url", failed_text)
        self.assertNotIn("short-lived", failed_text)

        failed_cache["next_update_at"] = 0.0
        for entry in failed_cache["profile_retry_entries"]:
            entry["retry_after"] = time.time() - 1
        vpngate_manager.save_publicvpnlist_api_cache(failed_cache)
        refreshed_row = dict(row)

        def retry_http_get(url, metadata=None, extra_headers=None, **_kwargs):
            calls.append(dict(extra_headers or {}))
            if len(calls) == 1:
                raise self._not_modified(url, '"retry-v1"')
            metadata.update({"status": 200, "content_type": "application/json", "etag": '"retry-v2"'})
            return self.api_response([refreshed_row])

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=retry_http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls, [{}, {}])
        self.assertIn("config_download_url", payload["data"][0])

        config = "client\nproto tcp\nremote retry-profile.fixture.invalid 443\n<ca>\nCERT\n</ca>\n"
        with mock.patch.object(vpngate_manager, "publicvpnlist_refresh_needed", return_value=True), mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_snapshot", return_value=payload
        ), mock.patch.object(vpngate_manager, "fetch_publicvpnlist_config", return_value=config), mock.patch.object(
            vpngate_manager, "log_to_json"
        ) as log_mock:
            refreshed_cache = vpngate_manager.refresh_publicvpnlist_cache(
                cache=vpngate_manager.publicvpnlist_cache_default(vpngate_manager.publicvpnlist_source_hash()),
            )

        self.assertEqual(len(refreshed_cache["profiles"]), 1)
        self.assertEqual(vpngate_manager.load_publicvpnlist_api_cache()["profile_retry_entries"], [])
        output = self.api_cache_file.read_text(encoding="utf-8") + self.profile_cache_file.read_text(encoding="utf-8")
        output += json.dumps(refreshed_cache, ensure_ascii=False)
        output += " ".join(str(call.args[2]) for call in log_mock.call_args_list if len(call.args) >= 3)
        self.assertNotIn("short-lived", output)
        self.assertNotIn("signature", output)

    def test_status_preserves_zero_candidates_and_counts_actual_304_only(self):
        cache = vpngate_manager.publicvpnlist_cache_default("fixture")
        cache["last_refresh_stats"] = {
            "last_refresh_connectable_candidates": 0,
            "usable_cached_profiles": 5,
            "current_returned_candidates": 0,
            "matched_existing_nodes": 0,
            "etag_cache_hits": 0,
        }
        api_cache = vpngate_manager.publicvpnlist_api_cache_default()
        api_cache["metadata_record_count"] = 0
        api_cache["etag_by_query"] = {f"query-{index}": f'"{index}"' for index in range(10)}
        api_cache["last_etag_cache_hits"] = 0
        with mock.patch.object(vpngate_manager, "load_publicvpnlist_cache", return_value=cache), mock.patch.object(
            vpngate_manager, "load_publicvpnlist_api_cache", return_value=api_cache
        ), mock.patch.object(vpngate_manager, "publicvpnlist_shared_cache_profile_summary", return_value=(5, 5)):
            status = vpngate_manager.publicvpnlist_web_status()
        self.assertEqual(status["connectable_candidates"], 0)
        self.assertEqual(status["usable_cached_profiles"], 5)
        self.assertEqual(status["current_returned_candidates"], 0)
        self.assertEqual(status["matched_existing_nodes"], 0)
        self.assertEqual(status["etag_cache_hits"], 0)

    def test_endpoint_match_is_not_verified_without_fresh_successful_measurement(self):
        row = self.record("verified-profile", with_config=False)
        row.update(
            {
                "checked_at": time.time(),
                "measurement_quality": "verified",
                "measurement_status": "success",
            }
        )
        normalized = vpngate_manager.normalize_publicvpnlist_row(row)
        self.assertTrue(vpngate_manager.publicvpnlist_metadata_is_verified(normalized))
        verified_node = vpngate_manager.publicvpnlist_row_to_node(
            normalized,
            "client\nproto tcp\nremote verified-profile.fixture.invalid 443\n<ca>\nCERT\n</ca>\n",
        )
        self.assertTrue(verified_node["pvl_endpoint_matched"])
        self.assertTrue(verified_node["pvl_verified"])

        stale = dict(normalized)
        stale["freshness_status"] = "stale"
        stale["measurement_status"] = "failed"
        existing = {"source": "vpngate", "config_text": "existing"}
        vpngate_manager.publicvpnlist_enrich_existing_node(existing, stale)
        self.assertTrue(existing["pvl_endpoint_matched"])
        self.assertFalse(existing["pvl_verified"])

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
