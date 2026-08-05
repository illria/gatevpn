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

    def _add_page_cache(self, cache, records_by_country, *, now=None):
        now = time.time() if now is None else now
        cache["records_by_query"] = {}
        cache["page_meta_by_query"] = {}
        for country, records in records_by_country.items():
            country_code = str(country).upper()
            query_key = vpngate_manager._publicvpnlist_api_query_key(country_code, 1)
            cache["records_by_query"][query_key] = list(records)
            cache["page_meta_by_query"][query_key] = {
                "country": country_code,
                "page": 1,
                "next_page": 0,
                "has_next": False,
                "record_count": len(records),
                "last_success_at": now,
                "last_validated_at": now,
            }
        return cache

    def test_default_api_source_is_enabled_without_manual_snapshot(self):
        with mock.patch.object(
            vpngate_manager, "load_ui_config", return_value={"node_sources": "vpngate,vpnbook,ipspeed,vpngate_scraper"}
        ):
            self.assertEqual(vpngate_manager.publicvpnlist_source(), ("api", "https://api.fixture.invalid/api/v1/servers"))
            self.assertIn("publicvpnlist", vpngate_manager.get_node_sources())

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_ENABLED", False):
            self.assertEqual(vpngate_manager.publicvpnlist_source(), ("", ""))
            self.assertNotIn("publicvpnlist", vpngate_manager.get_node_sources())

    def test_api_candidate_selection_ranks_quality_and_interleaves_countries(self):
        ph_low = self.record("ph-low", country="PH", with_config=False)
        ph_low.update({"technical_quality_score": 20, "speed_mbps": 5, "latency_ms": 120})
        ph_high = self.record("ph-high", country="PH", with_config=False)
        ph_high.update({"technical_quality_score": 99, "speed_mbps": 80, "latency_ms": 10})
        fr = self.record("fr-best", country="FR", with_config=False)
        fr.update({"technical_quality_score": 80, "speed_mbps": 40, "latency_ms": 20})

        ordered = vpngate_manager.publicvpnlist_order_api_candidate_records([ph_low, ph_high, fr])

        self.assertEqual([row["id"] for row in ordered], ["ph-high", "fr-best", "ph-low"])

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
            row = self.record(node_id=f"{country.lower()}-1", country=country)
            row["ip"] = "198.51.100.11" if country == "PH" else "198.51.100.12"
            return self.api_response([row])

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "FR"])

        self.assertEqual(payload["_api_meta"]["records_fetched"], 2)
        self.assertEqual(payload["_api_meta"]["network_records_fetched"], 2)
        self.assertEqual(payload["_api_meta"]["cached_records_considered"], 0)
        self.assertEqual(payload["_api_meta"]["cached_records_reused"], 0)
        self.assertEqual(payload["_api_meta"]["metadata_records_returned"], 2)
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

    def test_legacy_country_cache_migrates_unconditionally_before_304(self):
        cached = vpngate_manager.publicvpnlist_api_cache_default()
        cached_row = self.record(with_config=False)
        cached.update(
            {
                "schema_version": 2,
                "last_success_at": time.time() - 100,
                "next_update_at": time.time() - 1,
                "etag_by_query": {
                    "country=PH&protocol=openvpn&status=online&sort=last_checked&order=desc&page=1&per_page=200": '"old"'
                },
                "records_by_country": {"PH": [cached_row]},
            }
        )
        self.api_cache_file.write_text(json.dumps(cached), encoding="utf-8")
        calls = []

        def first_http_get(url, metadata=None, extra_headers=None, **_kwargs):
            calls.append(dict(extra_headers or {}))
            self.assertFalse(extra_headers)
            metadata.update({"status": 200, "content_type": "application/json", "etag": '"migrated"'})
            return self.api_response([cached_row])

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=first_http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        query_key = vpngate_manager._publicvpnlist_api_query_key("PH", 1)
        migrated = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertEqual(calls, [{}])
        self.assertIn(query_key, migrated["records_by_query"])
        self.assertIn(query_key, migrated["page_meta_by_query"])
        self.assertEqual(migrated["etag_by_query"][query_key], '"migrated"')
        self.assertEqual(payload["data"][0]["id"], "ph-1")

        migrated["next_update_at"] = time.time() - 1
        vpngate_manager.save_publicvpnlist_api_cache(migrated)
        headers = Message()
        headers["ETag"] = '"migrated"'

        def second_http_get(_url, metadata=None, extra_headers=None, **_kwargs):
            self.assertEqual(extra_headers.get("If-None-Match"), '"migrated"')
            raise urllib.error.HTTPError(_url, 304, "not modified", headers, io.BytesIO())

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=second_http_get
        ):
            not_modified = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual(not_modified["_api_meta"]["status"], 304)
        self.assertEqual(not_modified["data"][0]["id"], "ph-1")

    def test_legacy_country_cache_failure_falls_back_without_page_precision(self):
        cached = vpngate_manager.publicvpnlist_api_cache_default()
        cached.update(
            {
                "schema_version": 2,
                "last_success_at": time.time() - 100,
                "next_update_at": time.time() - 1,
                "etag_by_query": {
                    vpngate_manager._publicvpnlist_api_query_key("PH", 1): '"legacy"'
                },
                "records_by_country": {"PH": [self.record("legacy-fallback", with_config=False)]},
            }
        )
        self.api_cache_file.write_text(json.dumps(cached), encoding="utf-8")

        def failed_http_get(*_args, **_kwargs):
            raise urllib.error.URLError("fixture unavailable")

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=failed_http_get
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual([row["id"] for row in payload["data"]], ["legacy-fallback"])
        migrated = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertNotIn(vpngate_manager._publicvpnlist_api_query_key("PH", 1), migrated["records_by_query"])
        self.assertNotIn(vpngate_manager._publicvpnlist_api_query_key("PH", 1), migrated["etag_by_query"])

    def test_legacy_page_migration_does_not_let_ph_refresh_us_forever(self):
        now = time.time()
        old_time = now - 100
        ph = self.record("legacy-ph", country="PH", with_config=False)
        us = self.record("legacy-us", country="US", with_config=False)
        ph_key = vpngate_manager._publicvpnlist_api_query_key("PH", 1)
        us_key = vpngate_manager._publicvpnlist_api_query_key("US", 1)
        legacy = vpngate_manager.publicvpnlist_api_cache_default()
        legacy.update(
            {
                "schema_version": 2,
                "last_success_at": old_time,
                "next_update_at": 0.0,
                "records_by_query": {ph_key: [ph], us_key: [us]},
                "page_meta_by_query": {
                    ph_key: {"country": "PH", "page": 1, "record_count": 1},
                    us_key: {"country": "US", "page": 1, "record_count": 1},
                },
                "records_by_country": {"PH": [ph], "US": [us]},
            }
        )
        self.api_cache_file.write_text(json.dumps(legacy), encoding="utf-8")
        calls = []

        def refresh_http_get(url, metadata=None, **_kwargs):
            country = parse_qs(urlsplit(url).query)["country"][0]
            calls.append(country)
            if country == "US":
                raise urllib.error.URLError("US page unavailable")
            metadata.update({"status": 200, "content_type": "application/json"})
            return self.api_response([self.record("refreshed-ph", country="PH", with_config=False)])

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_RETRIES", 1), mock.patch.object(
            vpngate_manager,
            "PUBLICVPNLIST_API_MAX_STALE_SECONDS",
            10,
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=refresh_http_get,
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "US"])

        self.assertEqual(calls, ["PH", "US"])
        self.assertEqual([row["id"] for row in payload["data"]], ["refreshed-ph"])
        migrated = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertEqual(
            migrated["page_meta_by_query"][us_key]["legacy_last_success_at"],
            old_time,
        )

        migrated["next_update_at"] = 0.0
        vpngate_manager.save_publicvpnlist_api_cache(migrated)

        def second_http_get(_url, metadata=None, **_kwargs):
            metadata.update({"status": 200, "content_type": "application/json"})
            return self.api_response(
                [self.record("refreshed-ph-again", country="PH", with_config=False)]
            )

        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=second_http_get,
        ):
            refreshed = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual([row["id"] for row in refreshed["data"]], ["refreshed-ph-again"])
        self.assertEqual(
            vpngate_manager.load_publicvpnlist_api_cache()["page_meta_by_query"][us_key]["legacy_last_success_at"],
            old_time,
        )

    def test_schema_v3_page_without_timestamp_fails_closed(self):
        now = time.time()
        row = self.record("schema-v3-missing-page-time", with_config=False)
        key = vpngate_manager._publicvpnlist_api_query_key("PH", 1)
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        cache.update(
            {
                "schema_version": 3,
                "last_success_at": now,
                "records_by_query": {key: [row]},
                "page_meta_by_query": {
                    key: {"country": "PH", "page": 1, "record_count": 1},
                },
            }
        )
        self.assertEqual(vpngate_manager.publicvpnlist_api_cached_records(cache, now=now), [])

    def test_api_time_supports_numeric_rfc2822_and_iso8601_inputs(self):
        expected = vpngate_manager._publicvpnlist_api_time("2026-08-04T00:00:00Z")
        self.assertEqual(
            vpngate_manager._publicvpnlist_api_time("2026-08-04T08:00:00+08:00"),
            expected,
        )
        self.assertAlmostEqual(
            vpngate_manager._publicvpnlist_api_time("2026-08-04T00:00:00.123Z"),
            expected + 0.123,
            places=3,
        )
        self.assertEqual(
            vpngate_manager._publicvpnlist_api_time("Tue, 04 Aug 2026 00:00:00 GMT"),
            expected,
        )
        self.assertEqual(vpngate_manager._publicvpnlist_api_time(expected), expected)
        self.assertEqual(vpngate_manager._publicvpnlist_api_time(str(expected)), expected)
        self.assertEqual(
            vpngate_manager._publicvpnlist_api_time("2026-08-04T00:00:00"),
            expected,
        )
        for invalid in ("NaN", "Infinity", "not-a-date", "2026-99-99T00:00:00Z"):
            self.assertEqual(vpngate_manager._publicvpnlist_api_time(invalid), 0.0)

    def test_cache_timestamp_freshness_rejects_unreasonable_future_values(self):
        now = time.time()
        stale_seconds = vpngate_manager.PUBLICVPNLIST_API_MAX_STALE_SECONDS
        self.assertTrue(vpngate_manager._publicvpnlist_api_cache_timestamp_is_fresh(now, now))
        self.assertTrue(
            vpngate_manager._publicvpnlist_api_cache_timestamp_is_fresh(
                now - stale_seconds,
                now,
            )
        )
        self.assertTrue(
            vpngate_manager._publicvpnlist_api_cache_timestamp_is_fresh(
                now + 120,
                now,
            )
        )
        for future in (now + 301, "2099-01-01T00:00:00Z", "NaN", "Infinity"):
            self.assertFalse(
                vpngate_manager._publicvpnlist_api_cache_timestamp_is_fresh(future, now)
            )

        row = self.record("future-measurement", with_config=False)
        row.update(
            {
                "checked_at": now + 120,
                "measurement_quality": "verified",
                "measurement_status": "success",
            }
        )
        self.assertTrue(vpngate_manager.publicvpnlist_metadata_is_verified(row, now=now))
        row["checked_at"] = now + 301
        self.assertFalse(vpngate_manager.publicvpnlist_metadata_is_verified(row, now=now))

    def test_iso_checked_at_and_expires_at_control_metadata_verification(self):
        now = vpngate_manager._publicvpnlist_api_time("2026-08-04T12:00:00Z")
        row = self.record("iso-verified", with_config=False)
        row.update(
            {
                "checked_at": "2026-08-04T11:00:00.123Z",
                "expires_at": "2026-08-04T23:00:00+08:00",
                "measurement_quality": "verified",
                "measurement_status": "success",
            }
        )
        normalized = vpngate_manager.normalize_publicvpnlist_row(row)
        self.assertTrue(vpngate_manager.publicvpnlist_metadata_is_verified(normalized, now=now))

        stale = dict(normalized)
        stale["checked_at"] = "2026-08-04T05:59:59Z"
        self.assertFalse(vpngate_manager.publicvpnlist_metadata_is_verified(stale, now=now))
        expired = dict(normalized)
        expired["expires_at"] = "2026-08-04T11:59:59Z"
        self.assertFalse(vpngate_manager.publicvpnlist_metadata_is_verified(expired, now=now))

    def test_expired_api_metadata_is_not_fresh_before_next_update(self):
        now = time.time()
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        cache.update(
            {
                "next_update_at": now + 3600,
                "expires_at": now - 1,
            }
        )
        self.assertFalse(vpngate_manager.publicvpnlist_api_cache_is_fresh(cache, now=now))

    def test_next_update_at_is_bounded_and_past_values_refresh_normally(self):
        cases = (
            ("normal", time.time() + 3600, False),
            ("past", time.time() - 1, False),
            ("future", "2099-01-01T00:00:00Z", True),
        )
        for _label, next_update_at, capped in cases:
            try:
                self.api_cache_file.unlink()
            except FileNotFoundError:
                pass
            response = json.loads(
                self.api_response([self.record(f"next-update-{_label}", with_config=False)]).decode("utf-8")
            )
            response["meta"]["next_update_at"] = next_update_at
            body = json.dumps(response).encode("utf-8")

            def http_get(_url, metadata=None, **_kwargs):
                metadata.update({"status": 200, "content_type": "application/json"})
                return body

            before = time.time()
            with mock.patch.object(
                vpngate_manager,
                "publicvpnlist_download_host_addresses",
                return_value=("93.184.216.34",),
            ), mock.patch.object(
                vpngate_manager,
                "publicvpnlist_http_get",
                side_effect=http_get,
            ):
                vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
            saved = vpngate_manager.load_publicvpnlist_api_cache()
            after = time.time()
            self.assertGreater(saved["next_update_at"], before)
            self.assertLessEqual(
                saved["next_update_at"],
                after + (vpngate_manager.PUBLICVPNLIST_API_REFRESH_SECONDS if capped or _label == "past" else 3600) + 2,
            )
            if capped:
                self.assertEqual(saved["last_error_code"], "next_update_at_capped")

    def test_due_profile_retry_bypasses_fresh_cache_only_for_that_country(self):
        now = time.time()
        ph = self.record("retry-due", country="PH", with_config=False)
        fr = self.record("fresh-fr", country="FR", with_config=False)
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        ph_key = vpngate_manager._publicvpnlist_api_query_key("PH", 1)
        fr_key = vpngate_manager._publicvpnlist_api_query_key("FR", 1)
        cache.update(
            {
                "last_success_at": now,
                "next_update_at": now + 3600,
                "records_by_query": {ph_key: [ph], fr_key: [fr]},
                "page_meta_by_query": {
                    ph_key: {
                        "country": "PH", "page": 1, "next_page": 0, "has_next": False,
                        "record_count": 1, "last_success_at": now, "last_validated_at": now,
                    },
                    fr_key: {
                        "country": "FR", "page": 1, "next_page": 0, "has_next": False,
                        "record_count": 1, "last_success_at": now, "last_validated_at": now,
                    },
                },
            }
        )
        vpngate_manager.publicvpnlist_api_record_profile_retry(
            cache,
            vpngate_manager.normalize_publicvpnlist_row(ph),
            now=now - 100,
        )
        cache["profile_retry_entries"][0]["retry_after"] = now - 1
        vpngate_manager._publicvpnlist_api_sync_retry_fields(cache)
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        source_hash = vpngate_manager.publicvpnlist_source_hash()
        self.assertTrue(
            vpngate_manager.publicvpnlist_refresh_needed(
                vpngate_manager.publicvpnlist_cache_default(source_hash),
                "api",
                source_hash,
                now,
            )
        )
        calls = []

        def http_get(url, metadata=None, extra_headers=None, **_kwargs):
            query = parse_qs(urlsplit(url).query)
            calls.append((query["country"][0], dict(extra_headers or {})))
            metadata.update({"status": 200, "content_type": "application/json", "etag": '"retry-new"'})
            return self.api_response([self.record("retry-due-new", country="PH")])

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_RETRIES", 1), mock.patch.object(
            vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)
        ), mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=http_get):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "FR"])

        self.assertEqual(calls, [("PH", {})])
        self.assertEqual([row["id"] for row in payload["data"]], ["retry-due-new", "fresh-fr"])

    def test_due_profile_retry_still_respects_429_backoff(self):
        now = time.time()
        row = self.record("retry-backoff", country="PH", with_config=False)
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        cache.update({
            "last_success_at": now,
            "next_update_at": now + 3600,
            "backoff_until": now + 300,
            "rate_limited": True,
        })
        vpngate_manager.publicvpnlist_api_record_profile_retry(
            cache,
            vpngate_manager.normalize_publicvpnlist_row(row),
            now=now - 100,
        )
        cache["profile_retry_entries"][0]["retry_after"] = now - 1
        vpngate_manager._publicvpnlist_api_sync_retry_fields(cache)
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        with mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=AssertionError("backoff must suppress retry")
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertTrue(payload["_api_meta"]["rate_limited"])
        self.assertEqual(payload["_api_meta"]["backoff_until"], cache["backoff_until"])

    def _save_fresh_metadata_cache(
        self,
        records,
        *,
        status=200,
        next_update_offset=3600,
        backoff_until=0.0,
        rate_limited=False,
        api_stale=False,
        refresh_failed=False,
    ):
        now = time.time()
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        by_country = {}
        for record in records:
            by_country.setdefault(str(record.get("country_code") or "PH").upper(), []).append(record)
        cache.update(
            {
                "last_success_at": now,
                "next_update_at": now + next_update_offset,
                "last_http_status": status,
                "backoff_until": backoff_until,
                "rate_limited": rate_limited,
                "api_stale": api_stale,
                "refresh_failed": refresh_failed,
                "records_by_country": by_country,
            }
        )
        self._add_page_cache(cache, by_country, now=now)
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        return cache

    def test_healthy_fresh_cache_reports_real_status_without_network(self):
        self._save_fresh_metadata_cache([self.record("fresh-cache", with_config=False)])
        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=AssertionError("fresh cache must not request the API"),
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        meta = payload["_api_meta"]
        self.assertEqual(meta["status"], 200)
        self.assertTrue(meta["from_cache"])
        self.assertEqual(meta["records_fetched"], 1)
        self.assertEqual(meta["network_records_fetched"], 0)
        self.assertEqual(meta["cached_records_considered"], 1)
        self.assertEqual(meta["cached_records_reused"], 1)
        self.assertEqual(meta["metadata_records_returned"], 1)
        self.assertFalse(meta["api_stale"])
        self.assertFalse(meta["refresh_failed"])
        self.assertFalse(meta["rate_limited"])
        self.assertEqual(meta["backoff_until"], 0.0)

    def test_fresh_cache_preserves_304_status_without_calling_it_rate_limited(self):
        self._save_fresh_metadata_cache(
            [self.record("fresh-304", with_config=False)],
            status=304,
        )
        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=AssertionError("fresh 304 cache must not request the API"),
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertEqual(payload["_api_meta"]["status"], 304)
        self.assertFalse(payload["_api_meta"]["rate_limited"])
        self.assertEqual(payload["_api_meta"]["network_records_fetched"], 0)
        self.assertEqual(payload["_api_meta"]["cached_records_reused"], 1)
        self.assertEqual(payload["_api_meta"]["metadata_records_returned"], 1)

    def test_active_and_expired_429_backoff_have_distinct_cache_state(self):
        now = time.time()
        self._save_fresh_metadata_cache(
            [self.record("active-429", with_config=False)],
            status=429,
            next_update_offset=3600,
            backoff_until=now + 300,
            rate_limited=True,
            api_stale=True,
            refresh_failed=True,
        )
        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=AssertionError("active backoff must suppress requests"),
        ):
            active = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertEqual(active["_api_meta"]["status"], 429)
        self.assertTrue(active["_api_meta"]["rate_limited"])
        self.assertGreater(active["_api_meta"]["backoff_until"], now)

        expired = vpngate_manager.load_publicvpnlist_api_cache()
        expired["backoff_until"] = now - 1
        expired["next_update_at"] = now + 3600
        expired["rate_limited"] = True
        vpngate_manager.save_publicvpnlist_api_cache(expired)
        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=AssertionError("expired backoff with fresh cache must not request"),
        ):
            recovered = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertFalse(recovered["_api_meta"]["rate_limited"])
        self.assertEqual(recovered["_api_meta"]["backoff_until"], 0.0)

    def test_all_cache_return_paths_apply_runtime_metadata_limit(self):
        records = []
        for index in range(30):
            row = self.record(f"bounded-{index}", with_config=False)
            row["ip"] = f"198.51.100.{index + 1}"
            row["hostname"] = f"bounded-{index}.fixture.invalid"
            records.append(row)
        self._save_fresh_metadata_cache(records)
        for limit in (20, 5):
            with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_RECORDS", limit), mock.patch.object(
                vpngate_manager,
                "publicvpnlist_http_get",
                side_effect=AssertionError("bounded cache must not request the API"),
            ), mock.patch.object(
                vpngate_manager,
                "publicvpnlist_download_host_addresses",
                return_value=("93.184.216.34",),
            ):
                payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
                self.assertLessEqual(len(payload["data"]), limit)
                self.assertEqual(
                    payload["_api_meta"]["records_fetched"],
                    payload["_api_meta"]["metadata_records_returned"],
                )
                self.assertEqual(payload["_api_meta"]["network_records_fetched"], 0)
                self.assertEqual(
                    payload["_api_meta"]["cached_records_reused"],
                    payload["_api_meta"]["metadata_records_returned"],
                )
                self.assertLessEqual(
                    vpngate_manager.load_publicvpnlist_api_cache()["metadata_record_count"],
                    limit,
                )

        now = time.time()
        limited_cache = vpngate_manager.load_publicvpnlist_api_cache()
        limited_cache["backoff_until"] = now + 300
        limited_cache["rate_limited"] = True
        limited_cache["last_http_status"] = 429
        vpngate_manager.save_publicvpnlist_api_cache(limited_cache)
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_RECORDS", 5), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=AssertionError("backoff cache must not request the API"),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ):
            backoff = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertLessEqual(len(backoff["data"]), 5)

    def test_failed_refresh_fallback_also_applies_runtime_metadata_limit(self):
        records = []
        for index in range(12):
            row = self.record(f"failed-fallback-{index}", with_config=False)
            row["ip"] = f"198.51.100.{index + 1}"
            records.append(row)
        cache = self._save_fresh_metadata_cache(records, next_update_offset=-1)
        cache["next_update_at"] = time.time() - 1
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_RECORDS", 5), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=urllib.error.URLError("fixture unavailable"),
        ), mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertLessEqual(len(payload["data"]), 5)
        self.assertEqual(payload["_api_meta"]["network_records_fetched"], 0)
        self.assertEqual(
            payload["_api_meta"]["metadata_records_returned"],
            len(payload["data"]),
        )
        self.assertEqual(
            payload["_api_meta"]["records_fetched"],
            payload["_api_meta"]["metadata_records_returned"],
        )
        self.assertGreaterEqual(payload["_api_meta"]["cached_records_reused"], len(payload["data"]))

    def test_cached_records_considered_reused_and_returned_are_distinct(self):
        first = self.record("stats-first", with_config=False)
        duplicate = dict(first)
        duplicate["id"] = "stats-duplicate"
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        now = time.time()
        cache.update(
            {
                "last_success_at": now,
                "next_update_at": now + 3600,
                "records_by_country": {"PH": [first, duplicate]},
            }
        )
        self._add_page_cache(cache, {"PH": [first, duplicate]}, now=now)
        vpngate_manager.save_publicvpnlist_api_cache(cache)

        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=AssertionError("fresh cache must not request the API"),
        ):
            fresh = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertEqual(fresh["_api_meta"]["cached_records_considered"], 2)
        self.assertEqual(fresh["_api_meta"]["cached_records_reused"], 1)
        self.assertEqual(fresh["_api_meta"]["metadata_records_returned"], 1)

        expired_page = vpngate_manager.load_publicvpnlist_api_cache()
        expired_page["next_update_at"] = 0.0
        old_time = time.time() - 100
        key = vpngate_manager._publicvpnlist_api_query_key("PH", 1)
        expired_page["page_meta_by_query"][key]["last_success_at"] = old_time
        expired_page["page_meta_by_query"][key]["last_validated_at"] = old_time
        vpngate_manager.save_publicvpnlist_api_cache(expired_page)
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_STALE_SECONDS", 10), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=urllib.error.URLError("expired page"),
        ):
            stale = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        self.assertEqual(stale["_api_meta"]["cached_records_considered"], 2)
        self.assertEqual(stale["_api_meta"]["cached_records_reused"], 0)
        self.assertEqual(stale["_api_meta"]["metadata_records_returned"], 0)

    def test_bounded_metadata_deduplicates_public_ids_and_endpoints(self):
        first = self.record("duplicate-id", with_config=False)
        same_endpoint = dict(first)
        same_endpoint["id"] = "duplicate-endpoint"
        same_id_other_endpoint = dict(first)
        same_id_other_endpoint["hostname"] = "duplicate-id-other.fixture.invalid"
        same_id_other_endpoint["ip"] = "198.51.100.201"
        bounded = vpngate_manager.publicvpnlist_api_normalize_bounded_records(
            [first, same_endpoint, same_id_other_endpoint],
            limit=20,
        )
        self.assertEqual(len(bounded), 2)
        self.assertEqual(
            {row["hostname"] for row in bounded},
            {first["hostname"], same_id_other_endpoint["hostname"]},
        )

    def test_bounded_metadata_prefers_verified_then_freshness_and_availability(self):
        fresh_online = self.record("fresh-online", with_config=True)
        fresh_online["ip"] = "198.51.100.44"
        fresh_online["hostname"] = "shared.fixture.invalid"
        fresh_online["last_checked_at"] = "2026-08-04T12:00:00Z"
        stale_offline = dict(fresh_online)
        stale_offline["id"] = "stale-offline"
        stale_offline["freshness_status"] = "stale"
        stale_offline["availability_status"] = "offline"
        stale_offline.pop("config_download_url", None)
        bounded = vpngate_manager.publicvpnlist_api_normalize_bounded_records(
            [stale_offline, fresh_online],
            limit=20,
        )
        self.assertEqual([row["id"] for row in bounded], ["fresh-online"])
        self.assertIn("config_download_url", bounded[0])

        recent_online = dict(fresh_online)
        recent_online["id"] = "recent-online"
        recent_online["freshness_status"] = "recent"
        stale = dict(fresh_online)
        stale["id"] = "stale"
        stale["freshness_status"] = "stale"
        stale["availability_status"] = "unknown"
        forward = vpngate_manager.publicvpnlist_api_normalize_bounded_records(
            [stale, recent_online], limit=20
        )
        reverse = vpngate_manager.publicvpnlist_api_normalize_bounded_records(
            [recent_online, stale], limit=20
        )
        self.assertEqual([row["id"] for row in forward], ["recent-online"])
        self.assertEqual([row["id"] for row in reverse], ["recent-online"])

    def test_bounded_metadata_keeps_distinct_ports_and_protocols(self):
        tcp = self.record("same-host-tcp", with_config=False)
        tcp["ip"] = "198.51.100.55"
        tcp["hostname"] = "same-host.fixture.invalid"
        udp = dict(tcp)
        udp["id"] = "same-host-udp"
        udp["transport"] = "udp"
        udp["port"] = 1194
        other_port = dict(tcp)
        other_port["id"] = "same-host-other-port"
        other_port["port"] = 1195
        bounded = vpngate_manager.publicvpnlist_api_normalize_bounded_records(
            [tcp, udp, other_port], limit=20
        )
        self.assertEqual({row["id"] for row in bounded}, {"same-host-tcp", "same-host-udp", "same-host-other-port"})

    def test_due_retry_country_is_requested_before_full_fresh_cache(self):
        now = time.time()
        ph_records = []
        for index in range(20):
            row = self.record(f"cached-ph-{index}", country="PH", with_config=False)
            row["ip"] = f"198.51.100.{index + 1}"
            ph_records.append(row)
        us = self.record("retry-us", country="US", with_config=False)
        us["ip"] = "198.51.100.200"
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        cache.update(
            {
                "last_success_at": now,
                "next_update_at": now + 3600,
                "records_by_country": {"PH": ph_records, "US": [us]},
            }
        )
        self._add_page_cache(cache, {"PH": ph_records, "US": [us]}, now=now)
        vpngate_manager.publicvpnlist_api_record_profile_retry(
            cache,
            vpngate_manager.normalize_publicvpnlist_row(us),
            now=now - 100,
        )
        cache["profile_retry_entries"][0]["retry_after"] = now - 1
        vpngate_manager._publicvpnlist_api_sync_retry_fields(cache)
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        calls = []

        def retry_http_get(url, metadata=None, **_kwargs):
            country = parse_qs(urlsplit(url).query)["country"][0]
            calls.append(country)
            metadata.update({"status": 200, "content_type": "application/json"})
            return self.api_response([self.record("fresh-us", country="US", with_config=False)])

        with mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=retry_http_get), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "US"])
        self.assertEqual(calls, ["US"])
        self.assertLessEqual(len(payload["data"]), vpngate_manager.PUBLICVPNLIST_API_MAX_RECORDS)

    def test_multiple_due_retry_countries_each_get_one_bounded_request(self):
        now = time.time()
        rows = [self.record("retry-ph", country="PH", with_config=False), self.record("retry-us", country="US", with_config=False)]
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        cache.update({"last_success_at": now, "next_update_at": now + 3600, "records_by_country": {"PH": [rows[0]], "US": [rows[1]]}})
        self._add_page_cache(cache, {"PH": [rows[0]], "US": [rows[1]]}, now=now)
        for row in rows:
            vpngate_manager.publicvpnlist_api_record_profile_retry(cache, vpngate_manager.normalize_publicvpnlist_row(row), now=now - 100)
        for entry in cache["profile_retry_entries"]:
            entry["retry_after"] = now - 1
        vpngate_manager._publicvpnlist_api_sync_retry_fields(cache)
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        calls = []

        def retry_http_get(url, metadata=None, **_kwargs):
            country = parse_qs(urlsplit(url).query)["country"][0]
            calls.append(country)
            metadata.update({"status": 200, "content_type": "application/json"})
            return self.api_response([self.record(f"new-{country}", country=country, with_config=False)])

        with mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=retry_http_get), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "US"])
        self.assertEqual(calls, ["PH", "US"])
        self.assertLessEqual(len(payload["data"]), vpngate_manager.PUBLICVPNLIST_API_MAX_RECORDS)

    def _seed_page_cache(self, pages, *, country="PH"):
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        now = time.time()
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
                "last_success_at": now,
                "last_validated_at": now,
            }
            etag_by_query[query_key] = f'"page-{page}"'
        cache.update(
            {
                "last_success_at": now,
                "next_update_at": 0.0,
                "records_by_query": records_by_query,
                "page_meta_by_query": page_meta_by_query,
                "etag_by_query": etag_by_query,
            }
        )
        vpngate_manager.save_publicvpnlist_api_cache(cache)

    def test_country_page_success_times_do_not_refresh_failed_country(self):
        now = time.time()
        old_time = now - 100
        ph = self.record("fresh-ph", country="PH", with_config=False)
        us = self.record("old-us", country="US", with_config=False)
        ph_key = vpngate_manager._publicvpnlist_api_query_key("PH", 1)
        us_key = vpngate_manager._publicvpnlist_api_query_key("US", 1)
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        cache.update(
            {
                "last_success_at": now,
                "next_update_at": 0.0,
                "records_by_query": {ph_key: [ph], us_key: [us]},
                "page_meta_by_query": {
                    ph_key: {
                        "country": "PH",
                        "page": 1,
                        "next_page": 0,
                        "has_next": False,
                        "record_count": 1,
                        "last_success_at": old_time,
                        "last_validated_at": old_time,
                    },
                    us_key: {
                        "country": "US",
                        "page": 1,
                        "next_page": 0,
                        "has_next": False,
                        "record_count": 1,
                        "last_success_at": old_time,
                        "last_validated_at": old_time,
                    },
                },
            }
        )
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        calls = []

        def refresh_http_get(url, metadata=None, **_kwargs):
            country = parse_qs(urlsplit(url).query)["country"][0]
            calls.append(country)
            if country == "US":
                raise urllib.error.URLError("US page unavailable")
            metadata.update({"status": 200, "content_type": "application/json"})
            return self.api_response([self.record("new-ph", country="PH", with_config=False)])

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_RETRIES", 1), mock.patch.object(
            vpngate_manager,
            "PUBLICVPNLIST_API_MAX_STALE_SECONDS",
            10,
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=refresh_http_get,
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH", "US"])

        self.assertEqual(calls, ["PH", "US"])
        self.assertEqual([row["id"] for row in payload["data"]], ["new-ph"])
        refreshed = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertGreater(refreshed["page_meta_by_query"][ph_key]["last_success_at"], old_time)
        self.assertGreater(refreshed["page_meta_by_query"][ph_key]["last_validated_at"], old_time)
        self.assertEqual(refreshed["page_meta_by_query"][us_key]["last_success_at"], old_time)
        self.assertEqual(refreshed["page_meta_by_query"][us_key]["last_validated_at"], old_time)
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_STALE_SECONDS", 10):
            self.assertEqual(
                [row["id"] for row in vpngate_manager.publicvpnlist_api_cached_records(refreshed)],
                ["new-ph"],
            )

    def test_304_updates_only_page_validation_time_and_preserves_page_success_time(self):
        now = time.time()
        old_time = now - 100
        row = self.record("304-page", country="PH", with_config=False)
        key = vpngate_manager._publicvpnlist_api_query_key("PH", 1)
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        cache.update(
            {
                "last_success_at": now,
                "next_update_at": 0.0,
                "records_by_query": {key: [row]},
                "page_meta_by_query": {
                    key: {
                        "country": "PH",
                        "page": 1,
                        "next_page": 0,
                        "has_next": False,
                        "record_count": 1,
                        "etag": '"old"',
                        "last_success_at": old_time,
                        "last_validated_at": old_time,
                    }
                },
                "etag_by_query": {key: '"old"'},
            }
        )
        vpngate_manager.save_publicvpnlist_api_cache(cache)

        def not_modified(url, **_kwargs):
            raise self._not_modified(url, '"new"')

        with mock.patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=not_modified,
        ):
            vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        refreshed = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertEqual(refreshed["page_meta_by_query"][key]["last_success_at"], old_time)
        self.assertGreater(refreshed["page_meta_by_query"][key]["last_validated_at"], old_time)
        self.assertEqual(refreshed["page_meta_by_query"][key]["etag"], '"new"')

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
        self.assertEqual(payload["_api_meta"]["network_records_fetched"], 0)
        self.assertEqual(payload["_api_meta"]["cached_records_considered"], 2)
        self.assertEqual(payload["_api_meta"]["cached_records_reused"], 2)
        self.assertEqual(payload["_api_meta"]["metadata_records_returned"], 2)

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
        self.assertEqual(payload["_api_meta"]["network_records_fetched"], 1)
        self.assertEqual(payload["_api_meta"]["cached_records_considered"], 1)
        self.assertEqual(payload["_api_meta"]["cached_records_reused"], 1)
        self.assertEqual(payload["_api_meta"]["metadata_records_returned"], 2)

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
        self.assertEqual(payload["_api_meta"]["cached_records_considered"], 1)

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
        self.assertEqual(payload["_api_meta"]["network_records_fetched"], 1)
        self.assertEqual(payload["_api_meta"]["cached_records_considered"], 1)
        self.assertGreaterEqual(payload["_api_meta"]["cached_records_reused"], 1)
        self.assertEqual(payload["_api_meta"]["metadata_records_returned"], 2)

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
        self.assertEqual(payload["_api_meta"]["network_records_fetched"], 1)
        self.assertEqual(payload["_api_meta"]["cached_records_reused"], 0)
        self.assertEqual(payload["_api_meta"]["metadata_records_returned"], 1)
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

        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(vpngate_manager, "publicvpnlist_http_get", side_effect=recovered_http_get):
            recovered = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        refreshed_cache = vpngate_manager.load_publicvpnlist_api_cache()
        self.assertEqual(recovered["_api_meta"]["rate_limited"], False)
        self.assertEqual(refreshed_cache["rate_limited"], False)
        self.assertEqual(refreshed_cache["backoff_until"], 0.0)

    def test_429_stops_all_later_country_requests_and_reuses_fresh_cache(self):
        now = time.time()
        cached_us = self.record("cached-us", country="US", with_config=False)
        cached_fr = self.record("cached-fr", country="FR", with_config=False)
        cache = vpngate_manager.publicvpnlist_api_cache_default()
        cache.update(
            {
                "last_success_at": now,
                "next_update_at": 0.0,
                "records_by_country": {"US": [cached_us], "FR": [cached_fr]},
            }
        )
        self._add_page_cache(cache, {"US": [cached_us], "FR": [cached_fr]}, now=now)
        retry_ph = self.record("retry-ph", country="PH", with_config=False)
        for retry_row in (retry_ph, cached_us, cached_fr):
            vpngate_manager.publicvpnlist_api_record_profile_retry(
                cache,
                vpngate_manager.normalize_publicvpnlist_row(retry_row),
                now=now - 100,
            )
        for entry in cache["profile_retry_entries"]:
            entry["retry_after"] = now - 1
        vpngate_manager._publicvpnlist_api_sync_retry_fields(cache)
        vpngate_manager.save_publicvpnlist_api_cache(cache)
        headers = Message()
        headers["Retry-After"] = "120"
        calls = []

        def rate_limited_http_get(url, **_kwargs):
            country = parse_qs(urlsplit(url).query)["country"][0]
            calls.append(country)
            raise urllib.error.HTTPError(url, 429, "rate limited", headers, io.BytesIO())

        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=rate_limited_http_get,
        ):
            payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(
                target_countries=["PH", "US", "FR"]
            )

        self.assertEqual(calls, ["PH"])
        self.assertEqual([row["id"] for row in payload["data"]], ["cached-us", "cached-fr"])
        self.assertTrue(payload["_api_meta"]["rate_limited"])
        self.assertGreater(payload["_api_meta"]["backoff_until"], now)
        self.assertEqual(payload["_api_meta"]["network_records_fetched"], 0)
        self.assertEqual(payload["_api_meta"]["cached_records_considered"], 2)
        self.assertEqual(payload["_api_meta"]["cached_records_reused"], 2)

    def test_active_429_does_not_revive_expired_metadata_but_keeps_profile_cache(self):
        now = time.time()
        expired = self.record("expired-metadata", country="PH", with_config=False)
        profile_cache = vpngate_manager.publicvpnlist_cache_default("fixture")
        profile_cache["profiles"] = {
            "keep-profile": {
                "country_short": "PH",
                "config_text": "client\nproto tcp\nremote keep.fixture.invalid 443\n",
                "config_validated_at": now,
                "last_seen_at": now,
            }
        }
        profile_cache["profile_order"] = ["keep-profile"]
        vpngate_manager.save_publicvpnlist_cache(profile_cache)
        for cache_update in (
            {"last_success_at": now - vpngate_manager.PUBLICVPNLIST_API_MAX_STALE_SECONDS - 1},
            {"last_success_at": now, "expires_at": now - 1},
            {"last_success_at": 0.0},
        ):
            cache = vpngate_manager.publicvpnlist_api_cache_default()
            cache.update(
                {
                    **cache_update,
                    "last_http_status": 429,
                    "rate_limited": True,
                    "backoff_until": now + 120,
                    "records_by_country": {"PH": [expired]},
                }
            )
            vpngate_manager.save_publicvpnlist_api_cache(cache)
            with mock.patch.object(
                vpngate_manager,
                "publicvpnlist_http_get",
                side_effect=AssertionError("active backoff must not request metadata"),
            ):
                payload = vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
            self.assertEqual(payload["data"], [])
            self.assertEqual(payload["_api_meta"]["status"], 429)
            self.assertTrue(payload["_api_meta"]["rate_limited"])
            self.assertTrue(payload["_api_meta"]["api_stale"] or cache_update.get("expires_at"))
            self.assertEqual(vpngate_manager.load_publicvpnlist_api_cache()["records_by_country"]["PH"][0]["id"], "expired-metadata")
            self.assertIn("keep-profile", vpngate_manager.load_publicvpnlist_cache()["profiles"])

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
        self.assertEqual(calls, [{"If-None-Match": '"retry-v1"'}, {}])
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

    def test_profile_retry_304_failure_has_only_one_unconditional_attempt(self):
        row = self.record("retry-failure", with_config=True)
        row["config_sha256"] = ""

        def first_http_get(_url, metadata=None, **_kwargs):
            metadata.update({"status": 200, "content_type": "application/json", "etag": '"retry-failure-v1"'})
            return self.api_response([row])

        with mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=first_http_get,
        ):
            vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])
        api_cache = vpngate_manager.load_publicvpnlist_api_cache()
        api_cache["next_update_at"] = 0.0
        vpngate_manager.save_publicvpnlist_api_cache(api_cache)

        with mock.patch.object(
            vpngate_manager,
            "fetch_publicvpnlist_snapshot",
            return_value={"data": [row]},
        ), mock.patch.object(
            vpngate_manager,
            "fetch_publicvpnlist_config",
            side_effect=vpngate_manager.PublicVPNListSnapshotError("profile unavailable"),
        ), mock.patch.object(vpngate_manager, "log_to_json"):
            vpngate_manager.refresh_publicvpnlist_cache(
                cache=vpngate_manager.publicvpnlist_cache_default(vpngate_manager.publicvpnlist_source_hash()),
            )

        failed_cache = vpngate_manager.load_publicvpnlist_api_cache()
        failed_cache["next_update_at"] = 0.0
        for entry in failed_cache["profile_retry_entries"]:
            entry["retry_after"] = time.time() - 1
        vpngate_manager.save_publicvpnlist_api_cache(failed_cache)
        calls = []

        def retry_http_get(url, metadata=None, extra_headers=None, **_kwargs):
            calls.append(dict(extra_headers or {}))
            if len(calls) == 1:
                raise self._not_modified(url, '"retry-failure-v1"')
            raise urllib.error.URLError("unconditional retry failed")

        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_API_MAX_RETRIES", 1), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_download_host_addresses",
            return_value=("93.184.216.34",),
        ), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_http_get",
            side_effect=retry_http_get,
        ):
            vpngate_manager.fetch_publicvpnlist_api_snapshot(target_countries=["PH"])

        self.assertEqual(calls, [{"If-None-Match": '"retry-failure-v1"'}, {}])
        self.assertEqual(len(calls), 2)
        self.assertTrue(vpngate_manager.load_publicvpnlist_api_cache()["profile_retry_entries"])

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

    def test_metadata_without_public_id_is_not_treated_as_connectable(self):
        row = self.record(with_config=False)
        row["id"] = ""
        with mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [row]}
        ), mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_config", side_effect=AssertionError("metadata-only must not download")
        ), mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_official_config", side_effect=AssertionError("missing id must not run live check")
        ), mock.patch.object(vpngate_manager, "log_to_json"):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())
        self.assertEqual(result, [])

    def test_api_metadata_runs_official_live_check_token_and_profile_download(self):
        row = self.record("live-ph", with_config=False)
        row["config_sha256"] = ""
        calls = []
        config = (
            "client\nproto tcp\nremote live-ph.fixture.invalid 443\n"
            "<ca>\nCERT\n</ca>\n"
        )

        def http_get(url, metadata=None, accept=None, extra_headers=None, data=None, method=None, **_kwargs):
            parsed = urlsplit(url)
            calls.append(
                {
                    "url": url,
                    "path": parsed.path,
                    "query": parse_qs(parsed.query),
                    "accept": accept,
                    "headers": dict(extra_headers or {}),
                    "data": data,
                    "method": method,
                }
            )
            if parsed.path == "/test_server.php":
                metadata.update({"status": 200, "content_type": "application/json"})
                return json.dumps({"ok": True, "status": "ok"}).encode()
            if parsed.path == "/get_token.php":
                metadata.update({"status": 200, "content_type": "application/json"})
                return json.dumps({"ok": True, "token": "fixture-one-time-token"}).encode()
            if parsed.path == "/download.php":
                metadata.update({"status": 200, "content_type": "application/x-openvpn-profile"})
                return config.encode()
            raise AssertionError(f"unexpected PublicVPNList URL path: {parsed.path}")

        with mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [row]}
        ), mock.patch.object(
            vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)
        ), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ), mock.patch.object(vpngate_manager, "log_to_json"):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())

        self.assertEqual(len(result), 1)
        self.assertEqual([call["path"] for call in calls], ["/test_server.php", "/get_token.php", "/download.php"])
        self.assertEqual(calls[0]["query"]["id"], ["live-ph"])
        self.assertEqual(calls[0]["accept"], "application/json")
        self.assertEqual(calls[0]["headers"]["X-Requested-With"], "XMLHttpRequest")
        self.assertEqual(calls[1]["method"], "POST")
        self.assertEqual(calls[1]["data"], b"id=live-ph")
        self.assertEqual(calls[1]["headers"]["Content-Type"], "application/x-www-form-urlencoded;charset=UTF-8")
        self.assertEqual(calls[2]["accept"], "application/x-openvpn-profile,text/plain")
        cache_text = self.profile_cache_file.read_text(encoding="utf-8")
        self.assertNotIn("fixture-one-time-token", cache_text)
        self.assertNotIn("download.php", cache_text)
        stats = vpngate_manager.load_publicvpnlist_cache()["last_refresh_stats"]
        self.assertEqual(stats["live_check_attempted"], 1)
        self.assertEqual(stats["live_check_succeeded"], 1)
        self.assertEqual(stats["token_generated"], 1)

    def test_live_check_failure_is_fail_closed_without_token_request(self):
        row = self.record("live-failed", with_config=False)
        calls = []

        def http_get(url, metadata=None, **_kwargs):
            calls.append(urlsplit(url).path)
            metadata.update({"status": 200, "content_type": "application/json"})
            return json.dumps({"ok": False, "status": "fail"}).encode()

        with mock.patch.object(
            vpngate_manager, "fetch_publicvpnlist_snapshot", return_value={"data": [row]}
        ), mock.patch.object(
            vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)
        ), mock.patch.object(
            vpngate_manager, "publicvpnlist_http_get", side_effect=http_get
        ), mock.patch.object(vpngate_manager, "log_to_json"):
            result = vpngate_manager.fetch_publicvpnlist_candidates(["PH"], set())

        self.assertEqual(result, [])
        self.assertEqual(calls, ["/test_server.php"])
        stats = vpngate_manager.load_publicvpnlist_cache()["last_refresh_stats"]
        self.assertEqual(stats["live_check_attempted"], 1)
        self.assertEqual(stats["live_check_succeeded"], 0)
        self.assertEqual(stats["token_generated"], 0)

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
                "checked_at": time.time(),
                "measurement_quality": "verified",
                "measurement_status": "success",
            }
        )
        normalized = vpngate_manager.normalize_publicvpnlist_row(row)
        self.assertTrue(vpngate_manager.publicvpnlist_metadata_is_verified(normalized))
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
        self.assertNotIn("publicvpnlist", node["verification_sources"])
        self.assertIn("publicvpnlist", node["endpoint_match_sources"])
        self.assertEqual(node["pvl_public_id"], "ph-1")

    def _run_existing_node_enrichment_with_api_cache(self, last_success_at):
        row = self.record("enrich-me", with_config=False)
        row.update(
            {
                "ip": "198.51.100.77",
                "hostname": "enrich-me.fixture.invalid",
                "checked_at": time.time(),
                "measurement_quality": "verified",
                "measurement_status": "success",
            }
        )
        api_cache = vpngate_manager.publicvpnlist_api_cache_default()
        api_cache.update(
            {
                "last_success_at": last_success_at,
                "records_by_country": {"PH": [row]},
            }
        )
        self._add_page_cache(api_cache, {"PH": [row]}, now=last_success_at)
        vpngate_manager.save_publicvpnlist_api_cache(api_cache)
        node = {
            "source": "vpngate",
            "ip": "198.51.100.77",
            "remote_host": "enrich-me.fixture.invalid",
            "remote_port": 443,
            "proto": "tcp",
            "speed": 7_000_000,
            "score": 7_000_000,
            "ping": 31,
            "latency_ms": 31,
            "verification_sources": ["vpngate"],
        }
        empty_profile_cache = vpngate_manager.publicvpnlist_cache_default(
            vpngate_manager.publicvpnlist_source_hash()
        )
        with mock.patch.object(
            vpngate_manager,
            "refresh_publicvpnlist_cache",
            return_value=empty_profile_cache,
        ), mock.patch.object(vpngate_manager, "log_to_json"):
            vpngate_manager.fetch_publicvpnlist_candidates(
                ["PH"],
                set(),
                existing_nodes=[node],
            )
        stats = vpngate_manager.load_publicvpnlist_cache().get("last_refresh_stats", {})
        return node, stats

    def test_fresh_api_metadata_enriches_existing_node(self):
        node, stats = self._run_existing_node_enrichment_with_api_cache(time.time())
        self.assertTrue(node.get("pvl_endpoint_matched"))
        self.assertIn("publicvpnlist", node.get("endpoint_match_sources", []))
        self.assertIn("publicvpnlist", node.get("verification_sources", []))
        self.assertEqual(stats.get("matched_existing_nodes"), 1)

    def test_expired_api_metadata_does_not_enrich_existing_node(self):
        node, stats = self._run_existing_node_enrichment_with_api_cache(
            time.time() - vpngate_manager.PUBLICVPNLIST_API_MAX_STALE_SECONDS - 1
        )
        self.assertNotIn("pvl_endpoint_matched", node)
        self.assertNotIn("endpoint_match_sources", node)
        self.assertNotIn("publicvpnlist", node.get("verification_sources", []))
        self.assertEqual(node["speed"], 7_000_000)
        self.assertEqual(node["latency_ms"], 31)
        self.assertEqual(stats.get("matched_existing_nodes"), 0)

    def test_api_metadata_without_last_success_does_not_enrich_existing_node(self):
        node, stats = self._run_existing_node_enrichment_with_api_cache(0)
        self.assertNotIn("pvl_endpoint_matched", node)
        self.assertEqual(stats.get("matched_existing_nodes"), 0)

    def test_endpoint_enrichment_selects_one_best_record_independent_of_input_order(self):
        verified = self.record("verified-endpoint", with_config=False)
        verified.update(
            {
                "ip": "198.51.100.88",
                "hostname": "shared-endpoint.fixture.invalid",
                "checked_at": time.time(),
                "measurement_quality": "verified",
                "measurement_status": "success",
            }
        )
        stale = dict(verified)
        stale.update(
            {
                "id": "stale-endpoint",
                "freshness_status": "stale",
                "measurement_status": "failed",
                "checker_measured_throughput_mbps": 999,
            }
        )
        first = vpngate_manager.publicvpnlist_select_best_endpoint_records([stale, verified])
        second = vpngate_manager.publicvpnlist_select_best_endpoint_records([verified, stale])
        self.assertEqual([row["id"] for row in first], ["verified-endpoint"])
        self.assertEqual([row["id"] for row in second], ["verified-endpoint"])

    def test_same_public_id_on_different_endpoints_is_not_merged(self):
        first = self.record("same-public-id", with_config=False)
        second = dict(first)
        second["hostname"] = "different-endpoint.fixture.invalid"
        second["ip"] = "198.51.100.199"
        selected = vpngate_manager.publicvpnlist_select_best_endpoint_records([first, second])
        self.assertEqual({row["host"] for row in selected}, {first["hostname"], second["hostname"]})

    def test_endpoint_dedup_keeps_port_and_protocol_distinctions(self):
        base = self.record("endpoint-base", with_config=False)
        same_host_other_port = dict(base)
        same_host_other_port["id"] = "endpoint-other-port"
        same_host_other_port["port"] = 1194
        same_host_other_proto = dict(base)
        same_host_other_proto["id"] = "endpoint-other-proto"
        same_host_other_proto["transport"] = "udp"
        same_host_other_proto["protocol"] = "udp"
        selected = vpngate_manager.publicvpnlist_select_best_endpoint_records(
            [base, same_host_other_port, same_host_other_proto]
        )
        self.assertEqual(len(selected), 3)

    def test_failed_measurement_does_not_apply_publicvpnlist_metrics(self):
        node = {
            "source": "vpngate",
            "speed": 7_000_000,
            "score": 7_000_000,
            "ping": 31,
            "latency_ms": 31,
            "verification_sources": ["vpngate"],
        }
        row = self.record("failed-measurement", with_config=False)
        row.update(
            {
                "checked_at": time.time(),
                "measurement_quality": "verified",
                "measurement_status": "failed",
                "checker_measured_throughput_mbps": 99,
                "checker_measured_tunnel_rtt_ms": 4,
            }
        )
        normalized = vpngate_manager.normalize_publicvpnlist_row(row)
        vpngate_manager.publicvpnlist_enrich_existing_node(node, normalized)
        self.assertFalse(node["pvl_verified"])
        self.assertEqual(node["speed"], 7_000_000)
        self.assertEqual(node["score"], 7_000_000)
        self.assertEqual(node["ping"], 31)
        self.assertEqual(node["latency_ms"], 31)
        self.assertNotIn("publicvpnlist", node["verification_sources"])


if __name__ == "__main__":
    unittest.main()
