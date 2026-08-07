import importlib.util
import json
import threading
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_smoke_module():
    path = ROOT / "tools" / "publicvpnlist-smoke.py"
    spec = importlib.util.spec_from_file_location("publicvpnlist_smoke_runtime", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class PublicVPNListRuntimeTests(unittest.TestCase):
    def test_background_api_refresh_reconciles_validated_profiles_into_nodes(self):
        import vpngate_manager

        refresh_started = threading.Event()
        release_refresh = threading.Event()

        def refresh_fixture(*_args, **_kwargs):
            refresh_started.set()
            self.assertTrue(release_refresh.wait(timeout=2))
            return {}

        with patch.object(vpngate_manager, "publicvpnlist_is_enabled", return_value=True), patch.object(
            vpngate_manager,
            "publicvpnlist_source",
            return_value=("api", "https://publicvpnlist.com/api/v1/servers"),
        ), patch.object(vpngate_manager, "load_publicvpnlist_cache", return_value={}), patch.object(
            vpngate_manager, "refresh_publicvpnlist_cache", side_effect=refresh_fixture
        ), patch.object(
            vpngate_manager, "restore_cached_publicvpnlist_nodes", return_value=3
        ) as restore, patch.object(vpngate_manager, "log_to_json"):
            self.assertTrue(vpngate_manager.schedule_publicvpnlist_api_refresh(target_countries=["PH"]))
            self.assertTrue(refresh_started.wait(timeout=2))
            refresh_thread = vpngate_manager.publicvpnlist_api_refresh_thread
            self.assertIsInstance(refresh_thread, threading.Thread)
            release_refresh.set()
            refresh_thread.join(timeout=2)
            self.assertFalse(refresh_thread.is_alive())

        restore.assert_called_once_with()

    def test_live_flow_defaults_cover_two_rounds_for_all_fixed_countries(self):
        import vpngate_manager

        self.assertEqual(vpngate_manager.PUBLICVPNLIST_LIVE_FLOW_ATTEMPTS_PER_COUNTRY, 2)
        self.assertEqual(vpngate_manager.PUBLICVPNLIST_LIVE_FLOW_MAX_ATTEMPTS, 20)
        self.assertEqual(vpngate_manager.PUBLICVPNLIST_LIVE_FLOW_MAX_SECONDS, 180.0)
        self.assertEqual(vpngate_manager.PUBLICVPNLIST_LIVE_FLOW_MAX_FAILURES, 9)
        self.assertEqual(len(vpngate_manager.PUBLICVPNLIST_ALLOWED_COUNTRY_ORDER), 10)
        self.assertLessEqual(vpngate_manager.PUBLICVPNLIST_API_MAX_REQUESTS_PER_REFRESH, 30)

    def test_ph_missing_metadata_is_optional_degradation(self):
        smoke = load_smoke_module()
        countries = list(smoke.FIXED_COUNTRY_ORDER)
        report = {
            "countries": countries,
            "profiles_downloaded": 9,
            "profiles_validated": 9,
            "connectable_candidates": 9,
            "metadata_records_by_country": {
                country: 0 if country == "PH" else 1
                for country in countries
            },
            "eligible_candidates_by_country": {
                country: 0 if country == "PH" else 1
                for country in countries
            },
            "attempts_by_country": {
                country: 0 if country == "PH" else 1
                for country in countries
            },
            "validated_by_country": {
                country: 0 if country == "PH" else 1
                for country in countries
            },
            "skipped_by_country": {country: {} for country in countries},
            "failed_candidates_by_country": {country: {} for country in countries},
            "optional_country_errors": {"PH": {}},
            "openvpn": "not_started",
        }

        coverage = smoke.evaluate_live_coverage(report)

        self.assertEqual(coverage["coverage_errors"], [])
        self.assertNotIn("PH", coverage["metadata_missing"])
        self.assertEqual(coverage["required_validated_country_count"], 9)
        self.assertEqual(
            coverage["optional_degraded_countries"]["PH"]["reason"],
            "metadata_missing",
        )

    def test_ph_endpoint_failure_is_optional_degradation(self):
        smoke = load_smoke_module()
        countries = list(smoke.FIXED_COUNTRY_ORDER)
        report = {
            "countries": countries,
            "profiles_downloaded": 9,
            "profiles_validated": 9,
            "connectable_candidates": 9,
            "metadata_records_by_country": {
                country: 0 if country == "PH" else 1
                for country in countries
            },
            "eligible_candidates_by_country": {
                country: 0 if country == "PH" else 1
                for country in countries
            },
            "attempts_by_country": {
                country: 0 if country == "PH" else 1
                for country in countries
            },
            "validated_by_country": {
                country: 0 if country == "PH" else 1
                for country in countries
            },
            "skipped_by_country": {country: {} for country in countries},
            "failed_candidates_by_country": {country: {} for country in countries},
            "optional_country_errors": {"PH": {"network_error": 1}},
            "openvpn": "not_started",
        }

        coverage = smoke.evaluate_live_coverage(report)

        self.assertEqual(coverage["coverage_errors"], [])
        self.assertEqual(
            coverage["optional_degraded_countries"]["PH"]["reason"],
            "api_endpoint_error:network_error",
        )

    def test_smoke_selection_caps_two_candidates_per_country(self):
        import vpngate_manager

        smoke = load_smoke_module()
        records = []
        for country in ("PH", "FR"):
            for index in range(3):
                records.append(
                    {
                        "id": f"{country.lower()}-{index}",
                        "country_code": country,
                        "hostname": f"{country.lower()}-{index}.fixture.invalid",
                        "ip": f"198.51.100.{20 + index + (0 if country == 'PH' else 10)}",
                        "protocol": "openvpn",
                        "transport": "tcp",
                        "port": 443,
                        "technical_quality_score": 100 - index,
                    }
                )

        selected = smoke._select_records(vpngate_manager, records, ["PH", "FR"], 20)
        selected_counts = {}
        for raw in selected:
            country = vpngate_manager.normalize_publicvpnlist_row(raw)["country_short"]
            selected_counts[country] = selected_counts.get(country, 0) + 1

        self.assertEqual(selected_counts, {"PH": 2, "FR": 2})

    def test_smoke_selection_is_two_interleaved_rounds_not_three(self):
        import vpngate_manager

        smoke = load_smoke_module()
        records = []
        for country in ("PH", "FR"):
            for index in range(3):
                records.append(
                    {
                        "id": f"{country.lower()}-{index}",
                        "country_code": country,
                        "hostname": f"{country.lower()}-{index}.fixture.invalid",
                        "ip": f"198.51.100.{40 + index + (0 if country == 'PH' else 10)}",
                        "protocol": "openvpn",
                        "transport": "tcp",
                        "port": 443,
                        "technical_quality_score": 100 - index,
                        "web_download_id": str(112000 + index),
                    }
                )

        selected = smoke._select_records(vpngate_manager, records, ["PH", "FR"], 20)

        self.assertEqual(
            [row["id"] for row in selected],
            ["ph-0", "fr-0", "ph-1", "fr-1"],
        )

    def test_smoke_filters_us_before_live_flow_and_preserves_safety_reason(self):
        import vpngate_manager

        smoke = load_smoke_module()
        records = [
            {
                "id": "us-hosting",
                "country_code": "US",
                "hostname": "us-hosting.fixture.invalid",
                "ip": "198.51.100.51",
                "protocol": "openvpn",
                "transport": "tcp",
                "port": 443,
                "web_download_id": "112051",
            },
            {
                "id": "us-residential",
                "country_code": "US",
                "hostname": "us-residential.fixture.invalid",
                "ip": "198.51.100.52",
                "protocol": "openvpn",
                "transport": "tcp",
                "port": 443,
                "web_download_id": "112052",
            },
            {
                "id": "ph-usable",
                "country_code": "PH",
                "hostname": "ph-usable.fixture.invalid",
                "ip": "198.51.100.53",
                "protocol": "openvpn",
                "transport": "tcp",
                "port": 443,
                "web_download_id": "112053",
            },
        ]
        report = {
            "eligible_candidates_by_country": {"US": 0, "PH": 0},
            "skipped_by_country": {"US": {}, "PH": {}},
            "us_classification_attempted": 0,
            "us_residential_accepted": 0,
            "us_nonresidential_rejected": 0,
            "us_unclassified_rejected": 0,
            "attempts_by_country": {"US": 0, "PH": 0},
            "failed_candidates_by_country": {"US": {}, "PH": {}},
            "available_countries": [],
        }
        classifications = {
            "us-hosting": {"ip_type": "hosting", "risk_sources": ["ipinfo"]},
            "us-residential": {"ip_type": "residential", "risk_sources": ["ipinfo"]},
        }
        with patch.object(
            vpngate_manager,
            "load_publicvpnlist_api_cache",
            return_value={},
        ), patch.object(
            vpngate_manager,
            "publicvpnlist_enrich_us_rows",
            return_value=(classifications, False),
        ):
            selected = smoke._prepare_candidates(
                vpngate_manager,
                records,
                ["US", "PH"],
                20,
                report,
            )

        self.assertEqual(
            {row["id"] for row in selected},
            {"us-residential", "ph-usable"},
        )
        self.assertEqual(report["us_classification_attempted"], 2)
        self.assertEqual(report["us_nonresidential_rejected"], 1)
        self.assertEqual(report["skipped_by_country"]["US"]["us_nonresidential"], 1)

    def test_smoke_classifies_metadata_without_verified_mapping(self):
        smoke = load_smoke_module()
        records = [{"id": "pvl_" + "a" * 24}]
        self.assertEqual(smoke.classify_api_result(records, []), "mapping_missing")

    def test_smoke_classifies_blocked_runner_without_false_success(self):
        smoke = load_smoke_module()
        errors = [{"category": "github_runner_blocked", "status": 403, "type": "HTTPError"}]
        self.assertEqual(smoke.classify_api_result([], [], errors), "github_runner_blocked")

    def test_detail_enrichment_uses_documented_api_id_only(self):
        import vpngate_manager

        records = [{
            "id": "pvl_" + "b" * 24,
            "country_code": "PH",
            "hostname": "vpn.example",
            "port": 443,
            "protocol": "openvpn",
            "transport": "tcp",
        }]
        with patch.object(vpngate_manager, "publicvpnlist_download_host_addresses", return_value=("93.184.216.34",)), \
             patch.object(
                 vpngate_manager,
                 "publicvpnlist_http_get",
                 return_value=json.dumps({"data": {}}).encode("utf-8"),
             ) as http_get:
            metadata = {"request_count": 0}
            enriched = vpngate_manager.publicvpnlist_api_enrich_records_for_download(
                records,
                metadata,
            )
        self.assertEqual(len(enriched), 1)
        self.assertEqual(metadata["detail_requests"], 1)
        called_url = http_get.call_args.args[0]
        self.assertIn("/servers/pvl_", called_url)
        self.assertNotIn("test_server.php", called_url)
        self.assertNotIn("get_token.php", called_url)


if __name__ == "__main__":
    unittest.main()
