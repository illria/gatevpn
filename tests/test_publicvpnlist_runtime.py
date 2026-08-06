import importlib.util
import json
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
    def test_live_flow_defaults_cover_two_rounds_for_all_fixed_countries(self):
        import vpngate_manager

        self.assertEqual(vpngate_manager.PUBLICVPNLIST_LIVE_FLOW_ATTEMPTS_PER_COUNTRY, 2)
        self.assertEqual(vpngate_manager.PUBLICVPNLIST_LIVE_FLOW_MAX_ATTEMPTS, 20)
        self.assertEqual(vpngate_manager.PUBLICVPNLIST_LIVE_FLOW_MAX_SECONDS, 180.0)
        self.assertEqual(vpngate_manager.PUBLICVPNLIST_LIVE_FLOW_MAX_FAILURES, 9)
        self.assertEqual(len(vpngate_manager.PUBLICVPNLIST_ALLOWED_COUNTRY_ORDER), 10)
        self.assertLessEqual(vpngate_manager.PUBLICVPNLIST_API_MAX_REQUESTS_PER_REFRESH, 30)

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
