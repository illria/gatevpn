import time
import unittest
from pathlib import Path
from unittest import mock

from tools.publicvpnlist_cache import cache_profile_summary, profile_is_usable, resolve_vpngate_data_dir


VALID_CONFIG = """client
dev tun
proto tcp
remote fixture.example 443
<ca>
-----BEGIN CERTIFICATE-----
FIXTURE
-----END CERTIFICATE-----
</ca>
"""


class PublicVPNListCachePredicateTests(unittest.TestCase):
    def profile(self, **updates):
        profile = {
            "country_short": "PH",
            "config_text": VALID_CONFIG,
            "last_seen_at": 1_000.0,
            "config_validated_at": 1_000.0,
        }
        profile.update(updates)
        return profile

    def test_fresh_legal_profile_is_usable(self):
        self.assertTrue(profile_is_usable(self.profile(), now=1_100.0, stale_seconds=604_800))
        self.assertEqual(
            cache_profile_summary({"profiles": {"one": self.profile()}}, now=1_100.0, stale_seconds=604_800),
            (1, 1),
        )

    def test_disallowed_country_is_not_usable(self):
        self.assertFalse(profile_is_usable(self.profile(country_short="JP"), now=1_100.0))

    def test_non_openvpn_empty_and_missing_time_profiles_are_not_usable(self):
        for profile in (
            self.profile(config_text="not an OpenVPN profile"),
            self.profile(config_text=""),
            self.profile(last_seen_at=None, config_validated_at=None),
        ):
            with self.subTest(profile=profile):
                self.assertFalse(profile_is_usable(profile, now=1_100.0))

    def test_expiry_and_custom_stale_ttl_are_shared(self):
        profile = self.profile(last_seen_at=1_000.0, config_validated_at=1_000.0)
        self.assertFalse(profile_is_usable(profile, now=1_101.0, stale_seconds=100))
        self.assertTrue(profile_is_usable(profile, now=1_101.0, stale_seconds=200))

    def test_data_directory_resolution_is_consistent_for_default_relative_and_absolute(self):
        install_dir = Path("/opt/eianun-vpngate")
        self.assertEqual(resolve_vpngate_data_dir("", install_dir), install_dir / "vpngate_data")
        self.assertEqual(
            resolve_vpngate_data_dir("relative/data", install_dir),
            install_dir / "relative/data",
        )
        self.assertEqual(
            resolve_vpngate_data_dir("/var/lib/gatevpn", install_dir),
            Path("/var/lib/gatevpn"),
        )
        self.assertEqual(
            resolve_vpngate_data_dir("~/gatevpn", install_dir),
            Path.home() / "gatevpn",
        )

    def test_manager_and_shared_predicate_use_the_same_fixture(self):
        import vpngate_manager

        now = time.time()
        profile = self.profile(last_seen_at=now, config_validated_at=now)
        cache = {"profiles": {"one": profile}}
        with mock.patch.object(vpngate_manager, "PUBLICVPNLIST_STALE_PROFILE_SECONDS", 604_800):
            self.assertEqual(
                vpngate_manager.publicvpnlist_cache_has_usable_profiles(cache, now=now),
                cache_profile_summary(cache, now=now, stale_seconds=604_800)[1] == 1,
            )


if __name__ == "__main__":
    unittest.main()
