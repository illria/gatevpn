import contextlib
import importlib.util
import io
import os
import unittest
from pathlib import Path
from unittest import mock

import vpngate_manager


OPENVPN_CONFIG = """client
dev tun
proto tcp
remote 198.51.100.80 443
nobind
<ca>
-----BEGIN CERTIFICATE-----
FIXTURE
-----END CERTIFICATE-----
</ca>
"""


def load_smoke_module():
    path = Path(__file__).resolve().parents[1] / "tools" / "publicvpnlist-smoke.py"
    spec = importlib.util.spec_from_file_location("publicvpnlist_smoke_test_module", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class PublicVPNListSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke = load_smoke_module()

    @staticmethod
    def row():
        return {
            "id": "smoke-ph",
            "country": "PH",
            "countryName": "Philippines",
            "host": "198.51.100.80",
            "ip": "198.51.100.80",
            "port": 443,
            "proto": "tcp",
            "temporary_ovpn_url": "https://downloads.example/profile.ovpn?signature=do-not-print",
        }

    def snapshot_patches(self, allowed_hosts):
        return mock.patch.multiple(
            vpngate_manager,
            PUBLICVPNLIST_SNAPSHOT_URL="https://snapshot.example/export.json?signature=secret",
            PUBLICVPNLIST_SNAPSHOT_FILE="",
            PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS=frozenset(allowed_hosts),
            fetch_publicvpnlist_snapshot=mock.Mock(return_value={"data": [self.row()]}),
            publicvpnlist_payload_records=mock.Mock(return_value=[self.row()]),
            normalize_publicvpnlist_row=mock.Mock(side_effect=vpngate_manager.normalize_publicvpnlist_row),
        )

    def test_discovery_phase_outputs_hostname_without_requesting_config(self):
        with self.snapshot_patches([]), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_validate_download_url",
            return_value="downloads.example",
        ), mock.patch.object(vpngate_manager, "fetch_publicvpnlist_config") as config_builder, mock.patch.dict(
            os.environ,
            {"PUBLICVPNLIST_SNAPSHOT_URL": "https://snapshot.example/export.json?signature=secret"},
            clear=False,
        ), contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            result = self.smoke.main()
        output = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(result, 2)
        self.assertIn("downloads.example", output)
        self.assertIn("未请求配置", output)
        self.assertIn("PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS", output)
        self.assertNotIn("signature=secret", output)
        self.assertNotIn("https://downloads.example/profile.ovpn", output)
        config_builder.assert_not_called()

    def test_validation_phase_strips_signed_url_and_reports_safe_metadata(self):
        def config_fetch(_url, metadata=None):
            metadata.update({"redirect_count": 1, "final_download_host": "cdn.example"})
            return OPENVPN_CONFIG

        with self.snapshot_patches(["downloads.example"]), mock.patch.object(
            vpngate_manager,
            "publicvpnlist_validate_download_url",
            return_value="downloads.example",
        ), mock.patch.object(vpngate_manager, "fetch_publicvpnlist_config", side_effect=config_fetch) as config_builder, mock.patch.dict(
            os.environ,
            {
                "PUBLICVPNLIST_SNAPSHOT_URL": "https://snapshot.example/export.json?signature=secret",
                "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS": "downloads.example",
            },
            clear=False,
        ), contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
            result = self.smoke.main()
        output = stdout.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("country=PH", output)
        self.assertIn("remote=198.51.100.80:443", output)
        self.assertIn("proto=tcp", output)
        self.assertIn("redirects=1", output)
        self.assertIn("final_download_host=cdn.example", output)
        self.assertNotIn("signature=secret", output)
        self.assertNotIn("temporary_ovpn_url", output)
        config_builder.assert_called_once()


if __name__ == "__main__":
    unittest.main()
