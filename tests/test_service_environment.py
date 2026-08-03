import unittest
from pathlib import Path


class ServiceEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.install_text = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")

    def test_unified_environment_file_is_created_with_restricted_permissions(self):
        self.assertIn('EIANUN_ENV_FILE="/etc/eianun-vpngate.env"', self.install_text)
        self.assertIn('LEGACY_ENV_FILE="/etc/default/eianun-vpngate"', self.install_text)
        self.assertIn('chmod 600 "${EIANUN_ENV_FILE}"', self.install_text)
        self.assertIn('chown root:root "${EIANUN_ENV_FILE}"', self.install_text)
        self.assertIn('cp -p "${LEGACY_ENV_FILE}" "${EIANUN_ENV_FILE}"', self.install_text)

    def test_all_service_managers_load_and_export_both_environment_files(self):
        self.assertIn("EnvironmentFile=-/etc/default/eianun-vpngate", self.install_text)
        self.assertIn("EnvironmentFile=-/etc/eianun-vpngate.env", self.install_text)
        self.assertGreaterEqual(self.install_text.count(". /etc/default/eianun-vpngate"), 2)
        self.assertGreaterEqual(self.install_text.count(". /etc/eianun-vpngate.env"), 2)
        self.assertGreaterEqual(self.install_text.count("set -a"), 2)
        self.assertGreaterEqual(self.install_text.count("set +a"), 2)

    def test_en_publicvpnlist_commands_and_redacted_status_are_present(self):
        self.assertIn('elif cmd == "publicvpnlist":', self.install_text)
        self.assertIn("def publicvpnlist_command(args):", self.install_text)
        self.assertIn('action == "set-url"', self.install_text)
        self.assertIn('action == "set-file"', self.install_text)
        self.assertIn('action == "set-hosts"', self.install_text)
        self.assertIn('action == "clear"', self.install_text)
        self.assertIn('action == "restart"', self.install_text)
        self.assertIn("def redacted_snapshot_url(value):", self.install_text)
        self.assertIn("getpass.getpass", self.install_text)
        self.assertIn("需快照+下载域名", self.install_text)

    def test_service_execstart_does_not_include_snapshot_environment_values(self):
        exec_lines = [line for line in self.install_text.splitlines() if "ExecStart=" in line]
        self.assertTrue(exec_lines)
        self.assertTrue(all("PUBLICVPNLIST_SNAPSHOT_URL" not in line for line in exec_lines))


if __name__ == "__main__":
    unittest.main()
