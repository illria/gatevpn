import contextlib
import io
import unittest
from pathlib import Path
import tempfile


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

    def test_upgrade_repairs_sensitive_runtime_permissions(self):
        self.assertIn("repair_sensitive_runtime_files()", self.install_text)
        self.assertIn('chmod 700 "${CONFIG_PATH}"', self.install_text)
        self.assertIn('"${DATA_PATH}/publicvpnlist_cache.json"', self.install_text)
        self.assertIn('"${DATA_PATH}/nodes.json"', self.install_text)
        self.assertIn("-name '*.ovpn' -o -name '*.auth'", self.install_text)
        self.assertIn('"${DATA_PATH}/vpngate_auth.txt"', self.install_text)

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

    def test_generated_en_heredoc_compiles_and_runs_without_system_paths(self):
        marker = "cat > /usr/bin/en <<'EOF'\n"
        start = self.install_text.index(marker) + len(marker)
        end = self.install_text.index("\nEOF\n", start)
        source = self.install_text[start:end]
        compile(source, "install.sh:generated-en", "exec")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            env_file = root / "eianun-vpngate.env"
            legacy_env_file = root / "legacy.env"
            install_dir = root / "install"
            legacy_env_file.write_text(
                "PUBLICVPNLIST_SNAPSHOT_URL='https://fixture.invalid/export.json?token=secret'\n",
                encoding="utf-8",
            )
            namespace = {"__name__": "generated_en_ci"}
            exec(compile(source, "install.sh:generated-en", "exec"), namespace)
            namespace["ENV_FILE"] = str(env_file)
            namespace["LEGACY_ENV_FILE"] = str(legacy_env_file)
            namespace["INSTALL_DIR"] = str(install_dir)

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                namespace["publicvpnlist_command"](["status"])
            self.assertNotIn("token=secret", output.getvalue())
            self.assertNotIn("?token", output.getvalue())

            namespace["publicvpnlist_command"](["set-file", str(root / "snapshot.json")])
            namespace["publicvpnlist_command"](["set-hosts", "downloads.example"])
            saved = env_file.read_text(encoding="utf-8")
            self.assertIn("PUBLICVPNLIST_SNAPSHOT_FILE=", saved)
            self.assertIn("PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS=downloads.example", saved)
            self.assertNotIn("token=secret", saved)

            namespace["publicvpnlist_command"](["clear"])
            cleared = namespace["read_env_file"](str(env_file))
            self.assertEqual(cleared.get("PUBLICVPNLIST_SNAPSHOT_URL"), "")
            self.assertEqual(cleared.get("PUBLICVPNLIST_SNAPSHOT_FILE"), "")
            self.assertEqual(cleared.get("PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS"), "")


if __name__ == "__main__":
    unittest.main()
