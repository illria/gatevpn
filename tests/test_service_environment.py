import contextlib
import importlib.util
import io
import json
import py_compile
import stat
import subprocess
import sys
import unittest
from pathlib import Path
import tempfile
from unittest import mock


class ServiceEnvironmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.install_text = (cls.repo_root / "install.sh").read_text(encoding="utf-8")
        cls.helper_path = cls.repo_root / "tools" / "repair_gatevpn_permissions.py"
        spec = importlib.util.spec_from_file_location("repair_gatevpn_permissions_test_module", cls.helper_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load permission repair helper")
        cls.permission_helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.permission_helper)

    def test_unified_environment_file_is_created_with_restricted_permissions(self):
        self.assertIn('EIANUN_ENV_FILE="/etc/eianun-vpngate.env"', self.install_text)
        self.assertIn('LEGACY_ENV_FILE="/etc/default/eianun-vpngate"', self.install_text)
        self.assertIn('chmod 600 "${EIANUN_ENV_FILE}"', self.install_text)
        self.assertIn('chown root:root "${EIANUN_ENV_FILE}"', self.install_text)
        self.assertIn('cp -p "${LEGACY_ENV_FILE}" "${EIANUN_ENV_FILE}"', self.install_text)

    def test_upgrade_repairs_sensitive_runtime_permissions(self):
        self.assertIn("repair_sensitive_runtime_files()", self.install_text)
        self.assertIn('"${INSTALL_DIR}/tools/repair_gatevpn_permissions.py"', self.install_text)
        self.assertIn('--env-file "${EIANUN_ENV_FILE}"', self.install_text)
        self.assertIn('--legacy-env-file "${LEGACY_ENV_FILE}"', self.install_text)

    def test_upgrade_permission_repair_uses_custom_data_directory_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            install_dir = root / "install"
            default_data = install_dir / "vpngate_data"
            custom_data = root / "custom-data"
            for data_dir in (default_data, custom_data):
                config_dir = data_dir / "configs"
                config_dir.mkdir(parents=True, mode=0o755)
                for filename in ("nodes.json", "publicvpnlist_cache.json", "vpngate_auth.txt", "ui_auth.json"):
                    path = data_dir / filename
                    path.write_text("fixture\n", encoding="utf-8")
                    path.chmod(0o644)
                for filename in ("one.ovpn", "one.auth"):
                    path = config_dir / filename
                    path.write_text("fixture\n", encoding="utf-8")
                    path.chmod(0o644)
                config_dir.chmod(0o755)

            env_file = root / "eianun-vpngate.env"
            legacy_env_file = root / "legacy.env"
            legacy_env_file.write_text(f"VPNGATE_DATA_DIR={default_data}\n", encoding="utf-8")
            env_file.write_text(f"VPNGATE_DATA_DIR={custom_data}\n", encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(self.helper_path),
                    "--install-dir",
                    str(install_dir),
                    "--env-file",
                    str(env_file),
                    "--legacy-env-file",
                    str(legacy_env_file),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(completed.stderr, "")
            self.assertEqual(stat.S_IMODE((custom_data / "configs").stat().st_mode), 0o700)
            for filename in ("nodes.json", "publicvpnlist_cache.json", "vpngate_auth.txt", "ui_auth.json"):
                self.assertEqual(stat.S_IMODE((custom_data / filename).stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE((default_data / filename).stat().st_mode), 0o644)
            for filename in ("one.ovpn", "one.auth"):
                self.assertEqual(stat.S_IMODE((custom_data / "configs" / filename).stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE((default_data / "configs" / filename).stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE((default_data / "configs").stat().st_mode), 0o755)

    def test_upgrade_permission_repair_falls_back_to_default_data_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            install_dir = root / "install"
            data_dir = install_dir / "vpngate_data"
            config_dir = data_dir / "configs"
            config_dir.mkdir(parents=True, mode=0o755)
            nodes_file = data_dir / "nodes.json"
            ovpn_file = config_dir / "default.ovpn"
            nodes_file.write_text("[]\n", encoding="utf-8")
            ovpn_file.write_text("client\n", encoding="utf-8")
            nodes_file.chmod(0o644)
            ovpn_file.chmod(0o644)
            config_dir.chmod(0o755)

            repaired = self.permission_helper.repair_runtime_permissions(
                install_dir,
                root / "missing.env",
                root / "missing-legacy.env",
            )

            self.assertTrue(repaired)
            self.assertEqual(stat.S_IMODE(config_dir.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(nodes_file.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(ovpn_file.stat().st_mode), 0o600)

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
        self.assertIn("默认使用 PublicVPNList 官方 API v1", self.install_text)
        self.assertIn("live_flow_mapping_missing", self.install_text)
        self.assertIn("profile_validation_failed", self.install_text)

    def test_service_execstart_does_not_include_snapshot_environment_values(self):
        exec_lines = [line for line in self.install_text.splitlines() if "ExecStart=" in line]
        self.assertTrue(exec_lines)
        self.assertTrue(all("PUBLICVPNLIST_SNAPSHOT_URL" not in line for line in exec_lines))

    def test_generated_en_heredoc_compiles_and_runs_without_system_paths(self):
        marker = "cat > /usr/bin/en <<'EOF'\n"
        start = self.install_text.index(marker) + len(marker)
        end = self.install_text.index("\nEOF\n", start)
        source = self.install_text[start:end]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_path = root / "generated-en.py"
            source_path.write_text(source, encoding="utf-8")
            py_compile.compile(str(source_path), doraise=True)
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

            old_contents = "KEEP_SETTING=unchanged\nPUBLICVPNLIST_SNAPSHOT_URL=https://old.example/old.json\n"
            env_file.write_text(old_contents, encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
                namespace["os"], "replace", side_effect=OSError("replace failed")
            ):
                self.assertFalse(
                    namespace["save_publicvpnlist_environment"](
                        {"PUBLICVPNLIST_SNAPSHOT_URL": "https://new.example/new.json"}
                    )
                )
            self.assertEqual(env_file.read_text(encoding="utf-8"), old_contents)

    def test_generated_en_and_manager_share_cache_state_for_same_fixture(self):
        marker = "cat > /usr/bin/en <<'EOF'\n"
        start = self.install_text.index(marker) + len(marker)
        end = self.install_text.index("\nEOF\n", start)
        source = self.install_text[start:end]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            data_dir = root / "custom-data"
            data_dir.mkdir()
            cache_path = data_dir / "publicvpnlist_cache.json"
            cache_path.write_text(
                json.dumps(
                    {
                        "profiles": {
                            "ph": {
                                "country_short": "PH",
                                "config_text": "client\ndev tun\nproto tcp\nremote fixture.example 443\n<ca>\nCERT\n</ca>\n",
                                "last_seen_at": 2_000_000_000,
                                "config_validated_at": 2_000_000_000,
                            }
                        },
                        "last_refresh_stats": {
                            "live_flow_mapping_missing": 3,
                            "profile_validation_failed": 2,
                            "live_flow_deadline_exceeded": True,
                        },
                    }
                ),
                encoding="utf-8",
            )
            namespace = {"__name__": "generated_en_ci"}
            exec(compile(source, "install.sh:generated-en", "exec"), namespace)
            values = {
                "VPNGATE_DATA_DIR": str(data_dir),
                "PUBLICVPNLIST_ENABLED": "1",
                "PUBLICVPNLIST_STALE_PROFILE_SECONDS": "604800",
                "PUBLICVPNLIST_API_URL": "",
                "PUBLICVPNLIST_SNAPSHOT_URL": "",
                "PUBLICVPNLIST_SNAPSHOT_FILE": "",
                "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS": "",
            }
            generated_state = namespace["publicvpnlist_state"](values)
            self.assertEqual(generated_state["live_flow_mapping_missing"], 3)
            self.assertEqual(generated_state["profile_validation_failed"], 2)
            self.assertTrue(generated_state["live_flow_deadline_exceeded"])

            import vpngate_manager

            with mock.patch.object(vpngate_manager, "DATA_DIR", data_dir), mock.patch.object(
                vpngate_manager, "PUBLICVPNLIST_CACHE_FILE", cache_path
            ), mock.patch.object(vpngate_manager, "PUBLICVPNLIST_ENABLED", True), mock.patch.object(
                vpngate_manager, "PUBLICVPNLIST_API_URL", ""
            ), mock.patch.object(
                vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_URL", ""
            ), mock.patch.object(
                vpngate_manager, "PUBLICVPNLIST_SNAPSHOT_FILE", ""
            ), mock.patch.object(vpngate_manager, "PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS", frozenset()), mock.patch.object(
                vpngate_manager, "PUBLICVPNLIST_STALE_PROFILE_SECONDS", 604800
            ):
                manager_state = vpngate_manager.publicvpnlist_web_status()
            self.assertEqual(generated_state["status"], manager_state["status"])
            self.assertEqual(generated_state["effective_source_active"], manager_state["effective_source_active"])
            self.assertEqual(generated_state["refresh_ready"], manager_state["refresh_ready"])
            self.assertEqual(generated_state["cache_only"], manager_state["cache_only"])

    def test_generated_en_source_selection_does_not_disable_default_publicvpnlist(self):
        marker = "cat > /usr/bin/en <<'EOF'\n"
        start = self.install_text.index(marker) + len(marker)
        end = self.install_text.index("\nEOF\n", start)
        source = self.install_text[start:end]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            namespace = {"__name__": "generated_en_ci"}
            exec(compile(source, "install.sh:generated-en", "exec"), namespace)
            namespace["ENV_FILE"] = str(root / "eianun-vpngate.env")
            namespace["LEGACY_ENV_FILE"] = str(root / "legacy.env")
            namespace["INSTALL_DIR"] = str(root / "install")
            namespace["load_ui_cfg"] = lambda: {}
            namespace["publicvpnlist_status_label"] = lambda: "PublicVPNList（API）"
            namespace["ask_restart"] = lambda: None
            saved_configs = []
            namespace["save_ui_cfg"] = lambda cfg: saved_configs.append(dict(cfg)) or True
            original_env_writer = namespace["save_publicvpnlist_environment"]

            for key, expected_enabled, expected_sources in (
                ("1", "1", "vpngate,vpnbook,ipspeed,vpngate_scraper,publicvpnlist"),
                ("2", "1", "vpngate,vpnbook,ipspeed,vpngate_scraper"),
            ):
                namespace["getch"] = lambda key=key: key
                with contextlib.redirect_stdout(io.StringIO()):
                    namespace["configure_source"]()
                saved = namespace["read_env_file"](namespace["ENV_FILE"])
                self.assertEqual(saved.get("PUBLICVPNLIST_ENABLED"), expected_enabled)
                self.assertEqual(saved_configs[-1]["node_sources"], expected_sources)

            namespace["getch"] = lambda: "1"
            namespace["save_publicvpnlist_environment"] = lambda _updates: False
            before = len(saved_configs)
            with contextlib.redirect_stdout(io.StringIO()):
                namespace["configure_source"]()
            self.assertEqual(len(saved_configs), before)

            namespace["save_publicvpnlist_environment"] = original_env_writer
            namespace["save_ui_cfg"] = lambda _cfg: False
            namespace["getch"] = lambda: "1"
            with contextlib.redirect_stdout(io.StringIO()):
                namespace["configure_source"]()
            rolled_back = namespace["read_env_file"](namespace["ENV_FILE"])
            self.assertEqual(rolled_back.get("PUBLICVPNLIST_ENABLED"), "1")

    def test_generated_en_explicit_disable_writes_persistent_marker(self):
        marker = "cat > /usr/bin/en <<'EOF'\n"
        start = self.install_text.index(marker) + len(marker)
        end = self.install_text.index("\nEOF\n", start)
        source = self.install_text[start:end]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            namespace = {"__name__": "generated_en_ci"}
            exec(compile(source, "install.sh:generated-en", "exec"), namespace)
            namespace["ENV_FILE"] = str(root / "eianun-vpngate.env")
            namespace["LEGACY_ENV_FILE"] = str(root / "legacy.env")
            with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(
                namespace["subprocess"], "run"
            ), mock.patch.object(namespace["time"], "sleep"):
                namespace["save_publicvpnlist_environment"](
                    {"PUBLICVPNLIST_ENABLED": "0"}
                )
            saved = namespace["read_env_file"](namespace["ENV_FILE"])
            self.assertEqual(saved.get("PUBLICVPNLIST_ENABLED"), "0")
            self.assertEqual(saved.get("PUBLICVPNLIST_USER_DISABLED"), "1")

    def test_generated_en_legacy_zero_uses_api_but_explicit_marker_disables_it(self):
        marker = "cat > /usr/bin/en <<'EOF'\n"
        start = self.install_text.index(marker) + len(marker)
        end = self.install_text.index("\nEOF\n", start)
        source = self.install_text[start:end]
        namespace = {"__name__": "generated_en_ci"}
        exec(compile(source, "install.sh:generated-en", "exec"), namespace)
        base = {
            "PUBLICVPNLIST_ENABLED": "0",
            "PUBLICVPNLIST_USER_DISABLED": "0",
            "PUBLICVPNLIST_API_URL": "https://publicvpnlist.com/api/v1/servers",
        }
        legacy_state = namespace["publicvpnlist_state"](base)
        self.assertEqual(legacy_state["mode"], "api")
        self.assertTrue(legacy_state["effective_source_active"])

        explicit_state = namespace["publicvpnlist_state"](
            {**base, "PUBLICVPNLIST_USER_DISABLED": "1"}
        )
        self.assertEqual(explicit_state["mode"], "disabled")
        self.assertFalse(explicit_state["effective_source_active"])


if __name__ == "__main__":
    unittest.main()
