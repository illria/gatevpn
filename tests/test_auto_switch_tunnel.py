import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import proxy_server
import vpngate_manager


class AutoSwitchTunnelTests(unittest.TestCase):
    def test_single_tunnel_is_the_default_and_ui_exposes_both_modes(self):
        self.assertEqual(vpngate_manager.AUTO_SWITCH_TUNNEL_MODE, "single")
        self.assertEqual(vpngate_manager.AUTO_FAILOVER_TUNNEL_MODE, "single")
        self.assertEqual(vpngate_manager.PROXY_FAIL_AUTO_SWITCH_THRESHOLD, 3)
        self.assertEqual(vpngate_manager.PROXY_FAIL_GRACE_SECONDS, 30)
        self.assertEqual(vpngate_manager.PROXY_HEALTH_CHECK_INTERVAL_SECONDS, 10)
        page = Path(vpngate_manager.__file__).read_text(encoding="utf-8")
        self.assertIn('id="settings_auto_switch_tunnel_mode"', page)
        self.assertIn('value="single">单通道：停旧启新', page)
        self.assertIn('value="dual">双通道：验证新节点后切换', page)
        self.assertIn('id="settings_auto_failover_tunnel_mode"', page)
        self.assertIn('value="dual">双通道：验证备用后切换', page)

    def test_ui_mode_accepts_only_single_or_dual(self):
        with mock.patch.object(vpngate_manager, "load_ui_config", return_value={"auto_switch_tunnel_mode": "dual"}):
            self.assertEqual(vpngate_manager.get_auto_switch_tunnel_mode(), "dual")
        with mock.patch.object(vpngate_manager, "load_ui_config", return_value={"auto_switch_tunnel_mode": "invalid"}):
            self.assertEqual(vpngate_manager.get_auto_switch_tunnel_mode(), "single")
        with mock.patch.object(vpngate_manager, "load_ui_config", return_value={"auto_failover_tunnel_mode": "dual"}):
            self.assertEqual(vpngate_manager.get_auto_failover_tunnel_mode(), "dual")
        with mock.patch.object(vpngate_manager, "load_ui_config", return_value={"auto_failover_tunnel_mode": "invalid"}):
            self.assertEqual(vpngate_manager.get_auto_failover_tunnel_mode(), "single")

    def test_failure_failover_dual_mode_tries_backup_before_single_fallback(self):
        old_process = mock.Mock()
        old_process.poll.return_value = None
        nodes = [
            {
                "id": "old",
                "probe_status": "available",
                "active": True,
                "country_short": "US",
                "ip_type": "residential",
            },
            {
                "id": "backup",
                "probe_status": "available",
                "active": False,
                "country_short": "US",
                "ip_type": "residential",
                "risk_level": "clean",
                "risk_sources": ["fixture"],
                "blacklist_count": 0,
            },
        ]
        original_state = (
            vpngate_manager.active_openvpn_process,
            vpngate_manager.active_openvpn_node_id,
            vpngate_manager.is_connecting,
        )
        vpngate_manager.active_openvpn_process = old_process
        vpngate_manager.active_openvpn_node_id = "old"
        vpngate_manager.is_connecting = False
        try:
            def read_json_for_test(path, default=None):
                if path == vpngate_manager.NODES_FILE:
                    return nodes
                return {}

            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(vpngate_manager, "read_json", side_effect=read_json_for_test))
                stack.enter_context(mock.patch.object(vpngate_manager, "set_state"))
                stack.enter_context(mock.patch.object(vpngate_manager, "log_to_json"))
                stack.enter_context(mock.patch.object(vpngate_manager, "get_failover_targets", return_value=["US"]))
                stack.enter_context(mock.patch.object(vpngate_manager, "choose_auto_failover_candidates", return_value=([nodes[1]], "fixture")))
                stack.enter_context(mock.patch.object(vpngate_manager, "active_connection_looks_healthy", return_value=False))
                stack.enter_context(mock.patch.object(vpngate_manager, "node_is_clean_for_connect", return_value=True))
                stack.enter_context(mock.patch.object(vpngate_manager, "get_auto_failover_tunnel_mode", return_value="dual"))
                dual = stack.enter_context(mock.patch.object(
                    vpngate_manager,
                    "connect_node_dual_tunnel",
                    return_value=(True, "Dual tunnel connected backup"),
                ))
                single = stack.enter_context(mock.patch.object(vpngate_manager, "connect_node"))
                vpngate_manager.auto_switch_node()

            dual.assert_called_once_with("backup", update_failover_scope=False, allow_auto_risky=False)
            single.assert_not_called()
        finally:
            vpngate_manager.active_openvpn_process, vpngate_manager.active_openvpn_node_id, vpngate_manager.is_connecting = original_state

    def test_failure_failover_dual_mode_falls_back_to_single_when_backup_fails(self):
        old_process = mock.Mock()
        old_process.poll.return_value = None
        nodes = [
            {"id": "old", "probe_status": "available", "active": True, "country_short": "US"},
            {"id": "backup", "probe_status": "available", "active": False, "country_short": "US"},
        ]
        original_state = (
            vpngate_manager.active_openvpn_process,
            vpngate_manager.active_openvpn_node_id,
            vpngate_manager.is_connecting,
        )
        vpngate_manager.active_openvpn_process = old_process
        vpngate_manager.active_openvpn_node_id = "old"
        vpngate_manager.is_connecting = False
        try:
            def read_json_for_test(path, default=None):
                if path == vpngate_manager.NODES_FILE:
                    return nodes
                return {}

            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(vpngate_manager, "read_json", side_effect=read_json_for_test))
                stack.enter_context(mock.patch.object(vpngate_manager, "set_state"))
                stack.enter_context(mock.patch.object(vpngate_manager, "log_to_json"))
                stack.enter_context(mock.patch.object(vpngate_manager, "get_failover_targets", return_value=["US"]))
                stack.enter_context(mock.patch.object(vpngate_manager, "choose_auto_failover_candidates", return_value=([nodes[1]], "fixture")))
                stack.enter_context(mock.patch.object(vpngate_manager, "active_connection_looks_healthy", return_value=False))
                stack.enter_context(mock.patch.object(vpngate_manager, "node_is_clean_for_connect", return_value=True))
                stack.enter_context(mock.patch.object(vpngate_manager, "get_auto_failover_tunnel_mode", return_value="dual"))
                dual = stack.enter_context(mock.patch.object(
                    vpngate_manager,
                    "connect_node_dual_tunnel",
                    return_value=(False, "双通道故障切换失败，保持当前出口"),
                ))
                single = stack.enter_context(mock.patch.object(vpngate_manager, "connect_node"))
                vpngate_manager.auto_switch_node()

            dual.assert_called_once_with("backup", update_failover_scope=False, allow_auto_risky=False)
            single.assert_called_once_with("backup", update_failover_scope=False, allow_auto_risky=False)
        finally:
            vpngate_manager.active_openvpn_process, vpngate_manager.active_openvpn_node_id, vpngate_manager.is_connecting = original_state

    def test_proxy_new_connections_can_follow_promoted_interface(self):
        original = proxy_server.get_tun_interface()
        try:
            proxy_server.set_tun_interface("tun1")
            self.assertEqual(proxy_server.get_tun_interface(), "tun1")
        finally:
            proxy_server.set_tun_interface(original)

    def test_dual_switch_starts_candidate_before_draining_old_tunnel(self):
        old_process = mock.Mock()
        old_process.poll.return_value = None
        candidate_process = mock.Mock()
        candidate_process.poll.return_value = None
        nodes = [
            {
                "id": "old",
                "config_file": "/tmp/old.ovpn",
                "config_text": "client",
                "probe_status": "available",
                "active": True,
            },
            {
                "id": "better",
                "config_file": "/tmp/better.ovpn",
                "config_text": "client",
                "probe_status": "available",
                "active": False,
                "fraud_score": 1,
                "risk_level": "clean",
                "risk_sources": ["fixture"],
                "blacklist_count": 0,
                "ip_type": "residential",
            },
        ]
        original_state = (
            vpngate_manager.active_openvpn_process,
            vpngate_manager.active_openvpn_node_id,
            vpngate_manager.active_openvpn_interface,
            vpngate_manager.is_connecting,
        )
        vpngate_manager.active_openvpn_process = old_process
        vpngate_manager.active_openvpn_node_id = "old"
        vpngate_manager.active_openvpn_interface = "tun0"
        vpngate_manager.is_connecting = False
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(vpngate_manager, "read_json", return_value=nodes))
                stack.enter_context(mock.patch.object(vpngate_manager, "write_json"))
                stack.enter_context(mock.patch.object(vpngate_manager, "set_state"))
                stack.enter_context(mock.patch.object(vpngate_manager, "node_is_clean_for_connect", return_value=True))
                stack.enter_context(mock.patch.object(vpngate_manager, "sanitize_openvpn_config_for_eianun", return_value="client"))
                stack.enter_context(mock.patch.object(vpngate_manager, "atomic_write_text"))
                stack.enter_context(mock.patch.object(vpngate_manager, "auth_file_for_node", return_value="/tmp/auth"))
                run_openvpn = stack.enter_context(mock.patch.object(
                    vpngate_manager,
                    "run_openvpn_until_ready",
                    return_value=(True, "connected", candidate_process),
                ))
                setup_route = stack.enter_context(mock.patch.object(vpngate_manager, "setup_policy_routing", return_value=True))
                stack.enter_context(mock.patch.object(vpngate_manager, "check_proxy_health", return_value={"ok": True, "ip": "198.51.100.1", "latency_ms": 12}))
                stack.enter_context(mock.patch.object(vpngate_manager.proxy_server, "get_tun_interface", return_value="tun0"))
                set_interface = stack.enter_context(mock.patch.object(vpngate_manager.proxy_server, "set_tun_interface"))
                drain = stack.enter_context(mock.patch.object(vpngate_manager, "_start_openvpn_drain"))
                stack.enter_context(mock.patch.object(vpngate_manager, "log_to_json"))
                ok, message = vpngate_manager.connect_node_dual_tunnel("better", allow_auto_risky=True)

            self.assertTrue(ok, message)
            self.assertIn("Dual tunnel connected", message)
            self.assertEqual(run_openvpn.call_args.kwargs["dev"], "tun1")
            setup_route.assert_called_once_with("tun1")
            set_interface.assert_called_once_with("tun1")
            drain.assert_called_once_with(old_process, "old", "tun0", "/tmp/old.ovpn")
            self.assertIs(vpngate_manager.active_openvpn_process, candidate_process)
            self.assertEqual(vpngate_manager.active_openvpn_node_id, "better")
            self.assertEqual(vpngate_manager.active_openvpn_interface, "tun1")
        finally:
            vpngate_manager.active_openvpn_process, vpngate_manager.active_openvpn_node_id, vpngate_manager.active_openvpn_interface, vpngate_manager.is_connecting = original_state

    def test_dual_switch_failure_restores_old_interface_and_keeps_old_process(self):
        old_process = mock.Mock()
        old_process.poll.return_value = None
        candidate_process = mock.Mock()
        candidate_process.poll.return_value = None
        nodes = [
            {"id": "old", "config_file": "/tmp/old.ovpn", "config_text": "client", "probe_status": "available", "active": True},
            {
                "id": "better",
                "config_file": "/tmp/better.ovpn",
                "config_text": "client",
                "probe_status": "available",
                "active": False,
                "fraud_score": 1,
                "risk_level": "clean",
                "risk_sources": ["fixture"],
                "blacklist_count": 0,
                "ip_type": "residential",
            },
        ]
        original_state = (
            vpngate_manager.active_openvpn_process,
            vpngate_manager.active_openvpn_node_id,
            vpngate_manager.active_openvpn_interface,
            vpngate_manager.is_connecting,
        )
        vpngate_manager.active_openvpn_process = old_process
        vpngate_manager.active_openvpn_node_id = "old"
        vpngate_manager.active_openvpn_interface = "tun0"
        vpngate_manager.is_connecting = False
        try:
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(vpngate_manager, "read_json", return_value=nodes))
                stack.enter_context(mock.patch.object(vpngate_manager, "write_json"))
                stack.enter_context(mock.patch.object(vpngate_manager, "set_state"))
                stack.enter_context(mock.patch.object(vpngate_manager, "node_is_clean_for_connect", return_value=True))
                stack.enter_context(mock.patch.object(vpngate_manager, "sanitize_openvpn_config_for_eianun", return_value="client"))
                stack.enter_context(mock.patch.object(vpngate_manager, "atomic_write_text"))
                stack.enter_context(mock.patch.object(vpngate_manager, "auth_file_for_node", return_value="/tmp/auth"))
                stack.enter_context(mock.patch.object(
                    vpngate_manager,
                    "run_openvpn_until_ready",
                    return_value=(True, "connected", candidate_process),
                ))
                setup_route = stack.enter_context(mock.patch.object(vpngate_manager, "setup_policy_routing", side_effect=[True, True]))
                stack.enter_context(mock.patch.object(vpngate_manager, "check_proxy_health", return_value={"ok": False, "error": "fixture failure"}))
                stack.enter_context(mock.patch.object(vpngate_manager.proxy_server, "get_tun_interface", return_value="tun0"))
                set_interface = stack.enter_context(mock.patch.object(vpngate_manager.proxy_server, "set_tun_interface"))
                stop_process = stack.enter_context(mock.patch.object(vpngate_manager, "stop_process"))
                stack.enter_context(mock.patch.object(vpngate_manager, "log_to_json"))
                ok, message = vpngate_manager.connect_node_dual_tunnel("better", allow_auto_risky=True)

            self.assertFalse(ok)
            self.assertIn("保持当前出口", message)
            self.assertIs(vpngate_manager.active_openvpn_process, old_process)
            self.assertEqual(vpngate_manager.active_openvpn_node_id, "old")
            self.assertEqual(vpngate_manager.active_openvpn_interface, "tun0")
            self.assertEqual(setup_route.call_args_list[0].args, ("tun1",))
            self.assertEqual(setup_route.call_args_list[1].args, ("tun0",))
            set_interface.assert_has_calls([mock.call("tun1"), mock.call("tun0")])
            stop_process.assert_called_once_with(candidate_process)
        finally:
            vpngate_manager.active_openvpn_process, vpngate_manager.active_openvpn_node_id, vpngate_manager.active_openvpn_interface, vpngate_manager.is_connecting = original_state


if __name__ == "__main__":
    unittest.main()
