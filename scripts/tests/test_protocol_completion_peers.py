"""Fixture contracts; real peer traffic is checked only in owned containers."""

import unittest
from pathlib import Path
from unittest.mock import patch

from vcore_scripts.protocol_completion_peers import CASES, peer_configuration


class CompletionPeerTests(unittest.TestCase):
    def test_comparison_client_refuses_host_network_io(self):
        from vcore_scripts.container_protocol_client import main

        with (
            patch.dict("os.environ", {}, clear=True),
            self.assertRaisesRegex(SystemExit, "container harness"),
        ):
            main()

    def test_tuic_v5_and_upgrade_fixtures_select_real_wire_modes(self):
        tuic = [case for case in CASES if case.protocol == "tuic"]
        upgrades = [case for case in CASES if case.protocol in {"vmess", "trojan"}]
        self.assertEqual({case.udp_mode for case in tuic}, {"native", "quic"})
        self.assertEqual(len(upgrades), 6)
        for case in tuic + upgrades:
            with self.subTest(case=case.identifier):
                node, listener = peer_configuration(
                    case,
                    server="192.0.2.2",
                    cover="192.0.2.3:24001",
                    port=23000,
                    certificate=(Path("cert.pem"), Path("key.pem"), "a" * 64),
                )
                if case.protocol == "tuic":
                    self.assertNotIn("token", node)
                    self.assertEqual(listener["users"][node["uuid"]], node["password"])
                    self.assertEqual(node["udp-relay-mode"], case.udp_mode)
                else:
                    self.assertEqual(node["network"], "ws")
                    self.assertIs(node["ws-opts"]["v2ray-http-upgrade"], True)
                    self.assertEqual(
                        node["ws-opts"]["v2ray-http-upgrade-fast-open"], case.fast_open
                    )
                    self.assertEqual(node["ws-opts"]["path"], listener["ws-path"])
                self.assertEqual("certificate" in listener, case.tls)

    def test_uot_fixtures_force_v2_and_do_not_offer_native_udp(self):
        selected = [case for case in CASES if case.uot]
        self.assertEqual(len(selected), 6)
        for case in selected:
            with self.subTest(case=case.identifier):
                node, listener = peer_configuration(
                    case,
                    server="192.0.2.2",
                    cover="192.0.2.3:24001",
                    port=23000,
                    certificate=(Path("cert.pem"), Path("key.pem"), "a" * 64),
                )
                self.assertEqual(node["type"], "ss")
                self.assertIs(node["udp-over-tcp"], True)
                self.assertEqual(node["udp-over-tcp-version"], 2)
                self.assertIs(listener["udp"], False)
                if case.shadow_tls:
                    self.assertEqual(node["plugin"], "shadow-tls")
                    self.assertEqual(node["plugin-opts"]["version"], 3)
                    self.assertIs(listener["shadow-tls"]["strict-mode"], True)


if __name__ == "__main__":
    unittest.main()
