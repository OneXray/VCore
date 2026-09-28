import unittest

from vcore_scripts.cli import _parser
from vcore_scripts.protocol_reality_hybrid import (
    MODES,
    cases,
    negative_wire_pass,
    wire_pass,
)


class HybridRealityGateTests(unittest.TestCase):
    def test_browser_downgrade_and_retry_require_each_legs_actual_server_hello(self):
        events = []
        for port, group, hrr in ((25002, 29, False), (25003, 24, True)):
            events.extend(
                [
                    {
                        "port": port,
                        "event": "client-hello",
                        "shares": [[4588, 1216], [29, 32]],
                        "groups": [4588, 29, 23, 24],
                    },
                    {"port": port, "event": "server-hello", "group": group, "hrr": hrr},
                ]
            )
        self.assertTrue(negative_wire_pass(events, "chrome"))
        self.assertTrue(negative_wire_pass(events * 2, "chrome", legs=2))
        self.assertFalse(negative_wire_pass(events, "chrome", legs=2))
        self.assertFalse(negative_wire_pass(events[:-1], "chrome"))
        self.assertFalse(
            negative_wire_pass(events[:-1] + [dict(events[-1], hrr=False)], "chrome")
        )
        self.assertFalse(
            negative_wire_pass(
                [dict(events[0], shares=[[29, 32]])] + events[1:], "chrome"
            )
        )

    def test_hybrid_only_peer_rejection_needs_positive_no_shared_group_evidence(self):
        events = []
        for front, cover in ((25002, 24432), (25003, 24433)):
            events.extend(
                [
                    {
                        "port": front,
                        "event": "client-hello",
                        "shares": [[4588, 1216]],
                        "groups": [4588],
                    },
                    {"port": cover, "event": "no-shared-group"},
                    {"port": front, "event": "server-close", "bytes": 0},
                ]
            )
        self.assertTrue(negative_wire_pass(events, "none"))
        self.assertFalse(negative_wire_pass(events[:-1], "none"))
        self.assertFalse(negative_wire_pass(events, "none", legs=2))
        self.assertFalse(negative_wire_pass(events, "chrome"))
        self.assertFalse(
            negative_wire_pass(
                events + [{"port": 25002, "event": "server-hello", "group": 29}],
                "none",
            )
        )

    def test_required_scope_includes_profiles_download_and_lifecycle(self):
        required = cases()
        self.assertEqual(len(required), 54)
        self.assertEqual(len(MODES), 12)
        for profile in ("none", "chrome"):
            for version in ("h1", "h2"):
                for mode in ("stream-up", "packet-up"):
                    self.assertIn(f"{profile}-{version}-{mode}-base", required)
                for variant in ("main-classic", "download-classic"):
                    self.assertIn(f"{profile}-{version}-{variant}", required)
                self.assertIn(f"{profile}-{version}-stream-up-security", required)
        for mode in ("tcp", "grpc", "vision", "h2-stream-up"):
            for test in ("life", "owned"):
                self.assertIn(f"chrome-{mode}-{test}", required)

    def test_observation_requires_both_real_shares_and_actual_negotiation(self):
        events = [
            {
                "port": 25000,
                "event": "client-hello",
                "shares": [[4588, 1216], [29, 32]],
            },
            {"port": 25000, "event": "server-hello", "group": 4588},
        ]
        expected = {25000: (True, "chrome")}
        self.assertTrue(wire_pass(events, expected))
        self.assertFalse(wire_pass(events[:1], expected))
        self.assertFalse(wire_pass(events[1:], expected))
        self.assertFalse(wire_pass(events, {**expected, 25001: (True, "chrome")}))
        self.assertFalse(wire_pass(events + [dict(events[1], group=29)], expected))
        self.assertFalse(
            wire_pass([dict(events[0], shares=[[29, 32]]), events[1]], expected)
        )

    def test_classic_and_hybrid_legs_have_independent_requirements(self):
        events = [
            {"port": 25000, "event": "client-hello", "shares": [[4588, 1216]]},
            {"port": 25000, "event": "server-hello", "group": 4588},
            {"port": 25001, "event": "client-hello", "shares": [[29, 32]]},
            {"port": 25001, "event": "server-hello", "group": 29},
        ]
        self.assertTrue(
            wire_pass(events, {25000: (True, "none"), 25001: (False, "chrome")})
        )
        self.assertFalse(
            wire_pass(events, {25000: (True, "none"), 25001: (True, "chrome")})
        )

    def test_cli_exposes_a_subpackage_not_full_stage_acceptance(self):
        args = _parser().parse_args(
            [
                "check",
                "reality-hybrid",
                "--run-dir",
                "target/interop/runs/new",
                "--case",
                "chrome-tcp-base",
            ]
        )
        self.assertEqual(args.identifiers, ["chrome-tcp-base"])
