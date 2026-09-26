"""Offline checks of N6's evidence boundary; no sockets or protocol peers."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_hysteria2 import test_command
from vcore_scripts.protocol_hysteria2_acceptance import (
    bandwidth_pass,
    hopping_pass,
    native_result,
)
from vcore_scripts.protocol_hysteria2_catalog import (
    FIELDS,
    H,
    definitions,
    events_pass,
)


def pair(suite, assertion):
    return [
        dict(schema_version=1, suite=suite, assertion=assertion, status=s)
        for s in ("BEGIN", "PASS")
    ]


def tcp_events():
    outer = pair("N6-BASE", "tcp_ipv4_ipv6_domain_and_measure")
    return outer[:1] + pair("N6-BASE", "tcp_10mib_both_directions") * 3 + outer[1:]


class Hysteria2AcceptanceTest(unittest.TestCase):
    def test_catalog_covers_all_fields_and_eight_hop_combinations(self):
        cases = definitions()
        self.assertEqual(len(cases), 36)
        self.assertEqual(len(cases), len({c["case_id"] for c in cases}))
        self.assertEqual(len(FIELDS), 20)
        self.assertEqual(FIELDS, set().union(*(set(c["row_ids"]) for c in cases)))
        self.assertEqual(
            {
                (v["ipv6"], v["obfs"], v["random_interval"])
                for v in H.values()
                if v["test"] == "native_hopping"
            },
            {
                (a, b, c)
                for a in (False, True)
                for b in (False, True)
                for c in (False, True)
            },
        )

    def test_partial_unknown_duplicate_and_wrong_suite_events_fail(self):
        # The public caller records one outer case plus three nested bulk
        # transfers. Mirror that real trace, not only its outer success event.
        observed = tcp_events()
        self.assertTrue(events_pass(observed, "hysteria2_tcp_base"))
        wrong = copy.deepcopy(observed)
        wrong[1]["suite"] = "N5-BASE"
        for bad in (
            [],
            observed[:1],
            observed * 2,
            wrong,
            observed + pair("N6-BASE", "unknown"),
            pair("N6-BASE", "tcp_ipv4_ipv6_domain_and_measure"),
            observed[:1] + observed[3:],
            observed + pair("N6-BASE", "tcp_10mib_both_directions"),
        ):
            self.assertFalse(events_pass(bad, "hysteria2_tcp_base"))

    def test_native_identity_cleanup_or_missing_results_fail(self):
        case = next(c for c in definitions() if c["case_id"] == "N6-TCP")
        test = "hysteria2_tcp_base"
        report = dict(
            status="PASS",
            cleanup=True,
            source_unchanged=True,
            obfs=False,
            cases=[
                dict(
                    case_id=test,
                    status="PASS",
                    exit_code=0,
                    command_cleanup=True,
                    command=test_command(test),
                )
            ],
            isolation=dict(
                network_mode="hostOnly",
                host_servers=False,
                guest_mtu=1500,
                image_digest="sha256:" + "a" * 64,
                peers=[dict(started=True, joined=True)],
            ),
            peers={
                "M": dict(
                    version="test",
                    binary_sha256="b" * 64,
                    source_url="https://github.com/MetaCubeX/mihomo/"
                    "releases/download/test/fixture",
                )
            },
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            path = directory / f"{test}-events.jsonl"
            path.write_text("".join(json.dumps(e) + "\n" for e in tcp_events()))
            self.assertEqual(native_result(case, report, directory)["status"], "PASS")
            for key, bad in (
                ("peers", {}),
                ("cleanup", False),
                ("cases", []),
                ("source_unchanged", False),
            ):
                altered = copy.deepcopy(report)
                altered[key] = bad
                self.assertEqual(
                    native_result(case, altered, directory)["status"], "FAIL"
                )
            path.unlink()
            self.assertEqual(native_result(case, report, directory)["status"], "FAIL")

    def test_bandwidth_and_hop_counters_cannot_be_forged_as_empty_success(self):
        self.assertFalse(bandwidth_pass([]))
        self.assertFalse(bandwidth_pass([{}] * 10))
        self.assertFalse(hopping_pass({}))
        hop = dict(
            seconds=60,
            protected_sockets=9,
            tcp_bytes_per_direction=10485760,
            tcp_sha256="c" * 64,
            udp_packets=1500,
            udp_target_kinds=3,
            udp_maximums=[4071, 4052, 4060],
            socket_peak=2,
        )
        self.assertTrue(hopping_pass(hop))
        for key, value in (
            ("seconds", 59),
            ("protected_sockets", 8),
            ("udp_packets", 0),
            ("tcp_sha256", ""),
            ("socket_peak", 3),
            ("udp_maximums", []),
        ):
            altered = dict(hop, **{key: value})
            self.assertFalse(hopping_pass(altered))


if __name__ == "__main__":
    unittest.main()
