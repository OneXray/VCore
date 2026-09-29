import ipaddress
import re
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.memory_benchmark import _available_cn
from vcore_scripts.memory_geodata import (
    REGEX_WITNESSES,
    IpReference,
    SiteReference,
    cn_entries,
)


class GeoDataReferenceTests(unittest.TestCase):
    def test_independent_domain_full_and_regex_boundaries(self):
        model = SiteReference(
            [
                (2, "example.cn"),
                (3, "full.test"),
                (1, r"^r[0-9]+\.test$"),
                (0, "needle"),
            ]
        )
        for value in (
            "example.cn",
            "a.example.cn",
            "full.test",
            "r12.test",
            "xneedle.test",
        ):
            self.assertTrue(model.matches(value))
        for value in ("notexample.cn", "example.cn.test", "a.full.test", "rx.test"):
            self.assertFalse(model.matches(value))

    def test_independent_ip_boundaries_overlap_and_family(self):
        networks = [
            ipaddress.ip_network(value)
            for value in (
                "10.0.0.0/24",
                "10.0.1.0/24",
                "10.0.0.128/25",
                "2001:db8::/127",
            )
        ]
        model = IpReference(networks)
        for value in (
            "9.255.255.255",
            "10.0.0.0",
            "10.0.1.255",
            "10.0.2.0",
            "2001:db8::",
            "2001:db8::1",
            "2001:db8::2",
            "::ffff:10.0.0.1",
        ):
            address = ipaddress.ip_address(value)
            self.assertEqual(
                model.matches(address), any(address in network for network in networks)
            )

    def test_every_known_regex_has_independent_positive_and_negative_witnesses(self):
        self.assertEqual(len(REGEX_WITNESSES), 8)
        for pattern, (positive, negative) in REGEX_WITNESSES.items():
            self.assertTrue(positive and negative)
            for expected, names in ((True, positive), (False, negative)):
                for name in names:
                    self.assertEqual(
                        bool(re.search(pattern, name, flags=re.ASCII)), expected
                    )

    def test_missing_duplicate_and_truncated_cn_fail_reference_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "geosite.dat"
            for blob in (
                b"\x0a\x04\x0a\x02US",
                b"\x0a\x04\x0a\x02CN" * 2,
                b"\x0a\x05\x0a",
            ):
                path.write_bytes(blob)
                with self.assertRaises(ValueError):
                    cn_entries(path)

    def test_prepare_success_cannot_hide_unavailable_or_failed_asset(self):
        state = {
            kind: {"required": True, "available": True, "lastError": None}
            for kind in ("geosite", "geoip")
        }
        self.assertTrue(_available_cn(state))
        for key, value in (
            ("available", False),
            ("required", False),
            ("lastError", "failed"),
        ):
            changed = {
                kind: data | ({key: value} if kind == "geosite" else {})
                for kind, data in state.items()
            }
            self.assertFalse(_available_cn(changed))
        self.assertFalse(_available_cn({}))
