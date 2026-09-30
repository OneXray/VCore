import contextlib
import copy
import importlib.util
import io
import socket
import struct
import unittest

from vcore_scripts.memory_benchmark import run
from vcore_scripts.memory_process import FIXTURES
from vcore_scripts.memory_socks_load import joint_status


class SocksLoadTests(unittest.TestCase):
    def test_online_updates_require_owned_trusted_https_inputs_before_start(self):
        with self.assertRaisesRegex(RuntimeError, "trusted HTTPS"):
            run(identifiers=["profile-socks-socks5-v4-update-geosite-replace"])

    def test_endurance_cases_keep_smoke_and_full_workloads_distinct(self):
        names = [
            "lifecycle-socks-lifetimes-v4-smoke",
            "lifecycle-tun-rebuild-v6-full",
            "profile-socks-mixed-eight-v4-soak",
        ]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            for name in names:
                run(identifiers=[name], list_only=True)
        self.assertEqual(output.getvalue().splitlines(), names)

    def test_protocol_memory_profiles_have_public_two_entrypoint_cases(self):
        names = [
            "profile-socks-ss-aes128-v4-smoke",
            "profile-tun-vless-chrome-v6-smoke",
            "profile-socks-mixed-eight-v4-standard-1",
        ]
        with contextlib.redirect_stdout(io.StringIO()) as output:
            run(identifiers=names[:1], list_only=True)
            run(identifiers=names[1:2], list_only=True)
            run(identifiers=names[2:], list_only=True)
        self.assertEqual(output.getvalue().splitlines(), names)

    def test_tun_development_load_has_a_separate_public_entrypoint(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            run(identifiers=["tun-smoke-tcp-v4", "tun-smoke-udp-v4"], list_only=True)
        self.assertEqual(
            output.getvalue().splitlines(), ["tun-smoke-tcp-v4", "tun-smoke-udp-v4"]
        )

    def test_distributed_udp_development_case_has_a_public_entrypoint(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            run(identifiers=["socks-smoke-udp-distributed-v6"], list_only=True)
        self.assertEqual(output.getvalue().strip(), "socks-smoke-udp-distributed-v6")

    def test_dns_overlap_development_case_has_a_public_entrypoint(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            run(identifiers=["socks-smoke-dns-v6"], list_only=True)
        self.assertEqual(output.getvalue().strip(), "socks-smoke-dns-v6")

    def test_development_cases_are_explicit_and_separate_from_formal_load(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            run(
                identifiers=["socks-smoke-tcp-v6", "socks-smoke-udp-v6"],
                list_only=True,
            )
        self.assertEqual(
            output.getvalue().splitlines(),
            ["socks-smoke-tcp-v6", "socks-smoke-udp-v6"],
        )

    def test_ipv6_dns_oracle_returns_only_the_selected_address_family(self):
        spec = importlib.util.spec_from_file_location(
            "load_dns", FIXTURES / "load_dns.py"
        )
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        question = b"\x07fixture\x04test\0"
        head = struct.pack("!6H", 123, 0x100, 1, 0, 0, 0)
        packet = head + question + b"\0\x1c\0\x01"
        reply, case_id, qtype = fixture.answer(
            packet, {"fixture.test": "positive"}, "fd00::1234"
        )
        self.assertEqual((case_id, qtype), ("positive", "28"))
        self.assertEqual(struct.unpack("!6H", reply[:12]), (123, 0x8180, 1, 1, 0, 0))
        self.assertEqual(reply[-16:], socket.inet_pton(socket.AF_INET6, "fd00::1234"))
        empty, _, _ = fixture.answer(
            head + question + b"\0\x01\0\x01",
            {"fixture.test": "positive"},
            "fd00::1234",
        )
        self.assertEqual(struct.unpack("!6H", empty[:12]), (123, 0x8180, 1, 0, 0, 0))

    def test_coupled_subset_cannot_mix_with_a_different_dns_fixture(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            run(suite="socks-tcp-split", list_only=True)
        self.assertEqual(len(output.getvalue().splitlines()), 9)
        with self.assertRaisesRegex(ValueError, "dedicated DNS"):
            run(identifiers=["socks-tcp-split-up-16-1", "smoke-1"], list_only=True)

    def test_joint_gate_requires_same_process_routing_rate_and_lifetime_peak(self):
        flow = {
            "direction": "up",
            "source_verified": True,
            "sent": {"bytes": 2343698432, "packets": 35762, "seconds": 300},
            "received": {"bytes": 2343698432, "packets": 35762, "seconds": 300},
        }
        traffic = {
            "complete": True,
            "rate_pass": True,
            "transport": "tcp",
            "direction": "up",
            "nominal_seconds": 300,
            "offered_bps": 500000000,
            "payload_bytes": 65536,
            "proxy_endpoint_count": 1,
            "external_start_barrier": True,
            "flows": [flow] * 8,
            "sent_bytes": 18749587456,
            "received_bytes": 18749587456,
            "elapsed_seconds": 300,
            "receiver_goodput_bps": 499988998.82666665,
        }
        row = {
            "pid": 123,
            "attempt": "case/attempt-0001",
            "facility_valid": True,
            "geodata": {
                kind: {"required": True, "available": True, "lastError": None}
                for kind in ("geosite", "geoip")
            },
            "measurement": {
                "pid": 123,
                "status": "PASS",
                "peak_bytes": 9000000,
                "diagnostic": False,
                "final_barrier": True,
                "business_cleanup": True,
                "cleanup": True,
                "exit_code": 0,
                "sampling_errors": [],
            },
            "branches": [
                {
                    "pid": 123,
                    "attempt": "case/attempt-0001",
                    "route": route,
                    "driver_joined": True,
                    "driver_exit": 0,
                    "traffic": copy.deepcopy(traffic),
                }
                for route in ("cn-direct", "miss-proxy")
            ],
            "load_seconds": 300,
            "start_barrier": True,
            "witness_rounds": [
                {"elapsed_seconds": when, "passed": True} for when in (3, 150, 280)
            ],
        }
        spec = {
            "direction": "up",
            "flows": 16,
            "seconds": 300,
            "mbps": 1000,
            "witness_seconds": [3, 150, 280],
        }
        self.assertEqual(joint_status(row, spec), "PASS")
        self.assertEqual(joint_status(row, spec | {"development": True}), "DIAGNOSTIC")
        for changed in (
            "pid",
            "route",
            "rate",
            "geodata",
            "witness",
            "barrier",
            "peak",
        ):
            altered = copy.deepcopy(row)
            if changed == "pid":
                altered["branches"][0]["pid"] = 456
            elif changed == "route":
                altered["branches"][0]["traffic"]["flows"][0]["source_verified"] = False
            elif changed == "rate":
                altered["branches"][0]["traffic"]["receiver_goodput_bps"] = 450000000
            elif changed == "geodata":
                altered["geodata"]["geosite"]["available"] = False
            elif changed == "witness":
                altered["witness_rounds"] = []
            elif changed == "barrier":
                altered["start_barrier"] = False
            else:
                altered["measurement"]["status"] = "FAIL_MEMORY"
                altered["measurement"]["peak_bytes"] = 50000001
            with self.subTest(changed=changed):
                self.assertNotEqual(joint_status(altered, spec), "PASS")

        # Full outbound traffic has no DIRECT branch; do not accept the old
        # ingress-only report as proof of the new prescribed topology.
        proxy_spec = spec | {"topology": "proxy"}
        self.assertNotEqual(joint_status(row, proxy_spec), "PASS")
        row["branches"][0]["route"] = "cn-proxy"
        self.assertEqual(joint_status(row, proxy_spec), "PASS")

        single_spec = proxy_spec | {
            "flows": 1,
            "primary_route": "cn",
            "direction": "both",
        }
        single = copy.deepcopy(row)
        single["branches"] = single["branches"][:1]
        traffic = single["branches"][0]["traffic"]
        expected = (500 * 125000 * 300 // 65536) * 65536
        traffic.update(
            direction="both",
            offered_bps=1000000000,
            data_connection_count=1,
            single_connection_duplex=True,
            sent_bytes=expected * 2,
            received_bytes=expected * 2,
            receiver_goodput_bps=expected * 2 * 8 / 300,
            flows=[
                {
                    "direction": direction,
                    "source_verified": True,
                    "sent": {
                        "bytes": expected,
                        "packets": expected // 65536,
                        "seconds": 300,
                    },
                    "received": {
                        "bytes": expected,
                        "packets": expected // 65536,
                        "seconds": 300,
                    },
                }
                for direction in ("up", "down")
            ],
        )
        self.assertEqual(joint_status(single, single_spec), "PASS")
        self.assertNotEqual(
            joint_status(single, single_spec | {"primary_route": "miss"}), "PASS"
        )
        traffic["data_connection_count"] = 2
        self.assertNotEqual(joint_status(single, single_spec), "PASS")

    def test_dns_maps_only_allowlisted_questions_to_isolated_target(self):
        spec = importlib.util.spec_from_file_location(
            "load_dns", FIXTURES / "load_dns.py"
        )
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        question = b"\x07fixture\x04test\0"
        packet = struct.pack("!6H", 123, 0x100, 1, 0, 0, 0) + question + b"\0\x01\0\x01"
        answer, case_id, qtype = fixture.answer(
            packet, {"fixture.test": "positive"}, "192.0.2.1"
        )
        self.assertEqual((case_id, qtype), ("positive", "1"))
        self.assertEqual(answer[-4:], socket.inet_aton("192.0.2.1"))
        self.assertEqual(struct.unpack("!6H", answer[:12]), (123, 0x8180, 1, 1, 0, 0))
        for malformed in (
            packet[:-1],
            packet + b"\0",
            packet.replace(question, b"\xc0\x0c"),
        ):
            with (
                self.subTest(malformed=malformed),
                self.assertRaises((ValueError, IndexError)),
            ):
                fixture.answer(malformed, {"fixture.test": "positive"}, "192.0.2.1")
        with self.assertRaises(ValueError):
            fixture.answer(packet, {"different.test": "negative"}, "192.0.2.1")
