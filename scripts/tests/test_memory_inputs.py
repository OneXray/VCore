import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.memory_inputs import RunStore, bandwidth_complete, cn_statistics


class MemoryResumeTests(unittest.TestCase):
    def test_variable_size_udp_correctness_requires_every_prescribed_datagram(self):
        report = {
            "correctness": True,
            "complete": True,
            "transport": "udp",
            "direction": "both",
            "nominal_seconds": 5,
            "offered_bps": 0,
            "proxy_endpoint_count": 1,
            "data_connection_count": 1,
            "tcp_bytes_per_second_per_direction": 65536,
            "udp_packets_per_second_per_direction": 20,
            "udp_payload_cycle": [64, 512, 1200],
            "sent_bytes": 117344,
            "received_bytes": 117344,
            "elapsed_seconds": 4.96,
            "flows": [
                {
                    "transport": "udp",
                    "direction": direction,
                    "sent": {"bytes": 58672, "packets": 100, "seconds": 4.95},
                    "received": {"bytes": 58672, "packets": 100, "seconds": 4.96},
                }
                for direction in ("up", "down")
            ],
        }
        options = {"flows": 1, "proxy_endpoints": 1, "seconds": 5, "correctness": True}
        self.assertTrue(bandwidth_complete(report, "udp", "both", **options))
        report["flows"][1]["received"]["packets"] = 99
        self.assertFalse(bandwidth_complete(report, "udp", "both", **options))

    def test_single_tcp_duplex_requires_one_connection_and_two_complete_directions(
        self,
    ):
        size, seconds, mbps = 65536, 10, 1000
        expected = (mbps * 125000 // 2 * seconds // size) * size
        report = {
            "complete": True,
            "rate_pass": True,
            "transport": "tcp",
            "direction": "both",
            "nominal_seconds": seconds,
            "offered_bps": mbps * 1000000,
            "payload_bytes": size,
            "proxy_endpoint_count": 1,
            "data_connection_count": 1,
            "single_connection_duplex": True,
            "flows": [
                {
                    "direction": direction,
                    "sent": {
                        "bytes": expected,
                        "packets": expected // size,
                        "seconds": seconds,
                    },
                    "received": {
                        "bytes": expected,
                        "packets": expected // size,
                        "seconds": seconds,
                    },
                }
                for direction in ("up", "down")
            ],
            "sent_bytes": expected * 2,
            "received_bytes": expected * 2,
            "elapsed_seconds": seconds,
            "receiver_goodput_bps": expected * 2 * 8 / seconds,
        }
        workload = {"flows": 1, "proxy_endpoints": 1, "seconds": seconds, "mbps": mbps}
        self.assertTrue(bandwidth_complete(report, "tcp", "both", **workload))
        report["data_connection_count"] = 2
        self.assertFalse(bandwidth_complete(report, "tcp", "both", **workload))
        report["data_connection_count"] = 1
        report["single_connection_duplex"] = False
        self.assertFalse(bandwidth_complete(report, "tcp", "both", **workload))
        report["single_connection_duplex"] = True
        report["flows"][1]["received"]["bytes"] -= size
        self.assertFalse(bandwidth_complete(report, "tcp", "both", **workload))

    def test_peer_capacity_catalog_exposes_independent_single_flow_runs(self):
        from vcore_scripts.memory_benchmark import run

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            run(suite="peer-capacity", list_only=True)
        identifiers = output.getvalue().splitlines()
        self.assertIn("capacity-mihomo-udp-up-1-1", identifiers)
        self.assertIn("capacity-direct-udp-down-1-3", identifiers)
        self.assertNotIn("capacity-mihomo-udp-both-1-1", identifiers)
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_single_flow_capacity_cannot_reuse_multiflow_or_short_run_evidence(self):
        report = {
            "complete": True,
            "rate_pass": True,
            "transport": "udp",
            "direction": "up",
            "nominal_seconds": 300,
            "offered_bps": 1000000000,
            "payload_bytes": 1200,
            "proxy_endpoint_count": 1,
            "flows": [
                {
                    "direction": "up",
                    "sent": {"bytes": 37500000000, "packets": 31250000, "seconds": 300},
                    "received": {
                        "bytes": 37500000000,
                        "packets": 31250000,
                        "seconds": 300,
                    },
                }
            ],
            "sent_bytes": 37500000000,
            "received_bytes": 37500000000,
            "elapsed_seconds": 300,
            "receiver_goodput_bps": 1000000000,
        }
        workload = {"proxy_endpoints": 1, "flows": 1, "seconds": 300, "mbps": 1000}
        self.assertTrue(bandwidth_complete(report, "udp", "up", **workload))
        self.assertFalse(bandwidth_complete(report, "udp", "up", proxy_endpoints=1))
        report["flows"][0]["sent"]["seconds"] = 10
        self.assertFalse(bandwidth_complete(report, "udp", "up", **workload))

    def test_bandwidth_report_requires_all_work_and_a_real_send_window(self):
        flow = {"direction": "up"}
        for end in ("sent", "received"):
            flow[end] = {"bytes": 78118912, "packets": 1192, "seconds": 9.99}
        report = {
            "complete": True,
            "rate_pass": True,
            "transport": "tcp",
            "direction": "up",
            "nominal_seconds": 10,
            "offered_bps": 1000000000,
            "payload_bytes": 65536,
            "proxy_endpoint_count": 0,
            "flows": [flow] * 16,
            "sent_bytes": 1249902592,
            "received_bytes": 1249902592,
            "elapsed_seconds": 10,
            "receiver_goodput_bps": 999922073.6,
        }
        self.assertTrue(bandwidth_complete(report, "tcp", "up"))
        report["proxy_endpoint_count"] = 1
        self.assertFalse(bandwidth_complete(report, "tcp", "up"))
        report["proxy_endpoint_count"] = 0
        # Claimed nominal goodput must not hide a burst or missing work.
        flow["sent"]["seconds"] = 1
        self.assertFalse(bandwidth_complete(report, "tcp", "up"))
        flow["sent"]["seconds"] = 9.99
        flow["received"]["bytes"] -= 65536
        self.assertFalse(bandwidth_complete(report, "tcp", "up"))
        self.assertFalse(bandwidth_complete({}, "tcp", "up"))

    def test_offline_cn_count_is_a_labelled_input_audit_not_loader_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            asset = Path(directory) / "geosite.dat"
            # GeoSiteList{entry:{country_code:"CN",domain:{type:Domain,value:"a.cn"}}}
            asset.write_bytes(b"\x0a\x0e\x0a\x02CN\x12\x08\x08\x02\x12\x04a.cn")
            result = cn_statistics(asset)
            self.assertEqual(result["records"], 1)
            self.assertEqual(result["value_bytes"], 4)
            self.assertEqual(result["types"], {"2": 1})
            self.assertEqual(result["scope"], "offline-count-not-loader-acceptance")

    def test_resume_never_reuses_incomplete_or_changed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = {"source": "fixed", "binary": "same", "inputs": "same"}
            run = RunStore(root / "run", identity)
            first = run.begin("smoke")
            self.assertIsNone(run.completed("smoke"))
            resumed = RunStore(root / "run", identity, resume=True)
            second = resumed.begin("smoke")
            self.assertNotEqual(first, second)
            timeline = second / "timeline.jsonl"
            timeline.write_text('{"pid":123,"peak":50000001}\n')
            resumed.finish("smoke", second, {"status": "FAIL_MEMORY"}, [timeline])
            self.assertEqual(resumed.completed("smoke")["status"], "FAIL_MEMORY")
            timeline.write_text('{"pid":123,"peak":1}\n')
            with self.assertRaisesRegex(ValueError, "evidence"):
                resumed.completed("smoke")
            with self.assertRaisesRegex(ValueError, "identity"):
                RunStore(root / "run", {"source": "changed"}, resume=True)
            self.assertTrue(
                json.loads((first / "state.json").read_text())["incomplete"]
            )


if __name__ == "__main__":
    unittest.main()
