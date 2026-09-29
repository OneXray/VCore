import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.memory_inputs import RunStore, bandwidth_complete, cn_statistics


class MemoryResumeTests(unittest.TestCase):
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
