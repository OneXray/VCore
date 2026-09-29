"""The native measurement interface is exercised without a network listener."""

import platform
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.memory_process import build_observer, calibration


@unittest.skipUnless(platform.system() == "Darwin", "requires Darwin kernel counters")
class MemoryProcessTests(unittest.TestCase):
    def test_missing_peak_crash_and_missing_final_evidence_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            artifacts = build_observer(work)
            for name in ("sampling-failure", "crash", "missing-final", "wrong-pid"):
                with self.subTest(name=name):
                    result = calibration(name, artifacts, work / name)
                    self.assertEqual(result["status"], "INVALID")
                    self.assertTrue(result["cleanup"])

    def test_released_allocation_still_fails_lifetime_peak_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            artifacts = build_observer(work)
            result = calibration("transient", artifacts, work / "case")
            self.assertEqual(result["status"], "FAIL_MEMORY")
            self.assertGreaterEqual(result["peak_bytes"], 64 * 1024 * 1024)
            self.assertLess(result["final_current_bytes"], 50_000_000)
            self.assertLess(result["sampled_current_max_bytes"], 50_000_000)
            self.assertTrue(result["final_barrier"])
            self.assertTrue(result["cleanup"])
            self.assertEqual(result["exit_code"], 0)
            self_cpu = (
                result["self_final"]["user_ns"] + result["self_final"]["system_ns"]
            ) / 1e9
            reaped_cpu = result["user_seconds"] + result["system_seconds"]
            self.assertGreater(self_cpu, reaped_cpu * 0.8)
            self.assertLessEqual(self_cpu, reaped_cpu + 0.002)


if __name__ == "__main__":
    unittest.main()
