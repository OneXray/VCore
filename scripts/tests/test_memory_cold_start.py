import copy
import unittest

from vcore_scripts.memory_cold_start import available, cases, summarize


class ColdStartTests(unittest.TestCase):
    def test_four_profiles_require_exact_assets_and_five_fresh_runs(self):
        identifiers = cases()
        self.assertEqual(len(identifiers), 20)
        self.assertEqual(len(set(identifiers)), 20)
        for profile, required in (
            ("none", set()),
            ("site", {"geosite"}),
            ("ip", {"geoip"}),
            ("both", {"geosite", "geoip"}),
        ):
            self.assertEqual(
                [name for name in identifiers if name.startswith(f"cold-{profile}-")],
                [f"cold-{profile}-{index}" for index in range(1, 6)],
            )
            state = {
                key: {
                    "required": key in required,
                    "available": key in required,
                    "lastError": None,
                }
                for key in ("geosite", "geoip")
            }
            self.assertTrue(available(profile, state))
            for key in state:
                changed = {k: v.copy() for k, v in state.items()}
                changed[key]["required"] = not state[key]["required"]
                self.assertFalse(available(profile, changed))
                changed[key] = state[key] | {"lastError": "failed"}
                self.assertFalse(available(profile, changed))
                changed[key] = state[key] | {"available": not state[key]["available"]}
                self.assertFalse(available(profile, changed))
            self.assertFalse(available(profile, {}))

    def test_incomplete_reused_or_instrumented_processes_never_complete_matrix(self):
        rows = {}
        for pid, name in enumerate(cases(), start=1000):
            profile = name.split("-")[1]
            required = {
                "none": (),
                "site": ("geosite",),
                "ip": ("geoip",),
                "both": ("geosite", "geoip"),
            }[profile]
            rows[name] = {
                "profile": profile,
                "accepted": True,
                "geodata": {
                    key: {
                        "required": key in required,
                        "available": key in required,
                        "lastError": None,
                    }
                    for key in ("geosite", "geoip")
                },
                "idle_seconds": 30.01,
                "phases": {
                    key: {"seconds": 0.1}
                    for key in (
                        "initialize",
                        "prepare",
                        "start",
                        "first-hit",
                        "idle",
                        "stop",
                        "destroyInstance",
                    )
                },
                "measurement": {
                    "pid": pid,
                    "status": "PASS",
                    "peak_bytes": 8_000_000,
                    "exit_code": 0,
                    "final_barrier": True,
                    "business_cleanup": True,
                    "cleanup": True,
                    "sampling_errors": [],
                    "diagnostic": False,
                },
            }
        self.assertTrue(summarize(rows)["complete"])
        worst = copy.deepcopy(rows)
        worst["cold-both-5"]["measurement"]["peak_bytes"] = 49_999_999
        self.assertEqual(summarize(worst)["profiles"]["both"]["margin_bytes"], 1)
        for path, value in (
            (("measurement", "pid"), 1000),
            (("measurement", "diagnostic"), True),
            (("measurement", "peak_bytes"), 50_000_001),
            (("measurement", "final_barrier"), False),
            (("measurement", "status"), "INVALID"),
            (("measurement", "sampling_errors"), ["missing"]),
            (("idle_seconds",), 29.9),
            (("phases",), {}),
            (("geodata",), {}),
        ):
            changed = copy.deepcopy(rows)
            row = changed["cold-both-5"]
            for key in path[:-1]:
                row = row[key]
            row[path[-1]] = value
            with self.subTest(path=path):
                self.assertFalse(summarize(changed)["complete"])
        del rows["cold-ip-5"]
        self.assertFalse(summarize(rows)["complete"])
