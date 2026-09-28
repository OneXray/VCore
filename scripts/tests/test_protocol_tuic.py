import copy
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_evidence import load_manifest, validate_results
from vcore_scripts.protocol_security_acceptance import result, rust_command
from vcore_scripts.protocol_tuic import expected_observation, inputs, upstream_pair
from vcore_scripts.protocol_tuic_acceptance import wire_pass
from vcore_scripts.protocol_tuic_catalog import definitions, wire_cases


class TuicAcceptanceTest(unittest.TestCase):
    def test_registered_gates_cannot_omit_assertions_or_required_groups(self):
        cases = definitions()
        self.assertEqual(len(cases), 16)
        self.assertEqual(cases, [c for c in load_manifest() if c["stage"] == "TUIC"])
        results = [result(c, True, True) for c in cases]
        validate_results(cases, results)
        with self.assertRaises(ValueError):
            validate_results(cases, results[:-1])
        broken = copy.deepcopy(results)
        broken[0]["assertions"] = {}
        with self.assertRaises(ValueError):
            validate_results(cases, broken)

    def test_runner_matches_independent_wire_matrix(self):
        node = dict(
            udp=True,
            uuid="synthetic",
            password="synthetic",
            fingerprint="00" * 32,
            alpn=["h3"],
            **{"udp-relay-mode": "native"},
        )
        for name in ("TCP", "POLICY", "UDP", "PATHS", "NEGATIVE"):
            rows = inputs(node, {}, name.lower())
            self.assertEqual([(r[0], r[3]) for r in rows], wire_cases("MIHOMO-" + name))

    def test_raw_wire_evidence_rejects_truncation_forged_observation_and_wrong_consumer(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in (
                "MIHOMO-TCP",
                "MIHOMO-POLICY",
                "MIHOMO-UDP",
                "MIHOMO-PATHS",
                "MIHOMO-NEGATIVE",
            ):
                rows = []
                for identifier, consumer in wire_cases(name):
                    observed = expected_observation(consumer)
                    (root / (identifier + "-observations.json")).write_text(
                        json.dumps(observed)
                    )
                    (root / (identifier + "-events.jsonl")).write_text(
                        "".join(
                            json.dumps(
                                dict(
                                    schema_version=1,
                                    suite="TUIC-PUBLIC",
                                    assertion=consumer,
                                    status=status,
                                )
                            )
                            + "\n"
                            for status in ("BEGIN", "PASS")
                        )
                    )
                    rows.append(
                        dict(
                            case_id=identifier,
                            command=rust_command("vless_public", "tuic::" + consumer),
                            exit_code=0,
                            command_cleanup=True,
                            observations=observed,
                        )
                    )
                report = dict(cases=rows)
                self.assertTrue(wire_pass(name, root, report))
                self.assertFalse(wire_pass(name, root, dict(cases=rows[:-1])))
                for key, value in (
                    ("observations", {}),
                    ("command_cleanup", False),
                    ("exit_code", True),
                    (
                        "command",
                        rust_command(
                            "vless_public",
                            "tuic::tcp"
                            if rows[0]["command"]
                            != rust_command("vless_public", "tuic::tcp")
                            else "tuic::udp",
                        ),
                    ),
                ):
                    broken = copy.deepcopy(report)
                    broken["cases"][0][key] = value
                    self.assertFalse(wire_pass(name, root, broken))

    def test_mixed_pressure_requires_active_tuic_and_inactive_hysteria2(self):
        from vcore_scripts.protocol_evidence import RESOURCE_KINDS
        from vcore_scripts.protocol_integration_metrics import QUEUES, sample

        value = dict(
            heap_in_use=1,
            rss_kib=1,
            fd=1,
            resources=dict(
                counts=[dict(kind=k, current=1, peak=1) for k in RESOURCE_KINDS]
            ),
            queues=[
                dict(kind=k, capacity=v, peak=int(v > 0)) for k, v in QUEUES.items()
            ],
        )
        self.assertTrue(sample(value))
        for kind, mutation in (
            ("tuic_udp", dict(capacity=0, peak=0)),
            ("tuic_udp", dict(peak=33)),
            ("hysteria2_udp", dict(capacity=32)),
            ("hysteria2_udp", dict(peak=1)),
            ("quic_incoming", dict(kind="unknown")),
        ):
            broken = copy.deepcopy(value)
            next(q for q in broken["queues"] if q["kind"] == kind).update(mutation)
            self.assertFalse(sample(broken))
        value["queues"].pop()
        self.assertFalse(sample(value))

    def test_anytls_fixture_uses_listener_password_map(self):
        client, peer = upstream_pair(
            "anytls-native",
            {"server": "192.0.2.1"},
            (Path("cert.pem"), Path("key.pem"), "00" * 32),
            0,
        )
        self.assertEqual(peer["users"], {"fixture": client["password"]})
        self.assertTrue(client["udp"])


if __name__ == "__main__":
    unittest.main()
