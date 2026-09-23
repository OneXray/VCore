"""Offline evidence fixtures; these synthetic passes are never stage reports."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_evidence import RESOURCE_KINDS, check_run, load_manifest
from vcore_scripts.protocol_harness import SCRIPT_OBSERVATIONS


class RunEvidenceTest(unittest.TestCase):
    def fixture(self):
        cases = load_manifest()
        idle = {
            "counts": [
                {"kind": name, "current": 0, "peak": 1}
                for name in sorted(RESOURCE_KINDS)
            ]
        }
        events = []
        legacy = []
        native = []
        results = []
        for case in cases:
            results.append(
                {
                    "case_id": case["case_id"],
                    "row_ids": case["row_ids"],
                    "peer_kind": case["peer_kind"],
                    "scope": "foundation-only",
                    "status": "PASS",
                    "cleanup": True,
                    "command_exit_code": 0,
                    "assertions": dict.fromkeys(case["expected_observation"], True),
                    "evidence": case["required_evidence"],
                }
            )
            if case["runner"] in {"rust", "mihomo-legacy"}:
                target = legacy if case["runner"] == "mihomo-legacy" else events
                for assertion in case["expected_observation"]:
                    for status in ["BEGIN", "PASS"]:
                        target.append(
                            {
                                "schema_version": 1,
                                "suite": case["case_id"],
                                "assertion": assertion,
                                "status": status,
                                "seconds": 5,
                                "resources": idle
                                if case["case_id"] == "N1-RESOURCES"
                                and status == "PASS"
                                else None,
                                "checkpoints": [
                                    {"phase": phase, "resources": idle}
                                    for phase in ["baseline", "after-stop", "quiet"]
                                ],
                            }
                        )
            if case["runner"] == "native-stream":
                native.append(
                    {
                        "case_id": case["case_id"],
                        "status": "PASS",
                        "cleanup": {"joined": True},
                        "command_exit_code": 0,
                        "rust_event": {
                            "server_first": True,
                            "payload_bytes": 65536,
                            "tail_bytes": 14,
                            "protect_calls": 1,
                            "driver_joined": True,
                            "resources_idle": True,
                            "resources": idle,
                        },
                        "origin": {
                            "finished": True,
                            "accepted": 1,
                            "received": 65536,
                            "failed": False,
                        },
                    }
                )
        peers = [
            {
                "kind": kind,
                "status": "READY",
                "version": "offline-fixture",
                "source_url": "https://github.com/fixture/project/releases/latest/download/fixture",
                "archive_sha256": "0" * 64,
                "binary_sha256": "1" * 64,
                "release": "fixture",
                "container_status": "READY",
                "container_artifact": {"binary_sha256": "2" * 64, "release": "fixture"},
            }
            for kind in ["M", "V2"]
        ]
        commands = [
            "rust-foundations",
            "native-probe-build",
            "legacy-mihomo",
            "offline-scripts",
            "feature-default",
            "feature-minimal",
            "feature-outbound-trojan",
            "feature-outbound-vmess",
            "feature-outbound-hysteria2",
            "feature-outbound-wireguard",
            "feature-stream-transport",
            "feature-quic-transport",
        ]
        return {
            "run.json": {
                "stage": "N1",
                "mode": "execute",
                "source_unchanged": True,
                "cleanup": True,
                "selected_cases": [case["case_id"] for case in cases],
                "source_tree_sha256": "0" * 64,
                "lock_sha256": "1" * 64,
                "dirty_patch_sha256": "2" * 64,
                "commands": [
                    {"name": name, "exit_code": 0, "cleanup": True} for name in commands
                ],
            },
            "cases.json": results,
            "peers.json": peers,
            "rust-events.jsonl": events,
            "legacy-events.jsonl": legacy,
            "resources.jsonl": [{"resources": idle}],
            "summary.md": "Offline fixture only",
            "native/stream-cases.json": {
                "cases": native,
                "cleanup": True,
                "peers": peers,
                "abnormal_cleanup": {
                    "passed": True,
                    "kind": "M",
                    "failure_injected": True,
                    "joined": True,
                    "port_rebound": True,
                },
            },
            "script-tests.json": {
                "tests_run": len(set(SCRIPT_OBSERVATIONS.values())),
                "cases": [
                    {"test": name, "status": "PASS"}
                    for name in sorted(set(SCRIPT_OBSERVATIONS.values()))
                ],
            },
        }

    def write_fixture(self, directory, data):
        artifacts = []
        for name, value in data.items():
            if name == "run.json":
                continue
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            text = (
                "".join(json.dumps(item) + "\n" for item in value)
                if name.endswith(".jsonl")
                else value
                if name.endswith(".md")
                else json.dumps(value)
            )
            path.write_text(text)
            artifacts.append(
                {"path": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            )
        (directory / "run.json").write_text(
            json.dumps(data["run.json"] | {"artifacts": artifacts})
        )

    def test_complete_original_evidence_is_required_even_when_summary_claims_pass(self):
        fixture = self.fixture()
        with (
            tempfile.TemporaryDirectory() as temporary,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            directory = Path(temporary)
            self.write_fixture(directory, fixture)
            check_run(directory, "N1")
            for mutation in [
                "raw-event",
                "nonidle",
                "command",
                "peer",
                "artifact",
                "quiet",
                "script",
            ]:
                data = copy.deepcopy(fixture)
                if mutation == "raw-event":
                    data["rust-events.jsonl"][1]["status"] = "FAIL"
                elif mutation == "nonidle":
                    data["resources.jsonl"][0]["resources"]["counts"][0]["current"] = 1
                elif mutation == "command":
                    data["run.json"]["commands"][0]["exit_code"] = 124
                elif mutation == "peer":
                    data["peers.json"][0]["status"] = "BLOCKED"
                elif mutation == "artifact":
                    del data["rust-events.jsonl"]
                elif mutation == "quiet":
                    for event in data["rust-events.jsonl"]:
                        if event["suite"] == "N1-RESOURCES":
                            event["checkpoints"] = []
                else:
                    data["script-tests.json"]["cases"][0]["status"] = "NOT RUN"
                self.write_fixture(directory, data)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    check_run(directory, "N1")

    def test_content_tampering_partial_runs_and_preflight_cannot_sign_off(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            data = self.fixture()
            self.write_fixture(directory, data)
            (directory / "summary.md").write_text("tampered")
            with self.assertRaises(ValueError):
                check_run(directory, "N1")
            for change in [
                {"selected_cases": []},
                {"mode": "preflight"},
                {"source_unchanged": False},
            ]:
                data["run.json"].update(change)
                self.write_fixture(directory, data)
                with self.assertRaises(ValueError):
                    check_run(directory, "N1")
