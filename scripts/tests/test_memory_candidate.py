import json
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.memory_candidate import read
from vcore_scripts.memory_inputs import save
from vcore_scripts.memory_matrix import select_stress
from vcore_scripts.protocol_inputs import sha256


class CandidateTests(unittest.TestCase):
    def test_stress_selection_waits_for_every_protocol_group(self):
        rows = [
            {
                "id": "protocol-socks-anytls-v4",
                "status": "PASS",
                "peak": {"profile": "anytls", "value": 10},
                "cpu": {"profile": "anytls", "value": 3},
            },
            {
                "id": "protocol-tun-socks5-v6",
                "status": "NOT RUN",
                "peak": {"profile": "socks5", "value": 20},
                "cpu": {"profile": "socks5", "value": 2},
            },
        ]
        self.assertIsNone(select_stress(rows))
        rows[1]["status"] = "PASS"
        selected = select_stress(rows)
        self.assertEqual(selected["highest-memory-soak"]["profile"], "socks5")
        self.assertEqual(selected["highest-cpu-pressure"]["profile"], "anytls")

    def test_frozen_candidate_rejects_changed_inputs_and_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "artifacts").mkdir()
            binary = root / "artifacts/host"
            binary.write_bytes(b"frozen host")
            source = {"parent_commit": "frozen"}
            save(
                root / "manifest.json",
                {
                    "ready": True,
                    "source": source,
                    "files": {"artifacts/host": sha256(binary)},
                },
            )
            save(root / "matrix.json", {"groups": []})
            save(
                root / "candidate.json",
                {
                    "manifest_sha256": sha256(root / "manifest.json"),
                    "matrix_sha256": sha256(root / "matrix.json"),
                },
            )
            self.assertEqual(read(root, source)["source"], source)
            with self.assertRaisesRegex(ValueError, "source"):
                read(root, {"parent_commit": "changed"})
            binary.write_bytes(b"changed host")
            with self.assertRaisesRegex(ValueError, "input/artifact"):
                read(root, source)

    def test_candidate_rejects_evidence_paths_outside_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            save(
                root / "manifest.json",
                {"ready": True, "source": {}, "files": {"../outside": "not a hash"}},
            )
            save(root / "matrix.json", {})
            save(
                root / "candidate.json",
                {
                    "manifest_sha256": sha256(root / "manifest.json"),
                    "matrix_sha256": sha256(root / "matrix.json"),
                },
            )
            with self.assertRaisesRegex(ValueError, "input/artifact"):
                read(root, {})
            self.assertEqual(json.loads((root / "matrix.json").read_text()), {})
