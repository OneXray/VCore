"""Keep original license text and collect only linked runtime dependencies."""

import tempfile
import unittest
from pathlib import Path

from vole_scripts import notices


class NoticeTests(unittest.TestCase):
    def test_runtime_graph_skips_build_dependencies_and_proc_macros(self):
        packages = [
            {"id": name, "targets": [{"kind": [kind]}]}
            for name, kind in (
                ("core", "lib"),
                ("runtime", "lib"),
                ("build", "lib"),
                ("macro", "proc-macro"),
            )
        ]
        nodes = [{"id": p["id"], "deps": []} for p in packages]
        nodes[0]["deps"] = [
            {"pkg": name, "dep_kinds": [{"kind": kind}]}
            for name, kind in (("runtime", None), ("build", "build"), ("macro", None))
        ]
        graph = {"packages": packages, "resolve": {"root": "core", "nodes": nodes}}
        self.assertEqual(set(notices.linked_packages(graph)), {"core", "runtime"})

    def test_native_notices_preserve_original_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            native = root / "dependency"
            source = native / "deps/boringssl/LICENSE"
            source.parent.mkdir(parents=True)
            source.write_bytes(b"Native terms.\r\nCopyright upstream.\r\n")
            (root / "LICENSE").write_bytes(b"Project terms.\n")
            (native / "LICENSE-MIT").write_bytes(b"Binding terms.\n")
            package = {
                "name": "boring-sys",
                "version": "5.2.0",
                "license": "MIT",
                "manifest_path": str(native / "Cargo.toml"),
                "source": "git+https://github.com/YuanDevTeam/boring?branch=release#"
                + "a" * 40,
            }
            text = notices.collect_notices(
                {"native": package},
                {"native"},
                root,
                {"version": "1.2.3", "commit": "b" * 40},
                "YuanDevTeam/Vole",
                "aarch64-apple-darwin",
            )
            self.assertIn(source.read_bytes(), text)
            self.assertIn(b"Binding terms.\n", text)
            self.assertIn(b"boring/tree/" + b"a" * 40, text)
