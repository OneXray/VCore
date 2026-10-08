"""Unified release gates use real fourteen-archive fixture sets offline."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_cli_release import archive_set as cli_archives
from test_ffi_release import SOURCE, archive_set, elf, project

from vole_scripts import builds, cli_release, ffi_release, release


def complete_set(root: Path) -> Path:
    incoming = root / "dist/incoming"
    cli_archives(incoming, SOURCE)
    archive_set(incoming, root)
    return incoming


class ReleaseTest(unittest.TestCase):
    def test_complete_set_publishes_exactly_fourteen_fixed_archives(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            incoming = complete_set(root)
            output = root / "dist/ready/assets"
            notes = root / "dist/ready/notes.md"
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_source", return_value=SOURCE),
                patch.object(cli_release, "_audit_graph"),
            ):
                result = release.assemble_release("v1.2.3", incoming, output, notes)
            self.assertEqual(len(result), 14)
            self.assertEqual({path.name for path in output.iterdir()}, release.ASSETS)
            self.assertTrue(all(path.is_file() for path in result))
            self.assertIn("native libraries", notes.read_text())
            self.assertEqual(len(release.ASSETS), 14)
            self.assertFalse(any(path.suffix == ".json" for path in output.iterdir()))

    def test_missing_group_mixed_source_duplicates_and_extra_assets_never_replace_ready(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            incoming = complete_set(root)
            output = root / "dist/ready/assets"
            output.mkdir(parents=True)
            sentinel = output / "previous"
            sentinel.write_text("keep")
            notes = output.parent / "notes.md"
            windows = incoming / "ffi-windows-wintun-amd64/manifest.json"
            original = windows.read_text()
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_source", return_value=SOURCE),
                patch.object(cli_release, "_audit_graph"),
            ):
                windows.rename(windows.with_suffix(".missing"))
                with self.assertRaisesRegex(ValueError, "all six CLI and eight FFI"):
                    release.assemble_release("v1.2.3", incoming, output, notes)
                windows.with_suffix(".missing").rename(windows)
                record = json.loads(original)
                record["source"]["commit"] = "e" * 40
                windows.write_text(json.dumps(record))
                with self.assertRaisesRegex(ValueError, "release evidence"):
                    release.assemble_release("v1.2.3", incoming, output, notes)
                windows.write_text(original)
                duplicate = incoming / "ffi-windows-wintun-arm64/manifest.json"
                duplicate_original = duplicate.read_text()
                duplicate.write_text(original)
                with self.assertRaisesRegex(ValueError, "distinct FFI"):
                    release.assemble_release("v1.2.3", incoming, output, notes)
                duplicate.write_text(duplicate_original)
                extra = incoming / "checksums.txt"
                extra.write_text("unpublished")
                with self.assertRaisesRegex(ValueError, "unrecorded files"):
                    release.assemble_release("v1.2.3", incoming, output, notes)
            self.assertEqual(sentinel.read_text(), "keep")
            self.assertFalse(notes.exists())

    def test_actual_binary_architecture_is_rechecked_even_with_updated_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            incoming = complete_set(root)
            manifest = incoming / "ffi-linux-arm64/manifest.json"
            record = json.loads(manifest.read_text())
            archive = manifest.parent / ffi_release.archive_name("linux-arm64")
            staging = root / "dist/tamper"
            ffi_release._extract_archive(
                archive, staging, ffi_release._expected_files("linux-arm64")
            )
            binary = staging / "libvole.so"
            binary.write_bytes(elf(62))
            row = {
                "path": "libvole.so",
                "size": binary.stat().st_size,
                "sha256": cli_release._sha(binary),
            }
            for field in (record["artifacts"], record["delivery"]["artifacts"]):
                field[
                    field.index(
                        next(item for item in field if item["path"] == "libvole.so")
                    )
                ] = row
            ffi_release._write_archive(staging, archive)
            record["archive"] = {
                "name": archive.name,
                "size": archive.stat().st_size,
                "sha256": cli_release._sha(archive),
            }
            manifest.write_text(json.dumps(record))
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_source", return_value=SOURCE),
                patch.object(cli_release, "_audit_graph"),
                self.assertRaisesRegex(ValueError, "ELF type or architecture"),
            ):
                release.assemble_release(
                    "v1.2.3",
                    incoming,
                    root / "dist/ready/assets",
                    root / "dist/ready/notes.md",
                )
            self.assertFalse((root / "dist/ready").exists())

    def test_linked_job_directory_and_overlapping_output_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            incoming = complete_set(root)
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_source", return_value=SOURCE),
            ):
                with self.assertRaisesRegex(ValueError, "separate from the input"):
                    release.assemble_release(
                        "v1.2.3", incoming, incoming / "assets", root / "dist/notes.md"
                    )
                original = incoming / "ffi-apple"
                external = root / "dist/apple-fixture"
                original.rename(external)
                try:
                    original.symlink_to(external, target_is_directory=True)
                except OSError:
                    self.skipTest("symlink privilege is unavailable")
                with self.assertRaisesRegex(ValueError, "symlinks or reparse"):
                    release.assemble_release(
                        "v1.2.3",
                        incoming,
                        root / "dist/ready/assets",
                        root / "dist/notes.md",
                    )

    def test_source_change_before_assembly_keeps_previous_assets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkout"
            project(root)
            incoming = complete_set(root)
            output = root / "dist/ready/assets"
            output.mkdir(parents=True)
            (output / "previous").write_text("keep")
            changed = copy.deepcopy(SOURCE)
            changed["lockSha256"] = "f" * 64
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_source", side_effect=[SOURCE, changed]),
                patch.object(cli_release, "_audit_graph"),
                self.assertRaisesRegex(ValueError, "source changed"),
            ):
                release.assemble_release(
                    "v1.2.3", incoming, output, root / "dist/notes.md"
                )
            self.assertEqual((output / "previous").read_text(), "keep")

    def test_workflow_commands_allow_clean_non_tag_builds_but_pin_release_features(
        self,
    ):
        with (
            patch(
                "sys.argv",
                [
                    "release",
                    "build-cli",
                    "--target",
                    "aarch64-pc-windows-msvc",
                    "--output",
                    "dist/release/cli-win",
                ],
            ),
            patch.object(cli_release, "build_release") as build,
        ):
            release.main()
            build.assert_called_once_with(
                "aarch64-pc-windows-msvc",
                None,
                "YuanDevTeam/Vole",
                Path("dist/release/cli-win"),
            )
        with (
            patch(
                "sys.argv",
                [
                    "release",
                    "build-ffi",
                    "--platform",
                    "windows",
                    "--target",
                    "x86_64-pc-windows-msvc",
                    "--backend",
                    "uwp",
                    "--tag",
                    "v1.2.3",
                ],
            ),
            patch.object(ffi_release, "build_release") as build,
        ):
            release.main()
            build.assert_called_once_with(
                "windows",
                "v1.2.3",
                "YuanDevTeam/Vole",
                target="x86_64-pc-windows-msvc",
                backend="uwp",
                output=Path("dist/release/ffi-windows-uwp-amd64"),
            )
        with (
            patch(
                "sys.argv",
                [
                    "release",
                    "assemble",
                    "--inputs",
                    "dist/incoming",
                    "--output",
                    "dist/ready/assets",
                    "--notes",
                    "dist/ready/notes.md",
                ],
            ),
            patch.object(release, "assemble_release", return_value=[]) as assemble,
        ):
            release.main()
            assemble.assert_called_once_with(
                None,
                Path("dist/incoming"),
                Path("dist/ready/assets"),
                Path("dist/ready/notes.md"),
                "YuanDevTeam/Vole",
            )


if __name__ == "__main__":
    unittest.main()
