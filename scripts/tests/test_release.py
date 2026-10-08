"""The workflow assembles archive files, without build receipts or reinspection."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vole_scripts import builds, cli_release, ffi_release, release

INFO = {"tag": "v1.2.3", "version": "1.2.3", "commit": "a" * 40}


def complete_set(root):
    incoming = root / "dist/incoming"
    for index, name in enumerate(sorted(release.ASSETS)):
        path = incoming / str(index) / name
        path.parent.mkdir(parents=True)
        path.write_bytes(name.encode())
    return incoming


class ReleaseTest(unittest.TestCase):
    def test_complete_set_copies_fourteen_archives_and_writes_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incoming = complete_set(root)
            output = root / "dist/ready/assets"
            notes = output.parent / "notes.md"
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_release_info", return_value=INFO),
            ):
                paths = release.assemble_release("v1.2.3", incoming, output, notes)
            self.assertEqual(len(paths), 14)
            self.assertEqual({p.name for p in output.iterdir()}, release.ASSETS)
            for path in paths:
                self.assertEqual(path.read_bytes(), path.name.encode())
            self.assertIn("/tree/" + "a" * 40, notes.read_text())
            self.assertIn("Windows CLI uses Wintun", notes.read_text())

    def test_missing_duplicate_or_extra_archive_preserves_previous_output(self):
        for mutation in ("missing", "duplicate", "extra"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                incoming = complete_set(root)
                archive = next(incoming.glob("*/*"))
                if mutation == "missing":
                    archive.unlink()
                else:
                    extra = (
                        incoming
                        / "extra"
                        / (archive.name if mutation == "duplicate" else "manifest.json")
                    )
                    extra.parent.mkdir()
                    extra.write_bytes(b"extra")
                output = root / "dist/ready/assets"
                output.mkdir(parents=True)
                previous = output / "previous"
                previous.write_bytes(b"keep")
                with (
                    patch.object(builds, "CORE_DIR", root),
                    patch.object(cli_release, "_release_info", return_value=INFO),
                    self.assertRaisesRegex(ValueError, "fourteen"),
                ):
                    release.assemble_release(
                        None, incoming, output, output.parent / "notes.md"
                    )
                self.assertEqual(previous.read_bytes(), b"keep")

    def test_output_cannot_replace_input_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            incoming = complete_set(root)
            with (
                patch.object(builds, "CORE_DIR", root),
                patch.object(cli_release, "_release_info", return_value=INFO),
                self.assertRaisesRegex(ValueError, "separate from the input"),
            ):
                release.assemble_release(
                    None, incoming, incoming / "assets", root / "dist/notes.md"
                )

    def test_workflow_commands_allow_non_tag_builds_but_pin_release_features(
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
