"""One complete CLI/native-library release set; publication belongs to CI."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import tempfile
from pathlib import Path

from . import builds, cli_release, ffi_release

ASSETS = {cli_release.archive_name(target) for target in cli_release.TARGETS} | {
    ffi_release.archive_name(key) for key in ffi_release.RELEASES
}
_require = cli_release._require


def assemble_release(
    tag: str | None,
    incoming: Path,
    output: Path,
    notes_path: Path,
    repository: str = "YuanDevTeam/Vole",
) -> list[Path]:
    root = builds.CORE_DIR
    source = cli_release._source(root, tag)
    _require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
        "invalid public repository identity",
    )
    incoming = root / incoming
    output = root / output
    cli_release._guard_output(root, output)
    _require(
        not output.resolve().is_relative_to(incoming.resolve())
        and not incoming.resolve().is_relative_to(output.resolve()),
        "release output must be separate from the input evidence",
    )
    _require(
        not (root / notes_path).resolve().is_relative_to(output.resolve()),
        "release notes must be outside the asset directory",
    )
    files = ffi_release.tree_files(incoming)
    manifests = sorted(incoming.glob("*/manifest.json"))
    _require(
        len(manifests) == 14, "release requires all six CLI and eight FFI manifests"
    )
    seen_cli, seen_ffi, archives = set(), set(), []
    expected_files = set(manifests)
    for manifest in manifests:
        ffi_release.regular_file(manifest)
        record = json.loads(manifest.read_text(encoding="utf-8"))
        if record.get("kind") == "ffi":
            key = record.get("release")
            _require(
                key in ffi_release.RELEASES and key not in seen_ffi,
                "release requires eight distinct FFI identities",
            )
            seen_ffi.add(key)
            archive = ffi_release.inspect_release(manifest, source, root)
        else:
            target = record.get("target")
            _require(
                record.get("kind") in {None, "cli"}
                and target in cli_release.TARGETS
                and target not in seen_cli,
                "release requires six distinct CLI identities",
            )
            seen_cli.add(target)
            archive = cli_release.inspect_release(manifest, source, root)
        expected_files.add(archive)
        archives.append(archive)
    _require(
        seen_cli == set(cli_release.TARGETS) and seen_ffi == set(ffi_release.RELEASES),
        "release requires the complete CLI/FFI matrix",
    )
    _require(files == expected_files, "release inputs contain unrecorded files")
    _require(
        {path.name for path in archives} == ASSETS,
        "release requires exactly the fixed fourteen assets",
    )
    _require(
        cli_release._source(root, tag) == source,
        "source changed during release assembly",
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="vole-release-assemble-", dir=output.parent
    ) as directory:
        staged = Path(directory) / "assets"
        staged.mkdir()
        for archive in archives:
            destination = staged / archive.name
            shutil.copy2(archive, destination)
            _require(
                cli_release._sha(destination) == cli_release._sha(archive),
                "release asset changed while assembling",
            )
        if output.exists():
            shutil.rmtree(output)
        staged.rename(output)
    commit = f"https://github.com/{repository}/tree/{source['commit']}"
    notes = (
        f"Vole {source['version']} CLI and native libraries.\n\n"
        "The release contains six CLI archives "
        "(Linux, macOS and Windows; amd64/arm64), "
        "an Apple XCFramework, Android libraries with their matching C++ runtimes, "
        "two Linux library archives, and four Windows library archives "
        "(Wintun/UWP; amd64/arm64). Windows UWP includes both package hosts.\n\n"
        "Complete linked licenses and native notices are embedded in the Vole binaries "
        "between VOLE_RELEASE_NOTICES_BEGIN and VOLE_RELEASE_NOTICES_END. "
        "Archives include the public native headers where applicable; internal build "
        "manifests, standalone license files and checksum files "
        "are not release assets.\n\n"
        f"[Vole source and license]({commit}) · "
        f"[Locked dependency sources]({commit}/Cargo.lock)\n\n"
        "Windows CLI uses Wintun. Wintun requires a host-provided wintun.dll with the "
        "same architecture; the driver is not bundled. The host owns addresses, DNS, "
        "routes and physical-egress isolation. UWP package installation and device "
        "acceptance remain separate from these build checks.\n"
    )
    notes_path = root / notes_path
    if notes_path.exists():
        ffi_release.regular_file(notes_path)
    notes_path.parent.mkdir(parents=True, exist_ok=True)
    notes_path.write_text(notes, encoding="utf-8")
    return sorted(output / name for name in ASSETS)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    cli = commands.add_parser("build-cli")
    cli.add_argument("--target", choices=cli_release.TARGETS, required=True)
    cli.add_argument("--output", type=Path)
    ffi = commands.add_parser("build-ffi")
    ffi.add_argument(
        "--platform", choices=("apple", "android", "linux", "windows"), required=True
    )
    ffi.add_argument(
        "--target", choices=ffi_release.LINUX_TARGETS + ffi_release.WINDOWS_TARGETS
    )
    ffi.add_argument("--backend", choices=("wintun", "uwp"))
    ffi.add_argument("--output", type=Path)
    assemble = commands.add_parser("assemble")
    assemble.add_argument("--inputs", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument("--notes", type=Path, required=True)
    for command in (cli, ffi, assemble):
        command.add_argument("--tag")
        command.add_argument("--repository", default="YuanDevTeam/Vole")
    args = parser.parse_args()
    if args.command == "build-cli":
        output = args.output or Path("dist/release") / ("cli-" + args.target)
        cli_release.build_release(args.target, args.tag, args.repository, output)
    elif args.command == "build-ffi":
        key, _ = ffi_release.selection(args.platform, args.target, args.backend)
        output = args.output or Path("dist/release") / ("ffi-" + key)
        ffi_release.build_release(
            args.platform,
            args.tag,
            args.repository,
            target=args.target,
            backend=args.backend,
            output=output,
        )
    else:
        for path in assemble_release(
            args.tag, args.inputs, args.output, args.notes, args.repository
        ):
            print(path)


if __name__ == "__main__":
    main()
