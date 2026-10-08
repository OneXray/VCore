"""One complete CLI/native-library release set; publication belongs to CI."""

from __future__ import annotations

import argparse
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
    source = cli_release._release_info(root, tag)
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
        "release output must be separate from the input archives",
    )
    _require(
        not (root / notes_path).resolve().is_relative_to(output.resolve()),
        "release notes must be outside the asset directory",
    )
    archives = sorted(path for path in incoming.glob("*/*") if path.is_file())
    _require(
        len(archives) == len(ASSETS) and {path.name for path in archives} == ASSETS,
        "release requires exactly the fourteen CLI/FFI archives",
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
        "Archives include the public native headers where applicable; "
        "standalone license files and checksum files "
        "are not release assets.\n\n"
        f"[Vole source and license]({commit}) · "
        f"[Locked dependency sources]({commit}/Cargo.lock)\n\n"
        "Windows CLI uses Wintun. Wintun requires a host-provided wintun.dll with the "
        "same architecture; the driver is not bundled. The host owns addresses, DNS, "
        "routes and physical-egress isolation. UWP package installation and device "
        "acceptance remain separate from these build checks.\n"
    )
    notes_path = root / notes_path
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
