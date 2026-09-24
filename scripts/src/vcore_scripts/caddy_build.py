"""Explicit xcaddy-only exception for the isolated H3/mTLS test gateway."""

from __future__ import annotations

import os
import re
import shutil
import urllib.parse
import urllib.request
from pathlib import Path

from .native_release import PeerArtifact
from .protocol_inputs import redact, sha256
from .protocol_peers import run_command


def latest_tag(project):
    """Official latest redirect, not the GitHub API or a pinned old tag."""
    if project not in ("caddy", "xcaddy"):
        raise ValueError("unsupported gateway project")
    url = f"https://github.com/caddyserver/{project}/releases/latest"
    request = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": "VCore-interop-scripts"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        final = urllib.parse.urlsplit(response.geturl())
    prefix = f"/caddyserver/{project}/releases/tag/"
    tag = final.path.removeprefix(prefix)
    if (
        final.scheme != "https"
        or final.netloc != "github.com"
        or final.query
        or final.fragment
        or not final.path.startswith(prefix)
        or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag)
    ):
        raise RuntimeError("cannot resolve official stable gateway release")
    return tag


def build_caddy(directory: Path):
    directory.mkdir(parents=True, exist_ok=False)
    xcaddy, go = shutil.which("xcaddy"), shutil.which("go")
    if not xcaddy or not go:
        raise RuntimeError("xcaddy and Go are required for the approved gateway build")
    versions = {project: latest_tag(project) for project in ("xcaddy", "caddy")}
    tool = run_command([xcaddy, "version"], timeout=10, limit=4096)
    if (
        tool.returncode
        or not tool.cleanup
        or tool.stdout.decode().split()[0] != versions["xcaddy"]
    ):
        raise RuntimeError(
            "installed xcaddy must match the official latest stable release"
        )
    compiler = run_command([go, "version"], timeout=10, limit=4096)
    if compiler.returncode or not compiler.cleanup:
        raise RuntimeError("cannot read Go build identity")
    temporary = directory / "build-work"
    temporary.mkdir()
    binary = directory / "caddy"
    environment = os.environ.copy()
    # A fresh standard-module build, never a local source replacement or plugin.
    for key in tuple(environment):
        if key.startswith("XCADDY_") or key in ("CADDY_VERSION", "GOFLAGS", "GOWORK"):
            environment.pop(key)
    environment.update(
        GOOS="linux",
        GOARCH="arm64",
        CGO_ENABLED="0",
        GOWORK="off",
        XCADDY_SKIP_CLEANUP="1",
        XCADDY_PRINT_VERSION="0",
        TMPDIR=str(temporary),
    )
    print("Building official latest Caddy with xcaddy for linux/arm64", flush=True)
    built = run_command(
        [xcaddy, "build", "latest", "--output", str(binary)],
        env=environment,
        cwd=directory,
        timeout=600,
        limit=4 * 1024 * 1024,
    )
    (directory / "build.log").write_text(redact(built.stdout.decode(errors="replace")))
    if built.returncode or not built.cleanup or not binary.is_file():
        raise RuntimeError("xcaddy gateway build failed")
    metadata = run_command([go, "version", "-m", str(binary)], timeout=10, limit=65536)
    info = metadata.stdout.decode(errors="replace")
    expected = f"\tdep\tgithub.com/caddyserver/caddy/v2\t{versions['caddy']}\t"
    if (
        metadata.returncode
        or not metadata.cleanup
        or expected not in info
        or "=>" in info
    ):
        raise RuntimeError("gateway build is not the unmodified official latest Caddy")
    # xcaddy deliberately uses cwd on macOS, TMPDIR on other hosts.
    manifests = [
        *directory.glob("buildenv_*/go.mod"),
        *temporary.glob("buildenv_*/go.mod"),
    ]
    if len(manifests) != 1:
        raise RuntimeError("xcaddy build manifest is missing or ambiguous")
    inputs = {}
    for name in ("go.mod", "go.sum", "main.go"):
        source = manifests[0].with_name(name)
        shutil.copyfile(source, directory / name)
        inputs[name] = sha256(source)
    # Omit the host executable path from the retained module metadata.
    (directory / "modules.txt").write_text("\n".join(info.splitlines()[1:]) + "\n")
    return PeerArtifact(
        binary,
        dict(
            kind="Caddy-xcaddy",
            target="linux-arm64",
            source_built=True,
            source_url="https://github.com/caddyserver/caddy/releases/latest",
            release=versions["caddy"],
            xcaddy_version=tool.stdout.decode().strip(),
            go_version=compiler.stdout.decode().strip(),
            binary_sha256=sha256(binary),
            build_seconds=built.seconds,
            build_cleanup=built.cleanup,
            inputs=inputs,
            extra_plugins=[],
            version=None,
        ),
    )
