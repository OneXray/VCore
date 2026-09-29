"""Native Apple consumers and owned-simulator smoke; never device acceptance."""

from __future__ import annotations

import contextlib
import json
import platform
import shutil
import signal
import subprocess
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from . import builds
from .mihomo_isolation import exclusive_run
from .protocol_containers import ContainerLab, frozen_image
from .protocol_inputs import same_source, sha256, source_identity
from .protocol_peers import run_command


def link_consumer(
    framework: Path,
    work: Path,
    target_os: str,
    *,
    simulator: bool,
    runtime: bool = False,
    minimum: str = "17.0",
) -> Path:
    """Link actual static-library contents, not just the exported header."""
    sdk = {
        ("tvos", False): "appletvos",
        ("tvos", True): "appletvsimulator",
        ("ios", False): "iphoneos",
        ("ios", True): "iphonesimulator",
    }[target_os, simulator]
    target = f"arm64-apple-{target_os}{minimum}" + ("-simulator" if simulator else "")
    # Xcode uses the platform spelling ios/tvos in XCFramework identifiers.
    identifier = (
        "ios-arm64_x86_64-simulator"
        if target_os == "ios" and simulator
        else f"{target_os}-arm64" + ("-simulator" if simulator else "")
    )
    library = framework / identifier / "libvcore.a"
    builds._require_identity(library, "Apple")
    builds.check_apple_binary(
        library,
        target_os,
        "simulator" if simulator else None,
        {"arm64", "x86_64"} if target_os == "ios" and simulator else {"arm64"},
        minimum,
    )
    work.mkdir(parents=True, exist_ok=True)
    executable = work / (sdk + ("-runtime" if runtime else "-abi"))
    sysroot = subprocess.check_output(
        ["xcrun", "--sdk", sdk, "--show-sdk-path"], text=True, timeout=30
    ).strip()
    compiler = [
        "xcrun",
        "--sdk",
        sdk,
        "clang",
        "-target",
        target,
        "-isysroot",
        sysroot,
        "-Wall",
        "-Wextra",
        "-Werror",
        "-I",
        str(library.parent / "Headers"),
    ]
    source = builds.CORE_DIR / "scripts/fixtures/platform_abi.c"
    if runtime:
        abi_object = work / (sdk + "-abi.o")
        subprocess.run(
            compiler
            + ["-Dmain=vcore_abi_smoke", "-c", str(source), "-o", str(abi_object)],
            check=True,
            timeout=60,
        )
        sources = [
            "-fobjc-arc",
            str(builds.CORE_DIR / "scripts/fixtures/apple_runtime.m"),
            str(abi_object),
        ]
    else:
        sources = [str(source)]
    subprocess.run(
        compiler
        + sources
        + [
            str(library),
            "-lc++",
            "-lresolv",
            "-framework",
            "Security",
            "-framework",
            "SystemConfiguration",
            "-framework",
            "CoreFoundation",
            "-framework",
            "Foundation",
            "-o",
            str(executable),
        ],
        check=True,
        timeout=120,
    )
    builds.check_apple_binary(
        executable,
        target_os,
        "simulator" if simulator else None,
        {"arm64"},
        minimum,
    )
    return executable


def _simctl(*arguments: str, timeout: int = 30) -> str:
    result = run_command(["xcrun", "simctl", *arguments], timeout=timeout)
    if result.returncode or not result.cleanup:
        raise RuntimeError(f"simctl {arguments[0]} failed ({result.returncode})")
    return result.stdout.decode(errors="replace")


@contextlib.contextmanager
def simulator(target_os: str, record: dict, *, minimum: str):
    runtimes = json.loads(_simctl("list", "runtimes", "--json"))["runtimes"]
    candidates = [
        r
        for r in runtimes
        if r.get("isAvailable")
        and f".{'tvOS' if target_os == 'tvos' else 'iOS'}-" in r["identifier"]
        and tuple(map(int, r["version"].split(".")))
        >= tuple(map(int, minimum.split(".")))
    ]
    if not candidates:
        raise RuntimeError(f"no installed {target_os} simulator runtime")
    runtime = max(candidates, key=lambda r: tuple(map(int, r["version"].split("."))))
    family = "Apple TV" if target_os == "tvos" else "iPhone"
    types = [t for t in runtime["supportedDeviceTypes"] if t["productFamily"] == family]
    if not types:
        raise RuntimeError(f"no compatible {target_os} simulator device type")
    device_type = types[0]["identifier"]
    name = "vcore-platform-" + uuid.uuid4().hex
    record.update(
        name=name,
        runtime={
            key: runtime[key] for key in ("identifier", "version", "buildversion")
        },
        device_type=device_type,
        cleaned=False,
    )
    # Cleanup is registered before creation: an interrupted create may still
    # have created a device, even if its UUID was never returned to this caller.
    try:
        identifier = _simctl("create", name, device_type, runtime["identifier"]).strip()
        record["udid"] = identifier
        _simctl("boot", identifier)
        _simctl("bootstatus", identifier, "-b", timeout=180)
        yield identifier
    finally:
        rows = json.loads(_simctl("list", "devices", "--json"))["devices"]
        for device in (
            d for group in rows.values() for d in group if d["name"] == name
        ):
            if device["state"] != "Shutdown":
                _simctl("shutdown", device["udid"], timeout=60)
            _simctl("delete", device["udid"], timeout=60)
        rows = json.loads(_simctl("list", "devices", "--json"))["devices"]
        record["cleaned"] = not any(
            d["name"] == name for group in rows.values() for d in group
        )
        if not record["cleaned"]:
            raise RuntimeError("owned simulator cleanup failed")


def run(target_os: str, manifest: Path | None = None) -> None:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("Apple runtime smoke requires native Apple Silicon macOS")
    framework = builds.CORE_DIR / "dist/apple/LibVCore.xcframework"
    source = source_identity()
    if manifest is not None:
        from .platform_delivery import check_delivery

        manifest = manifest.resolve()
        check_delivery([manifest])
        if json.loads(manifest.read_text())["group"] != "apple":
            raise ValueError("Apple runtime smoke requires an Apple manifest")
        framework = manifest.parent / "LibVCore.xcframework"
    root = builds.CORE_DIR / "target/platform-delivery/runtime"
    root.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=target_os + "-", dir=root))
    record = dict(
        kind="apple-simulator-runtime",
        platform=target_os,
        source=source,
        manifest_sha256=sha256(manifest) if manifest else None,
        isolation={},
        simulator={},
        result="FAIL",
        physical_device=False,
    )
    previous_signal = signal.getsignal(signal.SIGTERM)

    def interrupted(*_):
        raise KeyboardInterrupt("Apple runtime check interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        minimum = builds.tvos_deployment_target() if target_os == "tvos" else "13.0"
        if manifest:
            minimum = json.loads(manifest.read_text())["toolchain"][
                target_os + "DeploymentTarget"
            ]
        for simulated in (False, True):
            executable = link_consumer(
                framework,
                work,
                target_os,
                simulator=simulated,
                runtime=True,
                minimum=minimum,
            )
        record["consumer_sha256"] = sha256(executable)
        identifier = (
            "tvos-arm64-simulator"
            if target_os == "tvos"
            else "ios-arm64_x86_64-simulator"
        )
        library = framework / identifier / "libvcore.a"
        record["library_sha256"] = sha256(library)
        with exclusive_run(), frozen_image(work / "image.log") as image:
            record["image"] = image
            lab = ContainerLab(record["isolation"], mtu=1500)
            with contextlib.ExitStack() as stack:
                origin = work / "origin"
                origin.mkdir()
                shutil.copy2(
                    Path(__file__).with_name("container_udp_origin.py"),
                    origin / "origin.py",
                )
                peer = lab.start(
                    stack,
                    origin,
                    "apple-origin",
                    [
                        "env",
                        "VCORE_ISOLATED_ORIGIN=1",
                        "python",
                        "-B",
                        "/data/fixture/origin.py",
                    ],
                )
                peer.release()
                peer.wait_tcp(24000)
                device = stack.enter_context(
                    simulator(target_os, record["simulator"], minimum=minimum)
                )
                data = work / "data"
                data.mkdir()
                result = run_command(
                    [
                        "xcrun",
                        "simctl",
                        "spawn",
                        device,
                        str(executable),
                        str(data),
                        peer.ipv4,
                    ],
                    timeout=180,
                )
                (work / "runtime.log").write_bytes(result.stdout)
                record["process"] = dict(
                    exit_code=result.returncode,
                    joined=result.cleanup,
                    seconds=result.seconds,
                    reason=result.reason,
                )
                if (
                    result.returncode
                    or not result.cleanup
                    or b"PASS Apple runtime:" not in result.stdout
                ):
                    raise RuntimeError(
                        f"Apple runtime smoke failed; inspect {work / 'runtime.log'}"
                    )
                peer.ensure_alive()
                # The dedicated simulator contains no user application logs.
                # Query only VCore's bounded public diagnostics before deleting it.
                logs = _simctl(
                    "spawn",
                    device,
                    "log",
                    "show",
                    "--style",
                    "compact",
                    "--last",
                    "2m",
                    "--info",
                    "--debug",
                    "--predicate",
                    'subsystem == "io.github.onexray.vcore"',
                    timeout=60,
                )
                (work / "unified.log").write_text(logs)
                event = target_os + "_memory_snapshot"
                if (
                    event not in logs
                    or target_os + "_memory_measurement_failed" in logs
                    or any(
                        stage not in logs
                        for stage in (
                            "prepare-complete",
                            "start-complete",
                            "stage=running",
                            "stop-complete",
                        )
                    )
                ):
                    raise RuntimeError(
                        "Apple TUN lifecycle memory/logging evidence missing"
                    )
                record["tun_memory_events"] = logs.count(event)
        if (
            not same_source(source, source_identity())
            or sha256(library) != record["library_sha256"]
        ):
            raise RuntimeError("source or artifact changed during Apple runtime check")
        if manifest:
            check_delivery([manifest])
        record["result"] = "PASS"
    finally:
        signal.signal(signal.SIGTERM, previous_signal)
        record["finished_utc"] = datetime.now(UTC).isoformat()
        (work / "result.json").write_text(json.dumps(record, indent=2) + "\n")
        print(work / "result.json")
    print(
        f"PASS {target_os} simulator runtime; "
        "physical Network Extension and memory limit NOT RUN"
    )
