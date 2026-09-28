"""Official Hysteria, with redirection confined to an owned Linux container."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import tempfile
import time
import urllib.request
from pathlib import Path

from .builds import CORE_DIR
from .protocol_containers import NETWORK, ContainerLab, ContainerPeer, command
from .protocol_evidence import read_events
from .protocol_fixtures import certificates
from .protocol_hysteria2_catalog import events_pass
from .protocol_inputs import redact, source_identity
from .protocol_peers import run_command


def guest(peer, *argv, timeout=30):
    # Container CLI can exit zero even when its guest command fails.
    result = run_command(
        [
            "container",
            "exec",
            peer.name,
            "/bin/sh",
            "-c",
            '"$@" 2>&1\ncode=$?\nprintf "\\nVCORE_STATUS=%s\\n" "$code"',
            "fixture",
            *argv,
        ],
        timeout=timeout,
    )
    output = result.stdout.decode(errors="replace")
    if result.returncode != 0 or not result.cleanup:
        raise RuntimeError(
            f"isolated guest {argv[0]} failed after {result.seconds:.1f}s "
            f"(exit={result.returncode}, cleanup={result.cleanup}): "
            f"{redact(output[-2048:])}"
        )
    body, marker, code = output.rpartition("\nVCORE_STATUS=")
    if not marker or code.strip() != "0":
        raise RuntimeError(
            f"isolated guest operation failed: {argv[0]}: {redact(body[-2048:])}"
        )
    return body


def native_binary(output):
    url = "https://github.com/HyNetworks/hysteria/releases/latest/download/hysteria-linux-arm64"
    path = output / "hysteria"
    digest, total, deadline = hashlib.sha256(), 0, time.monotonic() + 90
    request = urllib.request.Request(url, headers={"User-Agent": "VCore-interop"})
    with (
        urllib.request.urlopen(request, timeout=30) as response,
        path.open("xb") as target,
    ):
        if not response.geturl().startswith("https://"):
            raise RuntimeError("native download redirected outside HTTPS")
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > 128 * 1024 * 1024 or time.monotonic() > deadline:
                raise RuntimeError("native binary download budget exceeded")
            target.write(chunk)
            digest.update(chunk)
    path.chmod(0o755)
    return path, {"source_url": url, "binary_sha256": digest.hexdigest()}


def packages(lab, stack, root):
    """Only package preparation has external egress; no server runs there."""
    root.mkdir()
    peer = ContainerPeer(lab, root, "hysteria2-packages")
    lab.record["peers"].append(peer.record)
    stack.callback(peer.stop)
    command(
        "run",
        "--detach",
        "--name",
        peer.name,
        "--label",
        f"purpose={NETWORK}",
        "--label",
        f"vcore-run={lab.run_id}",
        "--network",
        "default",
        "--arch",
        "arm64",
        "--cpus",
        "1",
        "--memory",
        "256M",
        "--mount",
        f"type=bind,source={root},target=/packages",
        "--entrypoint",
        "/bin/sleep",
        lab.image,
        "360",
        timeout=45,
    )
    peer.record.update(
        started=True, role="package-preparation-only", network_mode="default"
    )
    guest(peer, "apk", "update", timeout=60)
    guest(
        peer,
        "apk",
        "fetch",
        "--recursive",
        "--output",
        "/packages",
        "nftables",
        timeout=240,
    )
    found = sorted(root.glob("*.apk"))
    if not found:
        raise RuntimeError("missing native firewall packages")
    lab.record["firewall_packages"] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in found
    }
    peer.stop()
    return found


def run(
    output: Path,
    *,
    ipv6=False,
    obfs=False,
    random_interval=False,
    test="native_hopping",
    supplied=None,
):
    if test not in {
        "native_hopping",
        "native_udp_disabled",
        "native_hop_protect_rejection",
        "native_stop_during_hop",
    }:
        raise ValueError("unknown native H gate")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        stage="HYSTERIA2",
        scope="incremental-native-H",
        source=source_identity(),
        status="NOT RUN",
        isolation={},
        cases=[],
        ipv6=ipv6,
        obfs=obfs,
        random_interval=random_interval,
    )
    try:
        if supplied is None:
            binary, report["peer"] = native_binary(output)
        else:
            binary, report["peer"], _, _ = supplied
            if (
                hashlib.sha256(binary.read_bytes()).hexdigest()
                != report["peer"]["binary_sha256"]
            ):
                raise RuntimeError("supplied H artifact identity mismatch")
        lab = ContainerLab(report["isolation"], mtu=1500)
        with (
            tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary,
            contextlib.ExitStack() as stack,
        ):
            root = Path(temporary)
            root.chmod(0o700)
            if supplied is None:
                apks = packages(lab, stack, root / "apks")
            else:
                _, _, apks, digests = supplied
                if {
                    p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in apks
                } != digests:
                    raise RuntimeError("supplied firewall package identity mismatch")
                report["isolation"]["firewall_packages"] = digests
            origin_dir, server_dir = root / "origin", root / "server"
            origin_dir.mkdir()
            server_dir.mkdir()
            shutil.copyfile(
                Path(__file__).with_name("container_udp_origin.py"),
                origin_dir / "origin.py",
            )
            shutil.copy2(binary, server_dir / "hysteria")
            (server_dir / "apks").mkdir()
            for path in apks:
                shutil.copy2(path, server_dir / "apks" / path.name)
            cert, key, pin = certificates(server_dir)
            origin = lab.start(
                stack,
                origin_dir,
                "hysteria2-h-origin",
                [
                    "env",
                    "VCORE_ISOLATED_ORIGIN=1",
                    "python",
                    "-B",
                    "/data/fixture/origin.py",
                ],
            )
            server = lab.start(
                stack,
                server_dir,
                "hysteria2-h-peer",
                [
                    "env",
                    "HYSTERIA_FIREWALL_BACKEND=nftables",
                    "/data/fixture/hysteria",
                    "server",
                    "--disable-update-check",
                    "--log-format",
                    "json",
                    "-c",
                    "/data/fixture/config.json",
                ],
                net_admin=True,
            )
            guest(
                server,
                "apk",
                "add",
                "--no-network",
                *[f"/data/fixture/apks/{path.name}" for path in apks],
                timeout=45,
            )
            report["peer"]["version"] = guest(
                server, "/data/fixture/hysteria", "version"
            ).strip()
            if (
                guest(server, "sha256sum", "/data/fixture/hysteria").split()[0]
                != report["peer"]["binary_sha256"]
            ):
                raise RuntimeError("native binary identity mismatch")
            report["isolation"]["nftables"] = guest(server, "nft", "--version").strip()
            (server_dir / "hosts").write_text(
                "127.0.0.1 localhost\n::1 localhost\n"
                f"{origin.ipv4} vcore-fixture.test\n"
            )
            guest(server, "cp", "/data/fixture/hosts", "/etc/hosts")
            # Pre-DNAT observations: native Hysteria owns its separate redirect table.
            rules = (
                "table inet vcore_hysteria2 { chain observe { "
                "type filter hook prerouting priority -150; policy accept; "
            )
            for port in range(23010, 23013):
                rules += f'udp dport {port} counter comment "p{port}"; '
            rules += "}\n}\n"
            (server_dir / "observe.nft").write_text(rules)
            guest(server, "nft", "-f", "/data/fixture/observe.nft")
            password = "synthetic-hysteria2-fixture"
            config = dict(
                # Native Hysteria deliberately treats [::] as IPv6-only.
                listen=f"[{server.ipv6}]:23010-23012"
                if ipv6
                else f"{server.ipv4}:23010-23012",
                tls=dict(
                    cert=f"/data/fixture/{cert.name}", key=f"/data/fixture/{key.name}"
                ),
                auth=dict(type="password", password=password),
                trafficStats=dict(listen="0.0.0.0:24003"),
            )
            node = dict(
                name="peer",
                type="hysteria2",
                server=server.ipv6 if ipv6 else server.ipv4,
                ports="23010-23012",
                **{"hop-interval": "5-7" if random_interval else 5},
                password=password,
                udp=True,
                sni="localhost",
                fingerprint=pin,
            )
            if obfs:
                config["obfs"] = dict(
                    type="salamander",
                    salamander=dict(password="independent-obfs-fixture"),
                )
                node.update(
                    obfs="salamander", **{"obfs-password": "independent-obfs-fixture"}
                )
            if test == "native_udp_disabled":
                config["disableUDP"] = True
            (server_dir / "config.json").write_text(json.dumps(config))
            fixture = root / "input.json"
            fixture.write_text(
                json.dumps(
                    dict(
                        isolation="containers",
                        origin_control=f"{origin.ipv4}:24000",
                        origin_ipv4=origin.ipv4,
                        origin_ipv6=origin.ipv6,
                        node=node,
                    )
                )
            )
            origin.release()
            server.release()
            origin.wait_tcp(24000)
            server.wait_tcp(24003)
            result = run_command(
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--all-features",
                    "--test",
                    "hysteria2_native",
                    test,
                    "--",
                    "--ignored",
                    "--exact",
                    "--nocapture",
                ],
                cwd=CORE_DIR,
                timeout=180,
                limit=4 * 1024 * 1024,
                env=dict(
                    os.environ,
                    VCORE_VLESS_INPUT=str(fixture),
                    VCORE_CASE_EVENTS=str(output / "hysteria2-events.jsonl"),
                    VCORE_HOP_OBSERVATIONS=str(output / "hopping.json"),
                ),
            )
            (output / "test.log").write_text(
                redact(result.stdout.decode(errors="replace"))
            )
            raw_log = command("logs", server.name)
            connected = sum(
                '"msg":"client connected"' in line for line in raw_log.splitlines()
            )
            report["auth_connections"] = connected
            (output / "server.log").write_text(
                redact(raw_log.replace(password, "<fixture-auth>"))
            )
            rules = json.loads(
                guest(server, "nft", "-j", "list", "table", "inet", "vcore_hysteria2")
            )
            counts = {}
            for entry in rules["nftables"]:
                if "rule" in entry:
                    rule = entry["rule"]
                    counts[rule["comment"]] = next(
                        item["counter"]["packets"]
                        for item in rule["expr"]
                        if "counter" in item
                    )
            report["entry_port_packets"] = counts
            passed = (
                result.returncode == 0
                and result.cleanup
                and (output / "hysteria2-events.jsonl").exists()
                and events_pass(read_events(output / "hysteria2-events.jsonl"), test)
                and connected == 1
                and sum(value > 0 for value in counts.values())
                >= (2 if test == "native_hopping" else 1)
            )
            report["cases"].append(
                dict(
                    case_id=test,
                    exit_code=result.returncode,
                    seconds=result.seconds,
                    command_cleanup=result.cleanup,
                    command=[
                        "cargo",
                        "test",
                        "--locked",
                        "--all-features",
                        "--test",
                        "hysteria2_native",
                        test,
                        "--",
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ],
                    status="PASS" if passed else "FAIL",
                )
            )
            report["status"] = "PASS" if passed else "FAIL"
    except (OSError, RuntimeError, ValueError) as error:
        report.update(
            status="FAIL",
            reason=str(error)
            if isinstance(error, RuntimeError)
            else type(error).__name__,
        )
    finally:
        report["cleanup"] = all(
            peer["joined"] for peer in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        if not report["source_unchanged"] or not report["cleanup"]:
            report["status"] = "FAIL"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


if __name__ == "__main__":
    import sys

    result = run(
        Path(sys.argv[1]),
        ipv6="--ipv6" in sys.argv,
        obfs="--salamander" in sys.argv,
        random_interval="--random" in sys.argv,
        test=(
            sys.argv[sys.argv.index("--test") + 1]
            if "--test" in sys.argv
            else "native_udp_disabled"
            if "--udp-disabled" in sys.argv
            else "native_hopping"
        ),
    )
    print(
        json.dumps(
            {
                key: result.get(key)
                for key in (
                    "status",
                    "reason",
                    "cleanup",
                    "cases",
                    "auth_connections",
                    "entry_port_packets",
                )
            }
        )
    )
    raise SystemExit(0 if result["status"] == "PASS" and result["cleanup"] else 1)
