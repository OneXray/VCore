"""N7.1 incremental wire gate; not public YAML or complete stage acceptance."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .protocol_containers import ContainerLab, command
from .protocol_inputs import redact, same_source, source_identity
from .protocol_peers import run_command


def cases():
    return {
        f"{style}-{rtt}-{key}": (style, rtt, key)
        for style in ("native", "xorpub", "random")
        for rtt in ("1rtt", "0rtt")
        for key in ("x25519", "mlkem", "mixed")
    }


def encode(value):
    return base64.urlsafe_b64encode(bytes.fromhex(value)).decode().rstrip("=")


def run(
    output: Path,
    selected=None,
    *,
    consumer=False,
    chacha=False,
    expiry=False,
    padding="minimal",
):
    output = output.resolve()
    required = cases()
    if expiry:
        required = {
            name: value for name, value in required.items() if value[1] == "0rtt"
        }
    paddings = {
        "minimal": ".100-35-35",
        "default": "",
        "fragmented": ".100-35-35.100-1-1.100-47-47",
        "maximum": ".100-65553-65553",
    }
    selected = list(required) if selected is None else selected
    if (
        output.parent != CORE_DIR / "target/interop/runs"
        or not selected
        or len(set(selected)) != len(selected)
        or not set(selected) <= required.keys()
        or padding not in paddings
        or (consumer and (chacha or expiry))
    ):
        raise ValueError("fresh run directory and known unique cases required")
    output.mkdir(parents=True, exist_ok=False)
    if expiry:
        test = "native_ticket_expiry"
        marker = "N7-ENCRYPTION-EXPIRY-PASS full-resumed-expired-full-resumed"
    elif consumer:
        test = "public_tcp_roundtrip"
        marker = "N7-ENCRYPTION-CONSUMER-PASS rounds=4 bytes_per_direction=10485760"
    else:
        test = "native_encryption_roundtrip"
        marker = "N7-ENCRYPTION-WIRE-PASS rounds=4 bytes_per_direction=10485760"
    report = dict(
        stage="N7.1-wire",
        scope="public-config-and-outbound" if consumer else "native-wire-only",
        cipher="chacha20-poly1305" if chacha else "cpu-selected",
        ticket_expiry=expiry,
        padding=padding,
        complete_selection=set(selected) == set(required),
        source=source_identity(),
        required=list(required),
        cases=[],
        isolation={},
        status="NOT RUN",
    )
    try:
        identity = {}
        binary = download_mihomo(
            "linux-arm64", directory=output / "binaries", identity=identity
        )
        report["peer"] = identity
        built = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "n7_encryption_wire",
                "--no-run",
            ],
            timeout=240,
        )
        (output / "build.log").write_text(redact(built.stdout.decode(errors="replace")))
        if built.returncode or not built.cleanup:
            raise RuntimeError("Encryption wire consumer build failed")
        vectors = json.loads(
            (CORE_DIR / "tests/protocols/encryption-crypto.json").read_text()
        )
        pairs = dict(
            x25519=(
                encode(vectors["x25519_public"]),
                encode(vectors["x25519_private"]),
            ),
            mlkem=(encode(vectors["mlkem_public"]), encode(vectors["mlkem_seed"])),
        )
        pairs["mixed"] = tuple(
            ".".join((pairs["x25519"][i], pairs["mlkem"][i], pairs["x25519"][i]))
            for i in (0, 1)
        )
        lab = ContainerLab(report["isolation"], mtu=1500)
        with (
            tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary,
            contextlib.ExitStack() as stack,
        ):
            root = Path(temporary)
            server_dir, origin_dir = root / "server", root / "origin"
            server_dir.mkdir()
            origin_dir.mkdir()
            shutil.copy2(binary, server_dir / "peer")
            shutil.copy2(
                Path(__file__).with_name("container_udp_origin.py"),
                origin_dir / "origin.py",
            )
            origin = lab.start(
                stack,
                origin_dir,
                "n7-e-origin",
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
                "n7-e-mihomo",
                [
                    "/data/fixture/peer",
                    "-d",
                    "/data/mihomo",
                    "-f",
                    "/data/fixture/config.json",
                ],
            )
            listeners = []
            for index, name in enumerate(selected):
                style, _, key = required[name]
                lifetime = "2-3s" if expiry else "600s"
                listeners.append(
                    dict(
                        name=f"encryption-{index}",
                        type="vless",
                        listen="::",
                        port=23000 + index,
                        users=[
                            dict(
                                username="fixture",
                                uuid="07070707-0707-0707-0707-070707070707",
                            )
                        ],
                        decryption=(
                            f"mlkem768x25519plus.{style}.{lifetime}."
                            f"{pairs[key][1]}{paddings[padding]}"
                        ),
                    )
                )
                # A distinct native handler has no tickets from the primary.
                # It exercises genuine unknown-ticket rejection without
                # patching the peer, restarting it, or replaying business data.
                listeners.append(
                    {
                        **listeners[-1],
                        "name": f"encryption-fresh-{index}",
                        "port": 23100 + index,
                    }
                )
            (server_dir / "config.json").write_text(
                json.dumps(
                    dict(
                        ipv6=True,
                        **{"log-level": "silent"},
                        listeners=listeners,
                        rules=["MATCH,DIRECT"],
                        hosts={"vcore-fixture.test": origin.ipv4},
                    )
                )
            )
            origin.release()
            origin.wait_tcp(24000)
            server.release()
            for index in range(len(selected)):
                server.wait_tcp(23000 + index)
                server.wait_tcp(23100 + index)
            identity["version"] = command(
                "exec", server.name, "/data/fixture/peer", "-v"
            ).strip()
            if (
                command("exec", server.name, "sha256sum", "/data/fixture/peer").split()[
                    0
                ]
                != identity["binary_sha256"]
            ):
                raise RuntimeError("Mihomo binary identity mismatch")
            for index, name in enumerate(selected):
                style, rtt, key = required[name]
                encryption = (
                    f"mlkem768x25519plus.{style}.{rtt}."
                    f"{pairs[key][0]}{paddings[padding]}"
                )
                fixture = root / "input.json"
                fixture.write_text(
                    json.dumps(
                        dict(
                            isolation="containers",
                            encryption=encryption,
                            force_chacha=chacha,
                            ticket_expiry=expiry,
                            node=dict(
                                name="edge",
                                type="vless",
                                server=server.ipv4,
                                port=23000 + index,
                                uuid="07070707-0707-0707-0707-070707070707",
                                udp=True,
                                encryption=encryption,
                            ),
                            origin_control=f"{origin.ipv4}:24000",
                            origin_ipv4=origin.ipv4,
                            origin_ipv6=origin.ipv6,
                            server_ipv4=server.ipv4,
                            server_ipv6=server.ipv6,
                            port=23000 + index,
                            reject_port=23100 + index,
                        )
                    )
                )
                argv = [
                    "cargo",
                    "test",
                    "--locked",
                    "--all-features",
                    "--test",
                    "n7_encryption_wire",
                    test,
                    "--",
                    "--ignored",
                    "--exact",
                    "--nocapture",
                ]
                result = run_command(
                    argv,
                    env={**os.environ, "VCORE_ENCRYPTION_FIXTURE": str(fixture)},
                    timeout=150,
                )
                text = result.stdout.decode(errors="replace")
                (output / f"{name}.log").write_text(redact(text))
                passed = (
                    result.returncode == 0
                    and result.cleanup
                    and marker in text
                    and "1 passed; 0 failed; 0 ignored" in text
                )
                report["cases"].append(
                    dict(
                        case_id=name,
                        command=argv,
                        returncode=result.returncode,
                        cleanup=result.cleanup,
                        status="PASS" if passed else "FAIL",
                    )
                )
                print(f"{name}: {'PASS' if passed else 'FAIL'}", flush=True)
                if not passed:
                    raise RuntimeError("Encryption wire gate failed")
                origin.ensure_alive()
                server.ensure_alive()
        report["status"] = "PASS"
    except KeyboardInterrupt:
        report["status"] = "INTERRUPTED"
    except Exception as error:
        report["status"] = "FAIL"
        report["error"] = redact(str(error))
    finally:
        report["source_after"] = source_identity()
        report["source_unchanged"] = same_source(
            report["source"], report["source_after"]
        )
        report["cleanup"] = all(
            peer.get("joined", False) for peer in report["isolation"].get("peers", [])
        )
        if not report["source_unchanged"] or not report["cleanup"]:
            report["status"] = "FAIL"
        (output / "encryption-results.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("cases", nargs="*")
    parser.add_argument("--consumer", action="store_true")
    parser.add_argument("--chacha", action="store_true")
    parser.add_argument("--expiry", action="store_true")
    parser.add_argument(
        "--padding",
        choices=("minimal", "default", "fragmented", "maximum"),
        default="minimal",
    )
    args = parser.parse_args()
    with exclusive_run():
        sys.exit(
            run(
                args.output,
                args.cases or None,
                consumer=args.consumer,
                chacha=args.chacha,
                expiry=args.expiry,
                padding=args.padding,
            )
        )
