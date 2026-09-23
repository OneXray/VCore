"""N3 wire gate against a freshly downloaded, owned official Mihomo process."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run, reserve_port
from .protocol_evidence import read_events
from .protocol_inputs import redact, source_identity
from .protocol_peers import OwnedProcess, run_command
from .protocol_preflight import preflight


def run(output: Path):
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "stage": "N3",
        "scope": "wire-only",
        "source": source_identity(),
        "status": "NOT RUN",
        "cleanup": {},
    }
    try:
        artifacts, report["preflight"] = preflight(output / "binaries", {"M"})
        if "M" not in artifacts:
            report["status"] = "BLOCKED"
            return 1
        artifact = artifacts["M"]
        report["peer"] = artifact.identity
        with (
            tempfile.TemporaryDirectory(prefix="private-", dir=output) as directory,
            contextlib.ExitStack() as stack,
        ):
            directory = Path(directory)
            port, reservation = reserve_port(stack)
            config = {
                "mode": "rule",
                "log-level": "silent",
                "ipv6": True,
                "listeners": [
                    {
                        "name": "n3",
                        "type": "vmess",
                        "listen": "127.0.0.1",
                        "port": port,
                        "users": [
                            {
                                "username": "fixture",
                                "uuid": "07070707-0707-0707-0707-070707070707",
                                "alterId": 0,
                            }
                        ],
                    }
                ],
                "rules": ["MATCH,DIRECT"],
            }
            path = directory / "peer.json"
            path.write_text(json.dumps(config))
            reservation.release_ipv4()
            with OwnedProcess(
                [str(artifact.binary), "-d", str(directory), "-f", str(path)],
                directory / "peer.log",
                report["cleanup"],
            ) as peer:
                peer.wait_tcp(port)
                events = output / "events.jsonl"
                command = [
                    "cargo",
                    "test",
                    "--locked",
                    "--all-features",
                    "--test",
                    "vmess_native",
                    "--",
                    "--ignored",
                    "--test-threads=1",
                    "--nocapture",
                ]
                result = run_command(
                    command,
                    cwd=CORE_DIR,
                    env=dict(
                        os.environ,
                        VCORE_VMESS_PEER=f"127.0.0.1:{port}",
                        VCORE_CASE_EVENTS=str(events),
                    ),
                    timeout=180,
                    limit=4 * 1024 * 1024,
                )
                (output / "native.log").write_text(
                    redact(result.stdout.decode(errors="replace"))
                )
                observed = read_events(events) if events.exists() else []
                report.update(
                    command=command,
                    exit_code=result.returncode,
                    command_cleanup=result.cleanup,
                    seconds=result.seconds,
                    status="PASS"
                    if result.returncode == 0
                    and result.cleanup
                    and observed
                    == [
                        dict(
                            schema_version=1,
                            suite="N3-WIRE",
                            assertion=assertion,
                            status=status,
                        )
                        for assertion in (
                            "native_cipher_matrix",
                            "native_identity_time_replay_rejection",
                        )
                        for status in ("BEGIN", "PASS")
                    ]
                    else "FAIL",
                )
                peer.ensure_alive()
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        return (
            0
            if report["status"] == "PASS"
            and report["source_unchanged"]
            and report["cleanup"].get("joined")
            else 1
        )
    finally:
        (output / "vmess-results.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    with exclusive_run():
        sys.exit(run(Path(sys.argv[1]).resolve()))
