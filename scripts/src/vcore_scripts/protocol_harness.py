"""Unified N1 runner. Public protocol consumer acceptance belongs to later stages."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from .builds import CORE_DIR
from .mihomo import _run_mihomo_interop
from .mihomo_isolation import exclusive_run
from .protocol_catalogs import CATALOG_DIR, check_protocol_catalogs
from .protocol_evidence import (
    check_limit_references,
    check_run,
    idle_resources,
    load_manifest,
    new_result,
    read_events,
    read_json,
    rust_results,
    select_cases,
    validate_results,
)
from .protocol_inputs import redact, run_identity, sha256, source_identity
from .protocol_peers import run_command
from .protocol_preflight import preflight
from .protocol_streams import run_streams


@contextlib.contextmanager
def deadline(seconds: float):
    if not hasattr(signal, "SIGALRM"):
        raise RuntimeError("whole-suite watchdog requires a supported Unix test host")
    previous = signal.getsignal(signal.SIGALRM)

    def expired(*_):
        raise TimeoutError("protocol suite deadline expired")

    signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.getitimer(signal.ITIMER_REAL)
    started = time.monotonic()
    signal.setitimer(
        signal.ITIMER_REAL,
        min(seconds, previous_timer[0]) if previous_timer[0] > 0 else seconds,
    )
    try:
        yield
    finally:
        remaining = (
            max(0.001, previous_timer[0] - (time.monotonic() - started))
            if previous_timer[0] > 0
            else 0
        )
        signal.setitimer(signal.ITIMER_REAL, remaining, previous_timer[1])
        signal.signal(signal.SIGALRM, previous)


def _events(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return read_events(path)


def _command(
    run,
    output: Path,
    name: str,
    command: list[str],
    seconds: int,
    *,
    events: Path | None = None,
):
    env = dict(os.environ)
    env.pop("VCORE_CASE_EVENTS", None)
    if events:
        env["VCORE_CASE_EVENTS"] = str(events)
    print(f"N1: {name}", flush=True)
    result = run_command(
        command, cwd=CORE_DIR, env=env, timeout=seconds, limit=4 * 1024 * 1024
    )
    log = output / f"{name}.log"
    log.write_text(redact(result.stdout.decode("utf-8", errors="replace")))
    run["commands"].append(
        {
            "name": name,
            "command": [redact(str(part)) for part in command],
            "exit_code": result.returncode,
            "seconds": result.seconds,
            "cleanup": result.cleanup,
            "reason": result.reason,
            "log": log.name,
        }
    )
    return result


def _features(case, run, output):
    started = time.monotonic()
    results = []
    names = [
        None,
        "outbound-trojan",
        "outbound-vmess",
        "outbound-hysteria2",
        "outbound-wireguard",
        "stream-transport",
        "quic-transport",
    ]
    for name in names:
        command = ["cargo", "check", "--locked", "--no-default-features", "--lib"]
        if name:
            command.extend(["--features", name])
        results.append(
            _command(
                run,
                output,
                "feature-" + (name or "minimal"),
                command,
                max(1, int(case["timeout_seconds"] - (time.monotonic() - started))),
            )
        )
    results.append(
        _command(
            run,
            output,
            "feature-default",
            ["cargo", "test", "--locked", "--test", "feature_foundations"],
            max(1, int(case["timeout_seconds"] - (time.monotonic() - started))),
        )
    )
    cargo = __import__("tomllib").loads((CORE_DIR / "Cargo.toml").read_text())
    for name in names[1:]:
        pending = [name]
        enabled = set()
        while pending:
            item = pending.pop()
            if item not in enabled:
                enabled.add(item)
                pending.extend(cargo["features"].get(item, []))
        if enabled & {"outbound-vless", "tun"}:
            raise RuntimeError(
                "foundation feature silently enables an old protocol or TUN"
            )
    passed = all(item.returncode == 0 and item.cleanup for item in results)
    result = new_result(case)
    result.update(
        status="PASS" if passed else "FAIL",
        assertions=dict.fromkeys(case["expected_observation"], passed),
        evidence=case["required_evidence"] if passed else [],
        cleanup=all(item.cleanup for item in results),
        command_exit_code=0 if passed else 1,
    )
    return result


SCRIPT_OBSERVATIONS = {
    "offline-success": (
        "test_protocol_peers.OwnedPeerTest."
        "test_success_is_bounded_and_records_exit_and_cleanup"
    ),
    "missing-duplicate-unknown-case": (
        "test_protocol_evidence.ProtocolEvidenceTest."
        "test_missing_duplicate_unknown_and_empty_required_cases_fail"
    ),
    "download-failure": (
        "test_native_release.NativeReleaseTest."
        "test_failed_download_never_uses_old_binary_or_leaks_network_details"
    ),
    "timeout": (
        "test_protocol_peers.OwnedPeerTest."
        "test_timeout_and_output_overflow_fail_and_join"
    ),
    "sigint": (
        "test_protocol_peers.OwnedPeerTest."
        "test_real_sigint_joins_nested_peer_without_stopping_unrelated_peer"
    ),
    "partial-start": (
        "test_protocol_peers.OwnedPeerTest."
        "test_partial_start_and_permission_failure_do_not_leave_a_process"
    ),
    "permission": (
        "test_protocol_peers.OwnedPeerTest."
        "test_partial_start_and_permission_failure_do_not_leave_a_process"
    ),
    "peer-exit": ("test_protocol_peers.OwnedPeerTest.test_peer_exit_is_not_readiness"),
    "cleanup-failure": (
        "test_protocol_peers.OwnedPeerTest.test_cleanup_failure_is_explicit"
    ),
    "redaction": (
        "test_native_release.NativeReleaseTest."
        "test_failed_download_never_uses_old_binary_or_leaks_network_details"
    ),
}


def _scripts(case, run, output):
    path = output / "script-tests.json"
    command = _command(
        run,
        output,
        "offline-scripts",
        [sys.executable, "-m", "vcore_scripts.protocol_script_tests", str(path)],
        case["timeout_seconds"],
    )
    data = read_json(path)
    tests = {entry["test"]: entry["status"] for entry in data["cases"]}
    assertions = {
        name: tests.get(identifier) == "PASS"
        for name, identifier in SCRIPT_OBSERVATIONS.items()
    }
    passed = (
        command.returncode == 0
        and all(assertions.values())
        and len(tests) == len(data["cases"]) == data["tests_run"]
    )
    result = new_result(case)
    result.update(
        status="PASS" if passed else "FAIL",
        assertions=assertions,
        evidence=case["required_evidence"] if passed else [],
        cleanup=command.cleanup,
        command_exit_code=command.returncode,
    )
    return result


def _legacy(case, run, output, artifacts):
    result = new_result(case)
    if "M" not in artifacts or "M-container" not in artifacts:
        result.update(
            status="BLOCKED",
            reason="M native/container prerequisites unavailable",
            cleanup=True,
        )
        return result
    path = output / "legacy-events.jsonl"
    previous = os.environ.get("VCORE_CASE_EVENTS")
    os.environ["VCORE_CASE_EVENTS"] = str(path)
    started = time.monotonic()
    code = 1
    cleaned = False
    try:
        # The existing orchestrator owns exact peers/containers through ExitStack.
        # SIGINT/timeout unwinds it in this process, not by orphaning a child CLI.
        with (
            (output / "legacy.log").open("w") as log,
            contextlib.redirect_stdout(log),
            deadline(case["timeout_seconds"]),
        ):
            _run_mihomo_interop(
                artifacts["M"].binary,
                extended=True,
                soak_seconds=0,
                container_binary=artifacts["M-container"].binary,
            )
        code = 0
        cleaned = True
    except Exception as error:
        result.update(status="FAIL", reason=type(error).__name__)
    finally:
        if previous is None:
            os.environ.pop("VCORE_CASE_EVENTS", None)
        else:
            os.environ["VCORE_CASE_EVENTS"] = previous
        run["commands"].append(
            {
                "name": "legacy-mihomo",
                "command": ["check", "mihomo-interop", "--container", "--extended"],
                "exit_code": code,
                "seconds": round(time.monotonic() - started, 3),
                "cleanup": cleaned,
            }
        )
        if (output / "legacy.log").exists():
            log = (output / "legacy.log").read_text()
            (output / "legacy.log").write_text(redact(log))
    result = rust_results(case, _events(path), code)
    result["cleanup"] = cleaned
    if result["status"] == "PASS":
        result["evidence"] = case["required_evidence"]
    return result


def _native_results(cases, report):
    actual = {case["case_id"]: case for case in report.get("cases", [])}
    results = []
    for case in cases:
        result = new_result(case)
        source = actual.get(case["case_id"], {})
        event = source.get("rust_event", {})
        assertions = {
            "server_first": event.get("server_first") is True,
            "payload_65536": event.get("payload_bytes") == 65536,
            "trailer_exact": event.get("tail_bytes") == 14,
            "origin_complete": source.get("origin")
            == {"finished": True, "accepted": 1, "received": 65536, "failed": False},
            "protect_once": event.get("protect_calls") == 1,
            "driver_joined": event.get("driver_joined") is True,
            "resources_idle": event.get("resources_idle") is True
            and idle_resources(event.get("resources")),
        }
        passed = (
            source.get("status") == "PASS"
            and all(assertions.values())
            and source.get("cleanup", {}).get("joined") is True
            and report.get("cleanup") is True
        )
        if case["peer_kind"] == "M":
            cleanup = report.get("abnormal_cleanup", {})
            passed = passed and cleanup == {
                "passed": True,
                "kind": "M",
                "failure_injected": True,
                "joined": True,
                "port_rebound": True,
            }
        result.update(
            status="PASS" if passed else source.get("status", "NOT RUN"),
            assertions=assertions,
            evidence=case["required_evidence"] if passed else [],
            cleanup=source.get("cleanup", {}).get("joined") is True
            and report.get("cleanup") is True,
            command_exit_code=source.get("command_exit_code"),
            seconds=source.get("seconds"),
        )
        if not passed and result["status"] == "PASS":
            result["status"] = "FAIL"
        results.append(result)
    return results


def _execute(selected, run, output, records):
    rust = [case for case in selected if case["runner"] == "rust"]
    if rust:
        path = output / "rust-events.jsonl"
        result = _command(
            run,
            output,
            "rust-foundations",
            ["cargo", "test", "--locked", "--all-features", "--all-targets"],
            max(case["timeout_seconds"] for case in rust),
            events=path,
        )
        events = _events(path)
        for case in rust:
            records[case["case_id"]] = rust_results(case, events, result.returncode)
            records[case["case_id"]]["cleanup"] = result.cleanup
    kinds = {case["peer_kind"] for case in selected if case["peer_kind"] != "unit"}
    artifacts, peers = preflight(
        output / "binaries",
        kinds,
        container=any(case["runner"] == "mihomo-legacy" for case in selected),
    )
    (output / "peers.json").write_text(json.dumps(peers, indent=2) + "\n")
    native = [case for case in selected if case["runner"] == "native-stream"]
    if native:
        build = _command(
            run,
            output,
            "native-probe-build",
            [
                "cargo",
                "build",
                "--locked",
                "--all-features",
                "--example",
                "protocol-stream-probe",
            ],
            300,
        )
        if build.returncode == 0:
            report = {}
            try:
                report = run_streams(
                    output / "native",
                    [case["case_id"] for case in native],
                    artifacts=artifacts,
                )
            except (OSError, ValueError, RuntimeError):
                if (output / "native/stream-cases.json").exists():
                    report = read_json(output / "native/stream-cases.json")
            for result in _native_results(native, report):
                records[result["case_id"]] = result
    for case in selected:
        if case["runner"] == "features":
            records[case["case_id"]] = _features(case, run, output)
        elif case["runner"] == "scripts":
            records[case["case_id"]] = _scripts(case, run, output)
        elif case["runner"] == "mihomo-legacy":
            records[case["case_id"]] = _legacy(case, run, output, artifacts)


def run_protocol_interop(
    *,
    stage: str,
    identifiers=None,
    protocol=None,
    list_only=False,
    preflight_only=False,
    run_dir: Path | None = None,
) -> Path | None:
    selected = select_cases(
        load_manifest(), stage=stage, identifiers=identifiers, protocol=protocol
    )
    check_limit_references(load_manifest())
    if list_only:
        for case in selected:
            print(
                f"{case['case_id']}\t{case['substage']}\t{case['peer_kind']}\t{case['protocol']}"
            )
        return None
    check_protocol_catalogs(CATALOG_DIR)
    root = CORE_DIR / "target/interop/runs"
    root.mkdir(parents=True, exist_ok=True)
    if run_dir is None:
        output = Path(tempfile.mkdtemp(prefix=f"{stage.lower()}-", dir=root))
    else:
        output = run_dir.resolve()
        if not output.is_relative_to(root.resolve()):
            raise ValueError(
                "run directory must be a fresh child of target/interop/runs"
            )
        output.mkdir(parents=True, exist_ok=False)
    print(f"Protocol evidence: {output.relative_to(CORE_DIR.resolve())}", flush=True)
    run = {
        "schema_version": 1,
        "stage": stage,
        "mode": "preflight" if preflight_only else "execute",
        "selected_cases": [case["case_id"] for case in selected],
        "commands": [],
        "cleanup": False,
        "source_unchanged": False,
    }
    records = {case["case_id"]: new_result(case) for case in selected}
    (output / "peers.json").write_text("[]\n")
    error = None
    try:
        run.update(run_identity(stage, selected, preflight_only))
        with exclusive_run(), deadline(run["suite_timeout_seconds"]):
            if preflight_only:
                _, peers = preflight(
                    output / "binaries", {"M", "V2", "H", "XR", "W"}, container=True
                )
                (output / "peers.json").write_text(json.dumps(peers, indent=2) + "\n")
                if any(
                    peer["status"] != "READY"
                    or peer.get("container_status", "READY") != "READY"
                    for peer in peers
                ):
                    raise RuntimeError(
                        "some independent peer prerequisites are BLOCKED"
                    )
            else:
                _execute(selected, run, output, records)
    except BaseException as caught:
        error = caught
        run["failure_kind"] = type(caught).__name__
    finally:
        results = list(records.values())
        run["finished_utc"] = datetime.now(UTC).isoformat()
        try:
            current = source_identity()
            run["source_unchanged"] = current == {key: run.get(key) for key in current}
        except (OSError, RuntimeError, ValueError):
            run["source_unchanged"] = False
            run["identity_failure"] = True
        run["cleanup"] = error is None and (
            preflight_only or all(result["cleanup"] for result in results)
        )
        (output / "cases.json").write_text(json.dumps(results, indent=2) + "\n")
        resources = []
        try:
            for path in output.glob("*-events.jsonl"):
                for event in _events(path):
                    if event.get("resources") is not None:
                        resources.append(event)
            if (output / "native/stream-cases.json").exists():
                for case in read_json(output / "native/stream-cases.json")["cases"]:
                    if case.get("rust_event", {}).get("resources") is not None:
                        resources.append(
                            {
                                "case_id": case["case_id"],
                                "phase": "after-stop",
                                "resources": case["rust_event"]["resources"],
                            }
                        )
        except (OSError, ValueError, KeyError, TypeError) as caught:
            error = error or caught
            run.update(cleanup=False, failure_kind=type(error).__name__)
        (output / "resources.jsonl").write_text(
            "".join(json.dumps(item) + "\n" for item in resources)
        )
        status = (
            "PREFLIGHT"
            if preflight_only
            else "PASS"
            if error is None
            and run["source_unchanged"]
            and all(result["status"] == "PASS" for result in results)
            else "FAIL"
        )
        (output / "summary.md").write_text(
            f"# {stage}: {status}\n\nFoundation-only evidence; "
            "production protocol field consumers remain NOT RUN.\n\n"
            + "\n".join(
                f"- {result['case_id']}: {result['status']}" for result in results
            )
            + "\n"
        )
        run["artifacts"] = [
            {"path": str(path.relative_to(output)), "sha256": sha256(path)}
            for path in sorted(output.rglob("*"))
            if path.is_file()
            and path.suffix in {".json", ".jsonl", ".log", ".md"}
            and "binaries" not in path.parts
            and path.name != "run.json"
        ]
        (output / "run.json").write_text(json.dumps(run, indent=2) + "\n")
    if error is not None:
        raise RuntimeError(
            f"protocol run incomplete ({type(error).__name__}); "
            f"see {output.relative_to(CORE_DIR.resolve())}"
        ) from None
    if not preflight_only:
        if not run["source_unchanged"]:
            raise RuntimeError(
                "source changed during the run; evidence cannot sign off this input"
            )
        validate_results(selected, list(records.values()))
        if not identifiers and protocol is None:
            check_run(output, stage)
    return output
