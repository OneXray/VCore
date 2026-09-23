"""Frozen N1 executable requirements and fail-closed structured result checks."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .protocol_catalogs import (
    CATALOG_DIR,
    FIELD_IDS,
    STAGES,
    WORK_PACKAGES,
    _unique_object,
)

N1_REQUIRED_IDS = {
    "N1-SCHEMA",
    "N1-LIMITS",
    "N1-STREAM",
    "N1-DATAGRAM",
    "N1-QUIC",
    "N1-RESOLUTION",
    "N1-RESOURCES",
    "N1-SECURITY",
    "N1-XUDP",
    "N1-REGRESSION",
    "N1-M-WS",
    "N1-M-WSS",
    "N1-M-GRPC",
    "N1-M-GRPC-TLS",
    "N1-M-WS-ED",
    "N1-V2-HTTP",
    "N1-V2-H2",
    "N1-V2-WS-HEADER",
    "N1-V2-WS-PATH",
    "N1-FEATURES",
    "N1-SCRIPTS",
}
HEX = re.compile(r"[0-9a-f]{64}")
RESOURCE_KINDS = {
    "task",
    "socket",
    "session",
    "association",
    "reassembly",
    "pool",
    "waiter",
    "handshake",
}


def idle_resources(snapshot) -> bool:
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get("counts"), list):
        return False
    counts = snapshot["counts"]
    return (
        len(counts) == len(RESOURCE_KINDS)
        and all(isinstance(count, dict) for count in counts)
        and {count.get("kind") for count in counts} == RESOURCE_KINDS
        and all(
            type(count.get("current")) is int
            and count["current"] == 0
            and type(count.get("peak")) is int
            and count["peak"] >= 0
            for count in counts
        )
    )


def read_events(path: Path) -> list[dict]:
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("case events exceeded bound")
    events = [
        json.loads(line, object_pairs_hook=_unique_object)
        for line in path.read_text().splitlines()
    ]
    if not all(isinstance(event, dict) for event in events):
        raise ValueError("malformed structured case event")
    return events


def read_json(path: Path):
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("protocol evidence exceeds bounded document size")
    return json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
    )


def load_manifest(path: Path = CATALOG_DIR / "cases.json") -> list[dict]:
    data = read_json(path)
    if (
        data.get("schema_version") != 1
        or data.get("kind") != "executable-case-manifest"
    ):
        raise ValueError("unsupported executable case manifest")
    cases = data.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("empty executable case manifest")
    seen = set()
    for case in cases:
        required = {
            "case_id",
            "stage",
            "substage",
            "required",
            "row_ids",
            "protocol",
            "network",
            "security",
            "udp_codec",
            "field_values",
            "outer_family",
            "inner_family",
            "target_type",
            "upstream_graph",
            "peer_kind",
            "peer_config",
            "gap_source",
            "expected_observation",
            "required_evidence",
            "prerequisites",
            "runner",
            "timeout_seconds",
        }
        if not isinstance(case, dict) or not required <= case.keys():
            raise ValueError("incomplete executable case metadata")
        identifier = case["case_id"]
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[A-Z0-9-]+", identifier)
            or identifier in seen
        ):
            raise ValueError("invalid or duplicate executable case ID")
        seen.add(identifier)
        if (
            case["stage"] not in STAGES
            or case["substage"] not in WORK_PACKAGES
            or not case["substage"].startswith(case["stage"] + ".")
        ):
            raise ValueError("invalid case ownership")
        if (
            type(case["required"]) is not bool
            or not isinstance(case["row_ids"], list)
            or len(set(case["row_ids"])) != len(case["row_ids"])
            or not set(case["row_ids"]) <= FIELD_IDS
        ):
            raise ValueError("invalid required flag or field references")
        if case["peer_kind"] not in {"M", "W", "H", "XR", "V2", "unit"}:
            raise ValueError("unknown peer kind")
        for key in ["expected_observation", "required_evidence", "prerequisites"]:
            items = case[key]
            if (
                not isinstance(items, list)
                or not items
                or not all(isinstance(item, str) and item for item in items)
                or len(items) != len(set(items))
            ):
                raise ValueError("empty or duplicate executable observations")
        if (
            not isinstance(case["field_values"], dict)
            or not isinstance(case["peer_config"], dict)
            or type(case["timeout_seconds"]) is not int
            or not 1 <= case["timeout_seconds"] <= 3600
        ):
            raise ValueError("invalid case bounds or configuration reference")
    if {
        case["case_id"] for case in cases if case["stage"] == "N1" and case["required"]
    } != N1_REQUIRED_IDS:
        raise ValueError("N1 required set was removed, renamed or downgraded")
    return cases


def check_limit_references(
    cases: list[dict], path: Path = CATALOG_DIR / "limits.json"
) -> None:
    limits = read_json(path)
    identifiers = {case["case_id"] for case in cases}
    if (
        limits.get("schema_version") != 1
        or limits.get("kind") != "runtime-limit-registry"
    ):
        raise ValueError("unsupported runtime limit registry")
    entries = limits.get("limits", [])
    names = [entry.get("id") for entry in entries]
    if not entries or len(names) != len(set(names)):
        raise ValueError("empty or duplicate runtime limits")
    for entry in entries:
        if (
            not entry.get("boundary_cases")
            or not set(entry["boundary_cases"]) <= identifiers
        ):
            raise ValueError("runtime limit has no executable boundary case")


def select_cases(
    cases: list[dict],
    *,
    stage: str,
    identifiers: list[str] | None = None,
    protocol: str | None = None,
) -> list[dict]:
    if identifiers and (
        len(identifiers) != len(set(identifiers))
        or not set(identifiers) <= {case["case_id"] for case in cases}
    ):
        raise ValueError("duplicate or unknown requested case")
    selected = [
        case
        for case in cases
        if case["stage"] == stage
        and case["required"]
        and (not identifiers or case["case_id"] in identifiers)
        and (protocol is None or case["protocol"] == protocol)
    ]
    if not selected:
        raise ValueError("selection has no executable required cases; stage is NOT RUN")
    if identifiers and {case["case_id"] for case in selected} != set(identifiers):
        raise ValueError("case selection conflicts with stage or protocol")
    return selected


def validate_results(required: list[dict], results: list[dict]) -> None:
    if not required:
        raise ValueError("empty required result set")
    expected = {case["case_id"]: case for case in required}
    identifiers = [result.get("case_id") for result in results]
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != set(expected):
        raise ValueError("missing, duplicate or unknown case result")
    for result in results:
        case = expected[result["case_id"]]
        if (
            result.get("status") != "PASS"
            or result.get("cleanup") is not True
            or type(result.get("command_exit_code")) is not int
            or result["command_exit_code"] != 0
        ):
            raise ValueError(
                "required case failed, was blocked/not run, or did not clean up"
            )
        observations = result.get("assertions", {})
        if (
            not isinstance(observations, dict)
            or set(observations) != set(case["expected_observation"])
            or not all(value is True for value in observations.values())
        ):
            raise ValueError("missing or false required behavioral assertion")
        evidence = result.get("evidence", [])
        if (
            not isinstance(evidence, list)
            or len(evidence) != len(set(evidence))
            or set(evidence) != set(case["required_evidence"])
        ):
            raise ValueError(
                "incomplete behavior evidence; CFG alone is not acceptance"
            )
        if (
            result.get("row_ids") != case["row_ids"]
            or result.get("peer_kind") != case["peer_kind"]
            or result.get("scope") != "foundation-only"
        ):
            raise ValueError("case mapping or evidence scope differs from manifest")


def rust_results(case: dict, events: list[dict], returncode: int) -> dict:
    observed = [event for event in events if event.get("suite") == case["case_id"]]
    names = case["expected_observation"]
    assertions = {name: False for name in names}
    unknown = any(
        event.get("assertion") not in assertions or event.get("schema_version") != 1
        for event in observed
    )
    for name in names:
        entries = [event for event in observed if event.get("assertion") == name]
        assertions[name] = len(entries) == 2 and [
            entry.get("status") for entry in entries
        ] == ["BEGIN", "PASS"]
        if assertions[name] and "resources" in case["required_evidence"]:
            assertions[name] = idle_resources(entries[-1].get("resources"))
    result = new_result(case)
    result.update(assertions=assertions, command_exit_code=returncode, cleanup=True)
    result["status"] = (
        "PASS"
        if not unknown and returncode == 0 and all(assertions.values())
        else "FAIL"
    )
    if result["status"] == "PASS":
        result["evidence"] = [
            item for item in case["required_evidence"] if item != "peer-identity"
        ]
    return result


def new_result(case: dict) -> dict:
    return {
        "case_id": case["case_id"],
        "row_ids": case["row_ids"],
        "peer_kind": case["peer_kind"],
        "scope": "foundation-only",
        "status": "NOT RUN",
        "assertions": {},
        "evidence": [],
        "cleanup": False,
        "command_exit_code": None,
    }


def artifact(run_dir: Path, relative: str, digest: str) -> Path:
    path = run_dir / relative
    if (
        Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or path.is_symlink()
        or not path.resolve().is_relative_to(run_dir.resolve())
        or not HEX.fullmatch(digest)
    ):
        raise ValueError("unsafe evidence path or invalid hash")
    with path.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != digest:
        raise ValueError("evidence content hash mismatch")
    return path


def check_run(
    run_dir: Path, stage: str, manifest: Path = CATALOG_DIR / "cases.json"
) -> None:
    cases = load_manifest(manifest)
    check_limit_references(cases, manifest.parent / "limits.json")
    required = select_cases(cases, stage=stage)
    run = read_json(run_dir / "run.json")
    result = read_json(run_dir / "cases.json")
    peers = read_json(run_dir / "peers.json")
    if (
        run.get("stage") != stage
        or run.get("mode") != "execute"
        or run.get("cleanup") is not True
        or run.get("source_unchanged") is not True
        or run.get("selected_cases") != [case["case_id"] for case in required]
    ):
        raise ValueError(
            "partial/preflight run or changing source cannot sign off the stage"
        )
    for key in ["source_tree_sha256", "lock_sha256", "dirty_patch_sha256"]:
        if not isinstance(run.get(key), str) or not HEX.fullmatch(run[key]):
            raise ValueError("missing immutable input identity")
    validate_results(required, result)
    artifacts = run.get("artifacts", [])
    paths = [entry["path"] for entry in artifacts]
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate evidence artifact")
    necessary = {
        "cases.json",
        "peers.json",
        "resources.jsonl",
        "summary.md",
        "rust-events.jsonl",
        "legacy-events.jsonl",
        "native/stream-cases.json",
        "script-tests.json",
    }
    if not necessary <= set(paths):
        raise ValueError("missing persisted behavior artifacts")
    for evidence in artifacts:
        artifact(run_dir, evidence["path"], evidence["sha256"])
    commands = run.get("commands", [])
    command_names = [command.get("name") for command in commands]
    required_commands = {
        "rust-foundations",
        "native-probe-build",
        "legacy-mihomo",
        "offline-scripts",
        "feature-default",
        "feature-minimal",
        "feature-outbound-trojan",
        "feature-outbound-vmess",
        "feature-outbound-hysteria2",
        "feature-outbound-wireguard",
        "feature-stream-transport",
        "feature-quic-transport",
    }
    if (
        len(command_names) != len(set(command_names))
        or set(command_names) != required_commands
        or any(
            type(command.get("exit_code")) is not int
            or command["exit_code"] != 0
            or command.get("cleanup") is not True
            for command in commands
        )
    ):
        raise ValueError("missing, failed or unjoined acceptance command")
    for command in commands:
        if command.get("log") and command["log"] not in paths:
            raise ValueError("command log has no content identity")
    rust_events = read_events(run_dir / "rust-events.jsonl")
    legacy_events = read_events(run_dir / "legacy-events.jsonl")
    native = read_json(run_dir / "native/stream-cases.json")
    native_cases = [case for case in required if case["runner"] == "native-stream"]
    if [item.get("case_id") for item in native.get("cases", [])] != [
        case["case_id"] for case in native_cases
    ]:
        raise ValueError("missing, duplicate or unknown native case evidence")
    # Use exactly the same structured evaluators as execution, never console text.
    from .protocol_harness import SCRIPT_OBSERVATIONS, _native_results

    recalculated = _native_results(native_cases, native)
    for case in required:
        if case["runner"] in {"rust", "mihomo-legacy"}:
            calculated = rust_results(
                case,
                legacy_events if case["runner"] == "mihomo-legacy" else rust_events,
                0,
            )
            if case["runner"] == "mihomo-legacy" and calculated["status"] == "PASS":
                calculated["evidence"] = case["required_evidence"]
            recalculated.append(calculated)
    actual = {item["case_id"]: item for item in result}
    for calculated in recalculated:
        for key in ["status", "assertions", "evidence", "cleanup", "command_exit_code"]:
            if actual[calculated["case_id"]].get(key) != calculated[key]:
                raise ValueError(
                    "case result disagrees with original structured evidence"
                )
    script = read_json(run_dir / "script-tests.json")
    scripts = script.get("cases", [])
    tests = {entry["test"]: entry["status"] for entry in scripts}
    if (
        not scripts
        or len(tests) != len(scripts)
        or len(tests) != script.get("tests_run")
        or any(status != "PASS" for status in tests.values())
        or any(
            tests.get(identifier) != "PASS"
            for identifier in SCRIPT_OBSERVATIONS.values()
        )
    ):
        raise ValueError("missing or failed offline harness failure-path proof")
    resources = read_events(run_dir / "resources.jsonl")
    if not resources or not all(
        idle_resources(event.get("resources")) for event in resources
    ):
        raise ValueError("missing, nonidle or malformed owned resource evidence")
    resource_passes = [
        event
        for event in rust_events
        if event.get("suite") == "N1-RESOURCES" and event.get("status") == "PASS"
    ]
    for event in resource_passes:
        checkpoints = event.get("checkpoints", [])
        by_phase = {point["phase"]: point["resources"] for point in checkpoints}
        if (
            len(checkpoints) != len(by_phase)
            or not {"baseline", "after-stop"} <= by_phase.keys()
            or not idle_resources(by_phase["baseline"])
            or not idle_resources(by_phase["after-stop"])
        ):
            raise ValueError("resource ownership has no baseline/Stop evidence")
        if "remain_quiet" in event["assertion"] and (
            by_phase.get("quiet") != by_phase["after-stop"]
            or event.get("seconds", 0) < 5
        ):
            raise ValueError("resource quiet-window evidence missing")
    for case in required:
        if "peer-identity" in case["required_evidence"]:
            matches = [
                peer
                for peer in peers
                if peer.get("kind") == case["peer_kind"]
                and peer.get("status") == "READY"
            ]
            if (
                len(matches) != 1
                or not matches[0].get("version")
                or not HEX.fullmatch(matches[0].get("binary_sha256", ""))
                or not HEX.fullmatch(matches[0].get("archive_sha256", ""))
                or not matches[0]
                .get("source_url", "")
                .startswith("https://github.com/")
            ):
                raise ValueError("missing official peer identity")
            if case["runner"] == "native-stream":
                native_peers = [
                    peer
                    for peer in native.get("peers", [])
                    if peer.get("kind") == case["peer_kind"]
                ]
                if (
                    len(native_peers) != 1
                    or native_peers[0].get("binary_sha256")
                    != matches[0]["binary_sha256"]
                ):
                    raise ValueError("case used a different peer from preflight")
            if case["runner"] == "mihomo-legacy":
                peer = matches[0]
                if (
                    peer.get("container_status") != "READY"
                    or not HEX.fullmatch(
                        peer.get("container_artifact", {}).get("binary_sha256", "")
                    )
                    or peer["container_artifact"].get("release") != peer.get("release")
                ):
                    raise ValueError(
                        "legacy peer did not use the same official release snapshot"
                    )
    print(
        f"{stage}: PASS ({len(required)} required foundation cases); "
        "production field consumers remain NOT RUN"
    )
