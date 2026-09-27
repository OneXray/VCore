"""Trojan stage execution and independent, fail-closed persisted evidence checks."""

from __future__ import annotations

import json

from .protocol_evidence import HEX, new_result, read_events, read_json, rust_results
from .protocol_preflight import preflight
from .protocol_trojan import native_events_pass
from .protocol_trojan import run as run_native

# Frozen independently of cases.json: removing or downgrading a case is not signoff.
REQUIRED_IDS = {
    "N2-CODEC",
    "N2-CFG",
    "N2-CANCEL",
    "N2-M-TCP",
    "N2-M-WS",
    "N2-M-GRPC",
    "N2-M-WS-ED-1",
    "N2-M-WS-ED-2048",
    "N2-M-WS-POLICY",
    "N2-M-GRPC-POLICY",
    "N2-M-WS-NEGATIVE",
    "N2-M-GRPC-NEGATIVE",
    "N2-M-ALPN-NEGATIVE",
    "N2-V2-WS-HEADER",
    "N2-V2-WS-PATH",
    "N2-M-TCP-POLICY",
    "N2-XR-UDP-DOMAIN",
    "N2-XR-WS-UDP-DOMAIN",
    "N2-XR-GRPC-UDP-DOMAIN",
    "N2-M-TCP-LIFE",
    "N2-M-TCP-ENTRYPOINTS",
    "N2-M-TCP-UDP-ISOLATION",
    "N2-M-TCP-IPV6",
    "N2-M-TCP-OWNED",
    "N2-M-TCP-CERTIFICATE",
    "N2-M-WS-LIFE",
    "N2-M-WS-ENTRYPOINTS",
    "N2-M-WS-UDP-ISOLATION",
    "N2-M-WS-IPV6",
    "N2-M-WS-OWNED",
    "N2-M-WS-CERTIFICATE",
    "N2-M-GRPC-LIFE",
    "N2-M-GRPC-ENTRYPOINTS",
    "N2-M-GRPC-UDP-ISOLATION",
    "N2-M-GRPC-IPV6",
    "N2-M-GRPC-OWNED",
    "N2-M-GRPC-CERTIFICATE",
    "N2-M-GRPC-CUSTOM",
    "N2-FEATURES",
    "N2-SCRIPTS",
    "N2-REGRESSION",
}
FIELD_IDS = {
    "C01",
    "C02",
    "C03",
    "C04",
    "C05",
    "C06",
    "T01",
    "T03",
    "T04",
    "T05",
    "W01",
    "W02",
    "W03",
    "W04",
    "W05",
    "G01",
    "TR01",
    "TR02",
}


def native_results(cases, report, directory):
    records = report.get("cases", [])
    if [entry.get("case_id") for entry in records] != [
        case["case_id"] for case in cases
    ]:
        raise ValueError("missing, duplicate or reordered Trojan native evidence")
    results = []
    for case, record in zip(cases, records, strict=True):
        path = directory / (case["case_id"] + "-events.jsonl")
        events = read_events(path) if path.exists() else []
        observed = native_events_pass(events, case["peer_config"]["test"])
        clean = (
            record.get("command_cleanup") is True
            and record.get("cleanup", {}).get("joined") is True
            and record.get("upstream_cleanup", {"joined": True}).get("joined") is True
        )
        passed = (
            observed
            and clean
            and record.get("exit_code") == 0
            and record.get("status") == "PASS"
            and record.get("mode") == case["peer_config"]["mode"]
            and report.get("source_unchanged") is True
        )
        result = new_result(case)
        result.update(
            status="PASS" if passed else "FAIL",
            assertions={name: observed for name in case["expected_observation"]},
            evidence=case["required_evidence"] if passed else [],
            command_exit_code=record.get("exit_code"),
            cleanup=clean,
        )
        results.append(result)
    return results


def fields_report(cases, results):
    statuses = {result["case_id"]: result["status"] for result in results}
    complete = {case["case_id"] for case in cases} == REQUIRED_IDS
    return {
        "schema_version": 1,
        "stage": "N2",
        "protocol": "trojan",
        "scope": "protocol-consumer; other protocols remain NOT RUN",
        "fields": [
            {
                "row_id": row,
                "status": "PASS"
                if complete
                and owners
                and all(statuses.get(case_id) == "PASS" for case_id in owners)
                else "NOT RUN",
                "required_cases": owners,
            }
            for row in sorted(FIELD_IDS)
            for owners in [
                [case["case_id"] for case in cases if row in case["row_ids"]]
            ]
        ],
        "peer_limitations": [
            "Mihomo v1.19.31 domain UDP FAIL is retained; "
            "Xray TCP/WS/gRPC supplies separate domain evidence.",
            "V2Ray ED supplement UDP path is bounded by its 2048-byte return buffer; "
            "8192-byte truncation is retained as peer failure.",
            "Xray domain UDP return frame has 8192 total bytes, "
            "leaving 8166 payload for the controlled domain; "
            "larger peer failure retained.",
        ],
    }


def execute(cases, run, output, records):
    from .protocol_harness import _command, _events, _features, _legacy, _scripts

    rust = [case for case in cases if case["runner"] == "rust"]
    if rust:
        command = _command(
            run,
            output,
            "rust-consumer",
            ["cargo", "test", "--locked", "--all-features", "--all-targets"],
            600,
            events=output / "rust-events.jsonl",
        )
        events = _events(output / "rust-events.jsonl")
        for case in rust:
            result = rust_results(case, events, command.returncode)
            result["cleanup"] = command.cleanup
            records[case["case_id"]] = result
    kinds = {case["peer_kind"] for case in cases if case["peer_kind"] != "unit"}
    artifacts, peers = preflight(
        output / "binaries",
        kinds,
        container=any(case["runner"] == "mihomo-legacy" for case in cases),
    )
    (output / "peers.json").write_text(json.dumps(peers, indent=2) + "\n")
    native = [case for case in cases if case["runner"] == "native-trojan"]
    if native:
        directory = output / "native"
        run_native(directory, [case["case_id"] for case in native], artifacts=artifacts)
        report = read_json(directory / "trojan-results.json")
        for result in native_results(native, report, directory):
            records[result["case_id"]] = result
    for case in cases:
        if case["runner"] == "features":
            records[case["case_id"]] = _features(case, run, output)
        elif case["runner"] == "scripts":
            records[case["case_id"]] = _scripts(case, run, output)
        elif case["runner"] == "mihomo-legacy":
            records[case["case_id"]] = _legacy(case, run, output, artifacts)
    (output / "fields.json").write_text(
        json.dumps(fields_report(cases, list(records.values())), indent=2) + "\n"
    )


def check(run_dir, required, run, results, peers, paths):
    from .protocol_harness import SCRIPT_OBSERVATIONS

    necessary = {
        "cases.json",
        "peers.json",
        "resources.jsonl",
        "summary.md",
        "rust-events.jsonl",
        "legacy-events.jsonl",
        "script-tests.json",
        "native/trojan-results.json",
        "fields.json",
    }
    if not necessary <= set(paths):
        raise ValueError("missing Trojan acceptance artifacts")
    expected_commands = {
        "rust-consumer",
        "legacy-mihomo",
        "offline-scripts",
        "feature-default",
        "feature-minimal",
        "feature-outbound-trojan",
        "feature-outbound-vmess",
        "feature-outbound-hysteria2",
        "feature-stream-transport",
        "feature-quic-transport",
    }
    commands = run.get("commands", [])
    if (
        len(commands) != len(expected_commands)
        or {command.get("name") for command in commands} != expected_commands
        or any(
            type(command.get("exit_code")) is not int
            or command["exit_code"] != 0
            or command.get("cleanup") is not True
            or (command.get("log") and command["log"] not in paths)
            for command in commands
        )
    ):
        raise ValueError("missing, failed or unjoined Trojan acceptance command")
    native = [case for case in required if case["runner"] == "native-trojan"]
    report = read_json(run_dir / "native/trojan-results.json")
    if (
        report.get("source_unchanged") is not True
        or report.get("cleanup") is not True
        or report.get("source", {}).get("source_tree_sha256")
        != run["source_tree_sha256"]
        or report.get("source", {}).get("lock_sha256") != run["lock_sha256"]
    ):
        raise ValueError("Trojan peer tests used another source input")
    for record, case in zip(report.get("cases", []), native, strict=True):
        for suffix in (".log", "-events.jsonl"):
            if "native/" + case["case_id"] + suffix not in paths:
                raise ValueError("native log/events missing immutable identity")
        identity = [peer for peer in peers if peer.get("kind") == case["peer_kind"]]
        if (
            len(identity) != 1
            or identity[0].get("status") != "READY"
            or not identity[0].get("version")
            or not HEX.fullmatch(identity[0].get("binary_sha256", ""))
            or not HEX.fullmatch(identity[0].get("archive_sha256", ""))
            or not identity[0].get("source_url", "").startswith("https://github.com/")
            or any(
                record.get("peer", {}).get(key) != identity[0].get(key)
                for key in ("version", "binary_sha256", "archive_sha256", "source_url")
            )
        ):
            raise ValueError("Trojan used a peer different from official preflight")
        test = case["peer_config"]["test"]
        target = (
            "trojan_lifecycle"
            if test == "trojan_native_owned_resources"
            else "mihomo_interop"
        )
        name = test if target == "trojan_lifecycle" else "trojan::" + test
        if record.get("command") != [
            "cargo",
            "test",
            "--locked",
            "--all-features",
            "--test",
            target,
            name,
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ]:
            raise ValueError("Trojan case did not execute its declared public consumer")
    calculated = native_results(native, report, run_dir / "native")
    rust = read_events(run_dir / "rust-events.jsonl")
    legacy = read_events(run_dir / "legacy-events.jsonl")
    for case in required:
        if case["runner"] in {"rust", "mihomo-legacy"}:
            entry = rust_results(
                case, legacy if case["runner"] == "mihomo-legacy" else rust, 0
            )
            if case["runner"] == "mihomo-legacy" and entry["status"] == "PASS":
                entry["evidence"] = case["required_evidence"]
            calculated.append(entry)
    actual = {entry["case_id"]: entry for entry in results}
    for entry in calculated:
        if actual[entry["case_id"]] != entry:
            raise ValueError(
                "Trojan result disagrees with original structured assertions"
            )
    script = read_json(run_dir / "script-tests.json")
    tests = {entry["test"]: entry["status"] for entry in script.get("cases", [])}
    if (
        not tests
        or len(tests) != len(script.get("cases", []))
        or len(tests) != script.get("tests_run")
        or any(status != "PASS" for status in tests.values())
        or any(tests.get(name) != "PASS" for name in SCRIPT_OBSERVATIONS.values())
        or not any("test_protocol_trojan." in name for name in tests)
    ):
        raise ValueError("Trojan harness failure paths were not exercised")
    mihomo = next(peer for peer in peers if peer["kind"] == "M")
    if (
        mihomo.get("container_status") != "READY"
        or not HEX.fullmatch(
            mihomo.get("container_artifact", {}).get("binary_sha256", "")
        )
        or mihomo["container_artifact"].get("release") != mihomo.get("release")
    ):
        raise ValueError("old regression did not use the same official Mihomo snapshot")
    field_report = fields_report(required, results)
    if read_json(run_dir / "fields.json") != field_report or any(
        row["status"] != "PASS" for row in field_report["fields"]
    ):
        raise ValueError("incomplete or inconsistent Trojan field report")
    print(
        f"N2: PASS ({len(required)} required cases, {len(FIELD_IDS)} Trojan fields); "
        "other protocols remain NOT RUN"
    )
