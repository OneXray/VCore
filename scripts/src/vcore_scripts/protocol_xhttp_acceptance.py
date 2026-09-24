"""N5 execution and independently recomputed, fail-closed stage evidence."""

from __future__ import annotations

import json
import sys

from .builds import DEFAULT_FEATURES
from .protocol_evidence import HEX, idle_resources, new_result, read_events, read_json
from .protocol_inputs import redact
from .protocol_vless_acceptance import commands as previous_commands
from .protocol_xhttp_catalog import (
    FIELD_IDS,
    GATES,
    NATIVE,
    OBSERVATIONS,
    REPRESENTATIVES,
    SECURITY,
    UNIT_TESTS,
    definitions,
)
from .protocol_xhttp_fields import PUBLIC_TESTS, events_pass, public_events_pass


def test_command(test):
    return [
        "cargo",
        "test",
        "--locked",
        "--all-features",
        "--test",
        "vless_public" if test in PUBLIC_TESTS else "xhttp_native",
        test,
        "--",
        "--exact",
        "--ignored",
        "--nocapture",
    ]


def commands(identifier):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if identifier in {"N5-CFG", "N5-UNIT", "N5-RELEASE"}:
        names = list(UNIT_TESTS)
        if identifier == "N5-CFG":
            names = names[:2]
        elif identifier == "N5-UNIT":
            names = names[2:]
        flags = ["--release"] if identifier == "N5-RELEASE" else []
        selected = sum((["--test", name] for name in names), [])
        result = [cargo + flags + selected]
        if identifier != "N5-CFG":
            result += [
                cargo + flags + ["--lib", "transport::xhttp::tests::"],
                cargo + flags + ["--lib", "transport::sing_mux::"],
                cargo + flags + ["--test", "vless_lifecycle"],
            ]
        return result
    if identifier == "N5-REGRESSION":
        return sum(
            (
                previous_commands("N4-" + part)
                for part in ("REGRESSION", "CODEC", "TRANSPORT", "VISION")
            ),
            [],
        )
    if identifier == "N5-QUALITY":
        return previous_commands("N4-QUALITY") + [
            [
                "cargo",
                "test",
                "--locked",
                "--manifest-path",
                "crates/vcore-netstack/Cargo.toml",
                "--all-targets",
            ],
            [
                "cargo",
                "clippy",
                "--locked",
                "--manifest-path",
                "crates/vcore-netstack/Cargo.toml",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ]
    return []


def gate_result(case, records, events):
    result = new_result(case)
    good = bool(records) and all(
        r.get("exit_code") == 0 and r.get("cleanup") is True for r in records
    )
    assertions = {}
    for name in case["expected_observation"]:
        observed = [e for e in events if e.get("assertion") == name]
        assertions[name] = len(observed) == 2 and [
            e.get("status") for e in observed
        ] == ["BEGIN", "PASS"]
    if case["case_id"] not in OBSERVATIONS:
        assertions = dict.fromkeys(case["expected_observation"], good)
    else:
        good &= all(assertions.values()) and all(
            e.get("schema_version") == 1 and e.get("status") in {"BEGIN", "PASS"}
            for e in events
        )
        if case["case_id"] != "N5-REGRESSION":
            unit = [e for e in events if e.get("suite") == "N5-UNIT"]
            good &= len(unit) == 2 * len(assertions) and all(
                e["assertion"] in assertions for e in unit
            )
    result.update(
        status="PASS" if good else "FAIL",
        assertions=assertions,
        evidence=case["required_evidence"] if good else [],
        command_exit_code=0 if good else 1,
        cleanup=bool(records) and all(r.get("cleanup") is True for r in records),
    )
    return result


def native_results(cases, report, directory, *, allow_partial=False):
    records = report.get("cases", [])
    expected = {case["case_id"] for case in cases}
    actual = {r.get("case_id") for r in records}
    if (
        len(records) != len(actual)
        or not actual <= expected
        or (not allow_partial and actual != expected)
    ):
        raise ValueError("missing, duplicate or unknown N5 native case")
    by_id = {record["case_id"]: record for record in records}
    output = []
    for case in cases:
        identifier = case["case_id"]
        if identifier not in by_id:
            continue
        record = by_id[identifier]
        variant, test = NATIVE[identifier]
        path = directory / f"{identifier}-events.jsonl"
        observed = read_events(path) if path.exists() else []
        observed_ok = (
            public_events_pass(observed, test)
            if test in PUBLIC_TESTS
            else events_pass(observed, test, owned=test.startswith("lifecycle::"))
        )
        clean = record.get("command_cleanup") is True and report.get("cleanup") is True
        good = (
            observed_ok
            and clean
            and report.get("source_unchanged") is True
            and record.get("status") == "PASS"
            and record.get("exit_code") == 0
            and record.get("command") == test_command(test)
            and record.get("assertion") == test
            and record.get("variant") == variant
        )
        if test.startswith("close::"):
            path = directory / f"{variant}-close-reference.json"
            reference = read_json(path) if path.exists() else {}
            good &= (
                reference.get("scope") == "same-mode"
                and reference.get("terminated") is True
                and reference.get("tail_hex") == ""
            )
        result = new_result(case)
        result.update(
            status="PASS" if good else "FAIL",
            assertions={test: observed_ok},
            evidence=case["required_evidence"] if good else [],
            command_exit_code=record.get("exit_code"),
            cleanup=clean,
        )
        output.append(result)
    return output


def security_results(cases, report, directory, *, allow_partial=False):
    from .protocol_xhttp_security import security_cases

    expected = {}
    identity = {
        k: {"certificate": "fixture", "private-key": "fixture"}
        for k in ("valid", "absent", "expired", "wrong-ca")
    }
    for case in cases:
        version = SECURITY[case["case_id"]]
        base = dict(
            alpn=["http/1.1" if version == "h1" else version],
            certificate="fixture",
            **{"private-key": "fixture", "xhttp-opts": {}},
        )
        expected[version] = {
            f"{version}-{name}": failure
            for name, _, _, failure in security_cases(
                base, identity, identity["valid"], "2001:db8::1"
            )
        }
    records = report.get("cases", [])
    ids = set().union(*(set(e) for e in expected.values()))
    actual = {r.get("case_id") for r in records}
    if (
        len(records) != len(actual)
        or not actual <= ids
        or (not allow_partial and actual != ids)
    ):
        raise ValueError("missing, duplicate or unknown N5 security case")
    results = []
    by_id = {r["case_id"]: r for r in records}
    for case in cases:
        version = SECURITY[case["case_id"]]
        if allow_partial and not actual.intersection(expected[version]):
            continue
        clean = report.get("cleanup") is True and report.get("owned_remaining") == []
        good = clean and report.get("source_unchanged") is True
        for name, failure in expected[version].items():
            record = by_id.get(name, {})
            path = directory / f"{name}-events.jsonl"
            events = read_events(path) if path.exists() else []
            good &= (
                events_pass(events, "security::native_xhttp_security")
                and record.get("exit_code") == 0
                and record.get("command_cleanup") is True
                and record.get("command")
                == test_command("security::native_xhttp_security")
                and record.get("status") == "PASS"
            )
            if version == "h3" and failure:
                category = {
                    "absent": "certificate_required",
                    "expired": "certificate_expired",
                    "wrong-ca": "unknown_ca",
                }[failure]
                good &= record.get("identity_enforced") is True and any(
                    e.get("category") == category
                    for e in record.get("certificate_errors", [])
                )
        result = new_result(case)
        result.update(
            status="PASS" if good else "FAIL",
            assertions={case["case_id"]: good},
            evidence=case["required_evidence"] if good else [],
            command_exit_code=0 if good else 1,
            cleanup=clean,
        )
        results.append(result)
    return results


def fields_report(cases, results):
    statuses = {r["case_id"]: r["status"] for r in results}
    complete = set(statuses) == {c["case_id"] for c in definitions()} and all(
        s == "PASS" for s in statuses.values()
    )
    fields = []
    for row in sorted(FIELD_IDS):
        owners = [c["case_id"] for c in cases if row in c["row_ids"]]
        behavior = [c for c in owners if c in NATIVE or c in SECURITY]
        fields.append(
            dict(
                row_id=row,
                required_cases=owners,
                status="PASS"
                if complete and behavior and "N5-CFG" in owners
                else "NOT RUN",
            )
        )
    return dict(schema_version=1, stage="N5", protocol="vless", fields=fields)


def prepare_peers(output, kinds):
    from .caddy_build import build_caddy
    from .mihomo_release import download_mihomo
    from .native_release import download_native

    supplied = {}
    for kind in sorted(kinds):
        directory = output / "binaries" / kind
        if kind == "M":
            identity = {}
            binary = download_mihomo(
                "linux-arm64", directory=directory, identity=identity
            )
            supplied[kind] = binary, identity
        else:
            artifact = (
                build_caddy(directory)
                if kind == "Caddy"
                else download_native(kind, directory, "linux-arm64", defer_version=True)
            )
            supplied[kind] = artifact.binary, artifact.identity
    return supplied


def preflight(output):
    """Only verify the N5 native artifacts inside an owned isolated guest."""
    import shutil
    import tempfile
    from contextlib import ExitStack

    from .protocol_containers import ContainerLab, command
    from .protocol_inputs import CORE_DIR

    supplied = prepare_peers(output, {"M", "XR", "V2", "Caddy"})
    isolation = {}
    lab = ContainerLab(isolation, mtu=1500)
    try:
        with tempfile.TemporaryDirectory(
            prefix="n5-preflight-", dir=CORE_DIR / "target"
        ) as tmp:
            from pathlib import Path

            root = Path(tmp)
            for kind, (binary, _) in supplied.items():
                shutil.copy2(binary, root / kind)
            with ExitStack() as stack:
                peer = lab.start(
                    stack,
                    root,
                    "preflight",
                    ["python", "-c", "import time; time.sleep(600)"],
                )
                peer.release()
                for kind, (_, identity) in supplied.items():
                    binary = "/data/fixture/" + kind
                    version = command(
                        "exec", peer.name, binary, "-v" if kind == "M" else "version"
                    ).strip()
                    digest = command("exec", peer.name, "sha256sum", binary).split()[0]
                    if not version or digest != identity["binary_sha256"]:
                        raise RuntimeError("isolated N5 artifact identity mismatch")
                    identity["version"] = version
    finally:
        (output / "peers.json").write_text(
            json.dumps({k: i for k, (_, i) in supplied.items()}, indent=2) + "\n"
        )
        (output / "preflight.json").write_text(
            json.dumps(
                dict(
                    scope="preflight-only",
                    wire_acceptance="NOT RUN",
                    isolation=isolation,
                ),
                indent=2,
            )
            + "\n"
        )


def execute(cases, run, output, results):
    from .protocol_harness import _command, _features, _scripts
    from .protocol_xhttp_fields import run as fields_run
    from .protocol_xhttp_security import run as security_run

    for case in cases:
        identifier = case["case_id"]
        if identifier not in GATES:
            continue
        if identifier == "N5-FEATURES":
            result = _features(case, run, output)
            for name, command in (
                (
                    "feature-outbound-vless",
                    [
                        "cargo",
                        "check",
                        "--locked",
                        "--no-default-features",
                        "--lib",
                        "--features",
                        "outbound-vless",
                    ],
                ),
                (
                    "production-build",
                    [
                        "cargo",
                        "build",
                        "--locked",
                        "--release",
                        "--no-default-features",
                        "--features",
                        DEFAULT_FEATURES,
                        "--lib",
                    ],
                ),
            ):
                observed = _command(run, output, name, command, 1200)
                if observed.returncode or not observed.cleanup:
                    result.update(
                        status="FAIL",
                        command_exit_code=observed.returncode,
                        cleanup=observed.cleanup,
                    )
            results[identifier] = result
        elif identifier == "N5-SCRIPTS":
            results[identifier] = _scripts(case, run, output)
        else:
            start = len(run["commands"])
            events = []
            for i, command in enumerate(commands(identifier)):
                path = output / f"{identifier}-{i}-events.jsonl"
                observed = _command(
                    run, output, f"{identifier}-{i}", command, 1200, events=path
                )
                if path.exists():
                    events.extend(read_events(path))
                if observed.returncode or not observed.cleanup:
                    break
            results[identifier] = gate_result(case, run["commands"][start:], events)
        if results[identifier]["status"] != "PASS":
            raise RuntimeError(f"{identifier} failed; later cases remain NOT RUN")
    native = [c for c in cases if c["case_id"] in NATIVE]
    security = [c for c in cases if c["case_id"] in SECURITY]
    kinds = {c["peer_kind"] for c in native + security}
    if native or security:
        kinds.add("M")
    if any(c["peer_kind"] == "XR" for c in security):
        kinds.add("Caddy")
    supplied = prepare_peers(output, kinds)
    try:
        if native:
            jobs = {}
            for case in native:
                identifier = case["case_id"]
                variant, test = NATIVE[identifier]
                jobs.setdefault(variant, []).append(dict(case_id=identifier, test=test))
            directory = output / "native"
            # Exercise native-gap transports before the long Mihomo matrix.
            # Ordering changes neither the frozen case set nor its evidence.
            ordered = sorted(
                jobs, key=lambda name: (not name.startswith(("h3-", "outer-")), name)
            )
            fields_run(directory, ordered, jobs=jobs, supplied=supplied)
            report = read_json(directory / "xhttp-fields-results.json")
            for result in native_results(native, report, directory, allow_partial=True):
                results[result["case_id"]] = result
            if report["status"] != "PASS":
                raise RuntimeError("native XHTTP cases failed")
        if security:
            directory = output / "security"
            security_run(
                directory, [SECURITY[c["case_id"]] for c in security], supplied=supplied
            )
            report = read_json(directory / "xhttp-security-results.json")
            for result in security_results(
                security, report, directory, allow_partial=True
            ):
                results[result["case_id"]] = result
            if report["status"] != "PASS":
                raise RuntimeError("native XHTTP security failed")
    finally:
        (output / "peers.json").write_text(
            json.dumps({k: identity for k, (_, identity) in supplied.items()}, indent=2)
            + "\n"
        )
        (output / "fields.json").write_text(
            json.dumps(fields_report(cases, list(results.values())), indent=2) + "\n"
        )


def required_command_names():
    return {
        f"{identifier}-{i}"
        for identifier in GATES
        for i in range(len(commands(identifier)))
    } | {
        "production-build",
        "offline-scripts",
        "feature-default",
        "feature-minimal",
        "feature-outbound-vless",
        *(
            "feature-" + name
            for name in (
                "outbound-trojan",
                "outbound-vmess",
                "outbound-hysteria2",
                "outbound-wireguard",
                "stream-transport",
                "quic-transport",
            )
        ),
    }


def check(run_dir, cases, run, results, peers, paths):
    from .protocol_harness import SCRIPT_OBSERVATIONS

    needed = {
        "native/xhttp-fields-results.json",
        "security/xhttp-security-results.json",
        "fields.json",
        "script-tests.json",
        "resources.jsonl",
        "peers.json",
        "cases.json",
        "summary.md",
    }
    if not needed <= set(paths) or cases != definitions():
        raise ValueError("missing N5 artifacts or altered frozen metadata")
    recalculated = []
    source_keys = (
        "parent_commit",
        "source_tree_sha256",
        "dirty_patch_sha256",
        "lock_sha256",
    )
    for name, file, evaluator, wanted in (
        ("native", "xhttp-fields-results.json", native_results, NATIVE),
        ("security", "xhttp-security-results.json", security_results, SECURITY),
    ):
        report = read_json(run_dir / name / file)
        if (
            report.get("source") != {key: run.get(key) for key in source_keys}
            or report.get("status") != "PASS"
        ):
            raise ValueError("N5 native source identity mismatch")
        isolation = report.get("isolation", {})
        if (
            isolation.get("host_servers") is not False
            or isolation.get("network_mode") != "hostOnly"
            or not isolation.get("peers")
            or any(
                p.get("joined") is not True or p.get("started") is not True
                for p in isolation["peers"]
            )
        ):
            raise ValueError("N5 native isolation or cleanup missing")
        if any(
            identity != peers.get(kind)
            for kind, identity in report.get("peers", {}).items()
        ):
            raise ValueError("N5 peer identity changed between reports")
        recalculated += evaluator(
            [c for c in cases if c["case_id"] in wanted], report, run_dir / name
        )
    if set(peers) != {"M", "XR", "V2", "Caddy"}:
        raise ValueError("N5 required official peers missing")
    for kind, peer in peers.items():
        project = {
            "M": "MetaCubeX/mihomo",
            "XR": "XTLS/Xray-core",
            "V2": "v2fly/v2ray-core",
            "Caddy": "caddyserver/caddy",
        }[kind]
        if (
            peer.get("target") != "linux-arm64"
            or not peer.get("version")
            or not peer.get("source_url", "").startswith(
                f"https://github.com/{project}/releases/"
            )
            or not HEX.fullmatch(peer.get("binary_sha256", ""))
        ):
            raise ValueError("invalid official N5 peer identity")
        if kind != "Caddy" and not HEX.fullmatch(peer.get("archive_sha256", "")):
            raise ValueError("missing native download digest")
        if kind == "Caddy" and (
            peer.get("source_built") is not True
            or peer.get("build_cleanup") is not True
            or peer.get("extra_plugins") != []
            or set(peer.get("inputs", {})) != {"go.mod", "go.sum", "main.go"}
            or any(not HEX.fullmatch(value) for value in peer["inputs"].values())
        ):
            raise ValueError("gateway is outside the approved xcaddy build exception")
    records = run.get("commands", [])
    if (
        len(records) != len(required_command_names())
        or {r.get("name") for r in records} != required_command_names()
        or any(
            r.get("exit_code") != 0
            or r.get("cleanup") is not True
            or r.get("log") not in paths
            for r in records
        )
    ):
        raise ValueError("missing, duplicate or failed N5 command")
    for case in cases:
        identifier = case["case_id"]
        expected_commands = commands(identifier)
        if not expected_commands:
            continue
        selected, events = [], []
        for i, argv in enumerate(expected_commands):
            record = next(r for r in records if r["name"] == f"{identifier}-{i}")
            if record["command"] != [redact(part) for part in argv]:
                raise ValueError("N5 validation command changed")
            selected.append(record)
            path = run_dir / f"{identifier}-{i}-events.jsonl"
            if path.exists():
                events.extend(read_events(path))
        recalculated.append(gate_result(case, selected, events))
    actual = {r["case_id"]: r for r in results}
    if any(r != actual.get(r["case_id"]) for r in recalculated):
        raise ValueError("N5 results disagree with structured evidence")
    for record in records:
        name = record["name"]
        if name == "feature-default":
            argv = ["cargo", "test", "--locked", "--test", "feature_foundations"]
        elif name.startswith("feature-"):
            argv = ["cargo", "check", "--locked", "--no-default-features", "--lib"]
            if name != "feature-minimal":
                argv += ["--features", name.removeprefix("feature-")]
        elif name == "production-build":
            argv = [
                "cargo",
                "build",
                "--locked",
                "--release",
                "--no-default-features",
                "--features",
                DEFAULT_FEATURES,
                "--lib",
            ]
        elif name == "offline-scripts":
            argv = [
                sys.executable,
                "-m",
                "vcore_scripts.protocol_script_tests",
                str(run_dir / "script-tests.json"),
            ]
        else:
            continue
        if record["command"] != [redact(part) for part in argv]:
            raise ValueError("N5 feature or script command changed")
    script = read_json(run_dir / "script-tests.json")
    tests = {t["test"]: t["status"] for t in script["cases"]}
    required_tests = set(SCRIPT_OBSERVATIONS.values()) | {
        "test_protocol_xhttp.XhttpAcceptanceTest." + name
        for name in (
            "test_frozen_catalog_has_all_rows_modes_and_mux_wires",
            "test_unknown_duplicate_wrong_suite_and_partial_events_fail",
            "test_unit_gate_requires_every_frozen_assertion_and_successful_command",
            "test_native_missing_and_duplicate_records_are_not_success",
        )
    }
    if (
        len(tests) != script["tests_run"]
        or not required_tests <= set(tests)
        or any(v != "PASS" for v in tests.values())
    ):
        raise ValueError("N5 offline failure-path proof missing")
    fields = fields_report(cases, results)
    if read_json(run_dir / "fields.json") != fields or any(
        f["status"] != "PASS" for f in fields["fields"]
    ):
        raise ValueError("incomplete N5 field behavior coverage")
    resources = read_events(run_dir / "resources.jsonl")
    owned = [
        e
        for e in resources
        if e.get("suite") == "N5-OWNED" and e.get("status") == "PASS"
    ]
    if len(owned) != 20 * len(REPRESENTATIVES) or any(
        not idle_resources(e.get("resources")) for e in owned
    ):
        raise ValueError("missing N5 twenty-round owned resource proof")
    print(f"N5: PASS ({len(cases)} required cases; {len(FIELD_IDS)} field rows)")
