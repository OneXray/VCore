"""N6 execution and independent fail-closed reconstruction of persisted evidence."""

from __future__ import annotations

import contextlib
import json
import sys

from .builds import DEFAULT_FEATURES
from .protocol_evidence import HEX, new_result, read_events, read_json
from .protocol_hysteria2_catalog import (
    CFG,
    FIELDS,
    GATES,
    H3,
    UNIT,
    H,
    M,
    assertions_pass,
    definitions,
    events_pass,
)
from .protocol_inputs import redact


def commands(identifier):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if identifier in {"N6-CFG", "N6-UNIT", "N6-RELEASE"}:
        if identifier == "N6-RELEASE":
            cargo += ["--release"]
        result = []
        if identifier != "N6-UNIT":
            result.append(cargo + ["--test", "hysteria2_config"])
        if identifier != "N6-CFG":
            result += [
                cargo + ["--lib", "outbound::hysteria2::"],
                cargo
                + [
                    "--lib",
                    "outbound::connector::tests::authenticated_continuation_keeps_group_choice_but_has_a_new_io_deadline",
                    "--",
                    "--exact",
                ],
                cargo + ["--test", "hysteria2_paths"],
            ]
        return result
    if identifier == "N6-REGRESSION":
        # Every chosen test uses memory IO/config, never a host server.
        targets = [
            "feature_foundations",
            "limit_foundations",
            "trojan",
            "trojan_config",
            "vmess_config",
            "vless_config",
            "vless_lifecycle",
            "xhttp_config",
            "xhttp_budget",
            "h2_stream_regression",
            "stream_foundations",
        ]
        return [
            cargo + sum((["--test", name] for name in targets), []),
            cargo
            + [
                "--test",
                "quic_datagram_foundations",
                "pending_send_is_not_restarted_and_stop_cancels_without_waiting_for_writable",
                "--",
                "--exact",
            ],
        ]
    if identifier == "N6-QUALITY":
        from .protocol_vmess_acceptance import commands as previous

        return previous("N3-QUALITY")[:7] + [
            [
                "cargo",
                "clippy",
                "--locked",
                "--all-features",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
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
    if identifier == "N6-PLATFORMS":
        return [
            ["vcore-scripts", "build", "apple"],
            ["vcore-scripts", "build", "android"],
        ]
    if identifier == "N6-FEATURES":
        checks = [
            ["cargo", "check", "--locked", "--no-default-features", "--lib"]
            + (["--features", feature] if feature else [])
            for feature in (
                "",
                "outbound-hysteria2",
                "quic-transport",
                "outbound-vless",
                "tun",
            )
        ]
        return checks + [
            [
                "cargo",
                "test",
                "--locked",
                "--test",
                "feature_foundations",
                "--test",
                "hysteria2_config",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--test",
                "hysteria2_config",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--features",
                "outbound-hysteria2",
                "--test",
                "hysteria2_config",
            ],
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
        ]
    if identifier == "N6-SCRIPTS":
        return [
            [
                sys.executable,
                "-m",
                "vcore_scripts.protocol_script_tests",
                "{output}/script-tests.json",
            ]
        ]
    return []


def gate_result(case, records, events, script=None):
    identifier = case["case_id"]
    good = bool(records) and all(
        r.get("exit_code") == 0 and r.get("cleanup") is True for r in records
    )
    if identifier in {"N6-CFG", "N6-UNIT", "N6-RELEASE"}:
        expected = {}
        if identifier != "N6-UNIT":
            expected.update({("N6-CFG", name): 1 for name in CFG})
        if identifier != "N6-CFG":
            expected.update({("N6-UNIT", name): 1 for name in UNIT})
        good &= assertions_pass(events, expected)
    if identifier == "N6-SCRIPTS":
        required = {
            "test_protocol_hysteria2.Hysteria2AcceptanceTest." + name
            for name in (
                "test_catalog_covers_all_fields_and_eight_hop_combinations",
                "test_partial_unknown_duplicate_and_wrong_suite_events_fail",
                "test_native_identity_cleanup_or_missing_results_fail",
                "test_bandwidth_and_hop_counters_cannot_be_forged_as_empty_success",
            )
        }
        samples = (script or {}).get("cases", [])
        names = [s.get("test") for s in samples]
        good &= (
            bool(samples)
            and len(names) == len(set(names)) == (script or {}).get("tests_run")
            and required <= set(names)
            and all(s.get("status") == "PASS" for s in samples)
        )
    result = new_result(case)
    result.update(
        status="PASS" if good else "FAIL",
        assertions=dict.fromkeys(case["expected_observation"], bool(good)),
        evidence=case["required_evidence"] if good else [],
        command_exit_code=0 if good else 1,
        cleanup=bool(records) and all(r.get("cleanup") is True for r in records),
    )
    return result


def bandwidth_pass(samples):
    expected = [
        (d, u, down, port, controller)
        for d in ("U", "D")
        for u, down, port, controller in (
            (0, 0, 23000, 0),
            *(
                (rate, 100, 23000, rate * 125000) if d == "U" else (0, rate, 23000, 0)
                for rate in (1, 2)
            ),
            (2, 100, 23002, 125000) if d == "U" else (0, 2, 23003, 0),
        )
    ] + [("U", 2, 0, 23000, 0), ("U", 2, 2, 23004, 0)]
    if len(samples) != len(expected):
        return False
    for sample, key in zip(samples, expected, strict=True):
        if (
            tuple(
                sample.get(k)
                for k in (
                    "direction",
                    "up_mbps",
                    "down_mbps",
                    "listener_port",
                    "controller_bps",
                )
            )
            != key
        ):
            return False
        buckets = sample.get("buckets", [])
        if (
            len(buckets) != 30
            or any(type(v) is not int or v < 0 for v in buckets)
            or sample.get("payload_bps", 0) <= 0
            or sample["payload_bps"] != sum(buckets) / 30
            or sample.get("udp_tx_bytes", 0) <= 0
            or sample.get("udp_rx_bytes", 0) <= 0
        ):
            return False
    for offset in (0, 4):
        rates = [samples[offset + i]["payload_bps"] for i in range(4)]
        if (
            rates[0] < 750000
            or rates[1] > 125000 * 1.1
            or rates[2] > 250000 * 1.1
            or rates[2] < rates[1] * 1.5
            or rates[3] > 125000 * 1.1
        ):
            return False
    return True


def hopping_pass(value):
    return (
        value.get("seconds", 0) >= 60
        and value.get("protected_sockets", 0) >= 9
        and value.get("tcp_bytes_per_direction", 0) >= 10 * 1024 * 1024
        and HEX.fullmatch(value.get("tcp_sha256", "")) is not None
        and value.get("udp_packets") == 1500
        and value.get("udp_target_kinds") == 3
        and len(value.get("udp_maximums", [])) == 3
        and all(1200 < n < 4096 for n in value["udp_maximums"])
        and value.get("socket_peak") == 2
    )


def native_result(case, report, directory):
    from .protocol_hysteria2 import test_command

    identifier = case["case_id"]
    test = M[identifier][0] if identifier in M else H[identifier]["test"]
    records = report.get("cases", [])
    events = directory / (
        f"{test}-events.jsonl" if identifier in M else "hysteria2-events.jsonl"
    )
    observed = read_events(events) if events.exists() else []
    isolation = report.get("isolation", {})
    peers = isolation.get("peers", [])
    clean = (
        report.get("cleanup") is True
        and bool(peers)
        and all(p.get("joined") is True and p.get("started") is True for p in peers)
    )
    good = (
        clean
        and report.get("status") == "PASS"
        and report.get("source_unchanged") is True
        and isolation.get("network_mode") == "hostOnly"
        and isolation.get("host_servers") is False
        and isolation.get("guest_mtu") == 1500
        and bool(isolation.get("image_digest"))
    )
    good &= (
        len(records) == 1
        and all(
            r.get("case_id") == test
            and r.get("status") == "PASS"
            and r.get("exit_code") == 0
            and r.get("command_cleanup") is True
            and r.get("command") == test_command(test)
            for r in records
        )
        and events_pass(observed, test)
    )
    if identifier in M:
        good &= report.get("obfs") is M[identifier][1]
        identity = report.get("peers", {}).get("M", {})
        project = "MetaCubeX/mihomo"
    else:
        identity = report.get("peer", {})
        project = "HyNetworks/hysteria"
        good &= (
            all(
                report.get(k) is H[identifier][k]
                for k in ("ipv6", "obfs", "random_interval")
            )
            and report.get("auth_connections") == 1
        )
        counts = report.get("entry_port_packets", {})
        good &= (
            set(counts) == {"p23010", "p23011", "p23012"}
            and all(type(v) is int and v >= 0 for v in counts.values())
            and sum(v > 0 for v in counts.values())
            >= (2 if test == "native_hopping" else 1)
        )
        if test == "native_hopping":
            good &= (directory / "hopping.json").exists() and hopping_pass(
                read_json(directory / "hopping.json")
            )
    good &= (
        bool(identity.get("version"))
        and HEX.fullmatch(identity.get("binary_sha256", "")) is not None
        and identity.get("source_url", "").startswith(
            f"https://github.com/{project}/releases/"
        )
    )
    if test == "native_bandwidth_matrix":
        path = directory / "bandwidth.jsonl"
        good &= path.exists() and bandwidth_pass(read_events(path))
    if test == "native_mihomo_close_alignment":
        path = directory / "hy2-close-reference.json"
        reference = read_json(path) if path.exists() else {}
        good &= reference == {"tail_hex": "", "terminated": True, "scope": "same-mode"}
    result = new_result(case)
    result.update(
        status="PASS" if good else "FAIL",
        assertions={test: bool(good)},
        evidence=case["required_evidence"] if good else [],
        command_exit_code=0 if good else 1,
        cleanup=clean,
    )
    return result


def fields_report(cases, results):
    status = {r["case_id"]: r["status"] for r in results}
    rows = []
    for field in sorted(FIELDS):
        native = [
            c["case_id"]
            for c in cases
            if field in c["row_ids"] and c["case_id"] in M | H
        ]
        good = (
            status.get("N6-CFG") == "PASS"
            and bool(native)
            and all(status.get(i) == "PASS" for i in native)
        )
        rows.append(
            dict(
                row_id=field,
                configuration="N6-CFG",
                behavior_cases=native,
                status="PASS" if good else "NOT RUN",
            )
        )
    return dict(stage="N6", scope="hysteria2-consumer", fields=rows)


def prepare(output, kinds):
    from .protocol_containers import ContainerLab
    from .protocol_hysteria2_hop import native_binary, packages
    from .protocol_xhttp_acceptance import prepare_peers

    supplied = prepare_peers(output, kinds - {"H"})
    if "H" in kinds:
        root = output / "binaries/H"
        root.mkdir(parents=True)
        binary, identity = native_binary(root)
        record = {}
        try:
            lab = ContainerLab(record, mtu=1500)
            with contextlib.ExitStack() as stack:
                apks = packages(lab, stack, root / "apks")
            supplied["H"] = binary, identity, apks, record["firewall_packages"]
        finally:
            (output / "package-preparation.json").write_text(
                json.dumps(record, indent=2) + "\n"
            )
    return supplied


def h3_jobs():
    return {
        name: [dict(case_id=name, test="public_base")]
        for name in (
            "h3-stream-one-headers",
            "h3-stream-up-headers",
            "h3-packet-up-headers",
        )
    }


def h3_result(case, report, directory):
    from .protocol_xhttp_fields import public_events_pass

    jobs = h3_jobs()
    records = report.get("cases", [])
    isolation = report.get("isolation", {})
    owned = isolation.get("peers", [])
    good = (
        report.get("status") == "PASS"
        and report.get("cleanup") is True
        and report.get("source_unchanged") is True
        and {r.get("case_id") for r in records} == set(jobs)
        and len(records) == len(jobs)
        and isolation.get("network_mode") == "hostOnly"
        and isolation.get("host_servers") is False
        and isolation.get("guest_mtu") == 1500
        and bool(isolation.get("image_digest"))
        and bool(owned)
        and all(p.get("started") is True and p.get("joined") is True for p in owned)
        and set(report.get("peers", {})) == {"M", "XR"}
    )
    for record in records:
        path = directory / (record["case_id"] + "-events.jsonl")
        good &= (
            record.get("exit_code") == 0
            and record.get("command_cleanup") is True
            and record.get("status") == "PASS"
            and record.get("assertion") == "public_base"
            and record.get("command")
            == [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "vless_public",
                "public_base",
                "--",
                "--exact",
                "--ignored",
                "--nocapture",
            ]
            and path.exists()
            and public_events_pass(read_events(path), "public_base")
        )
    result = new_result(case)
    result.update(
        status="PASS" if good else "FAIL",
        assertions={case["expected_observation"][0]: bool(good)},
        evidence=case["required_evidence"] if good else [],
        command_exit_code=0 if good else 1,
        cleanup=report.get("cleanup") is True,
    )
    return result


def execute(cases, run, output, results):
    from .protocol_harness import _command
    from .protocol_hysteria2 import run as run_m
    from .protocol_hysteria2_hop import run as run_h

    supplied = {}
    try:
        for case in cases:
            identifier = case["case_id"]
            if identifier not in GATES:
                continue
            records, events = [], []
            for index, argv in enumerate(commands(identifier)):
                argv = [v.replace("{output}", str(output)) for v in argv]
                name = f"{identifier}-{index}"
                path = output / f"{name}-events.jsonl"
                _command(run, output, name, argv, case["timeout_seconds"], events=path)
                records.append(run["commands"][-1])
                if path.exists():
                    events += read_events(path)
            script = (
                read_json(output / "script-tests.json")
                if identifier == "N6-SCRIPTS"
                else None
            )
            results[identifier] = gate_result(case, records, events, script)
            if results[identifier]["status"] != "PASS":
                raise RuntimeError(f"N6 local gate failed: {identifier}")
        kinds = {"M" for c in cases if c["case_id"] in M} | {
            "H" for c in cases if c["case_id"] in H
        }
        if any(c["case_id"] == H3 for c in cases):
            kinds |= {"M", "XR"}
        supplied = prepare(output, kinds)
        for case in cases:
            identifier = case["case_id"]
            directory = output / identifier
            if identifier in M:
                test, obfs, _ = M[identifier]
                report = run_m(directory, test, obfs=obfs, supplied=supplied["M"])
                result = native_result(case, report, directory)
            elif identifier in H:
                report = run_h(directory, **H[identifier], supplied=supplied["H"])
                result = native_result(case, report, directory)
            elif identifier == H3:
                from .protocol_xhttp_fields import run as run_h3

                jobs = h3_jobs()
                run_h3(
                    directory,
                    list(jobs),
                    jobs=jobs,
                    supplied={k: supplied[k] for k in ("M", "XR")},
                )
                report = read_json(directory / "xhttp-fields-results.json")
                result = h3_result(case, report, directory)
            else:
                continue
            results[identifier] = result
            print(f"{identifier}: {result['status']}", flush=True)
            if result["status"] != "PASS":
                raise RuntimeError(f"N6 native gate failed: {identifier}")
    finally:
        (output / "peers.json").write_text(
            json.dumps(
                {kind: artifact[1] for kind, artifact in supplied.items()}, indent=2
            )
            + "\n"
        )
        (output / "fields.json").write_text(
            json.dumps(fields_report(cases, list(results.values())), indent=2) + "\n"
        )


def check(run_dir, cases, run, results, peers, paths):
    if (
        cases != definitions()
        or set(peers) != {"M", "H", "XR"}
        or not {
            "fields.json",
            "script-tests.json",
            "package-preparation.json",
        }
        <= set(paths)
    ):
        raise ValueError("incomplete N6 stage artifacts or altered manifest")
    actual = {r["case_id"]: r for r in results}
    records = run.get("commands", [])
    expected_names = {
        f"{c['case_id']}-{i}"
        for c in cases
        for i, _ in enumerate(commands(c["case_id"]))
    }
    if (
        len(records) != len(expected_names)
        or {r.get("name") for r in records} != expected_names
    ):
        raise ValueError("missing, duplicate or extra N6 validation command")
    source = {
        k: run[k]
        for k in (
            "parent_commit",
            "source_tree_sha256",
            "dirty_patch_sha256",
            "lock_sha256",
        )
    }
    for case in cases:
        identifier = case["case_id"]
        if identifier in GATES:
            selected, events = [], []
            for i, argv in enumerate(commands(identifier)):
                record = next(r for r in records if r["name"] == f"{identifier}-{i}")
                if (
                    record["command"]
                    != [redact(v.replace("{output}", str(run_dir))) for v in argv]
                    or record["log"] not in paths
                ):
                    raise ValueError("N6 validation command/log changed")
                selected.append(record)
                path = run_dir / f"{identifier}-{i}-events.jsonl"
                if path.exists():
                    events += read_events(path)
            recalculated = gate_result(
                case,
                selected,
                events,
                read_json(run_dir / "script-tests.json")
                if identifier == "N6-SCRIPTS"
                else None,
            )
        else:
            directory = run_dir / identifier
            report = read_json(
                directory
                / ("xhttp-fields-results.json" if identifier == H3 else "report.json")
            )
            if report.get("source") != source:
                raise ValueError("N6 native source differs from stage input")
            recalculated = (
                h3_result(case, report, directory)
                if identifier == H3
                else native_result(case, report, directory)
            )
            if identifier in H:
                if report.get("peer") != peers.get("H"):
                    raise ValueError("H native identity changed")
                preparation = read_json(run_dir / "package-preparation.json")
                if report.get("isolation", {}).get(
                    "firewall_packages"
                ) != preparation.get("firewall_packages"):
                    raise ValueError("H native firewall package identity changed")
            elif set(report.get("peers", {})) != (
                {"M", "XR"} if identifier == H3 else {"M"}
            ):
                raise ValueError("missing or extra native peer identity")
            elif any(
                identity != peers.get(kind)
                for kind, identity in report.get("peers", {}).items()
            ):
                raise ValueError("native identity changed between reports")
        if recalculated != actual[identifier] or recalculated["status"] != "PASS":
            raise ValueError("N6 results differ from structured evidence")
    preparation = read_json(run_dir / "package-preparation.json")
    if (
        not preparation.get("firewall_packages")
        or not preparation.get("peers")
        or any(p.get("joined") is not True for p in preparation["peers"])
    ):
        raise ValueError("native firewall preparation identity/cleanup missing")
    fields = fields_report(cases, results)
    if read_json(run_dir / "fields.json") != fields or any(
        f["status"] != "PASS" for f in fields["fields"]
    ):
        raise ValueError("missing N6 field behavior coverage")
    print(f"N6: PASS ({len(cases)} required cases; {len(FIELDS)} field rows)")


def preflight(output):
    # The normal native gates prove readiness as well as protocol behavior;
    # this command deliberately never fabricates a protocol PASS.
    supplied = prepare(output, {"M", "H", "XR"})
    (output / "peers.json").write_text(
        json.dumps({k: v[1] for k, v in supplied.items()}, indent=2) + "\n"
    )
