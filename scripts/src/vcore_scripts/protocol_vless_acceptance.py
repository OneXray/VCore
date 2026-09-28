"""VLESS container-only public consumer acceptance and independent coverage."""

from __future__ import annotations

import json
import sys

from .builds import DEFAULT_FEATURES
from .protocol_evidence import HEX, idle_resources, new_result, read_events, read_json
from .protocol_inputs import redact
from .protocol_vless_container import run as native_run
from .protocol_vless_public import PUBLIC, WIRE, events_pass
from .protocol_vmess_acceptance import OBSERVATIONS as PREVIOUS_OBSERVATIONS
from .protocol_vmess_acceptance import SCRIPT_ASSERTIONS

NATIVE = WIRE | PUBLIC
FIELD_IDS = {
    *(f"C{i:02}" for i in range(1, 7)),
    *(f"T{i:02}" for i in range(2, 9)),
    *(f"W{i:02}" for i in range(1, 8)),
    *(f"G{i:02}" for i in range(1, 7)),
    *(f"H{i:02}" for i in range(1, 7)),
    *(f"VL{i:02}" for i in range(1, 6)),
    "S01",
    "S02",
}
GATES = {
    "VLESS-CFG",
    "VLESS-CODEC",
    "VLESS-TRANSPORT",
    "VLESS-VISION",
    "VLESS-REGRESSION",
    "VLESS-RELEASE",
    "VLESS-FEATURES",
    "VLESS-SCRIPTS",
    "VLESS-QUALITY",
}
REQUIRED_IDS = set(NATIVE) | GATES
OBSERVATIONS = {
    "VLESS-CFG": [
        "inline_client_identity_is_validated_and_redacted_before_io",
        "vision_requires_tcp_tls13_and_xudp_before_any_io",
        "default_tcp_and_three_udp_encodings_are_accepted_without_io",
        "tcp_and_existing_xhttp_reject_mismatched_and_future_options",
        "stream_transports_and_explicit_tls_policy_have_strict_public_fields",
        "extended_ws_and_grpc_fields_are_scoped_and_bounded",
    ],
    "VLESS-CODEC": [
        "stopping_before_first_udp_send_wakes_receive_and_releases_io",
        "raw_and_packetaddr_consume_wire_and_keep_cancelled_receive_progress",
        "udp_cancelled_send_and_bad_response_header_close_owned_io",
        "tcp_bad_response_header_poisoning_and_absolute_response_deadline",
        "vless_all_handshakes_keep_the_original_deadline_and_join_cancelled_io",
        "vless_expired_deadline_and_protect_failure_never_fall_back",
    ],
    "VLESS-TRANSPORT": [
        "http_camouflage_shutdown_releases_both_directions_without_waiting_for_peer_eof",
        "grpc_server_first_flushes_vless_request_without_an_application_write",
        "http_upgrade_consumes_early_prefix_and_requires_valid_101_even_fast_open",
        "grpc_idle_ping_is_observable_disabled_by_zero_and_joined_at_stop",
        "grpc_pool_matches_both_threshold_policies_and_keeps_other_streams_alive",
    ],
    "VLESS-VISION": [
        "vision_fragmented_headers_content_padding_and_cancelled_reads_keep_raw_tail",
        "vision_invalid_uuid_command_and_truncation_poison_the_stream",
        "vision_bounded_partial_writes_flush_and_close_preserve_all_plaintext",
        "fragmented_server_hello_distinguishes_tls12_tls13_and_non_tls",
        "record_boundary_preserves_buffered_plaintext_and_coalesced_raw_tail_and_flush_order",
    ],
}
OBSERVATIONS["VLESS-REGRESSION"] = (
    PREVIOUS_OBSERVATIONS["VMESS-REGRESSION"]
    + PREVIOUS_OBSERVATIONS["VMESS-CFG"]
    + PREVIOUS_OBSERVATIONS["VMESS-CODEC"]
    + PREVIOUS_OBSERVATIONS["VMESS-CANCEL"]
    + [
        "all_two_hop_protocol_combinations_build_as_connector_graphs",
        "direct_download_constructor_reuses_or_requires_the_precise_prepared_endpoint",
        "split_node_over_a_proxy_automatically_reuses_its_parent_for_both_legs",
    ]
)
OBSERVATIONS["VLESS-RELEASE"] = sum(
    (
        OBSERVATIONS[key]
        for key in ("VLESS-CFG", "VLESS-CODEC", "VLESS-TRANSPORT", "VLESS-VISION")
    ),
    [],
)


def rows(identifier):
    if identifier == "VLESS-CFG":
        return sorted(FIELD_IDS)
    if identifier == "VLESS-CODEC":
        return ["VL01", "VL02", "VL04"]
    if identifier == "VLESS-TRANSPORT":
        return [*(f"G{i:02}" for i in range(1, 7)), "W06", "W07"]
    if identifier == "VLESS-VISION":
        return ["VL03", "VL04", "VL05", "S01", "S02"]
    if identifier in GATES or identifier.startswith("VLESS-REGRESSION"):
        return []
    _, mode, tls, test = NATIVE[identifier]
    result = {"VL01", "VL02", "VL04", "VL05"}
    if identifier in PUBLIC:
        result |= {*(f"C{i:02}" for i in range(1, 6))}
    if "graph" in test or "selection" in test:
        result.add("C06")
    if mode.endswith("-reality"):
        result |= {"S01", "S02", "T02"}
    elif tls:
        result |= {"T02", "T03", "T04", "T05"}
    if mode.endswith("-mtls"):
        result |= {"T06", "T07", "T08"}
    if mode.startswith("vision-"):
        result.add("VL03")
    if mode.startswith(("ws", "upgrade")):
        result |= {*(f"W{i:02}" for i in range(1, 6))}
    if mode.startswith("upgrade"):
        result |= {"W06", "W07"}
    if mode.startswith("grpc"):
        result |= {*(f"G{i:02}" for i in range(1, 7))}
    if mode.startswith("http"):
        result |= {"H01", "H02", "H03", "H04"}
    if mode.startswith("h2"):
        result |= {"H05", "H06"}
    return sorted(result)


def definitions():
    cases = []
    for identifier in sorted(REQUIRED_IDS):
        kind, mode, tls, test = NATIVE.get(
            identifier, ("unit", "memory-or-build", False, identifier)
        )
        native = identifier in NATIVE
        substage = (
            "VLESS.vision"
            if mode.startswith("vision-") or identifier == "VLESS-VISION"
            else "VLESS.tcp"
            if mode in {"tcp", "tcp-tls"} or identifier == "VLESS-CODEC"
            else "VLESS.transports"
            if mode.startswith(("ws", "grpc", "http", "h2", "upgrade"))
            or identifier == "VLESS-TRANSPORT"
            else "VLESS.acceptance"
        )
        cases.append(
            dict(
                case_id=identifier,
                stage="VLESS",
                substage=substage,
                required=True,
                row_ids=rows(identifier),
                protocol="vless",
                network=mode,
                security="tls" if tls else "plain",
                udp_codec="raw/xudp/packetaddr"
                if "udp" in test or test == "public_base"
                else "per-assertion",
                field_values={
                    "network": mode,
                    "tls": tls,
                    "scope": "protocol-consumer",
                    "close_reference": "ws-standard-tls-baseline"
                    if test == "native_ws_reality_close_boundary"
                    else "same-mode"
                    if test == "native_mihomo_close_alignment"
                    else "not-applicable",
                },
                outer_family="IPv4/IPv6" if "ipv6" in test else "IPv4",
                inner_family="IPv4/IPv6/domain"
                if "base" in test or "udp_boundaries" in test
                else "per-assertion",
                target_type="isolated synthetic origin" if native else "memory-only",
                upstream_graph="direct/concrete/nested-select"
                if "graph" in test
                else "per-assertion",
                peer_kind=kind,
                peer_config=dict(mode=mode, tls=tls, test=test),
                gap_source={
                    "reason": "Mihomo WS client ignores RealityOpts; "
                    "REALITY listener data "
                    "is native-tested, but close uses the separate standard-TLS WS "
                    "adapter reference plus independent REALITY close cases, not a "
                    "same-combination client differential. Original failures retained.",
                    "source": "https://github.com/MetaCubeX/mihomo/blob/ab405bad5beeeac8b003bb01f60f134f6df54471/adapter/outbound/vless.go",
                }
                if test == "native_ws_reality_close_boundary"
                else {
                    "reason": "Mihomo VLESS listener has no HTTP header/legacy H2 "
                    "or custom ED field; official V2Ray supplements only these paths",
                    "source": "https://github.com/MetaCubeX/mihomo/blob/v1.19.31/listener/inbound/vless.go",
                }
                if kind == "V2"
                else None,
                expected_observation=[test]
                if native
                else SCRIPT_ASSERTIONS
                if identifier == "VLESS-SCRIPTS"
                else OBSERVATIONS.get(identifier, [identifier]),
                required_evidence=["structured-assertions", "command", "cleanup"]
                + (["peer-identity", "isolated-origins"] if native else []),
                prerequisites=[
                    "owned-host-only-container-network",
                    "official-latest-peer",
                ]
                if native
                else ["rust-toolchain"],
                runner="native-vless" if native else "vless-gate",
                timeout_seconds=240 if native else 1200,
            )
        )
    return cases


def commands(identifier):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if identifier == "VLESS-CFG":
        return [cargo + ["--test", "vless_config"], cargo + ["--lib", "config::"]]
    if identifier == "VLESS-CODEC":
        return [cargo + ["--test", "vless_codec", "--test", "vless_lifecycle"]]
    if identifier == "VLESS-TRANSPORT":
        return [cargo + ["--test", "vless_transports", "--test", "grpc_pool"]]
    if identifier == "VLESS-VISION":
        return [cargo + ["--lib", "vision"]]
    if identifier == "VLESS-RELEASE":
        return [
            cargo
            + [
                "--release",
                "--test",
                "vless_config",
                "--test",
                "vless_codec",
                "--test",
                "vless_lifecycle",
                "--test",
                "vless_transports",
                "--test",
                "grpc_pool",
            ],
            cargo + ["--release", "--lib", "vision"],
        ]
    if identifier == "VLESS-REGRESSION":
        from .protocol_vmess_acceptance import commands as previous

        return (
            previous("VMESS-REGRESSION")
            + previous("VMESS-CFG")
            + previous("VMESS-CODEC")
            + previous("VMESS-CANCEL")
            + [
                cargo
                + ["--lib", "outbound::vless::outbound::connector_composition_tests::"]
            ]
            + [
                ["cargo", "test", "--locked", "--no-default-features"]
                + features
                + [
                    "--test",
                    "feature_foundations",
                    "vless_yaml_follows_its_own_feature",
                    "--",
                    "--exact",
                ]
                for features in ([], ["--features", "outbound-trojan"])
            ]
        )
    if identifier == "VLESS-QUALITY":
        from .protocol_vmess_acceptance import commands as previous

        return previous("VMESS-QUALITY")
    return []


def gate_result(case, records, events):
    result = new_result(case)
    good = bool(records) and all(
        r.get("exit_code") == 0 and r.get("cleanup") is True for r in records
    )
    identifier = case["case_id"]
    assertions = {}
    if identifier in OBSERVATIONS:
        for name in case["expected_observation"]:
            observed = [e for e in events if e.get("assertion") == name]
            assertions[name] = len(observed) == 2 and [
                e.get("status") for e in observed
            ] == ["BEGIN", "PASS"]
        good &= (
            bool(assertions)
            and all(assertions.values())
            and all(
                e.get("schema_version") == 1 and e.get("status") in {"BEGIN", "PASS"}
                for e in events
            )
        )
    else:
        assertions = dict.fromkeys(case["expected_observation"], good)
    result.update(
        status="PASS" if good else "FAIL",
        assertions=assertions,
        evidence=case["required_evidence"] if good else [],
        command_exit_code=0 if good else 1,
        cleanup=all(r.get("cleanup") is True for r in records),
    )
    return result


def native_results(cases, report, directory):
    records = report.get("cases", [])
    expected = {case["case_id"] for case in cases}
    if len(records) != len(expected) or {r.get("case_id") for r in records} != expected:
        raise ValueError("missing, duplicate or unknown VLESS native case")
    by_id = {record["case_id"]: record for record in records}
    output = []
    for case in cases:
        record = by_id[case["case_id"]]
        path = directory / (case["case_id"] + "-events.jsonl")
        observed = read_events(path) if path.exists() else []
        test = NATIVE[case["case_id"]][3]
        observed_ok = (
            events_pass(observed, test, NATIVE[case["case_id"]][1])
            if case["case_id"] in PUBLIC
            else observed
            == [
                dict(
                    schema_version=1, suite="VLESS-WIRE", assertion=test, status=status
                )
                for status in ("BEGIN", "PASS")
            ]
        )
        clean = (
            record.get("command_cleanup") is True
            and record.get("cleanup") is True
            and report.get("cleanup") is True
        )
        expected_command = [
            "cargo",
            "test",
            "--locked",
            "--all-features",
            "--test",
            "vless_public" if case["case_id"] in PUBLIC else "vless_native",
            test,
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ]
        good = (
            observed_ok
            and clean
            and report.get("source_unchanged") is True
            and record.get("exit_code") == 0
            and record.get("status") == "PASS"
            and record.get("command") == expected_command
            and record.get("peer_kind") == case["peer_kind"]
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


def fields_report(cases, results):
    statuses = {result["case_id"]: result["status"] for result in results}
    complete = set(statuses) == REQUIRED_IDS and all(
        value == "PASS" for value in statuses.values()
    )
    fields = []
    for row in sorted(FIELD_IDS):
        owners = [c["case_id"] for c in cases if row in c["row_ids"]]
        fields.append(
            dict(
                row_id=row,
                required_cases=owners,
                status="PASS" if complete and len(owners) > 1 else "NOT RUN",
            )
        )
    return dict(schema_version=1, stage="VLESS", protocol="vless", fields=fields)


def execute(cases, run, output, results):
    from .protocol_harness import _command, _features, _scripts

    for case in cases:
        identifier = case["case_id"]
        if identifier in NATIVE:
            continue
        if identifier == "VLESS-FEATURES":
            result = _features(case, run, output)
            independent = _command(
                run,
                output,
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
                1200,
            )
            if independent.returncode or not independent.cleanup:
                result.update(
                    status="FAIL",
                    command_exit_code=independent.returncode,
                    cleanup=independent.cleanup,
                )
            build = _command(
                run,
                output,
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
                1200,
            )
            if build.returncode or not build.cleanup:
                result.update(
                    status="FAIL",
                    command_exit_code=build.returncode,
                    cleanup=build.cleanup,
                )
            results[identifier] = result
        elif identifier == "VLESS-SCRIPTS":
            results[identifier] = _scripts(case, run, output)
        else:
            events = []
            start = len(run["commands"])
            for index, argv in enumerate(commands(identifier)):
                path = output / f"{identifier}-{index}-events.jsonl"
                _command(run, output, f"{identifier}-{index}", argv, 1200, events=path)
                if path.exists():
                    events.extend(read_events(path))
            results[identifier] = gate_result(case, run["commands"][start:], events)
    native = [case for case in cases if case["case_id"] in NATIVE]
    if native:
        directory = output / "native"
        native_run(directory, [case["case_id"] for case in native])
        report = read_json(directory / "vless-results.json")
        (output / "peers.json").write_text(json.dumps(report["peers"], indent=2) + "\n")
        for result in native_results(native, report, directory):
            results[result["case_id"]] = result
    (output / "fields.json").write_text(
        json.dumps(fields_report(cases, list(results.values())), indent=2) + "\n"
    )


def required_command_names():
    # The shared feature smoke includes VMess; VLESS separately adds VLESS.
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
                "stream-transport",
                "quic-transport",
            )
        ),
    }


def check(run_dir, cases, run, results, peers, paths):
    from .protocol_harness import SCRIPT_OBSERVATIONS

    needed = {
        "native/vless-results.json",
        "fields.json",
        "script-tests.json",
        "resources.jsonl",
        "peers.json",
        "cases.json",
        "summary.md",
    }
    if not needed <= set(paths):
        raise ValueError("missing VLESS acceptance artifacts")
    expected = {c["case_id"]: c for c in definitions()}
    if len(cases) != len(expected) or any(
        c != expected.get(c["case_id"]) for c in cases
    ):
        raise ValueError("VLESS frozen case metadata changed")
    report = read_json(run_dir / "native/vless-results.json")
    source_keys = (
        "parent_commit",
        "source_tree_sha256",
        "dirty_patch_sha256",
        "lock_sha256",
    )
    if (
        report.get("source") != {key: run.get(key) for key in source_keys}
        or report.get("status") != "PASS"
    ):
        raise ValueError("VLESS peer evidence input mismatch")
    isolation = report.get("isolation", {})
    if (
        isolation.get("host_servers") is not False
        or isolation.get("network_mode") != "hostOnly"
        or not isolation.get("peers")
        or not all(
            p.get("joined") is True and p.get("started") is True
            for p in isolation["peers"]
        )
    ):
        raise ValueError("VLESS peers not isolated or cleaned")
    if peers != report.get("peers") or set(peers) != {"M", "V2"}:
        raise ValueError("missing VLESS official peers")
    for kind, peer in peers.items():
        project = "MetaCubeX/mihomo" if kind == "M" else "v2fly/v2ray-core"
        if (
            peer.get("kind") != kind
            or peer.get("target") != "linux-arm64"
            or not peer.get("version")
            or not peer.get("source_url", "").startswith(
                f"https://github.com/{project}/releases/"
            )
            or not all(
                HEX.fullmatch(peer.get(key, ""))
                for key in ("archive_sha256", "binary_sha256")
            )
        ):
            raise ValueError("invalid official VLESS peer identity")
    actual = {r["case_id"]: r for r in results}
    recalculated = native_results(
        [c for c in cases if c["case_id"] in NATIVE], report, run_dir / "native"
    )
    for case in cases:
        identifier = case["case_id"]
        argv = commands(identifier)
        if not argv:
            continue
        records = []
        events = []
        for i, command in enumerate(argv):
            matching = [r for r in run["commands"] if r["name"] == f"{identifier}-{i}"]
            if len(matching) != 1 or matching[0]["command"] != [
                redact(part) for part in command
            ]:
                raise ValueError("missing VLESS gate command")
            records.extend(matching)
            path = run_dir / f"{identifier}-{i}-events.jsonl"
            if path.exists():
                events.extend(read_events(path))
        recalculated.append(gate_result(case, records, events))
    for item in recalculated:
        if item != actual.get(item["case_id"]):
            raise ValueError("VLESS results disagree with structured observations")
    names = [c["name"] for c in run["commands"]]
    needed_commands = required_command_names()
    if (
        len(names) != len(set(names))
        or set(names) != needed_commands
        or any(
            c.get("exit_code") != 0
            or c.get("cleanup") is not True
            or c.get("log") not in paths
            for c in run["commands"]
        )
    ):
        raise ValueError("missing or failed VLESS validation command")
    for record in run["commands"]:
        name = record["name"]
        if name == "feature-default":
            expected_command = [
                "cargo",
                "test",
                "--locked",
                "--test",
                "feature_foundations",
            ]
        elif name.startswith("feature-"):
            expected_command = [
                "cargo",
                "check",
                "--locked",
                "--no-default-features",
                "--lib",
            ]
            if name != "feature-minimal":
                expected_command += ["--features", name.removeprefix("feature-")]
        elif name == "production-build":
            expected_command = [
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
            expected_command = [
                sys.executable,
                "-m",
                "vcore_scripts.protocol_script_tests",
                str(run_dir / "script-tests.json"),
            ]
        else:
            continue
        if record["command"] != [redact(part) for part in expected_command]:
            raise ValueError("VLESS feature or script command changed")
    script = read_json(run_dir / "script-tests.json")
    tests = {t["test"]: t["status"] for t in script["cases"]}
    if (
        len(tests) != script["tests_run"]
        or any(tests.get(name) != "PASS" for name in SCRIPT_OBSERVATIONS.values())
        or any(status != "PASS" for status in tests.values())
    ):
        raise ValueError("missing harness failure-path tests")
    fields = fields_report(cases, results)
    if read_json(run_dir / "fields.json") != fields or any(
        f["status"] != "PASS" for f in fields["fields"]
    ):
        raise ValueError("incomplete VLESS field coverage")
    resources = read_events(run_dir / "resources.jsonl")
    owned = [
        e
        for e in resources
        if e.get("suite") == "VLESS-OWNED" and e.get("status") == "PASS"
    ]
    if len(owned) != 80 or not all(idle_resources(e.get("resources")) for e in owned):
        raise ValueError("missing 20-round owned resource evidence per selected mode")
    print(
        f"VLESS: PASS ({len(cases)} required cases; {len(FIELD_IDS)} VLESS field rows)"
    )
