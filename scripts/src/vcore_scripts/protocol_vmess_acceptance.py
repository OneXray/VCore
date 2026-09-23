"""N3 container-only execution and independently recomputed stage acceptance."""

from __future__ import annotations

import json
import sys

from .builds import DEFAULT_FEATURES
from .protocol_evidence import HEX, idle_resources, new_result, read_events, read_json
from .protocol_inputs import redact
from .protocol_vmess import CASES as WIRE
from .protocol_vmess_container import run as native_run
from .protocol_vmess_public import CASES as PUBLIC
from .protocol_vmess_public import events_pass

NATIVE = WIRE | PUBLIC
FIELD_IDS = {
    *(f"C{i:02}" for i in range(1, 7)),
    *(f"T{i:02}" for i in range(2, 6)),
    *(f"W{i:02}" for i in range(1, 6)),
    "G01",
    *(f"H{i:02}" for i in range(1, 7)),
    *(f"VM{i:02}" for i in range(1, 9)),
}
GATES = {
    "N3-CFG",
    "N3-CODEC",
    "N3-CANCEL",
    "N3-REGRESSION",
    "N3-RELEASE",
    "N3-FEATURES",
    "N3-SCRIPTS",
    "N3-QUALITY",
}
SCRIPT_ASSERTIONS = [
    "offline-success",
    "missing-duplicate-unknown-case",
    "download-failure",
    "timeout",
    "sigint",
    "partial-start",
    "permission",
    "peer-exit",
    "cleanup-failure",
    "redaction",
]
REQUIRED_IDS = set(NATIVE) | GATES
# Frozen names, not a regex over test output and not read from the manifest.
OBSERVATIONS = {
    "N3-CFG": [
        "vmess_default_node_and_explicit_cipher_aliases_are_accepted_without_io",
        "vmess_transport_and_security_combinations_are_strict",
        "vmess_field_boundaries_and_normalized_transport_values",
        "vmess_normalized_websocket_fields_preserve_headers_and_early_data_order",
    ],
    "N3-CODEC": [
        "xudp_cancelled_send_and_bad_frame_release_io_and_cannot_resume",
        "xudp_zero_global_id_omits_the_optional_extension_like_mihomo",
        "packetaddr_has_ip_only_address_first_wire_and_rejects_truncation",
        "vmess_aead_requests_are_fresh_bounded_and_redacted",
        "vmess_response_authentication_cannot_be_skipped_by_none_cipher",
        "vmess_whole_close_wakes_reader_and_releases_io_before_response",
        "xudp_explicit_budget_rejects_max_plus_one_before_writing",
        "independently_published_nested_hmac_vectors",
        "chunks_preserve_boundaries_masks_padding_and_authenticated_eof",
        "tags_lengths_and_nonce_exhaustion_fail_closed",
        "auto_uses_detected_hardware_not_architecture_name",
    ],
    "N3-CANCEL": [
        "vmess_all_handshakes_keep_the_original_deadline_and_join_cancelled_io",
        "vmess_expired_deadline_and_protect_failure_never_fall_back",
    ],
    "N3-REGRESSION": [
        "shared_xudp_receives_frames_without_a_vless_response_header",
        "first_frame_matches_xray_mux_wire_format",
        "followup_frame_carries_each_datagrams_destination",
        "destination_codec_round_trips_all_address_families",
        "normal_and_error_end_frames_are_distinguishable",
        "oversized_response_is_rejected_before_payload_read",
        "fragmented_receive_survives_cancellation_and_resumes",
        "keepalive_data_is_consumed_without_becoming_an_udp_response",
        "full_wire_payload_remains_available_to_proxy_inbounds",
        "request_matches_the_official_sha224_and_socks_address_wire_format",
        "authentication_and_requests_are_strict_and_never_debug_credentials",
        "invalid_truncated_and_oversized_frames_fail_closed_without_payload_leaks",
        "datagram_limits_preserve_messages_and_drain_over_budget_responses",
        "datagram_sends_one_frame_and_receives_fragmented_consecutive_frames",
        "cancelled_receive_preserves_partial_frames_and_does_not_block_send",
        "cancelled_partial_send_poison_closes_without_replaying_or_waiting",
        "trojan_tcp_configuration_and_node_graph_accept_the_approved_fields",
        "trojan_tcp_defaults_preserve_credentials_and_address_policy",
        "trojan_invalid_configuration_is_rejected_without_exposing_credentials",
        "trojan_ws_and_grpc_configuration_applies_transport_specific_defaults",
        "trojan_transport_boundaries_fail_before_runtime_io",
        "transport_options_reject_ambiguous_headers_before_io",
        "http_first_header_preserves_prefix_raw_continuation_and_half_close_tail",
        "legacy_h2_keeps_unframed_bytes_server_first_and_owned_whole_close",
        "websocket_rejects_invalid_upgrade_responses_and_bounded_header_overflows",
        "websocket_early_data_and_remaining_frames_keep_the_original_byte_order",
        "setup_deadline_releases_supplied_io_in_stream_adapters",
        "cancelled_setup_releases_supplied_io_without_a_detached_task",
        "ws_rejects_oversized_and_truncated_frames_instead_of_reporting_eof",
        "ws_accepts_mihomo_clean_underlay_eof_only_at_complete_message_boundaries",
        "dropping_an_established_ws_releases_its_only_io_owner",
        "grpc_rejects_oversized_truncated_and_invalid_records",
        "grpc_large_writes_obey_small_http2_windows_and_keep_byte_integrity",
        "ws_partial_writes_empty_frames_ping_and_half_close_preserve_every_byte",
        "grpc_handles_response_after_upload_fragmented_records_and_owned_stop",
        "websocket_supplied_io_preserves_server_first_and_partial_writes",
        "xhttp_keeps_complete_response_when_peer_resets_after_end_stream",
        "xhttp_does_not_hide_reset_before_end_stream",
        "feature_skeletons_do_not_open_unimplemented_yaml_or_measurement_protocols",
        "future_fields_and_over_limit_documents_remain_rejected",
        "registry_matches_live_production_constants_and_has_owned_boundary_cases",
        "webpki_rejects_untrusted_wrong_name_and_expired_unless_explicitly_skipped",
        "leaf_pin_is_trust_but_nonleaf_pin_checks_chain_name_and_expiry",
        "ticket_storage_obeys_exact_node_budget_and_consumes_each_ticket_once",
        "every_certificate_policy_verifies_tls12_and_tls13_handshake_signatures",
        "vless_keeps_webpki_tls13_and_required_h2_after_anytls_connections",
        "alpn_and_tls_resumption_are_isolated_between_node_policies",
        "explicit_verification_name_does_not_change_sni_or_allow_skip_to_override_it",
        "mutual_tls_identity_is_required_verified_and_not_shared_between_clients",
        "tls_options_reject_invalid_alpn_identity_and_budget_before_using_a_stream",
        "certificate_rejection_delivers_no_business_bytes_and_diagnostics_are_redacted",
        "tls_close_write_sends_notify_without_closing_the_supplied_transport",
        "tls_close_notify_flush_has_a_five_second_bound",
        "cancelling_tls_handshake_releases_the_caller_supplied_stream",
    ],
    "N3-RELEASE": [
        "vmess_default_node_and_explicit_cipher_aliases_are_accepted_without_io",
        "vmess_transport_and_security_combinations_are_strict",
        "vmess_field_boundaries_and_normalized_transport_values",
        "vmess_normalized_websocket_fields_preserve_headers_and_early_data_order",
        "xudp_cancelled_send_and_bad_frame_release_io_and_cannot_resume",
        "xudp_zero_global_id_omits_the_optional_extension_like_mihomo",
        "packetaddr_has_ip_only_address_first_wire_and_rejects_truncation",
        "vmess_aead_requests_are_fresh_bounded_and_redacted",
        "vmess_response_authentication_cannot_be_skipped_by_none_cipher",
        "vmess_whole_close_wakes_reader_and_releases_io_before_response",
        "xudp_explicit_budget_rejects_max_plus_one_before_writing",
        "independently_published_nested_hmac_vectors",
        "chunks_preserve_boundaries_masks_padding_and_authenticated_eof",
        "tags_lengths_and_nonce_exhaustion_fail_closed",
        "auto_uses_detected_hardware_not_architecture_name",
        "vmess_all_handshakes_keep_the_original_deadline_and_join_cancelled_io",
        "vmess_expired_deadline_and_protect_failure_never_fall_back",
    ],
}


def rows(identifier):
    if identifier == "N3-CFG":
        return sorted(FIELD_IDS)
    if identifier == "N3-CODEC":
        return ["VM01", "VM03", "VM06", "VM07", "VM08"]
    if identifier in GATES or identifier.startswith("N3-REGRESSION"):
        return []
    _, mode, tls, test = NATIVE[identifier]
    result = {"VM04", "VM05"}
    if identifier in WIRE:
        if test == "native_identity_time_replay_rejection":
            result |= {"VM01", "VM02"}
        elif test == "native_cipher_matrix":
            result |= {"VM03", "VM07", "VM08"}
        elif test.endswith("udp_boundaries"):
            result.add("VM06")
    else:
        result |= {"C01", "C02", "C03", "C04", "VM01", "VM02"}
        if test == "public_body_options":
            result |= {"VM03", "VM07", "VM08"}
        if "graph" in test:
            result.add("C06")
        if "base" in test or "udp" in test or "gates" in test:
            result |= {"C05", "VM06"}
        if tls:
            result |= {"T02", "T03", "T05"}
            if test == "public_negative":
                result.add("T04")
        if mode.startswith("ws"):
            result |= {"W01", "W02", "W03"}
            if mode != "ws":
                result |= {"W04", "W05"}
        if mode.startswith("grpc"):
            result.add("G01")
        if mode == "http":
            result |= {"H01", "H02", "H03", "H04"}
        if mode == "h2":
            result |= {"H05", "H06"}
    return sorted(result)


def definitions():
    cases = []
    for identifier in sorted(REQUIRED_IDS):
        kind, mode, tls, test = NATIVE.get(
            identifier, ("unit", "memory-or-build", False, identifier)
        )
        native = identifier in NATIVE
        substage = "N3.5"
        if identifier in WIRE:
            substage = (
                "N3.1"
                if "identity" in test
                else "N3.2"
                if "cipher" in test
                else "N3.3"
                if "udp" in test
                else "N3.4"
            )
        elif identifier == "N3-CODEC":
            substage = "N3.2"
        cases.append(
            dict(
                case_id=identifier,
                stage="N3",
                substage=substage,
                required=True,
                row_ids=rows(identifier),
                protocol="vmess",
                network=mode,
                security="tls" if tls else "plain",
                udp_codec="raw/xudp/packetaddr"
                if "udp" in test or test == "public_base"
                else "per-assertion",
                field_values={
                    "network": mode,
                    "tls": tls,
                    "scope": "protocol-consumer",
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
                    "reason": "Mihomo VMess listener has no HTTP header/legacy H2 "
                    "or custom ED field; official V2Ray supplements only these paths",
                    "source": "https://github.com/MetaCubeX/mihomo/blob/v1.19.31/listener/inbound/vmess.go",
                }
                if kind == "V2"
                else None,
                expected_observation=[test]
                if native
                else SCRIPT_ASSERTIONS
                if identifier == "N3-SCRIPTS"
                else OBSERVATIONS.get(identifier, [identifier]),
                required_evidence=["structured-assertions", "command", "cleanup"]
                + (["peer-identity", "isolated-origins"] if native else []),
                prerequisites=[
                    "owned-host-only-container-network",
                    "official-latest-peer",
                ]
                if native
                else ["rust-toolchain"],
                runner="native-vmess" if native else "vmess-gate",
                timeout_seconds=240 if native else 1200,
            )
        )
    return cases


def commands(identifier):
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if identifier == "N3-CFG":
        return [cargo + ["--test", "vmess_config"], cargo + ["--lib", "config::"]]
    if identifier == "N3-CODEC":
        return [cargo + ["--test", "vmess_codec"], cargo + ["--lib", "outbound::vmess"]]
    if identifier == "N3-CANCEL":
        return [cargo + ["--test", "vmess_lifecycle"]]
    if identifier == "N3-RELEASE":
        return [
            cargo
            + [
                "--release",
                "--test",
                "vmess_config",
                "--test",
                "vmess_codec",
                "--test",
                "vmess_lifecycle",
            ],
            cargo + ["--release", "--lib", "outbound::vmess"],
        ]
    if identifier == "N3-REGRESSION":
        return [
            cargo + ["--lib", "xudp::"],
            cargo + ["--lib", "security::tls::tests::"],
            cargo
            + [
                "--test",
                "trojan",
                "--test",
                "trojan_config",
                "--test",
                "stream_foundations",
                "--test",
                "h2_stream_regression",
                "--test",
                "feature_foundations",
                "--test",
                "limit_foundations",
            ],
            cargo
            + [
                "--lib",
                "inbound::listen::tests::socks_udp_send_buffer_covers_the_declared_wire_limit",
                "--",
                "--exact",
            ],
        ]
    if identifier == "N3-QUALITY":
        return [
            ["cargo", "fmt", "--all", "--", "--check"],
            [
                "cargo",
                "clippy",
                "--locked",
                "--all-features",
                "--lib",
                "--bins",
                "--",
                "-D",
                "warnings",
            ],
            ["vcore-scripts", "check", "c-header"],
            ["vcore-scripts", "check", "tls-dependencies"],
            ["ruff", "check", "scripts"],
            ["ruff", "format", "--check", "scripts"],
            ["git", "diff", "--check"],
            ["vcore-scripts", "build", "apple"],
            ["vcore-scripts", "build", "android"],
        ]
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
        raise ValueError("missing, duplicate or unknown VMess native case")
    by_id = {record["case_id"]: record for record in records}
    output = []
    for case in cases:
        record = by_id[case["case_id"]]
        path = directory / (case["case_id"] + "-events.jsonl")
        observed = read_events(path) if path.exists() else []
        test = NATIVE[case["case_id"]][3]
        observed_ok = (
            events_pass(observed, test)
            if case["case_id"] in PUBLIC
            else observed
            == [
                dict(schema_version=1, suite="N3-WIRE", assertion=test, status=status)
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
            "vmess_public" if case["case_id"] in PUBLIC else "vmess_native",
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
    return dict(schema_version=1, stage="N3", protocol="vmess", fields=fields)


def execute(cases, run, output, results):
    from .protocol_harness import _command, _features, _scripts

    for case in cases:
        identifier = case["case_id"]
        if identifier in NATIVE:
            continue
        if identifier == "N3-FEATURES":
            result = _features(case, run, output)
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
        elif identifier == "N3-SCRIPTS":
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
        report = read_json(directory / "vmess-results.json")
        (output / "peers.json").write_text(json.dumps(report["peers"], indent=2) + "\n")
        for result in native_results(native, report, directory):
            results[result["case_id"]] = result
    (output / "fields.json").write_text(
        json.dumps(fields_report(cases, list(results.values())), indent=2) + "\n"
    )


def check(run_dir, cases, run, results, peers, paths):
    from .protocol_harness import SCRIPT_OBSERVATIONS

    needed = {
        "native/vmess-results.json",
        "fields.json",
        "script-tests.json",
        "resources.jsonl",
        "peers.json",
        "cases.json",
        "summary.md",
    }
    if not needed <= set(paths):
        raise ValueError("missing N3 acceptance artifacts")
    expected = {c["case_id"]: c for c in definitions()}
    if len(cases) != len(expected) or any(
        c != expected.get(c["case_id"]) for c in cases
    ):
        raise ValueError("VMess frozen case metadata changed")
    report = read_json(run_dir / "native/vmess-results.json")
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
        raise ValueError("VMess peer evidence input mismatch")
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
        raise ValueError("VMess peers not isolated or cleaned")
    if peers != report.get("peers") or set(peers) != {"M", "V2"}:
        raise ValueError("missing VMess official peers")
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
            raise ValueError("invalid official VMess peer identity")
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
                raise ValueError("missing VMess gate command")
            records.extend(matching)
            path = run_dir / f"{identifier}-{i}-events.jsonl"
            if path.exists():
                events.extend(read_events(path))
        recalculated.append(gate_result(case, records, events))
    for item in recalculated:
        if item != actual.get(item["case_id"]):
            raise ValueError("VMess results disagree with structured observations")
    names = [c["name"] for c in run["commands"]]
    needed_commands = {
        f"{identifier}-{i}"
        for identifier in GATES
        for i in range(len(commands(identifier)))
    } | {
        "production-build",
        "offline-scripts",
        "feature-default",
        "feature-minimal",
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
        raise ValueError("missing or failed VMess validation command")
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
            raise ValueError("VMess feature or script command changed")
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
        raise ValueError("incomplete VMess field coverage")
    resources = read_events(run_dir / "resources.jsonl")
    owned = [
        e
        for e in resources
        if e.get("suite") == "N3-OWNED" and e.get("status") == "PASS"
    ]
    if len(owned) != 40 or not all(idle_resources(e.get("resources")) for e in owned):
        raise ValueError("missing 20-round owned resource evidence per selected mode")
    print(f"N3: PASS ({len(cases)} required cases; {len(FIELD_IDS)} VMess field rows)")
