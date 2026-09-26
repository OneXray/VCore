"""Execute N7 and reconstruct its result from frozen commands and native events."""

from __future__ import annotations

import json
import sys
from contextlib import ExitStack

from .protocol_evidence import HEX, new_result, read_events, read_json
from .protocol_inputs import redact
from .protocol_n7_catalog import FIELDS, GATES, definitions, groups


def commands(identifier):
    from .protocol_hysteria2_acceptance import commands as previous

    cargo = ["cargo", "test", "--locked", "--all-features"]
    targets = [
        "n7_ech_config",
        "n7_ech_tls",
        "n7_encryption_config",
        "n7_reality_config",
        "n7_jls_config",
    ]
    if identifier in {"N7-CFG", "N7-RELEASE"}:
        if identifier == "N7-RELEASE":
            cargo += ["--release"]
        return [
            cargo + sum((["--test", name] for name in targets), []),
            cargo + ["--lib", "security::"],
            cargo + ["--lib", "outbound::vless::encryption"],
            cargo + ["--lib", "config::"],
        ]
    if identifier == "N7-FEATURES":
        return previous("N6-FEATURES") + [
            [
                "cargo",
                "test",
                "--locked",
                "--no-default-features",
                "--features",
                "outbound-vless",
                "--test",
                "n7_ech_config",
                "--test",
                "n7_ech_tls",
            ],
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--all-targets",
                "--no-run",
            ],
        ]
    if identifier == "N7-SCRIPTS":
        return [
            [
                sys.executable,
                "-m",
                "vcore_scripts.protocol_script_tests",
                "{output}/script-tests.json",
            ]
        ]
    return previous(identifier.replace("N7-", "N6-"))


def gate_result(case, records, events, script=None):
    from .protocol_hysteria2_catalog import assertions_pass
    from .protocol_n7_units import TESTS

    identifier = case["case_id"]
    good = bool(records) and all(
        r.get("exit_code") == 0 and r.get("cleanup") is True for r in records
    )
    if identifier in {"N7-CFG", "N7-RELEASE"}:
        # Config and TLS tests each have an exact BEGIN/PASS pair. Library
        # regressions run separately without these assertion identities.
        selected = [e for e in events if e.get("suite") == "N7-CONFIG-TLS"]
        good &= assertions_pass(
            selected,
            {("N7-CONFIG-TLS", name): 1 for names in TESTS.values() for name in names},
        )
        good &= all(e.get("status") in {"BEGIN", "PASS"} for e in events)
    if identifier == "N7-SCRIPTS":
        samples = (script or {}).get("cases", [])
        names = [s.get("test") for s in samples]
        required = {
            "test_protocol_n7.N7AcceptanceTest." + name
            for name in (
                "test_frozen_scope_and_compositions",
                "test_native_missing_duplicate_wrong_events_fail",
                "test_source_cleanup_and_identity_are_not_inferred",
                "test_empty_gate_and_missing_script_proof_fail",
                "test_legacy_ech_gateway_keeps_response_inside_tls",
                "test_close_reference_cannot_hide_a_different_official_profile",
            )
        }
        required |= {
            "test_protocol_containers.ContainerTests." + name
            for name in (
                "test_frozen_latest_image_is_single_run_owned",
                "test_image_refresh_failure_never_falls_back_to_a_cached_image",
            )
        }
        good &= (
            bool(samples)
            and len(names) == len(set(names)) == (script or {}).get("tests_run")
            and required <= set(names)
            and all(s.get("status") == "PASS" for s in samples)
        )
    return result(
        case, good, bool(records) and all(r.get("cleanup") is True for r in records)
    )


def result(case, good, cleanup):
    record = new_result(case)
    record.update(
        status="PASS" if good else "FAIL",
        assertions={case["case_id"]: bool(good)},
        evidence=case["required_evidence"] if good else [],
        command_exit_code=0 if good else 1,
        cleanup=cleanup,
    )
    return record


def native_envelope(report, peers=None, source=None, *, image_digest=None):
    isolation = report.get("isolation", {})
    owned = isolation.get("peers", [])
    identities = report.get("peers", {})
    if "peer" in report:
        identities = {"M": report["peer"]}
    good = (
        report.get("status") == "PASS"
        and report.get("cleanup") is True
        and report.get("source_unchanged") is True
        and isolation.get("network_mode") == "hostOnly"
        and isolation.get("host_servers") is False
        and isolation.get("guest_mtu") == 1500
        and isolation.get("image_digest", "").startswith("sha256:")
        and bool(HEX.fullmatch(isolation.get("image_digest", "")[7:]))
        and bool(owned)
        and all(p.get("started") is True and p.get("joined") is True for p in owned)
        and bool(identities)
    )
    for kind, identity in identities.items():
        good &= (
            bool(identity.get("version"))
            and bool(HEX.fullmatch(identity.get("binary_sha256", "")))
            and bool(HEX.fullmatch(identity.get("archive_sha256", "")))
            and identity.get("source_url", "").startswith(
                {
                    "M": "https://github.com/MetaCubeX/mihomo/releases/",
                    "XR": "https://github.com/XTLS/Xray-core/releases/",
                    "V2": "https://github.com/v2fly/v2ray-core/releases/",
                }.get(kind, "invalid-source")
            )
        )
        if peers is not None:
            good &= identity == peers.get(kind)
    if source is not None:
        good &= report.get("source") == source
    if image_digest is not None:
        good &= isolation.get("image_digest") == image_digest
    return bool(good)


def rust_command(target, test, *, fields=False):
    return [
        "cargo",
        "test",
        "--locked",
        "--all-features",
        "--test",
        target,
        test,
        "--",
        *(["--exact", "--ignored"] if fields else ["--ignored", "--exact"]),
        "--nocapture",
    ]


def vless_catalog(group):
    if group.get("ech"):
        from .protocol_ech import catalog

        return catalog()
    if group.get("jls"):
        from .protocol_jls import catalog

        return catalog()
    from .protocol_vless_container import ALL_CASES

    return ALL_CASES | {"F5-ANYTLS": ("M", "anytls", True, "public_legacy_regression")}


def close_reference_pass(group, mode, directory):
    profile = group.get("client_fingerprint")
    expected_profile, scope = profile, "same-mode"
    if mode == "grpc-tls":
        if group.get("jls") and profile in (None, "", "none"):
            expected_profile, scope = "chrome", "jls-grpc-chrome-baseline"
        elif group.get("ech") and profile in ("safari", "safari16"):
            expected_profile, scope = "chrome", "ech-safari-chrome-baseline"
    try:
        reference = read_json(directory / f"{mode}-tls-close-reference.json")
    except (OSError, ValueError):
        return False
    return (
        isinstance(reference, dict)
        and reference.get("scope") == scope
        and reference.get("client_fingerprint") == expected_profile
        and reference.get("dut_client_fingerprint") == profile
        and reference.get("terminated") is True
    )


def vless_pass(group, report, directory):
    from .protocol_vless_public import events_pass

    catalog = vless_catalog(group)
    expected = group["selected"]
    records = report.get("cases", [])
    if len(records) != len(expected) or {r.get("case_id") for r in records} != set(
        expected
    ):
        return False
    if any(report.get(k) != group.get(k, False) for k in ("jls", "ech")):
        return False
    if report.get("encryption_profile") != group.get("encryption") or report.get(
        "client_fingerprint"
    ) != group.get("client_fingerprint"):
        return False
    stage = (
        "N7"
        if group.get("ech") or group.get("jls") or group.get("encryption")
        else "N4"
    )
    for record in records:
        name = record["case_id"]
        kind, mode, _, test = catalog[name]
        native = test.startswith("native_")
        events = read_events(directory / (name + "-events.jsonl"))
        if not (
            record.get("status") == "PASS"
            and record.get("exit_code") == 0
            and record.get("command_cleanup") is True
            and record.get("cleanup") is True
            and record.get("peer_kind") == kind
            and record.get("command")
            == rust_command("vless_native" if native else "vless_public", test)
        ):
            return False
        if native:
            if test == "native_mihomo_close_alignment" and not close_reference_pass(
                group, mode, directory
            ):
                return False
            if events != [
                dict(
                    schema_version=1,
                    suite=stage + "-WIRE",
                    assertion=test,
                    status=status,
                )
                for status in ("BEGIN", "PASS")
            ]:
                return False
        elif not events_pass(events, test, mode, stage=stage):
            return False
    return True


def xhttp_pass(group, report, directory):
    from .protocol_xhttp_fields import PUBLIC_TESTS, events_pass, public_events_pass

    jobs = group["jobs"]
    expected = {
        entry["case_id"]: (variant, entry["test"])
        for variant, entries in jobs.items()
        for entry in entries
    }
    records = report.get("cases", [])
    if len(records) != len(expected) or {r.get("case_id") for r in records} != set(
        expected
    ):
        return False
    if (
        report.get("ech") != group.get("ech", False)
        or report.get("jls") != group.get("jls", False)
        or report.get("encryption_profile") != group.get("encryption")
    ):
        return False
    for record in records:
        variant, test = expected[record["case_id"]]
        events = read_events(directory / (record["case_id"] + "-events.jsonl"))
        if not (
            record.get("variant") == variant
            and record.get("assertion") == test
            and record.get("status") == "PASS"
            and record.get("exit_code") == 0
            and record.get("command_cleanup") is True
            and record.get("command")
            == rust_command(
                "vless_public" if test in PUBLIC_TESTS else "xhttp_native",
                test,
                fields=True,
            )
        ):
            return False
        if not (
            public_events_pass(events, test)
            if test in PUBLIC_TESTS
            else events_pass(events, test, owned=test.startswith("lifecycle::"))
        ):
            return False
    return True


def hybrid_pass(group, report, directory):
    from .protocol_reality_hybrid import MODES, cases, negative_wire_pass, wire_pass
    from .protocol_vless_public import events_pass

    catalog = cases()
    records = report.get("cases", [])
    selected = group["selected"]
    if (
        len(records) != len(selected)
        or {r.get("id") for r in records} != set(selected)
        or report.get("encryption_profile") != group.get("encryption")
    ):
        return False
    ports = {mode: 25000 + i * 10 for i, mode in enumerate(MODES)}
    for record in records:
        name = record["id"]
        profile, mode, test, variant = catalog[name]
        expected = {ports[mode]: (True, profile)}
        if mode.startswith(("h1-", "h2-")) and not mode.endswith("stream-one"):
            expected[ports[mode] + 1] = (True, profile)
        if variant != "hybrid":
            expected[ports[mode] + (variant == "download-classic")] = (False, profile)
        wire = read_json(directory / (name + "-wire.json"))
        events = read_events(directory / (name + "-events.jsonl"))
        native = test.startswith("native_")
        good = (
            record.get("status") == "PASS"
            and record.get("exit_code") == 0
            and record.get("command_cleanup") is True
            and (record.get("test"), record.get("variant"), record.get("profile"))
            == (test, variant, profile)
            and record.get("command")
            == rust_command("vless_native" if native else "vless_public", test)
            and wire_pass(wire, expected)
        )
        if test == "native_hybrid_fail_closed":
            good &= negative_wire_pass(wire, profile, ports["tcp"], len(expected))
        good &= (
            events
            == [
                dict(schema_version=1, suite="N7-WIRE", assertion=test, status=status)
                for status in ("BEGIN", "PASS")
            ]
            if native
            else events_pass(events, test, MODES[mode][0], stage="N7")
        )
        if not good:
            return False
    return True


def encryption_pass(group, report, directory):
    from .protocol_encryption import cases

    expected = [
        key
        for key, (_, rtt, _) in cases().items()
        if not group.get("expiry") or rtt == "0rtt"
    ]
    records = report.get("cases", [])
    test = (
        "native_ticket_expiry" if group.get("expiry") else "native_encryption_roundtrip"
    )
    marker = (
        "N7-ENCRYPTION-EXPIRY-PASS full-resumed-expired-full-resumed"
        if group.get("expiry")
        else "N7-ENCRYPTION-WIRE-PASS rounds=4 bytes_per_direction=10485760"
    )
    if (
        len(records) != len(expected)
        or {r.get("case_id") for r in records} != set(expected)
        or report.get("ticket_expiry") != group.get("expiry", False)
        or report.get("cipher")
        != ("chacha20-poly1305" if group.get("chacha") else "cpu-selected")
        or report.get("padding") != "minimal"
    ):
        return False
    for record in records:
        log = (directory / (record["case_id"] + ".log")).read_text()
        if not (
            record.get("status") == "PASS"
            and record.get("returncode") == 0
            and record.get("cleanup") is True
            and marker in log
            and "1 passed; 0 failed; 0 ignored" in log
            and record.get("command") == rust_command("n7_encryption_wire", test)
        ):
            return False
    return True


REPORTS = {
    "vless": "vless-results.json",
    "xhttp": "xhttp-fields-results.json",
    "hybrid": "reality-results.json",
    "encryption": "encryption-results.json",
}
CHECKERS = {
    "vless": vless_pass,
    "xhttp": xhttp_pass,
    "hybrid": hybrid_pass,
    "encryption": encryption_pass,
}


def native_result(
    case, group, report, directory, *, peers=None, source=None, image_digest=None
):
    good = native_envelope(report, peers, source, image_digest=image_digest)
    good &= CHECKERS[group["runner"]](group, report, directory)
    return result(case, good, report.get("cleanup") is True)


def fields_report(cases, results):
    by_id = {r["case_id"]: r for r in results}
    rows = []
    for field in sorted(FIELDS):
        owners = [c["case_id"] for c in cases if field in c["row_ids"]]
        cfg = [c for c in owners if c in {"N7-CFG", "N7-RELEASE"}]
        wire = [c for c in owners if c not in GATES]
        good = (
            bool(cfg)
            and bool(wire)
            and all(by_id.get(c, {}).get("status") == "PASS" for c in owners)
        )
        rows.append(
            dict(
                id=field,
                cfg_cases=cfg,
                wire_cases=wire,
                status="PASS" if good else "NOT RUN",
            )
        )
    return dict(stage="N7", scope="selected-vless-security-consumers", fields=rows)


def execute(cases, run, output, results):
    from .protocol_containers import frozen_image
    from .protocol_encryption import run as run_encryption
    from .protocol_harness import _command
    from .protocol_reality_hybrid import run as run_hybrid
    from .protocol_vless_container import run as run_vless
    from .protocol_xhttp_acceptance import prepare_peers
    from .protocol_xhttp_fields import run as run_xhttp

    supplied = {}
    image_scope = ExitStack()
    catalog = groups()
    source = {
        k: run[k]
        for k in (
            "parent_commit",
            "source_tree_sha256",
            "dirty_patch_sha256",
            "lock_sha256",
        )
    }
    try:
        for case in cases:
            identifier = case["case_id"]
            if identifier not in GATES:
                continue
            records, events = [], []
            for i, argv in enumerate(commands(identifier)):
                name = f"{identifier}-{i}"
                path = output / (name + "-events.jsonl")
                _command(
                    run,
                    output,
                    name,
                    [v.replace("{output}", str(output)) for v in argv],
                    case["timeout_seconds"],
                    events=path,
                )
                records.append(run["commands"][-1])
                if path.exists():
                    events += read_events(path)
            script = (
                read_json(output / "script-tests.json")
                if identifier == "N7-SCRIPTS"
                else None
            )
            results[identifier] = gate_result(case, records, events, script)
            print(identifier + ": " + results[identifier]["status"], flush=True)
            if results[identifier]["status"] != "PASS":
                raise RuntimeError("N7 local gate failed: " + identifier)
        if any(c["case_id"] in catalog for c in cases):
            supplied = prepare_peers(output, {"M", "XR", "V2"})
            run["container_image"] = image_scope.enter_context(
                frozen_image(output / "container-image-pull.log")
            )
        runners = {
            "vless": run_vless,
            "xhttp": run_xhttp,
            "hybrid": run_hybrid,
            "encryption": run_encryption,
        }
        # Retained combinations first, followed by the longer new ECH matrix.
        # Every required group still runs in this same frozen source/image scope.
        for case in sorted(
            cases, key=lambda c: (c["case_id"].startswith("N7-ECH-"), c["case_id"])
        ):
            identifier = case["case_id"]
            if identifier in GATES:
                continue
            group = catalog[identifier]
            kwargs = {k: v for k, v in group.items() if k not in {"rows", "runner"}}
            if group["runner"] == "xhttp":
                kwargs["selected"] = list(kwargs["jobs"])
            directory = output / identifier
            runners[group["runner"]](directory, supplied=supplied, **kwargs)
            report = read_json(directory / REPORTS[group["runner"]])
            results[identifier] = native_result(
                case,
                group,
                report,
                directory,
                peers={k: v[1] for k, v in supplied.items()},
                source=source,
                image_digest=run["container_image"]["digest"],
            )
            print(identifier + ": " + results[identifier]["status"], flush=True)
            if results[identifier]["status"] != "PASS":
                raise RuntimeError("N7 native gate failed: " + identifier)
    finally:
        image_scope.close()
        (output / "peers.json").write_text(
            json.dumps({k: v[1] for k, v in supplied.items()}, indent=2) + "\n"
        )
        (output / "fields.json").write_text(
            json.dumps(fields_report(cases, list(results.values())), indent=2) + "\n"
        )


def check(run_dir, cases, run, results, peers, paths):
    from .protocol_containers import IMAGE

    snapshot = run.get("container_image", {})
    digest = snapshot.get("digest", "")
    if (
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or not HEX.fullmatch(digest[7:])
        or snapshot
        != dict(
            tag=IMAGE,
            digest=digest,
            command=["container", "image", "pull", IMAGE],
            exit_code=0,
            cleanup=True,
            log="container-image-pull.log",
        )
        or snapshot["log"] not in paths
    ):
        raise ValueError("missing or altered N7 frozen container image")
    if (
        cases != definitions()
        or set(peers) != {"M", "XR", "V2"}
        or not {"fields.json", "script-tests.json"} <= set(paths)
    ):
        raise ValueError("incomplete N7 stage artifacts or altered manifest")
    records = run.get("commands", [])
    names = {
        f"{c['case_id']}-{i}"
        for c in cases
        for i, _ in enumerate(commands(c["case_id"]))
        if c["case_id"] in GATES
    }
    if len(records) != len(names) or {r.get("name") for r in records} != names:
        raise ValueError("missing, duplicate or extra N7 gate command")
    actual = {r["case_id"]: r for r in results}
    source = {
        k: run[k]
        for k in (
            "parent_commit",
            "source_tree_sha256",
            "dirty_patch_sha256",
            "lock_sha256",
        )
    }
    catalog = groups()
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
                    raise ValueError("N7 gate command or log changed")
                selected.append(record)
                path = run_dir / f"{identifier}-{i}-events.jsonl"
                if path.exists():
                    events += read_events(path)
            recalculated = gate_result(
                case,
                selected,
                events,
                read_json(run_dir / "script-tests.json")
                if identifier == "N7-SCRIPTS"
                else None,
            )
        else:
            group = catalog[identifier]
            directory = run_dir / identifier
            report = read_json(directory / REPORTS[group["runner"]])
            recalculated = native_result(
                case,
                group,
                report,
                directory,
                peers=peers,
                source=source,
                image_digest=digest,
            )
        if recalculated != actual[identifier] or recalculated["status"] != "PASS":
            raise ValueError("N7 results differ from independent evidence")
    fields = fields_report(cases, results)
    if read_json(run_dir / "fields.json") != fields or any(
        f["status"] != "PASS" for f in fields["fields"]
    ):
        raise ValueError("missing N7 field behavior coverage")
    print(f"N7: PASS ({len(cases)} required groups; {len(FIELDS)} field rows)")
