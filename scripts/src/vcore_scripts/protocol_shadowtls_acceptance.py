"""ShadowTLS execution and reconstruction from raw, source-bound evidence."""

from __future__ import annotations

import json

from .core_checks import validate_execution
from .protocol_evidence import read_events, read_json
from .protocol_hysteria2_catalog import assertions_pass
from .protocol_inputs import redact
from .protocol_integration_checks import envelope, runtime_pass
from .protocol_security_acceptance import REPORTS, result, rust_command, vless_pass
from .protocol_shadowtls import POLICIES, PROFILES
from .protocol_shadowtls_catalog import (
    FAULTS,
    LOCAL,
    MEMORY_EVENTS,
    SHARED,
    SS_CASES,
    commands,
)


def expected_observation(consumer, success):
    if consumer in {"data", "native_tcp"}:
        return dict(
            tcp_bytes_each_direction=10 * 1024 * 1024,
            udp_packets=500 if consumer == "data" else 0,
            udp_sizes=[1, 64, 512, 1200, 4096] if consumer == "data" else [],
            stop_idle=True,
        )
    if consumer == "policy":
        return dict(accepted=success, origin_connected=success, stop_idle=True)
    if consumer == "corrupt":
        return dict(origin_connected=True, delivered_bytes=0, stop_idle=True)
    if consumer == "stall":
        return dict(
            stop_idle=True,
            stop_handshake_cancelled=True,
            measure_deadline=True,
            origin_connected=False,
            closed_handshakes=2,
        )
    if consumer == "native_udp_disabled":
        return dict(tcp_accepted=True, udp_delivered=False, stop_idle=True)
    raise ValueError("unknown ShadowTLS consumer")


def fault_pass(label, events, cover):
    if any(e.get("upload_join_failed") for e in events):
        return False
    if label == "stall":
        return not cover and all(
            sum(e.get(key) is True for e in events) == 2
            for key in ("hello_seen", "client_closed")
        )
    if label == "native-udp-disabled":
        return True
    required = (
        "split_record"
        if label == "fragment"
        else "hrr_seen"
        if label == "hrr-wire"
        else "injected"
    )
    return any(e.get(required) is True for e in events)


def wire_pass(name, directory, report):
    if name == "MIHOMO-DATA":
        labels = [
            (f"{c}-{p}", "data", True, 24001, "h2", None)
            for c in SS_CASES
            for p in PROFILES
        ]
    elif name == "MIHOMO-POLICY":
        labels = [
            (
                f"{p}-chrome",
                "policy",
                p.startswith("alpn-") or p == "hrr",
                24002 if p == "hrr" else 24003 if p == "tls12" else 24001,
                None
                if p == "alpn-empty"
                else "fixture-custom"
                if p == "alpn-custom"
                else "h2",
                None,
            )
            for p in POLICIES
        ]
    elif name == "MIHOMO-FAULT":
        consumers = {
            "fragment": "native_tcp",
            "hrr-wire": "native_tcp",
            "cover-mac": "policy",
            "stall": "stall",
            "native-udp-disabled": "native_udp_disabled",
        }
        labels = [
            (
                f"{f}-chrome",
                consumers.get(f, "corrupt"),
                f not in {"cover-mac", "stall"},
                24002 if f == "hrr-wire" else 24001,
                "h2",
                f,
            )
            for f in FAULTS
        ]
    elif name == "NATIVE":
        labels = [(c, "native_tcp", True, None, None, None) for c in SS_CASES]
    else:
        raise ValueError("unknown wire group")
    rows = report.get("cases", [])
    if [r.get("case_id") for r in rows] != [item[0] for item in labels]:
        return False
    for row, (identifier, consumer, success, port, alpn, fault) in zip(
        rows, labels, strict=True
    ):
        observed = read_json(directory / (identifier + "-observations.json"))
        events = read_events(directory / (identifier + "-events.jsonl"))
        if not (
            row.get("command") == rust_command("vless_public", "shadowtls::" + consumer)
            and type(row.get("exit_code")) is int
            and row["exit_code"] == 0
            and row.get("command_cleanup") is True
            and observed
            == row.get("observations")
            == expected_observation(consumer, success)
            and assertions_pass(events, {("SHADOWTLS", consumer): 1})
        ):
            return False
        cover = row.get("cover", [])
        if (
            port is not None
            and success
            and dict(port=port, version="TLSv1.3", alpn=alpn) not in cover
        ):
            return False
        if fault is not None and not fault_pass(fault, row.get("fault", []), cover):
            return False
    return True


def local_pass(name, directory, run):
    expected = commands(name)
    records = [
        r for r in run["commands"] if r["name"].startswith("SHADOWTLS-" + name + "-")
    ]
    if len(records) != len(expected):
        return False
    events = []
    for i, (row, argv) in enumerate(zip(records, expected, strict=True)):
        label = f"SHADOWTLS-{name}-{i}"
        if row["name"] != label or row["command"] != [
            redact(v.replace("{output}", str(directory))) for v in argv
        ]:
            return False
        validate_execution(
            row["command"],
            (directory / row["log"]).read_text(),
            row["exit_code"],
            row["cleanup"],
        )
        path = directory / (label + "-events.jsonl")
        if path.exists():
            events += read_events(path)
    if name == "MEMORY":
        return assertions_pass(
            [e for e in events if e.get("suite", "").startswith("SHADOWTLS-")],
            MEMORY_EVENTS,
        )
    if name == "FEATURES":
        return assertions_pass(
            [e for e in events if e.get("suite") == "SHADOWTLS-CFG"],
            {("SHADOWTLS-CFG", "feature"): 1},
        )
    if name == "FINGERPRINT":
        from .protocol_fingerprint_shape import check_captures, check_warm_captures

        root = directory / "fingerprint"
        report = read_json(root / "shape-results.json")
        return (
            report.get("source") == source(run)
            and report.get("source_unchanged") is True
            and report.get("cleanup") is True
            and report.get("cases") == check_captures(read_json(root / "captures.json"))
            and report.get("warm_cases")
            == check_warm_captures(read_json(root / "warm.json"))
        )
    return True


def source(run):
    return {
        k: run[k]
        for k in (
            "parent_commit",
            "source_tree_sha256",
            "dirty_patch_sha256",
            "lock_sha256",
        )
    }


def group_pass(name, directory, run, peers):
    if name in LOCAL:
        return local_pass(name, directory, run)
    root = directory / name.lower()
    digest = run["container_image"]["digest"]
    if name == "SHARED":
        return all(
            envelope(
                report := read_json(root / label / REPORTS["vless"]),
                peers,
                source(run),
                digest,
            )
            and vless_pass(group, report, root / label)
            for label, group in SHARED.items()
        )
    if name == "BARE-SS":
        report = read_json(root / "integration-suite.json")
        rows = report.get("cases", [])
        return (
            envelope(report, peers, source(run), digest)
            and len(rows) == 1
            and runtime_pass("INTEGRATION-SS-ALGORITHMS", rows[0], root)
        )
    report = read_json(root / "report.json")
    identities = report.get("peers") if name == "NATIVE" else {"M": report.get("peer")}
    return (
        set(identities) == ({"SS", "ST"} if name == "NATIVE" else {"M"})
        and envelope(
            report, peers, source(run), digest, single=None if name == "NATIVE" else "M"
        )
        and wire_pass(name, root, report)
    )


def prepare(output, *, native):
    from .native_release import download_native
    from .protocol_hysteria2_acceptance import prepare as prepare_mihomo

    supplied = prepare_mihomo(output, {"M"})
    artifacts = (
        {
            kind: download_native(
                kind, output / "binaries" / kind, "linux-arm64", defer_version=True
            )
            for kind in ("ST", "SS")
        }
        if native
        else {}
    )
    return supplied, artifacts


def execute(cases, run, output, results):
    from .protocol_containers import frozen_image
    from .protocol_harness import _command
    from .protocol_integration_suite import run as integration
    from .protocol_shadowtls import run as mihomo
    from .protocol_shadowtls_native import run as native
    from .protocol_vless_container import run as vless

    selected = {c["case_id"].removeprefix("SHADOWTLS-"): c for c in cases}
    peers = {}

    def save(name):
        good = group_pass(name, output, run, peers)
        case = selected[name]
        results[case["case_id"]] = result(case, good, good)
        print(case["case_id"] + (": PASS" if good else ": FAIL"), flush=True)
        if not good:
            raise RuntimeError("ShadowTLS gate failed: " + name)

    try:
        for name in selected:
            if name not in LOCAL:
                continue
            for i, argv in enumerate(commands(name)):
                label = f"SHADOWTLS-{name}-{i}"
                command = _command(
                    run,
                    output,
                    label,
                    [v.replace("{output}", str(output)) for v in argv],
                    3600,
                    events=output / (label + "-events.jsonl"),
                )
                validate_execution(
                    argv,
                    command.stdout.decode(errors="replace"),
                    command.returncode,
                    command.cleanup,
                )
            save(name)
        if set(selected) <= LOCAL:
            return
        with frozen_image(output / "image-pull.log") as image:
            run["container_image"] = image
            supplied, artifacts = prepare(output, native="NATIVE" in selected)
            peers.update({k: v[1] for k, v in supplied.items()})
            peers.update({k: v.identity for k, v in artifacts.items()})
            for name in selected:
                if name in LOCAL:
                    continue
                root = output / name.lower()
                if name.startswith("MIHOMO-"):
                    mihomo(
                        root,
                        profiles=PROFILES if name == "MIHOMO-DATA" else ("chrome",),
                        checks=name.removeprefix("MIHOMO-").lower(),
                        supplied=supplied["M"],
                        image=image,
                    )
                elif name == "NATIVE":
                    native(root, supplied=artifacts, image=image)
                elif name == "SHARED":
                    for label, group in SHARED.items():
                        vless(root / label, supplied=supplied, **group)
                elif name == "BARE-SS":
                    integration(
                        root, ["INTEGRATION-SS-ALGORITHMS"], supplied=supplied["M"]
                    )
                else:
                    raise ValueError("unknown ShadowTLS gate")
                save(name)
    finally:
        (output / "peers.json").write_text(json.dumps(peers, indent=2) + "\n")


def check(directory, cases, run, results, peers, paths):
    if not {"cases.json", "peers.json", "resources.jsonl", "summary.md"} <= set(paths):
        raise ValueError("missing ShadowTLS evidence files")
    expected_commands = [
        f"SHADOWTLS-{c['case_id'].removeprefix('SHADOWTLS-')}-{i}"
        for c in cases
        for i, _ in enumerate(commands(c["case_id"].removeprefix("SHADOWTLS-")))
    ]
    actual = [r["name"] for r in run["commands"]]
    if (
        len(actual) != len(set(actual))
        or set(actual) != set(expected_commands)
        or set(peers) != {"M", "SS", "ST"}
    ):
        raise ValueError("ShadowTLS command or peer selection differs")
    for case in cases:
        name = case["case_id"].removeprefix("SHADOWTLS-")
        if not group_pass(name, directory, run, peers):
            raise ValueError("ShadowTLS raw evidence failed: " + name)
    print("SHADOWTLS coverage: PASS (all required groups; device delivery separate)")


def preflight(output):
    from .protocol_containers import command, frozen_image

    command("system", "status")
    with frozen_image(output / "image-pull.log"):
        supplied, artifacts = prepare(output, native=True)
    (output / "peers.json").write_text(
        json.dumps(
            dict(
                scope="download-only",
                wire_acceptance="NOT RUN",
                peers={
                    **{k: v[1] for k, v in supplied.items()},
                    **{k: v.identity for k, v in artifacts.items()},
                },
            ),
            indent=2,
        )
        + "\n"
    )
