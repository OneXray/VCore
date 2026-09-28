"""INTEGRATION execution and independent reconstruction of raw integration evidence."""

from __future__ import annotations

import json

from .protocol_evidence import read_events, read_json
from .protocol_hysteria2_catalog import assertions_pass
from .protocol_integration_catalog import LOCAL, PAIRS, definitions
from .protocol_integration_checks import envelope, runtime_pass
from .protocol_integration_local import commands, passed
from .protocol_integration_shared import hops_pass, shared_pass
from .protocol_security_acceptance import result


def pair_pass(identifier, record, directory):
    from .protocol_integration_native import rust_command

    first, last = PAIRS[identifier]
    targets = 2 if last == "trojan" else 3
    events = read_events(directory / (identifier + "-events.jsonl"))
    observation = read_json(directory / (identifier + "-observations.json"))
    expected = [
        dict(
            outer_ipv6=v6,
            nested_select=group,
            tcp_target_kinds=3,
            tcp_bytes_each_direction=31457280,
            udp_target_kinds=targets,
            udp_packets=targets * 400,
            udp_sizes=[1, 64, 512, 1200],
            server_first=True,
            client_first=True,
            ports_rebound=True,
        )
        for v6 in (False, True)
        for group in (False, True)
    ]
    return (
        record.get("case_id") == identifier
        and record.get("command") == rust_command()
        and type(record.get("exit_code")) is int
        and record["exit_code"] == 0
        and record.get("command_cleanup") is True
        and observation
        == dict(
            first=first,
            last=last,
            paths=expected,
            domain_native=[
                dict(
                    outer_ipv6=v6,
                    nested_select=group,
                    peer="XR",
                    udp_packets=400,
                    target="domain",
                )
                for v6 in (False, True)
                for group in (False, True)
            ]
            if last == "trojan"
            else [],
            budgets=[
                dict(
                    transmit=tx,
                    receive=rx,
                    roundtrip_size=min(tx, rx),
                    packets=100,
                    oversize_rejected_before_origin=True,
                )
                for tx, rx in ((128, 128), (512, 256))
            ],
            routed_udp=dict(
                upstream_business_udp_disabled=True,
                carrier_tcp=True,
                carrier_udp=True,
                leaf_business_udp_rejected=True,
            ),
            carrier_capability=dict(
                upstream_datagrams="rejected",
                tcp_allowed=last != "hysteria2",
                udp_allowed=last not in {"ss", "socks5", "hysteria2"},
                no_bypass=True,
            ),
        )
        and assertions_pass(
            events,
            {
                ("INTEGRATION-PAIR", "ordered_pair"): 1,
                ("INTEGRATION-BASE", "tcp_10mib_both_directions"): 12,
                ("INTEGRATION-PAIR", "directional_budget"): 1,
                ("INTEGRATION-PAIR", "routed_udp_permission"): 1,
                ("INTEGRATION-PAIR", "carrier_capability"): 1,
                **(
                    {("INTEGRATION-PAIR", "native_domain_terminal"): 1}
                    if last == "trojan"
                    else {}
                ),
            },
        )
    )


def execute(cases, run, output, results):
    from .protocol_containers import frozen_image
    from .protocol_harness import _command
    from .protocol_hysteria2_acceptance import prepare
    from .protocol_integration_native import run as run_pairs
    from .protocol_integration_shared import hops_run, shared_run
    from .protocol_integration_suite import CONSUMERS
    from .protocol_integration_suite import run as run_suite

    by_id = {c["case_id"]: c for c in cases}
    supplied, peers = {}, {}
    source = {
        k: run[k]
        for k in (
            "parent_commit",
            "source_tree_sha256",
            "dirty_patch_sha256",
            "lock_sha256",
        )
    }

    def save(identifier, good, cleanup=True):
        results[identifier] = result(by_id[identifier], good, cleanup)
        print(identifier + ": " + results[identifier]["status"], flush=True)
        if not good:
            raise RuntimeError("INTEGRATION gate failed: " + identifier)

    try:
        for identifier in sorted(by_id.keys() & LOCAL):
            records, events = [], []
            for i, argv in enumerate(commands(identifier)):
                name = f"{identifier}-{i}"
                path = output / (name + "-events.jsonl")
                _command(
                    run,
                    output,
                    name,
                    [v.replace("{output}", str(output)) for v in argv],
                    3600,
                    events=path,
                )
                records.append(run["commands"][-1])
                if path.exists():
                    events += read_events(path)
                if records[-1]["exit_code"] != 0 or not records[-1]["cleanup"]:
                    save(identifier, False, records[-1]["cleanup"])
            script = (
                read_json(output / "script-tests.json")
                if identifier == "INTEGRATION-SCRIPTS"
                else None
            )
            save(identifier, passed(identifier, records, events, script))
        if set(by_id) <= LOCAL:
            return
        with frozen_image(output / "container-image-pull.log") as snapshot:
            run["container_image"] = snapshot
            kinds = {"M"}
            if "INTEGRATION-SHARED" in by_id:
                kinds |= {"XR", "V2"}
            if any(PAIRS[i][1] == "trojan" for i in by_id.keys() & PAIRS.keys()):
                kinds.add("XR")
            if "INTEGRATION-HY2-HOP" in by_id:
                kinds.add("H")
            supplied = prepare(output, kinds)
            peers = {k: v[1] for k, v in supplied.items()}
            digest = snapshot["digest"]
            # Each group is rerun from this source/image/peer scope. Historical
            # reports are never imported into results.
            selected = sorted(by_id.keys() & PAIRS.keys())
            if selected:
                directory = output / "pairs"
                report = run_pairs(
                    directory,
                    selected,
                    supplied=supplied["M"],
                    domain_peer=supplied.get("XR"),
                )
                if [r["case_id"] for r in report["cases"]] != selected:
                    raise RuntimeError("INTEGRATION ordered-pair selection differs")
                for record in report["cases"]:
                    identifier = record["case_id"]
                    save(
                        identifier,
                        envelope(report, peers, source, digest)
                        and pair_pass(identifier, record, directory),
                        report["cleanup"],
                    )
            selected = sorted(
                by_id.keys() & CONSUMERS.keys(),
                key=lambda k: (k == "INTEGRATION-SOAK", k),
            )
            if selected:
                directory = output / "runtime"
                report = run_suite(directory, selected, supplied=supplied["M"])
                peers.update(report["peers"])
                if [r["case_id"] for r in report["cases"]] != selected:
                    raise RuntimeError("INTEGRATION runtime selection differs")
                for record in report["cases"]:
                    identifier = record["case_id"]
                    save(
                        identifier,
                        envelope(report, peers, source, digest)
                        and runtime_pass(identifier, record, directory),
                        report["cleanup"],
                    )
            if "INTEGRATION-HY2-HOP" in by_id:
                hops_run(output / "hop", supplied["H"])
                save(
                    "INTEGRATION-HY2-HOP",
                    hops_pass(output / "hop", peers, source, digest),
                )
            if "INTEGRATION-SHARED" in by_id:
                shared_run(
                    output / "shared",
                    {k: v for k, v in supplied.items() if k in {"M", "XR", "V2"}},
                )
                save(
                    "INTEGRATION-SHARED",
                    shared_pass(output / "shared", peers, source, digest),
                )
    finally:
        (output / "peers.json").write_text(json.dumps(peers, indent=2) + "\n")


def check(run_dir, cases, run, results, peers, paths):
    from .protocol_containers import IMAGE
    from .protocol_evidence import HEX
    from .protocol_inputs import redact
    from .protocol_integration_suite import CONSUMERS

    observed_paths = {
        str(p.relative_to(run_dir))
        for p in run_dir.rglob("*")
        if p.is_file()
        and p.suffix in {".json", ".jsonl", ".log", ".md"}
        and "binaries" not in p.parts
        and p.name != "run.json"
    }
    if set(paths) != observed_paths:
        raise ValueError("unhashed or missing INTEGRATION evidence artifact")
    snapshot = run.get("container_image", {})
    digest = snapshot.get("digest", "")
    if not (
        digest.startswith("sha256:")
        and HEX.fullmatch(digest[7:])
        and snapshot
        == dict(
            tag=IMAGE,
            digest=digest,
            command=["container", "image", "pull", IMAGE],
            exit_code=0,
            cleanup=True,
            log="container-image-pull.log",
        )
        and snapshot["log"] in paths
        and cases == definitions()
        and set(peers) == {"M", "XR", "V2", "H", "SS"}
        and {"script-tests.json", "package-preparation.json"} <= set(paths)
    ):
        raise ValueError("incomplete INTEGRATION scope, image or peer identities")
    source = {
        k: run[k]
        for k in (
            "parent_commit",
            "source_tree_sha256",
            "dirty_patch_sha256",
            "lock_sha256",
        )
    }
    records = run.get("commands", [])
    names = {
        f"{identifier}-{i}"
        for identifier in LOCAL
        for i, _ in enumerate(commands(identifier))
    }
    if len(records) != len(names) or {r.get("name") for r in records} != names:
        raise ValueError("missing, duplicate or extra INTEGRATION local command")
    pair_report = read_json(run_dir / "pairs/integration-native.json")
    runtime_report = read_json(run_dir / "runtime/integration-suite.json")
    expected_runtime = sorted(
        {c["case_id"] for c in cases} & CONSUMERS.keys(),
        key=lambda k: (k == "INTEGRATION-SOAK", k),
    )
    if (
        [r.get("case_id") for r in pair_report.get("cases", [])] != sorted(PAIRS)
        or [r.get("case_id") for r in runtime_report.get("cases", [])]
        != expected_runtime
        or set(pair_report.get("peers", {})) != {"M", "XR"}
        or set(runtime_report.get("peers", {})) != {"M", "SS"}
        or runtime_report.get("ssserver_policy")
        != dict(
            outbound_udp_allow_fragmentation=True,
            inbound_udp_allow_fragmentation=True,
            guest_mtu=1500,
        )
    ):
        raise ValueError(
            "missing INTEGRATION ordered pairs, runtime gates or native SS policy"
        )
    actual = {r["case_id"]: r for r in results}
    for case in cases:
        identifier = case["case_id"]
        if identifier in LOCAL:
            selected, events = [], []
            for i, argv in enumerate(commands(identifier)):
                record = next(r for r in records if r["name"] == f"{identifier}-{i}")
                if (
                    record.get("command")
                    != [redact(v.replace("{output}", str(run_dir))) for v in argv]
                    or record.get("log") not in paths
                ):
                    raise ValueError("INTEGRATION command or log changed")
                selected.append(record)
                path = run_dir / f"{identifier}-{i}-events.jsonl"
                if path.exists():
                    events += read_events(path)
            good = passed(
                identifier,
                selected,
                events,
                read_json(run_dir / "script-tests.json")
                if identifier == "INTEGRATION-SCRIPTS"
                else None,
            )
        elif identifier in PAIRS or identifier in CONSUMERS:
            pair = identifier in PAIRS
            report = pair_report if pair else runtime_report
            record = next(r for r in report["cases"] if r["case_id"] == identifier)
            directory = run_dir / ("pairs" if pair else "runtime")
            good = envelope(report, peers, source, digest) and (
                pair_pass if pair else runtime_pass
            )(identifier, record, directory)
        elif identifier == "INTEGRATION-HY2-HOP":
            good = hops_pass(run_dir / "hop", peers, source, digest)
        else:
            good = shared_pass(run_dir / "shared", peers, source, digest)
        if not good or result(case, good, True) != actual[identifier]:
            raise ValueError("INTEGRATION raw evidence does not pass: " + identifier)
    print(
        f"INTEGRATION: PASS ({len(cases)} required gates; 49 pairs, "
        "100 lifetimes, 100 rebuilds, 1800-second soak)"
    )


def preflight(output):
    from .protocol_containers import frozen_image
    from .protocol_hysteria2_acceptance import prepare

    # Downloads and container package setup only; never reports behavior PASS.
    with frozen_image(output / "container-image-pull.log"):
        supplied = prepare(output, {"M", "XR", "V2", "H"})
    (output / "peers.json").write_text(
        json.dumps({k: v[1] for k, v in supplied.items()}, indent=2) + "\n"
    )
