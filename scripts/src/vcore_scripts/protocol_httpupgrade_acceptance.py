"""Run HTTPUpgrade gates and independently reconstruct persisted acceptance."""

from __future__ import annotations

import json

from .core_checks import validate_execution
from .protocol_evidence import read_events, read_json
from .protocol_httpupgrade import events_pass, expected_observation
from .protocol_httpupgrade_catalog import (
    LOCAL,
    REGRESSION,
    UNIT,
    WIRE,
    commands,
    wire_cases,
)
from .protocol_hysteria2_catalog import assertions_pass
from .protocol_inputs import redact
from .protocol_integration_checks import envelope
from .protocol_security_acceptance import result, rust_command
from .protocol_shadowtls_acceptance import source


def wire_pass(name, directory, report):
    expected = wire_cases(name)
    rows = report.get("cases", [])
    if [r.get("case_id") for r in rows] != [r[0] for r in expected]:
        return False
    for row, (identifier, consumer) in zip(rows, expected, strict=True):
        observed = read_json(directory / (identifier + "-observations.json"))
        if consumer == "close":
            reference = read_json(directory / (identifier + "-close-reference.json"))
            raw = json.loads(
                (directory / (identifier + "-close-command.log")).read_text()
            )
            if (
                reference != raw
                or raw.get("terminated") is not True
                or raw.get("variant") != "plain"
            ):
                return False
            wanted = dict(tail_hex=raw["tail_hex"], terminated=True, stop_idle=True)
        else:
            node = dict(type="vmess" if identifier.startswith("vmess") else "trojan")
            node["packet-encoding"] = identifier.rsplit("-", 1)[-1]
            wanted = expected_observation(
                consumer, node, "XR" if name == "UDP-DOMAIN" else "M"
            )
        if not (
            row.get("command")
            == rust_command("vless_public", "httpupgrade::" + consumer)
            and type(row.get("exit_code")) is int
            and row["exit_code"] == 0
            and row.get("command_cleanup") is True
            and observed == row.get("observations") == wanted
            and events_pass(
                read_events(directory / (identifier + "-events.jsonl")), consumer
            )
        ):
            return False
    return True


def local_pass(name, directory, run):
    rows = [
        r for r in run["commands"] if r["name"].startswith("HTTPUPGRADE-" + name + "-")
    ]
    expected = commands(name)
    if len(rows) != len(expected):
        return False
    events = []
    for i, (row, argv) in enumerate(zip(rows, expected, strict=True)):
        label = f"HTTPUPGRADE-{name}-{i}"
        if row["name"] != label or row["command"] != [redact(v) for v in argv]:
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
    return name not in {"MEMORY", "FEATURES"} or assertions_pass(
        [e for e in events if e.get("suite", "").startswith("HTTPUPGRADE-")],
        {("HTTPUPGRADE-UNIT", n): 1 if name == "MEMORY" else 2 for n in UNIT},
    )


def regression_pass(name, directory, report):
    from .protocol_vless_public import PUBLIC
    from .protocol_vless_public import events_pass as vless_events
    from .protocol_vmess_public import CASES
    from .protocol_vmess_public import events_pass as vmess_events

    selected = REGRESSION[name]
    rows = report.get("cases", [])
    if [r.get("case_id") for r in rows] != selected:
        return False
    for row in rows:
        identifier = row["case_id"]
        kind, mode, _, consumer = (PUBLIC if name == "VLESS" else CASES)[identifier]
        observed = read_events(directory / (identifier + "-events.jsonl"))
        if not (
            row.get("peer_kind") == kind
            and row.get("command") == rust_command(name.lower() + "_public", consumer)
            and type(row.get("exit_code")) is int
            and row["exit_code"] == 0
            and row.get("command_cleanup") is True
            and row.get("cleanup") is True
            and (
                vless_events(observed, consumer, mode)
                if name == "VLESS"
                else vmess_events(observed, consumer)
            )
        ):
            return False
    return True


def group_pass(name, directory, run, peers):
    if name in LOCAL:
        return local_pass(name, directory, run)
    root = directory / name.lower()
    report = read_json(
        root / ("report.json" if name in WIRE else name.lower() + "-results.json")
    )
    return envelope(
        report,
        peers,
        source(run),
        run["container_image"]["digest"],
        single=("XR" if name == "UDP-DOMAIN" else "M") if name in WIRE else None,
    ) and (
        wire_pass(name, root, report)
        if name in WIRE
        else regression_pass(name, root, report)
    )


def execute(cases, run, output, results):
    from .protocol_containers import frozen_image
    from .protocol_harness import _command
    from .protocol_httpupgrade import run as upgrade
    from .protocol_hysteria2_acceptance import prepare
    from .protocol_vless_container import run as vless
    from .protocol_vmess_container import run as vmess

    selected = {c["case_id"].removeprefix("HTTPUPGRADE-"): c for c in cases}
    peers = {}

    def save(name):
        good = group_pass(name, output, run, peers)
        case = selected[name]
        results[case["case_id"]] = result(case, good, good)
        print(case["case_id"] + (": PASS" if good else ": FAIL"), flush=True)
        if not good:
            raise RuntimeError("HTTPUpgrade gate failed: " + name)

    try:
        for name in selected:
            if name not in LOCAL:
                continue
            for i, argv in enumerate(commands(name)):
                label = f"HTTPUPGRADE-{name}-{i}"
                completed = _command(
                    run,
                    output,
                    label,
                    argv,
                    3600,
                    events=output / (label + "-events.jsonl"),
                )
                validate_execution(
                    argv,
                    completed.stdout.decode(errors="replace"),
                    completed.returncode,
                    completed.cleanup,
                )
            save(name)
        if set(selected) <= LOCAL:
            return
        with frozen_image(output / "image-pull.log") as image:
            run["container_image"] = image
            kinds = (
                {"M"}
                | ({"XR"} if "UDP-DOMAIN" in selected else set())
                | ({"V2"} if "VMESS" in selected else set())
            )
            supplied = prepare(output, kinds)
            peers.update({k: v[1] for k, v in supplied.items()})
            for name in selected:
                if name in LOCAL:
                    continue
                root = output / name.lower()
                if name in WIRE:
                    upgrade(
                        root,
                        checks=name.lower(),
                        supplied=supplied["XR" if name == "UDP-DOMAIN" else "M"],
                        image=image,
                    )
                elif name == "VLESS":
                    vless(root, selected=REGRESSION[name], supplied=supplied)
                elif name == "VMESS":
                    vmess(root, selected=REGRESSION[name], supplied=supplied)
                save(name)
    finally:
        (output / "peers.json").write_text(json.dumps(peers, indent=2) + "\n")


def check(directory, cases, run, results, peers, paths):
    if not {"cases.json", "peers.json", "resources.jsonl", "summary.md"} <= set(paths):
        raise ValueError("missing HTTPUpgrade evidence")
    expected = [
        f"{c['case_id']}-{i}"
        for c in cases
        for i, _ in enumerate(commands(c["case_id"].removeprefix("HTTPUPGRADE-")))
    ]
    actual = [r["name"] for r in run["commands"]]
    if (
        len(actual) != len(set(actual))
        or set(actual) != set(expected)
        or set(peers) != {"M", "XR", "V2"}
    ):
        raise ValueError("HTTPUpgrade command or peer selection differs")
    for case in cases:
        name = case["case_id"].removeprefix("HTTPUPGRADE-")
        if not group_pass(name, directory, run, peers):
            raise ValueError("HTTPUpgrade raw evidence failed: " + name)
    print("HTTPUpgrade coverage: PASS (all required groups; device delivery separate)")


def preflight(output):
    from .protocol_containers import command, frozen_image
    from .protocol_hysteria2_acceptance import prepare

    command("system", "status")
    with frozen_image(output / "image-pull.log"):
        supplied = prepare(output, {"M", "XR", "V2"})
    (output / "peers.json").write_text(
        json.dumps(
            dict(
                scope="download-only",
                wire_acceptance="NOT RUN",
                peers={k: v[1] for k, v in supplied.items()},
            ),
            indent=2,
        )
        + "\n"
    )
