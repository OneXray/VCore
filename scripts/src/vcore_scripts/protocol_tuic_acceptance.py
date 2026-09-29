"""Execute TUIC gates; reconstruct acceptance from raw local and container evidence."""

from __future__ import annotations

import json

from .core_checks import validate_execution
from .protocol_evidence import read_events, read_json
from .protocol_hysteria2_catalog import M, assertions_pass
from .protocol_hysteria2_catalog import definitions as hy2_definitions
from .protocol_inputs import redact
from .protocol_integration_checks import envelope
from .protocol_security_acceptance import result, rust_command
from .protocol_shadowtls_acceptance import source
from .protocol_tuic import expected_observation
from .protocol_tuic_catalog import (
    CFG_EVENTS,
    LOCAL,
    MEMORY_EVENTS,
    commands,
    wire_cases,
)


def wire_pass(name, directory, report):
    selected = wire_cases(name)
    rows = report.get("cases", [])
    if [r.get("case_id") for r in rows] != [c[0] for c in selected]:
        return False
    for row, (identifier, consumer) in zip(rows, selected, strict=True):
        if not (
            row.get("command") == rust_command("vless_public", "tuic::" + consumer)
            and type(row.get("exit_code")) is int
            and row["exit_code"] == 0
            and row.get("command_cleanup") is True
            and row.get("observations")
            == read_json(directory / (identifier + "-observations.json"))
            == expected_observation(consumer)
            and assertions_pass(
                read_events(directory / (identifier + "-events.jsonl")),
                {("TUIC-PUBLIC", consumer): 1},
            )
        ):
            return False
    return True


def local_pass(name, directory, run):
    expected = commands(name)
    rows = [r for r in run["commands"] if r["name"].startswith("TUIC-" + name + "-")]
    if len(rows) != len(expected):
        return False
    events = []
    for index, (row, argv) in enumerate(zip(rows, expected, strict=True)):
        label = f"TUIC-{name}-{index}"
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
    if name in {"MEMORY", "FEATURES"}:
        required = (
            MEMORY_EVENTS
            if name == "MEMORY"
            else {
                **{
                    key: value
                    for key, value in MEMORY_EVENTS.items()
                    if key[1]
                    not in {"reassembly_order", "reassembly_limits", "delivery_limits"}
                },
                **{
                    key: 2 if key[1] in {"identity", "redaction"} else value
                    for key, value in CFG_EVENTS.items()
                },
            }
        )
        return assertions_pass(
            [e for e in events if e.get("suite", "").startswith("TUIC-")], required
        )
    return True


def group_pass(name, directory, run, peers):
    from .protocol_hysteria2_acceptance import h3_result, native_result

    if name in LOCAL:
        return local_pass(name, directory, run)
    root = directory / name.lower()
    digest = run["container_image"]["digest"]
    if name.startswith("MIHOMO-"):
        report = read_json(root / "report.json")
        return envelope(report, peers, source(run), digest, single="M") and wire_pass(
            name, root, report
        )
    if name.startswith("HYSTERIA2-"):
        case = next(c for c in hy2_definitions() if c["case_id"] == name)
        report = read_json(root / "report.json")
        return (
            envelope(report, peers, source(run), digest)
            and native_result(case, report, root)["status"] == "PASS"
        )
    if name == "XHTTP-H3":
        from .protocol_hysteria2_catalog import H3

        case = next(c for c in hy2_definitions() if c["case_id"] == H3)
        report = read_json(root / "xhttp-fields-results.json")
        return (
            envelope(report, peers, source(run), digest)
            and h3_result(case, report, root)["status"] == "PASS"
        )
    raise ValueError("unknown TUIC gate")


def execute(cases, run, output, results):
    from .protocol_containers import frozen_image
    from .protocol_harness import _command
    from .protocol_hysteria2 import run as hysteria2
    from .protocol_hysteria2_acceptance import h3_jobs, prepare
    from .protocol_tuic import run as tuic
    from .protocol_xhttp_fields import run as h3

    selected = {c["case_id"].removeprefix("TUIC-"): c for c in cases}
    peers = {}

    def save(name):
        good = group_pass(name, output, run, peers)
        case = selected[name]
        results[case["case_id"]] = result(case, good, good)
        print(case["case_id"] + (": PASS" if good else ": FAIL"), flush=True)
        if not good:
            raise RuntimeError("TUIC gate failed: " + name)

    try:
        for name in selected:
            if name not in LOCAL:
                continue
            for i, argv in enumerate(commands(name)):
                label = f"TUIC-{name}-{i}"
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
            supplied = prepare(output, {"M", "XR"} if "XHTTP-H3" in selected else {"M"})
            peers.update({k: v[1] for k, v in supplied.items()})
            for name in selected:
                if name in LOCAL:
                    continue
                root = output / name.lower()
                if name.startswith("MIHOMO-"):
                    tuic(
                        root,
                        checks=name.removeprefix("MIHOMO-").lower(),
                        supplied=supplied["M"],
                        image=image,
                    )
                elif name in M:
                    test, obfs, _ = M[name]
                    hysteria2(root, test, obfs=obfs, supplied=supplied["M"])
                elif name == "XHTTP-H3":
                    jobs = h3_jobs()
                    h3(root, list(jobs), jobs=jobs, supplied=supplied)
                else:
                    raise ValueError("unknown TUIC group")
                save(name)
    finally:
        (output / "peers.json").write_text(json.dumps(peers, indent=2) + "\n")


def check(directory, cases, run, results, peers, paths):
    if not {"cases.json", "peers.json", "resources.jsonl", "summary.md"} <= set(paths):
        raise ValueError("missing TUIC evidence")
    expected = [
        f"{c['case_id']}-{i}"
        for c in cases
        for i, _ in enumerate(commands(c["case_id"].removeprefix("TUIC-")))
    ]
    actual = [r["name"] for r in run["commands"]]
    if (
        len(actual) != len(set(actual))
        or set(actual) != set(expected)
        or set(peers) != {"M", "XR"}
    ):
        raise ValueError("TUIC command or peer selection differs")
    for case in cases:
        name = case["case_id"].removeprefix("TUIC-")
        if not group_pass(name, directory, run, peers):
            raise ValueError("TUIC raw evidence failed: " + name)
    print("TUIC coverage: PASS (all required groups; device delivery separate)")


def preflight(output):
    from .protocol_containers import command, frozen_image
    from .protocol_hysteria2_acceptance import prepare

    command("system", "status")
    with frozen_image(output / "image-pull.log"):
        supplied = prepare(output, {"M", "XR"})
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
