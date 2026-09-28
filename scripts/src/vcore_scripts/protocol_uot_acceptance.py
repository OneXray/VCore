"""Execute UoT gates and independently verify their raw evidence."""

from __future__ import annotations

import json

from .core_checks import validate_execution
from .protocol_evidence import read_events, read_json
from .protocol_hysteria2_catalog import assertions_pass
from .protocol_inputs import redact
from .protocol_integration_checks import envelope, runtime_pass
from .protocol_security_acceptance import REPORTS, result, rust_command, vless_pass
from .protocol_shadowtls_acceptance import source
from .protocol_uot import expected_observation
from .protocol_uot_catalog import LOCAL, MEMORY_EVENTS, commands, wire_cases


def wire_pass(name, directory, report):
    selected = wire_cases(name)
    rows = report.get("cases", [])
    if [r.get("case_id") for r in rows] != [c[0] for c in selected]:
        return False
    via_socks5 = name in {"MIHOMO-SOCKS5", "MIHOMO-GROUPS"}
    if report.get("tcp_only_upstream") is not via_socks5:
        return False
    for row, (identifier, consumer) in zip(rows, selected, strict=True):
        if not (
            row.get("command") == rust_command("vless_public", "uot::" + consumer)
            and type(row.get("exit_code")) is int
            and row["exit_code"] == 0
            and row.get("command_cleanup") is True
            and row.get("listener_native_udp") is False
            and row.get("observations")
            == read_json(directory / (identifier + "-observations.json"))
            == expected_observation(consumer, via_socks5)
            and assertions_pass(
                read_events(directory / (identifier + "-events.jsonl")),
                {("UOT-PUBLIC", consumer): 1},
            )
        ):
            return False
    return True


def local_pass(name, directory, run):
    expected = commands(name)
    rows = [r for r in run["commands"] if r["name"].startswith("UOT-" + name + "-")]
    if len(rows) != len(expected):
        return False
    events = []
    for index, (row, argv) in enumerate(zip(rows, expected, strict=True)):
        label = f"UOT-{name}-{index}"
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
    if name == "MEMORY":
        return assertions_pass(
            [e for e in events if e.get("suite", "").startswith("UOT-")], MEMORY_EVENTS
        )
    if name == "FEATURES":
        return assertions_pass(
            [e for e in events if e.get("suite", "").startswith("UOT-")],
            MEMORY_EVENTS | {("UOT-CFG", "strict_v2"): 2},
        )
    return True


ANYTLS = dict(selected=["FINGERPRINT-ANYTLS"], client_fingerprint="none")


def group_pass(name, directory, run, peers):
    if name in LOCAL:
        return local_pass(name, directory, run)
    root = directory / name.lower()
    digest = run["container_image"]["digest"]
    if name == "ANYTLS":
        report = read_json(root / REPORTS["vless"])
        return envelope(report, peers, source(run), digest) and vless_pass(
            ANYTLS, report, root
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
    return envelope(
        report,
        peers,
        source(run),
        digest,
        single="SS" if name == "NATIVE-UNSUPPORTED" else "M",
    ) and wire_pass(name, root, report)


def prepare(output, *, native):
    from .native_release import download_native
    from .protocol_hysteria2_acceptance import prepare as mihomo

    supplied = mihomo(output, {"M"})
    artifact = (
        download_native("SS", output / "binaries/SS", "linux-arm64", defer_version=True)
        if native
        else None
    )
    return supplied, artifact


def execute(cases, run, output, results):
    from .protocol_containers import frozen_image
    from .protocol_harness import _command
    from .protocol_integration_suite import run as integration
    from .protocol_uot import run as uot
    from .protocol_vless_container import run as vless

    selected = {c["case_id"].removeprefix("UOT-"): c for c in cases}
    peers = {}

    def save(name):
        good = group_pass(name, output, run, peers)
        case = selected[name]
        results[case["case_id"]] = result(case, good, good)
        print(case["case_id"] + (": PASS" if good else ": FAIL"), flush=True)
        if not good:
            raise RuntimeError("UoT gate failed: " + name)

    try:
        for name in selected:
            if name not in LOCAL:
                continue
            for i, argv in enumerate(commands(name)):
                label = f"UOT-{name}-{i}"
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
            supplied, artifact = prepare(
                output, native="NATIVE-UNSUPPORTED" in selected
            )
            peers.update({k: v[1] for k, v in supplied.items()})
            if artifact is not None:
                peers["SS"] = artifact.identity
            for name in selected:
                if name in LOCAL:
                    continue
                root = output / name.lower()
                if name.startswith("MIHOMO-"):
                    uot(
                        root,
                        via_socks5=name in {"MIHOMO-SOCKS5", "MIHOMO-GROUPS"},
                        checks="negative"
                        if name == "MIHOMO-NEGATIVE"
                        else "group"
                        if name == "MIHOMO-GROUPS"
                        else "data",
                        supplied=supplied["M"],
                        image=image,
                    )
                elif name == "NATIVE-UNSUPPORTED":
                    uot(
                        root,
                        native=True,
                        checks="negative",
                        supplied=(artifact.binary, artifact.identity),
                        image=image,
                    )
                elif name == "ANYTLS":
                    vless(root, supplied=supplied, **ANYTLS)
                elif name == "BARE-SS":
                    integration(
                        root, ["INTEGRATION-SS-ALGORITHMS"], supplied=supplied["M"]
                    )
                else:
                    raise ValueError("unknown UoT gate")
                save(name)
    finally:
        (output / "peers.json").write_text(json.dumps(peers, indent=2) + "\n")


def check(directory, cases, run, results, peers, paths):
    if not {"cases.json", "peers.json", "resources.jsonl", "summary.md"} <= set(paths):
        raise ValueError("missing UoT evidence")
    expected = [
        f"UOT-{c['case_id'].removeprefix('UOT-')}-{i}"
        for c in cases
        for i, _ in enumerate(commands(c["case_id"].removeprefix("UOT-")))
    ]
    actual = [r["name"] for r in run["commands"]]
    if (
        len(actual) != len(set(actual))
        or set(actual) != set(expected)
        or set(peers) != {"M", "SS"}
    ):
        raise ValueError("UoT command or peer selection differs")
    for case in cases:
        name = case["case_id"].removeprefix("UOT-")
        if not group_pass(name, directory, run, peers):
            raise ValueError("UoT raw evidence failed: " + name)
    print("UOT coverage: PASS (all required groups; device delivery separate)")


def preflight(output):
    from .protocol_containers import command, frozen_image

    command("system", "status")
    with frozen_image(output / "image-pull.log"):
        supplied, artifact = prepare(output, native=True)
    (output / "peers.json").write_text(
        json.dumps(
            dict(
                scope="download-only",
                wire_acceptance="NOT RUN",
                peers={
                    **{k: v[1] for k, v in supplied.items()},
                    "SS": artifact.identity,
                },
            ),
            indent=2,
        )
        + "\n"
    )
