"""Frozen strongly-coupled TLS/transport and uninterrupted hopping regressions."""

from __future__ import annotations

from .protocol_evidence import read_json
from .protocol_n7_acceptance import CHECKERS, REPORTS
from .protocol_n7_catalog import groups
from .protocol_n9_checks import envelope

SHARED = (
    "N7-SHARED-NONE",
    "N7-SHARED-CHROME",
    "N7-SHARED-XHTTP",
    "N7-HYBRID-RETAINED",
    "N7-JLS-RETAINED",
    "N7-ECH-CHROME",
    "N7-ECH-ENCRYPTION-NATIVE-0RTT-MIXED",
    "N7-JLS-ENCRYPTION-NATIVE-0RTT-MIXED",
    "N7-HYBRID-ENCRYPTION-NATIVE-0RTT-MIXED",
)
HOPS = (
    "N6-HOP-V4-PLAIN-FIXED",
    "N6-HOP-V4-OBFS-RANDOM",
    "N6-HOP-V6-PLAIN-RANDOM",
    "N6-HOP-V6-OBFS-FIXED",
)


def shared_run(directory, supplied):
    from .protocol_reality_hybrid import run as hybrid
    from .protocol_vless_container import run as vless
    from .protocol_xhttp_fields import run as xhttp

    catalog = groups()
    for name in SHARED:
        print("N9 shared: " + name, flush=True)
        group = catalog[name]
        options = {k: v for k, v in group.items() if k not in {"rows", "runner"}}
        if group["runner"] == "xhttp":
            options["selected"] = list(options["jobs"])
        {"vless": vless, "xhttp": xhttp, "hybrid": hybrid}[group["runner"]](
            directory / name, supplied=supplied, **options
        )


def shared_pass(directory, peers, source, digest):
    catalog = groups()
    for name in SHARED:
        group = catalog[name]
        root = directory / name
        report = read_json(root / REPORTS[group["runner"]])
        if not envelope(report, peers, source, digest) or not CHECKERS[group["runner"]](
            group, report, root
        ):
            return False
    return True


def hops_run(directory, supplied):
    from .protocol_hysteria2_catalog import H
    from .protocol_hysteria2_hop import run

    for name in HOPS:
        print("N9 uninterrupted: " + name, flush=True)
        run(directory / name, supplied=supplied, **H[name])


def hops_pass(directory, peers, source, digest):
    from .protocol_hysteria2_acceptance import native_result
    from .protocol_hysteria2_catalog import definitions

    catalog = {c["case_id"]: c for c in definitions()}
    prep = read_json(directory.parent / "package-preparation.json")
    if not (
        prep.get("firewall_packages")
        and prep.get("peers")
        and all(p.get("joined") is True for p in prep["peers"])
        and prep.get("image_digest") == digest
    ):
        return False
    for name in HOPS:
        root = directory / name
        report = read_json(root / "report.json")
        if not (
            envelope(report, peers, source, digest, single="H")
            and native_result(catalog[name], report, root)["status"] == "PASS"
            and report["isolation"].get("firewall_packages")
            == prep["firewall_packages"]
        ):
            return False
    return True
