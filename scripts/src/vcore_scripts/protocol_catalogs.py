"""Executable catalog integrity; production fields are documented in config.yaml."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CATALOG_DIR = Path(__file__).resolve().parents[3] / "tests" / "protocols"
PROTOCOLS = {"trojan", "vmess", "vless", "hysteria2"}
PEERS = {"M", "H", "XR", "V2"}
SUITES = {
    "FOUNDATIONS": (
        "schema",
        "security",
        "streams",
        "datagrams",
        "features",
        "regression",
    ),
    "TROJAN": ("codec", "configuration", "cancellation", "acceptance"),
    "VMESS": ("identity", "codec", "udp", "close", "acceptance"),
    "VLESS": ("tcp", "transports", "vision", "acceptance"),
    "XHTTP": ("requests", "download", "mux", "http3", "acceptance"),
    "HYSTERIA2": ("tcp", "udp", "bandwidth", "salamander", "hopping", "acceptance"),
    "SECURITY": ("encryption", "reality", "ech", "jls", "acceptance"),
    "INTEGRATION": ("routing", "lifecycle", "pressure", "regression"),
}
CATEGORIES = {
    f"{suite}.{category}"
    for suite, categories in SUITES.items()
    for category in categories
}
# Stable evidence tags; field semantics live in docs/config.yaml, not a planning mirror.
FIELD_IDS = {
    f"{prefix}{index:02}"
    for prefix, count in {
        "C": 6,
        "T": 8,
        "W": 7,
        "G": 6,
        "H": 6,
        "TR": 2,
        "VM": 8,
        "VL": 6,
        "X": 29,
        "D": 32,
        "S": 13,
        "M": 7,
        "HY": 8,
    }.items()
    for index in range(1, count + 1)
    if not (
        (prefix == "D" and 19 <= index <= 24) or (prefix == "S" and 6 <= index <= 11)
    )
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("protocol catalog: duplicate JSON key")
        result[key] = value
    return result


def check_protocol_catalogs(directory: Path = CATALOG_DIR) -> None:
    from .protocol_evidence import check_limit_references, load_manifest

    cases = load_manifest()
    check_limit_references(cases, directory / "limits.json")
    print(
        json.dumps(
            {
                "kind": "executable-catalog-check",
                "status": "VALID",
                "behavior_status": "NOT RUN",
                "cases": len(cases),
                "fields": len(set().union(*(set(case["row_ids"]) for case in cases))),
            },
            sort_keys=True,
        )
    )
