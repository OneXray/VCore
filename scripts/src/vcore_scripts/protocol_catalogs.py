from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, TypeGuard
from urllib.parse import urlsplit

CATALOG_DIR = Path(__file__).resolve().parents[3] / "tests" / "protocols"
PROTOCOLS = {"trojan", "vmess", "vless", "hysteria2", "wireguard"}
PEERS = {"M", "W", "H", "XR", "V2"}
STAGES = {f"N{index}" for index in range(11)}
WORK_PACKAGES = {
    f"N{stage}.{package}"
    for stage, count in enumerate((0, 6, 4, 5, 4, 5, 6, 5, 5, 4, 4))
    for package in range(1, count + 1)
}
# Frozen schema-v1 requirements, independent of a catalog's self-reported count.
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
        "WG": 7,
    }.items()
    for index in range(1, count + 1)
}
COMBINATION_IDS = {
    "TR-TCP",
    "TR-WS",
    "TR-GRPC",
    "TR-WS-ED-EXTENDED",
    "VM-BASE",
    "VM-AEAD-BODY",
    "VM-HTTP-RAW",
    "VM-H2-RAW",
    "VM-WS-ED-RAW",
    "VM-V2-XUDP",
    "VM-V2-PACKETADDR",
    "VL-BASE",
    "VL-REALITY",
    "VL-VISION-TLS",
    "VL-VISION-REALITY",
    "VL-WS-HTTPUPGRADE",
    "VL-GRPC-EXTENSIONS",
    "VL-HTTP-RAW-XUDP",
    "VL-HTTP-PACKETADDR",
    "VL-H2-RAW",
    "VL-WS-ED-RAW",
    "VL-V2-XUDP",
    "VL-V2-PACKETADDR",
    "VL-TLS-IDENTITY",
    "VL-XHTTP-H1H2",
    "VL-XHTTP-PLACEMENTS",
    "VL-XHTTP-DUAL-BASE",
    "VL-XHTTP-REUSE",
    "VL-XHTTP-H3",
    "VL-XHTTP-H3-ALL-LEAVES",
    "VL-XHTTP-H3-DUAL",
    "VL-XHTTP-H3-PACKETADDR",
    "VL-XHTTP-CROSS-LEG",
    "VL-SING-MUX",
    "VL-NATIVE-SING-MUX",
    "VL-ENCRYPTION-BASE",
    "VL-ENCRYPTION-VISION",
    "VL-ENCRYPTION-WRAPPERS",
    "VL-REALITY-HYBRID",
    "VL-ECH",
    "VL-SHADOWTLS",
    "VL-RESTLS",
    "VL-JLS",
    "VL-ADVANCED-NATIVE-TRANSPORT",
    "VL-ADVANCED-DOWNLOAD",
    "HY-BASE",
    "HY-SALAMANDER",
    "HY-HOPPING",
    "HY-SERVER-UDP-DISABLED",
    "WG-SINGLE-PEER",
    "ALL-UPSTREAMS",
    "REJECT-VISION-TRANSPORT",
    "REJECT-VISION-UDP-CODEC",
    "REJECT-TROJAN-PLAINTEXT",
    "REJECT-SECURITY-MUTEX",
    "REJECT-ECH-MTLS-WRAPPER",
    "REJECT-H3-SECURITY",
    "REJECT-STREAM-ONE-DOWNLOAD",
    "REJECT-GRPC-SCHEDULERS",
    "REJECT-SMUX-SCHEDULERS",
    "REJECT-VMESS-NONE-PADDING",
    "REJECT-HTTPUPGRADE-EXTENDED-ED",
    "REJECT-WS-PATH-ED-QUERY",
    "REJECT-TRANSPORT-ORPHAN",
    "REJECT-XHTTP-INERT-FIELDS",
    "REJECT-UDP-DISABLED",
    "REJECT-UPSTREAM-DATAGRAM",
    "REJECT-HOP-INTERVAL",
    "REJECT-WG-ADDRESSES",
}
FIELD_KEYS = {
    "id",
    "path",
    "protocols",
    "contract",
    "required_observation",
    "work_packages",
    "responsible_stages",
    "default_peer",
    "peer_override_rules",
    "sources",
    "behavior_status",
}
COMBINATION_KEYS = {
    "id",
    "classification",
    "protocols",
    "row_ids",
    "stages",
    "required_observation",
    "sources",
    "behavior_status",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("protocol catalog: duplicate JSON key")
        result[key] = value
    return result


def _load(directory: Path, name: str, kind: str, keys: set[str]) -> dict[str, Any]:
    try:
        catalog = json.loads(
            (directory / f"{name}.json").read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
        )
    except (json.JSONDecodeError, UnicodeError, RecursionError) as error:
        raise ValueError("protocol catalog: invalid JSON document") from error
    if (
        not isinstance(catalog, dict)
        or type(catalog.get("schema_version")) is not int
        or catalog["schema_version"] != 1
        or catalog.get("kind") != kind
        or "status" not in catalog
        or not isinstance(catalog.get("sources"), dict)
        or not isinstance(catalog.get("peers"), dict)
        or not isinstance(catalog.get(name), list)
        or not catalog[name]
        or any(
            not isinstance(row, dict)
            or not keys <= row.keys()
            or not isinstance(row["id"], str)
            for row in catalog[name]
        )
    ):
        raise ValueError("protocol catalog: malformed or unsupported schema")
    return catalog


def _references(value: object, known: set[str], *, allow_empty: bool = False) -> None:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or not all(isinstance(item, str) and item in known for item in value)
        or len(value) != len(set(value))
    ):
        raise ValueError("protocol catalog: invalid, empty or duplicate reference")


def _text(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and bool(value.strip())


def _source_reference(value: object) -> None:
    if not _text(value) or any(ord(character) < 32 for character in value):
        raise ValueError("protocol catalog: invalid source reference")
    try:
        url = urlsplit(value)
    except ValueError as error:
        raise ValueError("protocol catalog: invalid source reference") from error
    if url.scheme or url.netloc:
        valid = (
            url.scheme == "https"
            and bool(url.hostname)
            and url.username is None
            and url.password is None
            and not url.query
        )
    else:
        path = PurePosixPath(value)
        valid = (
            bool(path.parts)
            and not path.is_absolute()
            and ".." not in path.parts
            and "\\" not in value
        )
    if not valid:
        raise ValueError("protocol catalog: invalid source reference")


def check_protocol_catalogs(directory: Path) -> None:
    fields = _load(directory, "fields", "planned-field-catalog", FIELD_KEYS)
    combinations = _load(
        directory, "combinations", "planned-combination-catalog", COMBINATION_KEYS
    )
    identifiers = [row["id"] for row in fields["fields"]]
    if (
        type(fields.get("field_count")) is not int
        or fields["field_count"] != len(FIELD_IDS)
        or len(identifiers) != len(set(identifiers))
        or set(identifiers) != FIELD_IDS
    ):
        raise ValueError("protocol catalog: missing, duplicate or unknown field IDs")
    identifiers = [row["id"] for row in combinations["combinations"]]
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != COMBINATION_IDS:
        raise ValueError(
            "protocol catalog: missing, duplicate or unknown combination IDs"
        )
    for catalog, key in ((fields, "fields"), (combinations, "combinations")):
        for source in catalog["sources"].values():
            _source_reference(source)
        if catalog["status"] != "NOT RUN" or any(
            row["behavior_status"] != "NOT RUN" for row in catalog[key]
        ):
            raise ValueError("protocol catalog: declarations must remain NOT RUN")
    _references(fields.get("scope"), PROTOCOLS)
    if set(fields["scope"]) != PROTOCOLS:
        raise ValueError("protocol catalog: incomplete protocol scope")
    peers = set(fields["peers"])
    if peers != PEERS or fields["peers"] != combinations["peers"]:
        raise ValueError("protocol catalog: inconsistent native peer registry")
    for peer in fields["peers"].values():
        if not isinstance(peer, dict) or not all(
            _text(peer.get(key))
            for key in ("implementation", "artifact_policy", "source")
        ):
            raise ValueError("protocol catalog: incomplete native peer registry")
        _source_reference(peer["source"])
    rules = fields.get("peer_override_rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("protocol catalog: missing native peer override registry")
    overrides = set()
    for rule in rules:
        if (
            not isinstance(rule, dict)
            or not all(_text(rule.get(key)) for key in ("id", "when", "reason", "peer"))
            or rule["id"] in overrides
        ):
            raise ValueError(
                "protocol catalog: malformed or duplicate native peer override"
            )
        overrides.add(rule["id"])
        _references([rule["peer"]], peers)
        _references(rule.get("protocols"), PROTOCOLS)
        _references(rule.get("sources"), set(fields["sources"]))
    for row in fields["fields"]:
        _references(row["protocols"], PROTOCOLS)
        _references(row["responsible_stages"], STAGES)
        _references(row["work_packages"], WORK_PACKAGES)
        if (
            not _text(row["path"])
            or not row["path"].startswith("proxies[].")
            or not _text(row["contract"])
            or not _text(row["required_observation"])
            or set(row["responsible_stages"])
            != {package.split(".")[0] for package in row["work_packages"]}
        ):
            raise ValueError("protocol catalog: invalid field contract or ownership")
        _references(row["sources"], set(fields["sources"]))
        if not isinstance(row["default_peer"], str) or row["default_peer"] not in peers:
            raise ValueError("protocol catalog: invalid peer reference")
        _references(row["peer_override_rules"], overrides, allow_empty=True)
    by_id = {row["id"]: row for row in fields["fields"]}
    for row in combinations["combinations"]:
        _references(row["protocols"], PROTOCOLS)
        _references(row["stages"], STAGES)
        if row["id"] == "ALL-UPSTREAMS" and (
            type(row.get("ordered_pairs")) is not int
            or row["ordered_pairs"] != 64
            or set(row["protocols"]) != PROTOCOLS
            or not isinstance(row.get("existing_protocols"), list)
            or len(row["existing_protocols"]) != 3
            or not all(
                protocol in row["existing_protocols"]
                for protocol in ("anytls", "socks5", "ss2022")
            )
        ):
            raise ValueError("protocol catalog: incomplete upstream pair declaration")
        if not _text(row["required_observation"]):
            raise ValueError("protocol catalog: missing combination observation")
        classification = row["classification"]
        if classification not in (
            "supported-required",
            "rejected-by-contract",
            "required-but-peer-unproven",
        ):
            raise ValueError("protocol catalog: unknown classification contract")
        if classification == "rejected-by-contract" and (
            row.get("rejection_phase")
            not in ("prepare", "dispatch", "establish", "prepare-or-establish")
            or not _text(row.get("when"))
        ):
            raise ValueError(
                "protocol catalog: missing rejection classification contract"
            )
        if classification == "required-but-peer-unproven" and not _text(
            row.get("blocked_on")
        ):
            raise ValueError(
                "protocol catalog: missing native-gap classification contract"
            )
        _references(row["sources"], set(combinations["sources"]))
        _references(row["row_ids"], FIELD_IDS)
        if any(
            not set(row["protocols"]) & set(by_id[identifier]["protocols"])
            for identifier in row["row_ids"]
        ):
            raise ValueError("protocol catalog: incompatible field protocol reference")
        if row["classification"] != "rejected-by-contract":
            for key in ("networks", "security_modes", "udp_codecs", "business"):
                dimension = row.get(key)
                if (
                    not isinstance(dimension, list)
                    or not dimension
                    or not all(_text(value) for value in dimension)
                    or len(dimension) != len(set(dimension))
                ):
                    raise ValueError(
                        "protocol catalog: missing or malformed mode dimension"
                    )
            _references(row["business"], {"tcp", "udp"})
            _references(row.get("peers"), peers)
    print(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "protocol-catalog-check",
                "status": "VALID",
                "behavior_status": "NOT RUN",
                "fields": len(fields["fields"]),
                "combination_families": len(combinations["combinations"]),
            },
            sort_keys=True,
        )
    )
