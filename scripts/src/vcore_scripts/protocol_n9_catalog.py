"""N9 integration requirements; no stage inherits historical PASS results."""

from __future__ import annotations

PROTOCOLS = ("socks5", "anytls", "ss", "trojan", "vmess", "vless", "hysteria2")
PAIRS = {
    f"N9-PAIR-{first.upper()}-{last.upper()}": (first, last)
    for first in PROTOCOLS
    for last in PROTOCOLS
}
GATES = {
    "N9-ENTRYPOINTS": 1,
    "N9-GRAPH": 1,
    "N9-DNS-MEASURE": 1,
    "N9-SS-ALGORITHMS": 1,
    "N9-SS-EIH": 1,
    "N9-LIFECYCLE": 2,
    "N9-REBUILD": 2,
    "N9-FAILURES": 2,
    "N9-SOAK": 3,
    "N9-HY2-HOP": 3,
    "N9-DEBUG": 4,
    "N9-RELEASE": 4,
    "N9-QUALITY": 4,
    "N9-FEATURES": 4,
    "N9-SCRIPTS": 4,
    "N9-SHARED": 4,
}
LOCAL = {"N9-DEBUG", "N9-RELEASE", "N9-QUALITY", "N9-FEATURES", "N9-SCRIPTS"}


def definitions():
    result = []
    for identifier in sorted(PAIRS.keys() | GATES.keys()):
        pair = PAIRS.get(identifier)
        local = identifier in LOCAL
        result.append(
            dict(
                case_id=identifier,
                stage="N9",
                substage=f"N9.{GATES.get(identifier, 1)}",
                required=True,
                row_ids=["C06"] if pair else [],
                protocol="integration",
                network="seven-protocol-graph",
                security="per-frozen-consumer",
                udp_codec="per-protocol",
                field_values={"first": pair[0], "last": pair[1]} if pair else {},
                outer_family="IPv4/IPv6",
                inner_family="IPv4/IPv6/domain",
                target_type="memory-only/build" if local else "isolated origin",
                upstream_graph="concrete/nested-select" if pair else "per-gate",
                peer_kind="unit"
                if local
                else "H"
                if identifier == "N9-HY2-HOP"
                else "SS"
                if identifier == "N9-SS-EIH"
                else "M",
                peer_config={"group": identifier},
                gap_source=None,
                expected_observation=[identifier],
                required_evidence=["command", "structured-assertions", "cleanup"]
                + ([] if local else ["peer-identity", "isolated-origins"]),
                prerequisites=["rust-toolchain"]
                if local
                else ["owned-host-only-container-network", "official-latest-peer"],
                runner="integration-pair" if pair else "integration-gate",
                timeout_seconds=3600 if not pair else 300,
            )
        )
    return result
