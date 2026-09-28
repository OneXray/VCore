"""Cross-protocol integration requirements and descriptive coverage categories."""

from __future__ import annotations

PROTOCOLS = ("socks5", "anytls", "ss", "trojan", "vmess", "vless", "hysteria2")
PAIRS = {
    f"INTEGRATION-PAIR-{first.upper()}-{last.upper()}": (first, last)
    for first in PROTOCOLS
    for last in PROTOCOLS
}
GATES = {
    "INTEGRATION-ENTRYPOINTS": "routing",
    "INTEGRATION-GRAPH": "routing",
    "INTEGRATION-DNS-MEASURE": "routing",
    "INTEGRATION-SS-ALGORITHMS": "routing",
    "INTEGRATION-SS-EIH": "routing",
    "INTEGRATION-LIFECYCLE": "lifecycle",
    "INTEGRATION-REBUILD": "lifecycle",
    "INTEGRATION-FAILURES": "lifecycle",
    "INTEGRATION-SOAK": "pressure",
    "INTEGRATION-HY2-HOP": "pressure",
    "INTEGRATION-DEBUG": "regression",
    "INTEGRATION-RELEASE": "regression",
    "INTEGRATION-QUALITY": "regression",
    "INTEGRATION-FEATURES": "regression",
    "INTEGRATION-SCRIPTS": "regression",
    "INTEGRATION-SHARED": "regression",
}
LOCAL = {
    "INTEGRATION-DEBUG",
    "INTEGRATION-RELEASE",
    "INTEGRATION-QUALITY",
    "INTEGRATION-FEATURES",
    "INTEGRATION-SCRIPTS",
}


def definitions():
    result = []
    for identifier in sorted(PAIRS.keys() | GATES.keys()):
        pair = PAIRS.get(identifier)
        local = identifier in LOCAL
        result.append(
            dict(
                case_id=identifier,
                stage="INTEGRATION",
                substage=f"INTEGRATION.{GATES.get(identifier, 'routing')}",
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
                if identifier == "INTEGRATION-HY2-HOP"
                else "SS"
                if identifier == "INTEGRATION-SS-EIH"
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
