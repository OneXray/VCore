"""Frozen HYSTERIA2 requirements and exact structured assertion identities."""

from __future__ import annotations

from collections import Counter

from .protocol_evidence import idle_resources

FIELDS = {
    *(f"C{i:02}" for i in range(1, 7)),
    "T01",
    "T03",
    "T04",
    "T05",
    "T07",
    "T08",
    *(f"HY{i:02}" for i in range(1, 9)),
}
CFG = [
    "hysteria2_configuration_follows_its_protocol_feature",
    "hysteria2_accepts_the_approved_tls_bandwidth_obfs_and_hopping_configuration",
    "hysteria2_fields_are_strict_normalized_and_credentials_are_not_trimmed",
]
UNIT = [
    "tcp_wire_matches_the_protocol_and_preserves_server_first_bytes",
    "udp_wire_round_trips_at_budget_and_bounds_malformed_fragments",
    "udp_reassembly_isolates_sources_duplicates_counts_bytes_and_expiry",
    "salamander_matches_independent_blake2b256_vector_and_rejects_short_packets",
    "pacer_limits_actual_bytes_after_one_bounded_burst",
    "bandwidth_negotiation_obeys_auto_and_the_lower_positive_limit",
    "application_eof_closes_both_directions_without_consuming_a_tail",
    "shutdown_wakes_an_already_pending_logical_reader",
    "a_client_first_write_does_not_steal_a_pending_read_wakeup",
    "a_new_path_packet_does_not_end_the_old_receive_window",
    "authenticated_continuation_keeps_group_choice_but_has_a_new_io_deadline",
    "controlled_path_maps_only_its_authorized_source_and_stops_without_replay",
]
SECURITY = (
    "root-pin",
    "leaf-pin",
    "root-pin-wrong-name",
    "leaf-pin-is-trust",
    "unknown-ca",
    "explicit-skip",
    "wrong-pin",
    "skip-does-not-override-pin",
    "wrong-password",
    "empty-password",
    "raw-password",
    "empty-alpn-default",
    "custom-alpn",
    "wrong-alpn",
    "mtls-valid",
    "mtls-absent",
    "mtls-expired",
    "mtls-wrong-ca",
    "salamander",
    "salamander-client-only",
    "salamander-server-only",
    "salamander-wrong-key",
    "salamander-wrong-auth",
)
M = {
    "HYSTERIA2-TCP": (
        "hysteria2_tcp_base",
        False,
        ["C01", "C02", "C03", "C04", "T01", "T03", "HY01"],
    ),
    "HYSTERIA2-UDP": ("hysteria2_udp_base", False, ["C05", "HY06"]),
    "HYSTERIA2-TCP-SALAMANDER": ("hysteria2_tcp_base", True, ["HY02", "HY03"]),
    "HYSTERIA2-UDP-SALAMANDER": ("hysteria2_udp_base", True, ["HY02", "HY03", "HY06"]),
    "HYSTERIA2-SECURITY": (
        "native_security_matrix",
        False,
        ["T01", "T03", "T04", "T05", "T07", "T08", "HY01", "HY02", "HY03"],
    ),
    "HYSTERIA2-BANDWIDTH": ("native_bandwidth_matrix", False, ["HY04", "HY05"]),
    "HYSTERIA2-CLOSE": ("native_mihomo_close_alignment", False, []),
    "HYSTERIA2-CLOSE-SALAMANDER": (
        "native_mihomo_close_alignment",
        True,
        ["HY02", "HY03"],
    ),
    "HYSTERIA2-OWNED": ("native_owned_lifecycle", False, []),
    "HYSTERIA2-DEADLINE": ("native_deadline_and_udp_budget", False, ["HY06"]),
    "HYSTERIA2-LIFE": ("runtime::public_lifecycle", False, []),
    "HYSTERIA2-ENTRYPOINTS": ("runtime::public_entrypoints", False, ["C05"]),
    "HYSTERIA2-IPV6-GATES": ("runtime::public_ipv6_and_gates", False, ["C03", "C05"]),
    "HYSTERIA2-UDP-BOUNDARIES": ("hysteria2::public_udp_boundaries", False, ["HY06"]),
    "HYSTERIA2-UPSTREAM": ("hysteria2::public_concrete_upstream", False, ["C06"]),
    "HYSTERIA2-GRAPH": (
        "hysteria2::public_graph_and_hop_snapshot",
        False,
        ["C06", "HY07", "HY08"],
    ),
}
H = {
    "-".join(
        (
            "HYSTERIA2-HOP",
            "V6" if v6 else "V4",
            "OBFS" if obfs else "PLAIN",
            "RANDOM" if random else "FIXED",
        )
    ): dict(test="native_hopping", ipv6=v6, obfs=obfs, random_interval=random)
    for v6 in (False, True)
    for obfs in (False, True)
    for random in (False, True)
}
H.update(
    {
        "HYSTERIA2-UDP-DISABLED": dict(
            test="native_udp_disabled", ipv6=False, obfs=False, random_interval=False
        ),
        "HYSTERIA2-HOP-PROTECT": dict(
            test="native_hop_protect_rejection",
            ipv6=False,
            obfs=False,
            random_interval=False,
        ),
        "HYSTERIA2-HOP-STOP": dict(
            test="native_stop_during_hop", ipv6=True, obfs=True, random_interval=False
        ),
    }
)
GATES = {
    "HYSTERIA2-CFG",
    "HYSTERIA2-UNIT",
    "HYSTERIA2-RELEASE",
    "HYSTERIA2-REGRESSION",
    "HYSTERIA2-QUALITY",
    "HYSTERIA2-FEATURES",
    "HYSTERIA2-SCRIPTS",
    "HYSTERIA2-PLATFORMS",
}
H3 = "HYSTERIA2-H3-REGRESSION"


def expected_events(test):
    public = {
        "hysteria2_tcp_base": ("HYSTERIA2-BASE", "tcp_ipv4_ipv6_domain_and_measure"),
        "hysteria2_udp_base": ("HYSTERIA2-BASE", "udp_ipv4_ipv6_domain_fragmentation"),
        "hysteria2_client_first": ("HYSTERIA2-BASE", "client_first"),
    }
    if test in public:
        expected = {public[test]: 1}
        if test == "hysteria2_tcp_base":
            expected["HYSTERIA2-BASE", "tcp_10mib_both_directions"] = 3
        return expected
    if test.startswith("runtime::"):
        result = {("HYSTERIA2-PUBLIC", test): 1}
        if test == "runtime::public_lifecycle":
            result["HYSTERIA2-LIFE", "stop_and_remain_quiet"] = 20
        return result
    if test.startswith("hysteria2::"):
        return {("HYSTERIA2-PUBLIC", test.removeprefix("hysteria2::")): 1}
    if test == "native_security_matrix":
        return {
            ("HYSTERIA2-SECURITY", test): 1,
            **{("HYSTERIA2-SECURITY-CASE", name): 1 for name in SECURITY},
        }
    return {
        (
            {
                "native_bandwidth_matrix": "HYSTERIA2-BANDWIDTH",
                "native_owned_lifecycle": "HYSTERIA2-LIFE",
                "native_hopping": "HYSTERIA2-HOP",
                "native_udp_disabled": "HYSTERIA2-UDP-DISABLED",
                "native_hop_protect_rejection": "HYSTERIA2-HOP",
                "native_stop_during_hop": "HYSTERIA2-HOP",
                "native_deadline_and_udp_budget": "HYSTERIA2-NATIVE",
                "native_mihomo_close_alignment": "HYSTERIA2-NATIVE",
            }[test],
            test,
        ): 20 if test == "native_owned_lifecycle" else 1
    }


def assertions_pass(events, expected):
    if not events or any(
        e.get("schema_version") != 1 or e.get("status") not in {"BEGIN", "PASS"}
        for e in events
    ):
        return False
    actual = Counter((e.get("suite"), e.get("assertion")) for e in events)
    if actual != Counter({key: count * 2 for key, count in expected.items()}):
        return False
    for key, count in expected.items():
        selected = [e for e in events if (e.get("suite"), e.get("assertion")) == key]
        if [e["status"] for e in selected] != ["BEGIN", "PASS"] * count:
            return False
        for event in selected[1::2]:
            if event.get("resources") is not None and not idle_resources(
                event["resources"]
            ):
                return False
    return True


def events_pass(events, test):
    if not assertions_pass(events, expected_events(test)):
        return False
    passed = [e for e in events if e["status"] == "PASS"]
    if test in {
        "native_hopping",
        "native_hop_protect_rejection",
        "native_stop_during_hop",
        "native_owned_lifecycle",
        "native_deadline_and_udp_budget",
        "native_security_matrix",
    }:
        owned = [e for e in passed if e["assertion"] == test]
        if any(not idle_resources(e.get("resources")) for e in owned):
            return False
        if test == "native_owned_lifecycle" and any(
            [p["phase"] for p in e["checkpoints"]]
            != ["baseline", "after-stop", "quiet"]
            or any(not idle_resources(p.get("resources")) for p in e["checkpoints"])
            or e["seconds"] < 5
            for e in owned
        ):
            return False
    return True


def definitions():
    output = []
    for identifier in sorted(GATES | set(M) | set(H) | {H3}):
        kind, test, rows, options = "unit", identifier, [], {}
        if identifier in M:
            test, obfs, rows = M[identifier]
            kind, options = "M", dict(obfs=obfs)
        elif identifier in H:
            options = H[identifier]
            kind, test = "H", options["test"]
            rows = ["C04", "HY07", "HY08"] if test != "native_udp_disabled" else ["C05"]
        elif identifier == H3:
            kind, test = "XR", "shared-quic-h3-native-regression"
        elif identifier == "HYSTERIA2-CFG":
            rows = sorted(FIELDS)
        native = kind != "unit"
        substage = (
            "HYSTERIA2.hopping"
            if kind == "H" and test != "native_udp_disabled"
            else "HYSTERIA2.bandwidth"
            if identifier == "HYSTERIA2-BANDWIDTH"
            else "HYSTERIA2.udp"
            if "UDP" in identifier
            else "HYSTERIA2.tcp"
            if identifier in M
            else "HYSTERIA2.acceptance"
        )
        expected = (
            CFG
            if identifier == "HYSTERIA2-CFG"
            else UNIT
            if identifier == "HYSTERIA2-UNIT"
            else CFG + UNIT
            if identifier == "HYSTERIA2-RELEASE"
            else [test]
        )
        output.append(
            dict(
                case_id=identifier,
                stage="HYSTERIA2",
                substage=substage,
                required=True,
                row_ids=sorted(rows),
                protocol="hysteria2" if identifier != H3 else "vless",
                network="quic",
                security="tls13",
                udp_codec="hysteria2-datagram" if identifier != H3 else "vless",
                field_values=options,
                outer_family="IPv6"
                if options.get("ipv6")
                else "IPv4/IPv6"
                if identifier == "HYSTERIA2-IPV6-GATES"
                else "IPv4",
                inner_family="IPv4/IPv6/domain",
                target_type="isolated synthetic origin"
                if native
                else "memory-only/build",
                upstream_graph="direct/concrete/nested-select"
                if identifier in {"HYSTERIA2-GRAPH", "HYSTERIA2-UPSTREAM"}
                else "direct",
                peer_kind=kind,
                peer_config=dict(
                    test=test, **{k: v for k, v in options.items() if k != "test"}
                ),
                gap_source=dict(
                    reason=(
                        "Mihomo HY2 listener cannot redirect one QUIC state "
                        "across a port set or disable authenticated business "
                        "UDP; official Hysteria provides these gates"
                    ),
                    source="https://github.com/HyNetworks/hysteria/blob/e1366b173ccf5706e1e4630fe8aa654a4b574085/core/server/server.go",
                )
                if kind == "H"
                else dict(
                    reason=(
                        "XHTTP H3 shared-adapter regression uses the XHTTP "
                        "official Xray handler"
                    ),
                    source="https://github.com/XTLS/Xray-core",
                )
                if kind == "XR"
                else None,
                expected_observation=expected,
                required_evidence=["structured-assertions", "command", "cleanup"]
                + (["peer-identity", "isolated-origins"] if native else []),
                prerequisites=[
                    "owned-host-only-container-network",
                    "official-latest-peer",
                ]
                if native
                else ["rust-toolchain"],
                runner="native-hysteria2" if kind in {"M", "H"} else "hysteria2-gate",
                timeout_seconds=3600
                if identifier == "HYSTERIA2-PLATFORMS"
                else 900
                if identifier == H3
                else 1200
                if not native
                else 600
                if identifier == "HYSTERIA2-BANDWIDTH"
                else 300,
            )
        )
    return output
