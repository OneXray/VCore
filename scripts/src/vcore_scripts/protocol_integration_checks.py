"""Raw runtime observations and native isolation, independent of run status."""

from __future__ import annotations

from .protocol_evidence import HEX, idle_resources, read_events, read_json
from .protocol_hysteria2_catalog import assertions_pass
from .protocol_integration_catalog import PROTOCOLS
from .protocol_integration_metrics import lifetimes, rebuild, soak
from .protocol_integration_native import rust_command
from .protocol_integration_suite import CONSUMERS


def envelope(report, peers, source, digest, *, single=None):
    isolation = report.get("isolation", {})
    identities = {single: report.get("peer", {})} if single else report.get("peers", {})
    owned = isolation.get("peers", [])
    urls = {
        "M": "MetaCubeX/mihomo",
        "XR": "XTLS/Xray-core",
        "V2": "v2fly/v2ray-core",
        "SS": "shadowsocks/shadowsocks-rust",
        "H": "HyNetworks/hysteria",
    }
    return bool(
        report.get("status") == "PASS"
        and report.get("cleanup") is True
        and report.get("source_unchanged") is True
        and report.get("source") == source
        and isolation.get("network_mode") == "hostOnly"
        and isolation.get("host_servers") is False
        and isolation.get("guest_mtu") == 1500
        and isolation.get("image_digest") == digest
        and digest.startswith("sha256:")
        and HEX.fullmatch(digest[7:])
        and owned
        and all(p.get("started") is True and p.get("joined") is True for p in owned)
        and identities
        and all(
            kind in urls
            and identity == peers.get(kind)
            and identity.get("version")
            and HEX.fullmatch(identity.get("binary_sha256", ""))
            and (kind == "H" or HEX.fullmatch(identity.get("archive_sha256", "")))
            and identity.get("source_url", "").startswith(
                f"https://github.com/{urls[kind]}/releases/"
            )
            for kind, identity in identities.items()
        )
    )


def runtime_pass(identifier, record, directory):
    if not (
        record.get("case_id") == identifier
        and record.get("command") == rust_command(CONSUMERS[identifier])
        and type(record.get("exit_code")) is int
        and record["exit_code"] == 0
        and record.get("command_cleanup") is True
    ):
        return False
    value = read_json(directory / (identifier + "-observations.json"))
    events = read_events(directory / (identifier + "-events.jsonl"))
    protocols = list(PROTOCOLS)
    expected = {(identifier, p): 1 for p in protocols}
    if identifier == "INTEGRATION-ENTRYPOINTS":
        good = value == dict(
            entrypoints=[
                dict(
                    protocol=p,
                    http_forward=True,
                    http_connect=True,
                    tun_tcp=True,
                    tun_udp=True,
                    tun_dns=True,
                )
                for p in protocols
            ]
        )
    elif identifier == "INTEGRATION-GRAPH":
        good = value == dict(
            protocols=protocols,
            nested_select=True,
            old_transport_snapshot=True,
            cold_reject=True,
            direct=True,
            unselected_cycle=True,
            no_fallback=True,
        )
    elif identifier == "INTEGRATION-DNS-MEASURE":
        good = value == dict(
            protocols=protocols,
            controlled_dns_via_proxy=True,
            ip_rule_consumer=True,
            node_measure=True,
            group_measure_rejected=True,
        )
    elif identifier == "INTEGRATION-FAILURES":
        expected = {
            (suite, p): 1
            for suite in (
                identifier,
                "INTEGRATION-FAILURES-AUTH",
                "INTEGRATION-FAILURES-SOURCE",
            )
            for p in protocols
        }
        good = value == dict(
            protect_rejected=protocols,
            auth_rejected=protocols,
            certificate_pin_rejected=[
                "anytls",
                "trojan",
                "vmess",
                "vless",
                "hysteria2",
            ],
            source_and_oversize_isolated=protocols,
            cancel_preserves_sibling=protocols,
            no_origin_bytes=True,
            stop_idle=True,
        )
        good &= all(
            idle_resources(e.get("resources"))
            for e in events
            if e.get("status") == "PASS"
            and e.get("suite") != "INTEGRATION-FAILURES-AUTH"
        )
    elif identifier in {"INTEGRATION-SS-ALGORITHMS", "INTEGRATION-SS-EIH"}:
        eih = identifier == "INTEGRATION-SS-EIH"
        ciphers = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"] + (
            [] if eih else ["2022-blake3-chacha20-poly1305"]
        )
        expected = {(identifier, c): 1 for c in ciphers} | {
            ("INTEGRATION-BASE", "tcp_10mib_both_directions"): 8 if eih else 9
        }
        good = value == (
            dict(
                native_terminal_eih=[
                    dict(
                        cipher=c,
                        identity_depth=1,
                        outer_families=2,
                        tcp_targets=2,
                        tcp_bytes_each_direction=41943040,
                        udp_targets=2,
                        udp_packets=2000,
                        wrong_identity_rejected=True,
                        wrong_user_rejected=True,
                    )
                    for c in ciphers
                ],
                arbitrary_relay_claim=False,
            )
            if eih
            else dict(
                algorithms=[
                    dict(
                        cipher=c,
                        tcp_targets=3,
                        tcp_bytes_each_direction=31457280,
                        udp_targets=3,
                        udp_packets=1500,
                        wrong_key_rejected=True,
                    )
                    for c in ciphers
                ]
            )
        )
    elif identifier == "INTEGRATION-LIFECYCLE":
        expected = {(identifier, "stop_and_remain_quiet"): 100}
        good = lifetimes(value, events)
    else:
        name = (
            "forty_flows_same_session"
            if identifier == "INTEGRATION-REBUILD"
            else "mixed_forty_flows"
        )
        expected = {(identifier, name): 1}
        passes = [e for e in events if e.get("status") == "PASS"]
        good = len(passes) == 1 and (
            rebuild(value, passes[0])
            if identifier == "INTEGRATION-REBUILD"
            else soak(
                value,
                passes[0],
                read_events(directory / (identifier + "-observations.json.jsonl")),
            )
        )
    return bool(good and assertions_pass(events, expected))
