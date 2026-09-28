"""Mixed-load profiles built from the implemented protocol peer fixtures."""

from .protocol_completion_peers import CASES, peer_configuration

TCP_GROUPS = ("socks5", "ss-v3", "tuic", "httpupgrade")
UDP_GROUPS = ("ss-uot", "ss-uot-v3", "tuic", "httpupgrade")
LIFETIME_GROUPS = (
    "socks5",
    "anytls",
    "ss",
    "trojan",
    "vmess",
    "vless",
    "hysteria2",
    "tuic",
    "ss-v3",
    "ss-uot",
    "ss-uot-v3",
    "httpupgrade",
)


def group(case):
    if case.protocol == "ss":
        return (
            "ss-uot-v3"
            if case.uot and case.shadow_tls
            else "ss-uot"
            if case.uot
            else "ss-v3"
        )
    return "tuic" if case.protocol == "tuic" else "httpupgrade"


PROFILE_IDS = {
    name: [c.identifier for c in CASES if c.protocol != "socks5" and group(c) == name]
    for name in ("ss-v3", "ss-uot", "ss-uot-v3", "tuic", "httpupgrade")
}


def configuration(server, cover, certificate):
    nodes, listeners = {}, []
    for i, case in enumerate(c for c in CASES if c.protocol != "socks5"):
        node, listener = peer_configuration(
            case, server=server, cover=cover, port=23100 + i, certificate=certificate
        )
        node["name"] = "peer"
        nodes[case.identifier] = node
        listeners.append(listener)
    return nodes, listeners


def selected(group_name, generation, slot=0):
    options = PROFILE_IDS.get(group_name, [group_name])
    return options[(generation + slot) % len(options)]


def expected_flows(generation):
    return {
        kind: [
            selected(group_name, generation, slot)
            for group_name in groups
            for slot in range(5)
        ]
        for kind, groups in (("tcp", TCP_GROUPS), ("udp", UDP_GROUPS))
    }
