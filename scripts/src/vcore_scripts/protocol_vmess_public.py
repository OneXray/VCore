"""Required public-consumer cases, independent of the persisted manifest."""

from .protocol_evidence import idle_resources

CASES = {
    "VMESS-PUBLIC-UDP-FIRST": ("M", "tcp", False, "public_udp_first_response"),
    "VMESS-PUBLIC-BODY-OPTIONS": ("M", "tcp", False, "public_body_options"),
}
CASES["VMESS-PUBLIC-WS-ALPN"] = ("M", "ws-alpn", True, "public_alpn_rejection")
for mode in ("tcp", "ws", "grpc", "http", "h2"):
    kind = "V2" if mode in {"http", "h2"} else "M"
    for tls in (False, True):
        label = f"VMESS-PUBLIC-{mode.upper()}-{'TLS' if tls else 'PLAIN'}"
        for suffix, test in (
            ("BASE", "public_base"),
            ("NEG", "public_negative"),
            ("GRAPH", "runtime::public_graph"),
            ("IPV6", "runtime::public_ipv6_and_gates"),
            ("ENTRYPOINTS", "runtime::public_entrypoints"),
        ):
            CASES[label + "-" + suffix] = (kind, mode, tls, test)
for mode in ("tcp", "grpc"):
    for suffix, test in (
        ("LIFE", "runtime::public_lifecycle"),
        ("OWNED", "runtime::owned_resources"),
    ):
        CASES[f"VMESS-PUBLIC-{mode.upper()}-{suffix}"] = ("M", mode, True, test)
for mode in ("tcp", "ws", "grpc"):
    CASES[f"VMESS-REGRESSION-TROJAN-{mode.upper()}"] = (
        "M",
        "trojan-" + mode,
        True,
        "public_legacy_regression",
    )
    CASES[f"VMESS-PUBLIC-{mode.upper()}-UDP-ISOLATION"] = (
        "M",
        mode,
        True,
        "runtime::public_udp_isolation",
    )
for mode in ("ws-ed-1", "ws-ed-2048", "ws-header", "ws-path", "grpc-custom"):
    kind = "V2" if mode in {"ws-header", "ws-path"} else "M"
    CASES[f"VMESS-PUBLIC-{mode.upper()}"] = (kind, mode, True, "public_base")


def node_config(mode, tls, host, pin):
    if mode.startswith("trojan-"):
        node = node_config(mode.removeprefix("trojan-"), tls, host, pin)
        node.update(
            type="trojan",
            password="synthetic-regression-only",
            sni=node.pop("servername"),
        )
        for key in ("uuid", "tls"):
            node.pop(key)
        return node
    network = mode.split("-")[0]
    node = dict(
        name="peer",
        type="vmess",
        server=host,
        port=23000,
        uuid="07070707-0707-0707-0707-070707070707",
        udp=True,
        network=network,
        tls=tls,
    )
    if tls:
        node.update(servername="localhost", fingerprint=pin)
        node["alpn"] = ["h2" if network in {"grpc", "h2"} else "http/1.1"]
    if network == "ws":
        node["ws-opts"] = {
            "path": "/vmess-ws",
            "headers": {"Host": "localhost", "X-Fixture": "exact-value"},
        }
        if mode == "ws-alpn":
            node["alpn"] = ["h2", "http/1.1"]
        if mode.startswith("ws-ed"):
            node["ws-opts"]["max-early-data"] = int(mode.split("-")[-1])
        elif mode in {"ws-header", "ws-path"}:
            node["ws-opts"].update(
                {
                    "path": "/vmess-ws/",
                    "max-early-data": 2048,
                    "early-data-header-name": "X-Vcore-Ed"
                    if mode == "ws-header"
                    else "",
                }
            )
    elif network == "grpc":
        node["grpc-opts"] = {
            "grpc-service-name": "/vmess-grpc/Tun"
            if mode == "grpc-custom"
            else "vmess-grpc"
        }
    elif network == "http":
        node["http-opts"] = {
            "method": "POST",
            "path": ["/vmess-http"],
            "headers": {"Host": ["localhost"], "X-Fixture": ["exact-value"]},
        }
    elif network == "h2":
        node["h2-opts"] = {"host": ["localhost"], "path": "/vmess-h2"}
    return node


def pairs(events, suite, assertion, count):
    selected = [
        e for e in events if e.get("suite") == suite and e.get("assertion") == assertion
    ]
    return len(selected) == count * 2 and all(
        e.get("status") == ("BEGIN" if i % 2 == 0 else "PASS")
        for i, e in enumerate(selected)
    )


def events_pass(events, test):
    main = [event for event in events if event.get("suite") == "VMESS-PUBLIC"]
    if len(main) != 2 or not pairs(main, "VMESS-PUBLIC", test, 1):
        return False
    if any(
        event.get("schema_version") != 1 or event.get("status") not in {"BEGIN", "PASS"}
        for event in events
    ):
        return False
    if test == "public_base" and not (
        pairs(events, "VMESS-BASE", "tcp_10mib_both_directions", 3)
        and pairs(events, "VMESS-BASE", "udp_each_codec_and_family", 3)
    ):
        return False
    if test in {"runtime::public_lifecycle", "runtime::owned_resources"}:
        suite = "VMESS-LIFE" if test.endswith("public_lifecycle") else "VMESS-OWNED"
        if not pairs(events, suite, "stop_and_remain_quiet", 20):
            return False
        for end in [
            e for e in events if e.get("suite") == suite and e["status"] == "PASS"
        ]:
            if end.get("seconds", 0) < 5:
                return False
            if suite == "VMESS-OWNED":
                checkpoints = end.get("checkpoints", [])
                points = {p["phase"]: p["resources"] for p in checkpoints}
                if (
                    len(checkpoints) != 3
                    or set(points) != {"baseline", "after-stop", "quiet"}
                    or not all(idle_resources(p) for p in points.values())
                    or points["after-stop"] != points["quiet"]
                    or not idle_resources(end.get("resources"))
                ):
                    return False
    return test != "public_body_options" or pairs(
        events, "VMESS-BODY", "config_controls_aead_body", 14
    )
