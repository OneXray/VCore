"""VLESS isolated native fixtures. No host service or reference checkout is used."""

from pathlib import Path

MODES = [
    mode + suffix
    for mode in (
        "tcp",
        "ws",
        "ws-ed-1",
        "ws-ed-2048",
        "upgrade",
        "upgrade-fast",
        "grpc",
        "http",
        "h2",
        "ws-header",
        "ws-path",
    )
    for suffix in ("", "-tls")
] + [
    "xhttp-stream-one",
    "xhttp-stream-up",
    "xhttp-packet-up",
    "vision-tls",
    "vision-reality",
    "tcp-reality",
    "ws-reality",
    "grpc-reality",
    "upgrade-reality",
    "upgrade-fast-reality",
    "tcp-mtls",
    "ws-mtls",
    "grpc-mtls",
    "xhttp-stream-one-reality",
    "xhttp-stream-up-reality",
    "xhttp-packet-up-reality",
    "xhttp-stream-up-download",
    "xhttp-packet-up-download",
    "xhttp-stream-up-download-reality",
    "xhttp-packet-up-download-reality",
    "grpc-path-tls",
]


def peer_kind(mode):
    base = mode.removesuffix("-tls").removesuffix("-reality").removesuffix("-mtls")
    return "V2" if base in {"http", "h2", "ws-header", "ws-path"} else "M"


def configuration(mode, server, origin, cert: Path, key: Path):
    encrypted = mode.endswith(("-tls", "-reality", "-mtls")) or mode.startswith(
        ("xhttp-", "vision-")
    )
    base = mode.removesuffix("-tls").removesuffix("-reality").removesuffix("-mtls")
    separate_download = base.endswith("-download")
    base = base.removesuffix("-download")
    kind = peer_kind(mode)
    identity = "07070707-0707-0707-0707-070707070707"
    node = dict(
        name="edge", type="vless", server=server, port=23000, uuid=identity, udp=True
    )
    if encrypted:
        node.update(tls=True, servername="localhost")
    if base.startswith("xhttp-"):
        node.update(
            network="xhttp",
            **{
                "xhttp-opts": dict(
                    path="/vless", host="localhost", mode=base.removeprefix("xhttp-")
                )
            },
        )
        if separate_download:
            node["xhttp-opts"]["download-settings"] = {}
    elif base.startswith(("ws", "upgrade")):
        ws = dict(path="/vless-ws", headers={"Host": "localhost"})
        if base in {"ws-header", "ws-path"}:
            ws.update(
                path="/vless-ws/",
                **{
                    "max-early-data": 2048,
                    "early-data-header-name": "X-Vcore-Ed"
                    if base == "ws-header"
                    else "",
                },
            )
        elif base in {"ws-ed-1", "ws-ed-2048"}:
            ws["max-early-data"] = int(base.removeprefix("ws-ed-"))
        elif base.startswith("upgrade"):
            ws.update(
                **{
                    "v2ray-http-upgrade": True,
                    "v2ray-http-upgrade-fast-open": base == "upgrade-fast",
                    "max-early-data": 1,
                }
            )
        node.update(network="ws", **{"ws-opts": ws})
    elif base in {"grpc", "grpc-path"}:
        node.update(
            network="grpc",
            **{
                "grpc-opts": dict(
                    **{
                        "grpc-service-name": "/vless-grpc/Tun"
                        if base == "grpc-path"
                        else "vless-grpc",
                        "grpc-user-agent": "VCore-VLESS",
                        "ping-interval": 1,
                    }
                )
            },
        )
    elif base == "http":
        node.update(
            network="http",
            **{
                "http-opts": dict(
                    method="POST", path=["/vless-http"], headers={"Host": ["localhost"]}
                )
            },
        )
    elif base == "h2":
        node.update(
            network="h2", **{"h2-opts": dict(host=["localhost"], path="/vless-h2")}
        )
    if kind == "M":
        listener = dict(
            name="vless",
            type="vless",
            listen="::",
            port=23000,
            users=[dict(username="fixture", uuid=identity)],
        )
        if mode.startswith("vision-"):
            listener["users"][0]["flow"] = "xtls-rprx-vision"
            node["flow"] = "xtls-rprx-vision"
        if encrypted:
            listener.update(certificate=str(cert), **{"private-key": str(key)})
        else:
            listener["allow-insecure"] = True
        if mode.endswith("-reality"):
            from .mihomo_extended import PRIVATE_KEY, PUBLIC_KEY, SHORT_ID

            listener.pop("certificate", None)
            listener.pop("private-key", None)
            listener["reality-config"] = {
                "dest": f"{origin}:24001",
                "private-key": PRIVATE_KEY,
                "short-id": [SHORT_ID],
                "server-names": ["localhost"],
            }
            node["reality-opts"] = {"public-key": PUBLIC_KEY, "short-id": SHORT_ID}
        if node.get("network") == "ws":
            listener["ws-path"] = "/vless-ws"
        if base in {"grpc", "grpc-path"}:
            listener["grpc-service-name"] = "vless-grpc"
        if base == "ws-alpn":
            node["alpn"] = ["h2", "http/1.1"]
            listener["grpc-service-name"] = "vless-alpn"
        if base.startswith("xhttp-"):
            listener["xhttp-config"] = dict(path="/vless", mode="auto")
        listeners = [listener]
        if mode.startswith("vision-"):
            # Mihomo permits an explicit empty flow even for a Vision user.
            # Rejection requires a Vision request against an ordinary user.
            listeners.append(
                dict(
                    listener,
                    name="vless-flow-rejection",
                    port=23004,
                    users=[dict(user, flow="") for user in listener["users"]],
                )
            )
        return node, dict(
            ipv6=True,
            mode="rule",
            **{"log-level": "silent"},
            hosts={"vcore-fixture.test": origin},
            listeners=listeners,
            rules=["MATCH,DIRECT"],
        )
    stream = dict(network="tcp", security="tls" if encrypted else "none")
    if base == "http":
        stream["tcpSettings"] = dict(
            header=dict(type="http", request=dict(path=["/vless-http"]))
        )
    elif base == "h2":
        stream.update(
            network="http", httpSettings=dict(host=["localhost"], path="/vless-h2")
        )
    else:
        stream.update(
            network="ws",
            wsSettings=dict(
                path="/vless-ws/",
                maxEarlyData=2048,
                earlyDataHeaderName="X-Vcore-Ed" if base == "ws-header" else "",
            ),
        )
    if encrypted:
        stream["tlsSettings"] = dict(
            alpn=["h2"] if base == "h2" else ["http/1.1"],
            certificates=[dict(certificateFile=str(cert), keyFile=str(key))],
        )
    return node, dict(
        log={"loglevel": "none"},
        dns={"hosts": {"vcore-fixture.test": origin}},
        inbounds=[
            dict(
                listen="::",
                port=23000,
                protocol="vless",
                settings=dict(clients=[dict(id=identity)], decryption="none"),
                streamSettings=stream,
            )
        ],
        outbounds=[dict(protocol="freedom", settings={"domainStrategy": "UseIP"})],
    )
