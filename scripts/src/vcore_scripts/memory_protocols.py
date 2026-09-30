"""Memory profiles reuse the repository's official peer capability fixtures."""

import copy
import json
import shutil
import subprocess
import urllib.request
from pathlib import Path

from .memory_inputs import save
from .protocol_containers import command
from .protocol_fixtures import certificates

PROFILES = {
    "socks5": "SOCKS5 TCP/UDP",
    "ss-aes128": "SS2022 AES-128-GCM",
    "ss-aes256": "SS2022 AES-256-GCM",
    "ss-chacha": "SS2022 ChaCha20-Poly1305",
    "trojan-tls": "Trojan TLS; native Xray for domain UDP listener gap",
    "anytls": "AnyTLS TLS session pool",
    "vmess-ws-tls": "VMess WS+TLS/XUDP",
    "vless-tls": "VLESS TLS/default backend/XUDP",
    "vless-chrome": "VLESS TLS/Chrome/XUDP",
    "vless-reality-vision": "VLESS REALITY/Vision",
    "vless-grpc": "VLESS gRPC+TLS/XUDP",
    "vless-xhttp-h2": "VLESS XHTTP H2 packet-up/XUDP",
    "vless-xhttp-h3": "VLESS XHTTP H3 packet-up/XUDP; native Xray",
    "ss-uot": "SS2022 AES-128-GCM/UoT v2",
    "ss-shadowtls": "SS2022 AES-128-GCM/ShadowTLS strict v3; native UDP bypass",
    "ss-shadowtls-uot": "SS2022 AES-128-GCM/UoT v2 inside ShadowTLS strict v3",
    "hysteria2": "Hysteria2 TLS/QUIC",
    "tuic-native": "TUIC v5 native UDP",
    "tuic-quic": "TUIC v5 QUIC streams for UDP",
    "mixed-eight": "Eight active protocols; pinned flows across select changes",
    "two-hop": "TCP-only SOCKS5 upstream -> SS UoT v2 + ShadowTLS strict v3",
}
EIGHT = (
    "socks5",
    "ss-aes128",
    "trojan-tls",
    "anytls",
    "vmess-ws-tls",
    "vless-tls",
    "hysteria2",
    "tuic-native",
)


def components(profile):
    return EIGHT if profile == "mixed-eight" else (profile,)


def cases():
    rows = {}
    for profile in PROFILES:
        for entry in ("socks", "tun"):
            for family in ("v4", "v6"):
                prefix = f"profile-{entry}-{profile}-{family}"
                common = {
                    "profile": profile,
                    "family": "IPv6" if family == "v6" else "IPv4",
                    "entrypoint": "fd-TUN" if entry == "tun" else "SOCKS5",
                    "topology": "proxy",
                    "direction": "both",
                    "calibration_seconds": 5,
                    "warm_reuse": True,
                }
                rows[prefix + "-smoke"] = common | {
                    "transport": "mixed",
                    "correctness": True,
                    "flows": 32 if profile == "mixed-eight" else 4,
                    "seconds": 5,
                    "mbps": 0,
                    "witness_seconds": [],
                    "development": True,
                }
                for repeat in range(1, 4):
                    rows[prefix + f"-standard-{repeat}"] = common | {
                        "transport": "mixed",
                        "correctness": True,
                        "flows": 64,
                        "seconds": 300,
                        "mbps": 0,
                        "witness_seconds": list(range(35, 300, 35)),
                    }
                    for transport in ("tcp", "udp"):
                        for direction in ("up", "down", "both"):
                            rows[prefix + f"-{transport}-{direction}-1000-{repeat}"] = (
                                common
                                | {
                                    "transport": transport,
                                    "direction": direction,
                                    "flows": 16,
                                    "seconds": 300,
                                    "mbps": 1000,
                                    "witness_seconds": list(range(35, 300, 35)),
                                }
                            )
    return rows


def selected(manifest):
    return {
        row["profile"]
        for row in manifest.get("socks_load_workloads", {}).values()
        if row.get("profile")
    }


def prepare(root, manifest):
    profiles = selected(manifest)
    if not profiles:
        return
    if len(profiles) != 1:
        raise ValueError("freeze one protocol profile and DNS family per memory run")
    profile = profiles.pop()
    directory = root / "artifacts/peer-tls"
    directory.mkdir()
    # The full matrix can span days; all groups retain this exact pinned leaf.
    _, _, pin = certificates(directory, days=45)
    manifest["protocol_profile"] = {
        "name": profile,
        "description": PROFILES[profile],
        "pin": pin,
    }
    if set(components(profile)) & {"trojan-tls", "vless-xhttp-h3"}:
        from .native_release import download_native

        native = download_native(
            "XR", root / "artifacts/native", "linux-arm64", defer_version=True
        )
        manifest["native_peer"] = native.identity


def _node(profile, server, native, cover, directory, certificate, port):
    from .protocol_completion_peers import PeerCase
    from .protocol_completion_peers import peer_configuration as completion
    from .protocol_integration_native import peer_configuration as integration
    from .protocol_vless_peers import configuration as vless
    from .protocol_xhttp_peers import client_config
    from .protocol_xhttp_peers import peer_config as xhttp

    cert, key, pin = certificate
    guest_cert, guest_key = (
        Path("/data/fixture/cert.pem"),
        Path("/data/fixture/key.pem"),
    )
    native_config = None
    extra = []
    if profile.startswith("ss-") or profile == "two-hop":
        cipher = {
            "ss-aes256": "2022-blake3-aes-256-gcm",
            "ss-chacha": "2022-blake3-chacha20-poly1305",
        }.get(profile, "2022-blake3-aes-128-gcm")
        node, listener = completion(
            PeerCase(
                profile,
                "ss",
                cipher,
                shadow_tls="shadowtls" in profile or profile == "two-hop",
                uot="uot" in profile or profile == "two-hop",
            ),
            server=server,
            cover=f"{cover}:24001",
            port=port,
            certificate=certificate,
        )
        if profile == "two-hop":
            extra = [
                dict(name="front", type="socks5", server=server, port=1081, udp=False)
            ]
            node["dialer-proxy"] = "front"
    elif profile in {"vless-reality-vision", "vless-grpc"}:
        node, config = vless(
            "vision-reality" if profile.endswith("vision") else "grpc-tls",
            server,
            cover,
            guest_cert,
            guest_key,
        )
        listener = config["listeners"][0]
        if profile.endswith("vision"):
            node["client-fingerprint"] = "chrome"
        else:
            node["fingerprint"] = pin
            node["packet-encoding"] = "xudp"
    elif profile in {"vless-xhttp-h2", "vless-xhttp-h3"}:
        version = profile.rsplit("-", 1)[1]
        node = client_config(
            native if version == "h3" else server, pin, version, "packet-up"
        )["proxies"][0]
        config = xhttp(
            "XR" if version == "h3" else "M", str(guest_cert), str(guest_key)
        )
        if version == "h3":
            native_config, listener = config, None
        else:
            listener = config["listeners"][0]
    else:
        kind = (
            "vmess"
            if profile.startswith("vmess-")
            else "vless"
            if profile.startswith("vless-")
            else "tuic"
            if profile.startswith("tuic-")
            else "trojan"
            if profile.startswith("trojan-")
            else profile
        )
        node, config = integration(
            kind,
            native if kind == "trojan" else server,
            server,
            directory,
            certificate=certificate,
        )
        listener = config["listeners"][0]
        if kind == "trojan":
            from .protocol_fixtures import trojan_peer_config

            native_config = trojan_peer_config(
                "XR", "tcp", port, node["password"], guest_cert, guest_key
            )
            native_config["inbounds"][0]["listen"] = "::"
            listener = None
        elif profile == "vmess-ws-tls":
            listener["ws-path"] = "/memory-ws"
            node.update(
                network="ws",
                **{"ws-opts": {"path": "/memory-ws", "headers": {"Host": "localhost"}}},
            )
        elif profile == "vless-chrome":
            node["client-fingerprint"] = "chrome"
        elif kind == "tuic":
            node["udp-relay-mode"] = profile.removeprefix("tuic-")
    node.update(name=profile, port=port)
    if listener:
        listener.update(name=profile, port=port)
    if native_config:
        native_config["inbounds"][0]["port"] = port
    return extra + [node], listener, native_config


def install(
    root,
    manifest,
    lab,
    stack,
    directories,
    origin,
    bandwidth,
    cn_bandwidth,
    mihomo,
    positive,
    base_config,
):
    """Configure owned peers before release; no new server protocol code."""
    if not selected(manifest):
        return []
    profile = manifest["protocol_profile"]["name"]
    names = components(profile)
    family = next(iter(manifest["socks_load_workloads"].values()))["family"]

    def ip(peer):
        return peer.ipv6 if family == "IPv6" else peer.ipv4

    parent = directories["origin"].parent
    cert_dir = root / "artifacts/peer-tls"
    certificate = (
        cert_dir / "cert.pem",
        cert_dir / "key.pem",
        manifest["protocol_profile"]["pin"],
    )
    auxiliary = []
    cover = None
    if any(
        "shadowtls" in name or name in {"two-hop", "vless-reality-vision"}
        for name in names
    ):
        directory = parent / "cover"
        directory.mkdir()
        directories["cover"] = directory
        for name in ("cert.pem", "key.pem"):
            shutil.copy2(cert_dir / name, directory / name)
        for source, dest in (
            ("container_shadowtls_peer.py", "cover.py"),
            ("container_udp_origin.py", "origin.py"),
        ):
            shutil.copy2(Path(__file__).with_name(source), directory / dest)
        cover = lab.start(
            stack,
            directory,
            "memory-cover",
            [
                "env",
                "VCORE_ISOLATED_ORIGIN=1",
                "VCORE_ORIGIN_CERT=/data/fixture/cert.pem",
                "VCORE_ORIGIN_KEY=/data/fixture/key.pem",
                "python",
                "-B",
                "/data/fixture/cover.py",
            ],
        )
        cover.release()
        cover.wait_tcp(24001)
        auxiliary.append(cover)
    for role, peer in (("mihomo", mihomo), ("positive", positive)):
        if peer is None:
            continue
        directory = directories[role]
        for name in ("cert.pem", "key.pem"):
            shutil.copy2(cert_dir / name, directory / name)
        native = None
        if "native_peer" in manifest:
            native_dir = parent / (role + "-native")
            native_dir.mkdir()
            directories[role + "-native"] = native_dir
            for name in ("cert.pem", "key.pem"):
                shutil.copy2(cert_dir / name, native_dir / name)
            shutil.copy2(root / "artifacts/native/xray", native_dir / "peer")
            shutil.copy2(directory / "metrics.py", native_dir / "metrics.py")
            native = lab.start(
                stack,
                native_dir,
                "memory-" + role + "-native",
                ["/data/fixture/peer", "run", "-c", "/data/fixture/config.json"],
                cpus=8,
            )
            if (
                command("exec", native.name, "sha256sum", "/data/fixture/peer").split()[
                    0
                ]
                != manifest["native_peer"]["binary_sha256"]
            ):
                raise RuntimeError("memory native peer identity mismatch")
            native.record["version"] = command(
                "exec", native.name, "/data/fixture/peer", "version"
            ).strip()
            auxiliary.append(native)
            peer.memory_native = native
        config = copy.deepcopy(base_config)
        config.update(
            {
                "external-controller": "0.0.0.0:24005",
                "secret": "memory-peer-observation",
            }
        )
        config["proxies"] = []
        native_inbounds, nodes, members, sources = [], [], [], {}
        native_ports = []
        for index, name in enumerate(names):
            graph, listener, native_config = _node(
                name,
                ip(peer),
                ip(native) if native else None,
                cover.ipv4 if cover else origin.ipv4,
                directory,
                certificate,
                23000 + index,
            )
            nodes.extend(graph)
            members.append(name)
            sources[name] = ip(native) if native_config else ip(peer)
            if listener:
                config["listeners"].append(listener)
            if native_config:
                native_inbounds.extend(native_config["inbounds"])
                native_ports.append(23000 + index)
            calibration = copy.deepcopy(graph)
            renamed = {node["name"]: "calibration-" + node["name"] for node in graph}
            for node in calibration:
                node["name"] = renamed[node["name"]]
                if upstream := node.get("dialer-proxy"):
                    node["dialer-proxy"] = renamed[upstream]
            config["proxies"].extend(calibration)
            config["listeners"].append(
                dict(
                    name=f"calibration-{index}",
                    type="socks",
                    listen="::",
                    port=25000 + index,
                    udp=True,
                    proxy=renamed[name],
                )
            )
        if profile == "two-hop":
            config["listeners"] = [
                item for item in config["listeners"] if item["port"] != 1081
            ]
            config["listeners"].append(
                dict(
                    name="tcp-only-front",
                    type="socks",
                    listen="::",
                    port=1081,
                    udp=False,
                )
            )
            config["rules"][:0] = [
                f"IP-CIDR,{peer.ipv4}/32,DIRECT,no-resolve",
                f"IP-CIDR6,{peer.ipv6}/128,DIRECT,no-resolve",
            ]
        if native:
            allowed = [bandwidth, origin] + ([cn_bandwidth] if cn_bandwidth else [])
            native_config = {
                "log": {"loglevel": "warning"},
                "dns": {
                    "servers": [{"address": origin.ipv4, "port": 24004}],
                    "queryStrategy": "UseIPv6" if family == "IPv6" else "UseIPv4",
                },
                "inbounds": native_inbounds,
                "outbounds": [
                    {
                        "tag": "origin",
                        "protocol": "freedom",
                        "settings": {"domainStrategy": "UseIP"},
                    },
                    {"tag": "deny", "protocol": "blackhole"},
                ],
                "routing": {
                    "domainStrategy": "AsIs",
                    "rules": [
                        {
                            "type": "field",
                            "domain": [
                                "full:" + item["value"]
                                for item in manifest.get(
                                    "load_dns_names",
                                    manifest["geodata_reference"]["routes"],
                                )
                                if item["kind"] == "site"
                            ],
                            "outboundTag": "origin",
                        },
                        {
                            "type": "field",
                            "ip": [ip(p) for p in allowed],
                            "outboundTag": "origin",
                        },
                        {"type": "field", "network": "tcp,udp", "outboundTag": "deny"},
                    ],
                },
            }
            save(native.root / "config.json", native_config)
            native.release()
            # H3 listens only on UDP; the process identity + actual payload
            # establishes readiness. Never invent a TCP readiness success.
            if "trojan-tls" in names:
                native.wait_tcp(23000 + names.index("trojan-tls"))
        peer.record["memory_profile"] = dict(
            name=profile,
            nodes=nodes,
            members=members,
            sources=sources,
            native_ports=native_ports,
        )
        save(directory / "config.json", config)
        save(root / (role + "-profile.json"), peer.record["memory_profile"])
    return auxiliary


def source(peer):
    profile = peer.record.get("memory_profile")
    return profile["sources"][profile["members"][0]] if profile else None


def sources(peer, count):
    profile = peer.record.get("memory_profile")
    return (
        [
            profile["sources"][profile["members"][i % len(profile["members"])]]
            for i in range(count)
        ]
        if profile
        else None
    )


def reset_selection(config):
    """Witnesses use the first member; existing flows keep their chosen path."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for group in config["proxy-groups"]:
        request = urllib.request.Request(
            f"http://{config['external-controller']}/proxies/{group['name']}",
            data=json.dumps({"name": group["proxies"][0]}).encode(),
            method="PUT",
            headers={
                "Authorization": "Bearer " + config["secret"],
                "Content-Type": "application/json",
            },
        )
        with opener.open(request, timeout=5) as response:
            if response.status != 204:
                raise RuntimeError("memory route witness selection failed")


def snapshot(peers, pid):
    """Do not confuse logical tracker rows with unique observed transports."""
    captured = subprocess.run(
        ["lsof", "-nP", "-a", "-p", str(pid), "-i", "-F", "pfPtTn"],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    sockets = []
    for line in captured.stdout.splitlines():
        if line.startswith("p") and line[1:] != str(pid):
            raise RuntimeError("physical socket observation PID mismatch")
        if line.startswith("f"):
            sockets.append({"fd": line[1:]})
        elif sockets and line[:1] in {"P", "t", "T", "n"}:
            sockets[-1][line[0]] = line[1:]
    results = [
        {
            "pid": pid,
            "physical_inet_sockets": sockets,
            "tcp_established": sum(s.get("T") == "ST=ESTABLISHED" for s in sockets),
            "udp_sockets": sum(s.get("P") == "UDP" for s in sockets),
            "scope": "whole measured PID sockets including ingress/DNS; "
            "UDP sockets are not QUIC session counts",
        }
    ]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for peer in peers:
        from .memory_socks_load import host_source

        core_sources = {host_source(peer.ipv4), host_source(peer.ipv6)}
        request = urllib.request.Request(
            f"http://{peer.ipv4}:24005/connections",
            headers={"Authorization": "Bearer memory-peer-observation"},
        )
        with opener.open(request, timeout=5) as response:
            data = json.loads(response.read(1024 * 1024))
        logical = {}
        transports = {}
        for row in data.get("connections") or []:
            meta = row["metadata"]
            name = meta.get("inboundName", "")
            if (
                name not in peer.record["memory_profile"]["members"]
                or meta.get("sourceIP") not in core_sources
            ):
                continue
            logical[name] = logical.get(name, 0) + 1
            key = (
                meta.get("sourceIP"),
                meta.get("sourcePort"),
                meta.get("inboundPort"),
            )
            transports.setdefault(name, set()).add(key)
        results.append(
            {
                "peer": peer.name,
                "guest_kernel": json.loads(
                    command("exec", peer.name, "python", "/data/fixture/metrics.py")
                ),
                "logical_peer_trackers": logical,
                "observed_transport_tuples": {
                    name: len(values) for name, values in transports.items()
                },
                "scope": "active peer source tuples; not TLS handshake/resumption "
                "or QUIC connection-id counts",
            }
        )
        if native := getattr(peer, "memory_native", None):
            result = json.loads(
                command("exec", native.name, "python", "/data/fixture/metrics.py")
            )
            results.append(
                {
                    "peer": native.name,
                    "native_kernel": result,
                    "scope": "native guest transport counters; "
                    "no logical/TLS resumption inference",
                }
            )
    return results
