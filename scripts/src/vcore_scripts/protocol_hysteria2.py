"""N6 incremental native gates; all servers/origins stay in owned containers."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import os
import shutil
import ssl
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_release import download_mihomo
from .protocol_containers import ContainerLab, command
from .protocol_evidence import read_events
from .protocol_hysteria2_catalog import events_pass
from .protocol_inputs import redact, source_identity
from .protocol_peers import run_command
from .protocol_streams import certificates
from .protocol_trojan import certificate_chain
from .protocol_vless_security import client_identities


def security_cases(base, identities, leaf_pin):
    cases = []

    def case(name, changes=None, *, absent=(), success=True):
        node = copy.deepcopy(base)
        node.update(changes or {})
        for field in absent:
            node.pop(field, None)
        cases.append(dict(id=name, node=node, success=success))

    case("root-pin")
    case("leaf-pin", {"fingerprint": leaf_pin})
    case("root-pin-wrong-name", {"sni": "wrong.fixture.test"}, success=False)
    case("leaf-pin-is-trust", {"fingerprint": leaf_pin, "sni": "wrong.fixture.test"})
    case("unknown-ca", absent=("fingerprint",), success=False)
    case("explicit-skip", {"skip-cert-verify": True}, absent=("fingerprint",))
    case("wrong-pin", {"fingerprint": "00" * 32}, success=False)
    case(
        "skip-does-not-override-pin",
        {"fingerprint": "00" * 32, "skip-cert-verify": True},
        success=False,
    )
    case("wrong-password", {"password": "not-the-password"}, success=False)
    case("empty-password", {"port": 23005}, absent=("password",))
    case("raw-password", {"port": 23006, "password": "  untrimmed credential  "})
    case("empty-alpn-default", {"alpn": []})
    case("custom-alpn", {"port": 23007, "alpn": ["h3-fixture"]})
    case("wrong-alpn", {"alpn": ["wrong-fixture"]}, success=False)
    case("mtls-valid", {"port": 23008, **identities["valid"]})
    case("mtls-absent", {"port": 23008}, success=False)
    for identity in ("expired", "wrong-ca"):
        case("mtls-" + identity, {"port": 23008, **identities[identity]}, success=False)
    obfs = {"obfs": "salamander", "obfs-password": "independent-obfs-fixture"}
    case("salamander", {"port": 23009, **obfs})
    case("salamander-client-only", obfs, success=False)
    case("salamander-server-only", {"port": 23009}, success=False)
    case(
        "salamander-wrong-key",
        {"port": 23009, **obfs, "obfs-password": "wrong-obfs-key"},
        success=False,
    )
    case(
        "salamander-wrong-auth",
        {"port": 23009, **obfs, "password": "wrong-auth"},
        success=False,
    )
    return cases


def run(output: Path, test="hysteria2_tcp_base", *, obfs=False, supplied=None):
    if test not in {
        "hysteria2_tcp_base",
        "hysteria2_client_first",
        "hysteria2_udp_base",
        "native_bandwidth_matrix",
        "native_mihomo_close_alignment",
        "native_security_matrix",
        "native_owned_lifecycle",
        "native_deadline_and_udp_budget",
        "runtime::public_lifecycle",
        "runtime::public_ipv6_and_gates",
        "runtime::public_entrypoints",
        "hysteria2::public_udp_boundaries",
        "hysteria2::public_concrete_upstream",
        "hysteria2::public_graph_and_hop_snapshot",
    }:
        raise ValueError("unknown N6 test")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = dict(
        stage="N6",
        scope="incremental-native",
        source=source_identity(),
        status="NOT RUN",
        isolation={},
        peers={},
        cases=[],
        obfs=obfs,
    )
    try:
        if supplied is None:
            identity = {}
            binary = download_mihomo(
                "linux-arm64", directory=output / "binaries", identity=identity
            )
        else:
            binary, identity = supplied
            if (
                hashlib.sha256(binary.read_bytes()).hexdigest()
                != identity["binary_sha256"]
            ):
                raise RuntimeError("supplied native peer identity mismatch")
        report["peers"]["M"] = identity
        lab = ContainerLab(report["isolation"], mtu=1500)
        with tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary:
            root = Path(temporary)
            origin_dir, server_dir = root / "origin", root / "server"
            origin_dir.mkdir()
            server_dir.mkdir()
            shutil.copyfile(
                Path(__file__).with_name("container_udp_origin.py"),
                origin_dir / "origin.py",
            )
            shutil.copyfile(
                Path(__file__).with_name("container_close_client.py"),
                origin_dir / "close.py",
            )
            shutil.copy2(binary, server_dir / "peer")
            cert, key, pin = (
                certificate_chain if test == "native_security_matrix" else certificates
            )(server_dir)
            with contextlib.ExitStack() as stack:
                origin = lab.start(
                    stack,
                    origin_dir,
                    "n6-origin",
                    [
                        "env",
                        "VCORE_ISOLATED_ORIGIN=1",
                        "python",
                        "-B",
                        "/data/fixture/origin.py",
                    ],
                )
                server = lab.start(
                    stack,
                    server_dir,
                    "n6-mihomo",
                    [
                        "/data/fixture/peer",
                        "-d",
                        "/data",
                        "-f",
                        "/data/fixture/config.json",
                    ],
                )
                identity["version"] = command(
                    "exec", server.name, "/data/fixture/peer", "-v"
                ).strip()
                digest = command(
                    "exec", server.name, "sha256sum", "/data/fixture/peer"
                ).split()[0]
                if digest != identity["binary_sha256"]:
                    raise RuntimeError("native peer identity mismatch")
                upstream = server
                if test in {
                    "hysteria2::public_concrete_upstream",
                    "hysteria2::public_graph_and_hop_snapshot",
                }:
                    # A separate native instance prevents its own outer UDP
                    # source tuple from tripping Mihomo's loopback detector.
                    hop_dir = root / "hop"
                    hop_dir.mkdir()
                    shutil.copy2(binary, hop_dir / "peer")
                    (hop_dir / "config.json").write_text(
                        json.dumps(
                            {
                                "socks-port": 23001,
                                "allow-lan": True,
                                "bind-address": "*",
                                "ipv6": True,
                                "log-level": "silent",
                                "rules": ["MATCH,DIRECT"],
                            }
                        )
                    )
                    upstream = lab.start(
                        stack,
                        hop_dir,
                        "n6-hop",
                        [
                            "/data/fixture/peer",
                            "-d",
                            "/data",
                            "-f",
                            "/data/fixture/config.json",
                        ],
                    )
                    upstream.release()
                    upstream.wait_tcp(23001)
                password = "synthetic-hysteria2-fixture"
                (server_dir / "config.json").write_text(
                    json.dumps(
                        {
                            "socks-port": 23001,
                            "allow-lan": True,
                            "bind-address": "*",
                            "ipv6": True,
                            "log-level": "silent",
                            "hosts": {"vcore-fixture.test": origin.ipv4},
                            "listeners": [
                                {
                                    "name": "n6",
                                    "type": "hysteria2",
                                    "listen": "::",
                                    "port": 23000,
                                    "users": {"fixture": password},
                                    "certificate": f"/data/fixture/{cert.name}",
                                    "private-key": f"/data/fixture/{key.name}",
                                }
                            ],
                            "rules": ["MATCH,DIRECT"],
                        }
                    )
                )
                fixture = root / "input.json"
                bandwidth_peer = None
                if test == "native_bandwidth_matrix":
                    bandwidth_dir = root / "bandwidth"
                    bandwidth_dir.mkdir()
                    shutil.copyfile(
                        Path(__file__).with_name("container_bandwidth_origin.py"),
                        bandwidth_dir / "origin.py",
                    )
                    bandwidth_peer = lab.start(
                        stack,
                        bandwidth_dir,
                        "n6-bandwidth",
                        [
                            "env",
                            "VCORE_ISOLATED_ORIGIN=1",
                            "python",
                            "-B",
                            "/data/fixture/origin.py",
                        ],
                    )
                    bandwidth_peer.release()
                    bandwidth_peer.wait_tcp(24002)
                    peer_config = json.loads((server_dir / "config.json").read_text())
                    baseline = peer_config["listeners"][0]
                    for port, options in [
                        (23002, {"down": "1 Mbps"}),
                        (23003, {"up": "1 Mbps"}),
                        (23004, {"ignore-client-bandwidth": True}),
                    ]:
                        peer_config["listeners"].append(
                            dict(baseline, name=f"n6-{port}", port=port, **options)
                        )
                    (server_dir / "config.json").write_text(json.dumps(peer_config))
                fixture.write_text(
                    json.dumps(
                        dict(
                            isolation="containers",
                            origin_control=f"{origin.ipv4}:24000",
                            origin_ipv4=origin.ipv4,
                            origin_ipv6=origin.ipv6,
                            server_ipv6=server.ipv6,
                            data_dir=str(root / "data"),
                            hop=dict(
                                name="hop",
                                type="socks5",
                                server=upstream.ipv4,
                                port=23001,
                                udp=True,
                            ),
                            bandwidth_control=f"{bandwidth_peer.ipv4}:24002"
                            if bandwidth_peer
                            else None,
                            bandwidth_ipv4=bandwidth_peer.ipv4
                            if bandwidth_peer
                            else None,
                            node=dict(
                                name="peer",
                                type="hysteria2",
                                server=server.ipv4,
                                port=23000,
                                password=password,
                                udp=True,
                                sni="localhost",
                                fingerprint=pin,
                                alpn=["h3"],
                            ),
                        )
                    )
                )
                if test == "native_security_matrix":
                    identities = client_identities(server_dir)
                    peer_config = json.loads((server_dir / "config.json").read_text())
                    baseline = peer_config["listeners"][0]
                    for port, options in [
                        (23005, {"users": {"fixture": ""}}),
                        (23006, {"users": {"fixture": "  untrimmed credential  "}}),
                        (23007, {"alpn": ["h3-fixture"]}),
                        (
                            23008,
                            {
                                "client-auth-type": "require-and-verify",
                                "client-auth-cert": "/data/fixture/root.pem",
                            },
                        ),
                        (
                            23009,
                            {
                                "obfs": "salamander",
                                "obfs-password": "independent-obfs-fixture",
                            },
                        ),
                    ]:
                        peer_config["listeners"].append(
                            dict(baseline, name=f"n6-{port}", port=port, **options)
                        )
                    (server_dir / "config.json").write_text(json.dumps(peer_config))
                    value = json.loads(fixture.read_text())
                    leaf = (
                        cert.read_text().split("-----END CERTIFICATE-----", 1)[0]
                        + "-----END CERTIFICATE-----\n"
                    )
                    leaf_pin = hashlib.sha256(
                        ssl.PEM_cert_to_DER_cert(leaf)
                    ).hexdigest()
                    value["security"] = security_cases(
                        value["node"], identities, leaf_pin
                    )
                    value["invalid_identities"] = [
                        {
                            "certificate": identities["valid"]["certificate"],
                            "private-key": identities["expired"]["private-key"],
                        },
                        {
                            "certificate": "bad PEM",
                            "private-key": identities["valid"]["private-key"],
                        },
                    ]
                    fixture.write_text(json.dumps(value))
                if obfs:
                    peer_config = json.loads((server_dir / "config.json").read_text())
                    for listener in peer_config["listeners"]:
                        listener.update(
                            obfs="salamander",
                            **{"obfs-password": "independent-obfs-fixture"},
                        )
                    (server_dir / "config.json").write_text(json.dumps(peer_config))
                    value = json.loads(fixture.read_text())
                    value["node"].update(
                        obfs="salamander",
                        **{"obfs-password": "independent-obfs-fixture"},
                    )
                    fixture.write_text(json.dumps(value))
                origin.release()
                server.release()
                origin.wait_tcp(24000)
                server.wait_tcp(23001)
                if test == "native_mihomo_close_alignment":
                    from .protocol_xhttp_fields import close_reference

                    value = json.loads(fixture.read_text())
                    value["close_reference"] = close_reference(
                        lab, stack, root, "hy2", value["node"], origin, binary, output
                    )
                    fixture.write_text(json.dumps(value))
                events = output / f"{test}-events.jsonl"
                result = run_command(
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--all-features",
                        "--test",
                        "hysteria2_native"
                        if test.startswith("native_")
                        else "vless_public",
                        test,
                        "--",
                        "--ignored",
                        "--exact",
                        "--nocapture",
                    ],
                    cwd=CORE_DIR,
                    timeout=600 if test == "native_bandwidth_matrix" else 240,
                    limit=4 * 1024 * 1024,
                    env=dict(
                        os.environ,
                        VCORE_VLESS_INPUT=str(fixture),
                        VCORE_CASE_EVENTS=str(events),
                        VCORE_PROTOCOL_STAGE="N6",
                        VCORE_BANDWIDTH_OBSERVATIONS=str(output / "bandwidth.jsonl"),
                    ),
                )
                (output / f"{test}.log").write_text(
                    redact(result.stdout.decode(errors="replace"))
                )
                observed = read_events(events) if events.exists() else []
                passed = (
                    result.returncode == 0
                    and result.cleanup
                    and events_pass(observed, test)
                )
                report["cases"].append(
                    dict(
                        case_id=test,
                        status="PASS" if passed else "FAIL",
                        exit_code=result.returncode,
                        seconds=result.seconds,
                        command_cleanup=result.cleanup,
                        command=test_command(test),
                    )
                )
                report["status"] = "PASS" if passed else "FAIL"
                for role, peer in (("origin", origin), ("server", server)):
                    peer.ensure_alive()
                    if peer.log.exists():
                        (output / f"{role}.log").write_text(
                            redact(peer.log.read_text(errors="replace")[-65536:])
                        )
    except (OSError, RuntimeError, ValueError) as error:
        report.update(
            status="FAIL",
            reason=str(error)
            if isinstance(error, RuntimeError)
            else type(error).__name__,
        )
    finally:
        report["cleanup"] = all(
            peer["joined"] for peer in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        if not report["source_unchanged"] or not report["cleanup"]:
            report["status"] = "FAIL"
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def test_command(test):
    return [
        "cargo",
        "test",
        "--locked",
        "--all-features",
        "--test",
        "hysteria2_native" if test.startswith("native_") else "vless_public",
        test,
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
    ]


if __name__ == "__main__":
    import sys

    result = run(
        Path(sys.argv[1]),
        sys.argv[2] if len(sys.argv) > 2 else "hysteria2_tcp_base",
        obfs="--salamander" in sys.argv[3:],
    )
    print(json.dumps({key: result[key] for key in ("status", "cleanup", "cases")}))
    raise SystemExit(0 if result["status"] == "PASS" and result["cleanup"] else 1)
