"""N0-D: one official Hysteria state, two protected UDP sockets/entry ports."""

import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid

from run import CORE, SPIKE, PAYLOAD_BYTES, certificates, download_hysteria, origin
from vcore_scripts.mihomo_container import IMAGE, NETWORK, ContainerPeer, command
from vcore_scripts.mihomo_isolation import exclusive_run

FIRST, SECOND = 18444, 18445


def save(path, report):
    path.write_text(json.dumps(report, indent=2) + "\n")


def guest(peer, *arguments, timeout=30):
    # This Container CLI can exit 0 when its guest command failed. Check an
    # explicit guest status as well; never accept missing packages/rules silently.
    output = command(
        "exec",
        peer.name,
        "/bin/sh",
        "-c",
        '"$@" 2>&1\nn0_code=$?\nprintf "\\nVCORE_N0_STATUS=%s\\n" "$n0_code"',
        "n0",
        *arguments,
        timeout=timeout,
    )
    body, marker, status = output.rpartition("\nVCORE_N0_STATUS=")
    if not marker or status.strip() != "0":
        raise RuntimeError(f"guest {arguments[0]} failed: {body[-2048:]}")
    return body


def create_vm(stack, name, directory, *, prepare=False):
    owned = ContainerPeer(name)
    stack.callback(owned.stop)  # Even a timed-out launch can have created a VM.
    arguments = [
        "run",
        "--detach",
        "--name",
        name,
        "--label",
        f"purpose={NETWORK}",
        "--arch",
        "arm64",
        "--cpus",
        "1",
        "--memory",
        "256M",
        "--network",
        "default" if prepare else NETWORK,
    ]
    if not prepare:
        arguments += ["--cap-add", "CAP_NET_ADMIN", "--no-dns"]
    arguments += [
        "--mount",
        f"type=bind,source={directory},target=/fixture"
        + ("" if prepare else ",readonly"),
        "--entrypoint",
        "/bin/sleep",
        IMAGE,
        "300",
    ]
    command(*arguments, timeout=45)
    return owned


def observe_rules(address):
    # Separate pre-DNAT filter counters, never edit Hysteria's native NAT table.
    return f"""table ip vcore_n0_observe {{
      set first_sources {{ type inet_service; flags dynamic; size 8; }}
      set second_sources {{ type inet_service; flags dynamic; size 8; }}
      chain ingress {{ type filter hook prerouting priority -150; policy accept;
        ip daddr {address} udp dport {FIRST} update @first_sources {{ udp sport }} counter comment "first";
        ip daddr {address} udp dport {SECOND} update @second_sources {{ udp sport }} counter comment "second";
      }}
    }}
    """


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reject-hop",
        action="store_true",
        help="reject protection of the new hop socket, without unprotected fallback",
    )
    args = parser.parse_args()
    artifact = CORE / "target/interop/n0-hysteria-hop"
    artifact.mkdir(parents=True, exist_ok=True)
    run_id = (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    )
    output = artifact / run_id
    output.mkdir()
    report_path = output / "result.json"
    report = {
        "status": "incomplete",
        "run_id": run_id,
        "cases": [],
        "reject_hop": args.reject_hop,
        "image": IMAGE,
        "vcore_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=CORE, text=True
        ).strip(),
        "lock_sha256": hashlib.sha256((CORE / "Cargo.lock").read_bytes()).hexdigest(),
        "inputs": {
            str(path.relative_to(SPIKE)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [
                SPIKE / "Cargo.toml",
                SPIKE / "Cargo.lock",
                *sorted((SPIKE / "src").glob("*.rs")),
                SPIKE / "run.py",
                Path(__file__),
            ]
        },
    }
    save(report_path, report)
    try:
        network = json.loads(command("network", "inspect", NETWORK))[0]
        assert network["configuration"]["mode"] == "hostOnly"
        assert network["configuration"]["labels"].get("purpose") == NETWORK
        command("image", "inspect", IMAGE)
        report["container_version"] = command("--version").strip()
        executable = (
            CORE / "target/interop/n0-hysteria2-build/debug/vcore-n0-hysteria2-spike"
        )
        if not executable.is_file():
            raise RuntimeError("build the N0 probe first")
        report["probe_sha256"] = hashlib.sha256(executable.read_bytes()).hexdigest()
        binary, report["hysteria"] = download_hysteria(artifact, target="linux-arm64")
        save(report_path, report)
        with tempfile.TemporaryDirectory(prefix="fixture-", dir=artifact) as temporary:
            directory = Path(temporary)
            os.chmod(directory, 0o700)
            (directory / "apks").mkdir()
            with contextlib.ExitStack() as preparation:
                fetcher = create_vm(
                    preparation,
                    f"vcore-n0-hop-deps-{uuid.uuid4().hex[:12]}",
                    directory,
                    prepare=True,
                )
                report["preparation_vm"] = fetcher.name
                guest(fetcher, "apk", "update", timeout=60)
                guest(
                    fetcher,
                    "apk",
                    "fetch",
                    "--recursive",
                    "--output",
                    "/fixture/apks",
                    "nftables",
                    timeout=90,
                )
            packages = sorted((directory / "apks").glob("*.apk"))
            assert packages
            report["apk_sha256"] = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in packages
            }
            cert, _ = certificates(directory, "openssl")
            shutil.copyfile(binary, directory / "hysteria")
            (directory / "hysteria").chmod(0o755)
            with contextlib.ExitStack() as runtime:
                peer = create_vm(
                    runtime, f"vcore-n0-hop-peer-{uuid.uuid4().hex[:12]}", directory
                )
                report["runtime_vm"] = peer.name
                guest(
                    peer,
                    "apk",
                    "add",
                    "--no-network",
                    *[f"/fixture/apks/{path.name}" for path in packages],
                    timeout=45,
                )
                report["kernel"] = guest(peer, "uname", "-r").strip()
                report["nft_version"] = guest(peer, "nft", "--version").strip()
                report["hysteria"]["version"] = guest(
                    peer, "/fixture/hysteria", "version"
                ).strip()
                identity = json.loads(command("inspect", peer.name))[0]
                address = identity["status"]["networks"][0]["ipv4Address"].split("/")[0]
                assert ipaddress.ip_address(address) in ipaddress.ip_network(
                    network["status"]["ipv4Subnet"]
                )
                guest(peer, "nft", "list", "ruleset")
                # Container defaults to MTU 1280: Go QUIC's 1280-byte UDP Initial
                # then exceeds the IP MTU. Change only this owned VM, not macOS.
                report["guest_mtu_before"] = int(
                    guest(peer, "cat", "/sys/class/net/eth0/mtu")
                )
                guest(peer, "ip", "link", "set", "dev", "eth0", "mtu", "1500")
                report["guest_mtu"] = int(guest(peer, "cat", "/sys/class/net/eth0/mtu"))
                assert report["guest_mtu"] == 1500
                (directory / "observe.nft").write_text(observe_rules(address))
                guest(peer, "nft", "-f", "/fixture/observe.nft")
                password = secrets.token_urlsafe(24)
                server = {
                    "listen": f"{address}:{FIRST}-{SECOND}",
                    "tls": {"cert": "/fixture/cert.pem", "key": "/fixture/key.pem"},
                    "auth": {"type": "password", "password": password},
                    "ignoreClientBandwidth": True,
                    "disableUDP": True,
                }
                (directory / "server.json").write_text(json.dumps(server))
                command(
                    "exec",
                    "--detach",
                    "--env",
                    "HYSTERIA_FIREWALL_BACKEND=nftables",
                    peer.name,
                    "/bin/sh",
                    "-c",
                    "exec /fixture/hysteria server --disable-update-check -c /fixture/server.json > /tmp/hysteria.log 2>&1",
                )
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        log = guest(
                            peer,
                            "/bin/sh",
                            "-c",
                            "if [ -f /tmp/hysteria.log ]; then cat /tmp/hysteria.log; fi",
                        )
                        if "server up and running" in log:
                            break
                        if time.monotonic() > deadline or "FATAL" in log:
                            raise RuntimeError(
                                "native Hysteria range listener did not start"
                            )
                        time.sleep(0.05)
                    sockets = guest(peer, "cat", "/proc/net/udp")
                    bound_ports = [
                        int(line.split()[1].split(":")[1], 16)
                        for line in sockets.splitlines()[1:]
                    ]
                    assert bound_ports.count(FIRST) == 1 and SECOND not in bound_ports
                    native_rules = json.loads(
                        guest(peer, "nft", "-j", "list", "ruleset")
                    )
                    native_tables = [
                        item["table"]["name"]
                        for item in native_rules["nftables"]
                        if "table" in item
                        and item["table"]["name"].startswith("hysteria_")
                    ]
                    assert len(native_tables) == 1
                    report["single_udp_listener"] = True
                    report["native_redirect_table_count"] = len(native_tables)
                    with origin(False, host=network["status"]["ipv4Gateway"]) as echo:
                        config = {
                            "peer": f"{address}:{FIRST}",
                            "hop_port": SECOND,
                            "ca": str(cert),
                            "server_name": "localhost",
                            "password": password,
                            "half_close": False,
                            "reject_at": 2 if args.reject_hop else 0,
                            "target": f"{network['status']['ipv4Gateway']}:{echo.server_address[1]}",
                        }
                        (directory / "probe.json").write_text(json.dumps(config))
                        probe = subprocess.run(
                            [str(executable), str(directory / "probe.json")],
                            capture_output=True,
                            text=True,
                            check=True,
                            timeout=30,
                        )
                        result = json.loads(probe.stdout)
                        (output / "probe.log").write_text(probe.stderr)
                        result.update(
                            {
                                "origin_connections": echo.accepted,
                                "origin_bytes": echo.received,
                                "origin_failed": echo.failed,
                            }
                        )
                        report["cases"].append(
                            {
                                "name": "native-hysteria-reject-hop"
                                if args.reject_hop
                                else "native-hysteria-one-state-hop",
                                **result,
                            }
                        )
                        save(report_path, report)
                        assert result["outcome"] == (
                            "protect_rejected" if args.reject_hop else "pass"
                        ), result
                        assert (
                            result.get("rebinds") == 1
                            and result.get("connect_calls") == 1
                            and result.get("auth_requests") == 1
                        ), result
                        assert (
                            result["protect_calls"] == 2
                            and result["controller_builds"] == 1
                        ), result
                        assert result["stopped"] is True and echo.accepted == 1, result
                        if args.reject_hop:
                            assert (
                                result["post_hop_sent_packets"]
                                == result["post_hop_received_packets"]
                                == 0
                            ), result
                            assert echo.received == PAYLOAD_BYTES // 2, result
                        else:
                            assert (
                                result["same_connection"] is True
                                and result["same_stream"] is True
                            ), result
                            assert (
                                result["post_hop_sent_packets"] > 0
                                and result["post_hop_received_packets"] > 0
                            ), result
                            assert result["udp_enabled"] is False, result
                            assert echo.received == PAYLOAD_BYTES and not echo.failed, (
                                result
                            )
                    counters = json.loads(
                        guest(
                            peer,
                            "nft",
                            "-j",
                            "list",
                            "table",
                            "ip",
                            "vcore_n0_observe",
                        )
                    )
                    counts, sources = {}, {}
                    for item in counters["nftables"]:
                        if "rule" in item:
                            rule = item["rule"]
                            counts[rule["comment"]] = next(
                                part["counter"]["packets"]
                                for part in rule["expr"]
                                if "counter" in part
                            )
                        if "set" in item:
                            sources[item["set"]["name"]] = item["set"].get("elem", [])
                    report["ingress_packets"] = counts
                    report["client_source_ports"] = sources
                    assert counts["first"] > 0 and len(sources["first_sources"]) == 1
                    if args.reject_hop:
                        assert counts["second"] == 0 and not sources["second_sources"]
                    else:
                        assert (
                            counts["second"] > 0 and len(sources["second_sources"]) == 1
                        )
                        assert sources["first_sources"] != sources["second_sources"]
                        report["distinct_client_source_ports"] = True
                    log = guest(peer, "cat", "/tmp/hysteria.log")
                    report["server_authenticated_connections"] = log.count(
                        "client connected"
                    )
                    assert report["server_authenticated_connections"] == 1
                finally:
                    (output / "peer.log").write_text(
                        guest(
                            peer,
                            "/bin/sh",
                            "-c",
                            "if [ -f /tmp/hysteria.log ]; then cat /tmp/hysteria.log; fi",
                        )
                    )
                    pids = guest(
                        peer, "/bin/sh", "-c", "pidof hysteria || true"
                    ).split()
                    if pids:
                        assert len(pids) == 1 and pids[0].isdigit()
                        guest(peer, "kill", "-TERM", pids[0])
                    deadline = time.monotonic() + 5
                    while True:
                        rules = json.loads(guest(peer, "nft", "-j", "list", "ruleset"))
                        if not any(
                            "table" in item
                            and item["table"]["name"].startswith("hysteria_")
                            for item in rules["nftables"]
                        ):
                            report["native_rules_removed_on_stop"] = True
                            break
                        if time.monotonic() > deadline:
                            raise RuntimeError(
                                "native Hysteria did not clean its rules"
                            )
                        time.sleep(0.05)
                    guest(
                        peer,
                        "nft",
                        "delete",
                        "table",
                        "ip",
                        "vcore_n0_observe",
                    )
        remaining = {
            item["id"]
            for item in json.loads(command("list", "--all", "--format", "json"))
        }
        assert not {report["preparation_vm"], report["runtime_vm"]} & remaining
        report["owned_vms_removed"] = True
        report["status"] = "pass"
        print(f"PASS {report['cases'][0]['name']}", flush=True)
    except BaseException:
        report["status"] = "fail"
        raise
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save(report_path, report)
        print(f"Report: {report_path}", flush=True)


if __name__ == "__main__":
    with exclusive_run():
        main()
