"""Apple Container peers on an explicitly owned, host-only network.

The two upstream/terminal peers get separate Linux kernels. Reverse-direction
HTTP/SOCKS fixtures remain native so VCore's loopback-only listeners stay private.
No host forwarding, system DNS, proxy, TUN, or third-party changes are needed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shutil
import socket
import subprocess
import time
import uuid
from contextlib import ExitStack
from pathlib import Path

NETWORK = "vcore-mihomo-interop"
IMAGE = (
    "docker.io/library/alpine@sha256:"
    "fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40"
)


def command(*arguments: str, timeout: int = 30) -> str:
    try:
        return subprocess.run(
            ["container", *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        ).stdout
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            f"container {arguments[0]} failed: {error.stderr[-2048:].strip()}"
        ) from error


def host_ipv6(text: str, gateway: str, subnet: str) -> str | None:
    """Find the ULA on the same bridge as our gateway, never a LAN/utun address."""
    network = ipaddress.IPv6Network(subnet)
    for interface in re.split(r"(?=^\S+:[ ]flags=)", text, flags=re.MULTILINE):
        if not re.search(rf"\binet {re.escape(gateway)}\s", interface):
            continue
        for line in interface.splitlines():
            if re.search(r"\b(tentative|duplicated|deprecated|detached)\b", line):
                continue
            match = re.search(r"\binet6 ([0-9a-fA-F:]+) prefixlen", line)
            if match and ipaddress.IPv6Address(match[1]) in network:
                return match[1]
    return None


class ContainerPeer:
    def __init__(self, name: str) -> None:
        self.name = name

    def poll(self) -> int | None:
        state = json.loads(command("inspect", self.name))[0]["status"]["state"]
        return None if state == "running" else 1

    def stop(self) -> None:
        # Only this invocation's unguessable names, never a prune or system stop.
        owned = next(
            (
                item
                for item in json.loads(command("list", "--all", "--format", "json"))
                if item["id"] == self.name
            ),
            None,
        )
        if owned is None:
            return
        if owned["configuration"].get("labels", {}).get("purpose") != NETWORK:
            raise RuntimeError(
                "refusing to clean a container without fixture ownership"
            )
        if owned["status"]["state"] == "running":
            command("stop", "--time", "5", self.name, timeout=15)
        command("delete", "--force", self.name)

    def logs(self) -> str:
        return command("logs", self.name)[-4096:]


class ContainerPeers:
    def __init__(self, directory: Path, stack: ExitStack, binary: Path) -> None:
        if not binary.is_file():
            raise RuntimeError("Linux ARM64 mihomo binary missing (NOT RUN)")
        network = json.loads(command("network", "inspect", NETWORK))[0]
        if (
            network["configuration"]["mode"] != "hostOnly"
            or network["configuration"]["labels"].get("purpose") != NETWORK
        ):
            raise RuntimeError("mihomo requires its labelled host-only network")
        # An explicit setup step pulls the pinned image; test runs do not update it.
        command("image", "inspect", IMAGE)
        self.host = network["status"]["ipv4Gateway"]
        self.addresses = ["127.0.0.1"] * 4
        self.peers: dict[int, ContainerPeer] = {}
        prefix = f"vcore-mihomo-{uuid.uuid4().hex[:12]}"
        with binary.open("rb") as artifact:
            digest = hashlib.file_digest(artifact, "sha256").hexdigest()
        print(f"Linux mihomo SHA-256: {digest}; image: {IMAGE}", flush=True)
        for index in (0, 3):
            fixture = directory / str(index)
            fixture.mkdir(exist_ok=True)
            shutil.copyfile(binary, fixture / "mihomo")
            (fixture / "mihomo").chmod(0o755)
            name = f"{prefix}-{index}"
            peer = ContainerPeer(name)
            # Register before launch: a failed/timed-out CLI can still create a VM.
            stack.callback(peer.stop)
            # Boot before writing config so we can discover the allocated IPs.
            command(
                "run",
                "--detach",
                "--name",
                name,
                "--label",
                f"purpose={NETWORK}",
                "--network",
                NETWORK,
                "--cpus",
                "1",
                "--arch",
                "arm64",
                "--memory",
                "256M",
                "--read-only",
                "--no-dns",
                "--tmpfs",
                "/data",
                "--mount",
                f"type=bind,source={fixture},target=/data/fixture,readonly",
                "--entrypoint",
                "/bin/sh",
                IMAGE,
                "-c",
                "while [ ! -f /data/fixture/config.yaml ]; do sleep 0.05; done; "
                "exec /data/fixture/mihomo -d /data -f /data/fixture/config.yaml",
                timeout=45,
            )
            self.peers[index] = peer
            if index == 0:
                print(
                    command("exec", name, "/data/fixture/mihomo", "-v").strip(),
                    flush=True,
                )
            state = json.loads(command("inspect", name))[0]
            address = state["status"]["networks"][0]["ipv4Address"].split("/")[0]
            if ipaddress.IPv4Address(address) not in ipaddress.IPv4Network(
                network["status"]["ipv4Subnet"]
            ):
                raise RuntimeError("unexpected container network address")
            self.addresses[index] = address
        # SLAAC/DAD can finish shortly after the first VM boots.
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            interfaces = subprocess.run(
                ["/sbin/ifconfig", "-a"],
                check=True,
                text=True,
                capture_output=True,
                timeout=5,
            ).stdout
            address = host_ipv6(interfaces, self.host, network["status"]["ipv6Subnet"])
            if address:
                try:
                    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                        probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        probe.bind((address, 0))
                    # Container IPv6 also uses SLAAC/DAD. A readiness probe is
                    # not a retry of business traffic; tests have not started.
                    for peer in self.peers.values():
                        command(
                            "exec",
                            peer.name,
                            "ping",
                            "-6",
                            "-c",
                            "1",
                            "-W",
                            "1",
                            address,
                            timeout=5,
                        )
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    pass
                else:
                    self.host_v6 = address
                    break
            time.sleep(0.1)
        else:
            raise RuntimeError("host-only bridge IPv6 did not become ready (NOT RUN)")
        print(
            f"Apple Container upstreams: {self.addresses[0]}, {self.addresses[3]}; "
            f"origins: {self.host}, {self.host_v6}; "
            "reverse inbound peers: native loopback",
            flush=True,
        )

    def configure(self, index: int, config: dict) -> None:
        config["hosts"] = {
            "vcore-fixture.test": self.host,
            "vcore-peer.test": self.addresses[3],
        }
        if index not in self.peers:
            return
        config.update({"allow-lan": True, "bind-address": "0.0.0.0"})
        if "external-controller" in config:
            port = config["external-controller"].rsplit(":", 1)[1]
            config["external-controller"] = f"0.0.0.0:{port}"
        for listener in config.get("listeners", []):
            listener["listen"] = "0.0.0.0"
            for key in ("certificate", "private-key"):
                if key in listener:
                    listener[key] = f"/data/fixture/{Path(listener[key]).name}"

    def environment(self) -> dict[str, str]:
        return {
            "VCORE_MIHOMO_PEER_HOSTS": json.dumps(self.addresses),
            "VCORE_MIHOMO_ORIGIN_V4": self.host,
            "VCORE_MIHOMO_ORIGIN_V6": self.host_v6,
        }
