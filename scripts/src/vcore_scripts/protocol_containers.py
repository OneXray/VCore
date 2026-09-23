"""Owned Apple Container test peers; no native-server fallback or host publishing."""

from __future__ import annotations

import ipaddress
import json
import socket
import time
import uuid
from pathlib import Path

from .protocol_peers import OwnedProcess, run_command

NETWORK = "vcore-mihomo-interop"
IMAGE = "docker.io/library/python:3-alpine"


def command(*args, timeout=30):
    result = run_command(["container", *args], timeout=timeout)
    if result.returncode != 0 or not result.cleanup:
        # CLI output may contain fixture paths/config; retain a bounded operation only.
        raise RuntimeError(f"isolated container operation failed: {args[0]}")
    return result.stdout.decode(errors="replace")


def listing():
    return json.loads(command("list", "--all", "--format", "json"))


class ContainerLab:
    def __init__(self, record):
        self.record = record
        self.run_id = uuid.uuid4().hex[:12]
        network = json.loads(command("network", "inspect", NETWORK))[0]
        config = network["configuration"]
        if (
            config["mode"] != "hostOnly"
            or config.get("labels", {}).get("purpose") != NETWORK
        ):
            raise RuntimeError("owned host-only container network required")
        self.v4 = ipaddress.ip_network(network["status"]["ipv4Subnet"])
        self.v6 = ipaddress.ip_network(network["status"]["ipv6Subnet"])
        command("image", "pull", IMAGE, timeout=180)
        inspection = json.loads(command("image", "inspect", IMAGE))[0]
        digest = inspection["configuration"]["descriptor"]["digest"]
        self.image = IMAGE.split(":")[0] + "@" + digest
        record.update(
            backend="Apple Container",
            network_mode="hostOnly",
            image_tag=IMAGE,
            image_digest=digest,
            run_id=self.run_id,
            peers=[],
            host_servers=False,
        )

    def start(self, stack, root: Path, role, argv):
        peer = ContainerPeer(self, root, role)
        self.record["peers"].append(peer.record)
        # Register before launching: CLI interruption/timeout can leave a live VM.
        stack.callback(peer.stop)
        peer.start(argv)
        return peer


class ContainerPeer:
    def __init__(self, lab, root, role):
        self.lab, self.root = lab, root
        self.name = f"vcore-n3-{lab.run_id}-{role}"
        self.record = dict(role=role, name=self.name, joined=False, started=False)
        self.capture = None
        self.log = root / "peer.log"

    def start(self, argv):
        command(
            "run",
            "--detach",
            "--name",
            self.name,
            "--label",
            f"purpose={NETWORK}",
            "--label",
            f"vcore-run={self.lab.run_id}",
            "--network",
            NETWORK,
            "--cpus",
            "1",
            "--memory",
            "256M",
            "--arch",
            "arm64",
            "--read-only",
            "--no-dns",
            "--tmpfs",
            "/data",
            "--mount",
            f"type=bind,source={self.root},target=/data/fixture,readonly",
            "--entrypoint",
            "/bin/sh",
            self.lab.image,
            "-ec",
            "for i in $(seq 1 600); do "
            'if [ -f /data/fixture/ready ]; then exec "$@"; fi; '
            "sleep 0.1; done; exit 1",
            "fixture",
            *argv,
            timeout=45,
        )
        self.record["started"] = True
        self.capture = OwnedProcess(
            ["container", "logs", "--follow", self.name],
            self.log,
            {},
            limit=1024 * 1024,
        ).__enter__()
        state = json.loads(command("inspect", self.name))[0]
        self.ipv4 = state["status"]["networks"][0]["ipv4Address"].split("/")[0]
        if ipaddress.ip_address(self.ipv4) not in self.lab.v4:
            raise RuntimeError("container address outside owned network")
        # Wait for SLAAC/DAD before any business traffic. No host IPv6 binds needed.
        query = (
            "import pathlib,json; print(json.dumps(["
            "[x[0],int(x[4],16)] for line in "
            "pathlib.Path('/proc/net/if_inet6').read_text().splitlines() "
            "if (x:=line.split())[5]=='eth0']))"
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            rows = json.loads(command("exec", self.name, "python", "-c", query))
            for address, flags in rows:
                ip = ipaddress.IPv6Address(int(address, 16))
                if ip in self.lab.v6 and not flags & (0x40 | 0x08):
                    self.ipv6 = str(ip)
                    return
            time.sleep(0.1)
        raise RuntimeError("container IPv6 readiness failed")

    def release(self):
        (self.root / "ready").touch()

    def ensure_alive(self):
        state = json.loads(command("inspect", self.name))[0]["status"]["state"]
        if state != "running" or (self.capture and self.capture.overflow.is_set()):
            raise RuntimeError("owned container peer exited or exceeded output bound")

    def wait_tcp(self, port):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.ensure_alive()
            try:
                with socket.create_connection((self.ipv4, port), timeout=0.2):
                    self.record["ready"] = True
                    return
            except OSError:
                time.sleep(0.05)
        raise TimeoutError("container service readiness failed")

    def stop(self):
        owned = next((item for item in listing() if item["id"] == self.name), None)
        try:
            if owned is not None:
                labels = owned["configuration"].get("labels", {})
                if (
                    labels.get("purpose") != NETWORK
                    or labels.get("vcore-run") != self.lab.run_id
                ):
                    raise RuntimeError("container ownership mismatch; refusing cleanup")
                try:
                    if owned["status"]["state"] == "running":
                        command("stop", "--time", "5", self.name, timeout=15)
                finally:
                    command("delete", "--force", self.name, timeout=15)
        finally:
            if self.capture is not None:
                self.capture.__exit__(None, None, None)
                self.record["log_cleanup"] = self.capture.record.get("joined", False)
        self.record["joined"] = not any(
            item["id"] == self.name for item in listing()
        ) and self.record.get("log_cleanup", True)
        if not self.record["joined"]:
            raise RuntimeError("owned container cleanup incomplete")
