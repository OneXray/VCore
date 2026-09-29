"""Run an unmodified peer with a bounded UDP-side-channel observer in its guest.

The official server still owns every TCP listener. These otherwise unused UDP
ports detect accidental native SS fallback; the observer never replies to UDP.
"""

from __future__ import annotations

import contextlib
import json
import os
import select
import socket
import subprocess
import sys
from pathlib import Path


def main():
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit("isolated UoT peer required")
    config = json.loads(Path("/data/fixture/config.json").read_text())
    native = "servers" in config
    ports = [
        item["server_port" if native else "port"]
        for item in config["servers" if native else "listeners"]
    ]
    if not 1 <= len(ports) <= 32 or len(ports) != len(set(ports)):
        raise ValueError("bounded unique peer ports required")
    with contextlib.ExitStack() as stack:
        watchers = []
        for port in ports:
            udp = stack.enter_context(socket.socket(socket.AF_INET6, socket.SOCK_DGRAM))
            udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            udp.bind(("::", port))
            watchers.append(udp)
        observer = stack.enter_context(socket.socket())
        observer.bind(("0.0.0.0", 23998))
        observer.listen(4)
        counts = dict(ports=ports, native_udp_packets=0)
        with subprocess.Popen(sys.argv[1:]) as peer:
            try:
                while peer.poll() is None:
                    ready, _, _ = select.select([*watchers, observer], [], [], 0.1)
                    # Drain UDP before answering a snapshot in the same cycle.
                    for udp in watchers:
                        if udp in ready:
                            udp.recvfrom(65536)
                            counts["native_udp_packets"] += 1
                    if observer in ready:
                        client, _ = observer.accept()
                        with client:
                            client.settimeout(1)
                            if client.recv(1) == b"?":
                                client.sendall(json.dumps(counts).encode())
                raise RuntimeError("official UoT peer exited")
            finally:
                peer.terminate()
                try:
                    peer.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    peer.kill()
                    peer.wait(timeout=3)


if __name__ == "__main__":
    main()
