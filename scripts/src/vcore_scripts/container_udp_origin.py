"""Bounded UDP echo origin, run only inside the owned fixture container.

A TCP observer allocates one UDP association with a one-byte address family.
The response starts with its two-byte UDP port. Each real datagram is reported
as length/source-port (two network-order u16s), then the exact payload. Echoes
are sent by this container, never by the host test driver.
"""

from __future__ import annotations

import os
import select
import socket
import struct
import sys
import threading

CAPACITY = 20000
SLOTS = threading.BoundedSemaphore(8)


def serve(control):
    try:
        with control:
            control.settimeout(15)
            control.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            family = control.recv(1)
            if family not in (b"\x04", b"\x06"):
                return
            ipv6 = family == b"\x06"
            with socket.socket(
                socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM
            ) as udp:
                if ipv6:
                    udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                udp.bind(("::" if ipv6 else "0.0.0.0", 0))
                control.sendall(struct.pack("!H", udp.getsockname()[1]))
                for _ in range(20000):
                    ready, _, _ = select.select([control, udp], [], [], 30)
                    if not ready or control in ready:
                        return  # EOF/cancel closes this association's UDP socket.
                    packet, source = udp.recvfrom(CAPACITY + 1)
                    if len(packet) > CAPACITY:
                        return
                    control.sendall(struct.pack("!HH", len(packet), source[1]) + packet)
                    if udp.sendto(packet, source) != len(packet):
                        return
    except (OSError, ValueError):
        # Client cancellation/failed association is recorded by the test driver.
        pass
    finally:
        SLOTS.release()


def main():
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit(
            "BLOCKED: this origin must be launched by the container harness"
        )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("0.0.0.0", 24000))
        listener.listen(8)
        while True:
            control, _ = listener.accept()
            if not SLOTS.acquire(blocking=False):
                control.close()
                continue
            threading.Thread(target=serve, args=(control,), daemon=True).start()


if __name__ == "__main__":
    main()
