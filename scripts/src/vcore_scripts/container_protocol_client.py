"""Container-only comparison client for matched official protocol peers."""

import json
import os
import socket
import struct
import sys
from pathlib import Path


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise ValueError("truncated peer response")
        data.extend(part)
    return bytes(data)


def socks(stream, command, host, port):
    stream.sendall(b"\x05\x01\x00")
    if exact(stream, 2) != b"\x05\x00":
        raise ValueError("SOCKS authentication failed")
    stream.sendall(
        bytes([5, command, 0, 1]) + socket.inet_aton(host) + struct.pack("!H", port)
    )
    header = exact(stream, 4)
    if header[:3] != b"\x05\x00\x00":
        raise ValueError("SOCKS request failed")
    if header[3] == 1:
        address = socket.inet_ntop(socket.AF_INET, exact(stream, 4))
    elif header[3] == 4:
        address = socket.inet_ntop(socket.AF_INET6, exact(stream, 16))
    else:
        raise ValueError("unexpected SOCKS bound address")
    return address, struct.unpack("!H", exact(stream, 2))[0]


def probe(option, origin):
    """One real TCP exchange and two origin-observed UDP exchanges, no retry."""
    ingress = (option["socks_host"], option["socks_port"])
    payload = bytes(range(256)) * 4
    with socket.create_connection((origin, 24000), timeout=10) as control:
        control.sendall(b"\x0d")
        port = struct.unpack("!H", exact(control, 2))[0]
        with socket.create_connection(ingress, timeout=10) as stream:
            socks(stream, 1, origin, port)
            stream.sendall(payload)
            if exact(control, 1) != b"A" or exact(stream, len(payload)) != payload:
                raise ValueError("TCP origin exchange differs")
    with (
        socket.create_connection((origin, 24000), timeout=10) as control,
        socket.create_connection(ingress, timeout=10) as association,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
    ):
        control.sendall(b"\x04")
        port = struct.unpack("!H", exact(control, 2))[0]
        relay = socks(association, 3, "0.0.0.0", 0)
        # The ingress explicitly listens on IPv4, so no host/system DNS is used.
        if relay[0] == "0.0.0.0":
            relay = (option["socks_host"], relay[1])
        udp.settimeout(10)
        udp.connect(relay)
        header = (
            b"\x00\x00\x00\x01" + socket.inet_aton(origin) + struct.pack("!H", port)
        )
        for size in (64, 1200):
            payload = bytes(index % 251 for index in range(size))
            if udp.send(header + payload) != len(header) + size:
                raise ValueError("partial UDP submission")
            observed, _source = struct.unpack("!HH", exact(control, 4))
            if observed != size or exact(control, observed) != payload:
                raise ValueError("UDP origin exchange differs")
            if udp.recv(65536) != header + payload:
                raise ValueError("UDP reply differs")
    return dict(
        case_id=option["case_id"],
        status="PASS",
        tcp_bytes_each_direction=1024,
        udp_origin_packets=2,
        udp_reply_packets=2,
        udp_sizes=[64, 1200],
    )


def main():
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_CLIENT") != "1":
        raise SystemExit("isolated container harness required")
    fixture = json.loads(Path(sys.argv[1]).read_text())
    for option in fixture["cases"]:
        try:
            record = probe(option, fixture["origin"])
        except (OSError, ValueError) as error:
            print(
                json.dumps(
                    dict(
                        case_id=option["case_id"],
                        status="FAIL",
                        error=type(error).__name__,
                    )
                ),
                flush=True,
            )
            raise SystemExit(1) from None
        print(json.dumps(record), flush=True)


if __name__ == "__main__":
    main()
