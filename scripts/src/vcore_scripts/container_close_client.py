"""Read a real official client's close behavior; execute only inside its VM lab."""

import json
import os
import socket
import struct
import sys


def exact(io, length):
    data = bytearray()
    while len(data) < length:
        part = io.recv(length - len(data))
        if not part:
            raise ValueError("truncated close control")
        data.extend(part)
    return bytes(data)


def main(proxy, origin):
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise RuntimeError("isolated close consumer required")
    with socket.create_connection((origin, 24000), timeout=10) as control:
        control.sendall(b"\x0b")
        port = struct.unpack("!H", exact(control, 2))[0]
        with socket.create_connection((proxy, 23002), timeout=10) as client:
            client.sendall(b"\x05\x01\x00")
            assert exact(client, 2) == b"\x05\x00"
            client.sendall(
                b"\x05\x01\x00\x01" + socket.inet_aton(origin) + struct.pack("!H", port)
            )
            header = exact(client, 4)
            assert header[:3] == b"\x05\x00\x00"
            exact(client, 6 if header[3] == 1 else 18)
            assert exact(client, 5) == b"hello"
            client.sendall(b"ping")
            assert exact(client, 4) == b"ping"
            client.shutdown(socket.SHUT_WR)
            tail = bytearray()
            try:
                while chunk := client.recv(1024):
                    tail.extend(chunk)
                    if len(tail) > 1024:
                        raise ValueError("close tail limit")
            except ConnectionResetError:
                pass
            assert exact(control, 2) == b"AD"
            print(json.dumps({"tail_hex": tail.hex(), "terminated": True}))


if __name__ == "__main__":
    main(*sys.argv[1:])
