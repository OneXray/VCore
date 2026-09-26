"""Read a real official client's close behavior; execute only inside its VM lab."""

import json
import os
import socket
import ssl
import struct
import sys
from pathlib import Path


def exact(io, length):
    data = bytearray()
    while len(data) < length:
        part = io.recv(length - len(data))
        if not part:
            raise ValueError("truncated close control")
        data.extend(part)
    return bytes(data)


def main(proxy, origin, variant="plain"):
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise RuntimeError("isolated close consumer required")
    with socket.create_connection((origin, 24000), timeout=10) as control:
        vision = variant == "vision-direct"
        if variant not in ("plain", "vision-direct"):
            raise ValueError("unknown close variant")
        control.sendall(b"\x15" if vision else b"\x0b")
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
            io = client
            if vision:
                from tls_bio import TlsBio

                context = ssl.create_default_context(
                    cafile=str(Path(__file__).with_name("cert.pem"))
                )
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                io = TlsBio(client, context, server=False)
                assert io.tls.version() == "TLSv1.3"
                assert exact(control, 2) == b"A\x13"
            assert exact(io, 5) == b"hello"
            payload = b"Z" * 65536 if vision else b"ping"
            io.sendall(payload)
            assert exact(io, len(payload)) == payload
            client.shutdown(socket.SHUT_WR)
            tail = bytearray()
            try:
                while chunk := io.recv(1024):
                    tail.extend(chunk)
                    if len(tail) > 1024:
                        raise ValueError("close tail limit")
            except ConnectionResetError:
                pass
            assert exact(control, 1 if vision else 2) == (b"D" if vision else b"AD")
            print(
                json.dumps(
                    {"tail_hex": tail.hex(), "terminated": True, "variant": variant}
                )
            )


if __name__ == "__main__":
    main(*sys.argv[1:])
