"""Reuse the isolated origin with a bounded explicit CN DNS allowlist.

Names from official rules resolve only to this container, never public hosts.
No listener runs in the measured process or on the host.
"""

import json
import socket
import struct
from pathlib import Path

import origin


def wire_name(name):
    return (
        b"".join(
            bytes([len(label)]) + label.encode("ascii") for label in name.split(".")
        )
        + b"\0"
    )


def response(packet, ipv4, peer_ipv4=None):
    del peer_ipv4
    question = next(
        (name for name in NAMES if packet[12 : 12 + len(name)] == name), None
    )
    if (
        question is None
        or len(packet) != 12 + len(question) + 4
        or packet[-2:] != b"\0\x01"
    ):
        raise ValueError("unexpected CN fixture DNS question")
    qtype = struct.unpack("!H", packet[-4:-2])[0]
    answer = socket.inet_pton(socket.AF_INET, ipv4) if qtype == 1 else b""
    result = bytearray(packet)
    result[2:4] = b"\x81\x80"
    result[6:8] = struct.pack("!H", int(bool(answer)))
    if answer:
        result.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04" + answer)
    return bytes(result)


if __name__ == "__main__":
    names = json.loads(Path("/data/fixture/cn-names.json").read_text())
    if not 1 <= len(names) <= 32 or any(len(name) > 253 for name in names):
        raise SystemExit("invalid bounded CN DNS allowlist")
    NAMES = [wire_name(name) for name in names]
    origin.dns_response = response
    origin.main()
