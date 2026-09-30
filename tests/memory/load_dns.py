"""Bounded DNS oracle for coupled load; runs only in an owned Linux container."""

import json
import os
import select
import socket
import struct
import sys
from pathlib import Path


def answer(packet, names, target):
    if len(packet) < 17 or len(packet) > 512:
        raise ValueError("DNS size")
    _, flags, questions, answers, authority, additional = struct.unpack(
        "!6H", packet[:12]
    )
    if flags & 0xF800 or (questions, answers, authority, additional) != (1, 0, 0, 0):
        raise ValueError("DNS header")
    offset, labels = 12, []
    while packet[offset]:
        length = packet[offset]
        if length > 63 or offset + length + 1 >= len(packet):
            raise ValueError("DNS label")
        labels.append(packet[offset + 1 : offset + 1 + length].decode("ascii"))
        offset += length + 1
    if offset + 5 != len(packet):
        raise ValueError("DNS question")
    name = ".".join(labels).lower()
    qtype, qclass = struct.unpack("!HH", packet[offset + 1 :])
    if name not in names or qtype not in (1, 28) or qclass != 1:
        raise ValueError("DNS allowlist")
    target_type = 28 if ":" in target else 1
    family = socket.AF_INET6 if target_type == 28 else socket.AF_INET
    payload = socket.inet_pton(family, target) if qtype == target_type else b""
    # The core retains its production minimum TTL; the harness waits beyond it.
    reply = (
        packet[:2] + struct.pack("!5H", 0x8180, 1, bool(payload), 0, 0) + packet[12:]
    )
    if payload:
        reply += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 0, len(payload)) + payload
    return reply, names[name], str(qtype)


def main():
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit("DNS origin requires an owned isolated Linux container")
    config = json.loads(Path("/data/fixture/load-dns.json").read_text())
    names = {item["value"].lower(): item["id"] for item in config["names"]}
    if not 1 <= len(names) <= 2048 or any(len(name) > 253 for name in names):
        raise SystemExit("invalid bounded DNS names")
    counters = {"queries": {}, "rejected": 0}
    with socket.socket() as control, socket.socket(type=socket.SOCK_DGRAM) as dns:
        control.bind(("0.0.0.0", 24000))
        control.listen(8)
        dns.bind(("0.0.0.0", 24004))
        while True:
            ready, _, _ = select.select([control, dns], [], [])
            if dns in ready:
                packet, source = dns.recvfrom(513)
                try:
                    response, case_id, qtype = answer(packet, names, config["target"])
                    category = (
                        "core"
                        if source[0] == config["core_source"]
                        else "peer"
                        if source[0]
                        in config.get("peer_sources", [config["peer_source"]])
                        else "unknown"
                    )
                    key = case_id + ":" + qtype + ":" + category
                    counters["queries"][key] = counters["queries"].get(key, 0) + 1
                    dns.sendto(response, source)
                except (ValueError, UnicodeError, IndexError):
                    counters["rejected"] += 1
            if control in ready:
                stream, _ = control.accept()
                with stream:
                    stream.settimeout(1)
                    raw = json.dumps(counters, separators=(",", ":")).encode() + b"\n"
                    try:
                        stream.sendall(raw)
                    except OSError:
                        pass


if __name__ == "__main__":
    main()
