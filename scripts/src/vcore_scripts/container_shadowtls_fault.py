"""Bounded container TCP fault relay around an unmodified official ShadowTLS peer.

Only observes record framing/tags to locate faults; never terminates TLS or SS.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
from pathlib import Path

ROOT = Path("/data/fixture")
EVENTS = Path("/data/fault-events.jsonl")
LOCK = threading.Lock()
SLOTS = threading.BoundedSemaphore(16)
STALL = {"hello_seen": 0, "client_closed": 0}
PASSWORD = b"synthetic-shadowtls-fixture"
HRR = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"


def emit(mode, **fields):
    with LOCK, EVENTS.open("a") as output:
        output.write(json.dumps(dict(mode=mode, **fields)) + "\n")
        if mode == "stall":
            for key in STALL:
                STALL[key] += fields.get(key) is True


def observe():
    with socket.socket(socket.AF_INET) as listener:
        listener.bind(("0.0.0.0", 23998))
        listener.listen(4)
        while True:
            client, _ = listener.accept()
            with client:
                client.settimeout(2)
                try:
                    if client.recv(1) == b"?":
                        with LOCK:
                            data = json.dumps(STALL).encode()
                        client.sendall(data)
                except OSError:
                    pass


def exact(raw, count):
    data = bytearray()
    while len(data) < count:
        part = raw.recv(count - len(data))
        if not part:
            if data:
                raise EOFError("truncated fixture record")
            return None
        data.extend(part)
    return bytes(data)


def record(raw):
    header = exact(raw, 5)
    if header is None:
        return None
    size = int.from_bytes(header[3:5], "big")
    if not 0 < size <= 18436:
        raise ValueError("record bound")
    body = exact(raw, size)
    if body is None:
        raise EOFError("record body missing")
    return header + body


def upload(client, upstream):
    try:
        while data := client.recv(16384):
            upstream.sendall(data)
        upstream.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def serve(client, mode, target):
    upstream = None
    worker = None
    try:
        with client:
            client.settimeout(15)
            if mode == "stall":
                # Observe a real client hello, then await the client's deadline
                # or Stop. No business or cover destination is contacted.
                if record(client) is None:
                    return  # Readiness probes are not real stalled handshakes.
                emit(mode, hello_seen=True)
                while client.recv(16384):
                    pass
                emit(mode, client_closed=True)
                return
            upstream = socket.create_connection(target, timeout=10)
            upstream.settimeout(15)
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            worker = threading.Thread(target=upload, args=(client, upstream))
            worker.start()
            cover = business = None
            count = 0
            mutated = False
            while (data := record(upstream)) is not None:
                count += 1
                if data[0] == 22 and cover is None:
                    if len(data) < 43 or data[5] != 2:
                        raise ValueError("expected ServerHello")
                    seed = data[11:43]
                    cover = hmac.new(PASSWORD, seed, hashlib.sha1)
                    business = hmac.new(PASSWORD, seed + b"S", hashlib.sha1)
                    if seed.hex() == HRR:
                        emit(mode, hrr_seen=True)
                if data[0] == 23:
                    if len(data) < 9 or cover is None or business is None:
                        raise ValueError("authenticated record expected")
                    trial = cover.copy()
                    trial.update(data[9:])
                    is_cover = hmac.compare_digest(trial.digest()[:4], data[5:9])
                    if is_cover:
                        cover = trial
                    else:
                        trial = business.copy()
                        trial.update(data[9:])
                        if not hmac.compare_digest(trial.digest()[:4], data[5:9]):
                            raise ValueError("unclassified official record")
                        trial.update(data[5:9])
                        business = trial
                    if not mutated and (
                        (mode == "cover-mac" and is_cover)
                        or (
                            mode in {"business-mac", "business-truncated"}
                            and not is_cover
                        )
                    ):
                        mutated = True
                        emit(
                            mode,
                            injected=True,
                            phase="cover" if is_cover else "business",
                        )
                        if mode == "business-truncated":
                            client.sendall(data[:8])
                            client.shutdown(socket.SHUT_WR)
                            break
                        changed = bytearray(data)
                        changed[5] ^= 1
                        data = bytes(changed)
                if mode == "fragment" and count <= 8:
                    # The same authenticated records, with split headers and
                    # short writes; afterwards data remain bulk, not 10M syscalls.
                    for begin, end in ((0, 1), (1, 3), (3, 5), (5, 9), (9, len(data))):
                        if end > begin:
                            client.sendall(data[begin:end])
                    emit(mode, split_record=True)
                else:
                    client.sendall(data)
    except (OSError, EOFError, ValueError):
        pass
    finally:
        for raw in (client, upstream):
            if raw is not None:
                with contextlib.suppress(OSError):
                    raw.shutdown(socket.SHUT_RDWR)
                raw.close()
        if worker is not None:
            worker.join(timeout=2)
            if worker.is_alive():
                emit(mode, upload_join_failed=True)
        SLOTS.release()


def listen(item):
    with socket.socket(socket.AF_INET) as listener:
        listener.bind(("0.0.0.0", item["port"]))
        listener.listen(16)
        while True:
            client, _ = listener.accept()
            if not SLOTS.acquire(blocking=False):
                client.close()
                continue
            threading.Thread(
                target=serve,
                args=(client, item["mode"], (item["server"], item["server_port"])),
                daemon=True,
            ).start()


if __name__ == "__main__":
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit("isolated fault relay required")
    EVENTS.touch()
    threading.Thread(target=observe, daemon=True).start()
    items = json.loads((ROOT / "config.json").read_text())
    for item in items[1:]:
        threading.Thread(target=listen, args=(item,), daemon=True).start()
    listen(items[0])
