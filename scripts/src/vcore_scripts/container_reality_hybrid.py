"""Container-only OpenSSL cover sites, TCP origin, and transparent observation."""

import json
import os
import select
import socket
import ssl
import sys
import threading
import time
from pathlib import Path

ROOT = Path("/data/fixture")
EVENTS = Path("/data/events.jsonl")
LOCK = threading.Lock()
SLOTS = threading.BoundedSemaphore(32)


def emit(**event):
    with LOCK, EVENTS.open("a") as output:
        if EVENTS.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("observer event limit")
        output.write(json.dumps(event) + "\n")


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError()
        data.extend(part)
    return bytes(data)


def word(data, at):
    return int.from_bytes(data[at : at + 2], "big")


def client_hello(stream):
    wire, message = bytearray(), bytearray()
    for _ in range(8):
        head = exact(stream, 5)
        size = word(head, 3)
        if head[0] != 22 or not 1 <= size <= 16384:
            raise ValueError("TLS record")
        body = exact(stream, size)
        wire.extend(head + body)
        message.extend(body)
        if len(message) > 65536:
            raise ValueError("hello limit")
        if len(message) >= 4:
            expected = 4 + int.from_bytes(message[1:4], "big")
            if message[0] != 1 or len(message) > expected:
                raise ValueError("ClientHello length")
            if len(message) == expected:
                return bytes(wire), bytes(message)
    raise ValueError("record count")


def extensions(message, client):
    at = 39 + message[38]
    if client:
        at += 2 + word(message, at)
        at += 1 + message[at]
    else:
        at += 3
    end = at + 2 + word(message, at)
    at += 2
    if end != len(message):
        raise ValueError("extension length")
    while at < end:
        kind, size = word(message, at), word(message, at + 2)
        data = message[at + 4 : at + 4 + size]
        if len(data) != size:
            raise ValueError("truncated extension")
        yield kind, data
        at += 4 + size


def shares(message):
    result = []
    for kind, data in extensions(message, True):
        if kind == 51:
            at = 2
            while at < len(data):
                group, size = word(data, at), word(data, at + 2)
                if group & 0x0F0F != 0x0A0A:
                    result.append([group, size])
                at += 4 + size
            if at != len(data):
                raise ValueError("key share length")
    return result


def selected_group(wire):
    if len(wire) < 5 or len(wire) < 5 + word(wire, 3):
        return None
    if wire[0] != 22 or wire[5] != 2:
        return -1
    message = wire[5 : 5 + word(wire, 3)]
    size = 4 + int.from_bytes(message[1:4], "big")
    for kind, data in extensions(message[:size], False):
        if kind == 51:
            return word(data, 0)
    return -1


def handle(stream, port, context):
    try:
        with stream:
            stream.settimeout(5)
            if port == 9000:
                # Readiness opens a connection without application data.
                received = 0
                while part := stream.recv(16384):
                    if not received:
                        emit(port=port, event="origin-data")
                    received += len(part)
                    if received > 10 * 1024 * 1024:
                        raise ValueError("origin byte limit")
                    stream.sendall(part)
                if received:
                    emit(port=port, event="origin-complete", bytes=received)
                return
            try:
                raw, hello = client_hello(stream)
            except EOFError:
                return
            emit(
                port=port,
                event="client-hello",
                shares=shares(hello),
                groups=[
                    word(data, at)
                    for kind, data in extensions(hello, True)
                    if kind == 10
                    for at in range(2, len(data), 2)
                    if word(data, at) & 0x0F0F != 0x0A0A
                ],
            )
            if context is None:
                address = json.loads((ROOT / "routes.json").read_text())[str(port)]
                with socket.create_connection(tuple(address), timeout=5) as upstream:
                    upstream.sendall(raw)
                    deadline, total = time.monotonic() + 240, len(raw)
                    flight, observed = bytearray(), False
                    while time.monotonic() < deadline:
                        ready, _, _ = select.select([stream, upstream], [], [], 0.2)
                        for source in ready:
                            data = source.recv(16384)
                            if not data:
                                if source is upstream:
                                    emit(
                                        port=port,
                                        event="server-close",
                                        bytes=len(flight),
                                    )
                                return
                            total += len(data)
                            if total > 128 * 1024 * 1024:
                                raise ValueError("relay byte limit")
                            if source is upstream and not observed:
                                flight.extend(data)
                                if len(flight) > 65536:
                                    raise ValueError("server flight limit")
                                group = selected_group(flight)
                                if group is not None:
                                    emit(
                                        port=port,
                                        event="server-hello"
                                        if group >= 0
                                        else "tls-response",
                                        group=group,
                                        hrr=flight[11:43]
                                        == bytes.fromhex(
                                            "cf21ad74e59a6111be1d8c021e65b891"
                                            "c2a211167abb8c5e079e09e2c8a8339c"
                                        ),
                                    )
                                    observed = True
                            (upstream if source is stream else stream).sendall(data)
                raise TimeoutError("relay duration")
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = context.wrap_bio(incoming, outgoing, server_side=True)
            incoming.write(raw)
            for _ in range(32):
                try:
                    tls.do_handshake()
                    stream.sendall(outgoing.read())
                    emit(port=port, event="cover-complete", version=tls.version())
                    return
                except ssl.SSLWantReadError:
                    data = outgoing.read()
                    if data:
                        stream.sendall(data)
                    data = stream.recv(16384)
                    if not data:
                        return
                    incoming.write(data)
            raise ValueError("cover iteration limit")
    except ssl.SSLError as error:
        emit(
            port=port,
            event="no-shared-group"
            if error.reason == "NO_SUITABLE_KEY_SHARE"
            else "closed",
        )
    except (OSError, ValueError, EOFError):
        emit(port=port, event="closed")
    finally:
        SLOTS.release()


def serve(port, context):
    with socket.socket(socket.AF_INET6) as listener:
        listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        listener.bind(("::", port))
        listener.listen(32)
        while True:
            stream, _ = listener.accept()
            SLOTS.acquire()
            threading.Thread(
                target=handle, args=(stream, port, context), daemon=True
            ).start()


if __name__ == "__main__":
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit("isolated REALITY observer required")
    EVENTS.touch()
    contexts = {}
    for port, group, version in [
        (24431, "X25519MLKEM768", ssl.TLSVersion.TLSv1_3),
        (24432, "X25519", ssl.TLSVersion.TLSv1_3),
        (24433, "secp384r1", ssl.TLSVersion.TLSv1_3),
        (24434, "X25519", ssl.TLSVersion.TLSv1_2),
    ]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ROOT / "cert.pem", ROOT / "key.pem")
        # Python's EC-NID setter rejects hybrid group names even with OpenSSL
        # 3.5. Use the native default list for the hybrid cover, then verify the
        # actual ServerHello/finished connection selected 4588 in the harness.
        if group != "X25519MLKEM768":
            context.set_ecdh_curve(group)
        context.minimum_version = context.maximum_version = version
        context.set_alpn_protocols(["h2", "http/1.1"])
        contexts[port] = context
    emit(event="native-tls", version=ssl.OPENSSL_VERSION)
    threads = [
        threading.Thread(target=serve, args=(port, context))
        for port, context in [
            *contexts.items(),
            *(
                (int(port), None)
                for port in json.loads((ROOT / "routes.json").read_text())
            ),
        ]
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
