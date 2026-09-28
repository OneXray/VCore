"""Container-only TLS observer; never decodes or serves a proxy protocol."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import socket
import ssl
import threading
import time
from pathlib import Path


def capture_client_hello(receive):
    """Read at most eight records and 64 KiB of ClientHello from injected IO."""

    def exact(count):
        result = bytearray()
        while len(result) < count:
            part = receive(count - len(result))
            if not part:
                raise EOFError("incomplete TLS record")
            result.extend(part)
        return bytes(result)

    records, handshake, layout = bytearray(), bytearray(), []
    for _ in range(8):
        header = exact(5)
        size = int.from_bytes(header[3:], "big")
        if header[0] != 22 or not 1 <= size <= 18432:
            raise ValueError("expected bounded handshake record")
        payload = exact(size)
        records.extend(header + payload)
        handshake.extend(payload)
        layout.append(
            dict(type=header[0], version=int.from_bytes(header[1:3], "big"), bytes=size)
        )
        if len(handshake) >= 4:
            hello_size = int.from_bytes(handshake[1:4], "big") + 4
            if handshake[0] != 1 or hello_size > 65536:
                raise ValueError("expected bounded ClientHello")
            if len(handshake) >= hello_size:
                return bytes(records), bytes(handshake[:hello_size]), layout
    raise ValueError("ClientHello record limit")


def main():
    if os.environ.get("VCORE_ISOLATED_TLS_OBSERVER") != "1":
        raise RuntimeError("TLS observer requires an owned isolated container")
    log = Path("/data/events.jsonl")
    lock, stop = threading.Lock(), threading.Event()
    deadline = time.monotonic() + 900
    log.touch()

    def emit(event):
        with lock:
            if log.stat().st_size > 8 * 1024 * 1024:
                stop.set()
                raise RuntimeError("observer output limit")
            with log.open("a") as output:
                output.write(json.dumps(event, separators=(",", ":")) + "\n")

    contexts = {24430: None}
    for port, version in (
        (24431, ssl.TLSVersion.TLSv1_3),
        (24432, ssl.TLSVersion.TLSv1_2),
    ):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/data/fixture/cert.pem", "/data/fixture/key.pem")
        context.minimum_version = context.maximum_version = version
        context.set_alpn_protocols(["h2", "http/1.1"])
        contexts[port] = context

    def serve(port, context):
        try:
            with socket.socket() as listener:
                listener.settimeout(0.5)
                listener.bind(("0.0.0.0", port))
                listener.listen(8)
                sequence = 0
                while not stop.is_set() and time.monotonic() < deadline:
                    try:
                        stream, _ = listener.accept()
                    except TimeoutError:
                        continue
                    sequence += 1
                    if sequence > 512:
                        raise RuntimeError("observer connection limit")
                    with stream:
                        stream.settimeout(5)
                        event = dict(port=port, sequence=sequence)
                        try:
                            raw, hello, layout = capture_client_hello(stream.recv)
                        except EOFError:
                            continue  # The readiness connect carries no TLS bytes.
                        except (OSError, ValueError) as error:
                            emit(
                                event
                                | dict(
                                    status="capture-error", reason=type(error).__name__
                                )
                            )
                            continue
                        event.update(
                            client_hello_b64=base64.b64encode(hello).decode(),
                            records_b64=base64.b64encode(raw).decode(),
                            records=layout,
                        )
                        if context is None:
                            emit(event | dict(status="captured-only"))
                            with contextlib.suppress(OSError):
                                stream.sendall(bytes.fromhex("15030300020228"))
                            continue
                        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                        tls = context.wrap_bio(incoming, outgoing, server_side=True)
                        incoming.write(raw)
                        try:
                            consumed = len(raw)
                            for _ in range(32):
                                try:
                                    tls.do_handshake()
                                    stream.sendall(outgoing.read())
                                    emit(
                                        event
                                        | dict(
                                            status="tls-handshake-complete",
                                            version=tls.version(),
                                            cipher=tls.cipher()[0],
                                            alpn=tls.selected_alpn_protocol(),
                                            resumed=tls.session_reused,
                                        )
                                    )
                                    break
                                except ssl.SSLWantReadError:
                                    stream.sendall(outgoing.read())
                                    chunk = stream.recv(16384)
                                    if not chunk:
                                        raise EOFError() from None
                                    consumed += len(chunk)
                                    if consumed > 131072:
                                        raise ValueError(
                                            "TLS handshake input limit"
                                        ) from None
                                    incoming.write(chunk)
                            else:
                                raise ValueError("TLS handshake iteration limit")
                        except (OSError, EOFError, ValueError) as error:
                            with contextlib.suppress(OSError):
                                stream.sendall(outgoing.read())
                            emit(
                                event
                                | dict(
                                    status="tls-handshake-rejected",
                                    reason=getattr(
                                        error, "reason", type(error).__name__
                                    ),
                                )
                            )
        except BaseException as error:
            emit(dict(status="observer-error", reason=type(error).__name__))
            stop.set()

    workers = [
        threading.Thread(target=serve, args=(port, ctx))
        for port, ctx in contexts.items()
    ]
    print(
        json.dumps(dict(openssl=ssl.OPENSSL_VERSION, ports=list(contexts))), flush=True
    )
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()


if __name__ == "__main__":
    main()
