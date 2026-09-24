"""Bounded UDP echo origin, run only inside the owned fixture container.

A TCP observer allocates one UDP association with a one-byte address family.
The response starts with its two-byte UDP port. Each real datagram is reported
as length/source-port (two network-order u16s), then the exact payload. Echoes
are sent by this container, never by the host test driver.
"""

from __future__ import annotations

import contextlib
import os
import select
import socket
import ssl
import struct
import sys
import threading
import time

CAPACITY = 20000
SLOTS = threading.BoundedSemaphore(8)


def receive_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(min(65536, size - len(data)))
        if not chunk:
            raise ValueError("truncated fixture request")
        data.extend(chunk)
    return bytes(data)


def serve_tcp(control, mode, ipv6=False):
    """10=bulk/server-first, 11=close differential, 12=identity probe.

    Observer A proves an actual accept; D proves exact request bytes and normal
    completion. Rejected identities must produce neither. No host-side server.
    """
    with socket.socket(
        socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_STREAM
    ) as listener:
        if ipv6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind(("::" if ipv6 else "0.0.0.0", 0))
        listener.listen(8)
        control.sendall(struct.pack("!H", listener.getsockname()[1]))
        for _ in range(32):
            ready, _, _ = select.select([control, listener], [], [], 30)
            if not ready or control in ready:
                return
            stream, _ = listener.accept()
            control.sendall(b"A")
            if mode in (16, 18):
                context = tls_context(
                    ssl.TLSVersion.TLSv1_3 if mode == 16 else ssl.TLSVersion.TLSv1_2
                )
                stream.settimeout(15)
                stream = context.wrap_socket(stream, server_side=True)
                control.sendall(b"\x13" if stream.version() == "TLSv1.3" else b"\x12")
            with stream:
                stream.settimeout(15)
                if mode == 13:  # bounded-lifetime echo; client-first and cancellation
                    while data := stream.recv(65536):
                        stream.sendall(data)
                elif mode == 14:  # measureDelay/HTTP entrypoint, not a proxy decoder
                    request = bytearray()
                    while not request.endswith(b"\r\n\r\n"):
                        request.extend(receive_exact(stream, 1))
                        if len(request) > 16384:
                            raise ValueError("HTTP origin header limit")
                    stream.sendall(
                        b"HTTP/1.1 200 OK\r\nConnection: close\r\n"
                        b"Content-Length: 0\r\n\r\n"
                    )
                elif mode == 15:  # deliberately withhold all handshake replies
                    while stream.recv(65536):
                        pass
                elif mode == 12:
                    if receive_exact(stream, 15) != b"synthetic-probe":
                        raise ValueError("identity probe data")
                    stream.sendall(b"ok")
                else:
                    stream.sendall(b"hello")
                    if mode in (10, 16, 18):
                        data = receive_exact(stream, 10 * 1024 * 1024)
                        if data != b"\x5a" * len(data):
                            raise ValueError("bulk data")
                        stream.sendall(data + b"trailer")
                    else:
                        data = receive_exact(stream, 4)
                        if data != b"ping":
                            raise ValueError("close probe data")
                        stream.sendall(data)
                    if stream.recv(1):
                        raise ValueError("unexpected data after request")
                    if mode == 11:
                        # Whole-close peers need not accept a tail.
                        with contextlib.suppress(OSError):
                            stream.sendall(b"native-after-upload-eof")
            control.sendall(b"D")


def serve(control):
    try:
        with control:
            control.settimeout(15)
            control.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            family = control.recv(1)
            if family and (family[0] & 0x7F) in (*range(10, 17), 18):
                serve_tcp(control, family[0] & 0x7F, bool(family[0] & 0x80))
                return
            if family not in (b"\x04", b"\x06", b"\x11", b"\x13", b"\x14"):
                return
            ipv6 = family == b"\x06"
            with socket.socket(
                socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM
            ) as udp:
                if ipv6:
                    udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                udp.bind(("::" if ipv6 else "0.0.0.0", 0))
                control.sendall(struct.pack("!H", udp.getsockname()[1]))
                peer_ipv4 = (
                    socket.inet_ntop(socket.AF_INET, receive_exact(control, 4))
                    if family == b"\x13"
                    else None
                )
                seen = False
                dns = family in (b"\x11", b"\x13")
                dns_deadline = time.monotonic() + 240
                for _ in range(20000):
                    wait = (
                        min(30, max(0, dns_deadline - time.monotonic())) if dns else 30
                    )
                    if not wait:
                        return
                    ready, _, _ = select.select([control, udp], [], [], wait)
                    if control in ready:
                        return  # EOF/cancel closes this association's UDP socket.
                    if not ready:
                        if dns:
                            # Runtime-owned DNS can be quiet during TCP or an
                            # IP-only UDP phase. Keep it until control closes,
                            # within the same bounded 240-second fixture lifetime.
                            continue
                        return
                    packet, source = udp.recvfrom(CAPACITY + 1)
                    if len(packet) > CAPACITY:
                        return
                    if family == b"\x14":
                        # A native origin blackhole, not a protocol peer. Report
                        # only first receipt; all handshake bytes are discarded.
                        if not seen:
                            control.sendall(b"A")
                            seen = True
                        continue
                    control.sendall(struct.pack("!HH", len(packet), source[1]) + packet)
                    response = (
                        dns_response(packet, control.getsockname()[0], peer_ipv4)
                        if family in (b"\x11", b"\x13")
                        else packet
                    )
                    if udp.sendto(response, source) != len(response):
                        return
    except (OSError, ValueError):
        # Client cancellation/failed association is recorded by the test driver.
        pass
    finally:
        SLOTS.release()


def dns_response(packet, ipv4, peer_ipv4=None):
    """Only the synthetic business name is answerable; never system DNS."""
    question = b"\x0dvcore-fixture\x04test\x00"
    peer_question = b"\x04peer\x07fixture\x04test\x00"
    if peer_ipv4 and packet[12 : 12 + len(peer_question)] == peer_question:
        question, ipv4 = peer_question, peer_ipv4
    if (
        len(packet) < 12 + len(question) + 4
        or packet[12 : 12 + len(question)] != question
    ):
        raise ValueError("unexpected DNS question (including magic names)")
    qtype = struct.unpack("!H", packet[-4:-2])[0]
    answer = socket.inet_pton(socket.AF_INET, ipv4) if qtype == 1 else b""
    response = bytearray(packet)
    response[2:4] = b"\x81\x80"
    response[6:8] = struct.pack("!H", int(bool(answer)))
    if answer:
        response.extend(b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04" + answer)
    return bytes(response)


def tls_context(version):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = version
    context.maximum_version = version
    context.set_ecdh_curve("X25519")
    context.load_cert_chain(
        os.environ["VCORE_ORIGIN_CERT"], os.environ["VCORE_ORIGIN_KEY"]
    )
    context.set_alpn_protocols(["h2", "http/1.1"])
    context.num_tickets = 0
    return context


def camouflage():
    """Container-only TLS 1.3 target for REALITY's authenticated handshake."""
    context = tls_context(ssl.TLSVersion.TLSv1_3)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("0.0.0.0", 24001))
        listener.listen(8)
        while True:
            stream, _ = listener.accept()
            stream.settimeout(5)
            try:
                with context.wrap_socket(stream, server_side=True) as secured:
                    secured.recv(1)
            except OSError:
                stream.close()


def main():
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit(
            "BLOCKED: this origin must be launched by the container harness"
        )
    if os.environ.get("VCORE_ORIGIN_CERT"):
        threading.Thread(target=camouflage, daemon=True).start()
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
