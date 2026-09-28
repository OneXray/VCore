"""Container-only ShadowTLS cover variations; no proxy protocol implementation."""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import threading
from pathlib import Path

import origin

EVENTS = Path("/data/cover-events.jsonl")
LOCK = threading.Lock()
SLOTS = threading.BoundedSemaphore(16)


def event(**value):
    with LOCK, EVENTS.open("a") as output:
        output.write(json.dumps(value) + "\n")


def handle(raw, context, port):
    try:
        with raw:
            raw.settimeout(5)
            with context.wrap_socket(raw, server_side=True) as tls:
                event(
                    port=port, version=tls.version(), alpn=tls.selected_alpn_protocol()
                )
                tls.recv(1)
    except OSError:
        pass
    finally:
        SLOTS.release()


def cover(port, version, curve):
    context = origin.tls_context(version)
    context.set_ecdh_curve(curve)
    context.set_alpn_protocols(["h2", "http/1.1", "fixture-custom"])
    with socket.socket(socket.AF_INET) as listener:
        listener.bind(("0.0.0.0", port))
        listener.listen(16)
        while True:
            raw, _ = listener.accept()
            if not SLOTS.acquire(blocking=False):
                raw.close()
                continue
            threading.Thread(
                target=handle, args=(raw, context, port), daemon=True
            ).start()


if __name__ == "__main__":
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit("isolated ShadowTLS fixture required")
    EVENTS.touch()
    for port, version, curve in (
        (24001, ssl.TLSVersion.TLSv1_3, "X25519"),
        (24002, ssl.TLSVersion.TLSv1_3, "secp384r1"),
        (24003, ssl.TLSVersion.TLSv1_2, "X25519"),
    ):
        threading.Thread(target=cover, args=(port, version, curve), daemon=True).start()
    # This fixture owns the cover workers; the shared origin still owns its
    # independent TCP/UDP control channel and business-byte observations.
    origin.camouflage = lambda: None
    origin.main()
