"""Restart only this guest's owned, unmodified protocol child on a fixture command."""

from __future__ import annotations

import os
import select
import socket
import subprocess
import sys
import time


def terminate(peer):
    peer.terminate()
    try:
        peer.wait(timeout=3)
    except subprocess.TimeoutExpired:
        peer.kill()
        peer.wait(timeout=3)


def start(argv):
    peer = subprocess.Popen(argv)
    try:
        until = time.monotonic() + 10
        while peer.poll() is None and time.monotonic() < until:
            try:
                with socket.create_connection(("127.0.0.1", 23999), timeout=0.1):
                    return peer
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("owned protocol child not ready")
    except BaseException:
        terminate(peer)
        raise


def main():
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit("isolated restart peer required")
    peer = start(sys.argv[1:])
    try:
        with socket.socket() as control:
            control.bind(("0.0.0.0", 23998))
            control.listen(4)
            while peer.poll() is None:
                ready, _, _ = select.select([control], [], [], 0.1)
                if not ready:
                    continue
                client, _ = control.accept()
                with client:
                    client.settimeout(2)
                    if client.recv(1) == b"R":
                        terminate(peer)
                        peer = start(sys.argv[1:])
                        client.sendall(b"R")
            raise RuntimeError("owned protocol child exited")
    finally:
        terminate(peer)


if __name__ == "__main__":
    main()
