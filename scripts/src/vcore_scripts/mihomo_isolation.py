"""Owned fixture ports and a cross-process, fail-fast harness lock."""

from __future__ import annotations

import errno
import os
import socket
import tempfile
from contextlib import ExitStack, contextmanager
from pathlib import Path


class PortReservation:
    def __init__(self) -> None:
        self.ipv4 = ExitStack()
        self.ipv6 = ExitStack()

    def release_ipv4(self) -> None:
        # IPv4-only peers take these ports; IPv6 guards remain owned until exit.
        self.ipv4.close()

    def close(self) -> None:
        self.ipv4.close()
        self.ipv6.close()


def reserve_port(stack: ExitStack) -> tuple[int, PortReservation]:
    """Reserve TCP/UDP in both loopback families, before starting any traffic."""
    for _ in range(32):
        reservation = PortReservation()
        try:
            tcp = reservation.ipv4.enter_context(socket.socket())
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            udp = reservation.ipv4.enter_context(socket.socket(type=socket.SOCK_DGRAM))
            udp.bind(("127.0.0.1", port))
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                guard = reservation.ipv6.enter_context(
                    socket.socket(socket.AF_INET6, kind)
                )
                guard.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                guard.bind(("::1", port))
        except OSError as error:
            reservation.close()
            if error.errno == errno.EADDRINUSE:
                continue
            raise
        stack.callback(reservation.close)
        return port, reservation
    raise RuntimeError("could not reserve a dual-family loopback TCP/UDP port")


@contextmanager
def exclusive_run(path: Path | None = None):
    # Per-user temporary directory on macOS; uid also separates shared /tmp.
    # Never unlink a lock file: doing so could create two lockable inodes.
    suffix = f"-{os.getuid()}" if hasattr(os, "getuid") else ""
    path = path or Path(tempfile.gettempdir()) / f"vcore-mihomo-interop{suffix}.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags, 0o600), "r+b", buffering=0) as lock:
        # Windows byte-range locks need an existing byte. This is our lock file,
        # not a PID file or user configuration, and is never truncated.
        if os.fstat(lock.fileno()).st_size == 0:
            lock.write(b"\0")
        lock.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise
            raise RuntimeError(
                "another local mihomo harness is running; wait for that run to finish"
            ) from error
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
