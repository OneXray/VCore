"""External raw-IP client ownership and bounded local IPC; never a proxy peer."""

import contextlib
import ipaddress
import json
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path


def receive(stream, length):
    result = bytearray()
    while len(result) < length:
        chunk = stream.recv(length - len(result))
        if not chunk:
            raise EOFError("external TUN client closed")
        result.extend(chunk)
    return bytes(result)


def connect(path, host, port, *, udp=False):
    address = ipaddress.ip_address(host)
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        stream.settimeout(5)
        stream.connect(str(path))
        stream.sendall(
            struct.pack("!BBH", 2 if udp else 1, address.version, port)
            + address.packed.ljust(16, b"\0")
        )
        if receive(stream, 1) != b"\0":
            raise RuntimeError("external TUN client connection rejected")
        return stream
    except BaseException:
        stream.close()
        raise


def resolve(path, name, expected):
    version = ipaddress.ip_address(expected).version
    qtype = 28 if version == 6 else 1
    query = struct.pack("!6H", 2026, 0x100, 1, 0, 0, 0)
    for label in name.rstrip(".").encode("ascii").split(b"."):
        if not 1 <= len(label) <= 63:
            raise ValueError("invalid controlled DNS label")
        query += bytes([len(label)]) + label
    query += b"\0" + struct.pack("!HH", qtype, 1)
    with connect(path, "198.18.0.1", 53, udp=True) as stream:
        stream.sendall(struct.pack("!H", len(query)) + query)
        reply = receive(stream, struct.unpack("!H", receive(stream, 2))[0])
    # The isolated fixture has exactly one address RR; match identity/question,
    # successful answer and final typed RDATA before trusting the DNS hint.
    if not (
        reply[:2] == query[:2]
        and reply[2:4] == b"\x81\x80"
        and reply[4:8] == b"\0\x01\0\x01"
        and reply[12 : len(query)] == query[12:]
        and reply.endswith(ipaddress.ip_address(expected).packed)
    ):
        raise RuntimeError("TUN DNS response did not match isolated origin")


class TunClient:
    def __init__(self, root, work):
        self.root, self.work = root, work
        self.host, self.raw = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.host.setblocking(False)
        self.raw.setblocking(False)
        self.directory = tempfile.TemporaryDirectory(prefix="vcore-tun-")
        self.path = Path(self.directory.name) / "client.sock"
        self.process = None
        self.record = {"joined": False, "entrypoint": "fd-TUN", "framing": "utun"}
        self.log = None

    def __enter__(self):
        try:
            self.log = (self.work / "tun-client.log").open("wb")
            self.process = subprocess.Popen(
                [
                    str(self.root / "artifacts/tun-driver"),
                    str(self.raw.fileno()),
                    str(self.path),
                ],
                pass_fds=(self.raw.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=self.log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            deadline = time.monotonic() + 5
            while not self.path.exists():
                if self.process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("external TUN client did not become ready")
                time.sleep(0.01)
            return self
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            if self.process is not None:
                if self.process.poll() is None:
                    with (
                        contextlib.suppress(OSError),
                        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream,
                    ):
                        stream.settimeout(1)
                        stream.connect(str(self.path))
                        stream.sendall(b"\0")
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=5)
                self.record.update(joined=True, exit_code=self.process.returncode)
            if self.log:
                self.log.close()
                with contextlib.suppress(ValueError, IndexError):
                    self.record["traffic"] = json.loads(
                        (self.work / "tun-client.log").read_bytes().splitlines()[0]
                    )
        finally:
            self.host.close()
            self.raw.close()
            self.directory.cleanup()

    def __exit__(self, *_):
        self.close()
