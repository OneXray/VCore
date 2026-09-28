"""Bounded one-way bandwidth origin, only inside the owned HYSTERIA2 container.

64-KiB records carry a sequence and deterministic payload. Upload progress is
timestamped at the actual origin, not inferred from the client's send buffer.
"""

import hashlib
import os
import select
import socket
import struct
import sys
import threading
import time

SIZE = 65536
END = (1 << 64) - 1
SLOTS = threading.BoundedSemaphore(4)


def exact(stream, size):
    value = bytearray()
    while len(value) < size:
        part = stream.recv(size - len(value))
        if not part:
            raise ValueError("truncated bandwidth record")
        value.extend(part)
    return bytes(value)


def record(sequence):
    return struct.pack("!Q", sequence) + bytes([sequence % 251]) * (SIZE - 8)


def serve(control):
    try:
        with control, socket.socket() as listener:
            control.settimeout(90)
            direction = exact(control, 1)
            if direction not in (b"U", b"D"):
                raise ValueError("invalid bandwidth direction")
            listener.bind(("0.0.0.0", 0))
            listener.listen(1)
            listener.settimeout(15)
            control.sendall(struct.pack("!H", listener.getsockname()[1]))
            stream, _ = listener.accept()
            with stream:
                stream.settimeout(30)
                stream.sendall(b"ready")
                digest, sequence = hashlib.sha256(), 0
                started = time.monotonic_ns()
                if direction == b"U":
                    while True:
                        data = exact(stream, SIZE)
                        number = struct.unpack("!Q", data[:8])[0]
                        if number == END:
                            break
                        if data != record(sequence):
                            raise ValueError("upload sequence or payload mismatch")
                        digest.update(data)
                        sequence += 1
                        control.sendall(
                            b"P"
                            + struct.pack(
                                "!QQ", sequence, time.monotonic_ns() - started
                            )
                        )
                    stream.sendall(b"done!")
                else:
                    if exact(stream, 1) != b"S":
                        raise ValueError("missing start")
                    while True:
                        ready, _, _ = select.select([stream], [], [], 0)
                        if ready:
                            if exact(stream, 1) != b"X":
                                raise ValueError("invalid stop")
                            break
                        data = record(sequence)
                        stream.sendall(data)
                        digest.update(data)
                        sequence += 1
                    stream.sendall(record(END))
                control.sendall(b"D" + struct.pack("!Q", sequence) + digest.digest())
    except (OSError, ValueError) as error:
        print(type(error).__name__, flush=True)
    finally:
        SLOTS.release()


def main():
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit("isolated container required")
    with socket.socket() as listener:
        listener.bind(("0.0.0.0", 24002))
        listener.listen(4)
        while True:
            control, _ = listener.accept()
            if SLOTS.acquire(blocking=False):
                threading.Thread(target=serve, args=(control,), daemon=True).start()
            else:
                control.close()


if __name__ == "__main__":
    main()
