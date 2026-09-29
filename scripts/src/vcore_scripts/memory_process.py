"""Whole-PID Darwin measurement with kernel peaks and an acknowledged exit barrier."""

from __future__ import annotations

import contextlib
import ctypes
import json
import os
import select
import signal
import subprocess
import threading
import time
from pathlib import Path

from .builds import CORE_DIR

LIMIT = 50_000_000
FIXTURES = CORE_DIR / "tests/memory"


def build_observer(work: Path) -> dict:
    work.mkdir(parents=True, exist_ok=True)
    compiler = ["xcrun", "clang", "-O2", "-Wall", "-Wextra", "-Werror"]
    observer = work / "observer.dylib"
    host = work / "empty-host"
    commands = [
        compiler + ["-dynamiclib", str(FIXTURES / "observer.c"), "-o", str(observer)],
        compiler
        + [
            "-DMEMORY_EMPTY_HOST",
            str(FIXTURES / "host.c"),
            str(FIXTURES / "observer.c"),
            "-o",
            str(host),
        ],
    ]
    for command in commands:
        subprocess.run(command, check=True, timeout=60)
    (work / "observer-build.json").write_text(
        json.dumps({"commands": commands, "exit_codes": [0, 0]}, indent=2) + "\n"
    )
    return {"observer": observer, "empty": host}


class _Sample(ctypes.Structure):
    _fields_ = [
        (key, ctypes.c_uint64)
        for key in ("start", "footprint", "peak", "rss", "user_ns", "system_ns")
    ] + [("image_uuid", ctypes.c_uint8 * 16)]


class Observer:
    def __init__(self, library: Path):
        self.library = ctypes.CDLL(str(library), use_errno=True)
        self.library.memory_external.argtypes = [ctypes.c_int, ctypes.POINTER(_Sample)]
        self.library.memory_external.restype = ctypes.c_int

    def sample(self, pid: int) -> dict:
        sample = _Sample()
        if self.library.memory_external(pid, ctypes.byref(sample)):
            raise OSError(ctypes.get_errno(), "kernel memory sampling failed")
        return {key: getattr(sample, key) for key, _ in _Sample._fields_[:-1]} | {
            "pid": pid,
            "image_uuid": bytes(sample.image_uuid).hex(),
        }


class MeasuredProcess:
    """Invoke/observe/finalize one owned PID; output and sampling are bounded.

    A missing sample, identity change, crash, or absent final barrier is INVALID.
    Finalize is called only after the caller has joined business work and destroyed
    the public instance. Killing a child is cleanup, never successful measurement.
    """

    def __init__(
        self, executable: Path, observer: Path, work: Path, *, diagnostic=False
    ):
        if any(key.startswith(("Malloc", "DYLD_")) for key in os.environ):
            raise ValueError("unset inherited allocator/tracer overrides")
        work.mkdir(parents=True, exist_ok=True)
        self.work = work
        self.observer = Observer(observer)
        self.stage = "spawn"
        self.record = {
            "status": "INVALID",
            "cleanup": False,
            "final_barrier": False,
            "sampling_errors": [],
            "peak_bytes": 0,
            "diagnostic": diagnostic,
        }
        self.lock = threading.RLock()
        self.finished = threading.Event()
        self.stderr = (work / "host.log").open("wb")
        self.timeline = (work / "timeline.jsonl").open("w")
        try:
            self.child = subprocess.Popen(
                [str(executable)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.stderr,
                start_new_session=True,
                bufsize=0,
                env=os.environ
                | (
                    {
                        "MallocStackLogging": "full",
                        "MallocStackLoggingDirectory": str(work.resolve()),
                    }
                    if diagnostic
                    else {}
                ),
            )
        except BaseException:
            self.stderr.close()
            self.timeline.close()
            raise
        os.set_blocking(self.child.stdin.fileno(), False)
        self.record["pid"] = self.child.pid
        self.identity = None
        self.instance = None
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.buffer = bytearray()
        try:
            first = self.receive()
            self.record["self_initial"] = first
            self.crosscheck(first)
            self.thread.start()
        except BaseException:
            self.close()
            raise

    def _write(self, row):
        self.timeline.write(
            json.dumps(
                {"monotonic_ns": time.monotonic_ns(), "stage": self.stage, **row}
            )
            + "\n"
        )
        self.timeline.flush()

    def sample(self):
        with self.lock:
            row = self.observer.sample(self.child.pid)
            identity = (row["start"], row["image_uuid"])
            if self.identity is None:
                self.identity = identity
                self.record["identity"] = {
                    "start": identity[0],
                    "image_uuid": identity[1],
                }
            if identity != self.identity:
                raise RuntimeError("measured PID identity changed")
            self.record["peak_bytes"] = max(self.record["peak_bytes"], row["peak"])
            self.record["sampled_current_max_bytes"] = max(
                self.record.get("sampled_current_max_bytes", 0), row["footprint"]
            )
            self._write({"observer": "libproc", **row})
            return row

    def _monitor(self):
        while not self.finished.is_set():
            try:
                self.sample()
                if self.stderr.tell() > 1024 * 1024:
                    raise RuntimeError("host log exceeded bound")
            except (OSError, RuntimeError) as error:
                self.record["sampling_errors"].append(str(error))
                return
            self.finished.wait(0.02)

    def receive(self, timeout=30):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if (
                remaining <= 0
                or not select.select([self.child.stdout], [], [], remaining)[0]
            ):
                raise TimeoutError("native host response timed out")
            data = os.read(self.child.stdout.fileno(), 4096)
            if not data:
                raise RuntimeError("native host exited before final barrier")
            self.buffer.extend(data)
            if len(self.buffer) > 65536:
                raise RuntimeError("native host response exceeds bound")
        raw, _, tail = self.buffer.partition(b"\n")
        self.buffer = bytearray(tail)
        return json.loads(raw)

    def command(self, command, timeout=30):
        raw = command.encode() + b"\n"
        if len(raw) >= 65536:
            raise ValueError("measurement control request exceeds bound")
        self._send(raw, timeout)
        return self.receive(timeout)

    def _send(self, raw, timeout=30):
        deadline = time.monotonic() + timeout
        while raw:
            remaining = deadline - time.monotonic()
            if (
                remaining <= 0
                or not select.select([], [self.child.stdin], [], remaining)[1]
            ):
                raise TimeoutError("native host control write timed out")
            written = os.write(self.child.stdin.fileno(), raw)
            if not written:
                raise RuntimeError("native host control pipe closed")
            raw = raw[written:]

    def crosscheck(self, internal):
        external = self.sample()
        if (
            internal["pid"] != self.child.pid
            or internal["start"] != external["start"]
            or internal["peak"] > external["peak"]
            or abs(external["peak"] - internal["peak"]) > 1024 * 1024
        ):
            self.record["sampling_errors"].append(
                "self/external PID or counters disagree"
            )
            raise RuntimeError("self/external PID or byte counters disagree")
        with self.lock:
            self._write({"observer": "TASK_VM_INFO", **internal})

    def boundary(self, stage):
        self.stage = stage
        internal = self.command("S")
        self.crosscheck(internal)
        return internal

    def invoke(self, method, payload=None, instance=None):
        self.stage = method
        self.sample()
        request = {"apiVersion": 5, "method": method, "payload": payload or {}}
        if instance is not None:
            request["instanceId"] = instance
        response = self.command("I " + json.dumps(request, separators=(",", ":")))
        if response.get("success"):
            if method == "createInstance":
                self.instance = response["data"]["instanceId"]
            elif method == "destroyInstance":
                self.instance = None
        self.boundary(method + ":returned")
        return response

    def finalize(self):
        if self.instance is not None:
            self.record["business_cleanup"] = False
            raise RuntimeError("public instance must be destroyed before final barrier")
        self.record["business_cleanup"] = True
        self.stage = "final-barrier"
        internal = self.command("F")
        self.crosscheck(internal)
        self.record["self_final"] = internal
        self.record["final_current_bytes"] = internal["footprint"]
        self.finished.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("memory observer failed to join")
        self.sample()
        self.record["final_barrier"] = not self.record["sampling_errors"]
        self._send(b"E")
        self._reap()

    def _reap(self, *, block=True):
        if self.child.returncode is not None:
            return True
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            pid, status, usage = os.wait4(self.child.pid, os.WNOHANG)
            if pid:
                self.child.returncode = os.waitstatus_to_exitcode(status)
                self.record.update(
                    exit_code=self.child.returncode,
                    wait4_max_rss_bytes=usage.ru_maxrss,
                    user_seconds=usage.ru_utime,
                    system_seconds=usage.ru_stime,
                )
                return True
            if not block:
                return False
            time.sleep(0.01)
        raise TimeoutError("native host did not exit")

    def close(self):
        self.finished.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=2)
        try:
            if not self._reap(block=False):
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.child.pid, signal.SIGKILL)
                self._reap()
            self.record["cleanup"] = not self.thread.is_alive()
        finally:
            for stream in (
                self.child.stdin,
                self.child.stdout,
                self.stderr,
                self.timeline,
            ):
                stream.close()
        if (
            self.record["cleanup"]
            and self.record["final_barrier"]
            and self.record.get("exit_code") == 0
            and not self.record["sampling_errors"]
        ):
            self.record["status"] = (
                "DIAGNOSTIC"
                if self.record["diagnostic"]
                else "FAIL_MEMORY"
                if self.record["peak_bytes"] > LIMIT
                else "PASS"
            )
        self.record["peak_mib"] = self.record["peak_bytes"] / (1024 * 1024)
        self.record["margin_bytes"] = LIMIT - self.record["peak_bytes"]
        (self.work / "measurement.json").write_text(
            json.dumps(self.record, indent=2) + "\n"
        )


def calibration(name: str, artifacts: dict, work: Path) -> dict:
    process = MeasuredProcess(artifacts["empty"], artifacts["observer"], work)
    try:
        if name == "transient":
            # Hold the observer lock to deliberately miss the live excursion.
            # The next kernel high-water reading MUST still detect it.
            with process.lock:
                start = time.monotonic_ns()
                process.crosscheck(process.command("A 67108864"))
                process.record["excursion_control_ns"] = time.monotonic_ns() - start
        elif name == "over-limit":
            process.crosscheck(process.command("H 96000000"))
            time.sleep(0.1)
            process.crosscheck(process.command("R"))
        elif name == "wrong-pid":
            try:
                process.crosscheck(process.observer.sample(os.getpid()))
            except RuntimeError as error:
                process.record["failure"] = str(error)
        elif name == "sampling-failure":
            try:
                process.observer.sample(-1)
            except OSError as error:
                process.record["sampling_errors"].append(str(error))
        elif name == "crash":
            try:
                process.command("X")
            except RuntimeError as error:
                process.record["failure"] = str(error)
            return process.record
        elif name == "missing-final":
            return process.record
        elif name != "empty":
            raise ValueError("unknown memory calibration")
        process.finalize()
    finally:
        process.close()
    return process.record
