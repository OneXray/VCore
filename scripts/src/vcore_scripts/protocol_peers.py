"""Owned native-peer processes. Stop is a wait barrier, never a global prune."""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from pathlib import Path


class OwnedProcess:
    def __init__(self, command: list[str], log: Path, record: dict):
        self.command, self.log_path, self.record = command, log, record
        self.process = None
        self.log = None

    def __enter__(self):
        self.record.update(started=False, joined=False)
        self.log = self.log_path.open("wb")
        try:
            self.process = subprocess.Popen(
                self.command,
                stdout=self.log,
                stderr=subprocess.STDOUT,
                start_new_session=os.name != "nt",
            )
        except BaseException:
            self.log.close()
            self.record["joined"] = True
            raise
        self.record["started"] = True
        return self

    def ensure_alive(self):
        if self.process.poll() is not None:
            self.record["unexpected_exit"] = self.process.returncode
            raise RuntimeError("native peer exited before case completion")

    def wait_tcp(self, port: int, seconds: float = 10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.ensure_alive()
            try:
                with socket.create_connection(("127.0.0.1", port), 0.1):
                    self.record["ready"] = True
                    return
            except OSError:
                time.sleep(0.02)
        raise TimeoutError("native peer readiness timeout")

    def __exit__(self, *_):
        try:
            if self.process.poll() is None:
                if os.name == "nt":
                    self.process.terminate()
                else:
                    os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if os.name == "nt":
                        self.process.kill()
                    else:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=5)
            self.record.update(joined=True, exit_code=self.process.returncode)
        finally:
            self.log.close()
