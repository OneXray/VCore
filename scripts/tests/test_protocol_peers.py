from __future__ import annotations

import os
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_peers import OwnedProcess, run_command


class OwnedPeerTest(unittest.TestCase):
    def test_success_is_bounded_and_records_exit_and_cleanup(self):
        result = run_command([sys.executable, "-c", "print('fixture')"], timeout=2)
        self.assertEqual(result.stdout, b"fixture\n")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.cleanup)

    def test_timeout_and_output_overflow_fail_and_join(self):
        for source, limit in [
            ("import time; time.sleep(60)", 128),
            ("print('x'*10000)", 64),
        ]:
            result = run_command(
                [sys.executable, "-c", source], timeout=0.2, limit=limit
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(result.cleanup)
            self.assertLessEqual(len(result.stdout), limit)

    def test_partial_start_and_permission_failure_do_not_leave_a_process(self):
        from unittest.mock import patch

        for error in [FileNotFoundError(), PermissionError()]:
            with (
                tempfile.TemporaryDirectory() as directory,
                patch("subprocess.Popen", side_effect=error),
            ):
                record = {}
                with (
                    self.assertRaises(type(error)),
                    OwnedProcess(["fixture"], Path(directory) / "private.log", record),
                ):
                    pass
                self.assertTrue(record["joined"])
                self.assertFalse(record["started"])

    def test_peer_exit_is_not_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            record = {}
            with OwnedProcess(
                [sys.executable, "-c", "raise SystemExit(3)"],
                Path(directory) / "private.log",
                record,
            ) as peer:
                peer.process.wait(timeout=2)
                with self.assertRaises(RuntimeError):
                    peer.ensure_alive()
            self.assertEqual(record["unexpected_exit"], 3)
            self.assertTrue(record["joined"])

    def test_cleanup_failure_is_explicit(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            record = {}
            peer = OwnedProcess(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                Path(directory) / "private.log",
                record,
            )
            peer.__enter__()
            try:
                with (
                    patch.object(
                        peer,
                        "_terminate",
                        side_effect=OSError("synthetic-private-marker"),
                    ),
                    self.assertRaises(OSError),
                ):
                    peer.__exit__(None, None, None)
                self.assertFalse(record["joined"])
            finally:
                peer._terminate()
                peer._finish_reader()

    def test_cancellation_joins_only_the_owned_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            record = {}
            with (
                self.assertRaises(KeyboardInterrupt),
                OwnedProcess(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    Path(directory) / "peer.log",
                    record,
                ) as peer,
            ):
                pid = peer.process.pid
                raise KeyboardInterrupt
            self.assertTrue(record["joined"])
            self.assertIsNotNone(peer.process.poll())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    @unittest.skipIf(os.name == "nt", "Unix process-group signal contract")
    def test_real_sigint_joins_nested_peer_without_stopping_unrelated_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            source = (
                "import signal, sys\nfrom pathlib import Path\n"
                "from vcore_scripts.protocol_peers import OwnedProcess\n"
                "with OwnedProcess([sys.executable, '-c', "
                "'import time; time.sleep(60)'], "
                "Path(sys.argv[1]), {}) as peer:\n"
                " print(peer.process.pid, flush=True)\n signal.pause()\n"
            )
            unrelated = {}
            with OwnedProcess(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                Path(directory) / "unrelated.log",
                unrelated,
            ) as sentinel:
                worker = subprocess.Popen(
                    [sys.executable, "-c", source, str(Path(directory) / "nested.log")],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                try:
                    ready, _, _ = select.select([worker.stdout], [], [], 5)
                    self.assertTrue(ready, "signal fixture did not start")
                    pid = int(worker.stdout.readline())
                    worker.send_signal(signal.SIGINT)
                    self.assertNotEqual(worker.wait(timeout=10), 0)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                    sentinel.ensure_alive()
                finally:
                    if worker.poll() is None:
                        worker.kill()
                        worker.wait(timeout=5)
                    worker.stdout.close()


if __name__ == "__main__":
    unittest.main()
