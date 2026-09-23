from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_peers import OwnedProcess


class OwnedPeerTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
