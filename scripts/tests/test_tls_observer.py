"""The observer is tested over injected byte streams, never host listeners."""

import io
import os
import unittest
from unittest.mock import patch

from vcore_scripts.container_tls_observer import capture_client_hello, main


class TlsObserverTest(unittest.TestCase):
    def test_observer_refuses_host_execution_before_any_listener(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(RuntimeError):
            main()

    def test_captures_fragmented_hello_and_retains_record_layout(self):
        raw = bytes.fromhex("160301000301000016030300020100")
        records, hello, layout = capture_client_hello(io.BytesIO(raw).read)
        self.assertEqual(records, raw)
        self.assertEqual(hello, bytes.fromhex("0100000100"))
        self.assertEqual(
            layout,
            [
                {"type": 22, "version": 0x0301, "bytes": 3},
                {"type": 22, "version": 0x0303, "bytes": 2},
            ],
        )


if __name__ == "__main__":
    unittest.main()
