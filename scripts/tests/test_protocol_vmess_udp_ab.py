"""Small offline checks for diagnostic evidence extraction, not interop."""

import tempfile
import unittest
from pathlib import Path

from vcore_scripts.protocol_vmess_udp_ab import options, warning_summary


class UdpDiagnosticTests(unittest.TestCase):
    def test_matched_body_options(self):
        matrix = options(["raw", "xudp", "packetaddr"])
        self.assertEqual(len(matrix), 39)
        self.assertEqual(sum(item["cipher"] == "none" for item in matrix), 3)

    def test_loopback_ports_include_domain_and_exclude_timestamp(self):
        with tempfile.TemporaryDirectory() as root:
            log = Path(root) / "peer.log"
            log.write_text(
                'time="2026-09-23T10:27:13+08:00" level=warning '
                'msg="[UDP] 127.0.0.1:51243 --> vcore-fixture.test:63254 '
                'error: reject loopback connection to: vcore-fixture.test:63254"\n'
                'time="2026-09-23T10:27:14+08:00" level=warning '
                'msg="[UDP] 127.0.0.1:51386 --> [::1]:64969 '
                'error: reject loopback connection to: [::1]:64969"\n'
            )
            self.assertEqual(
                warning_summary(log)["loopback_rejections"],
                [{"ports": [51243, 63254, 63254]}, {"ports": [51386, 64969, 64969]}],
            )
