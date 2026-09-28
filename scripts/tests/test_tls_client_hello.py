"""RFC-shaped, in-memory ClientHello observations; no sockets or peers."""

import copy
import json
import unittest

from vcore_scripts.builds import CORE_DIR
from vcore_scripts.tls_client_hello import (
    compare_client_hellos,
    parse_client_hello,
    validate_capture,
)

# RFC 8446 vectors with synthetic random bytes, in their encoded order.
HELLO = bytes.fromhex(
    "010000590303"
    + "00" * 32
    + "0000041301c02f0100002c"
    + "000a00060004001d0017"
    + "000d0006000404030804"
    + "002b00050403040303"
    + "0010000b000908687474702f312e31"
)


def extensions_hello(extensions):
    body = HELLO[4:47] + len(extensions).to_bytes(2, "big") + extensions
    return b"\x01" + len(body).to_bytes(3, "big") + body


class ClientHelloTest(unittest.TestCase):
    def test_raw_official_fixture_detects_tampered_parsed_evidence(self):
        samples = json.loads(
            (CORE_DIR / "tests/fingerprints/mihomo-selected-v1.json").read_text()
        )["samples"]
        for sample in samples:
            self.assertEqual(validate_capture(sample), sample["parsed"])
        corrupted = copy.deepcopy(samples[0])
        corrupted["parsed"]["ciphers"].reverse()
        with self.assertRaises(ValueError):
            validate_capture(corrupted)

    def test_preserves_ordered_tls_vectors(self):
        hello = parse_client_hello(HELLO)
        self.assertEqual(hello["ciphers"], [0x1301, 0xC02F])
        self.assertEqual(
            hello["extensions"],
            [
                {"type": 10, "bytes": 6, "values": [29, 23]},
                {"type": 13, "bytes": 6, "values": [0x0403, 0x0804]},
                {"type": 43, "bytes": 5, "values": [0x0304, 0x0303]},
                {"type": 16, "bytes": 11, "protocols": ["http/1.1"]},
            ],
        )

    def test_retains_key_share_and_ech_layout_without_random_key_bytes(self):
        data = extensions_hello(
            bytes.fromhex("0033002b00290a0a000100001d0020" + "11" * 32)
            + bytes.fromhex("fe0d000f0000010001120004abababab0001ac")
        )

        hello = parse_client_hello(data)
        self.assertEqual(
            hello["extensions"],
            [
                {
                    "type": 51,
                    "bytes": 43,
                    "shares": [
                        {"group": 0x0A0A, "bytes": 1, "grease_data": "00"},
                        {"group": 29, "bytes": 32},
                    ],
                },
                {
                    "type": 65037,
                    "bytes": 15,
                    "hello_type": 0,
                    "kdf": 1,
                    "aead": 1,
                    "enc_bytes": 4,
                    "payload_bytes": 1,
                },
            ],
        )

    def test_comparison_ignores_random_bytes_but_not_order_or_lengths(self):
        random_changed = bytearray(HELLO)
        random_changed[6:38] = b"\x12" * 32
        self.assertEqual(compare_client_hellos(HELLO, bytes(random_changed)), [])
        cipher_changed = bytearray(HELLO)
        cipher_changed[41:45] = bytes.fromhex("c02f1301")
        self.assertIn("ciphers", compare_client_hellos(HELLO, bytes(cipher_changed)))
        reordered = extensions_hello(HELLO[59:69] + HELLO[49:59] + HELLO[69:])
        self.assertIn("extensions", compare_client_hellos(HELLO, reordered))
        self.assertEqual(
            compare_client_hellos(HELLO, reordered, shuffle_extensions=True), []
        )

    def test_reports_ticket_binder_sni_and_compression_structure(self):
        hello = parse_client_hello(
            extensions_hello(
                bytes.fromhex("00000009000700000474657374")
                + bytes.fromhex("001b00050400010002")
                + bytes.fromhex("00290030000b0005616263646500000000002120" + "55" * 32)
            )
        )
        self.assertEqual(
            hello["extensions"],
            [
                {"type": 0, "bytes": 9, "names": [{"type": 0, "name": "test"}]},
                {"type": 27, "bytes": 5, "values": [1, 2]},
                {"type": 41, "bytes": 48, "identities": [5], "binders": [32]},
            ],
        )

    def test_shuffle_keeps_grease_slots_and_share_group_relationships(self):
        grease = bytes.fromhex("0a0a0000")
        alpn = HELLO[78:]
        first = extensions_hello(grease + alpn)
        moved = extensions_hello(alpn + grease)
        self.assertIn(
            "extensions",
            compare_client_hellos(first, moved, shuffle_extensions=True),
        )
        group = bytes.fromhex("000a000400020a0a")
        share = bytes.fromhex("0033000700050a0a000100")
        linked = extensions_hello(group + share)
        unlinked = extensions_hello(group + share.replace(b"\x0a\x0a", b"\x1a\x1a"))
        self.assertIn(
            "grease_share_group_links", compare_client_hellos(linked, unlinked)
        )

    def test_rejects_truncated_duplicate_and_oversized_envelopes(self):
        malformed = [HELLO[:size] for size in range(len(HELLO))]
        malformed += [
            HELLO + b"\x00",
            b"\x00" * 65537,
            extensions_hello(bytes.fromhex("0012000000120000")),
        ]
        for data in malformed:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                parse_client_hello(data)


if __name__ == "__main__":
    unittest.main()
