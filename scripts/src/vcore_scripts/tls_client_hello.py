"""Bounded, offline TLS ClientHello inspection, not a TLS implementation."""

from __future__ import annotations

import base64
import hashlib
import io

from .container_tls_observer import capture_client_hello


class Cursor:
    def __init__(self, data: bytes):
        self.data, self.at = data, 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.at + size > len(self.data):
            raise ValueError("truncated ClientHello")
        result = self.data[self.at : self.at + size]
        self.at += size
        return result

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def vector(self, size: int) -> bytes:
        return self.take(self.number(size))

    def done(self):
        if self.at != len(self.data):
            raise ValueError("unparsed ClientHello data")


def _codes(data: bytes) -> list[int]:
    if len(data) % 2:
        raise ValueError("odd TLS uint16 vector")
    return [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)]


def is_grease(value: int) -> bool:
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def _shape(hello: dict, shuffle_extensions: bool) -> dict:
    def normalize(value, key=""):
        if isinstance(value, dict):
            return {k: normalize(v, k) for k, v in value.items() if k != "raw_sha256"}
        if isinstance(value, list):
            return [normalize(v, key) for v in value]
        if key in {"ciphers", "values", "type", "group"} and isinstance(value, int):
            return "GREASE" if is_grease(value) else value
        return value

    result = normalize(hello)
    groups = next((e["values"] for e in hello["extensions"] if e["type"] == 10), [])
    shares = next((e["shares"] for e in hello["extensions"] if e["type"] == 51), [])
    result["grease_share_group_links"] = [
        [i for i, group in enumerate(groups) if group == share["group"]]
        for share in shares
        if is_grease(share["group"])
    ]
    if shuffle_extensions:
        # Preserve GREASE/padding/PSK positions, sort ONLY the shuffled slots.
        rows = result["extensions"]
        slots = [
            i for i, row in enumerate(rows) if row["type"] not in {"GREASE", 21, 41}
        ]
        ordered = sorted((rows[i] for i in slots), key=lambda row: row["type"])
        for index, row in zip(slots, ordered, strict=True):
            rows[index] = row
    return result


def compare_client_hellos(
    expected: bytes, observed: bytes, *, shuffle_extensions: bool = False
) -> list[str]:
    """Return differing structural fields; no blanket JA3/ECH/PSK exemption.

    Random values are normalized, not their widths or positions. A caller may
    separately classify an observed ECH/padding length variant using its pinned
    template; it is intentionally still reported here.
    """
    left = _shape(parse_client_hello(expected), shuffle_extensions)
    right = _shape(parse_client_hello(observed), shuffle_extensions)
    return [
        key
        for key in sorted(left.keys() | right.keys())
        if left.get(key) != right.get(key)
    ]


def validate_capture(record: dict) -> dict:
    """Recompute the retained observation from raw records, not PASS text."""
    if any(
        len(record[key]) > 256 * 1024 for key in ("client_hello_b64", "records_b64")
    ):
        raise ValueError("capture size limit")
    wire = base64.b64decode(record["records_b64"], validate=True)
    raw = base64.b64decode(record["client_hello_b64"], validate=True)
    records, handshake, layout = capture_client_hello(io.BytesIO(wire).read)
    parsed = parse_client_hello(raw)
    if records != wire or handshake != raw or layout != record["records"]:
        raise ValueError("TLS records differ from retained ClientHello")
    if parsed != record["parsed"]:
        raise ValueError("ClientHello evidence differs from raw capture")
    return parsed


def parse_client_hello(data: bytes) -> dict:
    """Observe an entire handshake message, including its four-byte envelope."""
    if len(data) > 65536:
        raise ValueError("ClientHello size limit")
    cursor = Cursor(data)
    if cursor.number(1) != 1 or cursor.number(3) != len(data) - 4:
        raise ValueError("invalid ClientHello envelope")
    result = {"bytes": len(data), "legacy_version": cursor.number(2)}
    cursor.take(32)
    result["session_id_bytes"] = len(cursor.vector(1))
    result["ciphers"] = _codes(cursor.vector(2))
    result["compression_methods"] = list(cursor.vector(1))
    extensions = Cursor(cursor.vector(2))
    cursor.done()
    result["extensions"] = []
    seen = set()
    while extensions.at < len(extensions.data):
        kind, payload = extensions.number(2), extensions.vector(2)
        if kind in seen or len(seen) >= 128:
            raise ValueError("duplicate or excessive ClientHello extensions")
        seen.add(kind)
        row = {"type": kind, "bytes": len(payload)}
        value = Cursor(payload)
        if kind in (10, 13, 34, 50):
            row["values"] = _codes(value.vector(2))
        elif kind in (27, 43):
            row["values"] = _codes(value.vector(1))
        elif kind == 0:
            names = Cursor(value.vector(2))
            row["names"] = []
            while names.at < len(names.data):
                row["names"].append(
                    {"type": names.number(1), "name": names.vector(2).decode("ascii")}
                )
        elif kind in (16, 17513, 17613):
            protocols = Cursor(value.vector(2))
            row["protocols"] = []
            while protocols.at < len(protocols.data):
                row["protocols"].append(protocols.vector(1).decode("ascii"))
        elif kind == 51:
            shares = Cursor(value.vector(2))
            row["shares"] = []
            while shares.at < len(shares.data):
                group, key = shares.number(2), shares.vector(2)
                share = {"group": group, "bytes": len(key)}
                if is_grease(group):
                    share["grease_data"] = key.hex()
                elif group in (23, 24, 25) and key:
                    share["point_format"] = key[0]
                row["shares"].append(share)
        elif kind == 65037:
            row["hello_type"] = value.number(1)
            if row["hello_type"] != 0:
                raise ValueError("expected outer ECH structure")
            row["kdf"], row["aead"] = value.number(2), value.number(2)
            value.take(1)  # Random GREASE config_id remains in the raw evidence.
            row["enc_bytes"] = len(value.vector(2))
            row["payload_bytes"] = len(value.vector(2))
        elif kind == 35:
            row["ticket_bytes"] = len(value.take(len(payload)))
        elif kind == 41:
            identities = Cursor(value.vector(2))
            row["identities"] = []
            while identities.at < len(identities.data):
                row["identities"].append(len(identities.vector(2)))
                identities.take(4)  # Obfuscated age is time-dependent.
            binders = Cursor(value.vector(2))
            row["binders"] = []
            while binders.at < len(binders.data):
                row["binders"].append(len(binders.vector(1)))
            if not row["identities"] or len(row["identities"]) != len(row["binders"]):
                raise ValueError("invalid PSK identity/binder counts")
        else:
            row["payload_hex"] = value.take(len(payload)).hex()
        value.done()
        result["extensions"].append(row)
    result["raw_sha256"] = hashlib.sha256(data).hexdigest()
    return result
