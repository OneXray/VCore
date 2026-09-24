"""Read-only, bounded native qlog observer for the isolated identity diagnostic.

Return certificate failure categories only, never frames, keys, connection IDs,
request headers or peer addresses. Raw qlogs stay in the disposable container.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def summarize_trace(text):
    failures = []
    for line in text.splitlines(keepends=True):
        if not line.endswith("\n"):
            continue  # The native writer can still be appending the last record.
        row = json.loads(line.lstrip("\x1e"))
        if row.get("name") != "transport:connection_closed":
            continue
        data = row.get("data", {})
        code = data.get("connection_error", "")
        if data.get("initiator") != "local" or not code.startswith("crypto_error_"):
            continue
        # RFC 9001 CRYPTO_ERROR = 0x100 + the RFC 8446 TLS alert number.
        # quic-go's local crypto error deliberately leaves qlog.reason empty.
        categories = {
            "crypto_error_0x174": "certificate_required",
            "crypto_error_0x12d": "certificate_expired",
            "crypto_error_0x130": "unknown_ca",
        }
        category = categories.get(code)
        if category:
            failures.append({"tls_alert": code, "category": category})
    return failures


def main():
    files = sorted(Path("/data/qlog").glob("*.sqlog"))
    if len(files) > 128 or sum(path.stat().st_size for path in files) > 16 * 1024**2:
        raise ValueError("native identity trace exceeded diagnostic bound")
    print(
        json.dumps(
            {
                hashlib.sha256(path.name.encode()).hexdigest(): summarize_trace(
                    path.read_text()
                )
                for path in files
            }
        )
    )


if __name__ == "__main__":
    main()
