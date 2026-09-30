"""Owned container HTTPS asset origin. No untrusted routing or trust overrides."""

import hashlib
import http.server
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path

ROOT = Path("/data/fixture")


class Server(http.server.HTTPServer):
    address_family = socket.AF_INET6

    def handle_error(self, *_):
        pass  # Readiness TCP probes do not complete TLS.


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def hold(self, control, sent):
        temporary = ROOT / "response.partial"
        temporary.write_text(
            json.dumps(
                {
                    "token": control["token"],
                    "asset": control["asset"],
                    "mode": control["mode"],
                    "held_payload_bytes": sent,
                }
            )
        )
        temporary.replace(ROOT / "response.json")
        deadline = time.monotonic() + 60
        while not json.loads((ROOT / "control.json").read_text()).get("release"):
            if time.monotonic() > deadline:
                return False
            time.sleep(0.02)
        return True

    def do_GET(self):
        control = json.loads((ROOT / "control.json").read_text())
        kind, mode = control.get("asset"), control.get("mode")
        if kind not in ("geosite", "geoip") or self.path != f"/{kind}.dat":
            self.send_error(404)
            return
        if mode == "not-modified":
            if self.headers.get("If-None-Match") != control["etag"]:
                self.send_error(412)
                return
            if not self.hold(control, 0):
                return
            self.send_response(304)
            self.send_header("ETag", control["etag"])
            self.end_headers()
            return
        if mode == "corrupt":
            body = b"invalid candidate"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body[:1])
            self.wfile.flush()
            if self.hold(control, 1):
                self.wfile.write(body[1:])
            return
        asset = ROOT / (kind + ".dat")
        with asset.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
            source.seek(0)
            self.send_response(200)
            self.send_header("ETag", '"' + digest + '"')
            self.send_header("Content-Length", str(asset.stat().st_size))
            self.end_headers()
            prefix = source.read(65536)
            self.wfile.write(prefix)
            self.wfile.flush()
            if not self.hold(control, len(prefix)):
                return
            while data := source.read(65536):
                self.wfile.write(data)


def main():
    if sys.platform != "linux" or os.environ.get("VCORE_ISOLATED_ORIGIN") != "1":
        raise SystemExit("HTTPS origin requires an owned isolated Linux container")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(ROOT / "cert.pem", ROOT / "key.pem")
    with Server(("::", 24443), Handler) as server:
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
