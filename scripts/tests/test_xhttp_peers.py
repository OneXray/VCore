"""Offline fixture contracts; no host listener is used."""

import unittest

from vcore_scripts.protocol_xhttp_peers import (
    client_config,
    identity_peer_config,
    peer_config,
)


class XhttpPeerTest(unittest.TestCase):
    def test_identity_probe_distinguishes_client_auth_from_root_trust(self):
        mihomo = identity_peer_config("M", "cert", "key", "ca")
        listener = mihomo["listeners"][0]
        self.assertEqual(listener["client-auth-type"], "require-and-verify")
        self.assertEqual(listener["client-auth-cert"], "ca")
        xray = identity_peer_config("XR", "cert", "key", "ca")
        tls = xray["inbounds"][0]["streamSettings"]["tlsSettings"]
        self.assertEqual(
            tls["certificates"][-1],
            {
                "certificateFile": "ca",
                "usage": "verify",
            },
        )
        self.assertEqual(tls["alpn"], ["h3"])

    def test_http_versions_are_explicit_and_download_uses_the_same_handler(self):
        for version in ("h1", "h2", "h3"):
            config = client_config(
                "192.0.2.1", "pin", version, "packet-up", download=True
            )
            node = config["proxies"][0]
            self.assertEqual(node["alpn"], ["http/1.1" if version == "h1" else version])
            self.assertEqual(node["xhttp-opts"]["download-settings"], {})
            self.assertNotIn("skip-cert-verify", node)
            self.assertEqual(config["listeners"][0]["proxy"], node["name"])

    def test_mux_is_not_substituted_for_packet_encoding(self):
        for protocol in ("h2mux", "smux", "yamux"):
            config = client_config("192.0.2.1", "pin", "h2", "packet-up", mux=protocol)
            node = config["proxies"][0]
            self.assertEqual(node["smux"], {"enabled": True, "protocol": protocol})
            self.assertEqual(node["packet-encoding"], "xudp")

    def test_h3_bridge_does_not_replace_the_native_vless_decoder(self):
        direct = peer_config("XR", "cert", "key")
        bridge = peer_config("XR", "cert", "key", decoder="192.0.2.2")
        self.assertEqual(direct["inbounds"][0]["protocol"], "vless")
        self.assertEqual(bridge["inbounds"][0]["protocol"], "dokodemo-door")
        self.assertEqual(bridge["inbounds"][0]["settings"]["port"], 23001)
        self.assertEqual(
            direct["inbounds"][0]["streamSettings"],
            bridge["inbounds"][0]["streamSettings"],
        )
        for config in (direct, bridge):
            self.assertEqual(len(config["inbounds"]), 1)
            stream = config["inbounds"][0]["streamSettings"]
            self.assertEqual(stream["tlsSettings"]["alpn"], ["h3"])
            self.assertEqual(stream["xhttpSettings"]["mode"], "auto")
