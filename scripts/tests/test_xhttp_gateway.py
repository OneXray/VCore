"""Offline external fixture contracts; real peers are container-only."""

import json
import unittest

from vcore_scripts.container_quic_observer import summarize_trace
from vcore_scripts.protocol_xhttp_gateway import gateway_config, sanitized_gateway_log


class XhttpGatewayTest(unittest.TestCase):
    def test_gateway_requires_client_auth_and_only_forwards_to_one_native_handler(self):
        config = gateway_config("192.0.2.10")
        self.assertTrue(config["admin"]["disabled"])
        server = config["apps"]["http"]["servers"]["fixture"]
        self.assertEqual(server["protocols"], ["h3"])
        self.assertEqual(server["listen"], [":23000"])
        self.assertTrue(server["automatic_https"]["disable"])
        auth = server["tls_connection_policies"][0]["client_authentication"]
        self.assertEqual(auth["mode"], "require_and_verify")
        self.assertEqual(
            auth["ca"],
            {
                "provider": "file",
                "pem_files": ["/data/fixture/root.pem"],
            },
        )
        handler = server["routes"][0]["handle"][0]
        self.assertEqual(handler["handler"], "reverse_proxy")
        self.assertEqual(handler["upstreams"], [{"dial": "192.0.2.10:23000"}])
        self.assertEqual(handler["transport"]["versions"], ["h2c"])
        # Negative flush_interval disables upstream cancellation on disconnect.
        self.assertNotIn("flush_interval", handler)

    def test_retained_gateway_log_has_protocol_evidence_without_request_identity(self):
        retained = sanitized_gateway_log(
            json.dumps(
                {
                    "level": "warn",
                    "msg": "aborting with incomplete response",
                    "upstream": "192.0.2.10:23000",
                    "error": "context canceled",
                    "request": {
                        "remote_ip": "192.0.2.20",
                        "uri": "/private-session?token=secret",
                        "headers": {"Authorization": ["private-value"]},
                        "proto": "HTTP/3.0",
                        "method": "GET",
                        "tls": {"proto": "h3", "client_common_name": "private-name"},
                    },
                }
            )
        )
        evidence = json.loads(retained)
        self.assertEqual(evidence["http_version"], "HTTP/3.0")
        self.assertEqual(evidence["alpn"], "h3")
        self.assertTrue(evidence["client_certificate_present"])
        for forbidden in ("192.0.2", "private-", "secret", "Authorization"):
            self.assertNotIn(forbidden, retained)

    def test_native_trace_evidence_requires_local_certificate_rejection(self):
        trace = {
            "name": "transport:connection_closed",
            "data": {
                "initiator": "local",
                "connection_error": "crypto_error_0x12d",
                # Native quic-go records local TLS alerts with an empty reason.
                "reason": "",
            },
        }
        observed = summarize_trace("\x1e" + json.dumps(trace) + "\n")
        self.assertEqual(
            observed,
            [{"tls_alert": "crypto_error_0x12d", "category": "certificate_expired"}],
        )
        trace["data"]["initiator"] = "remote"
        self.assertEqual(summarize_trace(json.dumps(trace) + "\n"), [])
        trace["data"]["initiator"] = "local"
        trace["data"]["connection_error"] = "idle_timeout"
        self.assertEqual(summarize_trace(json.dumps(trace) + "\n"), [])
