"""Offline ownership/config checks; no server is launched on the host."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from vcore_scripts.container_udp_origin import main as origin_main
from vcore_scripts.protocol_containers import NETWORK, ContainerLab, ContainerPeer
from vcore_scripts.protocol_vmess_udp_ab import main, options
from vcore_scripts.protocol_vmess_udp_container import client_config


class ContainerTests(unittest.TestCase):
    def test_non_private_network_fails_before_image_or_launch(self):
        network = dict(configuration=dict(mode="shared", labels={"purpose": NETWORK}))
        with (
            patch(
                "vcore_scripts.protocol_containers.command",
                return_value=json.dumps([network]),
            ) as command,
            self.assertRaisesRegex(RuntimeError, "host-only"),
        ):
            ContainerLab({})
        command.assert_called_once_with("network", "inspect", NETWORK)

    def test_ownership_mismatch_never_deletes(self):
        lab = SimpleNamespace(run_id="fixture")
        with tempfile.TemporaryDirectory() as root:
            peer = ContainerPeer(lab, Path(root), "server")
            unrelated = dict(
                id=peer.name, configuration=dict(labels={"purpose": "other"})
            )
            with (
                patch(
                    "vcore_scripts.protocol_containers.listing",
                    return_value=[unrelated],
                ),
                patch("vcore_scripts.protocol_containers.command") as command,
                self.assertRaisesRegex(RuntimeError, "ownership"),
            ):
                peer.stop()
            command.assert_not_called()

    def test_cleanup_only_owned_vm_and_verifies_absence(self):
        lab = SimpleNamespace(run_id="fixture")
        with tempfile.TemporaryDirectory() as root:
            peer = ContainerPeer(lab, Path(root), "server")
            owned = dict(
                id=peer.name,
                configuration=dict(labels={"purpose": NETWORK, "vcore-run": "fixture"}),
                status=dict(state="running"),
            )
            other = dict(id="another-task")
            with (
                patch(
                    "vcore_scripts.protocol_containers.listing",
                    side_effect=[[owned, other], [other]],
                ),
                patch("vcore_scripts.protocol_containers.command") as command,
            ):
                peer.stop()
            self.assertEqual(
                [call.args for call in command.call_args_list],
                [
                    ("stop", "--time", "5", peer.name),
                    ("delete", "--force", peer.name),
                ],
            )
            self.assertTrue(peer.record["joined"])

    def test_failed_launch_still_registers_cleanup(self):
        lab = ContainerLab.__new__(ContainerLab)
        lab.run_id, lab.record = "fixture", {"peers": []}
        with (
            patch.object(
                ContainerPeer, "start", side_effect=RuntimeError("partial launch")
            ),
            patch.object(ContainerPeer, "stop") as stop,
        ):
            with (
                self.assertRaisesRegex(RuntimeError, "partial launch"),
                contextlib.ExitStack() as stack,
            ):
                lab.start(stack, Path("fixture"), "server", [])
            stop.assert_called_once()

    def test_no_native_origin_entry_or_archived_host_probe(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            self.assertRaisesRegex(SystemExit, "container harness"),
        ):
            origin_main()
        for option in ["--collision-probe", "--socket-probe"]:
            with (
                patch("sys.argv", ["diagnostic", "unused", option]),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as error:
                    main()
                self.assertEqual(error.exception.code, 2)

    def test_client_server_and_origins_use_distinct_container_addresses(self):
        config, selected = client_config(
            options(["raw", "xudp", "packetaddr"]),
            "ws",
            True,
            "192.0.2.2",
            "192.0.2.3",
            "192.0.2.4",
            "fixture-pin",
        )
        self.assertEqual(len(selected), 39)
        self.assertEqual({item["socks_host"] for item in selected}, {"192.0.2.4"})
        self.assertEqual(
            {item["listen"] for item in config["listeners"]}, {"192.0.2.4"}
        )
        self.assertEqual({item["server"] for item in config["proxies"]}, {"192.0.2.2"})
        self.assertEqual(config["hosts"]["vcore-fixture.test"], "192.0.2.3")
        self.assertEqual(config["rules"], ["MATCH,REJECT"])
        self.assertNotIn("packet-encoding", config["proxies"][0])


if __name__ == "__main__":
    unittest.main()
