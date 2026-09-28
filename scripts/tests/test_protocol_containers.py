"""Offline ownership/config checks; no server is launched on the host."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from vcore_scripts.container_udp_origin import main as origin_main
from vcore_scripts.container_udp_origin import serve as origin_serve
from vcore_scripts.protocol_containers import NETWORK, ContainerLab, ContainerPeer
from vcore_scripts.protocol_vmess_udp_ab import main, options
from vcore_scripts.protocol_vmess_udp_container import client_config


class ContainerTests(unittest.TestCase):
    def test_frozen_latest_image_is_single_run_owned(self):
        from vcore_scripts.protocol_containers import IMAGE, frozen_image

        network = dict(
            configuration=dict(mode="hostOnly", labels={"purpose": NETWORK}),
            status=dict(ipv4Subnet="192.0.2.0/24", ipv6Subnet="fd00::/64"),
        )
        digest = "sha256:" + "a" * 64
        inspection = dict(configuration=dict(descriptor=dict(digest=digest)))

        def command(*args, **_):
            return json.dumps([network if args[0] == "network" else inspection])

        with (
            tempfile.TemporaryDirectory() as root,
            patch("vcore_scripts.protocol_containers.command", side_effect=command),
            patch("vcore_scripts.protocol_containers.run_command") as pull,
        ):
            pull.return_value = SimpleNamespace(
                returncode=0, cleanup=True, stdout=b"ok"
            )
            with frozen_image(Path(root) / "image.log") as snapshot:
                first, second = ContainerLab({}), ContainerLab({})
                self.assertEqual(first.image, second.image)
                self.assertTrue(first.image.endswith("@" + digest))
                self.assertEqual(snapshot["digest"], digest)
                self.assertEqual(snapshot["tag"], IMAGE)
            self.assertEqual(pull.call_count, 1)
            ContainerLab({})
            self.assertEqual(
                pull.call_count, 2, "no image cache across independent runs"
            )

    def test_image_refresh_failure_never_falls_back_to_a_cached_image(self):
        from vcore_scripts.protocol_containers import frozen_image

        with (
            tempfile.TemporaryDirectory() as root,
            patch("vcore_scripts.protocol_containers.command") as inspect,
            patch("vcore_scripts.protocol_containers.run_command") as pull,
        ):
            pull.return_value = SimpleNamespace(
                returncode=1,
                cleanup=True,
                stdout=b"registry unavailable token=synthetic-secret",
            )
            log = Path(root) / "image.log"
            with self.assertRaisesRegex(RuntimeError, "image pull"), frozen_image(log):
                self.fail("failed refresh must not establish a frozen image scope")
            inspect.assert_not_called()
            self.assertIn("registry unavailable", log.read_text())
            self.assertNotIn("synthetic-secret", log.read_text())

    def test_dns_fixture_remains_owned_across_idle_business_phases(self):
        control, udp = MagicMock(), MagicMock()
        control.recv.return_value = b"\x11"
        control.getsockname.return_value = ("192.0.2.55", 24000)
        udp.getsockname.return_value = ("0.0.0.0", 53001)
        query = b"\x00" * 12 + b"\x0dvcore-fixture\x04test\x00\x00\x01\x00\x01"
        udp.recvfrom.return_value = (query, ("192.0.2.2", 40001))
        udp.sendto.side_effect = lambda data, _peer: len(data)
        with (
            patch("vcore_scripts.container_udp_origin.socket.socket") as socket,
            patch("vcore_scripts.container_udp_origin.SLOTS"),
            patch(
                "vcore_scripts.container_udp_origin.select.select",
                side_effect=[
                    ([], [], []),
                    ([udp], [], []),
                    ([control], [], []),
                ],
            ),
        ):
            socket.return_value.__enter__.return_value = udp
            origin_serve(control)
        udp.sendto.assert_called_once()
        self.assertEqual(udp.sendto.call_args.args[1], ("192.0.2.2", 40001))
        with (
            patch("vcore_scripts.container_udp_origin.socket.socket") as socket,
            patch("vcore_scripts.container_udp_origin.SLOTS"),
            patch(
                "vcore_scripts.container_udp_origin.time.monotonic",
                side_effect=[0, 241],
            ),
            patch("vcore_scripts.container_udp_origin.select.select") as wait,
        ):
            socket.return_value.__enter__.return_value = udp
            origin_serve(control)
        wait.assert_not_called()

    def test_quic_mtu_applies_only_to_the_owned_guest_network(self):
        lab = SimpleNamespace(
            run_id="fixture", mtu=1500, image="fixture@sha256:synthetic"
        )
        peer = ContainerPeer(lab, Path("fixture"), "quic")
        with (
            patch(
                "vcore_scripts.protocol_containers.command",
                side_effect=RuntimeError("captured launch"),
            ) as launch,
            self.assertRaisesRegex(RuntimeError, "captured launch"),
        ):
            peer.start(["peer"])
        arguments = launch.call_args.args
        self.assertEqual(
            arguments[arguments.index("--network") + 1], NETWORK + ",mtu=1500"
        )
        self.assertNotIn("--cap-add", arguments)
        self.assertNotIn("--publish", arguments)

    def test_long_roles_keep_bounded_distinct_owned_container_names(self):
        lab = SimpleNamespace(run_id="0123456789ab")
        roles = [
            "xhttp-stream-up-download-reality-tls-origin",
            "xhttp-stream-up-download-reality-tls-server",
            "xhttp-stream-up-download-reality-tls-upstream",
        ]
        peers = [ContainerPeer(lab, Path("fixture"), role) for role in roles]
        self.assertEqual(len({peer.name for peer in peers}), len(roles))
        for peer, role in zip(peers, roles, strict=True):
            self.assertLessEqual(len(peer.name), 63)
            self.assertIn(lab.run_id, peer.name)
            self.assertEqual(peer.record["role"], role)

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

    def test_inventory_failure_still_closes_log_capture(self):
        for error in [
            RuntimeError("isolated container operation failed: list"),
            TimeoutError("inventory query timed out"),
            json.JSONDecodeError("invalid inventory", "not-json", 0),
            KeyboardInterrupt(),
        ]:
            with self.subTest(error=type(error).__name__):
                peer = ContainerPeer(
                    SimpleNamespace(run_id="fixture"), Path("fixture"), "server"
                )
                peer.capture = MagicMock(record={"joined": True})
                with (
                    patch(
                        "vcore_scripts.protocol_containers.listing", side_effect=error
                    ) as listing,
                    patch("vcore_scripts.protocol_containers.command") as command,
                    self.assertRaises(type(error)) as raised,
                ):
                    peer.stop()
                self.assertIs(raised.exception, error)
                peer.capture.__exit__.assert_called_once_with(None, None, None)
                self.assertTrue(peer.record["log_cleanup"])
                self.assertFalse(peer.record["joined"])
                listing.assert_called_once_with()
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
