from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from vcore_scripts import cli


class N9AcceptanceTest(unittest.TestCase):
    def test_native_source_identity_and_cleanup_are_required(self):
        from vcore_scripts.protocol_n9_checks import envelope

        identity = dict(
            version="official-test",
            binary_sha256="a" * 64,
            archive_sha256="b" * 64,
            source_url="https://github.com/MetaCubeX/mihomo/releases/latest/download/test",
        )
        source = {
            k: "c" * 64
            for k in (
                "parent_commit",
                "source_tree_sha256",
                "dirty_patch_sha256",
                "lock_sha256",
            )
        }
        digest = "sha256:" + "d" * 64
        report = dict(
            status="PASS",
            cleanup=True,
            source_unchanged=True,
            source=source,
            peers={"M": identity},
            isolation=dict(
                network_mode="hostOnly",
                host_servers=False,
                guest_mtu=1500,
                image_digest=digest,
                peers=[dict(started=True, joined=True)],
            ),
        )
        self.assertTrue(envelope(report, {"M": identity}, source, digest))
        for mutate in (
            lambda d: d.update(cleanup=False),
            lambda d: d.update(source_unchanged=False),
            lambda d: d["source"].update(source_tree_sha256="e" * 64),
            lambda d: d["peers"]["M"].update(binary_sha256="e" * 64),
            lambda d: d["isolation"].update(host_servers=True),
            lambda d: d["isolation"].update(guest_mtu=1200),
            lambda d: d["isolation"]["peers"][0].update(joined=False),
            lambda d: d["isolation"].update(peers=[]),
        ):
            broken = copy.deepcopy(report)
            mutate(broken)
            self.assertFalse(envelope(broken, {"M": identity}, source, digest))

    def test_pressure_evidence_is_recomputed_not_inferred(self):
        from vcore_scripts.protocol_evidence import RESOURCE_KINDS
        from vcore_scripts.protocol_n9_metrics import (
            NEW,
            QUEUES,
            lifetimes,
            rebuild,
            soak,
        )

        def snapshot(current):
            return dict(
                counts=[
                    dict(kind=k, current=current, peak=1)
                    for k in sorted(RESOURCE_KINDS)
                ]
            )

        def sample(active=True):
            return dict(
                heap_in_use=2_000_000,
                rss_kib=50_000,
                fd=100 if active else 6,
                resources=snapshot(int(active)),
                queues=[dict(kind=k, capacity=v, peak=1) for k, v in QUEUES.items()],
            )

        event = dict(resources=snapshot(0))
        stop = dict(
            stop_ms=4,
            after_stop=sample(False),
            quiet_seconds=5.1,
            quiet=sample(False),
            ports_rebound=True,
        )
        rows = [
            dict(
                generation=i,
                tcp=20,
                udp=20,
                per_protocol_tcp=5,
                per_protocol_udp=5,
                active=sample(),
                setup_us=[1000] * 40,
                fault="owned-peer-connections-closed",
                new_clients=True,
                after_clients=sample(),
            )
            for i in range(100)
        ]
        value = dict(
            count=100,
            same_running_session=True,
            protocols=NEW,
            cold_fd=4,
            baseline_fd=6,
            cycles=rows,
            stopped=stop,
        )
        self.assertTrue(rebuild(value, event))
        for mutate in (
            lambda d: d["cycles"].pop(),
            lambda d: d.update(same_running_session=False),
            lambda d: d["cycles"][0].update(tcp=0),
            lambda d: d["cycles"][0].update(setup_us=[]),
            lambda d: d["stopped"].update(stop_ms=5001),
            lambda d: d["stopped"].update(quiet_seconds=0),
            lambda d: d["stopped"]["after_stop"].update(fd=7),
        ):
            broken = copy.deepcopy(value)
            mutate(broken)
            self.assertFalse(rebuild(broken, event))
        self.assertFalse(lifetimes(dict(count=99, cycles=[]), []))
        points = [
            dict(sample(), seconds=300 + i * 60, waves=i + 1, faults=5 + i)
            for i in range(25)
        ]
        value = dict(
            requested_seconds=1800,
            seconds=1800.2,
            protocols=NEW,
            tcp=20,
            udp=20,
            per_protocol_tcp=5,
            per_protocol_udp=5,
            waves=1000,
            normal_verified_bytes=1000 * 20 * 2 * 2 * 257,
            normal_corruption=0,
            normal_misdirection=0,
            normal_unexpected_loss=0,
            switches=list(range(1, 1800)),
            faults=[
                dict(
                    start=60 * i,
                    end=60 * i + 0.5,
                    old_tcp_closed=20,
                    new_tcp=20,
                    new_udp=20,
                    replay=False,
                )
                for i in range(1, 30)
            ],
            samples=points,
            cold_fd=4,
            baseline_fd=6,
            stopped=stop,
            active_end=sample(),
            first_setup_us=[1000] * 40,
            last_setup_us=[1100] * 40,
            first_setup_median_us=1000,
            last_setup_median_us=1100,
            heap=dict(
                early_median=2_000_000, late_median=2_000_000, allowed_growth=1048576
            ),
        )
        self.assertTrue(soak(value, event, points))
        for mutate in (
            lambda d: d.update(requested_seconds=65),
            lambda d: d.update(seconds=1799),
            lambda d: d["faults"].pop(),
            lambda d: d.update(switches=[]),
            lambda d: d["samples"][0].update(heap_in_use=0),
            lambda d: d["samples"][-1]["queues"][0].update(peak=10000),
            lambda d: d["heap"].update(late_median=4_000_000),
            lambda d: d.update(last_setup_us=[3000] * 40, last_setup_median_us=3000),
            lambda d: d.update(normal_unexpected_loss=1),
        ):
            broken = copy.deepcopy(value)
            mutate(broken)
            self.assertFalse(soak(broken, event, broken["samples"]))
        self.assertFalse(soak(value, event, points[:-1]))

    def test_n9_consumer_results_keep_the_manifest_scope(self):
        from vcore_scripts.protocol_evidence import load_manifest, validate_results
        from vcore_scripts.protocol_n7_acceptance import result

        case = next(c for c in load_manifest() if c["case_id"] == "N9-PAIR-SS-SS")
        validate_results([case], [result(case, True, True)])

    def test_pair_evidence_requires_each_real_path_and_original_assertions(self):
        from vcore_scripts.protocol_n9_acceptance import pair_pass
        from vcore_scripts.protocol_n9_native import rust_command

        identifier = "N9-PAIR-SOCKS5-VLESS"
        record = dict(
            case_id=identifier,
            command=rust_command(),
            exit_code=0,
            command_cleanup=True,
        )
        paths = [
            dict(
                outer_ipv6=v6,
                nested_select=group,
                tcp_target_kinds=3,
                tcp_bytes_each_direction=31457280,
                udp_target_kinds=3,
                udp_packets=1200,
                udp_sizes=[1, 64, 512, 1200],
                server_first=True,
                client_first=True,
                ports_rebound=True,
            )
            for v6 in (False, True)
            for group in (False, True)
        ]
        observation = dict(
            first="socks5",
            last="vless",
            paths=paths,
            domain_native=[],
            budgets=[
                dict(
                    transmit=tx,
                    receive=rx,
                    roundtrip_size=min(tx, rx),
                    packets=100,
                    oversize_rejected_before_origin=True,
                )
                for tx, rx in ((128, 128), (512, 256))
            ],
            routed_udp=dict(
                upstream_business_udp_disabled=True,
                carrier_tcp=True,
                carrier_udp=True,
                leaf_business_udp_rejected=True,
            ),
            carrier_capability=dict(
                upstream_datagrams="rejected",
                tcp_allowed=True,
                udp_allowed=True,
                no_bypass=True,
            ),
        )
        events = [
            dict(schema_version=1, suite=suite, assertion=assertion, status=status)
            for suite, assertion, count in (
                ("N9-PAIR", "ordered_pair", 1),
                ("N9-BASE", "tcp_10mib_both_directions", 12),
                ("N9-PAIR", "directional_budget", 1),
                ("N9-PAIR", "routed_udp_permission", 1),
                ("N9-PAIR", "carrier_capability", 1),
            )
            for _ in range(count)
            for status in ("BEGIN", "PASS")
        ]
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            event_path = root / (identifier + "-events.jsonl")
            data_path = root / (identifier + "-observations.json")
            event_path.write_text("".join(json.dumps(e) + "\n" for e in events))
            data_path.write_text(json.dumps(observation))
            self.assertTrue(pair_pass(identifier, record, root))
            for mutate in (
                lambda d: d["paths"].pop(),
                lambda d: d["paths"].append(d["paths"][0]),
                lambda d: d["paths"][0].update(udp_packets=799),
                lambda d: d["paths"][0].update(ports_rebound=False),
                lambda d: d.update(last="vmess"),
                lambda d: d["budgets"][0].update(packets=99),
                lambda d: d["carrier_capability"].update(no_bypass=False),
            ):
                broken = copy.deepcopy(observation)
                mutate(broken)
                data_path.write_text(json.dumps(broken))
                self.assertFalse(pair_pass(identifier, record, root))
            data_path.write_text(json.dumps(observation))
            event_path.write_text("".join(json.dumps(e) + "\n" for e in events[:-1]))
            self.assertFalse(pair_pass(identifier, record, root))

    def test_list_contains_all_ordered_pairs_and_remaining_gates(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                cli.main(["check", "protocol-interop", "--stage", "N9", "--list"]), 0
            )
        identifiers = [line.split("\t")[0] for line in output.getvalue().splitlines()]
        protocols = {"SOCKS5", "ANYTLS", "SS", "TROJAN", "VMESS", "VLESS", "HYSTERIA2"}
        expected = {
            f"N9-PAIR-{first}-{last}" for first in protocols for last in protocols
        }
        self.assertEqual(len(expected), 49)
        self.assertEqual({key for key in identifiers if "-PAIR-" in key}, expected)
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertTrue(
            {
                "N9-ENTRYPOINTS",
                "N9-GRAPH",
                "N9-DNS-MEASURE",
                "N9-SS-ALGORITHMS",
                "N9-SS-EIH",
                "N9-LIFECYCLE",
                "N9-REBUILD",
                "N9-FAILURES",
                "N9-SOAK",
                "N9-HY2-HOP",
                "N9-DEBUG",
                "N9-RELEASE",
                "N9-QUALITY",
                "N9-FEATURES",
                "N9-SCRIPTS",
                "N9-SHARED",
            }
            <= set(identifiers)
        )
