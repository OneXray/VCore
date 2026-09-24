"""N5 request-field development checks, not the complete N5 stage gate."""

from __future__ import annotations

import contextlib
import copy
import json
import os
import shutil
import ssl
import tempfile
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .native_release import download_native
from .protocol_containers import ContainerLab, command
from .protocol_evidence import idle_resources, read_events
from .protocol_inputs import redact, source_identity
from .protocol_peers import run_command
from .protocol_streams import certificates
from .protocol_trojan import certificate_chain
from .protocol_vless_peers import (
    configuration as vless_configuration,
)
from .protocol_vless_peers import (
    peer_kind as vless_peer_kind,
)
from .protocol_vless_public import events_pass as vless_events_pass
from .protocol_xhttp_peers import CLIENT_ID, peer_config

PUBLIC_TESTS = (
    "public_base",
    "public_negative",
    "runtime::public_entrypoints",
    "runtime::public_graph",
    "runtime::public_ipv6_and_gates",
    "runtime::public_lifecycle",
    "runtime::public_udp_isolation",
    "runtime::grpc_pool_keeps_physical_selection_until_new_transport",
)


def native_kind(version):
    return (
        vless_peer_kind(version.removeprefix("outer-"))
        if version.startswith("outer-")
        else "XR"
        if version == "h3"
        else "M"
    )


def public_events_pass(events, assertion):
    if assertion not in PUBLIC_TESTS or any(
        e.get("suite") not in {"N5-PUBLIC", "N5-BASE", "N5-LIFE"} for e in events
    ):
        return False
    expected = {
        ("N5-PUBLIC", assertion): 1,
    }
    if assertion == "public_base":
        expected.update(
            {
                ("N5-BASE", "tcp_10mib_both_directions"): 3,
                ("N5-BASE", "udp_each_codec_and_family"): 3,
            }
        )
    if assertion == "runtime::public_lifecycle":
        expected[("N5-LIFE", "stop_and_remain_quiet")] = 20
    if len(events) != 2 * sum(expected.values()):
        return False
    for key, count in expected.items():
        matched = [e for e in events if (e.get("suite"), e.get("assertion")) == key]
        if [e.get("status") for e in matched] != ["BEGIN", "PASS"] * count:
            return False
    remapped = [dict(e, suite=e["suite"].replace("N5-", "N4-", 1)) for e in events]
    return vless_events_pass(remapped, assertion, "xhttp")


def variants():
    result = {}
    result["auto"] = {"mode": "auto"}
    result["auto-download"] = {"mode": "auto", "download-settings": {}}
    for fault, peer_overrides in {
        "session": {"session-placement": "header", "session-key": "X-Required-Session"},
        "sequence": {"seq-placement": "header", "seq-key": "X-Required-Sequence"},
        "payload": {
            "uplink-data-placement": "header",
            "uplink-data-key": "required-data",
        },
        "post-size": {"sc-max-each-post-bytes": "1"},
    }.items():
        result[f"reject-{fault}"] = {
            "mode": "packet-up",
            "_reject": True,
            "_server": peer_overrides,
        }
    result["post-minimum"] = {
        "mode": "packet-up",
        "sc-max-each-post-bytes": "1",
        "sc-min-posts-interval-ms": "1",
        "_tiny": True,
    }
    result["post-maximum"] = {
        "mode": "packet-up",
        "sc-max-each-post-bytes": "16777216",
        "sc-min-posts-interval-ms": "0-1",
    }
    for table in (
        "uuid",
        "ALPHABET",
        "Alphabet",
        "BASE36",
        "Base62",
        "HEX",
        "alphabet",
        "base36",
        "hex",
        "number",
        "abAB0123",
    ):
        result[f"session-{table}"] = {
            "mode": "packet-up",
            "session-table": table,
            "sc-min-posts-interval-ms": "1",
            "_tiny": True,
        }
    for mode in ("stream-one", "stream-up", "packet-up"):
        result[f"{mode}-headers"] = dict(mode=mode, headers={"X-Probe": "fixture"})
    result["stream-up-no-grpc"] = {"mode": "stream-up", "no-grpc-header": True}
    result["stream-one-no-grpc"] = {"mode": "stream-one", "no-grpc-header": True}
    result["body-auto"] = {
        "mode": "packet-up",
        "uplink-data-placement": "auto",
        "sc-min-posts-interval-ms": "1",
    }
    for protocol in ("h2mux", "smux", "yamux"):
        for padding in (False, True):
            result[f"mux-{protocol}-{'padded' if padding else 'plain'}"] = {
                "mode": "packet-up",
                "sc-min-posts-interval-ms": "1",
                "_mux": {
                    "enabled": True,
                    "protocol": protocol,
                    "padding": padding,
                    "max-connections": 1,
                },
            }
    for mode in ("stream-one", "stream-up", "packet-up"):
        result[f"{mode}-reuse"] = {"mode": mode, "reuse-settings": {}}
        if mode == "packet-up":
            result[f"{mode}-reuse"]["sc-min-posts-interval-ms"] = "1"
    for mode in ("stream-up", "packet-up"):
        result[f"{mode}-split-reuse"] = {
            "mode": mode,
            "reuse-settings": {"h-max-request-times": "1"},
            "download-settings": {
                "alpn": ["http/1.1"],
                "headers": {"X-Down": "fixture"},
                "reuse-settings": {},
            },
        }
        if mode == "packet-up":
            result[f"{mode}-split-reuse"]["sc-min-posts-interval-ms"] = "1"
    for placement in ("queryInHeader", "header", "query", "cookie"):
        for method in ("repeat-x", "tokenish"):
            options = {
                "mode": "packet-up",
                "x-padding-bytes": "100",
                "x-padding-obfs-mode": True,
                "x-padding-placement": placement,
                "x-padding-method": method,
                "sc-min-posts-interval-ms": "1",
            }
            if placement != "header":
                options["x-padding-key"] = "pad"
            if placement in ("queryInHeader", "header"):
                options["x-padding-header"] = "X-Pad"
            result[f"padding-{placement}-{method}"] = options
    for placement, method in zip(
        ("path", "query", "header", "cookie"),
        ("POST", "PUT", "PATCH", "DELETE"),
        strict=True,
    ):
        options = {
            "mode": "packet-up",
            "session-placement": placement,
            "seq-placement": placement,
            "uplink-http-method": method,
            "session-table": "number",
            "session-length": "10",
            "sc-min-posts-interval-ms": "1",
        }
        if placement != "path":
            options.update({"session-key": "sid", "seq-key": "seq"})
        result[f"metadata-{placement}-{method}"] = options
    for placement in ("header", "cookie"):
        result[f"payload-{placement}"] = {
            "mode": "packet-up",
            "uplink-data-placement": placement,
            "uplink-data-key": "data",
            "uplink-chunk-size": "64-128",
            "sc-min-posts-interval-ms": "1",
        }
        result[f"payload-{placement}-auto"] = dict(
            result[f"payload-{placement}"], **{"uplink-chunk-size": "0"}
        )
    for protocol in ("h2mux", "smux", "yamux"):
        result[f"mux-{protocol}-padding-required"] = {
            "mode": "stream-one",
            "_mux": {"enabled": True, "protocol": protocol, "padding": False},
            "_require-padding": True,
            "_reject": True,
        }
    expanded = {}
    for version in ("h2", "h1", "h2c", "h1c", "h3", "h2r", "h1r"):
        for name, fields in result.items():
            options = copy.deepcopy(fields)
            if version == "h3" and "download-settings" in options:
                options["download-settings"]["alpn"] = ["h3"]
            expanded[f"{version}-{name}"] = (options, version)
            if "_mux" in options:
                tcp_only = copy.deepcopy(options)
                tcp_only["_mux"]["only-tcp"] = True
                expanded[f"{version}-{name}-only-tcp"] = (tcp_only, version)
        if version == "h3":
            expanded["h3-keepalive"] = (
                {"mode": "packet-up", "_keepalive": True},
                version,
            )
        if version.endswith("r"):
            from .mihomo_extended import PUBLIC_KEY

            replacement = {"public-key": PUBLIC_KEY}
            expanded[f"{version}-download-reality-replacement"] = (
                {
                    "mode": "stream-up",
                    "download-settings": {"reality-opts": replacement},
                },
                version,
            )
            expanded[f"{version}-reject-download-short-id"] = (
                {
                    "mode": "stream-up",
                    "download-settings": {
                        "reality-opts": dict(replacement, **{"short-id": "ff"})
                    },
                    "_reject": True,
                },
                version,
            )
            expanded[f"{version}-reject-download-public-key"] = (
                {
                    "mode": "stream-up",
                    "download-settings": {
                        "reality-opts": {
                            # Valid X25519 encoding, not this server's public key.
                            "public-key": "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        }
                    },
                    "_reject": True,
                },
                version,
            )
    for mode in (
        "tcp",
        "tcp-tls",
        "tcp-reality",
        "ws",
        "ws-tls",
        "ws-reality",
        "grpc",
        "grpc-tls",
        "grpc-reality",
        "http",
        "http-tls",
        "h2",
        "h2-tls",
        "ws-header",
        "ws-header-tls",
        "ws-path",
        "ws-path-tls",
    ):
        for name, options in result.items():
            if "_mux" in options:
                expanded[f"outer-{mode}-{name}"] = (
                    copy.deepcopy(options),
                    "outer-" + mode,
                )
                tcp_only = copy.deepcopy(options)
                tcp_only["_mux"]["only-tcp"] = True
                expanded[f"outer-{mode}-{name}-only-tcp"] = (tcp_only, "outer-" + mode)
    return expanded


def server_fields(fields, kind):
    if kind == "M":
        return fields
    names = {
        "path": "path",
        "mode": "mode",
        "host": "host",
        "no-grpc-header": "noGRPCHeader",
        "x-padding-bytes": "xPaddingBytes",
        "x-padding-obfs-mode": "xPaddingObfsMode",
        "x-padding-key": "xPaddingKey",
        "x-padding-header": "xPaddingHeader",
        "x-padding-placement": "xPaddingPlacement",
        "x-padding-method": "xPaddingMethod",
        "uplink-http-method": "uplinkHTTPMethod",
        "session-placement": "sessionPlacement",
        "session-key": "sessionKey",
        "seq-placement": "seqPlacement",
        "seq-key": "seqKey",
        "uplink-data-placement": "uplinkDataPlacement",
        "uplink-data-key": "uplinkDataKey",
        "uplink-chunk-size": "uplinkChunkSize",
        "sc-max-each-post-bytes": "scMaxEachPostBytes",
    }
    if not fields.keys() <= names.keys():
        raise ValueError("missing explicit Xray field translation")
    return {names[key]: value for key, value in fields.items()}


def events_pass(events, assertion, *, owned=False):
    if any(e.get("schema_version") != 1 for e in events):
        return False
    main = [event for event in events if event.get("suite") == "N5-XHTTP"]
    if (
        len(main) != 2
        or [e.get("status") for e in main] != ["BEGIN", "PASS"]
        or any(e.get("assertion") != assertion for e in main)
    ):
        return False
    if not owned:
        return len(events) == 2
    cycles = [e for e in events if e.get("suite") == "N5-OWNED"]
    if len(events) != 42 or len(cycles) != 40:
        return False
    for start, finish in zip(cycles[::2], cycles[1::2], strict=True):
        if (
            start.get("status") != "BEGIN"
            or start.get("assertion") != "stop_and_remain_quiet"
            or finish.get("status") != "PASS"
            or finish.get("assertion") != "stop_and_remain_quiet"
            or finish.get("seconds", 0) < 5
            or not idle_resources(finish.get("resources"))
        ):
            return False
        points = finish.get("checkpoints", [])
        if len(points) != 3 or [p.get("phase") for p in points] != [
            "baseline",
            "after-stop",
            "quiet",
        ]:
            return False
        if not all(idle_resources(p.get("resources")) for p in points):
            return False
        if points[1]["resources"] != points[2]["resources"]:
            return False
    return True


def close_reference(lab, stack, root, name, node, origin, binary, output):
    comparison_dir = root / "comparison"
    comparison_dir.mkdir()
    shutil.copy2(binary, comparison_dir / "peer")
    reference = copy.deepcopy(node)
    reference["name"] = "reference"
    reference.pop("smux", None)
    if reference.get("reality-opts"):
        # Required by the official Mihomo client's uTLS REALITY backend. This
        # belongs only to the reference fixture, not VCore's public config.
        reference["client-fingerprint"] = "chrome"
    config = {
        "socks-port": 23002,
        "allow-lan": True,
        "bind-address": "*",
        "log-level": "warning",
        "ipv6": True,
        "proxies": [reference],
        "rules": ["MATCH,reference"],
    }
    (comparison_dir / "config.json").write_text(json.dumps(config))
    comparison = lab.start(
        stack,
        comparison_dir,
        name + "-comparison",
        ["/data/fixture/peer", "-d", "/data", "-f", "/data/fixture/config.json"],
    )
    comparison.release()
    comparison.wait_tcp(23002)
    result = run_command(
        [
            "container",
            "exec",
            origin.name,
            "env",
            "VCORE_ISOLATED_ORIGIN=1",
            "python",
            "-B",
            "/data/fixture/close.py",
            comparison.ipv4,
            origin.ipv4,
        ],
        timeout=30,
    )
    (output / f"{name}-close-command.log").write_text(
        redact(result.stdout.decode(errors="replace"))
    )
    (output / f"{name}-comparison.log").write_text(
        redact(command("logs", comparison.name)[-65536:])
    )
    if result.returncode or not result.cleanup:
        raise RuntimeError("official XHTTP close comparison failed")
    observed = json.loads(result.stdout)
    observed["scope"] = "same-mode"
    (output / f"{name}-close-reference.json").write_text(json.dumps(observed) + "\n")
    comparison.ensure_alive()
    return observed


def run(
    output: Path,
    selected: list[str],
    *,
    udp: bool = False,
    owned: bool = False,
    public: str | None = None,
    jobs: dict | None = None,
    supplied: dict | None = None,
):
    if public is not None and (public not in PUBLIC_TESTS or udp or owned):
        raise ValueError("invalid public consumer selection")
    cases = variants()
    if jobs is not None:
        if set(jobs) != set(selected) or any(not entries for entries in jobs.values()):
            raise ValueError("invalid frozen native jobs")
        allowed = set(PUBLIC_TESTS) | {
            "native_xhttp_request_fields",
            "native_xhttp_udp_encodings",
            "lifecycle::native_xhttp_owned_resources",
            "keepalive::native_h3_keepalive_observes_each_leg_and_stop",
            "security::native_xhttp_security",
            "close::native_mihomo_xhttp_close",
        }
        ids = [entry["case_id"] for entries in jobs.values() for entry in entries]
        if len(ids) != len(set(ids)) or any(
            entry["test"] not in allowed
            for entries in jobs.values()
            for entry in entries
        ):
            raise ValueError("unknown or duplicate frozen native job")
    if not selected:
        selected = list(cases)
    if len(selected) != len(set(selected)) or not set(selected) <= cases.keys():
        raise ValueError("invalid XHTTP field case selection")
    if (
        not output.is_relative_to(CORE_DIR / "target/interop/runs")
        or output == CORE_DIR / "target/interop/runs"
    ):
        raise ValueError("new run directory must be directly under target/interop/runs")
    output.mkdir(exist_ok=False)
    report = dict(
        stage="N5",
        scope="protocol-consumer"
        if jobs is not None
        else "request-fields-development-only",
        traffic=public
        or ("owned-resources" if owned else "udp-three-encodings" if udp else "tcp"),
        source=source_identity(),
        status="NOT RUN",
        cases=[],
        peers={},
        isolation={},
    )
    try:
        artifacts = {}
        kinds = {native_kind(cases[name][1]) for name in selected}
        if jobs is not None or any(
            native_kind(cases[name][1]) != "M"
            and (udp or owned or public or "_mux" in cases[name][0])
            for name in selected
        ):
            kinds.add("M")
        for kind in sorted(kinds):
            if supplied is not None:
                binary, identity = supplied[kind]
            elif kind == "M":
                identity = {}
                binary = download_mihomo(
                    "linux-arm64", directory=output / "binary", identity=identity
                )
            else:
                artifact = download_native(
                    kind, output / kind, "linux-arm64", defer_version=True
                )
                binary, identity = artifact.binary, artifact.identity
            artifacts[kind] = binary
            report["peers"][kind] = identity
        lab = ContainerLab(report["isolation"], mtu=1500)
        build = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "xhttp_native",
                *(["--test", "vless_public"] if public or jobs is not None else []),
                "--no-run",
            ],
            timeout=180,
        )
        (output / "build.log").write_text(redact(build.stdout.decode(errors="replace")))
        if build.returncode or not build.cleanup:
            raise RuntimeError("XHTTP field test build failed")
        for name in selected:
            print(name, flush=True)
            fields, version = cases[name]
            kind = native_kind(version)
            entries = jobs[name] if jobs is not None else None
            needs_public = bool(public) or bool(
                entries and any(e["test"] in PUBLIC_TESTS for e in entries)
            )
            hop_tests = {
                "runtime::public_graph",
                "runtime::grpc_pool_keeps_physical_selection_until_new_transport",
            }
            needs_hop = public in hop_tests or bool(
                entries and any(e["test"] in hop_tests for e in entries)
            )
            needs_decoder = (
                udp
                or owned
                or needs_public
                or bool(
                    entries
                    and any(
                        e["test"] == "native_xhttp_udp_encodings"
                        or e["test"].startswith("lifecycle::")
                        for e in entries
                    )
                )
            )
            needs_close = bool(
                entries and any(e["test"].startswith("close::") for e in entries)
            )
            outer_mode = (
                version.removeprefix("outer-") if version.startswith("outer-") else None
            )
            identity = report["peers"][kind]
            with (
                tempfile.TemporaryDirectory(prefix="private-", dir=output) as temporary,
                contextlib.ExitStack() as stack,
            ):
                root = Path(temporary)
                server_dir, origin_dir = root / "server", root / "origin"
                server_dir.mkdir()
                origin_dir.mkdir()
                shutil.copy2(artifacts[kind], server_dir / "peer")
                shutil.copyfile(
                    Path(__file__).with_name("container_udp_origin.py"),
                    origin_dir / "origin.py",
                )
                if needs_close:
                    shutil.copyfile(
                        Path(__file__).with_name("container_close_client.py"),
                        origin_dir / "close.py",
                    )
                origin_security = []
                if version.endswith(("r", "-reality")):
                    origin_cert, origin_key, _ = certificates(origin_dir)
                    origin_security = [
                        f"VCORE_ORIGIN_CERT=/data/fixture/{origin_cert.name}",
                        f"VCORE_ORIGIN_KEY=/data/fixture/{origin_key.name}",
                    ]
                origin = lab.start(
                    stack,
                    origin_dir,
                    name + "-origin",
                    [
                        "env",
                        "VCORE_ISOLATED_ORIGIN=1",
                        *origin_security,
                        "python",
                        "-B",
                        "/data/fixture/origin.py",
                    ],
                )
                server = lab.start(
                    stack,
                    server_dir,
                    name + "-server",
                    [
                        "/data/fixture/peer",
                        "-d",
                        "/data",
                        "-f",
                        "/data/fixture/config.json",
                    ]
                    if kind == "M"
                    else [
                        "/data/fixture/peer",
                        "run",
                        "-c",
                        "/data/fixture/config.json",
                    ],
                )
                version_text = command(
                    "exec",
                    server.name,
                    "/data/fixture/peer",
                    "-v" if kind == "M" else "version",
                ).strip()
                digest = command(
                    "exec", server.name, "sha256sum", "/data/fixture/peer"
                ).split()[0]
                if not version_text or digest != identity["binary_sha256"]:
                    raise RuntimeError("XHTTP peer identity mismatch")
                identity["version"] = version_text
                cert, key, pin = certificate_chain(server_dir)
                # Xray always normalizes its handler path with a trailing slash,
                # unlike Mihomo when both metadata fields are outside the path.
                # Configure an explicit compatible path, without changing VCore.
                options = dict(fields, path="/n5/" if kind == "XR" else "/n5")
                plain = (
                    not outer_mode.endswith(("-tls", "-reality"))
                    if outer_mode
                    else version.endswith("c")
                )
                reality = version.endswith(("r", "-reality"))
                tiny = options.pop("_tiny", False)
                keepalive = options.pop("_keepalive", False)
                reject = options.pop("_reject", False)
                peer_overrides = options.pop("_server", {})
                mux = options.pop("_mux", None)
                require_padding = options.pop("_require-padding", False)
                decoder = None
                if kind != "M" and (needs_decoder or mux is not None):
                    decoder_dir = root / "decoder"
                    decoder_dir.mkdir()
                    shutil.copy2(artifacts["M"], decoder_dir / "peer")
                    listener = dict(
                        name="decoder",
                        type="vless",
                        listen="::",
                        port=23001,
                        users=[dict(uuid=CLIENT_ID)],
                        **{"allow-insecure": True},
                    )
                    if mux is not None:
                        listener["mux-option"] = {
                            "padding": require_padding or mux["padding"]
                        }
                    (decoder_dir / "config.json").write_text(
                        json.dumps(
                            dict(
                                ipv6=True,
                                hosts={
                                    "vcore-fixture.test": origin.ipv4,
                                    "peer.fixture.test": server.ipv4,
                                },
                                listeners=[listener],
                                rules=["MATCH,DIRECT"],
                                **{"log-level": "warning"},
                            )
                        )
                    )
                    decoder = lab.start(
                        stack,
                        decoder_dir,
                        name + "-decoder",
                        [
                            "/data/fixture/peer",
                            "-d",
                            "/data",
                            "-f",
                            "/data/fixture/config.json",
                        ],
                    )
                    decoded_version = command(
                        "exec", decoder.name, "/data/fixture/peer", "-v"
                    ).strip()
                    decoded_digest = command(
                        "exec", decoder.name, "sha256sum", "/data/fixture/peer"
                    ).split()[0]
                    if (
                        not decoded_version
                        or decoded_digest != report["peers"]["M"]["binary_sha256"]
                    ):
                        raise RuntimeError("layered decoder identity mismatch")
                    report["peers"]["M"]["version"] = decoded_version
                    decoder.release()
                    decoder.wait_tcp(23001)
                node = dict(
                    name="peer",
                    type="vless",
                    server=server.ipv4,
                    port=23000,
                    uuid=CLIENT_ID,
                    tls=not plain,
                    alpn=[
                        "http/1.1"
                        if version.startswith("h1")
                        else "h3"
                        if version == "h3"
                        else "h2"
                    ],
                    **{"xhttp-opts": options},
                    network="xhttp",
                    udp=True,
                )
                if mux is not None:
                    node["smux"] = mux
                if not plain:
                    node.update(servername="localhost", fingerprint=pin)
                config = peer_config(
                    kind,
                    f"/data/fixture/{cert.name}",
                    f"/data/fixture/{key.name}",
                    plain=plain,
                    decoder=decoder.ipv4 if decoder else None,
                )
                if outer_mode:
                    node, config = vless_configuration(
                        outer_mode,
                        server.ipv4,
                        origin.ipv4,
                        Path("/data/fixture") / cert.name,
                        Path("/data/fixture") / key.name,
                    )
                    node["name"] = "peer"
                    node["smux"] = mux
                    if not plain and not reality:
                        node["fingerprint"] = pin
                    if decoder:
                        config["inbounds"][0].update(
                            protocol="dokodemo-door",
                            settings=dict(
                                address=decoder.ipv4, port=23001, network="tcp"
                            ),
                        )
                if kind == "M":
                    config["hosts"] = {
                        "vcore-fixture.test": origin.ipv4,
                        "peer.fixture.test": server.ipv4,
                    }
                    if mux is not None:
                        config["listeners"][0]["mux-option"] = {
                            "padding": require_padding or mux["padding"]
                        }
                    if reality:
                        from .mihomo_extended import PRIVATE_KEY, PUBLIC_KEY, SHORT_ID

                        listener = config["listeners"][0]
                        listener.pop("certificate", None)
                        listener.pop("private-key", None)
                        listener["reality-config"] = {
                            "dest": f"{origin.ipv4}:24001",
                            "private-key": PRIVATE_KEY,
                            "short-id": [SHORT_ID, ""],
                            "server-names": ["localhost"],
                        }
                        node.pop("fingerprint", None)
                        node["reality-opts"] = {
                            "public-key": PUBLIC_KEY,
                            "short-id": SHORT_ID,
                        }
                else:
                    config["dns"] = {"hosts": {"vcore-fixture.test": origin.ipv4}}
                    config["outbounds"][0]["settings"] = {"domainStrategy": "UseIP"}
                # Client-only session generator and pacing have no server counterpart.
                peer_options = {
                    k: v
                    for k, v in options.items()
                    if k
                    not in {
                        "session-table",
                        "session-length",
                        "sc-min-posts-interval-ms",
                        "headers",
                        "reuse-settings",
                        "download-settings",
                    }
                }
                peer_options.update(peer_overrides)
                if outer_mode:
                    pass  # Native outer transport options were supplied above.
                elif kind == "M":
                    config["listeners"][0]["xhttp-config"].update(
                        server_fields(peer_options, kind)
                    )
                else:
                    config["inbounds"][0]["streamSettings"]["xhttpSettings"].update(
                        server_fields(peer_options, kind)
                    )
                (server_dir / "config.json").write_text(json.dumps(config))
                hop = None
                if needs_hop:
                    # An upstream must not dial a VLESS listener in its own
                    # Mihomo process: that correctly triggers loopback protection.
                    upstream_dir = root / "upstream"
                    upstream_dir.mkdir()
                    shutil.copy2(artifacts["M"], upstream_dir / "peer")
                    (upstream_dir / "config.json").write_text(
                        json.dumps(
                            dict(
                                ipv6=True,
                                hosts={
                                    "peer.fixture.test": server.ipv4,
                                    "vcore-fixture.test": origin.ipv4,
                                },
                                listeners=[
                                    dict(
                                        name="hop",
                                        type="socks",
                                        listen="::",
                                        port=23004,
                                        udp=True,
                                    )
                                ],
                                rules=["MATCH,DIRECT"],
                                **{"log-level": "warning"},
                            )
                        )
                    )
                    upstream = lab.start(
                        stack,
                        upstream_dir,
                        name + "-upstream",
                        [
                            "/data/fixture/peer",
                            "-d",
                            "/data",
                            "-f",
                            "/data/fixture/config.json",
                        ],
                    )
                    upstream.release()
                    upstream.wait_tcp(23004)
                    hop = dict(
                        name="hop",
                        type="socks5",
                        server=upstream.ipv4,
                        port=23004,
                        udp=True,
                    )
                fixture = root / "input.json"
                fixture.write_text(
                    json.dumps(
                        dict(
                            isolation="containers",
                            node=node,
                            tiny=tiny,
                            reject=reject,
                            peer_kind=kind,
                            data_dir=str(root / "data"),
                            server_ipv4=server.ipv4,
                            server_ipv6=server.ipv6,
                            hop=hop,
                            origin_control=f"{origin.ipv4}:24000",
                            origin_ipv4=origin.ipv4,
                            origin_ipv6=origin.ipv6,
                            root_der=list(
                                ssl.PEM_cert_to_DER_cert(
                                    (server_dir / "root.pem").read_text()
                                )
                            ),
                        )
                    )
                )
                origin.release()
                server.release()
                origin.wait_tcp(24000)
                if kind == "M":
                    server.wait_tcp(23000)
                default_assertion = (
                    public
                    or (
                        "keepalive::native_h3_keepalive_observes_each_leg_and_stop"
                        if keepalive
                        else None
                    )
                    or ("security::native_xhttp_security" if reject else None)
                    or (
                        "lifecycle::native_xhttp_owned_resources"
                        if owned
                        else "native_xhttp_udp_encodings"
                        if udp
                        else "native_xhttp_request_fields"
                    )
                )
                if needs_close:
                    try:
                        reference = close_reference(
                            lab, stack, root, name, node, origin, artifacts["M"], output
                        )
                    finally:
                        # A failed reference setup precedes the VCore cases;
                        # preserve its peer evidence before ExitStack cleanup.
                        for role, peer in (("server", server), ("origin", origin)):
                            (output / f"{name}-{role}.log").write_text(
                                redact(command("logs", peer.name)[-65536:])
                            )
                    data = json.loads(fixture.read_text())
                    data["close_reference"] = reference
                    fixture.write_text(json.dumps(data))
                for entry in entries or [dict(case_id=name, test=default_assertion)]:
                    case_id, assertion = entry["case_id"], entry["test"]
                    events = output / f"{case_id}-events.jsonl"
                    command_line = [
                        "cargo",
                        "test",
                        "--locked",
                        "--all-features",
                        "--test",
                        "vless_public" if assertion in PUBLIC_TESTS else "xhttp_native",
                        assertion,
                        "--",
                        "--exact",
                        "--ignored",
                        "--nocapture",
                    ]
                    result = run_command(
                        command_line,
                        timeout=240
                        if assertion.startswith("lifecycle::")
                        or assertion in PUBLIC_TESTS
                        else 150,
                        env=dict(
                            os.environ,
                            VCORE_XHTTP_INPUT=str(fixture),
                            VCORE_VLESS_INPUT=str(fixture),
                            VCORE_PROTOCOL_STAGE="N5",
                            VCORE_CASE_EVENTS=str(events),
                        ),
                    )
                    (output / f"{case_id}.log").write_text(
                        redact(result.stdout.decode(errors="replace"))
                    )
                    observed = read_events(events) if events.exists() else []
                    passed = (
                        result.returncode == 0
                        and result.cleanup
                        and (
                            public_events_pass(observed, assertion)
                            if assertion in PUBLIC_TESTS
                            else events_pass(
                                observed,
                                assertion,
                                owned=assertion.startswith("lifecycle::"),
                            )
                        )
                    )
                    report["cases"].append(
                        dict(
                            case_id=case_id,
                            variant=name,
                            assertion=assertion,
                            status="PASS" if passed else "FAIL",
                            command=command_line,
                            exit_code=result.returncode,
                            seconds=result.seconds,
                            command_cleanup=result.cleanup,
                            decoder_path=(
                                f"{kind} {outer_mode or 'XHTTP'} -> Mihomo VLESS"
                            )
                            if decoder
                            else kind,
                        )
                    )
                    print(f"{case_id}: {'PASS' if passed else 'FAIL'}", flush=True)
                    if not passed:
                        break
                for role, peer in (("server", server), ("origin", origin)):
                    peer.ensure_alive()
                    (output / f"{name}-{role}.log").write_text(
                        redact(command("logs", peer.name)[-65536:])
                    )
                if decoder:
                    decoder.ensure_alive()
                if needs_hop:
                    upstream.ensure_alive()
                    (output / f"{name}-upstream.log").write_text(
                        redact(command("logs", upstream.name)[-65536:])
                    )
                if not passed:
                    break
        report["status"] = (
            "PASS"
            if len(report["cases"])
            == (sum(map(len, jobs.values())) if jobs is not None else len(selected))
            and all(c["status"] == "PASS" for c in report["cases"])
            else "FAIL"
        )
    except (OSError, ValueError, RuntimeError) as error:
        report.update(
            status="FAIL",
            reason=str(error)
            if isinstance(error, RuntimeError)
            else type(error).__name__,
        )
    except KeyboardInterrupt:
        report.update(status="INTERRUPTED")
    finally:
        report["cleanup"] = all(
            p["joined"] for p in report["isolation"].get("peers", [])
        )
        report["source_unchanged"] = (
            source_identity()["source_tree_sha256"]
            == report["source"]["source_tree_sha256"]
        )
        if not report["cleanup"] or not report["source_unchanged"]:
            report["status"] = "FAIL"
        (output / "xhttp-fields-results.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("cases", nargs="*")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--owned", action="store_true")
    parser.add_argument("--public", choices=PUBLIC_TESTS)
    args = parser.parse_args()
    if sum((args.udp, args.owned, args.public is not None)) > 1:
        parser.error("select UDP or owned-resource checks")
    with exclusive_run():
        sys.exit(
            run(
                args.output.resolve(),
                args.cases,
                udp=args.udp,
                owned=args.owned,
                public=args.public,
            )
        )
