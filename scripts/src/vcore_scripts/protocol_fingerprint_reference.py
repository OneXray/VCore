"""Selected-v1 reference ClientHello acquisition; not VCore interoperability."""

from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import json
import secrets
import shutil
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .builds import CORE_DIR
from .mihomo_isolation import exclusive_run
from .mihomo_release import download_mihomo
from .protocol_containers import ContainerLab, command, listing
from .protocol_inputs import redact, source_identity
from .protocol_peers import run_command
from .protocol_streams import certificates
from .tls_client_hello import is_grease, parse_client_hello, validate_capture

PROFILES = ("chrome", "chrome120", "firefox", "firefox120", "safari", "safari16")
TEMPLATES = {
    "chrome": "Chrome133",
    "chrome120": "Chrome120",
    "firefox": "Firefox120",
    "firefox120": "Firefox120",
    "safari": "Safari16.0",
    "safari16": "Safari16.0",
}
SNIS = ("fingerprint.test", "f" * 63 + ".fingerprint.test")
PORTS = {
    "tcp": 24430,
    "ws": 24430,
    "grpc": 24430,
    "reality": 24430,
    "tls13": 24431,
    "tls12": 24432,
}


def reference_cases() -> list[dict]:
    """The public reference-case catalog; a listing does not start a peer."""
    cases = []
    for profile in (*PROFILES, "none"):
        contexts = ("tcp",) if profile == "none" else ("tcp", "ws", "grpc", "reality")
        for context in contexts:
            for sni in SNIS:
                for attempt in range(2):
                    cases.append(
                        dict(
                            id=f"CF0-{profile}-{context}-{len(sni)}-{attempt}",
                            profile=profile,
                            template=TEMPLATES.get(profile),
                            context=context,
                            sni=sni,
                            sni_length=len(sni),
                            attempt=attempt,
                        )
                    )
    for profile in ("chrome", "chrome120", "firefox", "safari"):
        for context in ("tls12", "tls13"):
            for attempt in range(2):
                cases.append(
                    dict(
                        id=f"CF0-{profile}-{context}-16-{attempt}",
                        profile=profile,
                        template=TEMPLATES[profile],
                        context=context,
                        sni=SNIS[0],
                        sni_length=16,
                        attempt=attempt,
                    )
                )
    return cases


def _reference_shape(hello, case, *, expected_alpn=None, allow_psk=False):
    """Apply only source-defined reference variations, checking before masking."""
    shape = copy.deepcopy(hello)
    shape.pop("raw_sha256")
    size = shape.pop("bytes")
    padding = next((e for e in shape["extensions"] if e["type"] == 21), None)
    psk = next((e for e in shape["extensions"] if e["type"] == 41), None)
    if psk and (not allow_psk or shape["extensions"][-1] != psk):
        raise ValueError("unexpected PSK or invalid last-extension position")
    unpadded = size - (padding["bytes"] + 4 if padding else 0)
    needs_padding = (
        case["template"] in {"Chrome120", "Safari16.0"} and 255 < unpadded < 512
    )
    if bool(padding) != needs_padding:
        raise ValueError("reference padding presence differs from template")
    if padding:
        expected = max(1, 512 - unpadded - 4)
        if (
            padding["bytes"] != expected
            or padding["payload_hex"] != "00" * expected
            or shape["extensions"][-2 if psk else -1] != padding
        ):
            raise ValueError("reference padding contents, position or size mismatch")
        shape["extensions"].remove(padding)
    groups = next(e["values"] for e in shape["extensions"] if e["type"] == 10)
    shares = next(e["shares"] for e in shape["extensions"] if e["type"] == 51)
    if any(s["group"] not in groups for s in shares):
        raise ValueError("reference key share/group correlation mismatch")
    for row in shape["extensions"]:
        if row["type"] == 0:
            if row["names"] != [dict(type=0, name=case["sni"])]:
                raise ValueError("reference SNI mismatch")
            row["names"], row["bytes"] = "synthetic-sni", "sni-dependent"
        elif row["type"] == 16:
            expected = expected_alpn or (
                ["http/1.1"] if case["context"] == "ws" else ["h2", "http/1.1"]
            )
            if row["protocols"] != expected:
                raise ValueError("reference transport ALPN mismatch")
            row["protocols"], row["bytes"] = "transport-alpn", "alpn-dependent"
        elif row["type"] == 65037:
            firefox = case["template"] == "Firefox120"
            if (
                (row["hello_type"], row["kdf"], row["enc_bytes"]) != (0, 1, 32)
                or row["aead"] not in ({1, 3} if firefox else {1})
                or row["payload_bytes"]
                not in ({239} if firefox else {144, 176, 208, 240})
                or row["bytes"] != 42 + row["payload_bytes"]
            ):
                raise ValueError(
                    "reference ECH GREASE differs from source-defined variants"
                )
            row["aead"], row["payload_bytes"], row["bytes"] = (
                "checked-variant",
                "checked-variant",
                "checked-variant",
            )
        for key in ("values",):
            if key in row:
                row[key] = ["GREASE" if is_grease(v) else v for v in row[key]]
        if row["type"] == 51:
            for share in row["shares"]:
                if is_grease(share["group"]):
                    share["group"] = "GREASE"
        if is_grease(row["type"]):
            row["type"] = "GREASE"
    shape["ciphers"] = ["GREASE" if is_grease(v) else v for v in shape["ciphers"]]
    if case["template"].startswith("Chrome"):
        rows = shape["extensions"]
        if rows[0] != dict(type="GREASE", bytes=0, payload_hex="") or rows[
            -2 if psk else -1
        ] != dict(type="GREASE", bytes=1, payload_hex="00"):
            raise ValueError("reference Chrome GREASE positions changed")
        shape["extensions"] = [
            rows[0],
            *sorted(rows[1 : -2 if psk else -1], key=lambda e: e["type"]),
            *rows[-2 if psk else -1 :],
        ]
    return shape


def check_reference_report(report: dict) -> dict:
    """Offline CF0 gate: complete scope, raw observations and known variations."""
    if (
        report.get("scope") != "selected-v1"
        or report.get("status") != "CAPTURED"
        or report.get("selection") != "full"
        or report.get("cleanup") is not True
        or report.get("source_unchanged") is not True
    ):
        raise ValueError("incomplete or unclean selected-profile reference run")
    if report.get("source") != report.get("source_after"):
        raise ValueError("reference source changed during capture")
    catalog = {case["id"]: case for case in reference_cases()}
    cases = report["cases"]
    if len(cases) != len(catalog) or {c["id"] for c in cases} != catalog.keys():
        raise ValueError("missing or duplicate reference cases")
    fixtures = json.loads(
        (CORE_DIR / "tests/fingerprints/mihomo-selected-v1.json").read_text()
    )
    baselines = {}
    for sample in fixtures["samples"]:
        case = catalog[sample["case_id"]]
        baselines[(sample["profile"], sample["context"])] = _reference_shape(
            validate_capture(sample), case
        )
    observed, tls_handshakes = 0, 0
    for row in cases:
        case = catalog[row["id"]]
        if (
            any(row.get(key) != value for key, value in case.items())
            or row["status"] != "CAPTURED"
            or not 1 <= len(row["observations"]) <= 4
        ):
            raise ValueError("reference case metadata or observations changed")
        for event in row["observations"]:
            hello = validate_capture(event)
            expected = (
                "tls-handshake-complete"
                if case["context"] in {"tls12", "tls13"}
                else "captured-only"
            )
            if event["status"] != expected or event["port"] != PORTS[case["context"]]:
                raise ValueError("reference observation has wrong outcome")
            if expected == "tls-handshake-complete":
                version = "TLSv1.2" if case["context"] == "tls12" else "TLSv1.3"
                if event["version"] != version:
                    raise ValueError("reference negotiated wrong TLS version")
                tls_handshakes += 1
            if case["profile"] != "none":
                profile = {"firefox120": "firefox", "safari16": "safari"}.get(
                    case["profile"], case["profile"]
                )
                context = "reality" if case["context"] == "reality" else "tcp"
                if _reference_shape(hello, case) != baselines[(profile, context)]:
                    raise ValueError(f"reference structure changed: {case['id']}")
            observed += 1
    return dict(
        scope="selected-v1",
        stage="CF0",
        status="BASELINE VERIFIED",
        cases=len(cases),
        observations=observed,
        tls_only_handshakes=tls_handshakes,
        business_interoperability="NOT TESTED",
        production_support="UNCHANGED",
    )


def _name(case):
    return f"{case['profile']}-{case['context']}-{case['sni_length']}"


def _node(case, server):
    context = case["context"]
    node = dict(
        name=_name(case),
        type="vless",
        server=server,
        port=PORTS[context],
        uuid="07070707-0707-0707-0707-070707070707",
        tls=True,
        servername=case["sni"],
        network=context if context in {"ws", "grpc"} else "tcp",
        alpn=["h2", "http/1.1"],
        **{"client-fingerprint": case["profile"]},
    )
    if context == "reality":
        # Public RFC 7748 test vector; observer never authenticates REALITY.
        public = bytes.fromhex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        )
        node["reality-opts"] = {
            "public-key": base64.urlsafe_b64encode(public).decode().rstrip("="),
            "short-id": "01020304",
        }
    else:
        node["skip-cert-verify"] = True
    if context == "ws":
        node["ws-opts"] = {"path": "/capture"}
    elif context == "grpc":
        node["grpc-opts"] = {"grpc-service-name": "capture"}
    return node


def _probe(client, case, target, secret):
    query = urllib.parse.urlencode(dict(url=f"http://{target}:80/", timeout=3000))
    request = urllib.request.Request(
        f"http://{client}:25000/proxies/{_name(case)}/delay?{query}",
        headers={"Authorization": "Bearer " + secret},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        body = response.read(4097)
        if len(body) > 4096:
            raise ValueError("reference controller response limit")
        # This observer cannot serve VLESS or a URL: delay failure is expected.
        return dict(delay_http_status=response.status, business_result="NOT TESTED")


def _events(observer, after):
    query = (
        "import json,pathlib,sys; p=pathlib.Path('/data/events.jsonl'); "
        "assert p.stat().st_size <= 8*1024*1024; "
        "print(json.dumps(p.read_text().splitlines()[int(sys.argv[1]):]))"
    )
    lines = json.loads(
        command("exec", observer.name, "python", "-c", query, str(after))
    )
    return [json.loads(line) for line in lines]


def run_reference(output: Path, selected=None) -> int:
    catalog = {case["id"]: case for case in reference_cases()}
    ids = list(catalog) if selected is None else selected
    if not ids or len(set(ids)) != len(ids) or not set(ids) <= catalog.keys():
        raise ValueError("invalid reference capture selection")
    output = output.resolve()
    if output.parent != CORE_DIR / "target/interop/runs" or output.exists():
        raise ValueError("fresh in-repository reference run directory required")
    output.mkdir(parents=True)
    report = dict(
        scope="selected-v1",
        stage="CF0",
        kind="reference-clienthello-only",
        status="NOT RUN",
        production_support="UNCHANGED",
        business_interoperability="NOT TESTED",
        selection="full" if set(ids) == catalog.keys() else "partial",
        source=source_identity(),
        cases=[],
        cleanup=False,
        source_unchanged=False,
    )
    lab = None
    try:
        with exclusive_run(), contextlib.ExitStack() as stack:
            identity = {}
            binary = download_mihomo(
                "linux-arm64", directory=output / "official-mihomo", identity=identity
            )
            report["mihomo"] = identity
            build = run_command(["go", "version", "-m", str(binary)], timeout=10)
            if build.returncode or not build.cleanup:
                raise RuntimeError("official binary build identity query failed")
            (output / "mihomo-build-info.txt").write_bytes(build.stdout)
            report["utls_build_info"] = [
                line.strip()
                for line in build.stdout.decode().splitlines()
                if "utls" in line or "vcs.revision" in line
            ]
            if not any(
                "github.com/metacubex/utls\tv1.8.7\t" in line
                for line in report["utls_build_info"]
            ):
                raise RuntimeError(
                    "reference uTLS revision changed; recheck selected template mapping"
                )
            root = Path(
                stack.enter_context(
                    tempfile.TemporaryDirectory(prefix="private-", dir=output)
                )
            )
            observer_root, client_root = root / "observer", root / "client"
            observer_root.mkdir()
            client_root.mkdir()
            certificates(observer_root)
            shutil.copy2(
                Path(__file__).with_name("container_tls_observer.py"),
                observer_root / "observer.py",
            )
            shutil.copy2(binary, client_root / "mihomo")
            lab = ContainerLab(report.setdefault("isolation", {}), mtu=1500)
            observer = lab.start(
                stack,
                observer_root,
                "cf0-observer",
                [
                    "env",
                    "VCORE_ISOLATED_TLS_OBSERVER=1",
                    "python",
                    "-B",
                    "-u",
                    "/data/fixture/observer.py",
                ],
            )
            observer.release()
            for port in sorted(set(PORTS.values())):
                observer.wait_tcp(port)
            secret = secrets.token_hex(24)
            nodes = {
                _name(catalog[case]): _node(catalog[case], observer.ipv4)
                for case in ids
            }
            config = dict(
                proxies=list(nodes.values()),
                rules=["MATCH,REJECT"],
                secret=secret,
                **{"log-level": "warning", "external-controller": "0.0.0.0:25000"},
            )
            (client_root / "config.json").write_text(json.dumps(config))
            client = lab.start(
                stack,
                client_root,
                "cf0-mihomo",
                [
                    "/data/fixture/mihomo",
                    "-d",
                    "/data/mihomo",
                    "-f",
                    "/data/fixture/config.json",
                ],
            )

            def retain_logs():
                for role, peer in (("observer", observer), ("client", client)):
                    if peer.log.exists():
                        text = peer.log.read_text(errors="replace")[-16384:]
                        for value in (secret, observer.ipv4, client.ipv4):
                            text = text.replace(value, "<fixture>")
                        (output / f"{role}.log").write_text(redact(text))

            stack.callback(retain_logs)
            identity["version"] = command(
                "exec", client.name, "/data/fixture/mihomo", "-v"
            ).strip()
            digest = command(
                "exec", client.name, "sha256sum", "/data/fixture/mihomo"
            ).split()[0]
            if digest != identity["binary_sha256"]:
                raise RuntimeError("container official binary identity mismatch")
            report["observer_tls"] = command(
                "exec",
                observer.name,
                "python",
                "-c",
                "import ssl; print(ssl.OPENSSL_VERSION)",
            ).strip()
            client.release()
            client.wait_tcp(25000)
            observed_count = 0
            for case_id in ids:
                case = catalog[case_id]
                row = dict(case, status="NOT RUN", observations=[])
                report["cases"].append(row)
                row["controller"] = _probe(client.ipv4, case, observer.ipv4, secret)
                deadline = time.monotonic() + 6
                while True:
                    events = _events(observer, observed_count)
                    if events or time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
                if not 1 <= len(events) <= 4:
                    raise RuntimeError(
                        f"reference observation count mismatch: {case_id}"
                    )
                observed_count += len(events)
                expected = (
                    "tls-handshake-complete"
                    if case["context"] in {"tls12", "tls13"}
                    else "captured-only"
                )
                for event in events:
                    row["observations"].append(event)
                    if "client_hello_b64" not in event:
                        raise RuntimeError(
                            f"reference observer did not capture a hello: {case_id}"
                        )
                    hello = parse_client_hello(
                        base64.b64decode(event["client_hello_b64"], validate=True)
                    )
                    event["parsed"] = hello
                    sni = next(
                        (e["names"] for e in hello["extensions"] if e["type"] == 0), []
                    )
                    if (
                        event["status"] != expected
                        or event["port"] != PORTS[case["context"]]
                        or sni != [dict(type=0, name=case["sni"])]
                    ):
                        raise RuntimeError(
                            f"reference TLS observation mismatch: {case_id}"
                        )
                row["status"] = "CAPTURED"
                print(
                    json.dumps(
                        dict(
                            case_id=case_id,
                            status=row["status"],
                            observations=len(events),
                        )
                    ),
                    flush=True,
                )
            client.ensure_alive()
            observer.ensure_alive()
            report["status"] = "CAPTURED"
    except BaseException as error:
        report["status"] = "FAIL"
        report["error"] = redact(f"{type(error).__name__}: {error}")
        raise
    finally:
        report["source_after"] = source_identity()
        report["source_unchanged"] = report["source_after"] == report["source"]
        if lab is not None:
            report["cleanup"] = not any(
                item["configuration"].get("labels", {}).get("vcore-run") == lab.run_id
                for item in listing()
            ) and all(peer.get("joined") for peer in report["isolation"]["peers"])
        if report["status"] == "CAPTURED" and not (
            report["source_unchanged"] and report["cleanup"]
        ):
            report["status"] = "FAIL"
        (output / "reference-results.json").write_text(
            json.dumps(report, indent=2) + "\n"
        )
        print(
            json.dumps(
                {key: report[key] for key in ("status", "cleanup", "source_unchanged")}
            ),
            flush=True,
        )
    return 0 if report["status"] == "CAPTURED" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true")
    mode.add_argument("--run-dir", type=Path)
    mode.add_argument("--check-run", type=Path)
    parser.add_argument("--case", action="append")
    args = parser.parse_args(argv)
    if args.check_run:
        if args.case:
            parser.error("--case requires --run-dir")
        report = args.check_run / "reference-results.json"
        if report.stat().st_size > 8 * 1024 * 1024:
            raise ValueError("reference report size limit")
        print(
            json.dumps(check_reference_report(json.loads(report.read_text())), indent=2)
        )
        return 0
    if args.list:
        if args.case:
            parser.error("--case requires --run-dir")
        print(json.dumps(reference_cases(), indent=2))
        return 0

    def stop_signal(_signum, _frame):
        raise KeyboardInterrupt()

    previous = signal.signal(signal.SIGTERM, stop_signal)
    try:
        return run_reference(args.run_dir, args.case)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    sys.exit(main())
