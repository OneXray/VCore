"""CF5 public-config TLS wire gate over memory IO; no network observer."""

from __future__ import annotations

import argparse
import base64
import copy
import io
import json
import os
from pathlib import Path

from .builds import CORE_DIR
from .container_tls_observer import capture_client_hello
from .protocol_fingerprint_reference import PROFILES, SNIS, TEMPLATES, _reference_shape
from .protocol_inputs import redact, same_source, source_identity
from .protocol_peers import run_command
from .tls_client_hello import parse_client_hello, validate_capture

CONTEXTS = ("tcp", "ws", "grpc", "reality", "vision", "xhttp-h1", "xhttp-h2")


def expected_shape(sample, context):
    """Transform an independent baseline only for documented caller policies."""
    case = dict(template=sample["template"], sni=SNIS[0], context=sample["context"])
    shape = _reference_shape(validate_capture(sample), case)
    tls13 = context in {"vision", "xhttp-h1", "xhttp-h2"}
    if tls13:
        # Standard Vision/XHTTP require TLS1.3 before authentication. These
        # TLS1.2-only fields are omitted by native version policy, not hidden
        # from actual captures. REALITY instead enforces TLS1.3 natively while
        # retaining the browser offer, exactly as the reference does.
        shape["ciphers"] = [
            c for c in shape["ciphers"] if c in {"GREASE", 4865, 4866, 4867}
        ]
        shape["extensions"] = [
            e for e in shape["extensions"] if e["type"] not in {11, 23, 35, 65281}
        ]
    if context in {"ws", "xhttp-h1"}:
        shape["extensions"] = [
            e for e in shape["extensions"] if e["type"] not in {17513, 17613}
        ]
    for extension in shape["extensions"]:
        if extension["type"] == 43:
            extension["values"] = [
                v
                for v in extension["values"]
                if v == "GREASE" or v >= (772 if tls13 else 771)
            ]
            extension["bytes"] = 1 + 2 * len(extension["values"])
    return shape


def check_captures(rows):
    wanted = {
        (p, c, s, a) for p in PROFILES for c in CONTEXTS for s in SNIS for a in range(2)
    }
    actual = [(r["profile"], r["context"], r["sni"], r["attempt"]) for r in rows]
    if len(actual) != len(wanted) or set(actual) != wanted:
        raise ValueError("incomplete or duplicate public-config wire matrix")
    samples = json.loads(
        (CORE_DIR / "tests/fingerprints/mihomo-selected-v1.json").read_text()
    )["samples"]
    baselines = {(s["profile"], s["context"]): s for s in samples}
    results = []
    for row in rows:
        profile, context = row["profile"], row["context"]
        canonical = {"firefox120": "firefox", "safari16": "safari"}.get(
            profile, profile
        )
        reference = baselines[(canonical, "reality" if context == "reality" else "tcp")]
        encoded = row["records_b64"]
        if len(encoded) > 128 * 1024:
            raise ValueError("wire capture size limit")
        wire = base64.b64decode(encoded, validate=True)
        records, raw, layout = capture_client_hello(io.BytesIO(wire).read)
        if records != wire or any(
            r["type"] != 22 or r["version"] != 769 for r in layout
        ):
            raise ValueError("unexpected initial TLS record envelope")
        hello = parse_client_hello(raw)
        alpn = (
            ["http/1.1"]
            if context in {"ws", "xhttp-h1"}
            else ["h2"]
            if context == "xhttp-h2"
            else ["h2", "http/1.1"]
        )
        shape = _reference_shape(
            hello, dict(row, template=TEMPLATES[profile]), expected_alpn=alpn
        )
        expected = expected_shape(reference, context)
        if shape != expected:
            differences = {
                k: dict(expected=expected.get(k), observed=shape.get(k))
                for k in expected.keys() | shape.keys()
                if expected.get(k) != shape.get(k)
            }
            raise ValueError(
                f"{profile}/{context}/{len(row['sni'])}/{row['attempt']}: "
                f"{json.dumps(differences)}"
            )
        results.append(
            dict(
                copy.deepcopy(row),
                client_hello_b64=base64.b64encode(raw).decode(),
                records=layout,
                parsed=hello,
                status="SHAPE VERIFIED",
            )
        )
    return results


def check_warm_captures(rows):
    wanted = {
        (p, v, phase)
        for p in ("chrome", "chrome120", "firefox", "safari")
        for v in ("TLSv1_2", "TLSv1_3")
        for phase in ("cold", "warm", "after-hint")
    }
    actual = [(r["profile"], r["version"], r["phase"]) for r in rows]
    if len(actual) != len(wanted) or set(actual) != wanted:
        raise ValueError("incomplete or duplicate warm/expiry matrix")
    samples = json.loads(
        (CORE_DIR / "tests/fingerprints/mihomo-selected-v1.json").read_text()
    )["samples"]
    baselines = {s["profile"]: s for s in samples if s["context"] == "tcp"}
    results = []
    for row in rows:
        profile, version, phase = row["profile"], row["version"], row["phase"]
        stateful_id = profile == "safari" and version == "TLSv1_2"
        resumed = phase == "warm" or (phase == "after-hint" and stateful_id)
        if row["resumed"] != resumed:
            raise ValueError("unexpected real peer resumption/expiry outcome")
        wire = base64.b64decode(row["records_b64"], validate=True)
        records, raw, layout = capture_client_hello(io.BytesIO(wire).read)
        if wire[len(records) :] not in (b"", b"\x14\x03\x03\x00\x01\x01"):
            raise ValueError("unexpected warm first flight beyond ClientHello/CCS")
        hello = parse_client_hello(raw)
        shape = _reference_shape(
            hello,
            dict(template=TEMPLATES[profile], sni="fixture.invalid", context="tcp"),
            allow_psk=True,
        )
        expected = expected_shape(baselines[profile], "tcp")
        if resumed and not stateful_id:
            length = row["prior_ticket_bytes"]
            if not isinstance(length, int) or not 1 <= length <= 4096:
                raise ValueError("independent peer did not issue a bounded ticket")
            if version == "TLSv1_3":
                expected["extensions"].append(
                    dict(type=41, bytes=length + 43, identities=[length], binders=[32])
                )
            else:
                ticket = next(e for e in expected["extensions"] if e["type"] == 35)
                ticket.update(bytes=length, ticket_bytes=length)
        if shape != expected:
            differences = {
                k: dict(expected=expected.get(k), observed=shape.get(k))
                for k in expected.keys() | shape.keys()
                if expected.get(k) != shape.get(k)
            }
            raise ValueError(
                f"warm {profile}/{version}/{phase}: {json.dumps(differences)}"
            )
        results.append(
            dict(
                row,
                records_b64=base64.b64encode(records).decode(),
                client_hello_b64=base64.b64encode(raw).decode(),
                records=layout,
                parsed=hello,
                status="SHAPE VERIFIED",
            )
        )
    return results


def run(output):
    if output.parent != CORE_DIR / "target/interop/runs":
        raise ValueError("use a fresh directory directly under target/interop/runs")
    output.mkdir(exist_ok=False)
    report = dict(
        stage="CF5",
        scope="memory-clienthello-structure",
        source=source_identity(),
        status="NOT RUN",
    )
    try:
        result = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--test",
                "fingerprint_capture",
                "--",
                "--nocapture",
            ],
            timeout=180,
            env=dict(
                os.environ, VCORE_FINGERPRINT_CAPTURE=str(output / "captures.json")
            ),
        )
        (output / "command.log").write_text(
            redact(result.stdout.decode(errors="replace"))
        )
        report["cleanup"] = result.cleanup
        if result.returncode or not result.cleanup:
            raise RuntimeError("memory capture command failed")
        report["cases"] = check_captures(
            json.loads((output / "captures.json").read_text())
        )
        warm = run_command(
            [
                "cargo",
                "test",
                "--locked",
                "--all-features",
                "--lib",
                "security::tls::tests::named_wire",
                "--",
                "--nocapture",
            ],
            timeout=180,
            env=dict(
                os.environ, VCORE_FINGERPRINT_WARM_CAPTURE=str(output / "warm.json")
            ),
        )
        (output / "warm-command.log").write_text(
            redact(warm.stdout.decode(errors="replace"))
        )
        report["cleanup"] = report["cleanup"] and warm.cleanup
        if warm.returncode or not warm.cleanup:
            raise RuntimeError("warm/expiry/version gate failed")
        report["warm_cases"] = check_warm_captures(
            json.loads((output / "warm.json").read_text())
        )
        report["status"] = "PASS"
    except Exception as error:
        report.update(status="FAIL", error=redact(str(error)))
    finally:
        report["source_after"] = source_identity()
        report["source_unchanged"] = same_source(
            report["source"], report["source_after"]
        )
        if not report["source_unchanged"]:
            report["status"] = "FAIL"
        (output / "shape-results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"], report.get("error", ""))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    raise SystemExit(run(parser.parse_args().output.resolve()))
