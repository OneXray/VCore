"""Frozen memory candidate and explicit final-matrix orchestration."""

import json
import math
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from . import memory_benchmark as benchmark
from . import memory_cold_start as cold
from . import memory_protocols as protocols
from . import memory_socks_load as load
from .memory_candidate import read, verify_files
from .memory_inputs import RunStore, save
from .protocol_inputs import sha256


def catalog():
    groups = [
        {"id": "facilities", "cases": list(benchmark.CASES)},
        {"id": "cold-start", "cases": cold.cases() + [cold.DIAGNOSTIC_CASE]},
        {"id": "peer-capacity", "cases": list(benchmark.CAPACITY_CASES)},
    ]
    for entry in ("socks", "tun"):
        for family in ("v4", "v6"):
            selected = {
                name: spec
                for name, spec in load.CASES.items()
                if not spec.get("development")
                and spec["family"] == ("IPv6" if family == "v6" else "IPv4")
                and spec.get("entrypoint", "SOCKS5")
                == ("fd-TUN" if entry == "tun" else "SOCKS5")
            }
            groups.append(
                {
                    "id": f"base-{entry}-{family}",
                    "cases": [n for n, s in selected.items() if not s.get("profile")],
                }
            )
            for profile in protocols.PROFILES:
                groups.append(
                    {
                        "id": f"protocol-{entry}-{profile}-{family}",
                        "cases": [
                            n
                            for n, s in selected.items()
                            if s.get("profile") == profile
                            and n.startswith("profile-")
                            and not s.get("updates")
                            and not n.endswith("-soak")
                        ],
                    }
                )
            groups.extend(
                [
                    {
                        "id": f"updates-{entry}-{family}",
                        "requires": ["trusted-https-update"],
                        "cases": [
                            n
                            for n, s in selected.items()
                            if s.get("profile") == "socks5" and "-update-" in n
                        ],
                    },
                    {
                        "id": f"lifecycle-{entry}-{family}",
                        "cases": [n for n in selected if n.startswith("lifecycle-")],
                    },
                    {
                        "id": f"mixed-soak-{entry}-{family}",
                        "cases": [f"profile-{entry}-mixed-eight-{family}-soak"],
                    },
                ]
            )
    names = [n for group in groups for n in group["cases"]]
    if len(set(names)) != len(names) or any(not g["cases"] for g in groups):
        raise ValueError("invalid final memory matrix grouping")
    # Background transfer only: calibration, setup, lifecycle, references, and
    # platform/device checks add time. It is deliberately not an ETA.
    seconds = sum(
        load.CASES[n]["seconds"] * (2 if load.CASES[n].get("warm_reuse") else 1)
        for n in names
        if n in load.CASES and not load.CASES[n].get("expected_cancel")
    )
    return {
        "schema": 1,
        "resource_profile": "standard; no mobile-only quota implemented",
        "limit_bytes": 50_000_000,
        "final_matrix_accepted": False,
        "groups": groups,
        "case_count": len(names),
        "background_seconds_lower_bound": seconds,
        "conditional_groups": [
            {
                "id": "highest-memory-soak",
                "selection": "highest whole-PID peak across all protocol groups",
                "suffixes": ["soak-tcp-1000", "soak-udp-1000"],
            },
            {
                "id": "highest-cpu-pressure",
                "selection": "highest whole-PID CPU seconds per received GiB "
                "across all protocol groups",
                "suffixes": ["pressure-tcp-1000", "pressure-udp-1000"],
            },
        ],
        "external_gates": [
            {
                "id": "single-flow-udp",
                "status": "BLOCKED",
                "required": "capacity and zero loss; "
                "distributed listeners do not substitute",
            },
            {
                "id": "single-listener-udp",
                "status": "BLOCKED",
                "required": "original single-listener topology needs "
                "independent calibration",
            },
            {
                "id": "tun-driver-capacity",
                "status": "BLOCKED",
                "required": "resolve observed 64 Mbps multi-flow driver capacity "
                "before 1 Gbps",
            },
            {
                "id": "trusted-https-update",
                "status": "BLOCKED",
                "required": "owned trusted certificate/key/domain "
                "and distinct complete official snapshot",
            },
            {
                "id": "ios-provider",
                "status": "NOT RUN",
                "required": "signed production Provider, physical devices/OS matrix "
                "and authorized isolated 1 Gbps network",
            },
            {
                "id": "tvos-provider",
                "status": "NOT RUN",
                "required": "signed production Provider, physical Apple TVs/OS matrix "
                "and authorized isolated 1 Gbps network",
            },
            {
                "id": "repository-platform-regression",
                "status": "NOT RUN",
                "required": "candidate core/features/ABI/platform builds/"
                "container integration and optimization A/B guards",
            },
            {
                "id": "release-dependency-source",
                "status": "NOT RUN",
                "required": "at PR preparation use boring release branch "
                "at the same revision, rebuild/audit/refreeze affected gates",
            },
        ],
    }


def select_stress(rows):
    profiles = [r for r in rows if r["id"].startswith("protocol-")]
    if not profiles or any(r["status"] != "PASS" for r in profiles):
        return None
    return {
        group: max((r[key] for r in profiles), key=lambda r: r["value"])
        for group, key in (
            ("highest-memory-soak", "peak"),
            ("highest-cpu-pressure", "cpu"),
        )
    }


def _freeze(root, fixture):
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=benchmark.builds.CORE_DIR,
        text=True,
        timeout=20,
    )
    if dirty:
        raise ValueError(
            "commit all candidate source and documentation before freezing"
        )
    prefix = "profile-tun-mixed-eight-v4-"
    selected = [prefix + "standard-1"]
    if fixture:
        selected += [prefix + f"update-{kind}-replace" for kind in ("geoip", "geosite")]
    # Superset inputs: raw-IP driver, pinned TLS leaf, native Xray, complete CN
    # semantics. No workload or server is started by preparation.
    root = benchmark.run(
        identifiers=selected, run_dir=root, prepare_only=True, update_fixture=fixture
    )
    save(root / "matrix.json", catalog())
    save(
        root / "candidate.json",
        {
            "schema": 1,
            "created_utc": datetime.now(UTC).isoformat(),
            "status": "FROZEN_NOT_ACCEPTED",
            "manifest_sha256": sha256(root / "manifest.json"),
            "matrix_sha256": sha256(root / "matrix.json"),
            "final_matrix_accepted": False,
            "peer_version_verification": "binary versions checked "
            "inside each isolated run",
            "update_inputs": "FROZEN_NOT_VERIFIED" if fixture else "BLOCKED",
        },
    )
    read(root, benchmark._source())
    print(f"FROZEN_NOT_ACCEPTED: {root}")


def _directory(candidate, group):
    return benchmark.ROOT / (candidate.name + "--" + group["id"])


def _group_status(candidate, manifest, group):
    root = _directory(candidate, group)
    row = {"id": group["id"], "case_count": len(group["cases"]), "status": "NOT RUN"}
    if not root.exists():
        if group.get("requires") and "update_fixture" not in manifest:
            row["status"] = "BLOCKED: trusted HTTPS update inputs"
        return row
    try:
        identity = json.loads((root / "manifest.json").read_text())
        if (
            not identity.get("ready")
            or identity["source"] != manifest["source"]
            or identity["cases"] != group["cases"]
            or identity.get("candidate", {}).get("manifest_sha256")
            != sha256(candidate / "manifest.json")
            or identity.get("candidate", {}).get("matrix_sha256")
            != sha256(candidate / "matrix.json")
        ):
            raise ValueError("group candidate/case identity mismatch")
        verify_files(root, identity)
        store = RunStore(root, identity, resume=True)
        failures = []
        peak, cpu = {"value": -1}, {"value": -1}
        for name in group["cases"]:
            result = store.completed(name)
            if not result or not result.get("accepted"):
                failures.append(name)
                continue
            if group["id"].startswith("protocol-"):
                spec = load.CASES[name]
                measured = result["measurement"]
                entry = {"case": name, "profile": spec["profile"], "group": group["id"]}
                peak = max(
                    peak,
                    entry | {"value": measured["peak_bytes"]},
                    key=lambda r: r["value"],
                )
                if spec.get("mbps") == 1000:
                    received = sum(
                        b["traffic"]["received_bytes"]
                        for traffic in (result, result.get("warm_load", {}))
                        for b in traffic.get("branches", [])
                    )
                    value = (measured["user_seconds"] + measured["system_seconds"]) / (
                        received / (1024**3)
                    )
                    if not math.isfinite(value) or value <= 0:
                        raise ValueError("missing valid whole-PID CPU comparison")
                    cpu = max(cpu, entry | {"value": value}, key=lambda r: r["value"])
        report = json.loads((root / "results.json").read_text())
        passed = not failures and all(
            report.get(k) is True
            for k in (
                "complete",
                "source_unchanged",
                "cleanup",
                "instrumentation_accepted",
            )
        )
        row.update(
            status="PASS" if passed else "INCOMPLETE_OR_FAILED", pending_cases=failures
        )
        if passed and group["id"].startswith("protocol-"):
            if min(peak["value"], cpu["value"]) <= 0:
                raise ValueError("incomplete protocol ranking evidence")
            row.update(peak=peak, cpu=cpu)
    except (OSError, ValueError, KeyError, TypeError, ZeroDivisionError) as error:
        row.update(status="INVALID", reason=str(error))
    return row


def _conditional(matrix, choices):
    if choices is None:
        return []
    return [
        {
            "id": f"{row['id']}-{entry}-{family}",
            "requires": ["trusted-https-update"],
            "cases": [
                f"profile-{entry}-{choices[row['id']]['profile']}-{family}-{suffix}"
                for suffix in row["suffixes"]
            ],
        }
        for row in matrix["conditional_groups"]
        for entry in ("socks", "tun")
        for family in ("v4", "v6")
    ]


def _report(candidate, manifest, matrix):
    rows = [_group_status(candidate, manifest, g) for g in matrix["groups"]]
    selected = select_stress(rows)
    conditional = _conditional(matrix, selected)
    rows += [_group_status(candidate, manifest, g) for g in conditional]
    report = {
        "candidate_manifest_sha256": sha256(candidate / "manifest.json"),
        "groups": rows,
        "selected_stress_profiles": selected,
        "local_matrix_accepted": bool(
            selected and all(r["status"] == "PASS" for r in rows)
        ),
        # External device/release/capacity evidence is reviewed separately. This
        # macOS runner can never turn a self-declared external gate into PASS.
        "external_gates": matrix["external_gates"],
        "final_matrix_accepted": False,
    }
    save(candidate / "matrix-results.json", report)
    return report, conditional


def run(
    *,
    export=None,
    list_only=False,
    freeze=None,
    candidate=None,
    execute=False,
    report_only=False,
    verify_only=False,
    groups=None,
    update_fixture=None,
):
    if freeze:
        if candidate or groups:
            raise ValueError(
                "freeze cannot attach an existing candidate or select groups"
            )
        _freeze(freeze, update_fixture)
        return 0
    if update_fixture:
        raise ValueError("update fixture is immutable; supply it only when freezing")
    if candidate:
        candidate = Path(candidate).absolute()
        if (
            candidate.is_symlink()
            or candidate.resolve().parent != benchmark.ROOT.resolve()
        ):
            raise ValueError("candidate must be a direct child of target/memory")
        if not (execute or report_only or verify_only):
            raise ValueError("choose candidate --verify, --report or --run explicitly")
        manifest = read(candidate, benchmark._source())
        matrix = json.loads((candidate / "matrix.json").read_text())
        if verify_only:
            print("FROZEN_NOT_ACCEPTED: source, binaries and inputs unchanged")
            return 0
        report, conditional = _report(candidate, manifest, matrix)
        if execute:
            pending = matrix["groups"] + conditional
            if groups:
                unknown = set(groups) - {g["id"] for g in pending}
                if unknown:
                    raise ValueError(
                        "unknown/not-yet-ranked matrix groups: "
                        + ", ".join(sorted(unknown))
                    )
                pending = [g for g in pending if g["id"] in groups]
            for group in pending:
                if any(
                    r["id"] == group["id"] and r["status"] == "PASS"
                    for r in report["groups"]
                ):
                    print(f"REUSE {group['id']}: sealed group complete", flush=True)
                    continue
                if group.get("requires") and "update_fixture" not in manifest:
                    print(
                        f"BLOCKED {group['id']}: trusted HTTPS update inputs",
                        flush=True,
                    )
                    continue
                root = _directory(candidate, group)
                kwargs = {"resume": root} if root.exists() else {"run_dir": root}
                try:
                    benchmark.run(
                        identifiers=group["cases"], candidate=candidate, **kwargs
                    )
                finally:
                    report, _ = _report(candidate, manifest, matrix)
            # Newly ranked long tests require a second explicit invocation so
            # that the selected profiles are visible before long execution.
        for row in report["groups"]:
            print(f"{row['id']}: {row['status']}")
        print("Final matrix NOT ACCEPTED; see matrix-results.json and external gates")
        if groups and execute:
            return (
                0
                if all(
                    r["status"] == "PASS" for r in report["groups"] if r["id"] in groups
                )
                else 1
            )
        return 0 if report["local_matrix_accepted"] else 1
    if execute or report_only or verify_only or groups:
        raise ValueError("matrix execution/verification/report requires --candidate")
    matrix = catalog()
    if export:
        path = Path(export)
        if path.exists():
            raise ValueError("matrix export must not overwrite an existing file")
        save(path, matrix)
    if list_only or not export:
        for group in matrix["groups"]:
            print(f"{group['id']}: {len(group['cases'])} cases")
        print(json.dumps({k: v for k, v in matrix.items() if k != "groups"}, indent=2))
    return 0
