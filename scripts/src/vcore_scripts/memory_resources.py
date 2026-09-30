"""Production-only resource diagnostics, separate from the kernel memory gate."""

import re
import subprocess
from datetime import datetime, timedelta

from .memory_inputs import save


def capture(pid, started, directory):
    """Limit to the owned PID/time window and existing non-sensitive stats events."""
    events = (
        "resource_stats_",
        "tun_netstack_stats_",
        "runtime_dns_tcp_pool_",
    )
    predicate = (
        f'processIdentifier == {pid} AND subsystem == "io.github.onexray.vcore"'
        " AND ("
        + " OR ".join(f'eventMessage CONTAINS "{event}"' for event in events)
        + ")"
    )
    result = {"scope": "production-log-diagnostic", "pid": pid, "available": False}
    try:
        output = subprocess.run(
            [
                "/usr/bin/log",
                "show",
                "--start",
                started,
                "--end",
                (datetime.now() + timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S"),
                "--style",
                "compact",
                "--predicate",
                predicate,
            ],
            timeout=15,
            check=True,
            capture_output=True,
            text=True,
        )
        rows = []
        for line in output.stdout.splitlines():
            if not any(event in line for event in events):
                continue
            fields = dict(re.findall(r"\b([a-z_]+)=([a-z_0-9]+)", line))
            if "event" in fields:
                rows.append(
                    {
                        key: int(value) if value.isdigit() else value
                        for key, value in fields.items()
                    }
                )
        result.update(available=bool(rows), snapshots=rows)
        final = [row for row in rows if row.get("event", "").endswith("_final")]
        result["final_current_zero"] = bool(final) and all(
            value == 0
            for row in final
            for key, value in row.items()
            if key.endswith("_current") or key.startswith("current_")
        )
    except (OSError, subprocess.SubprocessError):
        result["reason"] = "owned production statistics unavailable"
    save(directory / "resource-diagnostics.json", result)
    return result
