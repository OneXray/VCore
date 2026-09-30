"""Read-only guest counters; no host sysctl or socket buffer changes."""

import json
import os
from pathlib import Path

rows = Path("/proc/net/snmp").read_text().splitlines()
protocols = {}
for index in range(0, len(rows), 2):
    header, values = rows[index].split(), rows[index + 1].split()
    protocols[header[0].removesuffix(":")] = dict(
        zip(header[1:], map(int, values[1:]), strict=True)
    )
process = Path("/proc/1/stat").read_text().rsplit(")", 1)[1].split()
udp6 = {
    key: int(value)
    for key, value in (
        line.split() for line in Path("/proc/net/snmp6").read_text().splitlines()
    )
    if key.startswith("Udp6")
}
network = {}
for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
    interface, fields = line.split(":")
    values = list(map(int, fields.split()))
    network[interface.strip()] = {
        "rx_packets": values[1],
        "rx_errors": values[2],
        "rx_dropped": values[3],
        "tx_packets": values[9],
        "tx_errors": values[10],
        "tx_dropped": values[11],
    }
print(
    json.dumps(
        {
            "process_cpu_seconds": (int(process[11]) + int(process[12]))
            / os.sysconf("SC_CLK_TCK"),
            "process_rss_bytes": int(process[21]) * os.sysconf("SC_PAGE_SIZE"),
            "udp": protocols["Udp"],
            "udp6": udp6,
            "tcp": protocols["Tcp"],
            "network": network,
        }
    )
)
