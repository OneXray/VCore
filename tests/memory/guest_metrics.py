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
owned_sockets = set()
for fd in Path("/proc/1/fd").iterdir():
    try:
        link = os.readlink(fd)
    except FileNotFoundError:
        continue
    if link.startswith("socket:["):
        owned_sockets.add(link[8:-1])
sockets = {}
for transport in ("tcp", "tcp6", "udp", "udp6"):
    values = []
    for line in Path("/proc/net", transport).read_text().splitlines()[1:]:
        fields = line.split()
        if fields[9] in owned_sockets:
            values.append({"local": fields[1], "remote": fields[2], "state": fields[3]})
    sockets[transport] = values
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
            "pid1_sockets": sockets,
            "socket_scope": "kernel sockets, not TLS or QUIC session counts",
        }
    )
)
