"""Independent full-CN reference inputs, outside the measured VCore process.

Decode the official V2Ray protobuf wire schema, use Python sets/regular
expressions/ipaddress rather than the Rust matcher's implementation. The CN
regex witness catalog is intentionally closed: an upstream pattern change must
get reviewed witnesses instead of silently losing coverage.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import re
from collections import Counter
from pathlib import Path

from .memory_inputs import _fields, save
from .protocol_inputs import sha256

# Independent positive/negative witnesses, including both alternation arms
# where meaningful. Full-category expectations also account for other records.
REGEX_WITNESSES = {
    r".+\.awsdns-cn-[0-9][0-9]\.(biz|com|net|top)$": (
        [f"a.awsdns-cn-09.{tld}" for tld in ("biz", "com", "net", "top")],
        ["a.awsdns-cn-0x.com", "a.awsdns-cn-09.com.test"],
    ),
    r".+\.awsdns-cn-[0-9][a-e0-9]\.cn$": (
        ["a.awsdns-cn-0e.cn", "a.awsdns-cn-99.cn"],
        ["a.awsdns-cn-0f.cn", "awsdns-cn-09.cn"],
    ),
    r"^(.+\.)*zh\.okaapps\.com$": (
        ["zh.okaapps.com", "a.b.zh.okaapps.com"],
        ["xzh.okaapps.com", "zh.okaapps.com.test"],
    ),
    r"^.+-mihayo\.akamaized\.net$": (
        ["a-mihayo.akamaized.net"],
        ["mihayo.akamaized.net", "a-mihayo.akamaized.net.test"],
    ),
    r"^cdn\d-epicgames-\d+\.file\.myqcloud\.com$": (
        ["cdn1-epicgames-23.file.myqcloud.com"],
        ["cdn12-epicgames-23.file.myqcloud.com", "cdnx-epicgames-2.file.myqcloud.com"],
    ),
    r"^epicgames-download\d-\d+\.file\.myqcloud\.com$": (
        ["epicgames-download1-23.file.myqcloud.com"],
        [
            "epicgames-download12-3.file.myqcloud.com",
            "epicgames-download1-x.file.myqcloud.com",
        ],
    ),
    **{
        rf"^r+[0-9]+(---|\.)sn-(2x3|ni5|j5o)\w{{5}}\.{suffix}$": (
            [
                f"rr12{sep}sn-{region}abc09.{host}"
                for sep in ("---", ".")
                for region in ("2x3", "ni5", "j5o")
            ],
            [
                f"r1.sn-2x3abcd.{host}",
                f"r1.sn-xyzabc09.{host}",
                f"r1.sn-2x3abc09.{host}.test",
            ],
        )
        for suffix, host in (
            (r"googlevideo\.com", "googlevideo.com"),
            (r"xn--ngstr-lra8j\.com", "xn--ngstr-lra8j.com"),
        )
    },
}


def cn_entries(path: Path):
    """Read exactly one CN from complete assets; never truncate or substitute."""
    selected = None
    for field, wire, message in _fields(memoryview(path.read_bytes())):
        if (field, wire) != (1, 2):
            raise ValueError("unexpected top-level GeoData field")
        fields = list(_fields(message))
        if [bytes(v).lower() for f, w, v in fields if (f, w) == (1, 2)] == [b"cn"]:
            if selected is not None:
                raise ValueError("duplicate CN")
            selected = fields
    if selected is None:
        raise ValueError("missing CN")
    if path.name == "geoip.dat" and any(f == 3 and v for f, _, v in selected):
        raise ValueError("reverse CN is not supported")
    return [
        dict((f, v) for f, _, v in _fields(m))
        for f, w, m in selected
        if (f, w) == (2, 2)
    ]


class SiteReference:
    def __init__(self, records):
        self.records = records
        self.domains = {v for kind, v in records if kind == 2}
        self.full = {v for kind, v in records if kind == 3}
        self.plain = [v for kind, v in records if kind == 0]
        self.regexes = [re.compile(v, re.ASCII) for kind, v in records if kind == 1]
        if any(kind not in (0, 1, 2, 3) for kind, _ in records):
            raise ValueError("unsupported reference record")

    def matches(self, name):
        labels = name.split(".")
        return (
            name in self.full
            or any(
                ".".join(labels[index:]) in self.domains for index in range(len(labels))
            )
            or any(value in name for value in self.plain)
            or any(pattern.search(name) for pattern in self.regexes)
        )


class IpReference:
    def __init__(self, networks):
        self.intervals = {}
        for version in (4, 6):
            merged = []
            for lo, hi in sorted(
                (int(n.network_address), int(n.broadcast_address))
                for n in networks
                if n.version == version
            ):
                if merged and lo <= merged[-1][1] + 1:
                    merged[-1] = (merged[-1][0], max(hi, merged[-1][1]))
                else:
                    merged.append((lo, hi))
            self.intervals[version] = (
                [lo for lo, _ in merged],
                [hi for _, hi in merged],
            )

    def matches(self, address):
        starts, ends = self.intervals[address.version]
        index = bisect.bisect_right(starts, int(address)) - 1
        return index >= 0 and int(address) <= ends[index]


def route_witnesses(records, networks):
    """Small real-network sample; exhaustive semantics stay in the diagnostic."""
    sites = SiteReference(records)
    domains = [v for kind, v in records if kind == 2]
    full = next(v for kind, v in records if kind == 3 and not sites.matches("sub." + v))
    result = [
        {"id": "domain-first", "value": domains[0], "matched": True},
        {"id": "domain-tail", "value": domains[-1], "matched": True},
        {"id": "domain-sub", "value": "sub." + domains[-1], "matched": True},
        {"id": "full-exact", "value": full, "matched": True},
        {"id": "full-sub-negative", "value": "sub." + full, "matched": False},
        {"id": "domain-negative", "value": "vcore-cn-negative.test", "matched": False},
    ]
    literals_only = SiteReference([(k, v) for k, v in records if k != 1])
    regex_name = next(
        v
        for yes, _ in REGEX_WITNESSES.values()
        for v in yes
        if not literals_only.matches(v)
    )
    result.append({"id": "regex-positive", "value": regex_name, "matched": True})
    for item in result:
        if bool(sites.matches(item["value"])) != item["matched"]:
            raise ValueError("route witness disagrees with full CN reference")
        item["kind"] = "site"
    for version in (4, 6):
        network = next(n for n in networks if n.version == version)
        result.append(
            {
                "id": f"ip{version}-positive",
                "kind": "ip",
                "value": str(
                    network.network_address + min(1, network.num_addresses - 1)
                ),
                "matched": True,
            }
        )
    return result


def _varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def _bytes(field, value):
    return _varint(field << 3 | 2) + _varint(len(value)) + value


def generate(asset_dir: Path, output: Path) -> dict:
    """Write exhaustive witnesses and small isolated regex assets, not a core."""
    output.mkdir(parents=True, exist_ok=False)
    records = [
        (r.get(1, 0), bytes(r[2]).decode("ascii"))
        for r in cn_entries(asset_dir / "geosite.dat")
    ]
    if len(records) != len(set(records)):
        raise ValueError("review duplicate official CN records")
    sites = SiteReference(records)
    networks = [
        ipaddress.ip_network(
            (ipaddress.ip_address(bytes(r[1])), r.get(2, 0)), strict=True
        )
        for r in cn_entries(asset_dir / "geoip.dat")
    ]
    ips = IpReference(networks)
    counts = Counter()
    with (output / "cases.jsonl").open("w") as stream:

        def emit(kind, **data):
            counts[kind] += 1
            stream.write(json.dumps({"kind": kind, **data}, ensure_ascii=True) + "\n")

        for index, (kind, value) in enumerate(records):
            if kind == 1:
                continue
            if kind not in (2, 3) or not re.fullmatch(r"[a-z0-9.-]+", value):
                raise ValueError("review changed CN value/normalization witnesses")
            candidates = (value, "sub." + value, "not" + value, value + ".invalid")
            for boundary, name in enumerate(candidates):
                if len(name) > 253 or any(len(label) > 63 for label in name.split(".")):
                    # Prefixing a maximum-size label makes invalid DNS input,
                    # not a valid negative match. Check rejection explicitly.
                    emit("normalize", value=name, normalized=None)
                    continue
                emit(
                    "site",
                    id=f"record-{index}-{boundary}",
                    value=name,
                    matched=sites.matches(name),
                )
            emit(
                "site",
                id=f"normalized-{index}",
                value=value.upper() + ".",
                matched=sites.matches(value),
            )

        patterns = [v for kind, v in records if kind == 1]
        if set(patterns) != set(REGEX_WITNESSES):
            raise ValueError(
                "official CN regex changed: review complete witness catalog"
            )
        for index, pattern in enumerate(patterns):
            regex_dir = output / f"regex-{index}"
            regex_dir.mkdir()
            domain = b"\x08\x01" + _bytes(2, pattern.encode())
            (regex_dir / "geosite.dat").write_bytes(
                _bytes(1, _bytes(1, b"cn") + _bytes(2, domain))
            )
            for expected, names in zip(
                (True, False), REGEX_WITNESSES[pattern], strict=True
            ):
                for number, name in enumerate(names):
                    if bool(re.search(pattern, name, flags=re.ASCII)) != expected:
                        raise ValueError("incorrect independent regex witness")
                    emit("regex", index=index, value=name, matched=expected)
                    emit(
                        "site",
                        id=f"regex-{index}-{expected}-{number}",
                        value=name,
                        matched=sites.matches(name),
                    )

        for index, network in enumerate(networks):
            address_type = type(network.network_address)
            first, last = int(network.network_address), int(network.broadcast_address)
            for boundary, value in enumerate((first, last, first - 1, last + 1)):
                if 0 <= value < 1 << network.max_prefixlen:
                    address = address_type(value)
                    emit(
                        "ip",
                        id=f"cidr-{index}-{boundary}",
                        value=str(address),
                        matched=ips.matches(address),
                    )
        for value in (
            "0.0.0.0",
            "255.255.255.255",
            "::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "::ffff:1.0.1.1",
        ):
            emit(
                "ip",
                id="family-boundary-" + value,
                value=value,
                matched=ips.matches(ipaddress.ip_address(value)),
            )
        for value, normalized in (
            ("BAIDU.COM.", "baidu.com"),
            ("例子.测试", "xn--fsqu00a.xn--0zwm56d"),
            ("faß.de", "xn--fa-hia.de"),
            ("ｅｘａｍｐｌｅ.cn", "example.cn"),
            ("xn--a.test", "xn--a.test"),
            ("example..com", None),
            ("example.com..", None),
            ("a_b.test", None),
            ("-a.test", None),
            ("a" * 64 + ".test", None),
            ("", None),
        ):
            emit("normalize", value=value, normalized=normalized)

    report = {
        "records": len(records),
        "record_types": dict(Counter(k for k, _ in records)),
        "cidrs": len(networks),
        "cidr_families": dict(Counter(n.version for n in networks)),
        "regexes": len(patterns),
        "cases": dict(counts),
        "assets": {
            name: sha256(asset_dir / name) for name in ("geosite.dat", "geoip.dat")
        },
        "cases_sha256": sha256(output / "cases.jsonl"),
        "scope": "independent-reference-not-measured-process",
        "routes": route_witnesses(records, networks),
    }
    save(output / "reference.json", report)
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(generate(args.asset_dir, args.output), indent=2))
