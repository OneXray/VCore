#!/usr/bin/env python3
"""Windows demo: VCore TUN -> SOCKS5 -> a temporary Xray process.

The source config is not modified; its selected outbounds are copied only to a
user-temporary directory and deleted with the locally built Xray executable.
"""

from __future__ import annotations

import copy
import ctypes
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[3]
XRAY_SOURCE = ROOT / "references" / "Xray-core"
PACKAGE_NAME = "VCore.UwpDemo.Dev"
SOCKS_PORT = 19080
TUN_IPV4 = "192.168.8.1"
TUN_IPV6 = "fd00:8::2"
DNS_IPV4 = "223.5.5.5"
DNS_IPV6 = "2400:3200::1"
NTP_IPV4 = "203.107.6.88"
DIRECT_URL = "http://www.baidu.com/"
PROXY_URL = "https://www.cloudflare.com/cdn-cgi/trace"


def bridge_main(dll_path: str, request_path: str, response_path: str) -> None:
    dll = ctypes.CDLL(dll_path)
    invoke = dll.VCoreWindowsVpnInvoke
    invoke.argtypes = [ctypes.c_char_p]
    invoke.restype = ctypes.c_void_p
    free = dll.VCoreFree
    free.argtypes = [ctypes.c_void_p]
    free.restype = None
    response = invoke(Path(request_path).read_bytes())
    if not response:
        raise RuntimeError("VCoreWindowsVpnInvoke returned NULL")
    try:
        Path(response_path).write_bytes(ctypes.string_at(response))
    finally:
        free(response)


def powershell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


def ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def package_info() -> dict[str, str]:
    result = powershell(
        f"$p=Get-AppxPackage -Name {ps_quote(PACKAGE_NAME)} | Select-Object -First 1; "
        "if($null -eq $p){throw 'VCore UWP demo package is not installed'}; "
        "$p | Select-Object PackageFamilyName,InstallLocation | "
        "ConvertTo-Json -Compress"
    )
    return json.loads(result.stdout)


def invoke_bridge(
    temp: Path, package: dict[str, str], method: str, payload: dict
) -> dict:
    request = temp / "bridge-request.json"
    response = temp / "bridge-response.json"
    command = temp / "bridge.cmd"
    request.write_text(
        json.dumps(
            {"bridgeVersion": 3, "method": method, "payload": payload},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    response.unlink(missing_ok=True)
    command.write_bytes(
        (
            "@echo off\r\n"
            + subprocess.list2cmdline(
                [
                    sys.executable,
                    "-m",
                    "vcore_scripts.tun2socks",
                    "--bridge",
                    str(Path(package["InstallLocation"]) / "vcore.dll"),
                    str(request),
                    str(response),
                ]
            )
            + "\r\n"
        ).encode()
    )
    args = f'/d /c "{command}"'
    powershell(
        "Invoke-CommandInDesktopPackage "
        f"-PackageFamilyName {ps_quote(package['PackageFamilyName'])} "
        '-AppId App -Command "$env:SystemRoot\\System32\\cmd.exe" '
        f"-Args {ps_quote(args)} -PreventBreakaway"
    )
    deadline = time.monotonic() + 60
    while not response.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    if not response.exists():
        raise TimeoutError(f"packaged Windows bridge {method} timed out")
    result = json.loads(response.read_text(encoding="utf-8"))
    if not result["success"]:
        raise RuntimeError(f"Windows bridge {method} failed: {result['error']}")
    return result["data"]


def derive_xray_config(source_path: Path, temp: Path) -> tuple[dict, str, str]:
    source = json.loads(source_path.read_text(encoding="utf-8"))
    try:
        inbound = copy.deepcopy(
            next(item for item in source["inbounds"] if item["protocol"] == "socks")
        )
        inbound["listen"] = "127.0.0.1"
        inbound["port"] = SOCKS_PORT
        inbound["settings"]["udp"] = True
        inbound["sniffing"] = {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "routeOnly": True,
        }
        inbound_tag = inbound["tag"]
        proxy = copy.deepcopy(
            next(item for item in source["outbounds"] if item.get("tag") == inbound_tag)
        )
        direct = copy.deepcopy(
            next(item for item in source["outbounds"] if item["protocol"] == "freedom")
        )
        # Xray reads outbound sockopt only from streamSettings; the reference config
        # currently places the freedom binding at the ignored top level.
        if "sockopt" in direct:
            direct.setdefault("streamSettings", {})["sockopt"] = direct.pop("sockopt")
        direct_tag = direct["tag"]
    except (KeyError, StopIteration, TypeError) as error:
        raise ValueError(
            "source Xray config must contain a tagged SOCKS inbound, its matching "
            "outbound, and a tagged freedom outbound"
        ) from error
    direct_host = urlparse(DIRECT_URL).hostname
    rules = []
    if source.get("dns", {}).get("tag"):
        rules.append({"inboundTag": [source["dns"]["tag"]], "outboundTag": direct_tag})
    rules.extend(
        [
            {
                "domain": [f"full:{direct_host}"],
                "outboundTag": direct_tag,
                "ruleTag": "tun2socks-sniff-direct",
            },
            {"ip": [DNS_IPV4, NTP_IPV4], "outboundTag": direct_tag},
            {"inboundTag": [inbound_tag], "outboundTag": inbound_tag},
        ]
    )
    config = {
        "log": {
            "access": str(temp / "xray-access.log"),
            "error": "none",
            "loglevel": "warning",
        },
        "inbounds": [inbound],
        "outbounds": [proxy, direct],
        "routing": {"domainStrategy": "AsIs", "rules": rules},
    }
    if "dns" in source:
        config["dns"] = copy.deepcopy(source["dns"])
    return config, inbound_tag, direct_tag


def wait_for_socks(process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("temporary Xray process exited during startup")
        try:
            with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("temporary Xray SOCKS listener did not start")


def dns_probe(host: str) -> str:
    query_id = 0x4F56
    question = (
        b"".join(bytes([len(part)]) + part.encode("ascii") for part in host.split("."))
        + b"\0"
    )
    packet = (
        struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
        + question
        + struct.pack("!HH", 1, 1)
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(15)
        sock.connect((DNS_IPV4, 53))
        sock.send(packet)
        local_ip = sock.getsockname()[0]
        response = sock.recv(4096)
    if (
        len(response) < 12
        or struct.unpack("!H", response[:2])[0] != query_id
        or not response[2] & 0x80
    ):
        raise RuntimeError("invalid DNS response")
    if response[3] & 0x0F:
        raise RuntimeError(f"DNS returned rcode {response[3] & 0x0F}")
    return local_ip


def ntp_probe() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(15)
        sock.connect((NTP_IPV4, 123))
        sock.send(b"\x1b" + b"\0" * 47)
        local_ip = sock.getsockname()[0]
        response = sock.recv(512)
    if len(response) < 48:
        raise RuntimeError("truncated NTP response")
    return local_ip


def curl_probe(url: str) -> tuple[str, str]:
    result = subprocess.run(
        [
            "curl.exe",
            "-4",
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "--max-time",
            "30",
            "--output",
            "NUL",
            "--write-out",
            "%{http_code}|%{local_ip}",
            url,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    status, local_ip = result.stdout.strip().split("|", 1)
    if status == "000":
        raise RuntimeError(
            f"curl did not receive an HTTP response from {urlparse(url).hostname}"
        )
    return status, local_ip


def require_tun_source(label: str, address: str) -> None:
    if address != TUN_IPV4:
        raise RuntimeError(f"{label} used {address}, expected TUN source {TUN_IPV4}")


def wait_for_access_evidence(path: Path, inbound_tag: str, direct_tag: str) -> None:
    direct_marker = f"[{inbound_tag} -> {direct_tag}]"
    proxy_marker = f"[{inbound_tag} -> {inbound_tag}]"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        text = (
            path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
        )
        lines = text.splitlines()
        if (
            any(
                direct_marker in line and "tcp:" in line and ":80 " in line
                for line in lines
            )
            and any(
                proxy_marker in line and "tcp:" in line and ":443 " in line
                for line in lines
            )
            and any(
                direct_marker in line and f"udp:{DNS_IPV4}:53" in line for line in lines
            )
            and any(
                direct_marker in line and f"udp:{NTP_IPV4}:123" in line
                for line in lines
            )
        ):
            return
        time.sleep(0.1)
    raise RuntimeError(
        "Xray access log did not prove sniffed DIRECT, proxied TCP, DNS, and UDP routes"
    )


def vcore_yaml() -> str:
    return f"""tun:
  enable: true
  mtu: 1500
proxies:
  - name: xray
    type: socks5
    server: 127.0.0.1
    port: {SOCKS_PORT}
    udp: true
dns:
  enable: false
rules:
  - MATCH,xray
"""


def run_demo(source_config: Path | None = None) -> None:
    if os.name != "nt":
        raise RuntimeError("This demo requires Windows")
    source_config = source_config or Path.home() / "lib" / "xray" / "config.json"
    if not source_config.is_file() or not (XRAY_SOURCE / "go.mod").is_file():
        raise RuntimeError("Xray source checkout or source config is missing")

    package = package_info()
    with tempfile.TemporaryDirectory(prefix="vcore-tun2socks-") as directory:
        temp = Path(directory)
        initial = invoke_bridge(temp, package, "getVpnStatus", {})
        if initial["status"] != "disconnected":
            raise RuntimeError("Stop the existing VCore VPN before running this demo")

        xray_exe = temp / "xray.exe"
        env = os.environ.copy()
        env["CGO_ENABLED"] = "0"
        subprocess.run(
            [
                "go",
                "build",
                "-trimpath",
                "-buildvcs=false",
                "-ldflags=-s -w -buildid=",
                "-o",
                str(xray_exe),
                "./main",
            ],
            cwd=XRAY_SOURCE,
            env=env,
            check=True,
        )
        revision = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=XRAY_SOURCE,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        config, inbound_tag, direct_tag = derive_xray_config(source_config, temp)
        xray_config = temp / "xray.json"
        xray_config.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        subprocess.run(
            [
                str(xray_exe),
                "run",
                "-test",
                "-format",
                "json",
                "-config",
                str(xray_config),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        xray = subprocess.Popen(
            [str(xray_exe), "run", "-format", "json", "-config", str(xray_config)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        start_attempted = False
        try:
            wait_for_socks(xray)
            start_attempted = True
            state = invoke_bridge(
                temp,
                package,
                "startVpn",
                {
                    "configYaml": vcore_yaml(),
                    "networkSettings": {
                        "ipv4Address": TUN_IPV4,
                        "ipv6Address": TUN_IPV6,
                        "dnsIpv4Address": DNS_IPV4,
                        "dnsIpv6Address": DNS_IPV6,
                    },
                    "policy": {
                        "alwaysOn": False,
                        "allowLocalNetwork": True,
                        "excludedCidrs": [],
                    },
                },
            )
            if state["status"] != "connected":
                raise RuntimeError(f"unexpected VPN status: {state['status']}")

            direct_host = urlparse(DIRECT_URL).hostname or ""
            dns_source = dns_probe(direct_host)
            direct_status, direct_source = curl_probe(DIRECT_URL)
            proxy_status, proxy_source = curl_probe(PROXY_URL)
            ntp_source = ntp_probe()
            for label, source in [
                ("DNS", dns_source),
                ("sniffed HTTP", direct_source),
                ("proxied HTTPS", proxy_source),
                ("NTP", ntp_source),
            ]:
                require_tun_source(label, source)
            wait_for_access_evidence(temp / "xray-access.log", inbound_tag, direct_tag)

            print(f"Xray source {revision}: built and config-tested")
            print(f"DNS ordinary UDP: PASS ({dns_source} -> {DNS_IPV4}:53)")
            print(
                "HTTP sniffing route: PASS "
                f"({direct_status}, {inbound_tag} -> {direct_tag})"
            )
            print(
                "HTTPS proxy route: PASS "
                f"({proxy_status}, {inbound_tag} -> {inbound_tag})"
            )
            print(f"SOCKS5 UDP/NTP: PASS ({ntp_source} -> {NTP_IPV4}:123)")
            print(
                "VERDICT: VCore can serve as tun2socks in front of an external "
                "Xray SOCKS inbound."
            )
        finally:
            if start_attempted:
                try:
                    invoke_bridge(temp, package, "stopVpn", {})
                except (
                    OSError,
                    subprocess.SubprocessError,
                    ValueError,
                    KeyError,
                ) as error:
                    print(f"warning: VPN cleanup failed: {error}", file=sys.stderr)
            if xray.poll() is None:
                xray.terminate()
                try:
                    xray.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    xray.kill()
                    xray.wait()


if __name__ == "__main__":
    if len(sys.argv) != 5 or sys.argv[1] != "--bridge":
        raise SystemExit("This module is an internal packaged bridge helper")
    bridge_main(*sys.argv[2:])
