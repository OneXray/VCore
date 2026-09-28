"""JLS public consumers against official latest Mihomo in isolated containers."""

from __future__ import annotations

from pathlib import Path


def catalog():
    cases = {}

    def add(mode, suffix, test):
        cases[f"SECURITY-JLS-{mode.removesuffix('-tls').upper()}-{suffix}"] = (
            "M",
            mode,
            True,
            test,
        )

    modes = (
        "tcp-tls",
        "ws-tls",
        "upgrade-tls",
        "upgrade-fast-tls",
        "grpc-tls",
    ) + tuple(
        f"xhttp-{mode}{version}"
        for mode in (
            "stream-one",
            "stream-up",
            "packet-up",
            "stream-up-download",
            "packet-up-download",
        )
        for version in ("", "-h1")
    )
    for mode in modes:
        add(mode, "BASE", "public_base")
        add(mode, "CLOSE", "native_mihomo_close_alignment")
    for mode in (
        "tcp-tls",
        "ws-tls",
        "grpc-tls",
        "xhttp-stream-up-download",
        "xhttp-stream-up-download-h1",
    ):
        add(mode, "AUTH", "native_jls_fail_closed")
    for mode in modes:
        if "download" in mode:
            add(mode, "IDENTITY", "public_jls_download_identity")
    for mode in ("tcp-tls", "grpc-tls"):
        for suffix, test in (
            ("GRAPH", "runtime::public_graph"),
            ("IPV6", "runtime::public_ipv6_and_gates"),
            ("ENTRYPOINTS", "runtime::public_entrypoints"),
            ("UDP-ISOLATION", "runtime::public_udp_isolation"),
        ):
            add(mode, suffix, test)
    for mode in ("grpc-tls", "xhttp-stream-up-download"):
        add(mode, "LIFE", "runtime::public_lifecycle")
        add(mode, "OWNED", "runtime::owned_resources")
    return cases


def configuration(node, peer, origin, mode):
    credentials = dict(username="synthetic-jls-user", password="synthetic-jls-password")
    download = dict(
        username="synthetic-download-user", password="synthetic-download-password"
    )
    node.pop("fingerprint", None)
    node["jls-opts"] = credentials
    if mode.endswith("-h1"):
        node["alpn"] = ["http/1.1"]
    for listener in peer["listeners"]:
        listener.pop("certificate", None)
        listener.pop("private-key", None)
        listener["jls-config"] = dict(
            enable=True,
            sni="localhost",
            dest=f"{origin}:24001",
            users=[credentials, download],
        )
    return dict(jls_download_credentials=download)


if __name__ == "__main__":
    import argparse

    from .mihomo_isolation import exclusive_run
    from .protocol_vless_container import CLIENT_FINGERPRINTS, run

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("cases", nargs="*")
    parser.add_argument("--client-fingerprint", choices=CLIENT_FINGERPRINTS)
    args = parser.parse_args()
    with exclusive_run():
        raise SystemExit(
            run(
                args.output.resolve(),
                args.cases or None,
                jls=True,
                client_fingerprint=args.client_fingerprint,
            )
        )
