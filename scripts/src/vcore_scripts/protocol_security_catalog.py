"""Selected security requirements, independent of runtime results.

This is an explicit covering set, not a Cartesian-product support claim. Encryption,
hybrid REALITY and JLS have dedicated reports; this suite exercises their critical
consumers together with static ECH and composition checks.
"""

from __future__ import annotations

FIELDS = {"VL06", "S03", "S04", "S05", "S12", "S13", "D16", "D17", "D18", "D25", "D26"}
ECH_FIELDS = ["S04", "S05", "D17", "D18"]
JLS_FIELDS = ["S12", "S13", "D25", "D26"]
HYBRID_FIELDS = ["S03", "D16"]
GATES = {
    "SECURITY-CFG",
    "SECURITY-RELEASE",
    "SECURITY-REGRESSION",
    "SECURITY-QUALITY",
    "SECURITY-FEATURES",
    "SECURITY-SCRIPTS",
    "SECURITY-PLATFORMS",
}
PROFILES = ("chrome", "chrome120", "firefox", "safari")
ENCRYPTION = tuple(
    f"{style}-{rtt}-mixed"
    for style in ("native", "xorpub", "random")
    for rtt in ("1rtt", "0rtt")
)


def groups():
    from .protocol_ech import catalog as ech_catalog
    from .protocol_jls import catalog as jls_catalog

    result = {}

    def add(name, runner, rows, **options):
        result[name] = dict(runner=runner, rows=rows, **options)

    add(
        "SECURITY-ECH-STANDARD",
        "vless",
        ECH_FIELDS,
        selected=list(ech_catalog()),
        ech=True,
    )
    named = [
        "SECURITY-ECH-TCP-TLS-BASE",
        "SECURITY-ECH-TCP-TLS-REJECT",
        "SECURITY-ECH-WS-TLS-BASE",
        "SECURITY-ECH-GRPC-TLS-BASE",
        "SECURITY-ECH-GRPC-TLS-CLOSE",
        "SECURITY-ECH-TCP-MTLS-IDENTITY",
        "SECURITY-ECH-XHTTP-STREAM-UP-DOWNLOAD-BASE",
        "SECURITY-ECH-XHTTP-STREAM-UP-DOWNLOAD-REJECT",
        "SECURITY-ECH-XHTTP-STREAM-UP-DOWNLOAD-DOWNLOAD",
        "SECURITY-ECH-XHTTP-STREAM-UP-DOWNLOAD-H1-BASE",
        "SECURITY-ECH-XHTTP-STREAM-UP-DOWNLOAD-H1-DOWNLOAD",
    ]
    for profile in PROFILES:
        add(
            "SECURITY-ECH-" + profile.upper(),
            "vless",
            ECH_FIELDS,
            selected=named,
            ech=True,
            client_fingerprint=profile,
        )

    add(
        "SECURITY-JLS-RETAINED",
        "vless",
        JLS_FIELDS,
        jls=True,
        selected=[
            key
            for key, (_, mode, _, test) in jls_catalog().items()
            if mode
            in {
                "tcp-tls",
                "grpc-tls",
                "xhttp-stream-up-download",
                "xhttp-stream-up-download-h1",
            }
            and test
            in {
                "public_base",
                "native_jls_fail_closed",
                "public_jls_download_identity",
                "runtime::owned_resources",
                "runtime::public_lifecycle",
                "native_mihomo_close_alignment",
            }
        ],
    )
    add(
        "SECURITY-HYBRID-RETAINED",
        "hybrid",
        HYBRID_FIELDS,
        selected=[
            f"{profile}-{mode}-{test}"
            for profile in ("none", "chrome")
            for mode in ("tcp", "h1-stream-up", "h2-stream-up")
            for test in ("base", "security")
        ]
        + [
            "chrome-vision-inner-tls",
            "chrome-h2-stream-up-owned",
            "chrome-h2-stream-up-life",
            "chrome-h1-main-classic",
            "chrome-h2-download-classic",
        ],
    )

    for profile in ENCRYPTION:
        suffix = profile.upper()
        add(
            "SECURITY-ECH-ENCRYPTION-" + suffix,
            "vless",
            ["VL06", *ECH_FIELDS],
            ech=True,
            encryption=profile,
            client_fingerprint="chrome",
            selected=[
                "SECURITY-ECH-TCP-TLS-BASE",
                "SECURITY-ECH-XHTTP-STREAM-UP-DOWNLOAD-BASE",
                "SECURITY-ECH-XHTTP-STREAM-UP-DOWNLOAD-H1-BASE",
            ],
        )
        add(
            "SECURITY-JLS-ENCRYPTION-" + suffix,
            "vless",
            ["VL06", *JLS_FIELDS],
            jls=True,
            encryption=profile,
            selected=[
                "SECURITY-JLS-TCP-BASE",
                "SECURITY-JLS-XHTTP-STREAM-UP-DOWNLOAD-BASE",
            ],
        )
        add(
            "SECURITY-HYBRID-ENCRYPTION-" + suffix,
            "hybrid",
            ["VL06", *HYBRID_FIELDS],
            encryption=profile,
            selected=[
                "chrome-tcp-base",
                "chrome-vision-base",
                "chrome-h2-stream-up-base",
            ],
        )

    def fields(name, rows, specs, **options):
        jobs = {}
        for variant, tests in specs:
            jobs[variant] = [
                dict(case_id=variant + "-" + str(i), test=test)
                for i, test in enumerate(tests)
            ]
        add(name, "xhttp", rows, jobs=jobs, **options)

    specs = [
        (f"h3-{mode}-headers", ["public_base"])
        for mode in ("stream-one", "stream-up", "packet-up")
    ]
    specs += [
        (
            f"h3-ech-{action}",
            ["security::native_xhttp_security"]
            if action.startswith("reject")
            else ["public_base"],
        )
        for action in ("reject-main", "reject-download", "replace", "clear")
    ]
    specs += [
        (
            "h3-stream-up-reuse",
            [
                "runtime::public_graph",
                "runtime::public_entrypoints",
                "runtime::public_ipv6_and_gates",
                "runtime::public_udp_isolation",
                "runtime::public_lifecycle",
                "lifecycle::native_xhttp_owned_resources",
            ],
        ),
        ("h3-keepalive", ["keepalive::native_h3_keepalive_observes_each_leg_and_stop"]),
    ]
    fields("SECURITY-ECH-H3", ECH_FIELDS, specs, ech=True)
    for security in ("ech", "jls"):
        versions = ("h1", "h2", "h3") if security == "ech" else ("h1", "h2")
        specs = [
            (f"{version}-mux-{mux}-padded{only}", ["public_base"])
            for version in versions
            for mux in ("h2mux", "smux", "yamux")
            for only in ("", "-only-tcp")
        ]
        fields(
            "SECURITY-" + security.upper() + "-MUX",
            ECH_FIELDS if security == "ech" else JLS_FIELDS,
            specs,
            **{security: True},
            encryption="native-0rtt-mixed",
        )
    fields(
        "SECURITY-ECH-NATIVE-TRANSPORT",
        ECH_FIELDS,
        [
            ("outer-" + transport + "-tls", ["public_base"])
            for transport in ("http", "h2", "ws-header", "ws-path")
        ],
        ech=True,
        encryption="native-0rtt-mixed",
    )

    fields(
        "SECURITY-ECH-H3-ENCRYPTION",
        ["VL06", *ECH_FIELDS],
        [
            (f"h3-{mode}-headers", ["public_base"])
            for mode in ("stream-one", "stream-up", "packet-up")
        ]
        + [("h3-ech-replace", ["public_base"])],
        ech=True,
        encryption="native-0rtt-mixed",
    )

    add("SECURITY-ENCRYPTION-WIRE", "encryption", ["VL06"])
    add("SECURITY-ENCRYPTION-CHACHA", "encryption", ["VL06"], chacha=True)
    add("SECURITY-ENCRYPTION-EXPIRY", "encryption", ["VL06"], expiry=True)
    for profile in ("none", "chrome"):
        add(
            "SECURITY-SHARED-" + profile.upper(),
            "vless",
            [],
            client_fingerprint=profile,
            selected=[
                "VLESS-TCP-TLS-BASE",
                "VLESS-TCP-TLS-NEG",
                "VLESS-TCP-REALITY-BASE",
                "VLESS-TCP-REALITY-NEG",
                "VLESS-VISION-REALITY-BASE",
                "VLESS-GRPC-TLS-BASE",
                "VLESS-HTTP-TLS-BASE",
                "VLESS-H2-TLS-BASE",
                "VLESS-REGRESSION-TROJAN-TCP",
                "VLESS-REGRESSION-VMESS-GRPC",
                "FINGERPRINT-ANYTLS",
            ],
        )
    fields(
        "SECURITY-SHARED-XHTTP",
        [],
        [
            ("h1-stream-up-split-reuse", ["public_base"]),
            ("h2-stream-up-split-reuse", ["public_base"]),
            ("h3-stream-up-split-reuse", ["public_base"]),
            ("h2r-stream-up-split-reuse", ["public_base"]),
            ("h3-mux-yamux-padded", ["public_base"]),
        ],
    )
    return result


def definitions():
    native = groups()
    result = []
    for identifier in sorted(GATES | native.keys()):
        group = native.get(identifier, {})
        runner = group.get("runner", "gate")
        rows = sorted(
            FIELDS
            if identifier in {"SECURITY-CFG", "SECURITY-RELEASE"}
            else group.get("rows", [])
        )
        options = {k: v for k, v in group.items() if k not in {"rows", "runner"}}
        kind = (
            "unit"
            if not group
            else (
                "XR" if "H3" in identifier or "NATIVE-TRANSPORT" in identifier else "M"
            )
        )
        result.append(
            dict(
                case_id=identifier,
                stage="SECURITY",
                substage="SECURITY.acceptance",
                required=True,
                row_ids=rows,
                protocol="vless",
                network="explicit-selected-compositions",
                security="static-ech/encryption/hybrid-reality/jls",
                udp_codec="raw/xudp/packetaddr/sing-mux",
                field_values=options,
                outer_family="IPv4/IPv6",
                inner_family="IPv4/IPv6/domain",
                target_type=(
                    "memory-only/build"
                    if kind == "unit"
                    else "isolated synthetic origin"
                ),
                upstream_graph="direct/concrete/nested-select",
                peer_kind=kind,
                peer_config=dict(runner=runner, **options),
                gap_source=dict(
                    reason="Mihomo v1.19.31 Safari ECH fails before business data. "
                    "Only the gRPC close reference uses Chrome with the same ECH "
                    "listener; VCore remains Safari, not a same-profile comparison.",
                    source="https://github.com/MetaCubeX/utls/blob/v1.8.7/u_handshake_client.go",
                )
                if identifier == "SECURITY-ECH-SAFARI"
                else None
                if kind != "XR"
                else dict(
                    reason="Mihomo has no H3 or legacy HTTP/H2/extended WS listener; "
                    "official Xray/V2Ray terminate that transport, with "
                    "Mihomo VLESS for packetaddr, Encryption and sing-mux.",
                    source="https://github.com/XTLS/Xray-core",
                ),
                expected_observation=[identifier],
                required_evidence=["command", "cleanup", "structured-assertions"]
                + ([] if kind == "unit" else ["peer-identity", "isolated-origins"]),
                prerequisites=["rust-toolchain"]
                if kind == "unit"
                else ["owned-host-only-container-network", "official-latest-peer"],
                runner="vless-security-" + runner,
                timeout_seconds=3600,
            )
        )
    return result
