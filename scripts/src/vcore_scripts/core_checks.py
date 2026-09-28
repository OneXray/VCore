"""Memory-only checks shared by local development and CI.

Network consumers remain explicit container suites. Keep this allowlist independent
of historical milestone runners: compiling all targets is safe; executing them is not.
"""

from __future__ import annotations

import re

from .builds import CORE_DIR, DEFAULT_FEATURES
from .protocol_peers import run_command

FEATURE_TEST = (
    "runtime::tests::integration_feature_admission_is_explicit_without_opening_sockets"
)
PROTOCOLS = ("socks5", "anytls", "shadowsocks", "trojan", "vmess", "vless", "hysteria2")
TARGETS = (
    "ech_config",
    "ech_tls",
    "encryption_config",
    "reality_config",
    "jls_config",
    "security_capabilities",
    "retired_security",
    "feature_foundations",
    "limit_foundations",
    "trojan",
    "trojan_config",
    "vmess_config",
    "vless_config",
    "vless_lifecycle",
    "xhttp_config",
    "xhttp_budget",
    "h2_stream_regression",
    "stream_foundations",
    "stream_shutdown",
    "xhttp_h3_shutdown",
    "hysteria2_paths",
    "hysteria2_config",
    "shadowsocks_backpressure",
    "hysteria2_packet_ids",
)
LIB_FILTERS = (
    "security::",
    "outbound::vless::encryption",
    "config::",
    "outbound::hysteria2::",
    "outbound::shadowsocks::tests::official_tcp_",
    "outbound::anytls::",
    "transport::h2_write::tests::",
    "transport::sing_mux::smux_driver::tests::",
)
EXACT_LIB_TESTS = (
    "outbound::connector::tests::authenticated_continuation_keeps_group_choice_but_has_a_new_io_deadline",
    FEATURE_TEST,
    "ffi::tests::runtime_thread_cannot_reenter_invoke",
    "ffi::tests::null_invalid_utf8_and_oversized_input_return_json_failures",
    "ffi::tests::same_instance_command_is_fail_fast",
    "ffi::tests::android_protector_is_required_only_for_tun",
)


def commands(profile: str) -> list[list[str]]:
    cargo = ["cargo", "test", "--locked", "--all-features"]
    if profile in {"debug", "release"}:
        if profile == "release":
            cargo += ["--release"]
        return [
            cargo + [arg for target in TARGETS for arg in ("--test", target)],
            *(cargo + ["--lib", name] for name in LIB_FILTERS),
            *(cargo + ["--lib", name, "--", "--exact"] for name in EXACT_LIB_TESTS),
            cargo
            + [
                "--test",
                "quic_datagram_foundations",
                "pending_send_is_not_restarted_and_stop_cancels_without_waiting_for_writable",
                "--",
                "--exact",
            ],
        ]
    if profile == "features":
        features = ["outbound-" + protocol for protocol in PROTOCOLS]
        return (
            [
                ["cargo", "check", "--locked", "--no-default-features", "--lib"]
                + (["--features", name] if name else [])
                for name in [
                    "",
                    *features,
                    "stream-transport",
                    "quic-transport",
                    "tun",
                    "ffi",
                ]
            ]
            + [
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--no-default-features",
                    "--features",
                    name,
                    "--lib",
                    FEATURE_TEST,
                    "--",
                    "--exact",
                ]
                for name in features
            ]
            + [
                [
                    "cargo",
                    "test",
                    "--locked",
                    "--no-default-features",
                    "--test",
                    "feature_foundations",
                    "--test",
                    "hysteria2_config",
                ],
                ["cargo", "check", "--locked", "--lib"],
                cargo + ["--all-targets", "--no-run"],
                [
                    "cargo",
                    "build",
                    "--locked",
                    "--release",
                    "--no-default-features",
                    "--features",
                    DEFAULT_FEATURES,
                    "--lib",
                ],
            ]
        )
    raise ValueError("unknown core check profile")


def validate_execution(
    command: list[str], output: str, returncode: int, cleanup: bool
) -> None:
    if returncode != 0 or not cleanup:
        raise RuntimeError("core check failed, timed out, or did not join its process")
    if command[:2] != ["cargo", "test"] or "--no-run" in command:
        return
    summaries = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; \d+ ignored;", output
    )
    expected = max(1, command.count("--test"))
    if len(summaries) != expected or any(
        int(passed) == 0 or int(failed) for passed, failed in summaries
    ):
        raise RuntimeError(
            "core check selected no tests or returned incomplete test results"
        )


def run(profile: str, *, list_only: bool = False) -> None:
    for command in commands(profile):
        print(" ".join(command), flush=True)
        if list_only:
            continue
        result = run_command(command, cwd=CORE_DIR, timeout=3600, limit=4 * 1024 * 1024)
        output = result.stdout.decode("utf-8", errors="replace")
        print(output, end="", flush=True)
        validate_execution(command, output, result.returncode, result.cleanup)
