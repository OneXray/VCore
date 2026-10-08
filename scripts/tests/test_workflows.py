"""Offline release orchestration contracts; no builds or GitHub operations."""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"
CLI_ARCHIVES = {
    "vole-linux-amd64.gz",
    "vole-linux-arm64.gz",
    "vole-darwin-amd64.gz",
    "vole-darwin-arm64.gz",
    "vole-windows-amd64.zip",
    "vole-windows-arm64.zip",
}
FFI_ARCHIVES = {
    "vole-ffi-apple.tar.gz",
    "vole-ffi-android.tar.gz",
    "vole-ffi-linux-amd64.tar.gz",
    "vole-ffi-linux-arm64.tar.gz",
    "vole-ffi-windows-wintun-amd64.zip",
    "vole-ffi-windows-wintun-arm64.zip",
    "vole-ffi-windows-uwp-amd64.zip",
    "vole-ffi-windows-uwp-arm64.zip",
}


def _job(source: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(.*?)(?=^  [\w-]+:\n|\Z)",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing workflow job: {name}")
    return match[1]


def _matrix(job: str) -> list[dict[str, str]]:
    # Inspect the small, explicit include mappings without adding a YAML package
    # to the dependency-free build helpers. Unsupported row syntax fails closed.
    include = job.split("        include:\n", 1)[1].split("    steps:\n", 1)[0]
    rows = []
    for block in include.split("          - ")[1:]:
        row = {}
        for line in block.splitlines():
            match = re.fullmatch(r"\s*([\w-]+): (.*)", line)
            if match is None:
                raise AssertionError(f"unexpected matrix field: {line}")
            row[match[1]] = match[2].strip('"')
        rows.append(row)
    return rows


def _condition(job: str) -> str:
    match = re.search(r"^    if: >-\n((?:      [^\n]*\n)+)", job, re.MULTILINE)
    if match is None:
        raise AssertionError("missing explicit publish guard")
    return " ".join(line.strip() for line in match[1].splitlines())


def _allows_publish(
    condition: str,
    *,
    event="push",
    ref="refs/tags/v0.1.0",
    ref_type="tag",
    caller="release.yml",
    results=("success", "success", "success"),
) -> bool:
    github = SimpleNamespace(
        event_name=event,
        ref=ref,
        ref_type=ref_type,
        repository="YuanDevTeam/Vole",
        workflow_ref=f"YuanDevTeam/Vole/.github/workflows/{caller}@{ref}",
    )
    needs = SimpleNamespace(
        **{
            name: SimpleNamespace(result=result)
            for name, result in zip(("cli", "ffi", "assemble"), results, strict=True)
        }
    )
    # The checked-in condition uses only equality, conjunction and these two
    # pure GitHub expression functions; evaluate its actual event/DAG policy.
    return bool(
        eval(
            condition.replace("&&", " and "),
            {"__builtins__": {}},
            {
                "github": github,
                "needs": needs,
                "startsWith": str.startswith,
                "format": lambda template, *arguments: template.format(*arguments),
            },
        )
    )


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.release = (WORKFLOWS / "release.yml").read_text()
        cls.tests = (WORKFLOWS / "test.yml").read_text()

    def test_only_unified_workflow_is_called_and_owns_publication(self):
        for old in ("cli-release.yml", "platform-delivery.yml"):
            self.assertFalse((WORKFLOWS / old).exists())
            for path in WORKFLOWS.glob("*.yml"):
                self.assertNotIn(old, path.read_text())
        caller = _job(self.tests, "release-build")
        self.assertIn("uses: ./.github/workflows/release.yml", caller)
        self.assertRegex(caller, r"permissions:\n      contents: write")
        self.assertIn("statically bounded by the caller", caller)
        self.assertIn("permissions:\n  contents: read", self.tests)
        self.assertIn("permissions:\n  contents: read", self.release)
        self.assertEqual(self.release.count("contents: write"), 1)
        for job in ("cli", "ffi", "assemble"):
            self.assertNotIn("contents: write", _job(self.release, job))
            self.assertNotIn("GH_TOKEN", _job(self.release, job))

    def test_cli_matrix_has_six_native_targets_and_only_wintun_windows(self):
        rows = _matrix(_job(self.release, "cli"))
        self.assertEqual(len(rows), 6)
        self.assertEqual(
            {(row["target"], row["runner"]) for row in rows},
            {
                ("x86_64-unknown-linux-gnu", "ubuntu-24.04"),
                ("aarch64-unknown-linux-gnu", "ubuntu-24.04-arm"),
                ("x86_64-pc-windows-msvc", "windows-2025"),
                ("aarch64-pc-windows-msvc", "windows-11-arm"),
                ("x86_64-apple-darwin", "macos-26-intel"),
                ("aarch64-apple-darwin", "macos-26"),
            },
        )
        self.assertEqual({row["archive"] for row in rows}, CLI_ARCHIVES)
        self.assertTrue(
            all("wintun" in row["name"] for row in rows if row["platform"] == "windows")
        )
        self.assertNotIn("--backend", _job(self.release, "cli"))

    def test_ffi_matrix_retains_apple_android_and_all_native_backend_variants(self):
        rows = _matrix(_job(self.release, "ffi"))
        self.assertEqual(len(rows), 8)
        self.assertEqual({row["archive"] for row in rows}, FFI_ARCHIVES)
        platforms = {row["platform"] for row in rows}
        self.assertEqual(platforms, {"apple", "android", "linux", "windows"})
        windows = [row for row in rows if row["platform"] == "windows"]
        self.assertEqual(
            {(row["target"], row["backend"], row["runner"]) for row in windows},
            {
                (target, backend, runner)
                for target, runner in (
                    ("x86_64-pc-windows-msvc", "windows-2025"),
                    ("aarch64-pc-windows-msvc", "windows-11-arm"),
                )
                for backend in ("wintun", "uwp")
            },
        )
        linux = [row for row in rows if row["platform"] == "linux"]
        self.assertEqual(
            {(row["target"], row["runner"]) for row in linux},
            {
                ("x86_64-unknown-linux-gnu", "ubuntu-24.04"),
                ("aarch64-unknown-linux-gnu", "ubuntu-24.04-arm"),
            },
        )
        apple = next(row for row in rows if row["platform"] == "apple")
        self.assertEqual(
            set(apple["targets"].split(",")),
            {
                "aarch64-apple-ios",
                "aarch64-apple-ios-sim",
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
                "aarch64-apple-tvos",
                "aarch64-apple-tvos-sim",
            },
        )
        android = next(row for row in rows if row["platform"] == "android")
        self.assertEqual(
            set(android["targets"].split(",")),
            {"aarch64-linux-android", "x86_64-linux-android"},
        )
        self.assertTrue(all(not row["backend"] for row in rows if row not in windows))
        self.assertIn('args+=(--backend "$VOLE_BACKEND")', _job(self.release, "ffi"))

    def test_build_jobs_upload_only_archives_and_assemble_waits_for_both(self):
        for name, operation in (("cli", "build-cli"), ("ffi", "build-ffi")):
            job = _job(self.release, name)
            self.assertIn(f"args=({operation}", job)
            self.assertIn('args+=(--tag "$VOLE_RELEASE_TAG")', job)
            self.assertIn('python -m vole_scripts.release "${args[@]}"', job)
            self.assertIn(
                "path: dist/release/${{ matrix.name }}/${{ matrix.archive }}", job
            )
            self.assertIn("if-no-files-found: error", job)
            self.assertIn("fail-fast: false", job)
            self.assertIn("persist-credentials: false", job)
        assemble = _job(self.release, "assemble")
        self.assertIn("needs: [cli, ffi]", assemble)
        self.assertIn("pattern: vole-release-build-*-${{ github.sha }}", assemble)
        self.assertNotIn("merge-multiple: true", assemble)
        self.assertIn("args=(assemble --inputs dist/release-incoming", assemble)
        self.assertIn("--output dist/release-ready/assets", assemble)
        self.assertIn("--notes dist/release-ready/notes.md", assemble)
        self.assertIn("dist/release-ready/assets/*.gz", assemble)
        self.assertIn("dist/release-ready/assets/*.zip", assemble)
        self.assertIn("dist/release-ready/notes.md", assemble)

    def test_publish_requires_direct_tag_push_and_all_matrix_results(self):
        self.assertIn('tags:\n      - "v*"', self.release)
        self.assertIn("  workflow_call:\n", self.release)
        self.assertIn("  workflow_dispatch:\n", self.release)
        publish = _job(self.release, "publish")
        self.assertIn("needs: [cli, ffi, assemble]", publish)
        condition = _condition(publish)
        self.assertTrue(_allows_publish(condition))
        for values in (
            {"event": "pull_request", "ref": "refs/pull/1/merge", "ref_type": "branch"},
            {"event": "workflow_dispatch"},
            {"event": "workflow_call"},
            {"ref": "refs/heads/main", "ref_type": "branch"},
            {"ref": "refs/tags/other"},
            {"caller": "test.yml"},
            {"caller": "other-tag-caller.yml"},
        ):
            with self.subTest(values=values):
                self.assertFalse(_allows_publish(condition, **values))
        for index in range(3):
            for status in ("failure", "cancelled", "skipped"):
                results = ["success"] * 3
                results[index] = status
                with self.subTest(index=index, status=status):
                    self.assertFalse(_allows_publish(condition, results=results))

    def test_single_publish_uploads_exactly_the_fourteen_fixed_archives(self):
        sources = "\n".join(path.read_text() for path in WORKFLOWS.glob("*.yml"))
        self.assertEqual(sources.count("gh release create "), 1)
        self.assertNotIn("gh release upload ", sources)
        publish = _job(self.release, "publish")
        actual = re.findall(
            r"^            dist/release-ready/assets/(\S+)$", publish, re.M
        )
        self.assertEqual(len(actual), 14)
        self.assertEqual(set(actual), CLI_ARCHIVES | FFI_ARCHIVES)
        self.assertIn('test "${#archives[@]}" -eq 14', publish)
        self.assertIn('"${archives[@]}"', publish)
        self.assertIn("--verify-tag", publish)
        self.assertIn("--notes-file dist/release-ready/notes.md", publish)
        self.assertIn("name: vole-release-ready-${{ github.sha }}", publish)
        for name in actual:
            self.assertNotRegex(name, r"\d+\.\d+\.\d+")
            self.assertNotRegex(name, r"(?i)checksum|license|notice|manifest|\.dll$")

    def test_existing_action_versions_sdk_selection_and_cache_isolation_are_kept(self):
        actions = set(re.findall(r"uses: ([^\s]+)", self.release))
        self.assertEqual(
            actions,
            {
                "actions/checkout@v7",
                "dtolnay/rust-toolchain@stable",
                "astral-sh/setup-uv@v10.2.0",
                "Swatinem/rust-cache@v2",
                "actions/upload-artifact@v7",
                "actions/download-artifact@v8",
            },
        )
        ffi = _job(self.release, "ffi")
        self.assertIn("cargo fetch --locked", ffi)
        self.assertIn('"$sdkmanager" --list --channel=0', ffi)
        self.assertIn("Stable NDK r30 is unavailable", ffi)
        self.assertIn("ANDROID_NDK_HOME", ffi)
        for name in ("cli", "ffi"):
            job = _job(self.release, name)
            self.assertIn("key: release-${{ matrix.name }}", job)
            self.assertIn("env-vars: ImageOS ImageVersion SDKROOT DEVELOPER_DIR", job)
            self.assertIn('cache-bin: "false"', job)
            toolchain = job.split("uses: dtolnay/rust-toolchain@stable", 1)[1].split(
                "      - ", 1
            )[0]
            components = re.search(r"components: ([^\n]+)", toolchain)
            self.assertIsNotNone(components)
            self.assertIn("rust-docs", components[1].replace(" ", "").split(","))
        self.assertIn("components: rustfmt, rust-docs", ffi)
        self.assertNotIn("rust-docs", _job(self.release, "assemble"))


if __name__ == "__main__":
    unittest.main()
