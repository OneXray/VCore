"""Guard platform namespace source contracts, not native loading or device behavior."""

import re
import unittest
from pathlib import Path

CORE_DIR = Path(__file__).resolve().parents[2]
NAMESPACE = "io.github.yuandevteam.vole"


class PlatformNamespaceTests(unittest.TestCase):
    def test_android_exports_only_the_canonical_jni_class(self):
        source = (CORE_DIR / "src/ffi/android.rs").read_text(encoding="utf-8")
        symbols = re.findall(
            r'pub (?:unsafe )?extern "system" fn (Java_\w+)\s*\(', source
        )
        prefix = "Java_" + NAMESPACE.replace(".", "_") + "_NativeVole_"
        self.assertCountEqual(
            symbols,
            [
                prefix + "nativeInvoke",
                prefix + "nativeRegisterProtectController",
                prefix + "nativeUnregisterProtectController",
            ],
        )

    def test_apple_logging_uses_the_canonical_identity(self):
        source = (CORE_DIR / "src/platform/apple_logging.rs").read_text(
            encoding="utf-8"
        )
        self.assertRegex(
            source, rf'(?m)^const SUBSYSTEM: &str = "{re.escape(NAMESPACE)}";$'
        )
        self.assertRegex(source, r'(?m)^const CATEGORY: &str = "vole";$')
