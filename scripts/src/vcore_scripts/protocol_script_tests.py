"""Structured unittest results for the protocol harness; no stdout PASS parsing."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import unittest
from pathlib import Path

from .builds import CORE_DIR


class Result(unittest.TestResult):
    def __init__(self):
        super().__init__()
        self.cases = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.cases.append({"test": test.id(), "status": "PASS"})

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.cases.append({"test": test.id(), "status": "FAIL", "reason": "assertion"})

    def addError(self, test, error):
        super().addError(test, error)
        self.cases.append(
            {"test": test.id(), "status": "FAIL", "reason": error[0].__name__}
        )

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.cases.append({"test": test.id(), "status": "NOT RUN"})


class BoundedOutput(io.TextIOBase):
    def __init__(self):
        self.size = 0

    def write(self, text):
        self.size += len(text)
        if self.size > 128 * 1024:
            raise RuntimeError("script test output exceeded bound")
        return len(text)


def execute(path: Path) -> bool:
    result = Result()
    try:
        suite = unittest.defaultTestLoader.discover(str(CORE_DIR / "scripts/tests"))
        with (
            contextlib.redirect_stdout(BoundedOutput()),
            contextlib.redirect_stderr(BoundedOutput()),
        ):
            suite.run(result)
    finally:
        path.write_text(
            json.dumps({"tests_run": result.testsRun, "cases": result.cases}, indent=2)
            + "\n"
        )
    return result.testsRun > 0 and result.wasSuccessful() and not result.skipped


if __name__ == "__main__":
    raise SystemExit(0 if execute(Path(sys.argv[1])) else 1)
