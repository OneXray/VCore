"""Unpackaged DLL regression: COM lifetime only, without VPN or network access."""

from __future__ import annotations

import argparse
import ctypes
import json
import subprocess
import sys
import threading
from pathlib import Path

CASES = ("uninitialized", "caller-mta", "worker-handoff", "sta-rejection")
CO_E_NOTINITIALIZED = ctypes.c_int32(0x800401F0).value
IMPLICIT_MTA = (0, 1, 1)
EXPLICIT_MTA = (0, 1, 0)
IDENTITY_FAILURE = {
    "success": False,
    "data": None,
    "error": "Windows package identity is required",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def bind(library, name, result_type, argument_types):
    function = getattr(library, name)
    function.restype = result_type
    function.argtypes = argument_types
    return function


class Bridge:
    def __init__(self, dll: Path):
        kernel = ctypes.WinDLL("kernel32.dll")
        bind(kernel, "SetErrorMode", ctypes.c_uint32, [ctypes.c_uint32])(0x8003)
        package_name = bind(
            kernel,
            "GetCurrentPackageFullName",
            ctypes.c_int32,
            [ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint16)],
        )
        length = ctypes.c_uint32()
        require(
            package_name(ctypes.byref(length), None) == 15700,
            "requires an unpackaged process; refusing to access package data or VPNs",
        )
        com = ctypes.WinDLL("combase.dll")
        self.initialize = bind(com, "RoInitialize", ctypes.c_int32, [ctypes.c_uint32])
        self.uninitialize = bind(com, "RoUninitialize", None, [])
        self.get_apartment = bind(
            com,
            "CoGetApartmentType",
            ctypes.c_int32,
            [ctypes.POINTER(ctypes.c_int32), ctypes.POINTER(ctypes.c_int32)],
        )
        library = ctypes.CDLL(str(dll))
        self.invoke = bind(
            library, "VoleWindowsVpnInvoke", ctypes.c_void_p, [ctypes.c_char_p]
        )
        self.free = bind(library, "VoleFree", None, [ctypes.c_void_p])
        self.calls = 0

    def apartment(self) -> tuple[int, int, int]:
        kind = ctypes.c_int32()
        qualifier = ctypes.c_int32()
        result = self.get_apartment(ctypes.byref(kind), ctypes.byref(qualifier))
        return result, kind.value, qualifier.value

    def query(self, method: str) -> dict:
        request = json.dumps({"bridgeVersion": 3, "method": method, "payload": {}})
        pointer = self.invoke(request.encode("utf-8"))
        require(pointer is not None, "bridge returned a null response")
        try:
            response = json.loads(ctypes.string_at(pointer).decode("utf-8"))
        finally:
            self.free(pointer)
        self.calls += 1
        return response

    def repeat(self, count: int = 64, apartment=IMPLICIT_MTA) -> None:
        for _ in range(count):
            for method in ("getEnvironment", "getVpnStatus"):
                require(
                    self.query(method) == IDENTITY_FAILURE, "expected identity error"
                )
            require(
                self.apartment() == apartment,
                "per-call COM initialization was not balanced or MTA was torn down",
            )

    def reject_sta(self) -> None:
        require(self.initialize(0) >= 0, "cannot initialize the test STA")
        try:
            before = self.apartment()
            require(before[0] == 0 and before[1] in (0, 3), "expected STA or main STA")
            for method in ("getEnvironment", "getVpnStatus"):
                response = self.query(method)
                require(
                    response["success"] is False
                    and response["data"] is None
                    and "80010106" in response["error"],
                    "STA must return RPC_E_CHANGED_MODE without executing the request",
                )
                require(self.apartment() == before, "bridge changed the caller's STA")
        finally:
            self.uninitialize()


def run_case(dll: Path, case: str) -> None:
    bridge = Bridge(dll)
    require(
        bridge.apartment()[0] == CO_E_NOTINITIALIZED,
        "each regression must start without a preinitialized COM apartment",
    )
    if case == "uninitialized":
        bridge.repeat()
    elif case == "caller-mta":
        require(bridge.initialize(1) >= 0, "cannot initialize the test MTA")
        try:
            bridge.repeat(apartment=EXPLICIT_MTA)
        finally:
            bridge.uninitialize()
        # The caller can release its own reference without invalidating factories.
        bridge.repeat()
    elif case == "worker-handoff":
        # Each short-lived worker exits before the next is created. Neither the
        # main thread nor the caller holds an explicit MTA across requests.
        for index in range(32):
            errors: list[BaseException] = []

            def worker(first=index == 0, errors=errors):
                try:
                    if first:
                        require(
                            bridge.apartment()[0] == CO_E_NOTINITIALIZED,
                            "first worker must start without COM initialization",
                        )
                    else:
                        require(
                            bridge.apartment() == IMPLICIT_MTA, "MTA did not survive"
                        )
                    bridge.repeat(2)
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            thread.join(timeout=10)
            require(not thread.is_alive(), "worker did not complete within 10 seconds")
            if errors:
                raise errors[0]
        bridge.repeat(2)
    elif case == "sta-rejection":
        bridge.reject_sta()
        require(
            bridge.apartment()[0] == CO_E_NOTINITIALIZED,
            "a rejected STA call must not retain an MTA or unbalance the caller",
        )
        bridge.repeat(2)
        bridge.reject_sta()
        bridge.repeat(2)
    bridge.free(None)
    print(f"PASS {case}: {bridge.calls} responses released; no VPN access", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", required=True, type=Path)
    parser.add_argument("--case", choices=CASES, help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if sys.platform != "win32":
        parser.error(
            "requires native Windows and a matching-architecture Python and DLL"
        )
    dll = arguments.dll.resolve(strict=True)
    if arguments.case:
        run_case(dll, arguments.case)
        return
    # A fresh process per case prevents other tests or initialized factories from
    # hiding the first-call/last-MTA-thread bug. Timeouts also bound native hangs.
    for case in CASES:
        subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--dll",
                str(dll),
                "--case",
                case,
            ],
            check=True,
            timeout=30,
        )
    print("PASS all four isolated Windows COM lifecycle regressions", flush=True)


if __name__ == "__main__":
    main()
