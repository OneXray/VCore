"""N4 development mode selection, using the same container fixtures as acceptance.

This entry does not execute local/build gates or sign off the complete stage.
"""

from pathlib import Path

from .protocol_vless_container import run as run_cases
from .protocol_vless_peers import MODES
from .protocol_vless_public import CASES


def run(output: Path, modes=None):
    modes = MODES if modes is None else modes
    if not modes or not set(modes) <= set(MODES) or len(set(modes)) != len(modes):
        raise ValueError("invalid N4 development mode")
    selected = [case for case, (_, mode, _, _) in CASES.items() if mode in modes]
    return run_cases(output, selected)


if __name__ == "__main__":
    import sys

    from .mihomo_isolation import exclusive_run

    with exclusive_run():
        sys.exit(run(Path(sys.argv[1]).resolve(), sys.argv[2:] or None))
