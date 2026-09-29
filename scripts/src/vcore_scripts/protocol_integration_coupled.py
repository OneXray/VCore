"""Rerun the retained UoT/TUIC chain consumers in one integration source scope."""

from .protocol_evidence import read_json
from .protocol_integration_checks import envelope

GROUPS = ("MIHOMO-SOCKS5", "MIHOMO-GROUPS", "MIHOMO-PATHS")


def run(directory, supplied, image):
    from .protocol_tuic import run as tuic
    from .protocol_uot import run as uot

    for name in GROUPS:
        print("INTEGRATION coupled: " + name, flush=True)
        root = directory / name
        if name == "MIHOMO-PATHS":
            tuic(root, checks="paths", supplied=supplied, image=image)
        else:
            uot(
                root,
                checks="group" if name == "MIHOMO-GROUPS" else "data",
                via_socks5=True,
                supplied=supplied,
                image=image,
            )


def passed(directory, peers, source, digest):
    from .protocol_tuic_acceptance import wire_pass as tuic
    from .protocol_uot_acceptance import wire_pass as uot

    for name in GROUPS:
        root = directory / name
        report = read_json(root / "report.json")
        checker = tuic if name == "MIHOMO-PATHS" else uot
        if not (
            envelope(report, peers, source, digest, single="M")
            and checker(name, root, report)
        ):
            return False
    return True
