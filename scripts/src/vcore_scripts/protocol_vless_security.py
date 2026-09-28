"""Ephemeral public-test identities. Keys never leave the private fixture."""

from pathlib import Path

from .protocol_fixtures import certificates
from .protocol_peers import run_command


def client_identities(directory: Path):
    result = {}
    extensions = directory / "client-ext.cnf"
    extensions.write_text(
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
    )
    (directory / "index.txt").write_text("")
    (directory / "serial.txt").write_text("10\n")
    ca = directory / "client-ca.cnf"
    ca.write_text(
        "[ca]\ndefault_ca=fixture\n[fixture]\n"
        f"database={directory / 'index.txt'}\nserial={directory / 'serial.txt'}\n"
        f"new_certs_dir={directory}\ncertificate={directory / 'root.pem'}\n"
        f"private_key={directory / 'root-key.pem'}\n"
        "default_md=sha256\npolicy=names\n[names]\ncommonName=supplied\n"
    )
    for name, days in (("valid", "2"), ("expired", "2")):
        key, csr, cert = (
            directory / f"client-{name}.{suffix}" for suffix in ("key", "csr", "pem")
        )
        for argv in (
            [
                "openssl",
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=synthetic-client",
                "-keyout",
                str(key),
                "-out",
                str(csr),
            ],
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(directory / "root.pem"),
                "-CAkey",
                str(directory / "root-key.pem"),
                "-set_serial",
                "3" if name == "valid" else "4",
                "-days",
                days,
                "-extfile",
                str(extensions),
                "-out",
                str(cert),
            ],
        ):
            if name == "expired" and argv[1] == "x509":
                argv = [
                    "openssl",
                    "ca",
                    "-batch",
                    "-notext",
                    "-config",
                    str(ca),
                    "-in",
                    str(csr),
                    "-out",
                    str(cert),
                    "-extfile",
                    str(extensions),
                    "-startdate",
                    "20000101000000Z",
                    "-enddate",
                    "20010101000000Z",
                ]
            command = run_command(argv, timeout=20, limit=65536)
            if command.returncode or not command.cleanup:
                raise RuntimeError("synthetic client identity generation failed")
        result[name] = {"certificate": cert.read_text(), "private-key": key.read_text()}
    wrong = directory / "wrong-ca"
    wrong.mkdir()
    cert, key, _ = certificates(wrong)
    result["wrong-ca"] = {
        "certificate": cert.read_text(),
        "private-key": key.read_text(),
    }
    return result
