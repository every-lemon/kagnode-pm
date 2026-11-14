#!/usr/bin/python3
"""Renew the combined installation's local fleet certificates before expiry.

No remote agent identities are changed. Fleet CA rotation and remote-agent
rotation require separate administrator enrollment; the CA is never replaced.
"""

from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import ipaddress

BASE = Path("/srv/kagnode/proxy-manager")
UNITS = ["kagnode-proxy-controller.service", "kagnode-proxy-agent.service"]


def run(args, **kwargs):
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        timeout=60,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        **kwargs,
    )


def fingerprint(cert):
    return hashlib.sha256(
        run(["openssl", "x509", "-in", str(cert), "-outform", "DER"]).stdout
    ).hexdigest()


def extensions(host, client=False):
    if client:
        return "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n"
    try:
        ipaddress.ip_address(host)
        san = "IP:" + host
    except ValueError:
        import re

        if not host or not re.fullmatch("[a-zA-Z0-9.-]+", host):
            raise ValueError("Invalid fleet hostname")
        san = "DNS:" + host
    return (
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName="
        + san
        + ",DNS:localhost,IP:127.0.0.1,IP:::1\n"
    )


def replace(path, raw, uid, gid):
    fd, name = tempfile.mkstemp(prefix=".credential-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            os.fchown(stream.fileno(), uid, gid)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextlib.contextmanager
def database(path):
    db = sqlite3.connect(path)
    try:
        with db:
            yield db
    finally:
        db.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true")
    g.add_argument("--rotate-now", action="store_true")
    args = p.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("Certificate maintenance requires root")
    installation = json.loads((BASE / "installation.json").read_text())
    if installation["role"] != "combined":
        print(json.dumps({"applicable": False, "remote_agents_changed": False}))
        return
    controller = BASE / "controller"
    agent = BASE / "agent"
    pki = controller / "pki"
    config = json.loads((controller / "controller.json").read_text())
    node = json.loads((agent / "agent.json").read_text())
    if node["controller"] != config["fleet_url"]:
        raise ValueError("Local agent belongs to another controller")
    paths = [
        agent / "agent.key",
        agent / "agent.pem",
        pki / "server.key",
        pki / "server.pem",
    ]
    for path in paths:
        s = path.lstat()
        if (
            path.is_symlink()
            or not path.is_file()
            or s.st_mode & (0o077 if path.suffix == ".key" else 0o022)
            or s.st_nlink != 1
        ):
            raise ValueError("Unsafe existing credential")
    needed = any(
        subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(path),
                "-noout",
                "-checkend",
                str(days * 86400),
            ],
            capture_output=True,
        ).returncode
        != 0
        for path, days in [(paths[1], 7), (paths[3], 30)]
    )
    if args.check or not (needed or args.rotate_now):
        print(
            json.dumps(
                {
                    "rotation_needed": needed,
                    "modified": False,
                    "remote_agents_changed": False,
                }
            )
        )
        return
    old = fingerprint(agent / "agent.pem")
    with database(controller / "proxy.sqlite") as db:
        current = db.execute(
            "SELECT fingerprint FROM servers WHERE id=? AND revoked=0", (node["id"],)
        ).fetchone()
        if current != (old,):
            raise ValueError("Local agent identity has changed; maintenance stopped")
        active = db.execute(
            "SELECT COUNT(*) FROM jobs WHERE state='running'"
        ).fetchone()[0]
        if active:
            raise ValueError("An operation is running; defer credential maintenance")
    backup = BASE / "backups/credentials" / str(time.time_ns())
    backup.mkdir(mode=0o700, parents=True)
    for index, path in enumerate(paths):
        shutil.copy2(path, backup / str(index))
        (backup / str(index)).chmod(0o600)
    owners = {path: (path.stat().st_uid, path.stat().st_gid) for path in paths}
    with tempfile.TemporaryDirectory(prefix=".fleet-renew-", dir=pki) as tmp:
        tmp = Path(tmp)
        for label, client, days in [("agent", True, 30), ("server", False, 90)]:
            run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-keyout",
                    str(tmp / (label + ".key")),
                    "-out",
                    str(tmp / (label + ".csr")),
                    "-subj",
                    "/CN=KagNode Proxy Fleet",
                ]
            )
            (tmp / (label + ".ext")).write_text(
                extensions(urlsplit(config["fleet_url"]).hostname, client)
            )
            run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(tmp / (label + ".csr")),
                    "-CA",
                    str(pki / "ca.pem"),
                    "-CAkey",
                    str(pki / "ca.key"),
                    "-set_serial",
                    "0x" + os.urandom(15).hex(),
                    "-out",
                    str(tmp / (label + ".pem")),
                    "-days",
                    str(days),
                    "-extfile",
                    str(tmp / (label + ".ext")),
                ]
            )
            run(
                [
                    "openssl",
                    "verify",
                    "-CAfile",
                    str(pki / "ca.pem"),
                    str(tmp / (label + ".pem")),
                ]
            )
        new = fingerprint(tmp / "agent.pem")
        run(["systemctl", "stop", *UNITS])
        try:
            for dest, name in zip(
                paths, ["agent.key", "agent.pem", "server.key", "server.pem"]
            ):
                replace(dest, (tmp / name).read_bytes(), *owners[dest])
            with database(controller / "proxy.sqlite") as db:
                changed = db.execute(
                    "UPDATE servers SET fingerprint=? WHERE id=? AND fingerprint=? AND revoked=0",
                    (new, node["id"], old),
                ).rowcount
                if changed != 1:
                    raise ValueError("Local identity changed during renewal")
            run(["systemctl", "start", *UNITS])
            run(["systemctl", "is-active", "--quiet", *UNITS])
        except BaseException:
            for index, path in enumerate(paths):
                replace(path, (backup / str(index)).read_bytes(), *owners[path])
            with database(controller / "proxy.sqlite") as db:
                db.execute(
                    "UPDATE servers SET fingerprint=? WHERE id=? AND fingerprint=?",
                    (old, node["id"], new),
                )
            run(["systemctl", "start", *UNITS])
            raise
    print(
        json.dumps(
            {
                "rotated": True,
                "ca_replaced": False,
                "remote_agents_changed": False,
                "backup": str(backup),
            }
        )
    )


if __name__ == "__main__":
    main()
