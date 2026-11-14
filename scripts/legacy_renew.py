#!/usr/bin/python3
"""Preserve reviewed acme.sh lineages while migrating the old Nginx manager.

This root-only bridge never applies the legacy proxy configuration. New native
installations use Certbot; only the explicitly imported IDs use this bridge.
"""

from __future__ import annotations
import argparse
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

BASE = Path("/srv/kagnode/proxy-manager/traffic")
POLICY = Path("/etc/kagnode/proxy-manager/imported-certificates.json")
LEGACY = Path("/etc/nginx-manager/config.json")


def policy(value):
    if set(value) != {"schema", "ids"} or value["schema"] != 1:
        raise ValueError("Expected a reviewed imported-certificate policy")
    ids = value["ids"]
    if (
        not isinstance(ids, list)
        or not 1 <= len(ids) <= 250
        or len(set(ids)) != len(ids)
    ):
        raise ValueError("Invalid imported certificate IDs")
    if not all(
        isinstance(i, str) and re.fullmatch("[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", i)
        for i in ids
    ):
        raise ValueError("Invalid certificate ID")
    return ids


def protected(path):
    for p in [*reversed(path.parents), path]:
        s = p.lstat()
        if p.is_symlink() or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("Renewal configuration must be protected and root-owned")


def run(args, timeout=60):
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        timeout=timeout,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )


def pair(cert, key, names):
    cp = run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"]).stdout
    kp = run(["openssl", "pkey", "-in", str(key), "-pubout"]).stdout
    if cp != kp:
        raise ValueError("Renewed certificate does not match its private key")
    for name in names:
        run(
            [
                "openssl",
                "verify",
                "-CAfile",
                "/etc/ssl/certs/ca-certificates.crt",
                "-untrusted",
                str(cert),
                "-purpose",
                "sslserver",
                "-verify_hostname",
                name,
                str(cert),
            ]
        )
    run(["openssl", "x509", "-in", str(cert), "-noout", "-checkend", "0"])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--check",
        action="store_true",
        help="Validate existing imported certificates without ACME requests or changes",
    )
    args = p.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("Imported certificate renewal requires root")
    for path in [POLICY, LEGACY, BASE]:
        protected(path)
    ids = policy(json.loads(POLICY.read_text()))
    config = json.loads(LEGACY.read_text())
    sites = {s["id"]: s for s in config["sites"]}
    lock = Path("/run/kagnode-proxy-manager/renewal.lock")
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if args.check:
            for sid in ids:
                selected = BASE / "certificates" / sid
                pair(
                    selected / "fullchain.pem",
                    selected / "privkey.pem",
                    sites[sid]["names"],
                )
            print(
                json.dumps({"checked": len(ids), "acme_requests": 0, "modified": False})
            )
            return
        # The installed legacy library contains the precise existing account and
        # lineage paths. Its mutation/apply functions are deliberately not called.
        legacy_source = Path("/opt/nginx-manager/current").resolve(strict=True)
        protected(legacy_source)
        sys.path.insert(0, str(legacy_source))
        certs = importlib.import_module("nginx_ct.certificates")
        changes = []
        try:
            for sid in ids:
                site = sites[sid]
                if not site.get("enabled") or not site.get("tls"):
                    continue
                if site.get("cert_backend") != "acme":
                    raise ValueError(
                        "Imported certificate provider changed; review its migration"
                    )
                command, directory = certs.arguments(site, config["email"], renew=True)
                outcome = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=900,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
                )
                if outcome.returncode not in (0, 2):
                    raise RuntimeError(
                        "ACME renewal failed; see private ACME lineage logs"
                    )
                with tempfile.TemporaryDirectory(
                    prefix="pm-export-", dir=directory
                ) as temp:
                    temp = Path(temp)
                    run(
                        [
                            "/bin/sh",
                            str(certs.ACME),
                            "--home",
                            str(certs.ACME.parent),
                            "--config-home",
                            str(directory),
                            "--cert-home",
                            str(directory / "certs"),
                            "--install-cert",
                            "-d",
                            site["names"][0],
                            "--ecc",
                            "--fullchain-file",
                            str(temp / "fullchain.pem"),
                            "--key-file",
                            str(temp / "privkey.pem"),
                            "--reloadcmd",
                            "",
                        ]
                    )
                    # Reuse the previous manager's full public-chain and name validation.
                    certs.validate_pair(
                        temp / "fullchain.pem",
                        temp / "privkey.pem",
                        site["names"],
                        trusted=True,
                    )
                    selected = BASE / "certificates" / sid
                    if (temp / "fullchain.pem").read_bytes() == (
                        selected / "fullchain.pem"
                    ).read_bytes():
                        continue
                    version = BASE / "certificate-versions" / sid / str(time.time_ns())
                    version.mkdir(mode=0o700, parents=True)
                    for name in ["fullchain.pem", "privkey.pem"]:
                        shutil.copyfile(temp / name, version / name)
                        (version / name).chmod(0o600)
                    metadata = {
                        "provider": "imported_acme",
                        "domains": site["names"],
                        "issued": int(time.time()),
                        "sha256": hashlib.sha256(
                            (version / "fullchain.pem").read_bytes()
                        ).hexdigest(),
                    }
                    (version / "metadata.json").write_text(json.dumps(metadata))
                    (version / "metadata.json").chmod(0o600)
                    previous = os.readlink(selected)
                    next_link = selected.with_name("." + sid + "-renew")
                    next_link.symlink_to(version)
                    os.replace(next_link, selected)
                    changes.append((selected, previous))
            if changes:
                run(
                    [
                        "nginx",
                        "-t",
                        "-p",
                        str(BASE),
                        "-c",
                        str(BASE / "current/nginx.conf"),
                    ]
                )
                run(["systemctl", "reload", "kagnode-proxy-traffic.service"])
        except BaseException:
            for selected, previous in reversed(changes):
                link = selected.with_name("." + selected.name + "-restore")
                link.symlink_to(previous)
                os.replace(link, selected)
            if changes:
                run(["systemctl", "reload", "kagnode-proxy-traffic.service"])
            raise
        receipt = {
            "checked": len(ids),
            "renewed": len(changes),
            "completed": int(time.time()),
            "legacy_proxy_applied": False,
        }
        (BASE / "last-imported-renewal.json").write_text(json.dumps(receipt))
        (BASE / "last-imported-renewal.json").chmod(0o600)
        print(json.dumps(receipt))


if __name__ == "__main__":
    main()
