#!/usr/bin/python3
"""Project-owned native setup. Downloading or installing a package never starts it.

The controller, outbound agent and traffic engine have distinct identities. The
root helper accepts only the agent UID through its protected systemd socket.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import shutil
import stat
import subprocess
import tempfile
import tomllib
from urllib.parse import urlsplit

BASE = Path("/srv/kagnode/proxy-manager")
EXEC = Path("/usr/libexec/kagnode-proxy-manager")
CONFIG = Path("/etc/kagnode/proxy-manager")
USERS = ("kn-proxy-controller", "kn-proxy-agent", "kn-proxy-traffic")
UNITS = (
    "kagnode-proxy-controller.service",
    "kagnode-proxy-agent.service",
    "kagnode-proxy-broker.service",
    "kagnode-proxy-broker.socket",
    "kagnode-proxy-traffic.service",
    "kagnode-proxy-credentials.service",
    "kagnode-proxy-credentials.timer",
)


def command(args, **kwargs):
    return subprocess.run(
        args,
        check=True,
        capture_output=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        timeout=120,
        **kwargs,
    )


def protected(path, *, private=False):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("Use absolute protected paths")
    for parent in [*reversed(path.parents), path]:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Native setup paths must be protected and root-owned")
    info = path.stat()
    if info.st_size > 128 * 1024 and private:
        raise ValueError("Private configuration file exceeds limits")
    if private and (
        not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1
    ):
        raise ValueError("Secrets require private root-owned regular files")
    return path


def atomic(path, content, mode=0o644):
    path = Path(path)
    protected(path.parent)
    if path.exists() or path.is_symlink():
        protected(path)
        if not path.is_file():
            raise ValueError("Destination is not a regular file")
    fd, temporary = tempfile.mkstemp(prefix=".install-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def origin(value):
    u = urlsplit(value)
    if (
        u.scheme != "https"
        or not u.hostname
        or u.username
        or u.password
        or u.path not in ("", "/")
        or u.query
        or u.fragment
        or any(c in value for c in "\n\r\0")
    ):
        raise ValueError("Use an HTTPS website origin")
    return value.rstrip("/")


def inspect(configuration, source):
    import ipaddress

    allowed = {
        "role",
        "public_url",
        "fleet_url",
        "email",
        "name",
        "password_file",
        "controller",
        "enrollment_token_file",
        "ca_file",
        "ca_sha256",
        "management_bind",
        "fleet_bind",
        "behind_proxy",
        "package_removal",
    }
    if set(configuration) - allowed:
        raise ValueError("Unknown native configuration fields")
    if any(
        type(configuration.get(k, False)) is not bool
        for k in ("behind_proxy", "package_removal")
    ):
        raise ValueError("Expected boolean policy fields")
    role = configuration.get("role", "combined")
    if role not in ("controller", "agent", "combined"):
        raise ValueError("Choose controller, agent or combined")
    os_release = platform.freedesktop_os_release()
    supported = (os_release.get("ID"), os_release.get("VERSION_ID")) in (
        ("ubuntu", "24.04"),
        ("debian", "13"),
    ) and platform.machine() in ("x86_64", "aarch64")
    binary = source / "bin/kagnode-proxy-manager"
    protected(source)
    if not binary.is_file() or binary.is_symlink():
        raise ValueError(
            "Install a checked architecture-specific application archive; a source archive is not a runtime"
        )
    dependencies = [
        "ca-certificates",
        "openssl",
        "python3",
        "python3-apt",
        "nginx",
        "libnginx-mod-stream",
    ]
    missing = [
        p
        for p in dependencies
        if subprocess.run(
            ["/usr/bin/dpkg-query", "-W", "-f=${Status}", p],
            capture_output=True,
            text=True,
        ).stdout.strip()
        != "install ok installed"
    ]
    if role in ("controller", "combined"):
        origin(configuration.get("public_url", ""))
        origin(configuration.get("fleet_url", ""))
        if not configuration.get("email") or not configuration.get("name"):
            raise ValueError("An initial owner email and name are required")
        for key in ("management_bind", "fleet_bind"):
            raw = configuration.get(
                key, "127.0.0.1:9443" if key == "management_bind" else "0.0.0.0:9444"
            )
            address, port = raw.rsplit(":", 1)
            ip = ipaddress.ip_address(address.strip("[]"))
            if not 1024 <= int(port) <= 65535:
                raise ValueError("Use dedicated unprivileged management ports")
            if (
                key == "management_bind"
                and configuration.get("behind_proxy")
                and not ip.is_loopback()
            ):
                raise ValueError("Plain management must remain on loopback")
        secret = protected(configuration.get("password_file", ""), private=True)
        if not 14 <= len(secret.read_bytes().rstrip(b"\r\n")) <= 256:
            raise ValueError("Owner password must contain 14–256 bytes")
    if role == "agent":
        origin(configuration.get("controller", ""))
        ca = protected(configuration.get("ca_file", ""), private=True)
        if hashlib.sha256(ca.read_bytes()).hexdigest() != configuration.get(
            "ca_sha256"
        ):
            raise ValueError("Enrollment CA fingerprint changed")
        secret = protected(configuration.get("enrollment_token_file", ""), private=True)
        if len(secret.read_bytes().strip()) != 64:
            raise ValueError("Expected a one-time enrollment token")
    return {
        "supported": supported,
        "platform": os_release.get("PRETTY_NAME"),
        "architecture": platform.machine(),
        "role": role,
        "dependencies": dependencies,
        "missing_dependencies": missing,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "native_root": str(BASE),
        "ready_for_apply": supported and not missing,
        "manual_steps": [
            "Install the listed missing prerequisites using the operating system package manager; review any existing Nginx listener first."
        ]
        if missing
        else [],
        "changes": [
            "Create three dedicated service identities",
            "Install protected native executables and reviewed systemd definitions",
            "Initialize a private owner and fleet authority where requested",
            "Start only the explicitly selected controller and/or outbound agent",
            "Enable the restricted socket; traffic starts only after reviewed publication",
        ],
        "health_capability": "native-systemd-and-management-health",
        "configuration": configuration,
        "secret_references": {
            k: {
                "path": str(protected(v, private=True)),
                "inode": Path(v).stat().st_ino,
                "device": Path(v).stat().st_dev,
                "modified_ns": Path(v).stat().st_mtime_ns,
                "size": Path(v).stat().st_size,
            }
            for k, v in configuration.items()
            if k.endswith("_file")
        },
        "secrets": "Paths only; secret contents never appear in plans",
    }


def initialize(configuration, source):
    if os.geteuid() != 0:
        raise PermissionError("Native setup requires root")
    state = inspect(configuration, source)
    if not state["ready_for_apply"]:
        raise ValueError("Native prerequisites are not ready")
    # Installation is separate from adoption of a live proxy. Never overwrite it.
    if (BASE / "installation.json").exists():
        raise ValueError(
            "Already installed; use status/recovery or a reviewed update, not setup"
        )
    BASE.mkdir(parents=True, exist_ok=True)
    protected(BASE)
    CONFIG.mkdir(parents=True, exist_ok=True)
    protected(CONFIG)
    EXEC.mkdir(parents=True, exist_ok=True)
    protected(EXEC)
    for user in USERS:
        try:
            entry = pwd.getpwnam(user)
        except KeyError:
            command(
                [
                    "/usr/sbin/useradd",
                    "--system",
                    "--user-group",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    user,
                ]
            )
            entry = pwd.getpwnam(user)
        if entry.pw_uid == 0 or entry.pw_shell != "/usr/sbin/nologin":
            raise ValueError("Service identity has unexpected privileges")
    binary = (source / "bin/kagnode-proxy-manager").read_bytes()
    atomic(EXEC / "kagnode-proxy-manager", binary, 0o755)
    for filename in ("package_transaction.py", "local_credentials.py"):
        atomic(EXEC / filename, (source / "scripts" / filename).read_bytes(), 0o644)
    for directory, user in (("controller", USERS[0]), ("agent", USERS[1])):
        path = BASE / directory
        if path.exists() and any(path.iterdir()):
            raise ValueError(
                "Existing runtime data requires adoption; it cannot be replaced by setup"
            )
        path.mkdir(exist_ok=True, mode=0o700)
        protected(path)
        entry = pwd.getpwnam(user)
        os.chown(path, entry.pw_uid, entry.pw_gid)
        os.chmod(path, 0o700)
    (BASE / "traffic").mkdir(exist_ok=True, mode=0o750)
    protected(BASE / "traffic")
    agent = pwd.getpwnam(USERS[1])
    replacements = {
        "@EXEC@": str(EXEC),
        "@BASE@": str(BASE),
        "@AGENT_UID@": str(agent.pw_uid),
        "@MANAGEMENT_BIND@": configuration.get("management_bind", "127.0.0.1:9443"),
        "@FLEET_BIND@": configuration.get("fleet_bind", "0.0.0.0:9444"),
        "@PROXY_FLAG@": "--behind-proxy" if configuration.get("behind_proxy") else "",
    }
    for filename in UNITS:
        data = (source / "scripts/systemd" / filename).read_text()
        for key, value in replacements.items():
            data = data.replace(key, value)
        if "@" in data:
            raise ValueError("Unresolved service template")
        atomic(Path("/etc/systemd/system") / filename, data.encode())
    registry = {}
    registry_path = CONFIG / "managed-services.json"
    if registry_path.exists():
        registry = json.loads(protected(registry_path).read_text())
    for unit in UNITS:
        paths = [Path("/etc/systemd/system") / unit]
        if unit.endswith(".service"):
            paths.append(
                Path("/usr/sbin/nginx")
                if unit == "kagnode-proxy-traffic.service"
                else EXEC / "kagnode-proxy-manager"
            )
        registry[unit] = {
            "files": {
                str(p): hashlib.sha256(protected(p).read_bytes()).hexdigest()
                for p in paths
            },
            "required": state["dependencies"],
        }
    atomic(registry_path, json.dumps(registry).encode(), 0o600)
    role = state["role"]
    if role in ("controller", "combined"):
        secret = protected(configuration["password_file"], private=True).read_bytes()
        command(
            [
                "/usr/sbin/runuser",
                "-u",
                USERS[0],
                "--",
                str(EXEC / "kagnode-proxy-manager"),
                "init",
                "--root",
                str(BASE / "controller"),
                "--email",
                configuration["email"],
                "--name",
                configuration["name"],
                "--public-url",
                configuration["public_url"],
                "--fleet-url",
                configuration["fleet_url"],
            ],
            input=secret,
        )
    if role == "combined":
        command(
            [
                str(EXEC / "kagnode-proxy-manager"),
                "enroll-local",
                "--controller-root",
                str(BASE / "controller"),
                "--agent-root",
                str(BASE / "agent"),
                "--name",
                platform.node() or "Local server",
            ]
        )
        for directory, user in (("controller", USERS[0]), ("agent", USERS[1])):
            entry = pwd.getpwnam(user)
            for path in [BASE / directory, *sorted((BASE / directory).rglob("*"))]:
                if path.is_symlink():
                    raise ValueError("Unexpected initialization symlink")
                os.chown(path, entry.pw_uid, entry.pw_gid)
    elif role == "agent":
        ca = BASE / "agent" / "enrollment-ca.pem"
        ca.write_bytes(protected(configuration["ca_file"], private=True).read_bytes())
        os.chown(ca, agent.pw_uid, agent.pw_gid)
        os.chmod(ca, 0o600)
        secret = protected(
            configuration["enrollment_token_file"], private=True
        ).read_bytes()
        command(
            [
                "/usr/sbin/runuser",
                "-u",
                USERS[1],
                "--",
                str(EXEC / "kagnode-proxy-manager"),
                "enroll",
                "--root",
                str(BASE / "agent"),
                "--controller",
                configuration["controller"],
                "--ca",
                str(ca),
            ],
            input=secret,
        )
        ca.unlink()
    if configuration.get("package_removal"):
        atomic(
            CONFIG / "allow-package-removal",
            b"Explicitly enabled during reviewed native setup.\n",
            0o644,
        )
    elif (CONFIG / "allow-package-removal").exists():
        raise ValueError("Existing host-maintenance policy requires explicit adoption")
    atomic(
        BASE / "installation.json",
        json.dumps(
            {
                "schema": 1,
                "version": tomllib.loads((source / "Cargo.toml").read_text())[
                    "package"
                ]["version"],
                "role": role,
                "binary_sha256": state["binary_sha256"],
                "data_retained_on_removal": True,
            }
        ).encode(),
        0o600,
    )
    command(["/usr/bin/systemctl", "daemon-reload"])
    command(["/usr/bin/systemctl", "enable", "--now", "kagnode-proxy-broker.socket"])
    if role in ("controller", "combined"):
        command(
            [
                "/usr/bin/systemctl",
                "enable",
                "--now",
                "kagnode-proxy-controller.service",
            ]
        )
    if role in ("agent", "combined"):
        command(
            ["/usr/bin/systemctl", "enable", "--now", "kagnode-proxy-agent.service"]
        )
    if role == "combined":
        command(
            ["/usr/bin/systemctl", "enable", "--now", "kagnode-proxy-credentials.timer"]
        )
    return {
        "completed": True,
        "state": "completed",
        "installation": state,
        "traffic_started": False,
    }


def health():
    path = BASE / "installation.json"
    if not path.is_file():
        return {"healthy": False, "state": "not-installed"}
    state = json.loads(protected(path, private=True).read_text())
    units = ["kagnode-proxy-broker.socket"]
    if state["role"] in ("controller", "combined"):
        units.append("kagnode-proxy-controller.service")
    if state["role"] in ("agent", "combined"):
        units.append("kagnode-proxy-agent.service")
    status = {
        u: subprocess.run(["/usr/bin/systemctl", "is-active", "--quiet", u]).returncode
        == 0
        for u in units
    }
    return {
        "healthy": all(status.values()),
        "services": status,
        "scope": "Native process readiness; published routes and external connectivity require separate checks",
        "version": state["version"],
    }
