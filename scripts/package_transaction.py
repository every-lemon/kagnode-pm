#!/usr/bin/python3
"""APT solver and locked transaction worker. No shell, purge or autoremove interface."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import stat
import sys

CORE_PREFIXES = (
    "apt",
    "dpkg",
    "systemd",
    "udev",
    "linux-",
    "grub",
    "shim",
    "initramfs",
    "network",
    "netplan",
    "ifupdown",
    "iproute",
    "isc-dhcp",
    "dhcpcd",
    "resolv",
    "libc6",
    "libpam",
    "libnss",
    "libssl",
    "libsystemd",
    "openssl",
    "openssh",
    "sudo",
    "kagnode",
    "nginx",
    "3proxy",
    "python3",
)
CORE_NAMES = {
    "bash",
    "dash",
    "coreutils",
    "util-linux",
    "mount",
    "login",
    "passwd",
    "ca-certificates",
    "dbus",
    "tzdata",
    "chrony",
    "ntp",
    "polkitd",
}
NAME = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,199}(?::(?:amd64|arm64|all|i386))?$")


def run(args):
    result = subprocess.run(
        args,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError("Inventory too large")
    return result.stdout


def ownership_paths(path):
    """dpkg may record either spelling on a merged-/usr distribution."""
    resolved = Path(path).resolve(strict=True)
    names = {path, str(resolved)}
    for old, new in [
        ("/bin/", "/usr/bin/"),
        ("/sbin/", "/usr/sbin/"),
        ("/lib/", "/usr/lib/"),
    ]:
        candidate = (
            new + path[len(old) :]
            if path.startswith(old)
            else old + path[len(new) :]
            if path.startswith(new)
            else None
        )
        if (
            candidate
            and Path(candidate).exists()
            and Path(candidate).resolve() == resolved
        ):
            names.add(candidate)
    return sorted(names)


def package_ownership(paths, cache):
    variants = {}
    for path in paths:
        try:
            variants[path] = ownership_paths(path)
        except OSError:
            variants[path] = []
    names = sorted({name for row in variants.values() for name in row})
    found = {name: set() for name in names}
    for offset in range(0, len(names), 32):
        batch = names[offset : offset + 32]
        result = subprocess.run(
            ["/usr/bin/dpkg-query", "-S", *batch],
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
        if result.returncode not in (0, 1) or len(result.stdout) > 8 * 1024 * 1024:
            raise ValueError("Package ownership lookup failed")
        for line in result.stdout.splitlines():
            if ": " not in line:
                continue
            packages, name = line.rsplit(": ", 1)
            if name not in found:
                continue
            for package in packages.split(", "):
                if package in cache and cache[package].is_installed:
                    found[name].add(package)
    return {
        path: set().union(*(found[name] for name in names))
        for path, names in variants.items()
    }


def service_owners(cache):
    owners, uncertain = {}, []
    ownership_cache = {}
    declarations = {}
    policy = Path("/etc/kagnode/proxy-manager/managed-services.json")
    if policy.exists():
        info = policy.lstat()
        if (
            not policy.is_file()
            or policy.is_symlink()
            or info.st_uid
            or info.st_mode & 0o022
            or info.st_size > 1024 * 1024
        ):
            raise ValueError("Unsafe service ownership registry")
        declarations = json.loads(policy.read_text())
        if not isinstance(declarations, dict) or len(declarations) > 512:
            raise ValueError("Invalid service ownership registry")
    try:
        active = run(
            [
                "/usr/bin/systemctl",
                "list-units",
                "--all",
                "--state=active,activating",
                "--type=service,socket,timer",
                "--plain",
                "--no-legend",
                "--no-pager",
            ]
        )
        enabled = run(
            [
                "/usr/bin/systemctl",
                "list-unit-files",
                "--state=enabled",
                "--type=service,socket,timer",
                "--no-legend",
                "--no-pager",
            ]
        )
        units = sorted(
            {
                line.split()[0]
                for line in (active + enabled).splitlines()
                if line.strip()
            }
        )
        if len(units) > 512:
            raise ValueError("Service inventory exceeds bounded limit")
        # Batch systemd and dpkg inspection: spawning hundreds of commands
        # is unnecessarily expensive on a one-vCPU appliance.
        regular = [unit for unit in units if "@." not in unit]
        blocks = {}
        if regular:
            details = run(
                [
                    "/usr/bin/systemctl",
                    "show",
                    *regular,
                    "--property=Id,Names,FragmentPath,ExecStart",
                    "--no-pager",
                ]
            )
            for block in details.split("\n\n"):
                props = dict(
                    line.split("=", 1) for line in block.splitlines() if "=" in line
                )
                for name in props.get("Names", "").split() + [props.get("Id", "")]:
                    blocks[name] = block
        paths_by_unit = {}
        for unit in units:
            if not re.fullmatch(r"[A-Za-z0-9@_.:\\-]+\.(?:service|socket|timer)", unit):
                raise ValueError("Unexpected service identifier")
            if "@." in unit:
                content = run(["/usr/bin/systemctl", "cat", "--no-pager", unit])
                paths = re.findall(r"^# (/[^\n]+)", content, re.M) + re.findall(
                    r"^ExecStart=[-+!:@]*(/[^\s;]+)", content, re.M
                )
            else:
                if unit not in blocks:
                    raise ValueError("Service ownership could not be inspected")
                paths = re.findall(r"(?:FragmentPath=|path=)(/[^ ;\n}]+)", blocks[unit])
            if not paths:
                raise ValueError("Service files are unknown")
            paths_by_unit[unit] = paths
        ownership_cache = package_ownership(
            {path for row in paths_by_unit.values() for path in row}, cache
        )
        for unit, paths in paths_by_unit.items():
            for path in paths:
                try:
                    packages = ownership_cache[path]
                    if not packages:
                        raise ValueError(
                            "Service file is not owned by an installed package"
                        )
                    for package in packages:
                        owners.setdefault(package, set()).add(unit)
                except (OSError, ValueError):
                    declared = declarations.get(unit, {})
                    digest = declared.get("files", {}).get(path)
                    candidate = Path(path)
                    try:
                        st = candidate.lstat()
                        if (
                            not stat.S_ISREG(st.st_mode)
                            or st.st_uid
                            or st.st_mode & 0o022
                            or st.st_size > 64 * 1024 * 1024
                            or not isinstance(digest, str)
                            or hashlib.sha256(candidate.read_bytes()).hexdigest()
                            != digest
                        ):
                            raise ValueError("Unverified custom service file")
                        required = declared.get("required", [])
                        if (
                            not required
                            or len(required) > 128
                            or not all(
                                isinstance(n, str)
                                and NAME.fullmatch(n)
                                and n in cache
                                and cache[n].is_installed
                                for n in required
                            )
                        ):
                            raise ValueError("Unverified custom service dependencies")
                        for name in required:
                            owners.setdefault(name, set()).add(unit)
                    except (OSError, ValueError):
                        # Custom services need exact root-controlled ownership declarations.
                        uncertain.append("Unowned service file: " + path)
    except (subprocess.SubprocessError, ValueError) as error:
        uncertain.append("Service inventory unavailable: " + type(error).__name__)
    return owners, sorted(set(uncertain))


def inspect(cache, requested):
    import apt_pkg

    for name in requested:
        if (
            not NAME.fullmatch(name)
            or name not in cache
            or not cache[name].is_installed
        ):
            raise ValueError("Choose exact installed package names")
    owners, uncertain = service_owners(cache)
    required = set()
    installed = sorted((p for p in cache if p.is_installed), key=lambda p: p.fullname)
    for package in installed:
        name = package.name
        if (
            name.startswith(CORE_PREFIXES)
            or name in CORE_NAMES
            or name in owners
            or package.fullname in owners
        ):
            required.add(package.fullname)
    policy = Path("/etc/kagnode/proxy-manager/protected-packages.json")
    if policy.exists():
        st = policy.lstat()
        if (
            not policy.is_file()
            or policy.is_symlink()
            or st.st_uid
            or st.st_mode & 0o022
        ):
            raise ValueError("Unsafe protection policy permissions")
        extra = json.loads(policy.read_text())
        if not isinstance(extra, list) or not all(
            isinstance(n, str) and NAME.fullmatch(n) for n in extra
        ):
            raise ValueError("Invalid protection policy")
        for name in extra:
            if name not in cache or not cache[name].is_installed:
                uncertain.append("Declared protected package not found: " + name)
            else:
                required.add(cache[name].fullname)
    pending = list(required)
    while pending:
        name = pending.pop()
        for dependency in cache[name].installed.dependencies:
            for alternative in dependency.or_dependencies:
                for version in alternative.installed_target_versions:
                    target = version.package.fullname
                    if target not in required:
                        required.add(target)
                        pending.append(target)
    packages = []
    for package in installed:
        record = package.installed.record
        packages.append(
            {
                "name": package.fullname,
                "version": package.installed.version,
                "essential": record.get("Essential") == "yes",
                "protected": record.get("Protected") == "yes",
                "held": package._pkg.selected_state == apt_pkg.SELSTATE_HOLD,
                "bytes": package.installed.installed_size,
                "services": sorted(
                    owners.get(package.fullname, owners.get(package.name, []))
                ),
            }
        )
    inventory = {
        "packages": packages,
        "required": sorted(required),
        "uncertain": sorted(set(uncertain)),
    }
    for name in requested:
        cache[name].mark_delete(auto_fix=True, purge=False)
    changes = cache.get_changes()
    if cache.broken_count or any(not p.marked_delete for p in changes):
        raise ValueError("Removal requires an unsupported additional package change")
    removals = sorted(p.fullname for p in changes)
    return inventory, removals


def main():
    import apt
    import apt_pkg

    if len(sys.argv) < 2 or sys.argv[1] not in {"preview", "apply"}:
        raise ValueError("Unsupported package operation")
    mode = sys.argv[1]
    if mode == "preview":
        with apt.Cache() as cache:
            inventory, removals = inspect(cache, sys.argv[2:])
            # Canonical architecture-qualified names are returned to the Rust planner.
            requested = sorted(cache[n].fullname for n in sys.argv[2:])
            print(
                json.dumps(
                    {
                        "inventory": inventory,
                        "removals": removals,
                        "requested": requested,
                    },
                    separators=(",", ":"),
                )
            )
        return
    if os.geteuid() != 0:
        raise PermissionError("The restricted local helper must own package operations")
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError("Oversized plan")
    plan = json.loads(raw)
    if (
        set(plan) != {"requested", "removals", "fingerprint", "approved"}
        or plan["approved"] is not True
    ):
        raise ValueError("Expected an explicitly approved removal plan")
    # Retain APT's frontend lock from fresh cache creation through commit. APT
    # releases only its inner dpkg lock while dpkg runs, then restores that lock.
    with apt_pkg.SystemLock():
        with apt.Cache() as cache:
            inventory, removals = inspect(cache, plan["requested"])
            fingerprint = hashlib.sha256(
                json.dumps(
                    inventory, ensure_ascii=False, separators=(",", ":")
                ).encode()
            ).hexdigest()
            if fingerprint != plan["fingerprint"] or removals != plan["removals"]:
                raise ValueError(
                    "Package state changed; obtain a fresh removal preview"
                )
            by_name = {p["name"]: p for p in inventory["packages"]}
            if inventory["uncertain"]:
                raise ValueError("Package inventory cannot be fully verified")
            for name in removals:
                p = by_name[name]
                base = name.split(":", 1)[0]
                if (
                    p["essential"]
                    or p["protected"]
                    or p["held"]
                    or p["services"]
                    or name in inventory["required"]
                    or base.startswith(CORE_PREFIXES)
                    or base in CORE_NAMES
                ):
                    raise ValueError("Removal includes a protected package: " + name)
            os.environ.update(DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l")
            output_fd = os.dup(1)
            try:
                os.dup2(2, 1)
                # The reviewed solution contains removals only. Do not create
                # an Acquire/download phase or request any new package data.
                manager = apt_pkg.PackageManager(cache._depcache)
                result = cache.install_archives(
                    manager, apt.progress.base.InstallProgress()
                )
                if result != manager.RESULT_COMPLETED:
                    raise RuntimeError("APT did not confirm transaction completion")
            finally:
                os.dup2(output_fd, 1)
                os.close(output_fd)
    print(
        json.dumps(
            {"completed": True, "removed": removals, "configuration_retained": True}
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
