#!/usr/bin/python3
"""Bounded, read-only proxy discovery. Never loads engine plugins or changes traffic."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import tomllib
from urllib.parse import urlsplit

ROOTS = {
    "nginx": ("/etc/nginx", "/etc/nginx-manager"),
    "caddy": ("/etc/caddy",),
    "apache": ("/etc/apache2", "/etc/httpd"),
    "haproxy": ("/etc/haproxy",),
    "traefik": ("/etc/traefik",),
}
MAX_FILES = 256
MAX_BYTES = 4 * 1024 * 1024


def digest(value):
    return hashlib.sha256(value).hexdigest()


def valid_url(value):
    try:
        u = urlsplit(value)
    except ValueError:
        raise ValueError("Upstream URL cannot be safely inspected") from None
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise ValueError("Upstream requires an HTTP(S) URL without credentials")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("Upstream path rewriting requires explicit review")
    if any(c in value for c in "\r\n\0{};$\\"):
        raise ValueError("Upstream contains engine-specific expressions")
    return value.rstrip("/")


def resource(domains, upstreams, **settings):
    if not domains or any(
        not re.fullmatch(r"(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", d)
        for d in domains
    ):
        raise ValueError("Explicit DNS hostnames are required")
    if not upstreams:
        raise ValueError("No reverse-proxy upstream found")
    return {
        "kind": "proxy_host",
        "settings": {
            "domains": domains,
            "upstreams": [
                {"address": valid_url(u), "weight": 1, "backup": False}
                for u in upstreams
            ],
            "force_https": False,
            **settings,
        },
    }


def tokens(source):
    # Preserve quoting and comments; reject unbalanced or exotic syntax.
    pattern = (
        r"""\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};"'\#]+"""
    )
    out = []
    position = 0
    for m in re.finditer(pattern, source):
        if m.start() != position:
            raise ValueError("Unsupported configuration quoting")
        position = m.end()
        token = m.group()
        if token.isspace() or token.startswith("#"):
            continue
        if token.startswith(('"', "'")):
            token = token[1:-1]
        out.append(token)
    if position != len(source):
        raise ValueError("Incomplete configuration")
    return out


def nginx_parse(source):
    stream = tokens(source)
    index = 0

    def block(depth=0):
        nonlocal index
        if depth > 16:
            raise ValueError("Configuration nesting exceeds limit")
        nodes, directive = [], []
        while index < len(stream):
            token = stream[index]
            index += 1
            if token == "}":
                if not depth or directive:
                    raise ValueError("Unexpected closing brace")
                return nodes
            if token == "{":
                if not directive:
                    raise ValueError("Missing directive")
                nodes.append((directive, block(depth + 1)))
                directive = []
            elif token == ";":
                if not directive:
                    raise ValueError("Empty directive")
                nodes.append((directive, None))
                directive = []
            else:
                directive.append(token)
        if depth or directive:
            raise ValueError("Incomplete configuration block")
        return nodes

    return block()


def nginx_sites(source):
    tree = nginx_parse(source)
    output = []

    def walk(nodes, inherited=None):
        for args, children in nodes:
            if args[0] == "server" and children is not None:
                row = {"domains": [], "blockers": [], "resource": None}
                ups, settings, locations = [], {"websocket": False}, []
                for a, sub in children:
                    key, values = a[0], a[1:]
                    if key == "server_name":
                        row["domains"] += values
                    elif key == "location":
                        locations.append((values, sub))
                    elif key == "listen":
                        if len(values) != 1 or values[0] not in ("80", "[::]:80"):
                            row["blockers"].append(
                                "TLS, custom listener or listen options require migration review"
                            )
                    elif key not in ("access_log", "error_log"):
                        row["blockers"].append("Review server directive: " + key)
                if len(locations) != 1 or locations[0][0] != ["/"]:
                    row["blockers"].append("Combined locations require explicit review")
                for _, directives in locations:
                    for a, sub in directives or []:
                        if sub is not None:
                            row["blockers"].append(
                                "Nested location rules require review"
                            )
                        elif a[0] == "proxy_pass" and len(a) == 2:
                            ups.append(a[1])
                        elif a == ["proxy_http_version", "1.1"]:
                            pass
                        elif a[0] == "proxy_set_header" and a[1:] in (
                            ["Host", "$host"],
                            ["X-Real-IP", "$remote_addr"],
                            ["X-Forwarded-For", "$proxy_add_x_forwarded_for"],
                            ["X-Forwarded-Proto", "$scheme"],
                        ):
                            pass
                        else:
                            row["blockers"].append("Review location directive: " + a[0])
                # Unresolved includes/global inheritance can change security semantics.
                for a, sub in inherited or []:
                    if a[0] != "server":
                        row["blockers"].append("Review inherited directive: " + a[0])
                try:
                    row["resource"] = resource(row["domains"], ups, **settings)
                except ValueError as exc:
                    row["blockers"].append(str(exc))
                output.append(row)
            elif children is not None and args[0] == "http":
                walk(children, children)

    walk(tree, tree)
    return output


def caddy_sites(source):
    # Simple explicit HTTP blocks only. Automatic TLS/global options need review.
    out = []
    for match in re.finditer(r"(?m)^([^\s{}#][^{}\n]*)\s*\{([^{}]*)\}", source):
        names, body = match.groups()
        row = {"domains": [], "resource": None, "blockers": []}
        names = [v.strip() for v in names.split(",")]
        upstreams = []
        for name in names:
            u = urlsplit(name if "://" in name else "https://" + name)
            row["domains"].append(u.hostname or name)
            if u.scheme != "http" or u.port not in (None, 80):
                row["blockers"].append(
                    "Caddy automatic TLS or custom listener requires certificate review"
                )
        for line in body.splitlines():
            parts = line.strip().split()
            if not parts or parts[0].startswith("#"):
                continue
            if parts[0] == "reverse_proxy":
                upstreams += [v if "://" in v else "http://" + v for v in parts[1:]]
            else:
                row["blockers"].append("Review Caddy directive: " + parts[0])
        try:
            row["resource"] = resource(row["domains"], upstreams)
        except ValueError as exc:
            row["blockers"].append(str(exc))
        out.append(row)
    return out


def apache_sites(source):
    out = []
    for match in re.finditer(
        r"<VirtualHost\s+([^>]+)>(.*?)</VirtualHost\s*>", source, re.I | re.S
    ):
        listen, body = match.groups()
        row = {"domains": [], "resource": None, "blockers": []}
        if listen.strip() not in ("*:80", "0.0.0.0:80"):
            row["blockers"].append("TLS or custom listener requires review")
        upstreams = []
        for line in body.splitlines():
            parts = line.strip().split()
            if not parts or parts[0].startswith("#"):
                continue
            key = parts[0].lower()
            if key in ("servername", "serveralias"):
                row["domains"] += parts[1:]
            elif key == "proxypass" and len(parts) == 3 and parts[1] == "/":
                upstreams.append(parts[2])
            elif key == "proxypassreverse" and len(parts) == 3 and parts[1] == "/":
                if parts[2] not in upstreams:
                    row["blockers"].append("Reverse rewrite differs from upstream")
            elif key not in ("errorlog", "customlog", "proxyrequests") or (
                key == "proxyrequests" and parts[1:] != ["Off"]
            ):
                row["blockers"].append("Review Apache directive: " + key)
        try:
            row["resource"] = resource(row["domains"], upstreams)
        except ValueError as exc:
            row["blockers"].append(str(exc))
        out.append(row)
    return out


def haproxy_sites(source):
    # Inventory only for complex ACL/rule ordering; no lossy automatic conversion.
    out = []
    for match in re.finditer(r"(?m)^(?:frontend|listen)\s+(\S+)", source):
        out.append(
            {
                "domains": [],
                "resource": None,
                "blockers": [
                    "Review HAProxy ACL ordering, binds and backend selection"
                ],
                "label": match.group(1)[:80],
            }
        )
    return out


def traefik_sites(source, suffix):
    if suffix == ".json":
        doc = json.loads(source)
    elif suffix == ".toml":
        doc = tomllib.loads(source)
    else:
        # Safe optional YAML parsing, no constructors or engine plugin loading.
        try:
            import yaml

            if any(t in source for t in ("!!", "&", "*")):
                raise ValueError("YAML tags and aliases require review")
            doc = yaml.safe_load(source)
        except ImportError:
            return [
                {
                    "domains": [],
                    "resource": None,
                    "blockers": [
                        "Install python3-yaml to inspect Traefik YAML; original configuration retained"
                    ],
                }
            ]
    if not isinstance(doc, dict):
        raise ValueError("Expected a Traefik configuration object")
    out = []
    http = doc.get("http", {})
    for name, route in http.get("routers", {}).items():
        row = {
            "label": str(name)[:80],
            "domains": re.findall(r"Host\(`([^`]+)`\)", route.get("rule", "")),
            "resource": None,
            "blockers": [],
        }
        if route.get("middlewares") or route.get("tls") or route.get("entryPoints"):
            row["blockers"].append("Review entry points, middleware and TLS ownership")
        service = http.get("services", {}).get(route.get("service"), {})
        if set(service) != {"loadBalancer"} or set(service.get("loadBalancer", {})) - {
            "servers"
        }:
            row["blockers"].append("Review Traefik service settings")
        if route.get("rule") != " || ".join(
            "Host(`" + d + "`)" for d in row["domains"]
        ):
            row["blockers"].append("Review Traefik routing expression")
        try:
            row["resource"] = resource(
                row["domains"],
                [s["url"] for s in service.get("loadBalancer", {}).get("servers", [])],
            )
        except (ValueError, KeyError) as exc:
            row["blockers"].append(str(exc))
        out.append(row)
    return out


def inspect_file(path, engine):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > 512 * 1024:
            raise ValueError("Not a bounded regular configuration file")
        raw = os.read(fd, 512 * 1024 + 1)
        if len(raw) > 512 * 1024:
            raise ValueError("Configuration exceeds read limit")
        after = os.fstat(fd)
        if (meta.st_mtime_ns, meta.st_size) != (after.st_mtime_ns, after.st_size):
            raise ValueError("Configuration changed while reading")
    finally:
        os.close(fd)
    text = raw.decode("utf-8")
    row = {
        "path": str(path),
        "engine": engine,
        "sha256": digest(raw),
        "size": len(raw),
        "mode": oct(stat.S_IMODE(meta.st_mode)),
        "uid": meta.st_uid,
        "gid": meta.st_gid,
        "sites": [],
        "warnings": [],
    }
    parser = {
        "nginx": nginx_sites,
        "caddy": caddy_sites,
        "apache": apache_sites,
        "haproxy": haproxy_sites,
    }
    try:
        row["sites"] = (
            traefik_sites(text, path.suffix)
            if engine == "traefik"
            else parser[engine](text)
        )
    except (ValueError, KeyError, TypeError, RecursionError) as exc:
        row["warnings"].append(
            "Configuration needs manual review: " + type(exc).__name__
        )
    for index, site in enumerate(row["sites"]):
        site["id"] = digest((str(path) + ":" + str(index)).encode())[:32]
        site["blockers"] = sorted(set(site["blockers"]))
        site["supported"] = site["resource"] is not None and not site["blockers"]
    # Never return raw source, credential directives, key paths or opaque values.
    row["directives"] = sorted(
        set(re.findall(r"(?m)^\s*([A-Za-z][A-Za-z0-9_]*)\b", text))
    )[:80]
    return row


def containers():
    result = []
    for executable in ("/usr/bin/docker", "/usr/bin/podman"):
        if not Path(executable).is_file():
            continue
        try:
            data = subprocess.run(
                [
                    executable,
                    "ps",
                    "--all",
                    "--format",
                    "{{.ID}}\t{{.Image}}\t{{.Names}}",
                ],
                capture_output=True,
                text=True,
                timeout=8,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                check=True,
            )
            for line in data.stdout[:32768].splitlines()[:64]:
                parts = line.split("\t")
                if len(parts) == 3 and any(
                    k in parts[1].lower() for k in (*ROOTS, "nginx-proxy-manager")
                ):
                    result.append(
                        {
                            "runtime": Path(executable).name,
                            "id": parts[0][:64],
                            "name": parts[2][:80],
                            "image": parts[1][:180],
                            "adoption": "Review container configuration export and mounted volumes before adoption",
                        }
                    )
        except (OSError, subprocess.SubprocessError):
            result.append(
                {
                    "runtime": Path(executable).name,
                    "warning": "Container inventory unavailable; existing containers retained",
                }
            )
    return result


def runtime_inventory():
    services = []
    for unit in (
        "nginx.service",
        "caddy.service",
        "apache2.service",
        "httpd.service",
        "haproxy.service",
        "traefik.service",
        "kagnode-proxy-traffic.service",
        "nginx-manager-web.service",
    ):
        try:
            result = subprocess.run(
                [
                    "/usr/bin/systemctl",
                    "show",
                    unit,
                    "--property=ActiveState,FragmentPath,LoadState",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            )
            values = dict(
                line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
            )
            if values.get("LoadState") != "not-found":
                services.append(
                    {
                        "unit": unit,
                        "active": values.get("ActiveState", "unknown"),
                        "definition": values.get("FragmentPath", ""),
                    }
                )
        except (OSError, subprocess.SubprocessError):
            pass
    listeners = []
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            for line in Path(table).read_text().splitlines()[1:512]:
                parts = line.split()
                if len(parts) > 3 and parts[3] == "0A":
                    port = int(parts[1].rsplit(":", 1)[1], 16)
                    listeners.append(
                        {
                            "family": "ipv6" if table.endswith("6") else "ipv4",
                            "port": port,
                        }
                    )
        except (OSError, ValueError):
            pass
    return {
        "services": services,
        "listeners": listeners[:64],
        "active_engine": "nginx"
        if any(
            s["unit"] == "kagnode-proxy-traffic.service" and s["active"] == "active"
            for s in services
        )
        else None,
    }


def discover(roots=None, with_containers=True):
    roots = ROOTS if roots is None else roots
    files, warnings, total = [], [], 0
    for engine, directories in roots.items():
        if engine not in ROOTS:
            raise ValueError("Unknown proxy engine")
        for directory in directories:
            base = Path(directory)
            if not base.is_dir() or base.is_symlink():
                continue
            for parent, dirs, names in os.walk(base, followlinks=False):
                dirs[:] = sorted(
                    d for d in dirs if not (Path(parent) / d).is_symlink()
                )[:64]
                if len(Path(parent).relative_to(base).parts) > 8:
                    dirs[:] = []
                    continue
                for name in sorted(names):
                    path = Path(parent) / name
                    if path.is_symlink() or path.suffix.lower() in (
                        ".key",
                        ".pem",
                        ".crt",
                        ".db",
                        ".sqlite",
                    ):
                        continue
                    if (
                        path.suffix
                        not in (".conf", ".json", ".yaml", ".yml", ".toml", "")
                        and name != "Caddyfile"
                    ):
                        continue
                    if any(
                        x in path.parts
                        for x in ("certs", "certificates", "private", "accounts")
                    ):
                        continue
                    if len(files) >= MAX_FILES or total >= MAX_BYTES:
                        warnings.append(
                            "Inventory limit reached; review remaining configuration locally"
                        )
                        break
                    try:
                        item = inspect_file(path, engine)
                        total += item["size"]
                        files.append(item)
                    except (OSError, UnicodeError, ValueError):
                        warnings.append("Cannot inspect configuration: " + str(path))
    fingerprint = digest(
        json.dumps(
            [
                {k: f[k] for k in ("path", "sha256", "mode", "uid", "gid")}
                for f in files
            ],
            sort_keys=True,
        ).encode()
    )
    # Global/security/include semantics are intentionally never inferred away.
    for item in files:
        for site in item["sites"]:
            if len(files) > 1:
                site["blockers"].append(
                    "Review cross-file includes and inherited security policies"
                )
                site["supported"] = False
    report = {
        "schema": 1,
        "fingerprint": fingerprint,
        "sampled": int(time.time()),
        "read_only": True,
        "files": files,
        "warnings": sorted(set(warnings)),
        "containers": containers() if with_containers else [],
        "runtime": runtime_inventory() if with_containers else {},
    }
    # Bound receipts, fail explicitly instead of truncating routing semantics.
    if len(json.dumps(report)) > 56000:
        report["files"] = [
            {k: f[k] for k in ("path", "engine", "sha256", "size")} for f in files
        ]
        report["warnings"].append(
            "Detailed inventory exceeds protocol limit; split configuration review locally"
        )
    return report


def review(request):
    if set(request) != {"fingerprint", "selected"} or not re.fullmatch(
        r"[a-f0-9]{64}", request["fingerprint"]
    ):
        raise ValueError("Invalid adoption review")
    selected = request["selected"]
    if (
        not isinstance(selected, list)
        or not 1 <= len(selected) <= 32
        or len(set(selected)) != len(selected)
    ):
        raise ValueError("Select 1–32 distinct sites")
    report = discover()
    if report["fingerprint"] != request["fingerprint"] or report["warnings"]:
        raise ValueError(
            "Configuration changed or inventory is incomplete; review discovery again"
        )
    sites = {s["id"]: s for f in report["files"] for s in f.get("sites", [])}
    if any(i not in sites or not sites[i]["supported"] for i in selected):
        raise ValueError("Selected sites have unresolved migration blockers")
    return {
        "fingerprint": report["fingerprint"],
        "resources": [
            {"name": "import-" + i, "resource": sites[i]["resource"]} for i in selected
        ],
        "state": "reviewed",
        "traffic_changed": False,
    }


if __name__ == "__main__":
    try:
        action = sys.argv[1] if len(sys.argv) == 2 else "discover"
        if action not in ("discover", "review"):
            raise ValueError("Unknown discovery action")
        result = (
            discover()
            if action == "discover"
            else review(json.loads(sys.stdin.read(8193)))
        )
        print(json.dumps(result, separators=(",", ":")))
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
