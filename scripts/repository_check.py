#!/usr/bin/env python3
"""Non-mutating source, version and pinned-fallback inventory checks."""

import hashlib
import json
from pathlib import Path
import re
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def check():
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    assert re.fullmatch(r"5\.0\.\d+", package["version"]), (
        "KagNode releases remain 5.0.x"
    )
    assert package["license"] == "AGPL-3.0-only"
    lock = json.loads((ROOT / "core.lock.json").read_text())
    manifest_path = ROOT / "vendor/core/core-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    assert (
        hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        == lock["signed_ui_manifest_sha256"]
    )
    assert (
        manifest["version"] == lock["baseline"]
        and manifest["source_commit"] == lock["source_commit"]
        and lock["patch_range"] == "5.0.x"
    )
    subprocess.run(
        [
            "openssl",
            "pkeyutl",
            "-verify",
            "-rawin",
            "-pubin",
            "-inkey",
            str(ROOT / "vendor/core-source/assets/release-public.pem"),
            "-in",
            str(manifest_path),
            "-sigfile",
            str(ROOT / "vendor/core/core-manifest.sig"),
        ],
        check=True,
        capture_output=True,
    )
    for name, item in manifest["files"].items():
        p = ROOT / "vendor/core" / name
        assert p.is_file() and not p.is_symlink()
        content = p.read_bytes()
        assert (
            len(content) == item["size"]
            and hashlib.sha256(content).hexdigest() == item["sha256"]
        ), name
    import base64

    fallback_path = ROOT / "vendor/core-rust/fallback/bundle.json"
    assert (
        hashlib.sha256(fallback_path.read_bytes()).hexdigest()
        == lock["fallback_manifest_sha256"]
    )
    fallback = json.loads(fallback_path.read_text())
    assert fallback["version"] == lock["baseline"] and fallback["ui_api"] == 1
    for name, item in fallback["files"].items():
        assert (
            base64.b64decode(item["data"]) == (ROOT / "vendor/core" / name).read_bytes()
        ), name
    headings = [
        "Overview",
        "Release status",
        "Features",
        "Requirements",
        "Installation and downloads",
        "Usage",
        "Configuration and storage",
        "Security",
        "Development and testing",
        "Documentation",
        "Licensing",
    ]
    readme = (ROOT / "README.md").read_text()
    positions = [readme.index("## " + h) for h in headings]
    assert positions == sorted(positions)
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .split("\0")
    )
    allowlist = json.loads((ROOT / "packaging/source-files.json").read_text())
    assert allowlist == sorted(n for n in names if n), (
        "Refresh the exact committed source allowlist after changing generated files"
    )
    forbidden = {
        "target",
        "node_modules",
        "__pycache__",
        ".qa",
        "runtime",
        "downloads",
        ".env",
    }
    for name in filter(None, names):
        p = Path(name)
        assert not (set(p.parts) & forbidden), name
        assert (
            p.suffix not in {".sqlite", ".key", ".pyc"} and ".sqlite-" not in p.name
        ), name
        assert (ROOT / p).stat().st_size < 8 * 1024 * 1024, name
    print("Version, README, local Core bytes and tracked source inventory verified.")


if __name__ == "__main__":
    check()
