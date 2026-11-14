import importlib.util
from pathlib import Path
import tempfile
import unittest
import types
import sys
from unittest.mock import patch

s = importlib.util.spec_from_file_location(
    "native", Path(__file__).resolve().parents[1] / "scripts/native_install.py"
)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)


class NativePreflight(unittest.TestCase):
    def test_partial_data_and_executable_installations_stop_before_any_mutation(self):
        for kind in ("controller", "agent", "executable"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                base = root / "base"
                exe = root / "libexec"
                target = exe if kind == "executable" else base / kind
                target.mkdir(parents=True)
                original = target / "existing"
                original.write_text("retained")
                with (
                    patch.object(m, "BASE", base),
                    patch.object(m, "EXEC", exe),
                    patch.object(m.os, "geteuid", return_value=0),
                    patch.object(m, "inspect", return_value={"ready_for_apply": True}),
                    patch.object(
                        m,
                        "atomic",
                        side_effect=AssertionError("Mutation before preflight"),
                    ),
                    patch.object(
                        m,
                        "command",
                        side_effect=AssertionError("Command before preflight"),
                    ),
                ):
                    with self.assertRaisesRegex(ValueError, "adoption/recovery"):
                        m.initialize({}, root)
                self.assertEqual(original.read_text(), "retained")

    def test_repeated_unchanged_inventory_does_not_invalidate_review(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            (root / "bin/kagnode-proxy-manager").write_bytes(b"fixture")
            secret = root / "password"
            secret.write_text("fictional-long-password")
            config = {
                "public_url": "https://pm.example.com",
                "fleet_url": "https://pm.example.com:9444",
                "email": "owner@example.com",
                "name": "Owner",
                "password_file": str(secret),
            }
            discovery = types.SimpleNamespace(
                discover=lambda **_: {"fingerprint": "a" * 64, "sampled": 1}
            )
            with (
                patch.dict(sys.modules, {"discover_config": discovery}),
                patch.object(m, "protected", side_effect=lambda path, **_: Path(path)),
                patch.object(
                    m.platform,
                    "freedesktop_os_release",
                    return_value={"ID": "ubuntu", "VERSION_ID": "24.04"},
                ),
                patch.object(m.platform, "machine", return_value="x86_64"),
                patch.object(
                    m.subprocess,
                    "run",
                    return_value=types.SimpleNamespace(stdout="install ok installed"),
                ),
            ):
                first = m.inspect(config, root)
                discovery.discover = lambda **_: {"fingerprint": "a" * 64, "sampled": 2}
                self.assertEqual(first, m.inspect(config, root))
