import importlib.util
from pathlib import Path
import tempfile
import unittest
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
