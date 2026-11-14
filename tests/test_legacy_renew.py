import importlib.util
from pathlib import Path
import unittest

s = importlib.util.spec_from_file_location(
    "legacy_renew", Path(__file__).resolve().parents[1] / "scripts/legacy_renew.py"
)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)


class RenewalPolicy(unittest.TestCase):
    def test_only_reviewed_unique_ids_are_allowed(self):
        self.assertEqual(m.policy({"schema": 1, "ids": ["abc123"]}), ["abc123"])
        for value in [
            {"schema": 1, "ids": []},
            {"schema": 1, "ids": ["../etc"]},
            {"schema": 1, "ids": ["abc", "abc"]},
            {"schema": 1, "ids": ["abc"], "command": "anything"},
        ]:
            with self.assertRaises(ValueError):
                m.policy(value)
