import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "package_worker",
    Path(__file__).resolve().parents[1] / "scripts/package_transaction.py",
)
WORKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WORKER)


class PackageBoundaries(unittest.TestCase):
    def test_package_names_are_not_commands_or_options(self):
        for name in [
            "--allow-remove-essential",
            "../file.deb",
            "foo;true",
            "foo\nbar",
            "$(id)",
            "foo=1",
        ]:
            self.assertIsNone(WORKER.NAME.fullmatch(name))
        self.assertIsNotNone(WORKER.NAME.fullmatch("optional-lib:amd64"))

    def test_host_access_and_proxy_dependencies_are_protected(self):
        for name in [
            "openssh-server",
            "systemd-resolved",
            "linux-image-generic",
            "nginx-core",
            "3proxy",
            "python3-apt",
            "kagnode-proxy-manager",
        ]:
            self.assertTrue(
                name.startswith(WORKER.CORE_PREFIXES) or name in WORKER.CORE_NAMES
            )

    def test_worker_has_no_purge_autoremove_or_shell_execution(self):
        source = Path(WORKER.__file__).read_text()
        self.assertNotIn("shell=True", source)
        self.assertIn("purge=False", source)
        self.assertIn("with apt_pkg.SystemLock():", source)
        self.assertIn("fingerprint != plan", source)


if __name__ == "__main__":
    unittest.main()


class MergedUsrOwnership(unittest.TestCase):
    def test_merged_usr_aliases_resolve_to_the_same_file(self):
        # Both accepted names must refer to the same actual inode target.
        if Path("/bin/true").resolve() != Path("/usr/bin/true").resolve():
            self.skipTest("Distribution does not use merged /usr")
        self.assertIn("/bin/true", WORKER.ownership_paths("/usr/bin/true"))
        self.assertIn("/usr/bin/true", WORKER.ownership_paths("/bin/true"))
