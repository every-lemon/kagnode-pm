import importlib.util
from pathlib import Path
import tempfile
import json
import unittest
from unittest.mock import patch

s = importlib.util.spec_from_file_location(
    "discovery", Path(__file__).resolve().parents[1] / "scripts/discover_config.py"
)
m = importlib.util.module_from_spec(s)
s.loader.exec_module(m)


class Discovery(unittest.TestCase):
    def test_read_only_inventory_detects_change_and_never_exposes_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "site.conf"
            original = b"server { listen 80; server_name site.example.com; auth_basic_user_file /private/SECRET; location / { proxy_pass http://127.0.0.1:8080; } }\n"
            path.write_bytes(original)
            roots = {"nginx": [tmp]}
            report = m.discover(roots, False)
            self.assertEqual(path.read_bytes(), original)
            self.assertNotIn("SECRET", str(report))
            self.assertFalse(report["files"][0]["sites"][0]["supported"])
            before = report["fingerprint"]
            path.write_bytes(original + b"# change\n")
            self.assertNotEqual(before, m.discover(roots, False)["fingerprint"])

    def test_simple_nginx_and_all_engine_inventory(self):
        self.assertFalse(
            m.nginx_sites(
                "server { listen 80; server_name site.example.com; location / { proxy_pass http://127.0.0.1:8080; } }"
            )[0]["blockers"]
        )
        self.assertEqual(
            m.caddy_sites(
                "http://site.example.com {\n reverse_proxy 127.0.0.1:8080\n}"
            )[0]["resource"]["kind"],
            "proxy_host",
        )
        self.assertEqual(
            m.apache_sites(
                "<VirtualHost *:80>\nServerName site.example.com\nProxyRequests Off\nProxyPass / http://127.0.0.1:8080/\n</VirtualHost>"
            )[0]["resource"]["kind"],
            "proxy_host",
        )
        self.assertTrue(m.haproxy_sites("frontend public\n bind :80")[0]["blockers"])
        doc = {
            "http": {
                "routers": {"r": {"rule": "Host(`site.example.com`)", "service": "s"}},
                "services": {
                    "s": {
                        "loadBalancer": {"servers": [{"url": "http://127.0.0.1:8080"}]}
                    }
                },
            }
        }
        self.assertTrue(m.traefik_sites(json.dumps(doc), ".json")[0]["resource"])

    def test_unsupported_and_symlinks_cannot_be_silently_adopted(self):
        for source in [
            "server { server_name site.example.com; include /private/access.conf; location / { proxy_pass http://127.0.0.1:80; } }",
            "server {server_name site.example.com; location / {proxy_pass http://user:SECRET@127.0.0.1:80;}}",
        ]:
            site = m.nginx_sites(source)[0]
            self.assertTrue(site["blockers"])
            self.assertNotIn("SECRET", str(site))
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "loop.conf").symlink_to("/etc/passwd")
            self.assertEqual(m.discover({"nginx": [tmp]}, False)["files"], [])

    def test_review_rechecks_source_and_blocks_partial_inventory(self):
        report = {
            "fingerprint": "a" * 64,
            "warnings": [],
            "files": [
                {
                    "sites": [
                        {
                            "id": "one",
                            "supported": True,
                            "resource": {"kind": "proxy_host"},
                        }
                    ]
                }
            ],
        }
        with patch.object(m, "discover", return_value=report):
            self.assertFalse(
                m.review({"fingerprint": "a" * 64, "selected": ["one"]})[
                    "traffic_changed"
                ]
            )
            for request in [
                {"fingerprint": "b" * 64, "selected": ["one"]},
                {"fingerprint": "a" * 64, "selected": ["missing"]},
                {"fingerprint": "a" * 64, "selected": ["one", "one"]},
            ]:
                with self.assertRaises(ValueError):
                    m.review(request)
