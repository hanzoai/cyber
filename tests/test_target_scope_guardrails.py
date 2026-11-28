from __future__ import annotations

import unittest
from ipaddress import ip_address, ip_network
import re


class TargetScopeGuard:
    """Enforces target-scope allowlist and denylist guardrails for OpenCyber MCP tools."""

    def __init__(self, allowlist: list[str], denylist: list[str] | None = None):
        self.allowlist = allowlist
        self.denylist = denylist or [
            "127.0.0.0/8",
            "169.254.0.0/16",
            "10.0.0.0/8",
            "192.168.0.0/16",
            "172.16.0.0/12",
            "::1/128",
            "localhost",
        ]

    def is_target_allowed(self, target: str) -> bool:
        # Strip scheme and port
        cleaned = re.sub(r"^https?://", "", target).split(":")[0].split("/")[0]

        # Check explicit denylist first
        if cleaned.lower() == "localhost":
            return False

        try:
            target_ip = ip_address(cleaned)
            for denied_net in self.denylist:
                try:
                    if target_ip in ip_network(denied_net):
                        return False
                except ValueError:
                    pass
        except ValueError:
            # Target is a hostname/domain
            for denied in self.denylist:
                if cleaned.lower() == denied.lower() or cleaned.lower().endswith("." + denied.lower()):
                    return False

        # Check allowlist
        for allowed in self.allowlist:
            if cleaned.lower() == allowed.lower():
                return True
            if allowed.startswith("*.") and cleaned.lower().endswith(allowed[1:].lower()):
                return True
            try:
                if ip_address(cleaned) in ip_network(allowed):
                    return True
            except ValueError:
                pass

        return False

    def validate_or_raise(self, target: str):
        if not self.is_target_allowed(target):
            raise PermissionError(f"Target '{target}' is out-of-scope and blocked by OpenCyber guardrails.")
        return True


class TestTargetScopeGuardrails(unittest.TestCase):

    def setUp(self):
        self.guard = TargetScopeGuard(
            allowlist=["scanme.nmap.org", "*.example-sandbox.org", "198.51.100.0/24"],
            denylist=["127.0.0.0/8", "169.254.0.0/16", "localhost", "internal.corp"],
        )

    def test_allowed_explicit_domain(self):
        self.assertTrue(self.guard.is_target_allowed("scanme.nmap.org"))
        self.assertTrue(self.guard.is_target_allowed("https://scanme.nmap.org:443/api"))

    def test_allowed_wildcard_subdomain(self):
        self.assertTrue(self.guard.is_target_allowed("app.example-sandbox.org"))
        self.assertTrue(self.guard.is_target_allowed("test.app.example-sandbox.org"))

    def test_allowed_ip_cidr(self):
        self.assertTrue(self.guard.is_target_allowed("198.51.100.42"))

    def test_blocked_localhost_and_loopback(self):
        self.assertFalse(self.guard.is_target_allowed("localhost"))
        self.assertFalse(self.guard.is_target_allowed("127.0.0.1"))
        self.assertFalse(self.guard.is_target_allowed("http://127.0.0.1:8080/exploit"))

    def test_blocked_cloud_metadata_address(self):
        self.assertFalse(self.guard.is_target_allowed("169.254.169.254"))

    def test_blocked_internal_denylisted_domain(self):
        self.assertFalse(self.guard.is_target_allowed("internal.corp"))
        self.assertFalse(self.guard.is_target_allowed("admin.internal.corp"))

    def test_blocked_unauthorized_external_target_raises_error(self):
        with self.assertRaises(PermissionError) as ctx:
            self.guard.validate_or_raise("unauthorized-victim.com")
        self.assertIn("blocked by OpenCyber guardrails", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
