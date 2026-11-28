import unittest
from unittest.mock import patch
from opencyber.errors import OcError
from opencyber.policy import (
    canonical_http_url,
    credential_boundary_changed,
    enforcement_decision,
    target_matches,
)

class TargetScopeGuardrailTests(unittest.TestCase):
    def test_domain_and_subdomain_allowlist_blocks_suffix_spoofing(self) -> None:
        self.assertTrue(target_matches("example.com", "example.com"))
        self.assertTrue(target_matches("api.v2.example.com", "example.com"))
        self.assertTrue(target_matches("sub.example.com", "*.example.com"))
        self.assertFalse(target_matches("badexample.com", "example.com"))
        self.assertFalse(target_matches("example.com.evil.org", "example.com"))

    def test_cidr_ipv4_and_ipv6_scope_enforcement(self) -> None:
        self.assertTrue(target_matches("10.24.8.15", "10.24.0.0/16"))
        self.assertFalse(target_matches("10.25.0.1", "10.24.0.0/16"))
        self.assertTrue(target_matches("2001:db8::42", "2001:db8::/32"))
        self.assertFalse(target_matches("2001:db9::1", "2001:db8::/32"))
        self.assertFalse(target_matches("example.com", "10.24.0.0/16"))
    def test_ambiguous_url_authorities_are_refused(self) -> None:
        h1, h2 = "example.com", "evil.org"
        for bad in (f"https://{h1}@{h2}/p", f"https://{h1}\\{h2}/", f"https://{h1}%2f{h2}/", f"ftp://{h1}/f"):
            with self.subTest(url=bad):
                with self.assertRaises(OcError):
                    canonical_http_url(bad)

    def test_credential_boundary_drops_on_downgrade_or_host_change(self) -> None:
        h = "example.com"
        self.assertFalse(credential_boundary_changed(f"http://{h}/a", f"https://{h}/b"))
        self.assertTrue(credential_boundary_changed(f"https://{h}/a", f"http://{h}/a"))
        self.assertTrue(credential_boundary_changed(f"https://a.{h}", f"https://b.{h}"))

    def test_mixed_in_and_out_of_scope_arguments_are_blocked(self) -> None:
        fake_eng = {"id": "eng-1", "targets": ["example.com", "10.10.0.0/16"]}
        with patch("opencyber.policy.get_engagement", return_value=fake_eng):
            dec = enforcement_decision("eng-1", "nmap", ["-sV", "api.example.com", "198.51.100.9"])
        self.assertFalse(dec["allowed"])
        self.assertEqual(dec["denied"], ["198.51.100.9"])

if __name__ == "__main__":
    unittest.main()
