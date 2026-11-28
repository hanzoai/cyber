"""Tests for sandboxed OpenCyber MCP tool discovery and target-scope guardrails."""

from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
from opencyber.audit import read_audit
from opencyber.catalog import CATALOG, category_counts
from opencyber.contracts import contract_for
from opencyber.diagnostics import FIXED_MCP_TOOL_COUNT
from opencyber.errors import OcError
from opencyber.executor import execute_tool
from opencyber.policy import (
    canonical_http_url,
    enforce_scope,
    enforce_url_scope,
    enforcement_decision,
    scope_check,
    target_matches,
)
from opencyber.server import _registered_catalog, mcp, self_test


class McpStartupAndDiscoveryGuardrailTests(unittest.TestCase):
    """Verify clean MCP server startup, catalog alignment, and bounded discovery."""

    def test_clean_server_startup_and_self_test_catalog_alignment(self) -> None:
        with patch("opencyber.catalog.shutil.which", side_effect=lambda name: f"/usr/bin/{name}"):
            report = self_test()
        advertised_tools = asyncio.run(mcp.list_tools())
        advertised_names = [tool.name for tool in advertised_tools]

        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["missing_required_tools"], [])
        self.assertTrue(report["catalog"]["matches"])
        self.assertFalse(report["catalog"]["strict_mismatch"])
        self.assertEqual(report["catalog"]["unexpected_tools"], [])
        self.assertEqual(report["catalog"]["changed_tools"], [])
        self.assertEqual(len(advertised_names), len(CATALOG) + FIXED_MCP_TOOL_COUNT)
        self.assertEqual(len(advertised_names), len(set(advertised_names)))
        self.assertTrue(all(name.startswith("oc_") for name in advertised_names))

    def test_live_oc_catalog_discovery_filtering_and_pagination(self) -> None:
        unfiltered = asyncio.run(mcp.call_tool("oc_catalog", {})).structured_content
        self.assertTrue(unfiltered["ok"])
        self.assertTrue(unfiltered["catalog_matches_release"])
        self.assertEqual(unfiltered["external_tool_count"], len(CATALOG))
        self.assertEqual(unfiltered["returned_tool_count"], 0)

        exact = asyncio.run(
            mcp.call_tool("oc_catalog", {"name": "oc_scope_check", "include_contracts": True})
        ).structured_content
        self.assertTrue(exact["ok"])
        self.assertEqual(exact["matched_tool_count"], 1)
        self.assertEqual(exact["returned_tool_count"], 1)
        self.assertEqual(exact["tools"][0]["name"], "oc_scope_check")
        self.assertEqual(exact["tools"][0]["kind"], "native")
        self.assertIn("input_schema", exact["tools"][0])

        paged = asyncio.run(
            mcp.call_tool("oc_catalog", {"category": "network", "limit": 3, "offset": 0})
        ).structured_content
        self.assertTrue(paged["ok"])
        self.assertEqual(paged["returned_tool_count"], 3)
        self.assertGreater(paged["matched_tool_count"], 3)
        self.assertEqual(paged["coverage"]["status"], "partial")
        self.assertFalse(paged["coverage"]["exhausted"])
        self.assertEqual(paged["continuation"]["arguments"]["offset"], 3)
        self.assertTrue(all(entry["category"] == "network" for entry in paged["tools"]))

        ambiguous = asyncio.run(
            mcp.call_tool("oc_catalog", {"name": "oc_scope_check", "query": "scope"})
        ).structured_content
        self.assertFalse(ambiguous["ok"])
        self.assertEqual(ambiguous["error"]["code"], "invalid_argument")

    def test_registered_catalog_modes_compact_and_category_subset(self) -> None:
        counts = category_counts()
        self.assertIn("network", counts)
        self.assertIn("web", counts)

        with patch.dict("os.environ", {"OPENCYBER_MCP_MODE": "compact"}, clear=False):
            self.assertEqual(_registered_catalog(), ())

        with patch.dict(
            "os.environ",
            {"OPENCYBER_MCP_MODE": "full", "OPENCYBER_TOOL_CATEGORIES": "network,web"},
            clear=False,
        ):
            subset = _registered_catalog()
            self.assertEqual(len(subset), counts["network"] + counts["web"])
            self.assertTrue(all(spec.category in {"network", "web"} for spec in subset))

        with patch.dict(
            "os.environ",
            {"OPENCYBER_MCP_MODE": "full", "OPENCYBER_TOOL_CATEGORIES": "nonexistent_category"},
            clear=False,
        ):
            with self.assertRaises(ValueError):
                _registered_catalog()


class TargetScopeAllowlistDenylistTests(unittest.TestCase):
    """Validate engagement allowlist matches and fail-closed denylist boundaries."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        workspace = patch.object(engagements, "WORKSPACE", Path(self.temporary.name).resolve())
        workspace.start()
        self.addCleanup(workspace.stop)
        self.engagement = engagements.create_engagement(
            "Guardrail Scope",
            ["10.20.30.0/24", "corp.example", "*.staging.test", "192.0.2.44"],
        )
        self.engagement_id = self.engagement["engagement_id"]

    def test_allowlist_matches_cidr_exact_ip_apex_and_subdomains(self) -> None:
        allowed_cases = (
            ("10.20.30.1", "10.20.30.0/24"),
            ("10.20.30.254", "10.20.30.0/24"),
            ("192.0.2.44", "192.0.2.44"),
            ("corp.example", "corp.example"),
            ("api.corp.example", "corp.example"),
            ("https://portal.corp.example:8443/login", "corp.example"),
            ("qa.staging.test", "*.staging.test"),
        )
        for host, target in allowed_cases:
            with self.subTest(host=host, target=target):
                self.assertTrue(target_matches(host, target))
                self.assertTrue(scope_check(self.engagement_id, host)["allowed"])

    def test_denylist_blocks_adjacent_ips_suffix_spoofs_and_type_mismatches(self) -> None:
        denied_values = (
            "10.20.31.1",
            "192.0.2.45",
            "1.1.1.1",
            "evilcorp.example",
            "corp.example.attacker.tld",
            "otherstaging.test",
            "staging.test.evil.org",
            "https://evilcorp.example/v1",
        )
        for value in denied_values:
            with self.subTest(value=value):
                check = scope_check(self.engagement_id, value)
                self.assertFalse(check["allowed"])
                self.assertIsNone(check["matched_target"])

        self.assertFalse(target_matches("10.20.30.5", "corp.example"))
        self.assertFalse(target_matches("corp.example", "10.20.30.0/24"))

    def test_ambiguous_http_url_authorities_are_rejected_fail_closed(self) -> None:
        bad_urls = (
            "https://corp.example@evil.test/",
            "https://evil.test\\@corp.example/",
            "https://evil.test%2f@corp.example/",
            "ftp://corp.example/file",
            "https:///missing-host",
        )
        for bad_url in bad_urls:
            with self.subTest(url=bad_url):
                with self.assertRaises(OcError) as exc_info:
                    canonical_http_url(bad_url)
                self.assertEqual(exc_info.exception.code, "invalid_argument")

                with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"}):
                    with self.assertRaises(OcError) as url_exc:
                        enforce_url_scope(self.engagement_id, bad_url, tool="oc_http_request")
                    self.assertEqual(url_exc.exception.code, "invalid_argument")

    def test_enforce_scope_blocks_mixed_out_of_scope_targets_and_unscoped_shells(self) -> None:
        with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"}):
            with self.assertRaises(OcError) as mixed_exc:
                enforce_scope(self.engagement_id, "nmap", ["-sV", "10.20.30.5", "198.51.100.9"])
            self.assertEqual(mixed_exc.exception.code, "scope_denied")
            self.assertIn("198.51.100.9", mixed_exc.exception.details["denied"])
            self.assertNotIn("10.20.30.5", mixed_exc.exception.details["denied"])

            for shell_exec in ("bash", "python3"):
                with self.subTest(executable=shell_exec):
                    with self.assertRaises(OcError) as shell_exc:
                        enforce_scope(self.engagement_id, shell_exec, ["-c", "echo ok"])
                    self.assertEqual(shell_exc.exception.code, "scope_denied")

            with patch.dict("os.environ", {"OPENCYBER_ALLOW_UNSCOPED_EXECUTION": "1"}):
                decision = enforcement_decision(self.engagement_id, "bash", ["-c", "echo ok"])
                self.assertTrue(decision["allowed"])

            with self.assertRaises(OcError) as eng_exc:
                enforce_url_scope(None, "https://api.corp.example/health", tool="oc_http_request")
            self.assertEqual(eng_exc.exception.code, "engagement_required")


class LiveMcpDryRunAndScopeRefusalTests(unittest.TestCase):
    """Exercise MCP dry-run and fail-closed refusal without spawning child I/O."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        workspace = patch.object(engagements, "WORKSPACE", Path(self.temporary.name).resolve())
        workspace.start()
        self.addCleanup(workspace.stop)
        self.engagement = engagements.create_engagement("MCP Scope", ["10.20.30.0/24", "corp.example"])
        self.engagement_id = self.engagement["engagement_id"]
        self.enforce = patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"})
        self.enforce.start()
        self.addCleanup(self.enforce.stop)

    def test_oc_scope_check_dry_run_never_spawns_subprocess(self) -> None:
        with patch("asyncio.create_subprocess_exec") as spawn:
            in_scope = asyncio.run(
                mcp.call_tool(
                    "oc_scope_check",
                    {"engagement_id": self.engagement_id, "value": "https://api.corp.example/status"},
                )
            ).structured_content
            out_scope = asyncio.run(
                mcp.call_tool(
                    "oc_scope_check",
                    {"engagement_id": self.engagement_id, "value": "https://outside.invalid/status"},
                )
            ).structured_content
            proposed_exec = asyncio.run(
                mcp.call_tool(
                    "oc_scope_check",
                    {
                        "engagement_id": self.engagement_id,
                        "executable": "nmap",
                        "arguments": ["-sT", "10.20.30.10", "evil.example"],
                    },
                )
            ).structured_content

        spawn.assert_not_called()
        self.assertTrue(in_scope["ok"])
        self.assertTrue(in_scope["allowed"])
        self.assertTrue(out_scope["ok"])
        self.assertFalse(out_scope["allowed"])
        self.assertTrue(proposed_exec["ok"])
        self.assertTrue(proposed_exec["enforced"])
        self.assertFalse(proposed_exec["allowed"])
        self.assertEqual(proposed_exec["denied"], ["evil.example"])

    def test_live_mcp_refuses_out_of_scope_calls_and_records_denial(self) -> None:
        refusal_cases = (
            ("oc_nmap", {"engagement_id": self.engagement_id, "arguments": ["198.51.100.77", "-sT"]}, "scope_denied"),
            (
                "oc_execute",
                {"tool": "oc_curl", "engagement_id": self.engagement_id, "arguments": ["https://attacker.invalid/"]},
                "scope_denied",
            ),
            ("oc_bash", {"engagement_id": self.engagement_id, "script": "whoami"}, "scope_denied"),
            (
                "oc_http_request",
                {"method": "GET", "url": "https://attacker.invalid/", "engagement_id": self.engagement_id},
                "scope_denied",
            ),
            (
                "oc_http_request",
                {"method": "GET", "url": "https://corp.example/", "engagement_id": None},
                "engagement_required",
            ),
            (
                "oc_graphql_request",
                {
                    "url": "https://attacker.invalid/graphql",
                    "query": "{ __typename }",
                    "engagement_id": self.engagement_id,
                },
                "scope_denied",
            ),
        )
        with (
            patch("asyncio.create_subprocess_exec") as spawn,
            patch("requests.request") as req_request,
            patch("requests.post") as req_post,
        ):
            for tool_name, arguments, expected_code in refusal_cases:
                with self.subTest(tool=tool_name, expected=expected_code):
                    result = asyncio.run(mcp.call_tool(tool_name, arguments)).structured_content
                    self.assertFalse(result["ok"])
                    self.assertEqual(result["error"]["code"], expected_code)
                    self.assertIn(expected_code, contract_for(tool_name).error_codes)

        spawn.assert_not_called()
        req_request.assert_not_called()
        req_post.assert_not_called()

        audit_events = [entry["event"] for entry in read_audit(self.engagement_id, limit=50)["events"]]
        self.assertIn("tool.denied", audit_events)

    def test_live_in_scope_probe_succeeds_under_enforcement(self) -> None:
        result = asyncio.run(
            execute_tool(
                "printf",
                ["https://api.corp.example/health"],
                engagement_id=self.engagement_id,
            )
        )
        self.assertTrue(result["success"])
        self.assertTrue(result["scope_enforced"])
        self.assertEqual(result["stdout"], "https://api.corp.example/health")
        audit_events = [entry["event"] for entry in read_audit(self.engagement_id, limit=50)["events"]]
        self.assertIn("tool.scope_checked", audit_events)


if __name__ == "__main__":
    unittest.main()
