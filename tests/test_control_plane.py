"""Hermetic tests for the independent control plane.

No network, no browser, no real engagement: an in-memory SQLite backend plus a
scripted LLM and toolbox exercise the same functions the API and MCP tools use.
"""

from __future__ import annotations

import asyncio
import json
import os
import unittest

from opencyber.control import engine, findings, graph, intercept, platform, traffic
from opencyber.control.intercept import parse_simple_argv
from opencyber.control.api import Console, build_routes, create_app
from opencyber.control.governor import PROFILES, Governor, low_and_slow_flags, reset_governor
from opencyber.control.store import SQLiteBackend, Store, reset_store
from starlette.applications import Starlette


ENG = "eng_test"


def make_store() -> Store:
    return Store(SQLiteBackend(":memory:"))


def new_task(store: Store, goal: str = "find a proof") -> dict:
    return engine.create_task(store, ENG, goal, name="test", scope=["example.test"])


class ScriptedLLM:
    def __init__(self, replies: list[engine.Reply]) -> None:
        self.replies = list(replies)
        self.calls: list[list[dict]] = []

    def chat(self, messages, tools=None, *, profile=None):
        self.calls.append(messages)
        if not self.replies:
            return engine.Reply(text='{"intents":[],"goal_met":false,"reasoning":"empty"}', usage={"input_tokens": 1, "output_tokens": 1})
        return self.replies.pop(0)


class RecordingToolbox:
    def __init__(self, allowed: set[str] | None = None) -> None:
        self.allowed = allowed or {"http_request"}
        self.calls: list[tuple[str, dict]] = []

    def specs(self):
        return [{"type": "function", "function": {"name": name, "parameters": {"type": "object", "properties": {}}}} for name in self.allowed]

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        return {"ok": True, "tool": name, "body": "Admin Login form"}


class StoreTests(unittest.TestCase):
    def test_crud_filter_and_order(self):
        store = make_store()
        ids = [store.create("assets", engagement_id=ENG, kind="subdomain", value=f"h{i}.example.test")["id"] for i in range(3)]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(record_id.startswith("ast_") for record_id in ids))
        self.assertEqual(len(store.list("assets", {"engagement_id": ENG})), 3)
        self.assertEqual(store.list("assets", {"value": "h1.example.test"})[0]["id"], ids[1])
        store.update("assets", ids[0], value="changed.example.test")
        self.assertEqual(store.get("assets", ids[0])["value"], "changed.example.test")
        self.assertEqual(store.delete_where("assets", {"kind": "subdomain"}), 3)
        self.assertEqual(store.count("assets"), 0)

    def test_events_and_provenance(self):
        store = make_store()
        event = store.event(ENG, "tsk_x", "operator.message", "hint", key="value")
        self.assertEqual(event["kind"], "operator.message")
        self.assertEqual(event["payload"]["key"], "value")
        self.assertEqual(store.list("events", {"task_id": "tsk_x"})[0]["id"], event["id"])

    def test_reset_store_helper(self):
        store = make_store()
        reset_store(store)
        try:
            from opencyber.control.store import open_store

            self.assertIs(open_store(), store)
        finally:
            reset_store()


class GovernorTests(unittest.TestCase):
    def tearDown(self):
        reset_governor()

    def test_profiles_and_slot_observation(self):
        now = [0.0]
        slept: list[float] = []
        gov = Governor(PROFILES["quiet"], clock=lambda: now[0], sleep=slept.append, random_source=lambda: 0.5)
        with gov.slot("https://example.test/a") as decision:
            self.assertTrue(decision["governed"])
            self.assertEqual(decision["profile"], "quiet")
        gov.observe("https://example.test/a", 429)
        stats = gov.stats()
        self.assertEqual(stats["hosts"]["example.test"]["strikes"], 1)
        self.assertGreater(stats["hosts"]["example.test"]["backoff_seconds"], 0)

    def test_off_profile_is_transparent(self):
        gov = Governor(PROFILES["off"])
        with gov.slot("https://example.test/") as decision:
            self.assertFalse(decision["governed"])
        self.assertFalse(low_and_slow_flags(PROFILES["off"]))


class GraphTests(unittest.TestCase):
    def test_asset_dedup_containment_and_anchor(self):
        store = make_store()
        task = new_task(store)
        root, created = graph.upsert_asset(store, ENG, "root_domain", "example.test")
        self.assertTrue(created)
        again, created = graph.upsert_asset(store, ENG, "root_domain", "example.test", None, {"source": "worker"})
        self.assertFalse(created)
        self.assertEqual(root["id"], again["id"])
        child, _ = graph.upsert_asset(store, ENG, "subdomain", "api.example.test", root["id"])
        node = graph.add_node(store, ENG, task["id"], "intent", "check api", source="test")
        graph.anchor(store, task["id"], node["id"], child["id"])
        tree = graph.asset_tree(store, ENG)
        self.assertEqual(tree["total"], 2)
        self.assertEqual(tree["roots"][0]["children"][0]["value"], "api.example.test")
        coverage = graph.coverage(store, ENG, task["id"])
        self.assertEqual(coverage["tested"], 1)
        self.assertIn("not proof", coverage["caveat"])
        self.assertEqual(len(graph.assets_for_task(store, task["id"])), 1)

    def test_exploration_graph_and_lineage(self):
        store = make_store()
        task = new_task(store)
        goal = graph.add_node(store, ENG, task["id"], "goal", task["goal"], source="system")
        intent = graph.add_node(store, ENG, task["id"], "intent", "probe", source="planner")
        fact = graph.add_node(store, ENG, task["id"], "fact", "panel found", source="worker")
        graph.add_edge(store, task["id"], goal["id"], intent["id"], "spawns")
        graph.add_edge(store, task["id"], intent["id"], fact["id"], "yields")
        snapshot = graph.exploration_graph(store, task["id"])
        self.assertEqual(snapshot["counts"]["nodes"], 4)
        self.assertEqual(len(snapshot["edges"]), 2)
        lineage = graph.lineage(store, task["id"], intent["id"])
        self.assertEqual(lineage["upstream"][0]["node"]["kind"], "goal")
        self.assertEqual(lineage["downstream"][0]["node"]["kind"], "fact")


class InterceptTests(unittest.TestCase):
    def test_wrapper_set_matches_the_published_contract(self):
        from opencyber.control.intercept import _WRAPPERS

        self.assertEqual(len(_WRAPPERS), 27)
        self.assertIsNone(parse_simple_argv("runuser -u root nmap example.test"))

    def test_rules_string_regex_and_argv(self):
        store = make_store()
        intercept.set_default_policy(store, ENG, "ask")
        intercept.add_rule(store, ENG, "ask nmap", target="tool_name", kind="string", pattern="nmap", policy="ask")
        intercept.add_rule(store, ENG, "block rm", target="tool_input", kind="argv", pattern='["rm", "-rf"]', policy="block", priority=10)
        decision = intercept.evaluate(store, ENG, "nmap", {"tool_input": "nmap -sV example.test"})
        self.assertEqual(decision["policy"], "ask")
        decision = intercept.evaluate(store, ENG, "oc_bash", {"script": "rm -rf /tmp/x"})
        self.assertEqual(decision["policy"], "block")
        self.assertEqual(intercept.default_policy(store, ENG), "ask")

    def test_approval_decision_persists_and_always_allow(self):
        store = make_store()
        approval = store.create("approvals", engagement_id=ENG, task_id="tsk_x", tool="oc_bash", arguments={"script": "nmap -sV example.test"}, status="pending")
        record = intercept.decide(store, approval["id"], True, decided_by="human", reason="ok")
        self.assertEqual(record["status"], "approved")
        self.assertEqual(intercept.pending(store, ENG), [])
        prefix = intercept.always_allow_prefix("nmap -sV example.test", 2)
        self.assertEqual(prefix, '["nmap", "-sV"]')
        rule = intercept.add_rule(store, ENG, "allow nmap", target="tool_input", kind="argv", pattern=prefix, policy="allow")
        self.assertEqual(rule["policy"], "allow")

    def test_blocklist_covers_cidr_and_fuzzy_domain(self):
        store = make_store()
        intercept.add_blocked_target(store, ENG, "cidr", "10.0.0.0/8")
        intercept.add_blocked_target(store, ENG, "fuzzy_domain", "internal.example")
        self.assertIsNotNone(intercept.blocked_target(store, ENG, "10.1.2.3", "https://10.1.2.3/x"))
        self.assertIsNotNone(intercept.blocked_target(store, ENG, "a.internal.example", "https://a.internal.example/"))
        self.assertIsNone(intercept.blocked_target(store, ENG, "example.test", "https://example.test/"))


class TrafficTests(unittest.TestCase):
    def test_record_ingest_filters_and_truncation(self):
        store = make_store()
        first = traffic.record(store, ENG, method="get", url="http://example.test/admin", status=200, response_body="Admin Login", tags=["tsk_x"])
        self.assertEqual(first["method"], "GET")
        result = traffic.ingest(store, ENG, [
            {"method": "POST", "url": "http://example.test/login", "status": 401, "response_body": "denied"},
            {"method": "BAD"},
        ])
        self.assertEqual(result["stored"], 1)
        self.assertEqual(result["failed"], 1)
        rows = traffic.list_exchanges(store, ENG, host="example.test", search="admin")
        self.assertEqual(rows["total"], 1)
        self.assertEqual(traffic.hosts(store, ENG)[0]["host"], "example.test")
        self.assertEqual(traffic.get_exchange(store, first["id"])["response_body"]["text"], "Admin Login")
        traffic.delete_exchange(store, first["id"])
        self.assertEqual(traffic.list_exchanges(store, ENG)["total"], 1)

    def test_har_round_trip_and_body_contains(self):
        store = make_store()
        traffic.record(store, ENG, method="GET", url="http://example.test/a", status=200, response_body="needle-value")
        document = traffic.export_har(store, ENG)
        self.assertEqual(len(document["log"]["entries"]), 1)
        text = traffic.har_json(document)
        imported = traffic.import_har(store, ENG, json.loads(text))
        self.assertEqual(imported["imported"], 1)
        self.assertEqual(traffic.list_exchanges(store, ENG, body_contains="needle")["total"], 2)


class FindingsTests(unittest.TestCase):
    def test_verification_requires_bound_traffic_and_verbatim_quote(self):
        store = make_store()
        finding = findings.create(store, ENG, "tsk_x", "Exposed panel", severity="high", evidence="Admin Login")
        blocked = findings.verify(store, finding["id"], quotes=["Admin Login"])
        self.assertEqual(blocked["verification"], "blocked")
        exchange = traffic.record(store, ENG, method="GET", url="http://example.test/admin", status=200, response_body="Admin Login form")
        result = findings.verify(store, finding["id"], quotes=["Admin Login"], proof_exchange_ids=[exchange["id"]])
        self.assertEqual(result["verification"], "verified")
        bad = findings.verify(store, finding["id"], quotes=["not present"], proof_exchange_ids=[exchange["id"]])
        self.assertEqual(bad["verification"], "blocked")
        self.assertEqual(bad["missing_quotes"], ["not present"])

    def test_retest_and_export(self):
        store = make_store()
        finding = findings.create(store, ENG, "tsk_x", "Open redirect", severity="medium", detail="details")
        retest = findings.start_retest(store, finding["id"], "recheck")
        done = findings.complete_retest(store, retest["id"], verdict="fixed", summary="patched", evidence="200")
        self.assertEqual(done["verdict"], "fixed")
        self.assertEqual(len(findings.retests_for(store, finding["id"])), 1)
        content, media, name = findings.export_findings(store, [finding], "csv")
        self.assertIn(b"Open redirect", content)
        self.assertEqual(media, "text/csv")
        zipped, media, name = findings.export_findings(store, [finding], "zip")
        self.assertTrue(name.endswith(".zip"))
        self.assertEqual(zipped[:2], b"PK")

    def test_bulk_status_and_deepen(self):
        store = make_store()
        first = findings.create(store, ENG, "tsk_x", "One", severity="low")
        second = findings.create(store, ENG, "tsk_x", "Two", severity="low")
        updated = findings.bulk_status(store, [first["id"], second["id"]], "triage", "resolved")
        self.assertEqual(len(updated["updated"]), 2)
        intent = findings.deepen(store, first["id"], "prove impact")
        self.assertEqual(intent["status"], "proposed")
        self.assertEqual(store.list("intents", {"task_id": "tsk_x"})[0]["instruction"], "prove impact")


class PlatformTests(unittest.TestCase):
    def test_profiles_usage_and_settings(self):
        store = make_store()
        profile = platform.create_profile(store, "p1", model="test-model", provider="hanzo", rate_per_minute=60)
        self.assertTrue(platform.usable(store))
        platform.activate(store, profile["id"])
        self.assertTrue(store.get("models", profile["id"])["active"])
        platform.account(store, ENG, "tsk_x", profile=profile, model="test-model", input_tokens=10, output_tokens=5)
        summary = platform.usage_summary(store, task_id="tsk_x")
        self.assertEqual(summary["total_tokens"], 15)
        self.assertEqual(len(summary["by_model"]), 1)
        platform.set_setting(store, "worker_concurrency", 4, ENG)
        self.assertEqual(platform.get_setting(store, "worker_concurrency", 2, ENG), 4)

    def test_notification_digest_and_retry(self):
        store = make_store()
        platform.create_channel(store, "console", "generic", {"url": "http://127.0.0.1:9/x"}, min_severity="low")
        finding = {"id": "fnd_1", "task_id": "tsk_x", "title": "t", "severity": "high", "summary": "s", "vulnerability": "v"}
        def failing(url, payload):
            raise OSError("offline")
        result = platform.dispatch(store, finding, send=failing)
        self.assertGreater(result["queued"], 0)
        retried = platform.retry_failed(store)
        self.assertIn("retried", retried)


class EngineTests(unittest.TestCase):
    def test_task_lifecycle_and_budget(self):
        store = make_store()
        task = new_task(store)
        self.assertEqual(task["status"], "created")
        engine.start(store, task["id"])
        self.assertEqual(store.require("tasks", task["id"])["status"], "running")
        engine.pause(store, task["id"])
        self.assertEqual(store.require("tasks", task["id"])["status"], "paused")
        engine.resume(store, task["id"])
        engine.stop(store, task["id"], "operator")
        self.assertEqual(store.require("tasks", task["id"])["status"], "completed")
        self.assertEqual(engine.budget_left(task)["tokens"], task["budgets"]["tokens"])

    def test_planner_dispatches_intent_and_worker_executes_tool(self):
        store = make_store()
        task = new_task(store)
        engine.start(store, task["id"])
        llm = ScriptedLLM([
            engine.Reply(text=json.dumps({"intents": [{"title": "check /admin", "instruction": "GET /admin", "assets": []}], "goal_met": False, "reasoning": "r"}), usage={"input_tokens": 10, "output_tokens": 5}),
            engine.Reply(text=json.dumps({"summary": "panel found"}), tool_calls=[{"id": "call_1", "name": "http_request", "arguments": {"method": "GET", "url": "http://example.test/admin"}}], usage={"input_tokens": 10, "output_tokens": 5}),
        ])
        toolbox = RecordingToolbox()
        control = engine.Engine(store, llm, toolbox_factory=lambda *_: toolbox, max_workers=1)
        first = control.step(task["id"])
        self.assertEqual(first["planner"]["intents"], 1)
        second = control.step(task["id"])
        self.assertIn("workers", second)
        self.assertEqual(toolbox.calls[0][0], "http_request")
        self.assertEqual(store.count("intents", {"task_id": task["id"]}), 1)
        self.assertGreater(store.count("usage", {"task_id": task["id"]}), 0)

    def test_toolbox_gates_every_call_before_execution(self):
        store = make_store()
        task = new_task(store)
        toolbox = engine.NativeToolbox(store, ENG, task["id"])
        intercept.add_rule(store, ENG, "block http", target="tool_name", kind="string", pattern="http_request", policy="block")
        result = toolbox.call("http_request", {"url": "http://example.test/"})
        self.assertEqual(result["error"], "blocked")
        executions = store.list("executions", {"task_id": task["id"]})
        self.assertEqual(executions[0]["status"], "denied")
        self.assertTrue(executions[0]["approval_id"])


async def asgi_get(app: Starlette, path: str, headers: list[tuple[bytes, bytes]] | None = None, *, method: str = "GET", body: dict | None = None) -> tuple[int, dict]:
    payload = json.dumps(body).encode() if body is not None else b""
    if body is not None:
        headers = list(headers or []) + [(b"content-type", b"application/json")]
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path, "raw_path": path.encode(),
        "query_string": b"", "root_path": "", "headers": headers or [],
        "client": ("127.0.0.1", 1234), "server": ("testserver", 80),
    }
    captured: dict = {"status": 0, "body": b""}

    async def receive():
        return {"type": "http.request", "body": payload, "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]
        elif message["type"] == "http.response.body":
            captured["body"] += message.get("body", b"")

    await app(scope, receive, send)
    return captured["status"], json.loads(captured["body"] or b"{}")


class FakePlatform:
    base_url = "https://platform.hanzo.ai"
    token = "test-token"

    def __init__(self) -> None:
        self.spec: dict | None = None
        self.calls: list[str] = []

    def run(self, spec):
        self.calls.append("run")
        self.spec = spec
        return {"id": "app_1", "name": spec["name"], "url": "https://oc.example.hanzo.ai", "status": "deploying"}

    def app(self, name, project="default"):
        self.calls.append("app")
        return {"name": name, "status": "running"}

    def deployments(self, name, project="default"):
        self.calls.append("deployments")
        return {"deployments": [{"id": "dep_1"}]}

    def logs(self, name, deployment, project="default"):
        self.calls.append("logs")
        return {"logs": ["line one", "line two"], "source": "platform"}

    def stop(self, name, project="default"):
        self.calls.append("stop")
        return {"status": "stopped"}


class ChatTests(unittest.TestCase):
    def test_chat_runs_through_the_llm_and_persists_both_sides(self):
        store = make_store()
        task = new_task(store)
        llm = ScriptedLLM([engine.Reply(text="The task is queued with one open direction.", usage={"input_tokens": 8, "output_tokens": 4})])
        console = Console(store, llm=llm, token="secret")
        app = Starlette(routes=build_routes(console))
        status, body = asyncio.run(asgi_get(app, "/chat", [(b"authorization", b"Bearer secret")], method="POST", body={"task_id": task["id"], "message": "What is the status?"}))
        self.assertEqual(status, 201, body)
        self.assertEqual(body["reply"]["role"], "assistant")
        self.assertEqual(body["operator"]["role"], "operator")
        messages = store.list("messages", {"task_id": task["id"]})
        self.assertEqual({item["role"] for item in messages}, {"operator", "assistant"})
        assistant = next(item for item in messages if item["role"] == "assistant")
        self.assertEqual(assistant["content"], "The task is queued with one open direction.")
        self.assertIn("Engagement state", llm.calls[0][1]["content"])
        self.assertNotIn("What is the status?", llm.calls[0][1]["content"])


class CloudLaunchTests(unittest.TestCase):
    def test_launch_seals_tokens_and_never_persists_them(self):
        store = make_store()
        platform_client = FakePlatform()
        console = Console(store, platform_client=platform_client, token="")
        app = Starlette(routes=build_routes(console))
        status, body = asyncio.run(asgi_get(app, "/cloud/launch", method="POST", body={"name": "oc-pentest-01", "profile": "agentic-pentest"}))
        self.assertEqual(status, 201, body)
        self.assertTrue(body["control_token_once"])
        self.assertEqual(body["launch"]["status"], "deploying")
        env = {entry["key"]: entry for entry in platform_client.spec["env"]}
        self.assertTrue(env["OPENCYBER_CONTROL_TOKEN"]["secret"])
        self.assertEqual(env["OPENCYBER_CONTROL_TOKEN"]["value"], body["control_token_once"])
        self.assertEqual(env["OPENCYBER_ENGAGEMENT_ID"]["value"], "")
        self.assertNotIn("control_token_once", store.list("settings", {"kind": "cloud_launch"})[0])
        self.assertNotIn("OPENCYBER_CONTROL_TOKEN", json.dumps(store.list("settings", {"kind": "cloud_launch"})))

        status, body = asyncio.run(asgi_get(app, "/cloud/launches"))
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        launch_id = body["launches"][0]["id"]
        for suffix, expected in (("/status", "running"), ("/logs", "line one"), ("/stop", "stopped")):
            with self.subTest(suffix=suffix):
                status, result = asyncio.run(asgi_get(app, f"/cloud/launches/{launch_id}{suffix}", method="GET" if suffix != "/stop" else "POST", body={} if suffix == "/stop" else None))
                self.assertEqual(status, 200)
                if suffix == "/status":
                    self.assertEqual(result["launch"]["status"], expected)
                if suffix == "/logs":
                    self.assertIn(expected, result["logs"])
                if suffix == "/stop":
                    self.assertEqual(result["launch"]["status"], expected)

    def test_invalid_launch_is_refused_before_platform_call(self):
        store = make_store()
        platform_client = FakePlatform()
        app = Starlette(routes=build_routes(Console(store, platform_client=platform_client, token="")))
        status, body = asyncio.run(asgi_get(app, "/cloud/launch", method="POST", body={"name": "Bad Name", "profile": "agentic-pentest"}))
        self.assertEqual(status, 400)
        self.assertEqual(platform_client.calls, [])


class WiringTests(unittest.TestCase):
    def test_iam_local_and_kms_env_resolution(self):
        from opencyber.control.wiring import IAMVerifier, KMSResolver, Principal

        iam = IAMVerifier(token="secret", org="demo", user="demo@hanzo.ai")
        self.assertEqual(iam.verify("secret"), Principal(org="demo", user="demo@hanzo.ai"))
        self.assertIsNone(iam.verify("wrong"))
        resolver = KMSResolver()
        os.environ["TEST_WIRING_KEY"] = "value"
        self.assertEqual(resolver.resolve("env:TEST_WIRING_KEY"), "value")
        os.environ.pop("TEST_WIRING_KEY", None)

    def test_sandbox_adapter_and_wiring_routes(self):
        from opencyber.control.wiring import SandboxAdapter

        store = make_store()
        fake = FakePlatform()
        adapter = SandboxAdapter(platform=fake, token="t")
        result = adapter.launch({"name": "oc-sandbox"})
        self.assertEqual(result["mode"], "platform")
        self.assertEqual(result["url"], fake.spec and "https://oc.example.hanzo.ai")
        app = Starlette(routes=build_routes(Console(store, token="secret", sandbox=adapter)))
        auth = [(b"authorization", b"Bearer secret")]
        status, body = asyncio.run(asgi_get(app, "/whoami", auth))
        self.assertEqual(status, 200)
        self.assertEqual(body["org"], "admin")
        status, body = asyncio.run(asgi_get(app, "/wiring", auth))
        self.assertEqual(status, 200)
        self.assertEqual(body["sandbox"]["mode"], "platform")
        self.assertEqual(body["iam"]["mode"], "local")
        status, body = asyncio.run(asgi_get(app, "/secrets/status", auth))
        self.assertEqual(status, 200)


class KitchenTests(unittest.TestCase):
    def test_registry_and_security_surfaces(self):
        store = make_store()
        task = new_task(store)
        app = Starlette(routes=build_routes(Console(store, token="secret")))
        auth = [(b"authorization", b"Bearer secret")]
        status, body = asyncio.run(asgi_get(app, "/tools/catalog", auth))
        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 271)
        self.assertEqual(body["by_group"]["control_plane"], 18)
        for path in ("/skills", "/packets", "/hosts", "/security", "/sbom", "/hardening"):
            with self.subTest(path=path):
                status, body = asyncio.run(asgi_get(app, path, auth))
                self.assertEqual(status, 200, body)
        status, body = asyncio.run(asgi_get(app, "/security", auth, method="POST", body={"name": "test-secret", "severity": "high"}))
        self.assertEqual(status, 201)
        status, bundle = asyncio.run(asgi_get(app, f"/reports/{task['id']}/bundle", auth))
        self.assertEqual(status, 200)
        self.assertEqual(len(bundle["integrity"]["sha256"]), 64)
        self.assertEqual(len(bundle["integrity"]["signature"]), 64)
        self.assertTrue(bundle["verify"]["instructions"])


class ApiTests(unittest.TestCase):
    def test_routes_and_auth(self):
        store = make_store()
        console = Console(store, llm=ScriptedLLM([]), token="secret")
        app = Starlette(routes=build_routes(console))
        status, body = asyncio.run(asgi_get(app, "/health"))
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized")
        auth = [(b"authorization", b"Bearer secret")]
        status, body = asyncio.run(asgi_get(app, "/health", auth))
        self.assertTrue(body["ok"])
        self.assertEqual(body["backend"], "SQLiteBackend")
        for path in ("/dashboard", "/stats", "/tasks", "/findings", "/traffic", "/assets", "/settings", "/logs", "/llm/profiles", "/agents", "/mcp", "/intercept/rules", "/intercept/approvals", "/executions", "/usage", "/sync/status"):
            with self.subTest(path=path):
                status, body = asyncio.run(asgi_get(app, path, auth))
                self.assertEqual(status, 200, body)

    def test_create_app_serves_static_shell(self):
        store = make_store()
        app = create_app(store, enable_runner=False)
        self.assertTrue(any(getattr(route, "path", "") == "/" for route in app.routes))
        self.assertTrue(any(getattr(route, "path", "") == "/static" for route in app.routes))


if __name__ == "__main__":
    unittest.main()
