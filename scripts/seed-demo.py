#!/usr/bin/env python3
"""Seed a realistic offline demo engagement into the control plane.

Uses the same Store the API uses, so it works with the SQLite conformance
backend and with Hanzo Base. Idempotent: re-running adds nothing twice.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
from urllib.request import Request, urlopen

from opencyber.control.store import open_store


API = os.environ.get("OPENCYBER_CONTROL_URL", "http://127.0.0.1:8787")


def call(method: str, path: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    request = Request(
        API + "/v1" + path,
        data=data,
        method=method,
        headers={"content-type": "application/json"} if data else {},
    )
    with urlopen(request, timeout=20) as response:
        raw = response.read()
        return json.loads(raw) if raw else {}


def main() -> None:
    store = open_store()
    if store.find_one("settings", {"kind": "demo_seed", "name": "v1"}):
        print("demo already seeded")
        return

    engagement = call("POST", "/engagements", {
        "name": "Demo Bank",
        "targets": ["demo.bank.test"],
        "objective": "Authorized Q4 external assessment",
    })
    eid = engagement["engagement_id"]
    task = call("POST", "/tasks", {
        "name": "External web assessment",
        "goal": "Enumerate external assets and prove one authenticated admin exposure.",
        "description": "Scoped authorized assessment of demo.bank.test.",
        "category": "External web",
        "scope": ["demo.bank.test"],
    })
    tid = task["id"]
    print(f"engagement {eid}\ntask {tid}")

    for title in [
        "Enumerate subdomains", "Probe /admin endpoint", "Check payment logic",
        "Review auth flow", "Test file upload SSRF",
    ]:
        call("POST", f"/tasks/{tid}/intents", {"title": title, "instruction": title, "priority": 5})

    hosts = ["www", "api", "admin", "pay", "mail", "vpn", "dev", "staging", "cdn",
             "auth", "portal", "mobile", "test", "uat", "secure", "blog", "shop",
             "invest", "support", "cloud", "assets", "img", "login", "sso", "apps",
             "docs", "ftp", "smtp", "ns1", "ns2"]
    assets = [{"kind": "root_domain", "value": "demo.bank.test"}]
    assets += [{"kind": "subdomain", "value": f"{h}.demo.bank.test"} for h in hosts]
    call("POST", "/assets", {"assets": assets})

    titles = [
        "Admin panel exposed", "IDOR on account endpoint", "Reflected XSS in search",
        "Weak JWT signing key", "Open S3 bucket", "SQL error disclosure",
        "Missing auth on export", "Payment logic abuse", "SSRF via file upload",
        "Default credentials on staging", "Verbose error stack trace",
        "Unrestricted file upload",
    ]
    for index, title in enumerate(titles):
        body = (
            "HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
            f"<html><body>Admin Login panel for demo.bank.test - target-{index}. "
            "Sensitive dashboard visible.</body></html>"
        )
        ingest = call("POST", "/traffic/ingest", {"entries": [{
            "method": "GET", "url": f"https://demo.bank.test/admin/{index}",
            "status": 200, "request_headers": {"User-Agent": "OpenCyber/1.0"},
            "response_headers": {"Content-Type": "text/html"},
            "request_body": "", "response_body": body,
        }]})
        exchange_id = (ingest.get("records") or [{}])[0].get("id")
        finding = call("POST", "/findings", {
            "task_id": tid, "title": title,
            "severity": ["critical", "high", "medium", "low"][index % 4],
            "summary": "Verified against captured response.",
            "detail": "The captured response contains the verbatim marker below.",
            "evidence": "Admin Login", "vulnerability": "exposed_admin_panel",
        })
        fid = finding.get("id")
        if exchange_id and fid:
            call("POST", f"/findings/{fid}/traffic", {
                "exchange_ids": [exchange_id], "role": "vulnerability_proof",
                "note": "captured during authorized assessment",
            })
            call("POST", f"/findings/{fid}/verify", {
                "quotes": ["Admin Login"], "note": "quote matched",
            })

    def now():
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for tool, args in [
        ("oc_bash", {"script": "nmap -sV demo.bank.test"}),
        ("oc_http_request", {"url": "https://demo.bank.test/admin"}),
        ("oc_browser_navigate", {"url": "https://demo.bank.test/admin"}),
    ]:
        store.create("approvals", engagement_id=eid, task_id=tid, tool=tool,
                     arguments=args, status="pending", decision="ask",
                     reason="matched operator rule", note="Awaiting human decision",
                     timeout_seconds=0, timeout_action="deny")
    for i in range(46):
        store.create("usage", engagement_id=eid, task_id=tid, model="zen6-cyber",
                     provider="hanzo", input_tokens=1800 + i * 17,
                     output_tokens=420 + i * 5, cache_read=600,
                     latency_ms=310, status="ok", created=now())
    for tool in ["oc_http_request", "oc_nmap", "oc_browser_navigate",
                 "oc_finding_report", "oc_directory_brute"]:
        for i in range(7):
            store.create("executions", engagement_id=eid, task_id=tid, tool=tool,
                         arguments={"target": "demo.bank.test"},
                         status="succeeded" if i % 6 else "denied",
                         duration_ms=120 + i * 23, created=now())

    for row in store.list("assets", {"engagement_id": eid}):
        props = dict(row.get("props") or {})
        props.update({"ports": [80, 443, 8080][: len(row["value"]) % 3 + 1],
                      "services": ["http", "https", "admin"][: len(row["value"]) % 3 + 1],
                      "state": "up"})
        store.update("assets", row["id"], props=props, sources=["scanner", "har"])

    for profile in store.list("models", {"engagement_id": eid}):
        store.update("models", profile["id"], pool_enabled=False)
    store.create("models", engagement_id=eid, name="qwen3-local", model="default",
                 provider="hanzo", base_url=os.environ.get("OPENCYBER_ENGINE_URL",
                 "http://10.0.0.19:1234/v1"), key_ref="", active=True,
                 pool_enabled=True, max_output_tokens=512, rate_per_minute=60,
                 created=now())

    store.create("settings", kind="demo_seed", engagement_id=eid, name="v1")
    Path(os.environ.get("OPENCYBER_DEMO_FILE", "/tmp/opencyber-demo.json")).write_text(
        json.dumps({"engagement_id": eid, "task_id": tid})
    )
    print(f"seeded: {len(assets)} assets, {len(titles)} findings")


if __name__ == "__main__":
    main()
