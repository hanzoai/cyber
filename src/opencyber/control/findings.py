"""Findings, evidence binding, verification and retests.

A finding is only ``verified`` when a bound traffic exchange or proof object
exists **and** every supplied evidence quote appears verbatim in that recorded
body. Verification never edits or deletes the original evidence, and a retest
is an immutable record: it can change the finding's triage state, never its
history.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import zipfile
import zlib
from typing import Any, Iterable

from ..errors import OcError
from . import graph
from .store import Store


SEVERITIES = ("critical", "high", "medium", "low", "info")
TRIAGE = ("pending", "in_progress", "confirmed", "resolved", "fixed", "false_positive", "ignored", "duplicate", "risk_accepted")
REPORT_STAGES = ("not_submitted", "submitted", "accepted", "rejected", "duplicate")
VERIFICATION = ("unverified", "verified", "blocked", "not_assessed", "false_positive")
POE = ("none", "lead", "demonstrated", "verified", "exploited")
RETEST_VERDICTS = ("still_reproducible", "fixed", "cannot_confirm")
RETEST_STATES = ("waiting", "running", "completed", "failed", "stopped", "interrupted")


def create(
    store: Store,
    engagement_id: str,
    task_id: str,
    title: str,
    *,
    severity: str = "info",
    summary: str = "",
    detail: str = "",
    vulnerability: str = "",
    asset_ids: Iterable[str] | None = None,
    evidence: str = "",
    confidence: str = "",
    counterevidence: str = "",
    finding_node: str | None = None,
) -> dict[str, Any]:
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity!r}; choose from {list(SEVERITIES)}")
    node = graph.add_node(
        store,
        engagement_id,
        task_id,
        "finding",
        title,
        payload={"severity": severity, "vulnerability": vulnerability},
        source="worker",
    )
    for asset_id in asset_ids or []:
        if store.get("assets", asset_id) is None:
            raise ValueError(f"unknown asset {asset_id}")
        graph.anchor(store, task_id, node["id"], asset_id)
    if finding_node:
        graph.add_edge(store, task_id, finding_node, node["id"], "proves")
    record = store.create(
        "findings",
        engagement_id=engagement_id,
        task_id=task_id,
        node_id=node["id"],
        title=title,
        severity=severity,
        summary=summary,
        detail=detail,
        vulnerability=vulnerability,
        asset_ids=list(asset_ids or []),
        evidence=evidence,
        counterevidence=counterevidence,
        confidence=confidence,
        triage="pending",
        report_stage="not_submitted",
        verification="not_assessed",
        verification_note="",
        poe="lead",
        traffic=[],
        retests=[],
        inherited_from=None,
    )
    store.event(engagement_id, task_id, "finding.created", title, finding_id=record["id"], severity=severity)
    return record


def update(store: Store, finding_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    allowed = {"title", "severity", "summary", "detail", "vulnerability", "triage", "report_stage", "evidence", "counterevidence", "confidence"}
    unknown = set(patch) - allowed
    if unknown:
        raise ValueError(f"fields cannot be edited directly: {sorted(unknown)}")
    if "severity" in patch and patch["severity"] not in SEVERITIES:
        raise ValueError(f"unknown severity {patch['severity']!r}")
    if "triage" in patch and patch["triage"] not in TRIAGE:
        raise ValueError(f"unknown triage status {patch['triage']!r}")
    if "report_stage" in patch and patch["report_stage"] not in REPORT_STAGES:
        raise ValueError(f"unknown report stage {patch['report_stage']!r}")
    return store.update("findings", finding_id, **patch)


def verify(
    store: Store,
    finding_id: str,
    *,
    quotes: Iterable[str] | None = None,
    proof_exchange_ids: Iterable[str] | None = None,
    note: str = "",
) -> dict[str, Any]:
    """Verify a finding against its bound traffic.

    ``verified`` requires at least one bound exchange and every quote present
    verbatim in a recorded response body (gzip/deflate is decoded first). A
    missing quote is a refusal to verify, with the missing text named.
    """
    from .traffic import bind_to_finding, traffic_for_finding

    finding = store.require("findings", finding_id)
    if proof_exchange_ids:
        bind_to_finding(store, finding_id, proof_exchange_ids, role="vulnerability_proof")
    bound = traffic_for_finding(store, finding_id)
    if not bound:
        result = store.update(
            "findings",
            finding_id,
            verification="blocked",
            verification_note="no bound traffic exchange or proof object supports this finding",
        )
        return {**result, "missing_quotes": [], "checked_quotes": []}
    haystacks = []
    for item in bound:
        body = ((item.get("exchange") or {}).get("response_body") or {})
        text = str(body.get("text") or "")
        if body.get("encoding") == "base64":
            continue
        haystacks.append(_decode(text, (item.get("exchange") or {}).get("response_headers") or {}))
    checked, missing = [], []
    for quote in quotes or []:
        if not isinstance(quote, str) or not quote:
            continue
        checked.append(quote)
        if not any(quote in haystack for haystack in haystacks):
            missing.append(quote)
    if not checked:
        result = store.update(
            "findings",
            finding_id,
            verification="not_assessed",
            verification_note="bound evidence exists but no verbatim quote was supplied",
        )
        return {**result, "missing_quotes": [], "checked_quotes": []}
    if missing:
        result = store.update(
            "findings",
            finding_id,
            verification="blocked",
            verification_note=f"{len(missing)} supplied quote(s) do not appear in the bound evidence",
        )
        return {**result, "missing_quotes": missing, "checked_quotes": checked}
    result = store.update(
        "findings",
        finding_id,
        verification="verified",
        verification_note=note or "every supplied quote appears verbatim in bound evidence",
        poe="verified",
    )
    store.event(finding["engagement_id"], finding["task_id"], "finding.verified", finding["title"], finding_id=finding_id)
    return {**result, "missing_quotes": [], "checked_quotes": checked}


def _decode(text: str, headers: dict[str, str]) -> str:
    encoding = ""
    for key, value in headers.items():
        if key.lower() == "content-encoding":
            encoding = str(value).lower()
    if "gzip" in encoding:
        try:
            return gzip.decompress(text.encode("latin-1")).decode("utf-8", errors="replace")
        except (OSError, ValueError):
            return text
    if "deflate" in encoding:
        try:
            return zlib.decompress(text.encode("latin-1")).decode("utf-8", errors="replace")
        except (zlib.error, ValueError):
            return text
    return text


def list_findings(
    store: Store,
    *,
    engagement_id: str | None = None,
    task_id: str | None = None,
    severity: str = "",
    triage: str = "",
    verification: str = "",
    search: str = "",
    limit: int = 0,
    offset: int = 0,
    order: str = "-created",
) -> dict[str, Any]:
    where: dict[str, Any] = {}
    if engagement_id:
        where["engagement_id"] = engagement_id
    if task_id:
        where["task_id"] = task_id
    if severity:
        where["severity"] = severity
    if triage:
        where["triage"] = triage
    if verification:
        where["verification"] = verification
    records = store.list("findings", where, order=order)
    search = search.lower()
    if search:
        records = [item for item in records if search in f"{item.get('title', '')} {item.get('summary', '')} {item.get('vulnerability', '')}".lower()]
    total = len(records)
    page = records[offset : offset + limit] if limit else records[offset:]
    return {"findings": page, "total": total, "offset": offset, "limit": limit}


def bulk_status(store: Store, finding_ids: Iterable[str], field: str, value: str) -> dict[str, Any]:
    if field not in {"triage", "report_stage"}:
        raise ValueError("bulk update supports triage or report_stage only")
    allowed = TRIAGE if field == "triage" else REPORT_STAGES
    if value not in allowed:
        raise ValueError(f"unknown {field} {value!r}")
    updated, failed = [], []
    for finding_id in finding_ids:
        try:
            updated.append(update(store, finding_id, {field: value}))
        except (OcError, ValueError) as exc:
            failed.append({"finding_id": finding_id, "error": str(exc)})
    return {"updated": updated, "failed": failed}


def start_retest(store: Store, finding_id: str, note: str = "", fixed_version: str = "") -> dict[str, Any]:
    finding = store.require("findings", finding_id)
    active = [
        retest
        for retest in store.list("retests", {"finding_id": finding_id})
        if retest.get("state") in {"waiting", "running"}
    ]
    if active:
        raise OcError("already_exists", "a retest is already running for this finding", details={"finding_id": finding_id})
    record = store.create(
        "retests",
        engagement_id=finding["engagement_id"],
        task_id=finding["task_id"],
        finding_id=finding_id,
        state="running",
        verdict=None,
        note=note,
        fixed_version=fixed_version,
        summary="",
        evidence="",
        error="",
    )
    store.update("findings", finding_id, retests=[*(finding.get("retests") or []), record["id"]])
    store.event(finding["engagement_id"], finding["task_id"], "finding.retest_started", finding["title"], retest_id=record["id"])
    return record


def complete_retest(
    store: Store,
    retest_id: str,
    *,
    verdict: str,
    summary: str = "",
    evidence: str = "",
    error: str = "",
    state: str = "completed",
) -> dict[str, Any]:
    if verdict not in RETEST_VERDICTS:
        raise ValueError(f"unknown retest verdict {verdict!r}")
    if state not in RETEST_STATES:
        raise ValueError(f"unknown retest state {state!r}")
    retest = store.require("retests", retest_id)
    if retest.get("state") not in {"waiting", "running"}:
        raise OcError("already_exists", f"retest {retest_id} is already {retest.get('state')}")
    updated = store.update(
        "retests",
        retest_id,
        state=state,
        verdict=verdict,
        summary=summary,
        evidence=evidence,
        error=error,
        completed_at=_now(),
    )
    if verdict == "fixed" and state == "completed":
        update(store, retest["finding_id"], {"triage": "fixed"})
    store.event(
        retest["engagement_id"],
        retest["task_id"],
        "finding.retest_completed",
        f"retest {verdict}",
        retest_id=retest_id,
        finding_id=retest["finding_id"],
    )
    return updated


def retests_for(store: Store, finding_id: str) -> list[dict[str, Any]]:
    return store.list("retests", {"finding_id": finding_id}, order="-created")


def deepen(store: Store, finding_id: str, instruction: str = "") -> dict[str, Any]:
    """Spawn a priority intent that tries to turn a lead into an exploit."""
    finding = store.require("findings", finding_id)
    intent = store.create(
        "intents",
        engagement_id=finding["engagement_id"],
        task_id=finding["task_id"],
        title=f"Deepen: {finding['title']}",
        instruction=instruction or f"Turn this finding into a demonstrated exploit and record the proof: {finding['title']}",
        status="proposed",
        priority=99,
        source_node=finding.get("node_id"),
        asset_ids=finding.get("asset_ids") or [],
        depth=9,
    )
    intent_node = _intent_node(store, finding["task_id"], intent)
    graph.add_edge(store, finding["task_id"], finding["node_id"], intent_node, "derived_from")
    store.event(finding["engagement_id"], finding["task_id"], "finding.deepen", finding["title"], intent_id=intent["id"])
    return intent


def _intent_node(store: Store, task_id: str, intent: dict[str, Any]) -> str:
    node = store.find_one("nodes", {"task_id": task_id, "intent_id": intent["id"]})
    if node is None:
        node = graph.add_node(
            store,
            intent["engagement_id"],
            task_id,
            "intent",
            intent["title"],
            state="pending",
            payload={"intent_id": intent["id"]},
        )
        store.update("intents", intent["id"], node_id=node["id"])
    return str(node["id"])


def export_findings(store: Store, findings: list[dict[str, Any]], fmt: str = "json") -> tuple[bytes, str, str]:
    """Return ``(content, media_type, filename)`` for one export format."""
    if fmt == "json":
        return json.dumps(findings, indent=2, default=str).encode("utf-8"), "application/json", "findings.json"
    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["id", "title", "severity", "triage", "report_stage", "verification", "task_id", "created"])
        for item in findings:
            writer.writerow([item["id"], item["title"], item["severity"], item["triage"], item["report_stage"], item["verification"], item["task_id"], item["created"]])
        return buffer.getvalue().encode("utf-8"), "text/csv", "findings.csv"
    if fmt == "markdown":
        lines = ["# Findings", ""]
        for item in findings:
            lines.extend(
                [
                    f"## {item['title']}",
                    "",
                    f"- Severity: **{item['severity'].upper()}**",
                    f"- Triage: {item['triage']}",
                    f"- Verification: {item['verification']}",
                    f"- Task: `{item['task_id']}`",
                    "",
                    item.get("summary") or "",
                    "",
                ]
            )
        return "\n".join(lines).encode("utf-8"), "text/markdown", "findings.md"
    if fmt == "zip":
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for item in findings:
                archive.writestr(f"{item['id']}.md", item.get("detail") or f"# {item['title']}\n\n{item.get('summary', '')}\n")
        return zip_buffer.getvalue(), "application/zip", "findings.zip"
    raise ValueError(f"unknown export format {fmt!r}")


def _now() -> str:
    from .store import now

    return now()
