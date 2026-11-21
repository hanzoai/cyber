"""Traffic capture, replay and HAR interchange.

Captured exchanges are the evidence findings point at. The store keeps the
request and response side by side, marks truncated bodies instead of silently
shortening them, and refuses to invent a body it does not hold.

Replay re-sends one recorded request through the same scope gate, target
blocklist and noise governor as every other target call, then records the new
exchange with ``source="replay"`` and ``replayed_from`` set.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Iterable

from ..errors import OcError
from ..policy import canonical_http_url, enforce_url_scope
from .governor import governor
from .intercept import blocked_target
from .store import Store


MAX_BODY_BYTES = 256 * 1024
MAX_BATCH = 50
TEXT_TYPES = (
    "text/", "json", "xml", "javascript", "x-www-form-urlencoded", "graphql",
    "html", "css", "yaml", "csv", "plain",
)


def _content_type(headers: dict[str, str]) -> str:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return str(value).lower()
    return ""


def _is_text(content_type: str) -> bool:
    return not content_type or any(token in content_type for token in TEXT_TYPES)


def _body(value: str | bytes | None, content_type: str) -> dict[str, Any]:
    if value is None:
        return {"text": "", "bytes": 0, "truncated": False, "encoding": "utf-8"}
    raw = value.encode("utf-8", errors="replace") if isinstance(value, str) else value
    truncated = len(raw) > MAX_BODY_BYTES
    raw = raw[:MAX_BODY_BYTES]
    if _is_text(content_type):
        return {
            "text": raw.decode("utf-8", errors="replace"),
            "bytes": len(raw),
            "truncated": truncated,
            "encoding": "utf-8",
        }
    return {
        "text": base64.b64encode(raw).decode("ascii"),
        "bytes": len(raw),
        "truncated": truncated,
        "encoding": "base64",
    }


def record(
    store: Store,
    engagement_id: str,
    *,
    method: str,
    url: str,
    request_headers: dict[str, str] | None = None,
    request_body: str | bytes | None = None,
    status: int | None = None,
    response_headers: dict[str, str] | None = None,
    response_body: str | bytes | None = None,
    source: str = "proxy",
    replayed_from: str | None = None,
    tags: Iterable[str] | None = None,
    duration_ms: int = 0,
    note: str = "",
) -> dict[str, Any]:
    request_headers = dict(request_headers or {})
    response_headers = dict(response_headers or {})
    request = _body(request_body, _content_type(request_headers))
    response = _body(response_body, _content_type(response_headers))
    return store.create(
        "traffic",
        engagement_id=engagement_id,
        method=method.upper(),
        url=url,
        host=(canonical_http_url(url).split("://", 1)[-1].split("/", 1)[0].split(":")[0]).lower(),
        request_headers=request_headers,
        request_body=request,
        status=status,
        response_headers=response_headers,
        response_body=response,
        source=source,
        replayed_from=replayed_from,
        tags=list(tags or []),
        duration_ms=duration_ms,
        note=note,
        content_type=_content_type(response_headers),
    )


def ingest(store: Store, engagement_id: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Store a batch from the browser extension.

    Binary bodies are skipped, bodies beyond 256 KiB are truncated and marked,
    and a batch larger than 50 entries is refused rather than split silently.
    """
    if not isinstance(entries, list):
        raise ValueError("entries must be a list")
    if len(entries) > MAX_BATCH:
        raise OcError(
            "limit_exceeded",
            f"ingest accepts at most {MAX_BATCH} entries per batch",
            details={"limit": MAX_BATCH, "received": len(entries)},
        )
    stored, skipped, errors = [], [], []
    for index, entry in enumerate(entries):
        try:
            url = canonical_http_url(str(entry.get("url") or ""))
            request_headers = dict(entry.get("request_headers") or {})
            response_headers = dict(entry.get("response_headers") or {})
            if not _is_text(_content_type(response_headers)) and entry.get("response_body"):
                skipped.append({"index": index, "reason": "binary or non-text response"})
                continue
            stored.append(
                record(
                    store,
                    engagement_id,
                    method=str(entry.get("method") or "GET"),
                    url=url,
                    request_headers=request_headers,
                    request_body=entry.get("request_body"),
                    status=entry.get("status"),
                    response_headers=response_headers,
                    response_body=entry.get("response_body"),
                    source=str(entry.get("source") or "extension"),
                    tags=entry.get("tags") or [],
                )
            )
        except (ValueError, OcError) as exc:
            errors.append({"index": index, "error": str(exc)})
    return {"stored": len(stored), "skipped": len(skipped), "failed": len(errors), "skipped_entries": skipped, "errors": errors, "records": stored}


def list_exchanges(
    store: Store,
    engagement_id: str,
    *,
    host: str = "",
    method: str = "",
    search: str = "",
    status_class: str = "",
    body_contains: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    where: dict[str, Any] = {"engagement_id": engagement_id}
    if host:
        where["host"] = host
    if method:
        where["method"] = method.upper()
    records = store.list("traffic", where, order="-created")
    search = search.lower()
    filtered = []
    for item in records:
        if search and search not in f"{item.get('url', '')} {item.get('method', '')} {item.get('content_type', '')} {item.get('status', '')}".lower():
            continue
        if status_class:
            status = int(item.get("status") or 0)
            if status_class == "2xx" and not 200 <= status < 300:
                continue
            if status_class == "3xx" and not 300 <= status < 400:
                continue
            if status_class == "4xx" and not 400 <= status < 500:
                continue
            if status_class == "5xx" and not 500 <= status < 600:
                continue
        if body_contains:
            haystack = str((item.get("response_body") or {}).get("text") or "")
            if body_contains.lower() not in haystack.lower():
                continue
        filtered.append(item)
    total = len(filtered)
    page = filtered[offset : offset + limit] if limit else filtered[offset:]
    return {"records": page, "total": total, "offset": offset, "limit": limit, "hosts": hosts(store, engagement_id)}


def hosts(store: Store, engagement_id: str) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in store.list("traffic", {"engagement_id": engagement_id}):
        counts[item["host"]] = counts.get(item["host"], 0) + 1
    return [{"host": host, "count": count} for host, count in sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))]


def get_exchange(store: Store, exchange_id: str) -> dict[str, Any]:
    return store.require("traffic", exchange_id)


def delete_exchange(store: Store, exchange_id: str) -> None:
    store.require("traffic", exchange_id)
    store.delete("traffic", exchange_id)


def purge(store: Store, engagement_id: str, host: str = "") -> dict[str, Any]:
    where: dict[str, Any] = {"engagement_id": engagement_id}
    if host:
        where["host"] = host
    deleted = store.delete_where("traffic", where)
    return {"deleted": deleted, "host": host or "all"}


def replay(
    store: Store,
    engagement_id: str,
    exchange_id: str,
    *,
    method: str | None = None,
    url: str | None = None,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    original = get_exchange(store, exchange_id)
    if original.get("engagement_id") != engagement_id:
        raise OcError("scope_denied", "the exchange belongs to another engagement", details={"exchange_id": exchange_id})
    target = url or original["url"]
    enforce_url_scope(engagement_id, target, tool="oc_traffic_replay")
    blocked = blocked_target(store, engagement_id, original.get("host", ""), target)
    if blocked:
        raise OcError(
            "scope_denied",
            f"target blocklist refused {blocked.get('pattern')}",
            details={"blocked_target": blocked.get("pattern"), "kind": blocked.get("match_kind")},
        )
    if original.get("request_body", {}).get("truncated"):
        raise OcError(
            "invalid_argument",
            "the stored request body is truncated; replay would send a partial request",
            details={"exchange_id": exchange_id},
        )
    import requests

    request_headers = {**(original.get("request_headers") or {}), **(headers or {})}
    request_headers.pop("host", None)
    payload = body if body is not None else original.get("request_body", {}).get("text", "")
    with governor().slot(target) as decision:
        response = requests.request(
            (method or original["method"]).upper(),
            target,
            headers=request_headers,
            data=payload or None,
            timeout=timeout,
            stream=True,
        )
        response_body = response.raw.read(MAX_BODY_BYTES + 1, decode_content=True) if response.raw else b""
        truncated = len(response_body) > MAX_BODY_BYTES
        response_body = response_body[:MAX_BODY_BYTES]
    governor().observe(target, response.status_code)
    recorded = record(
        store,
        engagement_id,
        method=(method or original["method"]).upper(),
        url=target,
        request_headers=request_headers,
        request_body=payload,
        status=response.status_code,
        response_headers=dict(response.headers),
        response_body=response_body,
        source="replay",
        replayed_from=exchange_id,
        tags=["replay", *original.get("tags", [])],
    )
    return {
        "exchange": recorded,
        "status": response.status_code,
        "headers": dict(response.headers),
        "body": response_body.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "governor": decision,
        "replayed_from": exchange_id,
    }


def export_har(store: Store, engagement_id: str) -> dict[str, Any]:
    entries = []
    for item in store.list("traffic", {"engagement_id": engagement_id}, order="created"):
        entries.append(
            {
                "startedDateTime": item["created"],
                "time": int(item.get("duration_ms") or 0),
                "request": {
                    "method": item["method"],
                    "url": item["url"],
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in (item.get("request_headers") or {}).items()],
                    "queryString": [],
                    "cookies": [],
                    "headersSize": -1,
                    "bodySize": int((item.get("request_body") or {}).get("bytes") or 0),
                    **(
                        {"postData": {"mimeType": (item.get("request_headers") or {}).get("content-type", ""), "text": (item.get("request_body") or {}).get("text", "")}}
                        if (item.get("request_body") or {}).get("text")
                        else {}
                    ),
                },
                "response": {
                    "status": int(item.get("status") or 0),
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": [{"name": k, "value": v} for k, v in (item.get("response_headers") or {}).items()],
                    "cookies": [],
                    "content": {
                        "size": int((item.get("response_body") or {}).get("bytes") or 0),
                        "mimeType": item.get("content_type", ""),
                        "text": (item.get("response_body") or {}).get("text", ""),
                        "encoding": (item.get("response_body") or {}).get("encoding", "utf-8"),
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": int((item.get("response_body") or {}).get("bytes") or 0),
                },
                "cache": {},
                "timings": {"send": 0, "wait": int(item.get("duration_ms") or 0), "receive": 0},
                "_opencyber": {"id": item["id"], "source": item.get("source"), "tags": item.get("tags", [])},
            }
        )
    return {"log": {"version": "1.2", "creator": {"name": "OpenCyber", "version": "1"}, "entries": entries}}


def import_har(store: Store, engagement_id: str, document: dict[str, Any]) -> dict[str, Any]:
    entries = (document.get("log") or {}).get("entries")
    if not isinstance(entries, list):
        raise ValueError("a HAR document must carry log.entries")
    stored, skipped, errors = [], [], []
    for index, entry in enumerate(entries):
        try:
            request = entry.get("request") or {}
            response = entry.get("response") or {}
            url = canonical_http_url(str(request.get("url") or ""))
            request_headers = {item.get("name", ""): item.get("value", "") for item in request.get("headers") or []}
            response_headers = {item.get("name", ""): item.get("value", "") for item in response.get("headers") or []}
            content = response.get("content") or {}
            if content.get("encoding") == "base64":
                raw = base64.b64decode(content.get("text") or "")
                response_body: str | bytes = raw
            else:
                response_body = content.get("text") or ""
                if not _is_text(_content_type(response_headers)) and response_body:
                    skipped.append({"index": index, "reason": "binary response"})
                    continue
            stored.append(
                record(
                    store,
                    engagement_id,
                    method=str(request.get("method") or "GET"),
                    url=url,
                    request_headers=request_headers,
                    request_body=(request.get("postData") or {}).get("text") or "",
                    status=int(response.get("status") or 0),
                    response_headers=response_headers,
                    response_body=response_body,
                    source="har",
                )
            )
        except (ValueError, OcError) as exc:
            errors.append({"index": index, "error": str(exc)})
    return {"imported": len(stored), "skipped": len(skipped), "failed": len(errors), "skipped_entries": skipped, "errors": errors}


def bind_to_finding(store: Store, finding_id: str, exchange_ids: Iterable[str], role: str = "supporting", note: str = "") -> dict[str, Any]:
    finding = store.require("findings", finding_id)
    evidence = list(finding.get("traffic") or [])
    known = {item["exchange_id"] for item in evidence}
    for exchange_id in exchange_ids:
        store.require("traffic", exchange_id)
        if exchange_id in known:
            continue
        evidence.append({"exchange_id": exchange_id, "role": role, "note": note, "added": True})
    return store.update("findings", finding_id, traffic=evidence)


def traffic_for_finding(store: Store, finding_id: str) -> list[dict[str, Any]]:
    finding = store.require("findings", finding_id)
    rows = []
    for item in finding.get("traffic") or []:
        exchange = store.get("traffic", item["exchange_id"])
        rows.append({**item, "exchange": exchange})
    return rows


def har_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=False)
