"""Dual graph: shared asset graph plus per-task exploration graph.

The asset graph answers *what exists* (root_domain → subdomain → service →
app → endpoint, with IP as a sibling of service). The exploration graph answers
*what was tried and what it produced* (goal → intent → fact/finding/hint, joined
by ``spawns``, ``derived_from``, ``yields`` and ``proves``). An anchor ties an
exploration node to a concrete asset, which is what makes asset coverage and
the two graph views possible.

Agents submit raw observations; this module computes identity, containment and
deduplication so two workers cannot fork the same asset into two nodes.
"""

from __future__ import annotations

from typing import Any, Iterable
from urllib.parse import urlsplit

from .store import Store


ASSET_KINDS = ("root_domain", "subdomain", "ip", "service", "app", "endpoint")
NODE_KINDS = ("goal", "intent", "fact", "finding", "hint", "digest")
EDGE_KINDS = ("spawns", "derived_from", "yields", "proves", "intent_chain")
NODE_STATES = ("pending", "running", "done", "failed", "blocked", "cancelled")

_PARENT_RULES = {
    "root_domain": (),
    "subdomain": ("root_domain",),
    "ip": (),
    "service": ("ip", "subdomain", "root_domain"),
    "app": ("root_domain", "subdomain"),
    "endpoint": ("service", "app", "subdomain", "root_domain", "ip"),
}


def _normalize(kind: str, value: str) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError("asset value must not be empty")
    if kind == "endpoint":
        parts = urlsplit(text)
        return text if parts.scheme else text
    return text.rstrip(".").lower()


def asset_key(kind: str, value: str, parent_id: str | None) -> str:
    return f"{kind}|{_normalize(kind, value)}|{parent_id or ''}"


def upsert_asset(
    store: Store,
    engagement_id: str,
    kind: str,
    value: str,
    parent_id: str | None = None,
    props: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], bool]:
    """Create or merge one asset. Returns ``(record, created)``.

    Deduplication is by ``(engagement, kind, normalized value, parent)``. A
    second observation merges its properties instead of adding a node, and
    keeps the first observation's source in ``sources``.
    """
    if kind not in ASSET_KINDS:
        raise ValueError(f"unknown asset kind {kind!r}; choose from {list(ASSET_KINDS)}")
    if parent_id:
        parent = store.get("assets", parent_id)
        if parent is None or parent.get("engagement_id") != engagement_id:
            raise ValueError(f"parent asset {parent_id} is not in engagement {engagement_id}")
        if parent["kind"] not in _PARENT_RULES[kind] and parent["kind"] != kind:
            raise ValueError(f"a {kind} asset cannot be a child of a {parent['kind']} asset")
    key = asset_key(kind, value, parent_id)
    existing = store.find_one("assets", {"engagement_id": engagement_id, "key": key})
    merged = dict(props or {})
    source = str(merged.pop("source", "agent"))
    if existing is not None:
        current = dict(existing.get("props") or {})
        current.update(merged)
        sources = list(existing.get("sources") or [])
        if source not in sources:
            sources.append(source)
        record = store.update(
            "assets",
            existing["id"],
            value=_normalize(kind, value),
            props=current,
            sources=sources,
        )
        return record, False
    record = store.create(
        "assets",
        engagement_id=engagement_id,
        kind=kind,
        value=_normalize(kind, value),
        parent_id=parent_id,
        key=key,
        props=merged,
        sources=[source],
    )
    return record, True


def add_node(
    store: Store,
    engagement_id: str,
    task_id: str,
    kind: str,
    summary: str,
    *,
    state: str = "done",
    priority: int = 0,
    payload: dict[str, Any] | None = None,
    source: str = "planner",
    digest_of: Iterable[str] | None = None,
) -> dict[str, Any]:
    if kind not in NODE_KINDS:
        raise ValueError(f"unknown node kind {kind!r}")
    if state not in NODE_STATES:
        raise ValueError(f"unknown node state {state!r}")
    sequence = store.count("nodes", {"task_id": task_id}) + 1
    return store.create(
        "nodes",
        engagement_id=engagement_id,
        task_id=task_id,
        kind=kind,
        summary=summary,
        state=state,
        priority=priority,
        payload=payload or {},
        source=source,
        digest_of=list(digest_of or []),
        sequence=sequence,
    )


def add_edge(store: Store, task_id: str, source: str, target: str, kind: str) -> dict[str, Any]:
    if kind not in EDGE_KINDS:
        raise ValueError(f"unknown edge kind {kind!r}")
    existing = store.find_one("edges", {"task_id": task_id, "source": source, "target": target, "kind": kind})
    if existing is not None:
        return existing
    return store.create("edges", task_id=task_id, source=source, target=target, kind=kind)


def anchor(store: Store, task_id: str, node_id: str, asset_id: str) -> dict[str, Any]:
    existing = store.find_one("anchors", {"task_id": task_id, "node_id": node_id, "asset_id": asset_id})
    if existing is not None:
        return existing
    return store.create("anchors", task_id=task_id, node_id=node_id, asset_id=asset_id)


def anchors_for(store: Store, task_id: str, node_id: str) -> list[dict[str, Any]]:
    links = store.list("anchors", {"task_id": task_id, "node_id": node_id})
    return [asset for asset in (store.get("assets", link["asset_id"]) for link in links) if asset]


def assets_for_task(store: Store, task_id: str) -> list[dict[str, Any]]:
    links = store.list("anchors", {"task_id": task_id})
    seen: set[str] = set()
    assets = []
    for link in links:
        if link["asset_id"] in seen:
            continue
        asset = store.get("assets", link["asset_id"])
        if asset:
            seen.add(asset["id"])
            assets.append(asset)
    return assets


def task_assets(store: Store, task_id: str) -> dict[str, Any]:
    """Every asset the task touched, grouped by kind, with the anchors back."""
    assets = assets_for_task(store, task_id)
    grouped: dict[str, list[dict[str, Any]]] = {kind: [] for kind in ASSET_KINDS}
    for asset in assets:
        grouped.setdefault(asset["kind"], []).append(asset)
    return {"task_id": task_id, "total": len(assets), "by_kind": grouped}


def exploration_graph(store: Store, task_id: str) -> dict[str, Any]:
    nodes = store.list("nodes", {"task_id": task_id}, order="sequence")
    edges = store.list("edges", {"task_id": task_id})
    anchors = store.list("anchors", {"task_id": task_id})
    return {
        "task_id": task_id,
        "nodes": nodes,
        "edges": edges,
        "anchors": anchors,
        "counts": {
            "nodes": len(nodes),
            "edges": len(edges),
            "by_kind": {kind: sum(1 for node in nodes if node["kind"] == kind) for kind in NODE_KINDS},
        },
    }


def lineage(store: Store, task_id: str, node_id: str) -> dict[str, Any]:
    """Walk ``derived_from``/``spawns`` backwards to the goal and ``yields``/``proves`` forward."""
    nodes = {node["id"]: node for node in store.list("nodes", {"task_id": task_id})}
    edges = store.list("edges", {"task_id": task_id})
    upstream_kinds = {"derived_from", "spawns", "intent_chain"}
    upstream = [edge for edge in edges if edge["target"] == node_id and edge["kind"] in upstream_kinds]
    downstream = [edge for edge in edges if edge["source"] == node_id and edge["kind"] in {"yields", "proves"}]
    return {
        "task_id": task_id,
        "node": nodes.get(node_id),
        "upstream": [{**edge, "node": nodes.get(edge["source"])} for edge in upstream],
        "downstream": [{**edge, "node": nodes.get(edge["target"])} for edge in downstream],
    }


def coverage(store: Store, engagement_id: str, task_id: str | None = None) -> dict[str, Any]:
    """In-scope assets and whether this task (or any task) anchored them.

    The denominator is every asset in the engagement's asset graph. An asset is
    ``tested`` when at least one intent or finding anchors it. The caveat that
    "tested" means "some node referenced it", not "a tool proved it", is part of
    the result, not a footnote the UI can drop.
    """
    assets = store.list("assets", {"engagement_id": engagement_id})
    if task_id:
        anchors = store.list("anchors", {"task_id": task_id})
    else:
        task_ids = {task["id"] for task in store.list("tasks", {"engagement_id": engagement_id})}
        anchors = [link for link in store.list("anchors") if link["task_id"] in task_ids]
    nodes = {}
    if anchors:
        node_ids = {link["node_id"] for link in anchors}
        nodes = {node["id"]: node for node in store.list("nodes") if node["id"] in node_ids}
    tested: dict[str, dict[str, Any]] = {}
    for link in anchors:
        node = nodes.get(link["node_id"])
        if node is None:
            continue
        entry = tested.setdefault(link["asset_id"], {"intents": [], "facts": [], "findings": [], "hints": []})
        bucket = {
            "intent": "intents",
            "fact": "facts",
            "finding": "findings",
            "hint": "hints",
        }.get(node["kind"])
        if bucket and node["id"] not in entry[bucket]:
            entry[bucket].append(node["id"])
    rows = []
    for asset in assets:
        links = tested.get(asset["id"], {"intents": [], "facts": [], "findings": [], "hints": []})
        rows.append(
            {
                "asset_id": asset["id"],
                "kind": asset["kind"],
                "value": asset["value"],
                "parent_id": asset.get("parent_id"),
                "tested": bool(links["intents"] or links["findings"]),
                **links,
            }
        )
    by_kind: dict[str, dict[str, int]] = {}
    for row in rows:
        counter = by_kind.setdefault(row["kind"], {"total": 0, "tested": 0})
        counter["total"] += 1
        counter["tested"] += 1 if row["tested"] else 0
    total = len(rows)
    hit = sum(1 for row in rows if row["tested"])
    return {
        "engagement_id": engagement_id,
        "task_id": task_id,
        "total": total,
        "tested": hit,
        "percent": round((hit / total) * 100, 1) if total else 0.0,
        "by_kind": by_kind,
        "assets": rows,
        "caveat": (
            "Tested means at least one intent or finding anchored the asset. "
            "It is not proof that a tool exercised every service or endpoint."
        ),
    }


def asset_tree(store: Store, engagement_id: str) -> dict[str, Any]:
    assets = store.list("assets", {"engagement_id": engagement_id}, order="created")
    children: dict[str | None, list[dict[str, Any]]] = {}
    for asset in assets:
        children.setdefault(asset.get("parent_id"), []).append(asset)
    roots = children.get(None, [])
    for bucket in children.values():
        bucket.sort(key=lambda item: (item["kind"], item["value"]))

    def build(asset: dict[str, Any], depth: int = 0) -> dict[str, Any]:
        return {
            "id": asset["id"],
            "kind": asset["kind"],
            "value": asset["value"],
            "props": asset.get("props") or {},
            "sources": asset.get("sources") or [],
            "depth": depth,
            "children": [build(child, depth + 1) for child in children.get(asset["id"], [])],
        }

    return {
        "engagement_id": engagement_id,
        "total": len(assets),
        "roots": [build(root) for root in roots],
        "orphans": [
            {"id": asset["id"], "kind": asset["kind"], "value": asset["value"]}
            for asset in assets
            if asset.get("parent_id") and asset["parent_id"] not in {item["id"] for item in assets}
        ],
    }
