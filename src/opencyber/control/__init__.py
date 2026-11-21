"""Operator control plane for engagement-scoped autonomous assessment.

The control plane is an independent implementation of the documented behavior:
a planner/worker loop, a shared asset graph plus a per-task exploration graph,
findings bound to captured traffic, approval gates, budgets and a request noise
governor.

Persistence is a small document store with two backends: Hanzo Base over its
``/v1/collections`` REST API (production) and SQLite (hermetic tests and local
single-operator use). Nothing here imports the MCP server; the server registers
a thin adapter over the same functions.
"""

from __future__ import annotations

from .store import BaseBackend, SQLiteBackend, Store, backend_from_env, open_store

__all__ = ["BaseBackend", "SQLiteBackend", "Store", "backend_from_env", "open_store"]
