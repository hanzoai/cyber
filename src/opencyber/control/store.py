"""Document store with Hanzo Base and SQLite backends.

Every control-plane record is a flat JSON document with ``id``, ``created`` and
``updated``. The domain modules never know which backend is underneath; they
call :class:`Store` and the store routes to the configured backend.

Production uses Hanzo Base (the ``/v1/collections/{name}/records`` API), so the
data lands beside the rest of the org's records and inherits its access rules.
SQLite is the conformance and single-operator backend: it exercises the exact
same call surface in tests and runs without a server.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Iterable, Mapping, Protocol
import uuid

from ..errors import OcError


Record = dict[str, Any]

_COLLECTIONS = {
    "tasks": "tsk",
    "intents": "int",
    "assets": "ast",
    "nodes": "nod",
    "edges": "edg",
    "anchors": "anc",
    "findings": "fnd",
    "retests": "rts",
    "traffic": "trf",
    "approvals": "apr",
    "usage": "usg",
    "templates": "tpl",
    "notifications": "ntf",
    "models": "mdl",
    "messages": "msg",
    "events": "evt",
    "lessons": "lsn",
    "goals": "gol",
    "credentials": "crd",
    "executions": "exe",
    "settings": "set",
    "security": "sec",
    "sbom": "sbm",
    "hardening": "hrd",
}


def new_id(collection: str) -> str:
    prefix = _COLLECTIONS.get(collection, "rec")
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _matches(record: Mapping[str, Any], where: Mapping[str, Any] | None) -> bool:
    for key, expected in (where or {}).items():
        actual = record.get(key)
        if isinstance(expected, (list, tuple, set)):
            if actual not in expected:
                return False
        elif callable(expected):
            if not expected(actual):
                return False
        elif actual != expected:
            return False
    return True


def _sorted(records: list[Record], order: str | None) -> list[Record]:
    if not order:
        return records
    fields = [part.strip() for part in order.split(",") if part.strip()]
    for field in reversed(fields):
        reverse = field.startswith("-")
        name = field.lstrip("-")
        records.sort(key=lambda item: (item.get(name) is None, item.get(name)), reverse=reverse)
    return records


class Backend(Protocol):
    """The four operations a persistence backend must answer."""

    def insert(self, collection: str, record: Record) -> Record: ...

    def get(self, collection: str, record_id: str) -> Record | None: ...

    def update(self, collection: str, record_id: str, patch: Record) -> Record: ...

    def delete(self, collection: str, record_id: str) -> None: ...

    def list(
        self,
        collection: str,
        where: Mapping[str, Any] | None = None,
        order: str | None = None,
        limit: int = 0,
        offset: int = 0,
    ) -> list[Record]: ...

    def count(self, collection: str, where: Mapping[str, Any] | None = None) -> int: ...


class SQLiteBackend:
    """One table of JSON documents. Filters are evaluated in Python."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS records ("
            "collection TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL, "
            "created TEXT NOT NULL, updated TEXT NOT NULL, "
            "PRIMARY KEY (collection, id))"
        )
        self._connection.execute("CREATE INDEX IF NOT EXISTS records_order ON records(collection, created)")
        self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _write(self, collection: str, record: Record) -> None:
        self._connection.execute(
            "INSERT OR REPLACE INTO records(collection, id, data, created, updated) VALUES (?, ?, ?, ?, ?)",
            (
                collection,
                record["id"],
                json.dumps(record, ensure_ascii=False, sort_keys=True),
                record.get("created") or now(),
                record.get("updated") or now(),
            ),
        )
        self._connection.commit()

    def insert(self, collection: str, record: Record) -> Record:
        with self._lock:
            self._write(collection, record)
        return record

    def get(self, collection: str, record_id: str) -> Record | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT data FROM records WHERE collection = ? AND id = ?", (collection, record_id)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def update(self, collection: str, record_id: str, patch: Record) -> Record:
        with self._lock:
            current = self.get(collection, record_id)
            if current is None:
                raise OcError("not_found", f"unknown {collection} record: {record_id}")
            merged = {**current, **patch, "id": record_id, "updated": now()}
            self._write(collection, merged)
        return merged

    def delete(self, collection: str, record_id: str) -> None:
        with self._lock:
            self._connection.execute(
                "DELETE FROM records WHERE collection = ? AND id = ?", (collection, record_id)
            )
            self._connection.commit()

    def list(
        self,
        collection: str,
        where: Mapping[str, Any] | None = None,
        order: str | None = None,
        limit: int = 0,
        offset: int = 0,
    ) -> list[Record]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT data FROM records WHERE collection = ? ORDER BY created, id", (collection,)
            ).fetchall()
        records = [json.loads(row[0]) for row in rows]
        if where:
            records = [record for record in records if _matches(record, where)]
        records = _sorted(records, order)
        if offset or limit:
            records = records[offset : offset + limit] if limit else records[offset:]
        return records

    def count(self, collection: str, where: Mapping[str, Any] | None = None) -> int:
        return len(self.list(collection, where))


def _base_filter(where: Mapping[str, Any] | None) -> str:
    parts: list[str] = []
    for key, expected in (where or {}).items():
        if callable(expected) or isinstance(expected, (list, tuple, set)):
            raise ValueError(f"Hanzo Base backend cannot express the filter for {key}")
        text = str(expected).replace("\\", "\\\\").replace("'", "\\'")
        parts.append(f"{key}='{text}'")
    return " && ".join(parts)


class BaseBackend:
    """Hanzo Base records API (``/v1/collections``).

    Collections are created lazily with the fields the control plane needs and
    the permissive rules an operator deployment already scopes with IAM. Base
    owns identity; this adapter forwards the bearer token it is given.
    """

    PAGE = 500

    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        session: Any = None,
        timeout: float = 15.0,
    ) -> None:
        self.base_url = (base_url or os.environ.get("HANZO_BASE_URL", "https://base.hanzo.ai")).rstrip("/")
        self.token = token or os.environ.get("HANZO_API_KEY") or os.environ.get("HANZO_TOKEN") or ""
        self.timeout = timeout
        self._ensured: set[str] = set()
        if session is None:
            import requests

            session = requests.Session()
        self._session = session

    def _headers(self) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        return headers

    def _url(self, collection: str, record_id: str = "") -> str:
        url = f"{self.base_url}/v1/collections/{collection}/records"
        return f"{url}/{record_id}" if record_id else url

    def _ensure(self, collection: str) -> None:
        if collection in self._ensured:
            return
        response = self._session.post(
            f"{self.base_url}/v1/collections",
            json={"name": collection, "type": "base", "listRule": "", "viewRule": "", "createRule": "", "updateRule": "", "deleteRule": ""},
            headers=self._headers(),
            timeout=self.timeout,
        )
        if response.status_code not in (200, 201, 204, 400, 409):
            raise OcError(
                "integration_unavailable",
                f"Hanzo Base refused collection creation for {collection}: {response.status_code}",
                details={"collection": collection, "status": response.status_code},
            )
        self._ensured.add(collection)

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        response = self._session.request(method, url, headers=self._headers(), timeout=self.timeout, **kwargs)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise OcError(
                "integration_unavailable",
                f"Hanzo Base {method} {url} failed with {response.status_code}",
                details={"status": response.status_code, "body": response.text[:400]},
            )
        return response.json() if response.content else {}

    def insert(self, collection: str, record: Record) -> Record:
        self._ensure(collection)
        payload = {key: value for key, value in record.items() if key not in {"collectionId", "collectionName"}}
        body = self._request("POST", self._url(collection), json=payload)
        if isinstance(body, dict) and body.get("id"):
            return {**record, "id": body["id"]}
        return record

    def get(self, collection: str, record_id: str) -> Record | None:
        return self._request("GET", self._url(collection, record_id))

    def update(self, collection: str, record_id: str, patch: Record) -> Record:
        body = self._request("PATCH", self._url(collection, record_id), json=patch)
        if not isinstance(body, dict):
            raise OcError("not_found", f"unknown {collection} record: {record_id}")
        return body

    def delete(self, collection: str, record_id: str) -> None:
        self._request("DELETE", self._url(collection, record_id))

    def list(
        self,
        collection: str,
        where: Mapping[str, Any] | None = None,
        order: str | None = None,
        limit: int = 0,
        offset: int = 0,
    ) -> list[Record]:
        page = max(1, (offset // self.PAGE) + 1)
        skip = offset % self.PAGE
        records: list[Record] = []
        while True:
            params: dict[str, Any] = {"page": page, "perPage": self.PAGE}
            expression = _base_filter(where)
            if expression:
                params["filter"] = expression
            if order:
                params["sort"] = order
            body = self._request("GET", self._url(collection), params=params)
            items = list((body or {}).get("items") or [])
            records.extend(items[skip:] if page == max(1, offset // self.PAGE + 1) else items)
            skip = 0
            if limit and len(records) >= limit:
                return records[:limit]
            if len(items) < self.PAGE:
                return records
            page += 1
            if page > 1000:
                return records

    def count(self, collection: str, where: Mapping[str, Any] | None = None) -> int:
        params: dict[str, Any] = {"page": 1, "perPage": 1}
        expression = _base_filter(where)
        if expression:
            params["filter"] = expression
        body = self._request("GET", self._url(collection), params=params)
        return int((body or {}).get("totalItems") or 0)


class Store:
    """Domain-facing CRUD with generated ids and timestamps."""

    def __init__(self, backend: Backend) -> None:
        self.backend = backend

    def create(self, collection: str, record: Record | None = None, **fields: Any) -> Record:
        document: Record = {"id": new_id(collection), "created": now(), "updated": now()}
        document.update(record or {})
        document.update(fields)
        document["id"] = document.get("id") or new_id(collection)
        return self.backend.insert(collection, document)

    def get(self, collection: str, record_id: str) -> Record | None:
        return self.backend.get(collection, record_id)

    def require(self, collection: str, record_id: str) -> Record:
        record = self.get(collection, record_id)
        if record is None:
            raise OcError("not_found", f"unknown {collection} record: {record_id}", details={"collection": collection})
        return record

    def update(self, collection: str, record_id: str, **patch: Any) -> Record:
        return self.backend.update(collection, record_id, patch)

    def patch(self, collection: str, record_id: str, patch: Mapping[str, Any]) -> Record:
        return self.backend.update(collection, record_id, dict(patch))

    def delete(self, collection: str, record_id: str) -> None:
        self.backend.delete(collection, record_id)

    def list(
        self,
        collection: str,
        where: Mapping[str, Any] | None = None,
        order: str | None = None,
        limit: int = 0,
        offset: int = 0,
    ) -> list[Record]:
        return self.backend.list(collection, where, order, limit, offset)

    def count(self, collection: str, where: Mapping[str, Any] | None = None) -> int:
        return self.backend.count(collection, where)

    def find_one(self, collection: str, where: Mapping[str, Any] | None = None, order: str | None = None) -> Record | None:
        records = self.list(collection, where, order, limit=1)
        return records[0] if records else None

    def delete_where(self, collection: str, where: Mapping[str, Any]) -> int:
        records = self.list(collection, where)
        for record in records:
            self.delete(collection, record["id"])
        return len(records)

    def event(self, engagement_id: str, task_id: str | None, kind: str, message: str, **payload: Any) -> Record:
        return self.create(
            "events",
            engagement_id=engagement_id,
            task_id=task_id,
            kind=kind,
            message=message,
            payload=payload,
        )


def backend_from_env() -> Backend:
    """Pick Hanzo Base when configured, SQLite otherwise."""
    if os.environ.get("OPENCYBER_STATE_BACKEND", "").strip().lower() == "sqlite":
        return _sqlite_from_env()
    if os.environ.get("HANZO_BASE_URL") or os.environ.get("OPENCYBER_STATE_BACKEND", "").strip().lower() == "base":
        return BaseBackend()
    return _sqlite_from_env()


def _sqlite_from_env() -> SQLiteBackend:
    path = os.environ.get("OPENCYBER_STATE_DB", "")
    if not path:
        root = Path(os.environ.get("OPENCYBER_WORKSPACE", "/workspace")) / "state"
        root.mkdir(parents=True, exist_ok=True)
        path = str(root / "control.db")
    return SQLiteBackend(path)


_STORE: Store | None = None


def open_store(backend: Backend | None = None) -> Store:
    global _STORE
    if backend is not None:
        return Store(backend)
    if _STORE is None:
        _STORE = Store(backend_from_env())
    return _STORE


def reset_store(store: Store | None = None) -> None:
    """Test hook: forget the process-wide store."""
    global _STORE
    _STORE = store


def collections() -> Iterable[str]:
    return tuple(_COLLECTIONS)
