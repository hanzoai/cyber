"""LLM profiles, usage accounting, notification channels and templates.

The pool answers one question: which configured provider serves this call, and
what happens when it fails. Profiles carry an ordered priority, a failure
counter and a cooldown; worker rotation assigns successive intents across the
usable chain while planner calls keep the task's current profile.

Usage is recorded per call, never estimated after the fact. A budget check reads
the same ledger, so "spent" and "reported" cannot diverge.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .store import Store


PROVIDERS = ("hanzo", "anthropic", "openai", "openai_responses", "ollama")
NOTIFY_KINDS = ("generic", "telegram", "dingtalk", "feishu", "wecom", "email")
NOTIFY_STATES = ("pending", "sending", "sent", "failed", "skipped")
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# --- model profiles ---------------------------------------------------------

def create_profile(
    store: Store,
    name: str,
    *,
    provider: str = "hanzo",
    model: str = "enso-auto",
    base_url: str = "",
    key_ref: str = "",
    priority: int = 100,
    pool_enabled: bool = True,
    rate_per_second: float = 0,
    rate_per_minute: int = 0,
    context_k: int = 0,
    reasoning: bool = False,
    max_output_tokens: int = 0,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    if provider not in PROVIDERS:
        raise ValueError(f"unknown provider {provider!r}; choose from {list(PROVIDERS)}")
    if not name.strip():
        raise ValueError("profile name must not be empty")
    return store.create(
        "models",
        name=name.strip(),
        provider=provider,
        model=model,
        base_url=base_url.rstrip("/"),
        key_ref=key_ref,
        priority=priority,
        pool_enabled=pool_enabled,
        rate_per_second=rate_per_second,
        rate_per_minute=rate_per_minute,
        context_k=context_k,
        reasoning=reasoning,
        max_output_tokens=max_output_tokens,
        headers=headers or {},
        failures=0,
        cooldown_until="",
        last_error="",
        active=False,
    )


def update_profile(store: Store, profile_id: str, **patch: Any) -> dict[str, Any]:
    allowed = {
        "name", "provider", "model", "base_url", "key_ref", "priority", "pool_enabled",
        "rate_per_second", "rate_per_minute", "context_k", "reasoning", "max_output_tokens", "headers",
    }
    unknown = set(patch) - allowed
    if unknown:
        raise ValueError(f"fields cannot be edited: {sorted(unknown)}")
    return store.update("models", profile_id, **patch)


def activate(store: Store, profile_id: str) -> dict[str, Any]:
    store.require("models", profile_id)
    for other in store.list("models", {"active": True}):
        if other["id"] != profile_id:
            store.update("models", other["id"], active=False)
    return store.update("models", profile_id, active=True)


def list_profiles(store: Store) -> list[dict[str, Any]]:
    return store.list("models", {}, order="priority")


def _cooldown_active(profile: dict[str, Any]) -> bool:
    until = profile.get("cooldown_until") or ""
    if not until:
        return False
    try:
        return datetime.fromisoformat(until.replace("Z", "+00:00")) > datetime.now(timezone.utc)
    except ValueError:
        return False


def usable(store: Store) -> list[dict[str, Any]]:
    return [profile for profile in list_profiles(store) if profile.get("pool_enabled", True) and not _cooldown_active(profile)]


def record_failure(store: Store, profile_id: str, error: str, *, cooldown_seconds: int = 60) -> dict[str, Any]:
    profile = store.require("models", profile_id)
    failures = int(profile.get("failures") or 0) + 1
    cooldown = min(3600, cooldown_seconds * (2 ** (failures - 1)))
    until = (datetime.now(timezone.utc) + timedelta(seconds=cooldown)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return store.update("models", profile_id, failures=failures, last_error=error[:500], cooldown_until=until)


def record_success(store: Store, profile_id: str) -> dict[str, Any]:
    return store.update("models", profile_id, failures=0, last_error="", cooldown_until="")


class Rotation:
    """Round-robin over the usable chain, restarting on process start.

    The cursor is in memory, matching the documented behavior: saving the chain
    does not reset it, a restart does.
    """

    def __init__(self) -> None:
        self._cursor = 0

    def pick(self, profiles: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not profiles:
            return None
        profile = profiles[self._cursor % len(profiles)]
        self._cursor += 1
        return profile

    def reset(self) -> None:
        self._cursor = 0


def task_chain(store: Store, task: dict[str, Any]) -> list[dict[str, Any]]:
    ids = list(task.get("llm_profile_ids") or [])
    resolved: list[dict[str, Any]] = []
    for profile_id in ids:
        profile = store.get("models", profile_id)
        if profile is not None:
            resolved.append(profile)
    return resolved if resolved else usable(store)


# --- usage ledger -----------------------------------------------------------

def account(
    store: Store,
    engagement_id: str,
    task_id: str,
    *,
    intent_id: str | None = None,
    profile: dict[str, Any] | None = None,
    model: str = "",
    input_tokens: int = 0,
    output_tokens: int = 0,
    cache_read: int = 0,
    cache_write: int = 0,
    latency_ms: int = 0,
    status: str = "ok",
) -> dict[str, Any]:
    return store.create(
        "usage",
        engagement_id=engagement_id,
        task_id=task_id,
        intent_id=intent_id,
        profile_id=(profile or {}).get("id"),
        profile_name=(profile or {}).get("name"),
        provider=(profile or {}).get("provider"),
        model=model or (profile or {}).get("model", ""),
        input_tokens=max(0, int(input_tokens)),
        output_tokens=max(0, int(output_tokens)),
        cache_read=max(0, int(cache_read)),
        cache_write=max(0, int(cache_write)),
        total_tokens=max(0, int(input_tokens) + int(output_tokens)),
        latency_ms=max(0, int(latency_ms)),
        status=status,
    )


def usage_summary(store: Store, *, task_id: str | None = None, engagement_id: str | None = None) -> dict[str, Any]:
    where: dict[str, Any] = {}
    if task_id:
        where["task_id"] = task_id
    if engagement_id:
        where["engagement_id"] = engagement_id
    records = store.list("usage", where)
    totals: dict[str, Any] = {
        "input_tokens": sum(int(item.get("input_tokens") or 0) for item in records),
        "output_tokens": sum(int(item.get("output_tokens") or 0) for item in records),
        "cache_read": sum(int(item.get("cache_read") or 0) for item in records),
        "cache_write": sum(int(item.get("cache_write") or 0) for item in records),
        "calls": len(records),
    }
    totals["total_tokens"] = totals["input_tokens"] + totals["output_tokens"]
    denominator = totals["input_tokens"] + totals["cache_read"]
    totals["cache_hit_rate"] = round(totals["cache_read"] / denominator, 4) if denominator else 0.0
    by_model: dict[str, dict[str, Any]] = {}
    for item in records:
        entry: dict[str, Any] = by_model.setdefault(str(item.get("model") or "unknown"), {"model": item.get("model"), "calls": 0, "input_tokens": 0, "output_tokens": 0, "cache_read": 0})
        entry["calls"] += 1
        entry["input_tokens"] += int(item.get("input_tokens") or 0)
        entry["output_tokens"] += int(item.get("output_tokens") or 0)
        entry["cache_read"] += int(item.get("cache_read") or 0)
    totals["by_model"] = sorted(by_model.values(), key=lambda entry: -entry["input_tokens"] - entry["output_tokens"])
    return totals


def daily_usage(store: Store, *, days: int = 30, engagement_id: str | None = None) -> list[dict[str, Any]]:
    where: dict[str, Any] = {}
    if engagement_id:
        where["engagement_id"] = engagement_id
    buckets: dict[str, dict[str, Any]] = {}
    for item in store.list("usage", where):
        day = str(item.get("created", ""))[:10]
        bucket = buckets.setdefault(day, {"date": day, "input": 0, "output": 0, "cache": 0})
        bucket["input"] += int(item.get("input_tokens") or 0)
        bucket["output"] += int(item.get("output_tokens") or 0)
        bucket["cache"] += int(item.get("cache_read") or 0)
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    return [buckets[day] for day in sorted(buckets) if day >= cutoff]


# --- notification channels --------------------------------------------------

def create_channel(
    store: Store,
    name: str,
    kind: str,
    config: dict[str, Any],
    *,
    min_severity: str = "high",
    enabled: bool = True,
    digest_seconds: int = 0,
    rate_limit_seconds: int = 0,
    include_classes: list[str] | None = None,
    exclude_classes: list[str] | None = None,
) -> dict[str, Any]:
    if kind not in NOTIFY_KINDS:
        raise ValueError(f"unknown channel kind {kind!r}; choose from {list(NOTIFY_KINDS)}")
    if min_severity not in SEVERITY_ORDER:
        raise ValueError(f"unknown severity {min_severity!r}")
    return store.create(
        "notifications",
        record_type="channel",
        name=name,
        channel_kind=kind,
        config=config,
        min_severity=min_severity,
        enabled=enabled,
        digest_seconds=max(0, int(digest_seconds)),
        rate_limit_seconds=max(0, int(rate_limit_seconds)),
        include_classes=include_classes or [],
        exclude_classes=exclude_classes or [],
    )


def list_channels(store: Store) -> list[dict[str, Any]]:
    return store.list("notifications", {"record_type": "channel"}, order="created")


def _channel_accepts(channel: dict[str, Any], finding: dict[str, Any]) -> bool:
    if not channel.get("enabled", True):
        return False
    if SEVERITY_ORDER.get(finding.get("severity", "info"), 0) < SEVERITY_ORDER.get(channel.get("min_severity", "high"), 3):
        return False
    text = f"{finding.get('title', '')} {finding.get('vulnerability', '')}".lower()
    if any(str(token).lower() in text for token in channel.get("exclude_classes") or []):
        return False
    include = channel.get("include_classes") or []
    if include and not any(str(token).lower() in text for token in include):
        return False
    return True


def _payload(channel: dict[str, Any], finding: dict[str, Any], base_url: str) -> dict[str, Any]:
    text = (
        f"[{finding.get('severity', 'info').upper()}] {finding.get('title')}\n"
        f"Task: {finding.get('task_id')}\n{finding.get('summary', '')}"
    )
    kind = channel["channel_kind"]
    if kind == "telegram":
        return {"chat_id": (channel.get("config") or {}).get("chat_id"), "text": text}
    if kind in ("dingtalk", "feishu", "wecom"):
        return {"msgtype": "text", "text": {"content": text}}
    if kind == "email":
        return {"to": (channel.get("config") or {}).get("to"), "subject": finding.get("title"), "text": text}
    return {"text": text, "finding_id": finding.get("id"), "url": f"{base_url}/#/findings/{finding.get('id')}"}


def dispatch(
    store: Store,
    finding: dict[str, Any],
    *,
    base_url: str = "",
    send: Any = None,
) -> dict[str, Any]:
    """Queue and deliver a finding to every accepting channel."""
    queued = []
    for channel in list_channels(store):
        if not _channel_accepts(channel, finding):
            continue
        delivery = store.create(
            "notifications",
            record_type="delivery",
            channel_id=channel["id"],
            channel_kind=channel["channel_kind"],
            finding_id=finding["id"],
            task_id=finding["task_id"],
            status="pending",
            attempts=0,
            error="",
            payload=_payload(channel, finding, base_url),
        )
        queued.append(_deliver(store, channel, delivery, send=send))
    return {"queued": len(queued), "deliveries": queued}


def _deliver(store: Store, channel: dict[str, Any], delivery: dict[str, Any], *, send: Any = None) -> dict[str, Any]:
    target = str((channel.get("config") or {}).get("url") or "")
    if channel["channel_kind"] == "email":
        return store.update("notifications", delivery["id"], status="skipped", error="email delivery requires a configured SMTP relay")
    if send is not None:
        exporter = send
    elif channel["channel_kind"] == "telegram":
        token = str((channel.get("config") or {}).get("bot_token") or "")
        exporter = lambda url, payload: __import__("requests").post(  # noqa: E731
            f"https://api.telegram.org/bot{token}/sendMessage", json=payload, timeout=10
        )
        target = "telegram"
    else:
        exporter = lambda url, payload: __import__("requests").post(url, json=payload, timeout=10)  # noqa: E731
    if not target:
        return store.update("notifications", delivery["id"], status="skipped", error="channel has no target URL")
    try:
        response = exporter(target, delivery["payload"])
        status = int(getattr(response, "status_code", 200))
        if status >= 400:
            raise RuntimeError(f"channel answered {status}")
        return store.update("notifications", delivery["id"], status="sent", attempts=1, sent_at=_now())
    except Exception as exc:  # noqa: BLE001 - delivery failures are recorded, not raised
        return store.update("notifications", delivery["id"], status="failed", attempts=1, error=str(exc)[:500])


def retry_failed(store: Store, *, send: Any = None) -> dict[str, Any]:
    channels = {channel["id"]: channel for channel in list_channels(store)}
    retried = []
    for delivery in store.list("notifications", {"record_type": "delivery", "status": "failed"}):
        channel = channels.get(delivery.get("channel_id"))
        if channel:
            retried.append(_deliver(store, channel, delivery, send=send))
    return {"retried": len(retried), "deliveries": retried}


# --- templates --------------------------------------------------------------

def create_template(store: Store, name: str, goal: str, **fields: Any) -> dict[str, Any]:
    return store.create("templates", name=name, goal=goal, **fields)


def list_templates(store: Store) -> list[dict[str, Any]]:
    return store.list("templates", {}, order="name")


def apply_template(store: Store, template_id: str) -> dict[str, Any]:
    return store.require("templates", template_id)


# --- settings ---------------------------------------------------------------

def set_setting(store: Store, key: str, value: Any, engagement_id: str = "") -> dict[str, Any]:
    existing = store.find_one("settings", {"kind": "setting", "key": key, "engagement_id": engagement_id})
    if existing:
        return store.update("settings", existing["id"], value=value)
    return store.create("settings", kind="setting", key=key, value=value, engagement_id=engagement_id)


def get_setting(store: Store, key: str, default: Any = None, engagement_id: str = "") -> Any:
    existing = store.find_one("settings", {"kind": "setting", "key": key, "engagement_id": engagement_id})
    return existing["value"] if existing else default


def all_settings(store: Store, engagement_id: str = "") -> dict[str, Any]:
    return {
        item["key"]: item["value"]
        for item in store.list("settings", {"kind": "setting", "engagement_id": engagement_id})
    }


def _now() -> str:
    from .store import now

    return now()
