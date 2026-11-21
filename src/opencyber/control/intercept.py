"""Pre-execution interception: rules, approvals and the target blocklist.

Every worker tool call is matched against ordered rules before it runs. A rule
matches a tool name or the tool input by ``string``, ``regex`` or ``argv``
prefix, and answers ``allow``, ``block`` or ``ask``. The first match wins; an
unmatched call takes the configured default policy.

The argv form is deliberately narrow, because approving ``git push`` must not
approve ``git push --force`` hidden behind a pipeline: it matches only a single
simple command whose parsed prefix equals the pattern exactly. Pipes, lists,
redirections, assignments, subshells, background jobs, wrapper programs and
command/parameter substitutions never match an argv rule.
"""

from __future__ import annotations

import json
import re
import shlex
from typing import Any, Iterable

from ..errors import OcError
from .store import Store


RULE_TARGETS = ("tool_name", "tool_input")
RULE_KINDS = ("string", "regex", "argv")
POLICIES = ("allow", "block", "ask")
DECIDED_BY = ("human", "rule", "model", "system")

_WRAPPERS = {
    "sudo", "doas", "runuser", "env", "timeout", "nice", "ionice", "nohup", "xargs", "watch",
    "sh", "bash", "zsh", "dash", "ksh", "ash", "eval", "exec", "command", "builtin",
    "parallel", "stdbuf", "time", "flock", "chroot", "setsid", "script",
}
_META = {"|", "||", "&&", "&", ";", ";;", ">", ">>", "<", "<<", ">&", "<&", "(", ")", "{", "}"}
_EXPANSION = re.compile(r"[$`*?\[\]{}~]")

DEFAULT_POLICY = "allow"


def parse_simple_argv(script: str) -> list[str] | None:
    """Return argv only for one simple command with no shell metacharacters.

    ``None`` means the text is not a single simple command, so an argv rule must
    not be applied to it.
    """
    if not isinstance(script, str) or not script.strip():
        return None
    if "\n" in script or "\r" in script or "\\" in script:
        return None
    lexer = shlex.shlex(script, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    if not tokens:
        return None
    for token in tokens:
        if token in _META:
            return None
        if any(char in token for char in "|&;<>()"):
            return None
    if any(token == "" for token in tokens):
        return None
    first = tokens[0]
    if "=" in first and not first.startswith("-"):
        return None
    if first.lower() in _WRAPPERS:
        return None
    if any(_EXPANSION.search(token) for token in tokens):
        return None
    return tokens


def argv_prefix(argv: list[str], length: int) -> list[str]:
    return [token.lower() for token in argv[:length]]


def _rule_pattern(rule: dict[str, Any]) -> Any:
    return rule.get("pattern") or ""


def rule_matches(rule: dict[str, Any], tool: str, arguments: dict[str, Any]) -> bool:
    if not rule.get("enabled", True):
        return False
    kind = rule.get("match_kind") or rule.get("kind", "string")
    target = rule.get("target", "tool_name")
    pattern = _rule_pattern(rule)
    if kind == "argv":
        if tool not in {"oc_bash", "oc_execute", "bash"}:
            return False
        script = str(arguments.get("script") or arguments.get("command") or "")
        argv = parse_simple_argv(script)
        if argv is None:
            return False
        try:
            wanted = json.loads(pattern) if isinstance(pattern, str) else list(pattern)
        except (ValueError, TypeError):
            return False
        if not isinstance(wanted, list) or not 1 <= len(wanted) <= 8:
            return False
        return argv_prefix(argv, len(wanted)) == [str(token).lower() for token in wanted]
    haystack = tool if target == "tool_name" else json.dumps(arguments, sort_keys=True, default=str)
    if kind == "string":
        return str(pattern) in haystack
    if kind == "regex":
        try:
            return re.search(str(pattern), haystack) is not None
        except re.error:
            return False
    return False


def _ordered_rules(store: Store, engagement_id: str) -> list[dict[str, Any]]:
    rules = store.list("settings", {"kind": "intercept_rule", "engagement_id": engagement_id}, order="-priority")
    rules.extend(store.list("settings", {"kind": "intercept_rule", "engagement_id": ""}, order="-priority"))
    rules.sort(key=lambda rule: int(rule.get("priority", 0)), reverse=True)
    return rules


def default_policy(store: Store, engagement_id: str) -> str:
    setting = store.find_one("settings", {"kind": "intercept_default", "engagement_id": engagement_id})
    if setting and setting.get("value") in POLICIES:
        return str(setting["value"])
    return DEFAULT_POLICY


def set_default_policy(store: Store, engagement_id: str, policy: str) -> dict[str, Any]:
    if policy not in POLICIES:
        raise ValueError(f"unknown policy {policy!r}")
    setting = store.find_one("settings", {"kind": "intercept_default", "engagement_id": engagement_id})
    if setting:
        return store.update("settings", setting["id"], value=policy)
    return store.create("settings", kind="intercept_default", engagement_id=engagement_id, value=policy)


def add_rule(
    store: Store,
    engagement_id: str,
    name: str,
    *,
    target: str = "tool_name",
    kind: str = "string",
    pattern: str = "",
    policy: str = "ask",
    priority: int = 0,
    enabled: bool = True,
    note: str = "",
    timeout_seconds: int = 0,
    timeout_action: str = "deny",
) -> dict[str, Any]:
    if target not in RULE_TARGETS:
        raise ValueError(f"unknown rule target {target!r}")
    if kind not in RULE_KINDS:
        raise ValueError(f"unknown rule kind {kind!r}")
    if policy not in POLICIES:
        raise ValueError(f"unknown policy {policy!r}")
    if kind == "regex":
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex: {exc}") from exc
    if kind == "argv":
        try:
            tokens = json.loads(pattern) if isinstance(pattern, str) else pattern
        except ValueError as exc:
            raise ValueError("an argv rule pattern must be a JSON array of 1 to 8 tokens") from exc
        if not isinstance(tokens, list) or not 1 <= len(tokens) <= 8 or not all(isinstance(token, str) for token in tokens):
            raise ValueError("an argv rule pattern must be a JSON array of 1 to 8 tokens")
        pattern = json.dumps(tokens)
    return store.create(
        "settings",
        kind="intercept_rule",
        engagement_id=engagement_id,
        name=name,
        target=target,
        match_kind=kind,
        pattern=pattern,
        policy=policy,
        priority=priority,
        enabled=enabled,
        note=note,
        timeout_seconds=max(0, int(timeout_seconds)),
        timeout_action=timeout_action if timeout_action in {"allow", "deny"} else "deny",
    )


def _rule_view(rule: dict[str, Any]) -> dict[str, Any]:
    view = dict(rule)
    view["kind"] = rule.get("match_kind", "string")
    return view


def list_rules(store: Store, engagement_id: str) -> list[dict[str, Any]]:
    return [_rule_view(rule) for rule in _ordered_rules(store, engagement_id)]


def evaluate(store: Store, engagement_id: str, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    for rule in _ordered_rules(store, engagement_id):
        if rule_matches(rule, tool, arguments):
            return {
                "policy": rule.get("policy", "ask"),
                "rule": _rule_view(rule),
                "matched": True,
                "reason": f"matched rule {rule.get('name')!r}",
            }
    policy = default_policy(store, engagement_id)
    return {"policy": policy, "rule": None, "matched": False, "reason": f"default policy {policy}"}


def gate(
    store: Store,
    engagement_id: str,
    task_id: str,
    tool: str,
    arguments: dict[str, Any],
    *,
    decided_by: str = "rule",
) -> dict[str, Any]:
    """Evaluate one call and record an approval when the answer is ``ask``.

    Returns ``{"decision": allow|deny|pending, "approval": record|None,
    "rule": ...}``. A pending call must not execute; the caller polls
    :func:`decide` or refuses the step.
    """
    decision = evaluate(store, engagement_id, tool, arguments)
    record = store.create(
        "approvals",
        engagement_id=engagement_id,
        task_id=task_id,
        tool=tool,
        arguments=arguments,
        status="pending" if decision["policy"] == "ask" else ("approved" if decision["policy"] == "allow" else "denied"),
        decision=decision["policy"],
        decided_by=decided_by if decision["policy"] != "ask" else "",
        rule_id=(decision["rule"] or {}).get("id"),
        rule_name=(decision["rule"] or {}).get("name"),
        reason=decision["reason"],
        note=(decision["rule"] or {}).get("note", ""),
        timeout_seconds=int((decision["rule"] or {}).get("timeout_seconds") or 0),
        timeout_action=(decision["rule"] or {}).get("timeout_action") or "deny",
    )
    if decision["policy"] == "ask":
        return {"decision": "pending", "approval": record, "rule": decision["rule"], "reason": decision["reason"]}
    return {
        "decision": "allow" if decision["policy"] == "allow" else "deny",
        "approval": record,
        "rule": decision["rule"],
        "reason": decision["reason"],
    }


def decide(
    store: Store,
    approval_id: str,
    approved: bool,
    *,
    decided_by: str = "human",
    reason: str = "",
) -> dict[str, Any]:
    if decided_by not in DECIDED_BY:
        raise ValueError(f"unknown decision source {decided_by!r}")
    approval = store.require("approvals", approval_id)
    if approval.get("status") != "pending":
        raise OcError(
            "already_exists",
            f"approval {approval_id} is already {approval.get('status')}",
            details={"approval_id": approval_id, "status": approval.get("status")},
        )
    return store.update(
        "approvals",
        approval_id,
        status="approved" if approved else "denied",
        decision="allow" if approved else "block",
        decided_by=decided_by,
        decided_reason=reason,
        decided_at=_now(),
    )


def batch_decide(store: Store, approval_ids: Iterable[str], approved: bool, decided_by: str = "human") -> dict[str, Any]:
    results, failures = [], []
    for approval_id in approval_ids:
        try:
            results.append(decide(store, approval_id, approved, decided_by=decided_by))
        except (OcError, ValueError) as exc:
            failures.append({"approval_id": approval_id, "error": str(exc)})
    return {"decided": results, "failed": failures}


def pending(store: Store, engagement_id: str | None = None, task_id: str | None = None) -> list[dict[str, Any]]:
    where: dict[str, Any] = {"status": "pending"}
    if engagement_id:
        where["engagement_id"] = engagement_id
    if task_id:
        where["task_id"] = task_id
    return store.list("approvals", where, order="-created")


def history(
    store: Store,
    engagement_id: str | None = None,
    task_id: str | None = None,
    limit: int = 0,
    offset: int = 0,
) -> dict[str, Any]:
    where: dict[str, Any] = {}
    if engagement_id:
        where["engagement_id"] = engagement_id
    if task_id:
        where["task_id"] = task_id
    return {
        "records": store.list("approvals", where, order="-created", limit=limit, offset=offset),
        "total": store.count("approvals", where),
    }


def always_allow_prefix(script: str, tokens: int = 2) -> str | None:
    """The argv prefix an operator can save from an approved Bash call."""
    argv = parse_simple_argv(script)
    if not argv:
        return None
    return json.dumps(argv[: max(1, min(tokens, len(argv)))])


# --- target blocklist -------------------------------------------------------

BLOCKLIST_KINDS = ("exact_domain", "fuzzy_domain", "exact_ip", "fuzzy_ip", "exact_url", "fuzzy_url", "cidr")


def add_blocked_target(
    store: Store,
    engagement_id: str,
    kind: str,
    pattern: str,
    *,
    note: str = "",
    enabled: bool = True,
    builtin: bool = False,
) -> dict[str, Any]:
    if kind not in BLOCKLIST_KINDS:
        raise ValueError(f"unknown blocklist kind {kind!r}")
    return store.create(
        "settings",
        kind="blocked_target",
        engagement_id=engagement_id,
        match_kind=kind,
        pattern=pattern.strip(),
        note=note,
        enabled=enabled,
        builtin=builtin,
    )


def list_blocked_targets(store: Store, engagement_id: str) -> list[dict[str, Any]]:
    records = store.list("settings", {"kind": "blocked_target", "engagement_id": engagement_id}, order="-created")
    return records


def blocked_target(
    store: Store,
    engagement_id: str,
    host: str,
    url: str = "",
) -> dict[str, Any] | None:
    import ipaddress

    host = (host or "").lower().rstrip(".")
    url = (url or "").lower()
    for item in store.list("settings", {"kind": "blocked_target", "engagement_id": engagement_id, "enabled": True}):
        kind, pattern = item.get("match_kind"), str(item.get("pattern") or "").lower().rstrip(".")
        matched = False
        if kind in ("exact_domain", "exact_ip"):
            matched = host == pattern
        elif kind == "fuzzy_domain":
            matched = host == pattern or host.endswith("." + pattern)
        elif kind == "fuzzy_ip":
            matched = host == pattern or host.startswith(pattern)
        elif kind in ("exact_url", "fuzzy_url"):
            matched = url == pattern if kind == "exact_url" else pattern in url
        elif kind == "cidr":
            try:
                matched = ipaddress.ip_address(host) in ipaddress.ip_network(pattern, strict=False)
            except ValueError:
                matched = False
        if matched:
            return item
    return None


def _now() -> str:
    from .store import now

    return now()
