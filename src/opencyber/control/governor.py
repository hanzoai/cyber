"""Per-target request governor.

Autonomous assessment multiplies request volume, so every outbound call to a
target passes the same governor: a per-host token bucket, a burst ceiling, an
in-flight cap, jitter, exponential backoff after 429/503, and a short cache for
idempotent GETs.

Profiles are ``quiet``, ``balanced`` and ``aggressive`` (``off`` disables the
governor). ``OPENCYBER_NOISE_PROFILE`` selects the default; a caller may pass a
profile explicitly. The governor is process-wide per host, so the HTTP tool, the
browser and traffic replay share one budget instead of each opening its own.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import os
import random
import threading
import time
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

from ..errors import OcError


@dataclass(frozen=True, slots=True)
class Profile:
    name: str
    rate: float  # sustained requests per second per host
    burst: int  # bucket capacity
    inflight: int  # concurrent requests per host
    jitter: float  # fraction of the inter-request interval, 0..1
    backoff_base: float
    backoff_max: float
    cache_ttl: float

    def describe(self) -> dict[str, Any]:
        return {
            "profile": self.name,
            "requests_per_second": self.rate,
            "burst": self.burst,
            "inflight": self.inflight,
            "jitter": self.jitter,
            "backoff_base_seconds": self.backoff_base,
            "backoff_max_seconds": self.backoff_max,
            "get_cache_seconds": self.cache_ttl,
        }


PROFILES: dict[str, Profile] = {
    "off": Profile("off", 0.0, 0, 0, 0.0, 0.0, 0.0, 0.0),
    "quiet": Profile("quiet", 0.5, 1, 1, 0.35, 2.0, 60.0, 30.0),
    "balanced": Profile("balanced", 2.0, 4, 4, 0.15, 1.0, 30.0, 10.0),
    "aggressive": Profile("aggressive", 10.0, 20, 16, 0.0, 0.5, 15.0, 0.0),
}

ENV_PROFILE = "OPENCYBER_NOISE_PROFILE"


def profile_from_env() -> Profile:
    name = os.environ.get(ENV_PROFILE, "balanced").strip().lower() or "balanced"
    if name not in PROFILES:
        raise OcError(
            "invalid_argument",
            f"unknown noise profile {name!r}; choose from {sorted(PROFILES)}",
            details={"parameter": ENV_PROFILE},
        )
    return PROFILES[name]


def host_of(url: str) -> str:
    parts = urlsplit(url)
    return (parts.hostname or "").lower()


@dataclass
class _HostState:
    tokens: float
    stamp: float
    first: float
    inflight: int = 0
    blocked_until: float = 0.0
    strikes: int = 0
    served: int = 0
    peak_rate: float = 0.0
    duplicates: int = 0
    cache: dict[str, tuple[float, Any]] = field(default_factory=dict)


class Governor:
    """Thread-safe token bucket plus in-flight gate, keyed by host."""

    def __init__(
        self,
        profile: Profile | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,
    ) -> None:
        self.profile = profile or profile_from_env()
        self._clock = clock
        self._sleep = sleep
        self._random = random_source
        self._lock = threading.Lock()
        self._hosts: dict[str, _HostState] = {}

    @property
    def enabled(self) -> bool:
        return self.profile.name != "off" and self.profile.rate > 0

    def _state(self, host: str) -> _HostState:
        state = self._hosts.get(host)
        if state is None:
            current = self._clock()
            state = _HostState(tokens=float(self.profile.burst), stamp=current, first=current)
            self._hosts[host] = state
        return state

    def _take_token(self, host: str, state: _HostState) -> float:
        """Return seconds the caller must wait before sending."""
        current = self._clock()
        elapsed = max(0.0, current - state.stamp)
        state.tokens = min(float(self.profile.burst), state.tokens + elapsed * self.profile.rate)
        state.stamp = current
        if state.tokens >= 1.0:
            state.tokens -= 1.0
            return 0.0
        return (1.0 - state.tokens) / self.profile.rate

    @contextmanager
    def slot(self, url: str) -> Iterator[dict[str, Any]]:
        """Reserve a request slot for ``url``; yields the decision record."""
        host = host_of(url)
        if not self.enabled or not host:
            yield {"governed": False, "host": host}
            return
        decision: dict[str, Any] = {"governed": True, "host": host, "profile": self.profile.name}
        while True:
            with self._lock:
                state = self._state(host)
                current = self._clock()
                blocked = state.blocked_until - current
                if blocked <= 0:
                    wait = self._take_token(host, state)
                    if wait <= 0 and state.inflight < self.profile.inflight:
                        state.inflight += 1
                        state.served += 1
                        elapsed = max(current - state.first, 1e-9)
                        state.peak_rate = max(state.peak_rate, state.served / elapsed)
                        break
                    if wait <= 0:
                        wait = 0.05
                else:
                    wait = min(blocked, 1.0)
            self._sleep(min(wait, 5.0))
        if self.profile.jitter:
            delay = self._random() * self.profile.jitter
            if delay > 0:
                self._sleep(delay)
                decision["jitter_seconds"] = round(delay, 3)
        try:
            yield decision
        finally:
            with self._lock:
                state.inflight = max(0, state.inflight - 1)

    def observe(self, url: str, status: int) -> dict[str, Any]:
        """Record a response; 429/503 raise a backoff for the host."""
        host = host_of(url)
        if not self.enabled or not host:
            return {"governed": False}
        with self._lock:
            state = self._state(host)
            if status in (429, 503):
                state.strikes += 1
                delay = min(self.profile.backoff_max, self.profile.backoff_base * (2 ** (state.strikes - 1)))
                state.blocked_until = self._clock() + delay
                return {"governed": True, "host": host, "backoff_seconds": delay, "strikes": state.strikes}
            state.strikes = 0
            state.blocked_until = 0.0
        return {"governed": True, "host": host, "backoff_seconds": 0.0}

    def cached(self, key: str, host: str) -> Any | None:
        if not self.enabled or self.profile.cache_ttl <= 0:
            return None
        with self._lock:
            state = self._hosts.get(host)
            if not state:
                return None
            entry = state.cache.get(key)
            if entry is None:
                return None
            stamp, value = entry
            if self._clock() - stamp > self.profile.cache_ttl:
                state.cache.pop(key, None)
                return None
            state.duplicates += 1
            return value

    def remember(self, key: str, host: str, value: Any) -> None:
        if not self.enabled or self.profile.cache_ttl <= 0:
            return
        with self._lock:
            state = self._state(host)
            state.cache[key] = (self._clock(), value)
            if len(state.cache) > 256:
                oldest = min(state.cache, key=lambda item: state.cache[item][0])
                state.cache.pop(oldest, None)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            hosts = {
                host: {
                    "served": state.served,
                    "inflight": state.inflight,
                    "peak_rate_per_second": round(state.peak_rate, 3),
                    "strikes": state.strikes,
                    "backoff_seconds": round(max(0.0, state.blocked_until - self._clock()), 3),
                    "cached_answers": state.duplicates,
                }
                for host, state in sorted(self._hosts.items())
            }
        return {"profile": self.profile.describe(), **({"hosts": hosts} if hosts else {})}

    def reset(self) -> None:
        with self._lock:
            self._hosts.clear()


_GOVERNOR: Governor | None = None
_GOVERNOR_LOCK = threading.Lock()


def governor() -> Governor:
    """The process-wide governor, created on first use from the environment."""
    global _GOVERNOR
    if _GOVERNOR is None:
        with _GOVERNOR_LOCK:
            if _GOVERNOR is None:
                _GOVERNOR = Governor()
    return _GOVERNOR


def reset_governor(value: Governor | None = None) -> None:
    global _GOVERNOR
    with _GOVERNOR_LOCK:
        _GOVERNOR = value


def low_and_slow_flags(profile: Profile | None = None) -> dict[str, str]:
    """Scanner flags that keep automated tools inside the selected profile.

    The strings are advisory argv fragments an agent may pass to the installed
    scanners; they never replace the governor, which is what actually limits
    request volume.
    """
    selected = profile or profile_from_env()
    if not selected.name or selected.name == "off":
        return {}
    if selected.name == "quiet":
        return {"nmap": "-T2", "ffuf": "-rate 5 -p 1", "nuclei": "-rate-limit 5 -bulk-size 1", "httpx": "-rl 5"}
    if selected.name == "balanced":
        return {"nmap": "-T3", "ffuf": "-rate 20 -p 2", "nuclei": "-rate-limit 20 -bulk-size 5", "httpx": "-rl 20"}
    return {"nmap": "-T4", "ffuf": "-rate 100 -p 10", "nuclei": "-rate-limit 100 -bulk-size 25", "httpx": "-rl 100"}
