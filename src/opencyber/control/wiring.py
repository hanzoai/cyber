"""Native Hanzo wiring: IAM identity, KMS secrets and agentic sandbox launch.

Every mode fails closed. The local mode exists for hermetic testing and laptop
work; production uses the Hanzo SDKs or their canonical HTTP surfaces. Secret
values are never logged, persisted in control state, or returned by the API.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from ..errors import OcError


@dataclass(frozen=True)
class Principal:
    org: str
    user: str
    roles: tuple[str, ...] = ("operator",)
    mode: str = "local"

    @property
    def is_superadmin(self) -> bool:
        return self.org == "admin" and "superadmin" in self.roles


@dataclass
class IAMVerifier:
    token: str = ""
    url: str = ""
    org: str = ""
    user: str = ""

    def __post_init__(self) -> None:
        self.token = self.token or os.environ.get("OPENCYBER_CONTROL_TOKEN", "")
        self.url = (self.url or os.environ.get("HANZO_IAM_URL", "https://iam.hanzo.ai")).rstrip("/")
        self.org = self.org or os.environ.get("HANZO_ORG", "admin")
        self.user = self.user or os.environ.get("HANZO_USER", "operator@hanzo.ai")

    @property
    def mode(self) -> str:
        return "iam" if os.environ.get("OPENCYBER_IAM_MODE", "").strip().lower() in {"1", "true", "yes", "on", "remote"} else "local"

    def verify(self, token: str) -> Principal | None:
        if not token:
            return None
        if self.mode == "local":
            if not self.token or token != self.token:
                return None
            return Principal(org=self.org, user=self.user, mode="local")
        claims = self._verify_remote(token)
        if claims is None:
            return None
        org = str(claims.get("org") or claims.get("organization") or "")
        user = str(claims.get("email") or claims.get("sub") or "")
        if not org or not user:
            return None
        roles = tuple(str(role) for role in (claims.get("roles") or []) if isinstance(role, (str, int, float)))
        return Principal(org=org, user=user, roles=roles or ("operator",), mode="iam")

    def _verify_remote(self, token: str) -> dict[str, Any] | None:
        try:
            from hanzo_iam.tokens import verify  # type: ignore
        except ImportError:
            verify = None
        if verify is not None:
            result = verify(token)
            claims = getattr(result, "claims", None)
            return dict(claims) if claims else None
        import requests

        response = requests.post(
            self.url + "/v1/auth/introspect",
            json={"token": token},
            headers={"authorization": "Bearer " + token, "accept": "application/json"},
            timeout=10,
        )
        if response.status_code >= 400:
            return None
        payload = response.json()
        return payload if isinstance(payload, dict) else None

    def status(self) -> dict[str, Any]:
        return {"mode": self.mode, "url": self.url if self.mode == "iam" else "local shared token", "configured": bool(self.token) or self.mode == "iam"}


@dataclass
class KMSResolver:
    url: str = ""
    org: str = ""
    env: str = ""
    token: str = ""

    def __post_init__(self) -> None:
        self.url = (self.url or os.environ.get("HANZO_KMS_URL", "https://kms.hanzo.ai")).rstrip("/")
        self.org = self.org or os.environ.get("HANZO_KMS_ORG", "hanzo")
        self.env = self.env or os.environ.get("HANZO_KMS_ENV", "prod")
        self.token = self.token or os.environ.get("HANZO_API_KEY", "")

    def resolve(self, key_ref: str) -> str:
        ref = str(key_ref or "").strip()
        if not ref:
            return ""
        if ref.startswith("env:"):
            return os.environ.get(ref[4:], "")
        path, _, name = ref.partition("/")
        if not path or not name:
            return ""
        try:
            from hanzo_kms import KMSClient  # type: ignore

            return str(KMSClient().get_secret(path, name, env=self.env) or "")
        except ImportError:
            pass
        import requests

        response = requests.get(
            f"{self.url}/v1/secrets/{path}/{name}",
            params={"org": self.org, "env": self.env},
            headers={"authorization": "Bearer " + self.token, "accept": "application/json"},
            timeout=10,
        )
        if response.status_code >= 400:
            raise OcError("integration_unavailable", f"KMS refused {ref}", details={"status": response.status_code})
        return str((response.json() or {}).get("value") or "")

    def status(self) -> dict[str, Any]:
        return {"mode": "kms" if self.token else "env-only", "url": self.url, "org": self.org, "env": self.env, "configured": bool(self.token)}


@dataclass
class SandboxAdapter:
    """Launch into the agentic sandbox: local visor when configured, else platform."""

    url: str = ""
    token: str = ""
    platform: Any = None
    records: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.url = (self.url or os.environ.get("HANZO_SANDBOX_URL", "")).rstrip("/")

    @property
    def mode(self) -> str:
        return "visor" if self.url else "platform"

    def launch(self, spec: dict[str, Any]) -> dict[str, Any]:
        if self.url:
            import requests

            response = requests.post(
                self.url + "/v1/sandboxes",
                json=spec,
                headers={"authorization": "Bearer " + self.token, "accept": "application/json"},
                timeout=30,
            )
            if response.status_code >= 400:
                raise OcError("integration_unavailable", f"sandbox returned {response.status_code}")
            result = response.json()
        else:
            if self.platform is None:
                raise OcError("integration_unavailable", "no sandbox backend configured")
            result = self.platform.run(spec)
        record = {
            "id": str(result.get("id") or result.get("sandbox_id") or ""),
            "name": str(result.get("name") or spec.get("name") or ""),
            "url": str(result.get("url") or ""),
            "status": str(result.get("status") or "launching"),
            "mode": self.mode,
        }
        self.records.append(record)
        return record

    def status(self) -> dict[str, Any]:
        return {"mode": self.mode, "url": self.url or "platform.hanzo.ai", "launches": len(self.records), "configured": bool(self.url or self.platform)}
