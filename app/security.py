import os
import secrets
from fastapi import Header, HTTPException


def _keys(*names: str) -> list[str]:
    return [value for name in names if (value := os.getenv(name, "").strip())]


def _require(provided: str | None, accepted: list[str]) -> None:
    if accepted and not any(provided and secrets.compare_digest(provided, key) for key in accepted):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def require_ingest_key(x_api_key: str | None = Header(default=None)):
    _require(x_api_key, _keys("SIEM_API_KEY", "SIEM_INGEST_API_KEY", "SIEM_ADMIN_API_KEY"))


def require_analyst_key(x_api_key: str | None = Header(default=None)):
    _require(x_api_key, _keys("SIEM_API_KEY", "SIEM_ANALYST_API_KEY", "SIEM_ADMIN_API_KEY"))


def require_admin_key(x_api_key: str | None = Header(default=None)):
    _require(x_api_key, _keys("SIEM_API_KEY", "SIEM_ADMIN_API_KEY"))


def require_read_access(x_api_key: str | None = Header(default=None)):
    if os.getenv("SIEM_PROTECT_READS", "false").lower() in {"1", "true", "yes"}:
        accepted = _keys("SIEM_API_KEY", "SIEM_ANALYST_API_KEY", "SIEM_ADMIN_API_KEY")
        if not accepted:
            raise HTTPException(status_code=503, detail="Read protection is enabled but no analyst key is configured")
        _require(x_api_key, accepted)


def analyst_identity(x_analyst: str | None = Header(default=None)) -> str:
    return (x_analyst or "analyst")[:255]
