"""Cấu hình engine, đọc từ biến môi trường (xem .env.example ở thư mục gốc)."""

from __future__ import annotations

import os
from dataclasses import dataclass

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw else default


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    return float(raw) if raw else default


def _severity(name: str, default: str) -> str:
    value = (os.getenv(name) or default).strip().lower()
    if value not in SEVERITY_ORDER:
        raise ValueError(f"{name} phải là một trong {SEVERITY_ORDER}, nhận được {value!r}")
    return value


@dataclass(frozen=True)
class Settings:
    db_path: str = "sentinel.db"
    api_token: str = ""

    vt_api_key: str = ""
    vt_base_url: str = "https://www.virustotal.com/api/v3"
    vt_rate_per_minute: int = 4
    vt_daily_quota: int = 500
    vt_max_wait_seconds: float = 20.0
    vt_cache_ttl_hours: float = 24.0
    vt_not_found_ttl_hours: float = 2.0
    vt_fetch_mitre: bool = True

    ollama_url: str = ""
    ollama_model: str = "qwen2.5:3b"
    ollama_timeout: float = 60.0

    claude_enabled: bool = False
    claude_model: str = "claude-opus-5-5"
    claude_effort: str = "medium"
    claude_redact: bool = True

    alert_email_to: str = ""
    action_base_url: str = "http://localhost:5678/webhook/sentinel-action"
    action_secret: str = ""
    action_token_ttl_hours: float = 24.0

    notify_min_severity: str = "medium"
    escalate_min_severity: str = "high"
    dedup_window_seconds: int = 600

    @classmethod
    def from_env(cls) -> "Settings":
        anthropic_key = os.getenv("ANTHROPIC_API_KEY", "")
        return cls(
            db_path=os.getenv("SENTINEL_DB_PATH", "sentinel.db"),
            api_token=os.getenv("SENTINEL_API_TOKEN", ""),
            vt_api_key=os.getenv("VT_API_KEY", ""),
            vt_base_url=os.getenv("VT_BASE_URL", "https://www.virustotal.com/api/v3"),
            vt_rate_per_minute=_int("VT_RATE_PER_MINUTE", 4),
            vt_daily_quota=_int("VT_DAILY_QUOTA", 500),
            vt_max_wait_seconds=_float("VT_MAX_WAIT_SECONDS", 20.0),
            vt_cache_ttl_hours=_float("VT_CACHE_TTL_HOURS", 24.0),
            vt_not_found_ttl_hours=_float("VT_NOT_FOUND_TTL_HOURS", 2.0),
            vt_fetch_mitre=_bool("VT_FETCH_MITRE", True),
            ollama_url=os.getenv("OLLAMA_URL", ""),
            ollama_model=os.getenv("OLLAMA_MODEL", "qwen2.5:3b"),
            ollama_timeout=_float("OLLAMA_TIMEOUT", 60.0),
            claude_enabled=_bool("CLAUDE_ENABLED", bool(anthropic_key)),
            claude_model=os.getenv("CLAUDE_MODEL", "claude-opus-5-5"),
            claude_effort=os.getenv("CLAUDE_EFFORT", "medium"),
            claude_redact=_bool("CLAUDE_REDACT", True),
            alert_email_to=os.getenv("ALERT_EMAIL_TO", ""),
            action_base_url=os.getenv(
                "ACTION_BASE_URL", "http://localhost:5678/webhook/sentinel-action"
            ),
            action_secret=os.getenv("ACTION_SECRET", ""),
            action_token_ttl_hours=_float("ACTION_TOKEN_TTL_HOURS", 24.0),
            notify_min_severity=_severity("NOTIFY_MIN_SEVERITY", "medium"),
            escalate_min_severity=_severity("ESCALATE_MIN_SEVERITY", "high"),
            dedup_window_seconds=_int("DEDUP_WINDOW_SECONDS", 600),
        )


def severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)


def max_severity(*severities: str) -> str:
    return max(severities, key=SEVERITY_ORDER.index)
