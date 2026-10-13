"""Chuẩn hoá alert JSON của Wazuh (FIM/syscheck hoặc VirusTotal integration) về FileEvent."""

from __future__ import annotations

import ntpath
import posixpath
import re
from typing import Any

from .models import FileEvent

_HEX = re.compile(r"^[0-9a-fA-F]+$")


def _get(data: dict, dotted: str, default: Any = None) -> Any:
    cur: Any = data
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def _hash(value: Any, length: int) -> str:
    if isinstance(value, str) and len(value) == length and _HEX.match(value):
        return value.lower()
    return ""


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def guess_os(path: str) -> str:
    if path.startswith("/"):
        return "linux"
    if re.match(r"^[A-Za-z]:\\", path) or path.upper().startswith("HKEY_") or "\\" in path:
        return "windows"
    return "unknown"


def split_name(path: str, os_family: str) -> tuple[str, str]:
    mod = ntpath if os_family == "windows" else posixpath
    filename = mod.basename(path)
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename.strip(".") else ""
    return filename, ext


def _event_type(alert: dict) -> str:
    raw = (_get(alert, "syscheck.event") or "").lower()
    if raw in {"added", "modified", "deleted"}:
        return raw
    groups = set(_get(alert, "rule.groups", []) or [])
    for name in ("added", "modified", "deleted"):
        if f"syscheck_entry_{name}" in groups:
            return name
    return "unknown"


def normalize_alert(alert: dict) -> FileEvent:
    """Trích xuất các trường cần thiết từ một alert Wazuh.

    Hỗ trợ hai dạng:
    - alert FIM gốc (rule 550/553/554, 594, 750-752 và các rule tùy biến kế thừa);
    - alert do integration VirusTotal có sẵn của Wazuh sinh ra (rule 87105...).
    """
    if not isinstance(alert, dict):
        raise ValueError("Alert phải là một JSON object")

    syscheck = alert.get("syscheck") or {}
    vt_data = _get(alert, "data.virustotal") or {}

    path = syscheck.get("path") or _get(vt_data, "source.file") or ""
    if not path:
        raise ValueError("Alert không chứa syscheck.path hoặc data.virustotal.source.file")

    value_name = syscheck.get("value_name")
    if value_name:
        # Sự kiện registry Windows: ghép tên value để có ngữ cảnh đầy đủ.
        path = f"{path}\\{value_name}"

    os_family = guess_os(path)
    filename, ext = split_name(path, os_family)
    kind = "registry" if path.upper().startswith("HKEY_") else "file"

    audit = syscheck.get("audit") or {}
    mitre_ids = _get(alert, "rule.mitre.id", []) or []

    positives = None
    if vt_data:
        positives = _to_int(vt_data.get("positives"))

    return FileEvent(
        alert_id=str(alert.get("id", "")),
        timestamp=str(alert.get("timestamp", "")),
        agent_id=str(_get(alert, "agent.id", "000")),
        agent_name=str(_get(alert, "agent.name", "")),
        agent_ip=str(_get(alert, "agent.ip", "")),
        os_family=os_family,  # type: ignore[arg-type]
        rule_id=str(_get(alert, "rule.id", "")),
        rule_level=_to_int(_get(alert, "rule.level", 0)) or 0,
        rule_description=str(_get(alert, "rule.description", "")),
        rule_groups=[str(g) for g in (_get(alert, "rule.groups", []) or [])],
        rule_mitre_ids=[str(m) for m in mitre_ids],
        kind=kind,  # type: ignore[arg-type]
        event=_event_type(alert),  # type: ignore[arg-type]
        path=path,
        filename=filename,
        extension=ext,
        size=_to_int(syscheck.get("size_after")),
        sha256=_hash(syscheck.get("sha256_after"), 64),
        sha1=_hash(syscheck.get("sha1_after") or _get(vt_data, "source.sha1"), 40),
        md5=_hash(syscheck.get("md5_after") or _get(vt_data, "source.md5"), 32),
        mode=str(syscheck.get("mode", "")),
        process_name=str(_get(audit, "process.name", "") or ""),
        process_id=str(_get(audit, "process.id", "") or ""),
        user_name=str(_get(audit, "user.name", "") or syscheck.get("uname_after", "") or ""),
        wazuh_virustotal_positives=positives,
    )
