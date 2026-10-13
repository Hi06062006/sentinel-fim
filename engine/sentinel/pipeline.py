"""Điều phối toàn bộ quy trình: chuẩn hoá -> VirusTotal -> chấm điểm -> ATT&CK -> AI nhỏ -> Claude."""

from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from typing import Callable

from .actions import ACTIONS, make_token, verify_token
from .claude import ClaudeAnalyst
from .config import Settings, max_severity, severity_at_least
from .mitre import map_event
from .models import TriageResult, VTResult
from .normalize import normalize_alert
from .report import build_email
from .scoring import score_event, severity_for
from .small_llm import SmallLLM
from .store import Store
from .virustotal import VirusTotalClient


class ActionError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        vt: VirusTotalClient,
        small_llm: SmallLLM,
        claude: ClaudeAnalyst,
        clock: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self.store = store
        self.vt = vt
        self.small_llm = small_llm
        self.claude = claude
        self.clock = clock

    # ------------------------------------------------------------------ triage
    def triage(self, alert: dict) -> TriageResult:
        event = normalize_alert(alert)
        file_hash = event.best_hash

        recent = self.store.find_recent_incident(
            event.agent_id, event.path, file_hash, self.settings.dedup_window_seconds
        )
        if recent is not None:
            # Chống "bão cảnh báo": cùng file trên cùng máy trong cửa sổ thời gian -> gộp.
            previous = TriageResult.model_validate(recent["data"])
            return previous.model_copy(
                update={"duplicate": True, "notify": False, "escalate": False, "email": None}
            )

        allowlisted = self.store.is_allowlisted(file_hash)
        if allowlisted:
            vt = VTResult(status="disabled", error="Bỏ qua: hash nằm trong allowlist")
        else:
            vt = self.vt.lookup(event)
        techniques = map_event(event, vt)
        score, factors = score_event(event, vt, techniques, allowlisted)
        severity = severity_for(score)

        small = None if allowlisted else self.small_llm.classify(event, vt, factors)
        llm_flag = bool(small) and (
            (severity_at_least(severity, "medium") and small.verdict != "benign" and small.confidence >= 0.6)
            or (small.verdict == "malicious" and small.confidence >= 0.8)
        )
        notify = severity_at_least(severity, self.settings.notify_min_severity) or llm_flag
        escalate = self.claude.enabled and (
            severity_at_least(severity, self.settings.escalate_min_severity) or llm_flag
        )

        result = TriageResult(
            incident_id=self._new_incident_id(),
            event=event,
            virustotal=vt,
            score=score,
            severity=severity,  # type: ignore[arg-type]
            factors=factors,
            mitre=techniques,
            small_llm=small,
            escalate=escalate,
            notify=notify,
            allowlisted=allowlisted,
            final_severity=severity,  # type: ignore[arg-type]
        )
        if notify and not escalate:
            result.email = self._email(result)
        self._save(result)
        return result

    # ----------------------------------------------------------------- analyze
    def analyze(self, incident_id: str) -> TriageResult:
        record = self.store.get_incident(incident_id)
        if record is None:
            raise KeyError(incident_id)
        result = TriageResult.model_validate(record["data"])

        if result.claude is None and self.claude.enabled:
            report, status = self.claude.analyze(result)
            result.claude, result.claude_status = report, status
            if report is not None:
                result.final_severity = max_severity(result.severity, report.suggested_severity)  # type: ignore[assignment]
            result.notify = True
        result.email = self._email(result)
        self._save(result)
        return result

    # ----------------------------------------------------------------- actions
    def check_action(self, incident_id: str, action: str, token: str) -> dict:
        if not self.settings.action_secret:
            raise ActionError(503, "ACTION_SECRET chưa được cấu hình")
        if not verify_token(self.settings.action_secret, incident_id, action, token, self.clock()):
            raise ActionError(403, "Link không hợp lệ hoặc đã hết hạn")
        record = self.store.get_incident(incident_id)
        if record is None:
            raise ActionError(404, "Không tìm thấy sự cố")
        if record["status"] != "open":
            raise ActionError(409, f"Sự cố đã được xử lý trước đó ({record['decision']})")
        if action == "quarantine" and not _can_quarantine(record["data"]["event"]):
            raise ActionError(422, "Không thể cách ly: không phải file còn tồn tại hoặc thiếu SHA256")
        return record

    def execute_action(self, incident_id: str, action: str, token: str) -> dict:
        record = self.check_action(incident_id, action, token)
        if not self.store.record_decision(incident_id, action):
            raise ActionError(409, "Sự cố đã được xử lý trước đó")
        event = record["data"]["event"]

        if action == "false_positive":
            file_hash = event.get("sha256") or event.get("sha1") or event.get("md5")
            if file_hash:
                self.store.allowlist_add(file_hash, incident_id, "analyst: false positive")
            return {
                "ok": True,
                "action": action,
                "message": "Đã ghi nhận dương tính giả; hash được đưa vào allowlist.",
            }

        script = "!sentinel-quarantine.exe" if event.get("os_family") == "windows" else "!sentinel-quarantine"
        return {
            "ok": True,
            "action": action,
            "message": f"Đã duyệt cách ly file trên agent {event['agent_id']}.",
            # n8n dùng khối này để gọi Wazuh API: PUT /active-response?agents_list=<agent_id>
            "wazuh": {
                "agent_id": event["agent_id"],
                "body": {
                    "command": script,
                    "arguments": [],
                    "alert": {
                        "data": {
                            "sentinel": {
                                "incident_id": incident_id,
                                "path": event["path"],
                                "sha256": event["sha256"],
                            }
                        }
                    },
                },
            },
        }

    # ----------------------------------------------------------------- helpers
    def _new_incident_id(self) -> str:
        day = datetime.fromtimestamp(self.clock(), tz=timezone.utc).strftime("%Y%m%d")
        return f"INC-{day}-{secrets.token_hex(3).upper()}"

    def _email(self, result: TriageResult):
        tokens: dict[str, str] = {}
        if self.settings.action_secret:
            ttl = self.settings.action_token_ttl_hours * 3600
            for action in ACTIONS:
                if action == "quarantine" and not _can_quarantine(result.event.model_dump()):
                    continue
                tokens[action] = make_token(
                    self.settings.action_secret, result.incident_id, action, ttl, self.clock()
                )
        return build_email(result, self.settings.alert_email_to, self.settings.action_base_url, tokens)

    def _save(self, result: TriageResult) -> None:
        self.store.save_incident(
            result.incident_id,
            result.event.agent_id,
            result.event.path,
            result.event.best_hash,
            result.final_severity,
            result.model_dump(mode="json"),
        )


def _can_quarantine(event: dict) -> bool:
    # Cần SHA256 để script trên agent xác minh đúng file trước khi di chuyển (chống TOCTOU).
    return event.get("kind") == "file" and event.get("event") != "deleted" and bool(event.get("sha256"))
