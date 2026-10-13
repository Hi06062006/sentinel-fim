"""Các kiểu dữ liệu dùng chung trong pipeline."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]


class FileEvent(BaseModel):
    """Sự kiện FIM đã được chuẩn hoá từ alert Wazuh.

    Mọi trường chuỗi ở đây (đường dẫn, tên tiến trình...) đều do máy trạm gửi lên,
    tức là kẻ tấn công có thể kiểm soát: chỉ coi là DỮ LIỆU, không bao giờ là lệnh.
    """

    alert_id: str = ""
    timestamp: str = ""
    agent_id: str = "000"
    agent_name: str = ""
    agent_ip: str = ""
    os_family: Literal["windows", "linux", "unknown"] = "unknown"

    rule_id: str = ""
    rule_level: int = 0
    rule_description: str = ""
    rule_groups: list[str] = Field(default_factory=list)
    rule_mitre_ids: list[str] = Field(default_factory=list)

    kind: Literal["file", "registry"] = "file"
    event: Literal["added", "modified", "deleted", "unknown"] = "unknown"
    path: str = ""
    filename: str = ""
    extension: str = ""
    size: Optional[int] = None
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    mode: str = ""

    process_name: str = ""
    process_id: str = ""
    user_name: str = ""

    wazuh_virustotal_positives: Optional[int] = None

    @property
    def best_hash(self) -> str:
        return self.sha256 or self.sha1 or self.md5


class VTResult(BaseModel):
    status: Literal[
        "found", "not_found", "no_hash", "rate_limited", "error", "disabled"
    ] = "disabled"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    threat_label: str = ""
    threat_category: str = ""
    threat_names: list[str] = Field(default_factory=list)
    meaningful_name: str = ""
    type_description: str = ""
    tags: list[str] = Field(default_factory=list)
    first_submission_date: Optional[int] = None
    last_analysis_date: Optional[int] = None
    times_submitted: Optional[int] = None
    mitre_techniques: list[dict] = Field(default_factory=list)
    permalink: str = ""
    cached: bool = False
    error: str = ""

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected


class Factor(BaseModel):
    """Một yếu tố góp điểm rủi ro — để giải thích được vì sao hệ thống kết luận như vậy."""

    code: str
    points: int
    description: str


class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    source: Literal["wazuh_rule", "heuristic", "virustotal_sandbox"]
    reason: str = ""

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"


class SmallLLMVerdict(BaseModel):
    verdict: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    model: str = ""


class ClaudeReport(BaseModel):
    summary: str
    assessment: str
    suggested_severity: Severity
    false_positive_likelihood: Literal["low", "medium", "high"]
    false_positive_reasoning: str
    mitre_techniques: list[dict]
    iocs: list[dict]
    immediate_actions: list[str]
    investigation_steps: list[str]
    recommend_quarantine: bool
    model: str = ""


class EmailMessage(BaseModel):
    to: str
    subject: str
    html: str


class TriageResult(BaseModel):
    incident_id: str
    duplicate: bool = False
    event: FileEvent
    virustotal: VTResult
    score: int
    severity: Severity
    factors: list[Factor]
    mitre: list[MitreTechnique]
    small_llm: Optional[SmallLLMVerdict] = None
    escalate: bool
    notify: bool
    allowlisted: bool = False
    claude: Optional[ClaudeReport] = None
    claude_status: str = "not_requested"
    final_severity: Severity
    email: Optional[EmailMessage] = None
