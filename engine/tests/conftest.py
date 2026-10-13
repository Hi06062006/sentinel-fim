from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from sentinel.claude import ClaudeAnalyst
from sentinel.config import Settings
from sentinel.pipeline import Pipeline
from sentinel.small_llm import SmallLLM
from sentinel.store import Store
from sentinel.virustotal import RateLimiter, VirusTotalClient

SAMPLES = Path(__file__).resolve().parents[2] / "samples" / "alerts"

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
WANNACRY_SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
BENIGN_PDF_SHA256 = "c4ca4238a0b923820dcc509a6f75849bc4ca4238a0b923820dcc509a6f75849b"

VT_REPORTS = {
    EICAR_SHA256: {
        "stats": {"malicious": 62, "suspicious": 1, "undetected": 8, "harmless": 0},
        "ptc": {
            "suggested_threat_label": "virus.eicar/test",
            "popular_threat_category": [{"count": 40, "value": "virus"}],
            "popular_threat_name": [{"count": 30, "value": "eicar"}],
        },
        "type": "DOS COM",
    },
    WANNACRY_SHA256: {
        "stats": {"malicious": 68, "suspicious": 0, "undetected": 4, "harmless": 0},
        "ptc": {
            "suggested_threat_label": "ransomware.wannacry/wanna",
            "popular_threat_category": [{"count": 50, "value": "ransomware"}],
            "popular_threat_name": [{"count": 40, "value": "wannacry"}],
        },
        "type": "Win32 EXE",
    },
    BENIGN_PDF_SHA256: {
        "stats": {"malicious": 0, "suspicious": 0, "undetected": 60, "harmless": 0},
        "ptc": {},
        "type": "PDF",
    },
}


def load_sample(name: str) -> dict:
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


class FakeVT:
    """Giả lập VirusTotal API v3 bằng httpx.MockTransport."""

    def __init__(self):
        self.calls: list[str] = []
        self.force_status: int | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request.url.path)
        assert request.headers["x-apikey"] == "test-vt-key"
        if self.force_status:
            return httpx.Response(self.force_status, json={"error": {"code": "QuotaExceededError"}})
        parts = request.url.path.split("/")
        file_hash = parts[parts.index("files") + 1]
        report = VT_REPORTS.get(file_hash)
        if report is None:
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}})
        if request.url.path.endswith("/behaviour_mitre_trees"):
            return httpx.Response(200, json={"data": {"Zenbox": {"tactics": [
                {"id": "TA0040", "name": "Impact", "techniques": [
                    {"id": "T1486", "name": "Data Encrypted for Impact"}]},
                {"id": "TA0007", "name": "Discovery", "techniques": [
                    {"id": "T1083", "name": "File and Directory Discovery"}]},
            ]}}})
        return httpx.Response(200, json={"data": {"id": file_hash, "type": "file", "attributes": {
            "sha256": file_hash,
            "last_analysis_stats": report["stats"],
            "popular_threat_classification": report["ptc"],
            "type_description": report["type"],
            "meaningful_name": "sample",
            "first_submission_date": 1494547200,
            "times_submitted": 1000,
            "tags": ["peexe"],
        }}})


class FakeOllama:
    def __init__(self, verdict: str = "suspicious", confidence: float = 0.7, fail: bool = False):
        self.verdict, self.confidence, self.fail = verdict, confidence, fail
        self.requests: list[dict] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append(body)
        if self.fail:
            return httpx.Response(500, text="model not loaded")
        content = json.dumps({"verdict": self.verdict, "confidence": self.confidence,
                              "reason": "Phân loại thử nghiệm"})
        return httpx.Response(200, json={"message": {"role": "assistant", "content": content}})


CLAUDE_REPORT = {
    "summary": "Mẫu mã độc đã biết được thả vào máy trạm.",
    "assessment": "VirusTotal định danh mẫu; vị trí file cho thấy ý đồ duy trì truy cập.",
    "suggested_severity": "critical",
    "false_positive_likelihood": "low",
    "false_positive_reasoning": "Nhiều engine đồng thuận.",
    "mitre_techniques": [{"id": "T1547.001", "name": "Registry Run Keys / Startup Folder",
                          "tactic": "Persistence", "rationale": "File trong Startup"}],
    "iocs": [{"type": "sha256", "value": WANNACRY_SHA256}],
    "immediate_actions": ["Cách ly file", "Cô lập máy khỏi mạng"],
    "investigation_steps": ["Kiểm tra tiến trình cha powershell.exe"],
    "recommend_quarantine": True,
}


class FakeClaudeMessages:
    def __init__(self, report: dict | None = None, stop_reason: str = "end_turn"):
        self.report = report or CLAUDE_REPORT
        self.stop_reason = stop_reason
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        content = [] if self.stop_reason == "refusal" else [
            SimpleNamespace(type="text", text=json.dumps(self.report, ensure_ascii=False))
        ]
        return SimpleNamespace(stop_reason=self.stop_reason, content=content, model=kwargs["model"])


def fake_claude_client(messages: FakeClaudeMessages):
    return SimpleNamespace(beta=SimpleNamespace(messages=messages))


@pytest.fixture
def settings() -> Settings:
    return Settings(
        db_path=":memory:",
        api_token="test-api-token",
        vt_api_key="test-vt-key",
        ollama_url="http://ollama:11434",
        claude_enabled=True,
        alert_email_to="soc@example.com",
        action_base_url="http://n8n.local/webhook/sentinel-action",
        action_secret="test-action-secret",
    )


@pytest.fixture
def fake_vt() -> FakeVT:
    return FakeVT()


@pytest.fixture
def fake_ollama() -> FakeOllama:
    return FakeOllama()


@pytest.fixture
def fake_claude() -> FakeClaudeMessages:
    return FakeClaudeMessages()


@pytest.fixture
def clock():
    state = {"now": 1_792_000_000.0}

    def now() -> float:
        return state["now"]

    now.state = state  # type: ignore[attr-defined]
    return now


@pytest.fixture
def pipeline(settings, fake_vt, fake_ollama, fake_claude, clock) -> Pipeline:
    store = Store(":memory:", clock=clock)
    vt = VirusTotalClient(
        settings,
        store,
        http=httpx.Client(transport=httpx.MockTransport(fake_vt.handler)),
        limiter=RateLimiter(per_minute=1000, per_day=100000),
    )
    small = SmallLLM(settings, http=httpx.Client(transport=httpx.MockTransport(fake_ollama.handler)))
    claude = ClaudeAnalyst(settings, client=fake_claude_client(fake_claude))  # type: ignore[arg-type]
    return Pipeline(settings, store, vt, small, claude, clock=clock)
