import httpx

from sentinel.actions import make_token, verify_token
from sentinel.claude import ClaudeAnalyst, build_incident_context
from sentinel.config import Settings
from sentinel.normalize import normalize_alert
from sentinel.store import Store
from sentinel.virustotal import RateLimiter, VirusTotalClient

from .conftest import (
    WANNACRY_SHA256,
    FakeClaudeMessages,
    FakeVT,
    fake_claude_client,
    load_sample,
)


def make_vt(settings, fake: FakeVT, clock, limiter=None) -> VirusTotalClient:
    return VirusTotalClient(
        settings,
        Store(":memory:", clock=clock),
        http=httpx.Client(transport=httpx.MockTransport(fake.handler)),
        limiter=limiter or RateLimiter(per_minute=100, per_day=1000),
    )


def test_vt_found_parses_reputation_and_sandbox_mitre(settings, fake_vt, clock):
    vt = make_vt(settings, fake_vt, clock)
    res = vt.lookup(normalize_alert(load_sample("02_wannacry_startup_windows.json")))
    assert res.status == "found"
    assert res.malicious == 68 and res.total == 72
    assert res.threat_label == "ransomware.wannacry/wanna"
    assert res.threat_category == "ransomware"
    assert {t["id"] for t in res.mitre_techniques} == {"T1486", "T1083"}
    assert res.permalink.endswith(WANNACRY_SHA256)


def test_vt_cache_avoids_second_request(settings, fake_vt, clock):
    vt = make_vt(settings, fake_vt, clock)
    ev = normalize_alert(load_sample("01_eicar_downloads_linux.json"))
    first = vt.lookup(ev)
    calls = len(fake_vt.calls)
    second = vt.lookup(ev)
    assert not first.cached and second.cached
    assert len(fake_vt.calls) == calls


def test_vt_not_found_uses_shorter_ttl(settings, fake_vt, clock):
    vt = make_vt(settings, fake_vt, clock)
    ev = normalize_alert(load_sample("03_webshell_unknown_linux.json"))
    assert vt.lookup(ev).status == "not_found"
    assert vt.lookup(ev).cached
    clock.state["now"] += settings.vt_not_found_ttl_hours * 3600 + 1
    assert not vt.lookup(ev).cached
    assert len(fake_vt.calls) == 2


def test_vt_quota_errors_and_disabled(settings, fake_vt, clock):
    fake_vt.force_status = 429
    vt = make_vt(settings, fake_vt, clock)
    ev = normalize_alert(load_sample("01_eicar_downloads_linux.json"))
    assert vt.lookup(ev).status == "rate_limited"

    no_key = Settings(vt_api_key="")
    assert make_vt(no_key, fake_vt, clock).lookup(ev).status == "disabled"


def test_rate_limiter_sliding_window():
    t = {"now": 0.0}
    sleeps = []

    def sleep(s):
        sleeps.append(s)
        t["now"] += s

    limiter = RateLimiter(per_minute=4, per_day=5, clock=lambda: t["now"],
                          wall_clock=lambda: 1_792_000_000.0, sleep=sleep)
    assert all(limiter.acquire(0) for _ in range(4))
    assert limiter.acquire(0) is False          # hết 4 lượt/phút, không chờ
    assert limiter.acquire(90) is True           # chờ tới khi cửa sổ trượt mở lại
    assert sleeps and sleeps[0] == 60
    assert limiter.acquire(120) is False         # hết hạn mức ngày (5)


def test_action_tokens():
    tok = make_token("s3cret", "INC-1", "quarantine", 3600, now=1000)
    assert verify_token("s3cret", "INC-1", "quarantine", tok, now=2000)
    assert not verify_token("s3cret", "INC-1", "quarantine", tok, now=1000 + 3601)  # hết hạn
    assert not verify_token("s3cret", "INC-2", "quarantine", tok, now=2000)          # sai sự cố
    assert not verify_token("s3cret", "INC-1", "false_positive", tok, now=2000)      # sai hành động
    assert not verify_token("other", "INC-1", "quarantine", tok, now=2000)           # sai khoá
    assert not verify_token("", "INC-1", "quarantine", tok, now=2000)
    assert not verify_token("s3cret", "INC-1", "quarantine", "garbage", now=2000)


def test_claude_request_shape_and_report(pipeline, fake_claude):
    result = pipeline.triage(load_sample("02_wannacry_startup_windows.json"))
    analyzed = pipeline.analyze(result.incident_id)
    assert analyzed.claude is not None and analyzed.claude_status == "ok"
    call = fake_claude.calls[0]
    assert call["model"] == "claude-opus-5-5"
    assert call["fallbacks"] == "default"
    assert "server-side-fallback-2026-07-01" in call["betas"]
    assert call["output_config"]["format"]["type"] == "json_schema"
    assert "<incident>" in call["messages"][0]["content"]


def test_claude_refusal_is_handled(settings):
    analyst = ClaudeAnalyst(settings, client=fake_claude_client(FakeClaudeMessages(stop_reason="refusal")))
    from sentinel.models import TriageResult, VTResult

    ev = normalize_alert(load_sample("01_eicar_downloads_linux.json"))
    tr = TriageResult(incident_id="INC-x", event=ev, virustotal=VTResult(), score=50, severity="high",
                      factors=[], mitre=[], escalate=True, notify=True, final_severity="high")
    report, status = analyst.analyze(tr)
    assert report is None and status == "refused"


def test_claude_context_redacts_user_and_ip(pipeline):
    result = pipeline.triage(load_sample("01_eicar_downloads_linux.json"))
    ctx = build_incident_context(result, redact=True)
    text = str(ctx)
    assert "/home/<user>/Downloads/eicar.com" in text
    assert "192.168.56.101" not in text
    assert "ubuntu-lab-01" not in text
    raw = str(build_incident_context(result, redact=False))
    assert "/home/student/Downloads" in raw


def test_claude_context_redacts_windows_user_in_rule_description(pipeline):
    alert = load_sample("02_wannacry_startup_windows.json")
    alert["rule"]["description"] += ": " + alert["syscheck"]["path"]
    result = pipeline.triage(alert)
    ctx = build_incident_context(result, redact=True)
    assert "\\users\\<user>\\appdata" in ctx["su_kien_fim"]["duong_dan"]
    assert "\\lan\\" not in ctx["rule_wazuh"]["mo_ta"]
    assert "\\users\\<user>\\" in ctx["rule_wazuh"]["mo_ta"]
