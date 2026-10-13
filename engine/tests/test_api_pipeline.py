from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from sentinel.api import create_app

from .conftest import CLAUDE_REPORT, FakeClaudeMessages, load_sample

AUTH = {"X-Sentinel-Token": "test-api-token"}


@pytest.fixture
def client(pipeline) -> TestClient:
    return TestClient(create_app(pipeline))


def test_auth_required(client):
    assert client.get("/healthz").status_code == 200
    assert client.post("/v1/triage", json={}).status_code == 401
    assert client.post("/v1/triage", json={}, headers={"X-Sentinel-Token": "wrong"}).status_code == 401


def test_invalid_alert_returns_422(client):
    assert client.post("/v1/triage", json={"rule": {}}, headers=AUTH).status_code == 422


def test_known_malware_is_identified_and_escalated(client):
    r = client.post("/v1/triage", json=load_sample("01_eicar_downloads_linux.json"), headers=AUTH)
    body = r.json()
    assert r.status_code == 200
    assert body["virustotal"]["threat_label"] == "virus.eicar/test"
    assert body["severity"] == "critical"
    # Leo thang lên Claude: email chỉ được dựng sau bước analyze.
    assert body["escalate"] is True and body["email"] is None

    analyzed = client.post(f"/v1/incidents/{body['incident_id']}/analyze", headers=AUTH).json()
    assert analyzed["claude_status"] == "ok"
    assert analyzed["email"]["to"] == "soc@example.com"
    assert "virus.eicar/test" in analyzed["email"]["subject"]
    assert "Mẫu mã độc đã biết" in analyzed["email"]["html"]


def test_claude_can_raise_severity(client):
    body = client.post("/v1/triage", json=load_sample("03_webshell_unknown_linux.json"), headers=AUTH).json()
    assert body["severity"] == "high"
    analyzed = client.post(f"/v1/incidents/{body['incident_id']}/analyze", headers=AUTH).json()
    # Claude (giả lập) đề xuất critical -> được phép NÂNG mức.
    assert analyzed["final_severity"] == "critical"
    assert "NGHIÊM TRỌNG" in analyzed["email"]["subject"]
    assert "được nâng từ" in analyzed["email"]["html"]


def test_claude_cannot_lower_severity(pipeline):
    pipeline.claude._client.beta.messages = FakeClaudeMessages(
        report={**CLAUDE_REPORT, "suggested_severity": "low", "false_positive_likelihood": "high"})
    result = pipeline.triage(load_sample("02_wannacry_startup_windows.json"))
    assert result.severity == "critical"
    analyzed = pipeline.analyze(result.incident_id)
    assert analyzed.final_severity == "critical"
    assert "Khả năng dương tính giả:</b> cao" in analyzed.email.html


def test_clean_file_is_not_notified(client, fake_ollama):
    fake_ollama.verdict, fake_ollama.confidence = "benign", 0.9
    body = client.post("/v1/triage", json=load_sample("05_benign_pdf_downloads.json"), headers=AUTH).json()
    assert body["severity"] == "low"
    assert body["notify"] is False and body["escalate"] is False


def test_prompt_injection_cannot_lower_rule_based_severity(client, fake_ollama):
    # Mô hình nhỏ bị "lừa" bởi tên file và trả về benign với độ tin cậy cao...
    fake_ollama.verdict, fake_ollama.confidence = "benign", 0.99
    body = client.post("/v1/triage", json=load_sample("06_prompt_injection_double_ext.json"),
                       headers=AUTH).json()
    # ...nhưng mức độ do luật xác định (hai phần mở rộng + file thực thi) vẫn giữ nguyên.
    assert "double_extension" in {f["code"] for f in body["factors"]}
    assert body["severity"] == "medium"
    assert body["notify"] is True
    # Prompt gửi cho mô hình nhỏ bọc dữ liệu trong thẻ <alert>.
    assert fake_ollama.requests[-1]["messages"][1]["content"].startswith("<alert>")


def test_small_llm_can_raise_attention_on_medium(client, fake_ollama):
    fake_ollama.verdict, fake_ollama.confidence = "malicious", 0.85
    body = client.post("/v1/triage", json=load_sample("04_authorized_keys_modified.json"),
                       headers=AUTH).json()
    assert body["severity"] == "medium"
    assert body["escalate"] is True


def test_small_llm_failure_does_not_break_pipeline(client, fake_ollama):
    fake_ollama.fail = True
    body = client.post("/v1/triage", json=load_sample("03_webshell_unknown_linux.json"),
                       headers=AUTH).json()
    assert body["small_llm"] is None
    assert body["severity"] == "high" and body["escalate"] is True


def test_duplicate_alert_is_suppressed(client):
    sample = load_sample("03_webshell_unknown_linux.json")
    first = client.post("/v1/triage", json=sample, headers=AUTH).json()
    second = client.post("/v1/triage", json=sample, headers=AUTH).json()
    assert second["duplicate"] is True and second["incident_id"] == first["incident_id"]
    assert second["notify"] is False and second["escalate"] is False


def test_email_escapes_attacker_controlled_filename(client):
    alert = load_sample("03_webshell_unknown_linux.json")
    alert["rule"] = {"id": "554", "level": 5, "groups": ["syscheck", "syscheck_entry_added"]}
    alert["syscheck"]["path"] = "/tmp/<img src=x onerror=alert(1)>.sh"
    alert["syscheck"].pop("audit")
    body = client.post("/v1/triage", json=alert, headers=AUTH).json()
    analyzed = client.post(f"/v1/incidents/{body['incident_id']}/analyze", headers=AUTH).json()
    html = analyzed["email"]["html"]
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;.sh" in html


def _action_link(email_html: str, action: str) -> dict:
    import re

    for href in re.findall(r'href="([^"]+)"', email_html):
        url = href.replace("&amp;", "&")
        if "sentinel-action" in url and f"action={action}" in url:
            return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
    raise AssertionError(f"no {action} link")


def test_quarantine_flow_requires_confirmation_and_is_single_use(client):
    body = client.post("/v1/triage", json=load_sample("02_wannacry_startup_windows.json"), headers=AUTH).json()
    analyzed = client.post(f"/v1/incidents/{body['incident_id']}/analyze", headers=AUTH).json()
    params = _action_link(analyzed["email"]["html"], "quarantine")

    confirm = client.get("/v1/actions/confirm", params=params, headers=AUTH).json()
    assert confirm["valid"] is True
    assert 'method="post"' in confirm["html"]
    # Mở trang xác nhận không được thay đổi trạng thái.
    assert client.get(f"/v1/incidents/{body['incident_id']}", headers=AUTH).json()["status"] == "open"

    done = client.post("/v1/actions/execute", json=params, headers=AUTH).json()
    assert done["ok"] is True
    assert done["wazuh"]["agent_id"] == "002"
    assert done["wazuh"]["body"]["command"] == "!sentinel-quarantine.exe"
    assert done["wazuh"]["body"]["alert"]["data"]["sentinel"]["sha256"] == body["event"]["sha256"]

    again = client.post("/v1/actions/execute", json=params, headers=AUTH).json()
    assert again["ok"] is False and again["status_code"] == 409


def test_tampered_action_token_rejected(client):
    body = client.post("/v1/triage", json=load_sample("02_wannacry_startup_windows.json"), headers=AUTH).json()
    analyzed = client.post(f"/v1/incidents/{body['incident_id']}/analyze", headers=AUTH).json()
    params = _action_link(analyzed["email"]["html"], "quarantine")
    params["token"] = params["token"][:-1] + ("0" if params["token"][-1] != "0" else "1")
    res = client.post("/v1/actions/execute", json=params, headers=AUTH).json()
    assert res["ok"] is False and res["status_code"] == 403


def test_false_positive_feedback_allowlists_hash(client, clock):
    sample = load_sample("03_webshell_unknown_linux.json")
    body = client.post("/v1/triage", json=sample, headers=AUTH).json()
    analyzed = client.post(f"/v1/incidents/{body['incident_id']}/analyze", headers=AUTH).json()
    params = _action_link(analyzed["email"]["html"], "false_positive")
    assert client.post("/v1/actions/execute", json=params, headers=AUTH).json()["ok"] is True

    clock.state["now"] += 3600  # ra khỏi cửa sổ chống trùng
    again = client.post("/v1/triage", json=sample, headers=AUTH).json()
    assert again["allowlisted"] is True
    assert again["severity"] == "low" and again["notify"] is False
