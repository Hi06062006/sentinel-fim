"""Dựng email cảnh báo (HTML) và trang xác nhận hành động.

Mọi giá trị động đều được escape: tên file do kẻ tấn công đặt có thể chứa HTML
(ví dụ `<img src=x onerror=...>.exe`) và sẽ được hiển thị trong hộp thư của analyst.
"""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone

from .actions import ACTIONS, action_url
from .models import EmailMessage, TriageResult

SEVERITY_LABEL = {
    "low": ("THẤP", "#2e7d32"),
    "medium": ("TRUNG BÌNH", "#f9a825"),
    "high": ("CAO", "#ef6c00"),
    "critical": ("NGHIÊM TRỌNG", "#c62828"),
}
FP_LABEL = {"low": "thấp", "medium": "trung bình", "high": "cao"}
_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_HEX = re.compile(r"^[0-9a-f]{32,64}$")


def e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _row(label: str, value: str) -> str:
    return (f'<tr><td style="padding:4px 8px;color:#555;white-space:nowrap;vertical-align:top">'
            f"{e(label)}</td><td style=\"padding:4px 8px;word-break:break-all\">{value}</td></tr>")


def _list(items: list[str]) -> str:
    if not items:
        return "<p><i>Không có.</i></p>"
    return "<ol>" + "".join(f"<li>{e(i)}</li>" for i in items) + "</ol>"


def _technique_link(tid: str) -> str:
    if _TECHNIQUE_ID.match(tid):
        url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
        return f'<a href="{e(url)}">{e(tid)}</a>'
    return e(tid)


def _section(title: str, body: str) -> str:
    return (f'<h3 style="margin:20px 0 6px;border-bottom:1px solid #ddd;padding-bottom:4px">'
            f"{e(title)}</h3>{body}")


def _fmt_ts(epoch: int | None) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d")


def build_subject(result: TriageResult) -> str:
    label, _ = SEVERITY_LABEL[result.final_severity]
    ev, vt = result.event, result.virustotal
    what = vt.threat_label or ev.filename or ev.path
    subject = f"[Sentinel-FIM][{label}] {what} trên {ev.agent_name or ev.agent_id} ({result.incident_id})"
    # Chặn header injection: subject không được chứa xuống dòng.
    return re.sub(r"[\r\n\t]+", " ", subject)[:200]


def build_email(
    result: TriageResult,
    to: str,
    action_base_url: str,
    tokens: dict[str, str],
) -> EmailMessage:
    ev, vt = result.event, result.virustotal
    label, color = SEVERITY_LABEL[result.final_severity]
    parts: list[str] = []

    parts.append(
        f'<div style="background:{color};color:#fff;padding:12px 16px;border-radius:6px">'
        f'<div style="font-size:12px;opacity:.9">SENTINEL-FIM · {e(result.incident_id)}</div>'
        f'<div style="font-size:20px;font-weight:bold">Mức độ: {e(label)} '
        f"(điểm rủi ro {result.score}/100)</div></div>"
    )
    if result.final_severity != result.severity:
        parts.append(f"<p><b>Lưu ý:</b> mức độ được nâng từ "
                     f"{e(SEVERITY_LABEL[result.severity][0])} sau phân tích của Claude.</p>")

    overview = [
        _row("Máy trạm", f"{e(ev.agent_name)} (agent {e(ev.agent_id)}, {e(ev.agent_ip)})"),
        _row("Thời gian", e(ev.timestamp)),
        _row("Sự kiện", f"{e(ev.event)} · {e(ev.kind)} · chế độ {e(ev.mode or 'n/a')}"),
        _row("Đường dẫn", f"<code>{e(ev.path)}</code>"),
        _row("SHA256", f"<code>{e(ev.sha256 or 'n/a')}</code>"),
        _row("Rule Wazuh", f"{e(ev.rule_id)} (level {ev.rule_level}) — {e(ev.rule_description)}"),
    ]
    if ev.process_name:
        overview.append(_row("Tiến trình ghi file", f"<code>{e(ev.process_name)}</code> (pid {e(ev.process_id)})"))
    if ev.user_name:
        overview.append(_row("Người dùng", e(ev.user_name)))
    parts.append(_section("Tổng quan", "<table>" + "".join(overview) + "</table>"))

    # VirusTotal
    vt_rows: list[str] = []
    if vt.status == "found":
        vt_rows.append(_row("Kết quả", f"<b>{vt.malicious}/{vt.total}</b> engine phát hiện độc hại"
                                       f" ({vt.suspicious} đáng ngờ)"))
        if vt.threat_label:
            vt_rows.append(_row("Định danh", f"<b>{e(vt.threat_label)}</b> {e(vt.threat_category)}"))
        if vt.type_description:
            vt_rows.append(_row("Loại file", e(vt.type_description)))
        if vt.first_submission_date:
            vt_rows.append(_row("Lần đầu thấy", e(_fmt_ts(vt.first_submission_date))))
    else:
        status_text = {
            "not_found": "Chưa từng được báo cáo trên VirusTotal (mẫu mới/hiếm hoặc file nội bộ)",
            "no_hash": "Alert không có hash (thư mục, registry hoặc file đã bị xoá)",
            "rate_limited": "Bỏ qua do vượt hạn mức API — hãy tra cứu thủ công",
            "error": f"Lỗi khi tra cứu: {vt.error}",
            "disabled": "Chưa cấu hình VT_API_KEY",
        }[vt.status]
        vt_rows.append(_row("Trạng thái", e(status_text)))
    if vt.permalink and _HEX.match(vt.permalink.rsplit("/", 1)[-1]):
        vt_rows.append(_row("Liên kết", f'<a href="{e(vt.permalink)}">Mở trên VirusTotal</a>'))
    parts.append(_section("VirusTotal (danh tiếng toàn cầu)", "<table>" + "".join(vt_rows) + "</table>"))

    # Yếu tố rủi ro
    factor_rows = "".join(
        f"<tr><td style=\"padding:2px 8px;text-align:right\">{f.points:+d}</td>"
        f"<td style=\"padding:2px 8px\">{e(f.description)}</td></tr>"
        for f in result.factors
    ) or "<tr><td>Không có yếu tố rủi ro.</td></tr>"
    parts.append(_section("Vì sao hệ thống chấm điểm như vậy", f"<table>{factor_rows}</table>"))

    # MITRE ATT&CK
    techniques = []
    if result.claude and result.claude.mitre_techniques:
        for t in result.claude.mitre_techniques:
            techniques.append(f"<li>{_technique_link(str(t.get('id', '')))} {e(t.get('name'))} "
                              f"<i>({e(t.get('tactic'))})</i> — {e(t.get('rationale'))}</li>")
    else:
        for t in result.mitre:
            techniques.append(f"<li>{_technique_link(t.id)} {e(t.name)} <i>({e(t.tactic)})</i> — "
                              f"{e(t.reason)} <small>[{e(t.source)}]</small></li>")
    parts.append(_section("MITRE ATT&CK",
                          "<ul>" + "".join(techniques) + "</ul>" if techniques
                          else "<p><i>Chưa ánh xạ được kỹ thuật nào.</i></p>"))

    # Phân loại L1
    if result.small_llm:
        s = result.small_llm
        parts.append(_section(
            "Phân loại sơ bộ (mô hình nhỏ cục bộ)",
            f"<p><b>{e(s.verdict)}</b> (độ tin cậy {s.confidence:.0%}, {e(s.model)}): {e(s.reason)}</p>",
        ))

    # Báo cáo L2
    if result.claude:
        c = result.claude
        body = (
            f"<p><b>Tóm tắt:</b> {e(c.summary)}</p>"
            f"<p>{e(c.assessment)}</p>"
            f"<p><b>Claude đề xuất mức:</b> {e(SEVERITY_LABEL[c.suggested_severity][0])} · "
            f"<b>Khả năng dương tính giả:</b> {e(FP_LABEL[c.false_positive_likelihood])} — "
            f"{e(c.false_positive_reasoning)}</p>"
            f"<p><b>Hành động ngay:</b></p>{_list(c.immediate_actions)}"
            f"<p><b>Điều tra thêm:</b></p>{_list(c.investigation_steps)}"
        )
        if c.iocs:
            body += "<p><b>IOC:</b></p><ul>" + "".join(
                f"<li>{e(i.get('type'))}: <code>{e(i.get('value'))}</code></li>" for i in c.iocs
            ) + "</ul>"
        parts.append(_section(f"Phân tích chuyên sâu (Claude · {c.model})", body))
    elif result.escalate:
        parts.append(_section("Phân tích chuyên sâu (Claude)",
                              f"<p><i>Không có báo cáo ({e(result.claude_status)}). "
                              "Analyst cần tự đánh giá dựa trên dữ liệu ở trên.</i></p>"))

    # Hành động (human-in-the-loop)
    if tokens:
        buttons = []
        for action, token in tokens.items():
            url = action_url(action_base_url, result.incident_id, action, token)
            bg = "#c62828" if action == "quarantine" else "#455a64"
            buttons.append(
                f'<a href="{e(url)}" style="display:inline-block;margin:4px 8px 4px 0;padding:10px 16px;'
                f'background:{bg};color:#fff;text-decoration:none;border-radius:4px">{e(ACTIONS[action])}</a>'
            )
        parts.append(_section("Quyết định của analyst",
                              "".join(buttons) + "<p style=\"color:#777;font-size:12px\">Link mở trang xác "
                              "nhận; hành động chỉ thực hiện sau khi bạn bấm nút xác nhận.</p>"))

    html_body = (
        '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;max-width:760px">'
        + "".join(parts)
        + '<p style="color:#999;font-size:11px;margin-top:24px">Sentinel-FIM · Wazuh + n8n + '
        "VirusTotal + AI. Email tự động, không trả lời.</p></div>"
    )
    return EmailMessage(to=to, subject=build_subject(result), html=html_body)


def confirm_page(incident: dict, action: str, token: str, post_url: str) -> str:
    data = incident["data"]
    ev = data["event"]
    hidden = "".join(
        f'<input type="hidden" name="{e(k)}" value="{e(v)}">'
        for k, v in {"incident": incident["id"], "action": action, "token": token}.items()
    )
    return (
        "<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width\"><title>Sentinel-FIM</title></head>"
        "<body style=\"font-family:Segoe UI,Arial,sans-serif;max-width:640px;margin:40px auto;padding:0 16px\">"
        f"<h2>{e(ACTIONS[action])}?</h2>"
        f"<p>Sự cố <b>{e(incident['id'])}</b> — mức {e(data.get('final_severity'))}</p>"
        f"<p>Máy: <b>{e(ev.get('agent_name'))}</b> (agent {e(ev.get('agent_id'))})<br>"
        f"File: <code style=\"word-break:break-all\">{e(ev.get('path'))}</code><br>"
        f"SHA256: <code style=\"word-break:break-all\">{e(ev.get('sha256'))}</code></p>"
        f"<form method=\"post\" action=\"{e(post_url)}\">{hidden}"
        "<button type=\"submit\" style=\"padding:10px 18px;font-size:15px\">Xác nhận</button></form>"
        "</body></html>"
    )


def message_page(title: str, message: str) -> str:
    return (
        "<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\"><title>Sentinel-FIM</title></head>"
        "<body style=\"font-family:Segoe UI,Arial,sans-serif;max-width:640px;margin:40px auto;padding:0 16px\">"
        f"<h2>{e(title)}</h2><p>{e(message)}</p></body></html>"
    )
