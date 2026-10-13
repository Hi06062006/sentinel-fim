#!/usr/bin/env python3
"""Phát lại alert Wazuh mẫu để demo/đánh giá mà KHÔNG cần mẫu mã độc thật.

Phát hiện "virus đã được báo cáo" dựa trên hash, nên chỉ cần hash của mẫu đã biết
(EICAR, WannaCry...) là VirusTotal trả về định danh — không phải chạm vào mã độc.

Ví dụ:
  # Gửi thẳng vào engine, in bảng kết quả + thời gian xử lý
  python3 scripts/replay_alerts.py --engine http://127.0.0.1:8000 --token $SENTINEL_API_TOKEN

  # Gửi qua webhook n8n (đi hết luồng tới Gmail), giống hệt Wazuh integration
  python3 scripts/replay_alerts.py --n8n http://127.0.0.1:5678/webhook/sentinel-fim --token <webhook token>

Engine gộp alert trùng trong DEDUP_WINDOW_SECONDS; khi chạy đánh giá nhiều lượt hãy
đặt DEDUP_WINDOW_SECONDS=0 cho engine.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_GLOB = os.path.join(ROOT, "samples", "alerts", "*.json")


def post(url: str, token: str, payload: dict, timeout: float) -> tuple[int, dict | str, float]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json", "X-Sentinel-Token": token})
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            status = resp.status
    except urllib.error.HTTPError as exc:
        body, status = exc.read().decode(), exc.code
    elapsed = time.perf_counter() - start
    try:
        return status, json.loads(body), elapsed
    except json.JSONDecodeError:
        return status, body, elapsed


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--engine", help="URL gốc của engine, ví dụ http://127.0.0.1:8000")
    target.add_argument("--n8n", help="URL webhook n8n, ví dụ http://127.0.0.1:5678/webhook/sentinel-fim")
    ap.add_argument("--token", required=True)
    ap.add_argument("--analyze", action="store_true", help="(engine) gọi thêm bước Claude cho sự cố leo thang")
    ap.add_argument("files", nargs="*", help=f"mặc định: {DEFAULT_GLOB}")
    args = ap.parse_args()

    files = args.files or sorted(glob.glob(DEFAULT_GLOB))
    rows = []
    for path in files:
        with open(path, encoding="utf-8") as fh:
            alert = json.load(fh)
        if args.n8n:
            status, _, elapsed = post(args.n8n, args.token, alert, 30)
            print(f"{os.path.basename(path):42} -> n8n HTTP {status} ({elapsed:.2f}s)")
            continue

        status, body, elapsed = post(args.engine.rstrip("/") + "/v1/triage", args.token, alert, 180)
        if status != 200 or not isinstance(body, dict):
            print(f"{os.path.basename(path)}: HTTP {status} {body}")
            continue
        total = elapsed
        final = body["final_severity"]
        if args.analyze and body["escalate"]:
            status, analyzed, t2 = post(
                f"{args.engine.rstrip('/')}/v1/incidents/{body['incident_id']}/analyze", args.token, {}, 600)
            total += t2
            if status == 200 and isinstance(analyzed, dict):
                final = f"{analyzed['final_severity']} (Claude: {analyzed['claude_status']})"
        vt = body["virustotal"]
        rows.append((
            os.path.basename(path)[:34],
            f"{vt['status']}:{vt['malicious']}" + (f" {vt['threat_label']}" if vt["threat_label"] else ""),
            str(body["score"]),
            body["severity"],
            (body["small_llm"] or {}).get("verdict", "-"),
            "yes" if body["escalate"] else "no",
            final,
            ",".join(t["id"] for t in body["mitre"]) or "-",
            f"{total:.1f}s",
        ))

    if rows:
        header = ("sample", "virustotal", "score", "severity", "L1 (AI nhỏ)", "→Claude", "final", "ATT&CK", "time")
        widths = [max(len(str(r[i])) for r in rows + [header]) for i in range(len(header))]
        for r in [header] + rows:
            print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
