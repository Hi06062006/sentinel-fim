"""Link hành động trong email (human-in-the-loop) được ký HMAC và có hạn dùng.

Link GET chỉ mở trang XÁC NHẬN; hành động thật chỉ chạy khi analyst bấm nút (POST).
Lý do: Gmail/Outlook và các cổng lọc thư tự động "bấm thử" link trong email để quét
mã độc — nếu GET thực thi ngay thì file sẽ bị cách ly mà không ai đồng ý.
"""

from __future__ import annotations

import hashlib
import hmac
from urllib.parse import urlencode

ACTIONS = {
    "quarantine": "Cách ly file",
    "false_positive": "Đánh dấu dương tính giả",
}


def make_token(secret: str, incident_id: str, action: str, ttl_seconds: float, now: float) -> str:
    expires = int(now + ttl_seconds)
    msg = f"{incident_id}|{action}|{expires}".encode()
    sig = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return f"{expires}.{sig}"


def verify_token(secret: str, incident_id: str, action: str, token: str, now: float) -> bool:
    if not secret or action not in ACTIONS or "." not in token:
        return False
    expires_raw, sig = token.split(".", 1)
    try:
        expires = int(expires_raw)
    except ValueError:
        return False
    if expires < now:
        return False
    msg = f"{incident_id}|{action}|{expires}".encode()
    expected = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig)


def action_url(base_url: str, incident_id: str, action: str, token: str) -> str:
    query = urlencode({"incident": incident_id, "action": action, "token": token})
    return f"{base_url}?{query}"
