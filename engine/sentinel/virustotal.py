"""Tra cứu VirusTotal API v3 theo hash (KHÔNG BAO GIỜ tải file lên).

Gói miễn phí bị giới hạn 4 request/phút và 500 request/ngày, vì vậy client này
có cache SQLite và bộ giới hạn tốc độ. Upload file nội bộ lên VirusTotal sẽ làm
file đó lộ ra cho mọi thuê bao VT Intelligence, nên engine chỉ tra cứu hash.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable

import httpx

from .config import Settings
from .models import FileEvent, VTResult
from .store import Store

log = logging.getLogger(__name__)


class RateLimiter:
    """Cửa sổ trượt theo phút + hạn mức theo ngày (UTC), an toàn đa luồng."""

    def __init__(
        self,
        per_minute: int,
        per_day: int,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.per_minute = per_minute
        self.per_day = per_day
        self._clock = clock
        self._wall = wall_clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._recent: deque[float] = deque()
        self._day = ""
        self._day_count = 0

    def acquire(self, max_wait: float) -> bool:
        deadline = self._clock() + max_wait
        while True:
            with self._lock:
                today = datetime.fromtimestamp(self._wall(), tz=timezone.utc).strftime("%Y-%m-%d")
                if today != self._day:
                    self._day, self._day_count = today, 0
                if self._day_count >= self.per_day:
                    return False
                now = self._clock()
                while self._recent and now - self._recent[0] >= 60:
                    self._recent.popleft()
                if len(self._recent) < self.per_minute:
                    self._recent.append(now)
                    self._day_count += 1
                    return True
                wait = 60 - (now - self._recent[0])
            if self._clock() + wait > deadline:
                return False
            self._sleep(wait)


class VirusTotalClient:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        http: httpx.Client | None = None,
        limiter: RateLimiter | None = None,
    ):
        self.settings = settings
        self.store = store
        self.http = http or httpx.Client(timeout=20.0)
        self.limiter = limiter or RateLimiter(settings.vt_rate_per_minute, settings.vt_daily_quota)

    @property
    def enabled(self) -> bool:
        return bool(self.settings.vt_api_key)

    def lookup(self, event: FileEvent) -> VTResult:
        if not self.enabled:
            return VTResult(status="disabled")
        file_hash = event.best_hash
        if not file_hash:
            return VTResult(status="no_hash")

        cached = self.store.vt_cache_get(file_hash)
        if cached is not None:
            payload, age = cached
            result = VTResult.model_validate(payload)
            # File "chưa được báo cáo" có thể xuất hiện trên VT bất cứ lúc nào -> TTL ngắn hơn.
            ttl_hours = (
                self.settings.vt_cache_ttl_hours
                if result.status == "found"
                else self.settings.vt_not_found_ttl_hours
            )
            if age <= ttl_hours * 3600:
                return result.model_copy(update={"cached": True})

        if not self.limiter.acquire(self.settings.vt_max_wait_seconds):
            return VTResult(status="rate_limited", error="Vượt hạn mức VirusTotal, bỏ qua tra cứu")

        try:
            resp = self._get(f"/files/{file_hash}")
        except httpx.HTTPError as exc:
            log.warning("VirusTotal lookup failed: %s", exc)
            return VTResult(status="error", error=str(exc))

        if resp.status_code == 404:
            result = VTResult(status="not_found", permalink=self._permalink(file_hash))
        elif resp.status_code == 429:
            return VTResult(status="rate_limited", error="VirusTotal trả về 429 (QuotaExceeded)")
        elif resp.status_code != 200:
            return VTResult(status="error", error=f"HTTP {resp.status_code}")
        else:
            result = self._parse_file(resp.json(), file_hash)
            if result.malicious > 0 and self.settings.vt_fetch_mitre:
                result.mitre_techniques = self._mitre_trees(result, file_hash)

        self.store.vt_cache_put(file_hash, result.model_dump())
        return result

    # ------------------------------------------------------------------
    def _get(self, path: str) -> httpx.Response:
        return self.http.get(
            self.settings.vt_base_url + path,
            headers={"x-apikey": self.settings.vt_api_key, "accept": "application/json"},
        )

    @staticmethod
    def _permalink(file_hash: str) -> str:
        return f"https://www.virustotal.com/gui/file/{file_hash}"

    def _parse_file(self, body: dict, file_hash: str) -> VTResult:
        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        ptc = attrs.get("popular_threat_classification") or {}
        categories = ptc.get("popular_threat_category") or []
        names = ptc.get("popular_threat_name") or []
        sha256 = attrs.get("sha256") or file_hash
        return VTResult(
            status="found",
            malicious=int(stats.get("malicious", 0)),
            suspicious=int(stats.get("suspicious", 0)),
            harmless=int(stats.get("harmless", 0)),
            undetected=int(stats.get("undetected", 0)),
            threat_label=ptc.get("suggested_threat_label", "") or "",
            threat_category=(categories[0].get("value", "") if categories else ""),
            threat_names=[n.get("value", "") for n in names if n.get("value")][:5],
            meaningful_name=attrs.get("meaningful_name", "") or "",
            type_description=attrs.get("type_description", "") or "",
            tags=list(attrs.get("tags") or [])[:10],
            first_submission_date=attrs.get("first_submission_date"),
            last_analysis_date=attrs.get("last_analysis_date"),
            times_submitted=attrs.get("times_submitted"),
            permalink=self._permalink(sha256),
        )

    def _mitre_trees(self, result: VTResult, file_hash: str) -> list[dict]:
        """Lấy các kỹ thuật ATT&CK mà sandbox của VirusTotal quan sát được (nếu có)."""
        if not self.limiter.acquire(0):
            return []
        try:
            resp = self._get(f"/files/{file_hash}/behaviour_mitre_trees")
        except httpx.HTTPError:
            return []
        if resp.status_code != 200:
            return []
        techniques: dict[str, dict] = {}
        for sandbox in (resp.json().get("data") or {}).values():
            for tactic in (sandbox or {}).get("tactics") or []:
                for tech in tactic.get("techniques") or []:
                    tid = tech.get("id")
                    if tid and tid not in techniques:
                        techniques[tid] = {
                            "id": tid,
                            "name": tech.get("name", ""),
                            "tactic": tactic.get("name", ""),
                        }
        return list(techniques.values())[:15]
