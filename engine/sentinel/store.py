"""Lưu trữ SQLite: cache VirusTotal, sự cố (incident), danh sách hash đã xác nhận an toàn."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS vt_cache (
    hash TEXT PRIMARY KEY,
    fetched_at REAL NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    agent_id TEXT NOT NULL,
    path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    severity TEXT NOT NULL,
    data TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    decision TEXT,
    decided_at REAL
);
CREATE INDEX IF NOT EXISTS idx_incidents_dedup ON incidents (agent_id, path, file_hash, created_at);
CREATE TABLE IF NOT EXISTS allowlist (
    hash TEXT PRIMARY KEY,
    added_at REAL NOT NULL,
    incident_id TEXT,
    note TEXT
);
"""


class Store:
    def __init__(self, path: str = ":memory:", clock=time.time):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._clock = clock

    # --- VirusTotal cache -------------------------------------------------
    def vt_cache_get(self, file_hash: str) -> Optional[tuple[dict, float]]:
        """Trả về (payload, tuổi tính bằng giây) hoặc None nếu chưa có trong cache."""
        with self._lock:
            row = self._conn.execute(
                "SELECT fetched_at, payload FROM vt_cache WHERE hash = ?", (file_hash,)
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["payload"]), self._clock() - row["fetched_at"]

    def vt_cache_put(self, file_hash: str, payload: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO vt_cache (hash, fetched_at, payload) VALUES (?, ?, ?)",
                (file_hash, self._clock(), json.dumps(payload)),
            )

    # --- Incidents ----------------------------------------------------------
    def find_recent_incident(
        self, agent_id: str, path: str, file_hash: str, window_seconds: float
    ) -> Optional[dict]:
        since = self._clock() - window_seconds
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE agent_id = ? AND path = ? AND file_hash = ?"
                " AND created_at >= ? ORDER BY created_at DESC LIMIT 1",
                (agent_id, path, file_hash, since),
            ).fetchone()
        return self._row(row)

    def save_incident(
        self, incident_id: str, agent_id: str, path: str, file_hash: str, severity: str, data: dict
    ) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO incidents (id, created_at, agent_id, path, file_hash, severity, data)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(id) DO UPDATE SET severity = excluded.severity, data = excluded.data",
                (incident_id, self._clock(), agent_id, path, file_hash, severity, json.dumps(data)),
            )

    def get_incident(self, incident_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
        return self._row(row)

    def list_incidents(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row(r) for r in rows]  # type: ignore[misc]

    def record_decision(self, incident_id: str, decision: str) -> bool:
        """Ghi quyết định của analyst. Trả về False nếu sự cố đã được xử lý trước đó."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE incidents SET status = 'closed', decision = ?, decided_at = ?"
                " WHERE id = ? AND status = 'open'",
                (decision, self._clock(), incident_id),
            )
        return cur.rowcount == 1

    # --- Allowlist (phản hồi dương tính giả) --------------------------------
    def allowlist_add(self, file_hash: str, incident_id: str, note: str = "") -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO allowlist (hash, added_at, incident_id, note)"
                " VALUES (?, ?, ?, ?)",
                (file_hash, self._clock(), incident_id, note),
            )

    def is_allowlisted(self, file_hash: str) -> bool:
        if not file_hash:
            return False
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM allowlist WHERE hash = ?", (file_hash,)
            ).fetchone()
        return row is not None

    @staticmethod
    def _row(row: Any) -> Optional[dict]:
        if row is None:
            return None
        result = dict(row)
        result["data"] = json.loads(result["data"])
        return result
