"""SQLite persistence for scan reports. Stores report JSON and metadata only; never source files."""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any
import uuid

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    source TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    score INTEGER,
    label TEXT,
    report_json TEXT NOT NULL
);
"""


class ScanStore:
    def __init__(self, path: str = ":memory:") -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save(self, report: dict[str, Any], source: str) -> str:
        scan_id = str(uuid.uuid4())
        report = {**report, "id": scan_id, "source": source}
        with self._lock:
            self._conn.execute(
                "INSERT INTO scans (id, project_name, source, scanned_at, score, label, report_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, report["project_name"], source, report["scanned_at"],
                 report["score"], report["label"], json.dumps(report)),
            )
            self._conn.commit()
        return scan_id

    def list_summaries(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, project_name, source, scanned_at, score, label FROM scans "
                "ORDER BY scanned_at DESC, rowid DESC").fetchall()
        return [dict(r) for r in rows]

    def get(self, scan_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return json.loads(row["report_json"]) if row else None

    def delete(self, scan_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            self._conn.commit()
        return cur.rowcount > 0


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
