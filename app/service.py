"""Business logic shared by every interface (HTTP API, CLI). Route handlers stay thin."""
from __future__ import annotations

import os

from .analyzer import analyze_archive, analyze_directory
from .store import ScanStore, utc_now

DEMO_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "demo_project")
DEMO_NAME = "demo-notes-api (bundled demo)"


class ScanService:
    def __init__(self, store: ScanStore) -> None:
        self.store = store

    def scan_zip(self, data: bytes, filename: str) -> dict:
        name = os.path.basename(filename or "upload.zip") or "upload.zip"
        report = analyze_archive(data, name, utc_now())
        scan_id = self.store.save(report, source="upload")
        return self.store.get(scan_id)

    def scan_demo(self) -> dict:
        report = analyze_directory(DEMO_DIR, DEMO_NAME, utc_now())
        scan_id = self.store.save(report, source="demo")
        return self.store.get(scan_id)

    def list_scans(self) -> list[dict]:
        return self.store.list_summaries()

    def get_scan(self, scan_id: str) -> dict | None:
        return self.store.get(scan_id)

    def delete_scan(self, scan_id: str) -> bool:
        return self.store.delete(scan_id)
