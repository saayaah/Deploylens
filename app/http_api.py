"""REST API and static file server, built on the standard library.

Stands in for FastAPI in this environment (see TASKS.md). Routes and response shapes
are the ones a FastAPI version would expose. Responses are {"data": ...} on success and
{"error": {"code", "message"}} on failure.
"""
from __future__ import annotations

import json
import os
import re
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .report_export import to_csv, to_json
from .service import ScanService
from .zip_safety import MAX_ARCHIVE_BYTES, ArchiveError, ArchiveLimitError

VERSION = "0.1.0"
FRONTEND_DIR = os.environ.get("DEPLOYLENS_FRONTEND_DIR") or os.path.join(
    os.path.dirname(__file__), "..", "..", "frontend")
SCAN_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8", ".svg": "image/svg+xml"}


def make_handler(service: ScanService):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"DeployLens/{VERSION}"

        # ---- helpers -------------------------------------------------------
        def _send_json(self, status: int, payload) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._common_headers()
            self.end_headers()
            self.wfile.write(body)

        def _send_error_json(self, status: int, code: str, message: str) -> None:
            self._send_json(status, {"error": {"code": code, "message": message}})

        def _send_bytes(self, status: int, body: bytes, content_type: str, filename: str | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if filename:
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self._common_headers()
            self.end_headers()
            self.wfile.write(body)

        def _common_headers(self) -> None:
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")

        def _route(self) -> tuple[list[str], dict[str, str]]:
            parsed = urllib.parse.urlsplit(self.path)
            parts = [p for p in parsed.path.split("/") if p]
            query = dict(urllib.parse.parse_qsl(parsed.query))
            return parts, query

        def log_message(self, fmt, *args):  # keep test and console output quiet
            return

        # ---- verbs ---------------------------------------------------------
        def do_GET(self):
            parts, query = self._route()
            if parts[:1] == ["api"]:
                return self._api_get(parts[1:], query)
            return self._serve_static(parts)

        def do_POST(self):
            parts, _ = self._route()
            if parts == ["api", "scans"]:
                return self._create_upload_scan()
            if parts == ["api", "scans", "demo"]:
                return self._send_json(HTTPStatus.CREATED, {"data": service.scan_demo()})
            return self._send_error_json(404, "not_found", "No such route.")

        def do_DELETE(self):
            parts, _ = self._route()
            if len(parts) == 3 and parts[:2] == ["api", "scans"]:
                if not SCAN_ID_RE.match(parts[2]):
                    return self._send_error_json(400, "invalid_id", "Scan id is malformed.")
                if service.delete_scan(parts[2]):
                    return self._send_bytes(HTTPStatus.NO_CONTENT, b"", "application/json")
                return self._send_error_json(404, "not_found", "Scan not found.")
            return self._send_error_json(404, "not_found", "No such route.")

        # ---- API handlers --------------------------------------------------
        def _api_get(self, parts, query):
            if parts == ["health"]:
                return self._send_json(200, {"data": {"status": "ok", "version": VERSION}})
            if parts == ["scans"]:
                return self._send_json(200, {"data": service.list_scans()})
            if len(parts) == 2 and parts[0] == "scans":
                report = self._load_scan(parts[1])
                if report is None:
                    return
                return self._send_json(200, {"data": report})
            if len(parts) == 3 and parts[0] == "scans" and parts[2] == "export":
                report = self._load_scan(parts[1])
                if report is None:
                    return
                fmt = query.get("format", "json")
                stem = f"deploylens-{report['id']}"
                if fmt == "json":
                    return self._send_bytes(200, to_json(report).encode(), "application/json", f"{stem}.json")
                if fmt == "csv":
                    return self._send_bytes(200, to_csv(report).encode(), "text/csv; charset=utf-8", f"{stem}.csv")
                return self._send_error_json(400, "invalid_format", "format must be json or csv.")
            return self._send_error_json(404, "not_found", "No such route.")

        def _load_scan(self, scan_id: str):
            if not SCAN_ID_RE.match(scan_id):
                self._send_error_json(400, "invalid_id", "Scan id is malformed.")
                return None
            report = service.get_scan(scan_id)
            if report is None:
                self._send_error_json(404, "not_found", "Scan not found.")
            return report

        def _create_upload_scan(self):
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                return self._send_error_json(411, "length_required", "Content-Length header is required.")
            try:
                length = int(length_header)
            except ValueError:
                return self._send_error_json(400, "invalid_length", "Content-Length is not a number.")
            if length <= 0:
                return self._send_error_json(400, "empty_upload", "Upload is empty.")
            if length > MAX_ARCHIVE_BYTES:
                return self._send_error_json(413, "too_large",
                                             f"Upload exceeds the {MAX_ARCHIVE_BYTES // (1024 * 1024)} MB limit.")
            filename = self.headers.get("X-Filename", "upload.zip")
            if not filename.lower().endswith(".zip"):
                return self._send_error_json(415, "unsupported_type", "Only .zip archives are accepted.")
            body = self.rfile.read(length)
            try:
                report = service.scan_zip(body, filename)
            except ArchiveLimitError as exc:
                return self._send_error_json(413, "archive_limit", str(exc))
            except ArchiveError as exc:
                return self._send_error_json(400, "invalid_archive", str(exc))
            return self._send_json(HTTPStatus.CREATED, {"data": report})

        # ---- static frontend ----------------------------------------------
        def _serve_static(self, parts):
            root = os.path.realpath(FRONTEND_DIR)
            rel = "index.html" if not parts else "/".join(parts)
            target = os.path.realpath(os.path.join(root, rel))
            if not target.startswith(root + os.sep) or not os.path.isfile(target):
                return self._send_error_json(404, "not_found", "No such file.")
            ext = os.path.splitext(target)[1].lower()
            with open(target, "rb") as fh:
                data = fh.read()
            return self._send_bytes(200, data, STATIC_TYPES.get(ext, "application/octet-stream"))

    return Handler


def make_server(service: ScanService, host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(service))
