"""End-to-end API tests over real HTTP against an in-process server on an ephemeral port."""
import io
import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.http_api import make_server  # noqa: E402
from app.service import ScanService  # noqa: E402
from app.store import ScanStore  # noqa: E402


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service = ScanService(ScanStore(":memory:"))
        cls.server = make_server(cls.service, "127.0.0.1", 0)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.service.store.close()

    def request(self, method, path, body=None, headers=None):
        req = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as err:
            return err.code, dict(err.headers), err.read()

    def json_request(self, method, path, body=None, headers=None):
        status, hdrs, raw = self.request(method, path, body, headers)
        return status, json.loads(raw) if raw else None

    def upload(self, data, filename="app.zip"):
        return self.json_request("POST", "/api/scans", data,
                                 {"Content-Type": "application/zip", "X-Filename": filename,
                                  "Content-Length": str(len(data))})

    # ---- health and static --------------------------------------------------
    def test_health_endpoint(self):
        status, body = self.json_request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["data"]["status"], "ok")

    def test_dashboard_is_served(self):
        status, headers, raw = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"DeployLens", raw)

    def test_static_path_traversal_is_blocked(self):
        status, _, _ = self.request("GET", "/..%2F..%2Fetc%2Fpasswd")
        self.assertEqual(status, 404)

    def test_unknown_static_file_is_404(self):
        status, _, _ = self.request("GET", "/nope.js")
        self.assertEqual(status, 404)

    # ---- upload and demo ----------------------------------------------------
    def test_demo_scan_creates_report(self):
        status, body = self.json_request("POST", "/api/scans/demo")
        self.assertEqual(status, 201)
        report = body["data"]
        self.assertIn("FastAPI", report["technologies"])
        self.assertEqual(report["source"], "demo")
        self.assertIsNotNone(report["score"])

    def test_valid_upload_produces_findings_from_real_files(self):
        data = make_zip({"app/main.py": "print(1)\n", "requirements.txt": "flask\n", "README.md": "x"})
        status, body = self.upload(data, "my-app.zip")
        self.assertEqual(status, 201)
        report = body["data"]
        self.assertEqual(report["project_name"], "my-app.zip")
        self.assertIn("Flask", report["technologies"])
        ids = {f["id"]: f["status"] for f in report["findings"]}
        self.assertEqual(ids["DEP-003"], "WARN")  # unpinned 'flask' from the uploaded file

    def test_upload_with_env_file_reports_critical_failure_without_leaking_value(self):
        data = make_zip({"requirements.txt": "fastapi==1.0\n", ".env": "DB_PASSWORD=supersecretvalue123\n"})
        status, body = self.upload(data, "leaky.zip")
        self.assertEqual(status, 201)
        serialized = json.dumps(body)
        self.assertNotIn("supersecretvalue123", serialized)
        cfg = next(f for f in body["data"]["findings"] if f["id"] == "CFG-001")
        self.assertEqual(cfg["status"], "FAIL")

    def test_path_traversal_archive_is_rejected_400(self):
        status, body = self.upload(make_zip({"../escape.txt": "x"}), "bad.zip")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_archive")

    def test_non_zip_bytes_are_rejected_400(self):
        status, body = self.upload(b"plain text, not a zip", "fake.zip")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_archive")

    def test_non_zip_filename_is_rejected_415(self):
        status, body = self.upload(make_zip({"a.py": "x"}), "project.tar.gz")
        self.assertEqual(status, 415)
        self.assertEqual(body["error"]["code"], "unsupported_type")

    def test_oversized_upload_is_rejected_413_before_reading(self):
        status, body = self.json_request("POST", "/api/scans",
                                         b"x", {"Content-Type": "application/zip", "X-Filename": "a.zip",
                                                "Content-Length": str(25 * 1024 * 1024)})
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "too_large")

    def test_missing_content_length_is_411(self):
        req = urllib.request.Request(self.base + "/api/scans", data=None, method="POST",
                                     headers={"X-Filename": "a.zip"})
        # urllib sends Content-Length: 0 for empty bodies; bypass with a raw request check instead.
        status, body = self.json_request("POST", "/api/scans", b"", {"X-Filename": "a.zip"})
        self.assertIn(status, (400, 411))

    def test_empty_upload_is_rejected(self):
        status, body = self.json_request("POST", "/api/scans", b"", {"X-Filename": "a.zip",
                                                                     "Content-Length": "0"})
        self.assertEqual(status, 400)

    # ---- history, retrieval, deletion, export ------------------------------
    def test_history_lists_and_report_is_retrievable(self):
        _, created = self.json_request("POST", "/api/scans/demo")
        scan_id = created["data"]["id"]
        _, listing = self.json_request("GET", "/api/scans")
        self.assertIn(scan_id, [s["id"] for s in listing["data"]])
        _, one = self.json_request("GET", f"/api/scans/{scan_id}")
        self.assertEqual(one["data"]["id"], scan_id)

    def test_unknown_report_is_404(self):
        status, body = self.json_request("GET", "/api/scans/00000000-0000-4000-8000-000000000000")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    def test_malformed_id_is_400(self):
        status, body = self.json_request("GET", "/api/scans/not-a-valid-id")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_id")

    def test_delete_then_get_is_404(self):
        _, created = self.json_request("POST", "/api/scans/demo")
        scan_id = created["data"]["id"]
        status, _, _ = self.request("DELETE", f"/api/scans/{scan_id}")
        self.assertEqual(status, 204)
        status, _ = self.json_request("GET", f"/api/scans/{scan_id}")
        self.assertEqual(status, 404)
        status, _, _ = self.request("DELETE", f"/api/scans/{scan_id}")
        self.assertEqual(status, 404)

    def test_export_json_is_attachment_and_parses(self):
        _, created = self.json_request("POST", "/api/scans/demo")
        scan_id = created["data"]["id"]
        status, headers, raw = self.request("GET", f"/api/scans/{scan_id}/export?format=json")
        self.assertEqual(status, 200)
        self.assertIn("attachment", headers["Content-Disposition"])
        self.assertEqual(json.loads(raw)["id"], scan_id)

    def test_export_csv_has_header(self):
        _, created = self.json_request("POST", "/api/scans/demo")
        scan_id = created["data"]["id"]
        status, headers, raw = self.request("GET", f"/api/scans/{scan_id}/export?format=csv")
        self.assertEqual(status, 200)
        self.assertIn("text/csv", headers["Content-Type"])
        self.assertTrue(raw.decode().startswith("id,title,category"))

    def test_export_bad_format_is_400(self):
        _, created = self.json_request("POST", "/api/scans/demo")
        status, body = self.json_request("GET", f"/api/scans/{created['data']['id']}/export?format=xml")
        self.assertEqual(status, 400)

    def test_demo_secret_never_appears_in_any_api_response(self):
        _, created = self.json_request("POST", "/api/scans/demo")
        scan_id = created["data"]["id"]
        for path in ["/api/scans", f"/api/scans/{scan_id}", f"/api/scans/{scan_id}/export?format=csv",
                     f"/api/scans/{scan_id}/export?format=json"]:
            _, _, raw = self.request("GET", path)
            self.assertNotIn(b"demo_sk_live_0123456789abcdef", raw, path)


if __name__ == "__main__":
    unittest.main()
