"""Unit tests for the analysis core. Uses only the standard library (unittest)."""
import io
import os
import sys
import unittest
import zipfile
from datetime import datetime, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import zip_safety  # noqa: E402
from app.analyzer import analyze_archive, analyze_directory, analyze_files  # noqa: E402
from app.context import (  # noqa: E402
    TECH_DJANGO, TECH_EXPRESS, TECH_FLASK, TECH_PYTHON_FASTAPI, ProjectContext, detect_technologies,
)
from app.redaction import REDACTED, redact, scan_text_for_secrets  # noqa: E402
from app.rules import FAIL, NOT_APPLICABLE, PASS, WARN  # noqa: E402
from app.scoring import compute_score  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(__file__), "..", "fixtures", "demo_project")
FIXED_TIME = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_zip(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def finding(report: dict, rule_id: str) -> dict:
    return next(f for f in report["findings"] if f["id"] == rule_id)


class ZipValidationTests(unittest.TestCase):
    def test_valid_archive_returns_entries(self):
        entries = zip_safety.validate_archive(make_zip({"a/b.py": "x", "README.md": "y"}))
        self.assertEqual(sorted(e.path for e in entries), ["README.md", "a/b.py"])

    def test_parent_traversal_is_rejected(self):
        with self.assertRaises(zip_safety.UnsafeArchiveError):
            zip_safety.validate_archive(make_zip({"../evil.txt": "x"}))

    def test_embedded_traversal_is_rejected(self):
        with self.assertRaises(zip_safety.UnsafeArchiveError):
            zip_safety.validate_archive(make_zip({"a/../../x": "x"}))

    def test_absolute_path_is_rejected(self):
        with self.assertRaises(zip_safety.UnsafeArchiveError):
            zip_safety.validate_archive(make_zip({"/etc/passwd": "x"}))

    def test_windows_drive_path_is_rejected(self):
        with self.assertRaises(zip_safety.UnsafeArchiveError):
            zip_safety.validate_archive(make_zip({"C:evil.txt": "x"}))

    def test_symlink_entry_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.external_attr = (0o120777 & 0xFFFF) << 16
            zf.writestr(info, "/etc/passwd")
        with self.assertRaises(zip_safety.UnsafeArchiveError):
            zip_safety.validate_archive(buf.getvalue())

    def test_invalid_zip_is_rejected(self):
        with self.assertRaises(zip_safety.ArchiveError):
            zip_safety.validate_archive(b"this is not a zip")

    def test_empty_upload_is_rejected(self):
        with self.assertRaises(zip_safety.ArchiveError):
            zip_safety.validate_archive(b"")

    def test_archive_with_only_directories_is_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("folder/", "")
        with self.assertRaises(zip_safety.ArchiveError):
            zip_safety.validate_archive(buf.getvalue())

    def test_oversized_upload_is_rejected(self):
        with mock.patch.object(zip_safety, "MAX_ARCHIVE_BYTES", 10):
            with self.assertRaises(zip_safety.ArchiveLimitError):
                zip_safety.validate_archive(make_zip({"a.txt": "x" * 100}))

    def test_file_count_limit_is_enforced(self):
        with mock.patch.object(zip_safety, "MAX_FILES", 2):
            with self.assertRaises(zip_safety.ArchiveLimitError):
                zip_safety.validate_archive(make_zip({f"f{i}.txt": "x" for i in range(5)}))

    def test_total_uncompressed_limit_is_enforced(self):
        with mock.patch.object(zip_safety, "MAX_TOTAL_UNCOMPRESSED", 50):
            with self.assertRaises(zip_safety.ArchiveLimitError):
                zip_safety.validate_archive(make_zip({"a.txt": "x" * 100}))

    def test_zip_bomb_ratio_is_rejected(self):
        # 2 MB of zeros compresses to a few KB, well above the ratio limit.
        data = make_zip({"bomb.txt": b"\x00" * (2 * 1024 * 1024)})
        with self.assertRaises(zip_safety.UnsafeArchiveError):
            zip_safety.validate_archive(data)


class DetectionTests(unittest.TestCase):
    def test_detects_fastapi_from_requirements(self):
        ctx = ProjectContext(files={"requirements.txt": b"fastapi==0.110.0\n", "main.py": b""})
        self.assertIn(TECH_PYTHON_FASTAPI, detect_technologies(ctx))

    def test_detects_django_from_manage_py(self):
        ctx = ProjectContext(files={"manage.py": b"import django"})
        self.assertIn(TECH_DJANGO, detect_technologies(ctx))

    def test_detects_flask_and_express(self):
        ctx = ProjectContext(files={
            "requirements.txt": b"Flask==3.0.0\n",
            "package.json": b'{"dependencies": {"express": "^4.18.0"}}',
        })
        techs = detect_technologies(ctx)
        self.assertIn(TECH_FLASK, techs)
        self.assertIn(TECH_EXPRESS, techs)

    def test_multiple_technologies_are_sorted_and_deduplicated(self):
        ctx = ProjectContext(files={"requirements.txt": b"fastapi\nflask\n", "manage.py": b""})
        techs = detect_technologies(ctx)
        self.assertEqual(techs, sorted(set(techs)))

    def test_unknown_project_detects_nothing(self):
        self.assertEqual(detect_technologies(ProjectContext(files={"notes.bin": b"\x00\x01"})), [])


class RedactionTests(unittest.TestCase):
    SECRET = "sk_live_abcdef1234567890XYZ"

    def test_secret_value_never_appears_in_scan_output(self):
        hits = scan_text_for_secrets("config.py", f'API_KEY = "{self.SECRET}"\n')
        self.assertTrue(hits)
        for h in hits:
            self.assertNotIn(self.SECRET, repr(h))

    def test_redact_removes_secret_value_from_text(self):
        out = redact(f'api_key = "{self.SECRET}"')
        self.assertNotIn(self.SECRET, out)
        self.assertIn(REDACTED, out)

    def test_placeholder_values_are_not_flagged(self):
        self.assertEqual(scan_text_for_secrets("x.py", 'api_key = "your_api_key_here_123456"'), [])

    def test_aws_access_key_is_detected(self):
        hits = scan_text_for_secrets("x.py", "KEY = 'AKIAABCDEFGHIJKLMNOP'")
        self.assertEqual(hits[0].label, "AWS access key ID")


class RuleTests(unittest.TestCase):
    def test_env_file_is_critical_failure(self):
        report = analyze_files({"app.py": b"", ".env": b"DB=postgres://u:p@h/db"}, "p", FIXED_TIME)
        f = finding(report, "CFG-001")
        self.assertEqual(f["status"], FAIL)
        self.assertEqual(f["severity"], "critical")

    def test_env_example_does_not_trigger_env_failure(self):
        report = analyze_files({"app.py": b"", ".env.example": b"DB=changeme"}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CFG-001")["status"], PASS)

    def test_gitignore_missing_env_entry_fails_when_env_present(self):
        report = analyze_files({".env": b"X=1", ".gitignore": b"node_modules/\n"}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CFG-002")["status"], FAIL)

    def test_gitignore_rule_not_applicable_without_env(self):
        report = analyze_files({"app.py": b""}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CFG-002")["status"], NOT_APPLICABLE)

    def test_django_debug_true_fails(self):
        report = analyze_files({"manage.py": b"", "proj/settings.py": b"DEBUG = True\n"}, "p", FIXED_TIME)
        f = finding(report, "CFG-004")
        self.assertEqual(f["status"], FAIL)
        self.assertEqual(f["evidence"], ["proj/settings.py:1"])

    def test_django_debug_false_passes(self):
        report = analyze_files({"manage.py": b"", "proj/settings.py": b"DEBUG = False\n"}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CFG-004")["status"], PASS)

    def test_dockerfile_without_user_warns(self):
        files = {"requirements.txt": b"fastapi==1.0\n", "Dockerfile": b"FROM python:3.12-slim\nCMD [\"x\"]\n"}
        report = analyze_files(files, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CONT-003")["status"], WARN)

    def test_dockerfile_latest_tag_warns(self):
        files = {"requirements.txt": b"fastapi==1.0\n", "Dockerfile": b"FROM python:latest\n"}
        report = analyze_files(files, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CONT-004")["status"], WARN)

    def test_missing_dockerfile_is_failure_for_web_project(self):
        report = analyze_files({"requirements.txt": b"fastapi==1.0\n"}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CONT-001")["status"], FAIL)

    def test_dockerignore_rule_not_applicable_without_dockerfile(self):
        report = analyze_files({"requirements.txt": b"fastapi==1.0\n"}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CONT-002")["status"], NOT_APPLICABLE)

    def test_unpinned_python_requirements_warn(self):
        report = analyze_files({"requirements.txt": b"fastapi\n"}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "DEP-003")["status"], WARN)

    def test_missing_manifest_fails_for_python_project(self):
        report = analyze_files({"main.py": b"import os\n"}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "DEP-001")["status"], FAIL)

    def test_no_tests_fails(self):
        report = analyze_files({"requirements.txt": b"fastapi==1.0\n", "app.py": b""}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "TST-001")["status"], FAIL)

    def test_test_files_pass(self):
        report = analyze_files({"requirements.txt": b"fastapi==1.0\n", "tests/test_a.py": b""}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "TST-001")["status"], PASS)

    def test_health_endpoint_detected(self):
        src = b'@app.get("/health")\ndef h(): return {"ok": True}\n'
        report = analyze_files({"requirements.txt": b"fastapi==1.0\n", "main.py": src}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "APP-001")["status"], PASS)

    def test_health_endpoint_warns_when_absent(self):
        report = analyze_files({"requirements.txt": b"fastapi==1.0\n", "main.py": b"x=1"}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "APP-001")["status"], WARN)

    def test_flask_debug_true_fails(self):
        src = b"app.run(host='0.0.0.0', debug=True)\n"
        report = analyze_files({"requirements.txt": b"flask==3.0\n", "app.py": src}, "p", FIXED_TIME)
        self.assertEqual(finding(report, "CFG-006")["status"], FAIL)

    def test_remediation_only_for_actionable_findings(self):
        report = analyze_files({"requirements.txt": b"fastapi==1.0\n", "main.py": b'@app.get("/health")\n'}, "p", FIXED_TIME)
        for f in report["findings"]:
            if f["status"] in (PASS, NOT_APPLICABLE):
                self.assertIsNone(f["remediation"])
            else:
                self.assertTrue(f["remediation"])


class ScoringTests(unittest.TestCase):
    def _f(self, status, severity):
        return {"status": status, "severity": severity}

    def test_all_pass_scores_100(self):
        score, label, _ = compute_score([self._f(PASS, "high"), self._f(PASS, "low")])
        self.assertEqual(score, 100)
        self.assertEqual(label, "Strong readiness")

    def test_all_fail_scores_0(self):
        score, label, _ = compute_score([self._f(FAIL, "high")])
        self.assertEqual(score, 0)
        self.assertEqual(label, "Significant improvements required")

    def test_warn_earns_half_credit(self):
        score, _, _ = compute_score([self._f(PASS, "low"), self._f(WARN, "low")])
        self.assertEqual(score, 75)

    def test_not_applicable_is_excluded(self):
        score, _, breakdown = compute_score([self._f(PASS, "low"), self._f(NOT_APPLICABLE, "critical")])
        self.assertEqual(score, 100)
        self.assertEqual(breakdown["possible_points"], 2)

    def test_severity_weights_affect_score(self):
        # critical FAIL (10) outweighs low PASS (2): 2/12 ~ 17
        score, _, _ = compute_score([self._f(FAIL, "critical"), self._f(PASS, "low")])
        self.assertEqual(score, 17)

    def test_no_applicable_checks_gives_no_score(self):
        score, label, _ = compute_score([self._f(NOT_APPLICABLE, "low")])
        self.assertIsNone(score)
        self.assertIsNone(label)

    def test_label_thresholds(self):
        from app.scoring import label_for
        self.assertEqual(label_for(100), "Strong readiness")
        self.assertEqual(label_for(90), "Strong readiness")
        self.assertEqual(label_for(89), "Good readiness with improvements")
        self.assertEqual(label_for(75), "Good readiness with improvements")
        self.assertEqual(label_for(74), "Needs attention")
        self.assertEqual(label_for(50), "Needs attention")
        self.assertEqual(label_for(49), "Significant improvements required")
        self.assertEqual(label_for(0), "Significant improvements required")


class AnalyzerTests(unittest.TestCase):
    def test_same_input_gives_identical_output(self):
        files = {"requirements.txt": b"fastapi\n", "app.py": b"DEBUG = True"}
        a = analyze_files(files, "p", FIXED_TIME)
        b = analyze_files(files, "p", FIXED_TIME)
        self.assertEqual(a, b)

    def test_counts_are_consistent(self):
        report = analyze_directory(FIXTURE, "demo", FIXED_TIME)
        c = report["counts"]
        self.assertEqual(c["total_checks"], c["passed"] + c["warnings"] + c["failed"] + c["unverified"])

    def test_demo_fixture_produces_real_findings(self):
        report = analyze_directory(FIXTURE, "demo", FIXED_TIME)
        self.assertIn("FastAPI", report["technologies"])
        self.assertEqual(finding(report, "CFG-003")["status"], FAIL)   # the fake key in config.py
        self.assertEqual(finding(report, "CFG-001")["status"], PASS)   # no real .env shipped
        self.assertEqual(finding(report, "CI-002")["status"], PASS)    # workflow runs pytest
        self.assertIsNotNone(report["score"])

    def test_demo_report_never_leaks_its_fake_secret(self):
        report = analyze_directory(FIXTURE, "demo", FIXED_TIME)
        self.assertNotIn("demo_sk_live_0123456789abcdef", repr(report))

    def test_archive_analysis_end_to_end(self):
        data = make_zip({
            "app/main.py": '@app.get("/health")\ndef h(): pass\n',
            "requirements.txt": "fastapi==0.110.0\nuvicorn==0.29.0\n",
            "Dockerfile": "FROM python:3.12-slim\nUSER app\nCMD [\"uvicorn\", \"app.main:app\"]\n",
            ".dockerignore": ".git\n",
            ".gitignore": ".env\n",
            "tests/test_app.py": "def test_x(): pass\n",
            "README.md": "# x\n",
            ".env.example": "KEY=\n",
            ".github/workflows/ci.yml": "steps:\n  - run: pytest\n",
        })
        report = analyze_archive(data, "good-app", FIXED_TIME)
        self.assertEqual(report["counts"]["failed"], 0)
        self.assertEqual(report["score"], 100)
        self.assertEqual(report["label"], "Strong readiness")

    def test_invalid_archive_raises_before_analysis(self):
        with self.assertRaises(zip_safety.ArchiveError):
            analyze_archive(b"not a zip", "x", FIXED_TIME)


if __name__ == "__main__":
    unittest.main()


class ExportTests(unittest.TestCase):
    def test_json_export_round_trips(self):
        import json
        from app.report_export import to_json
        report = analyze_directory(FIXTURE, "demo", FIXED_TIME)
        self.assertEqual(json.loads(to_json(report))["score"], report["score"])

    def test_csv_has_header_and_one_row_per_finding(self):
        import csv as csvmod
        import io as iomod
        from app.report_export import CSV_COLUMNS, to_csv
        report = analyze_directory(FIXTURE, "demo", FIXED_TIME)
        rows = list(csvmod.reader(iomod.StringIO(to_csv(report))))
        self.assertEqual(rows[0], CSV_COLUMNS)
        self.assertEqual(len(rows) - 1, len(report["findings"]))

    def test_csv_never_contains_secret_value(self):
        from app.report_export import to_csv
        report = analyze_directory(FIXTURE, "demo", FIXED_TIME)
        self.assertNotIn("demo_sk_live_0123456789abcdef", to_csv(report))
