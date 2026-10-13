"""Report serialization to JSON and CSV. Input is the analyzer's report dict."""
from __future__ import annotations

import csv
import io
import json

CSV_COLUMNS = ["id", "title", "category", "severity", "status", "explanation", "remediation", "evidence"]


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, sort_keys=False)


def to_csv(report: dict) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for f in report["findings"]:
        writer.writerow({
            **{k: f.get(k) or "" for k in CSV_COLUMNS if k != "evidence"},
            "evidence": " | ".join(f.get("evidence", [])),
        })
    return buf.getvalue()
