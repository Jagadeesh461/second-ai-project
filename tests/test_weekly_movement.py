import csv
import json
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import services.csv_loader as csv_loader
import services.vulnerability_service as service
from tests.js_harness import run_js
from utils.vuln_identity import vul_key


class WeeklyMovementImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.output = self.root / "output"
        self.archive = self.root / "archive"
        for path in (self.data, self.output, self.archive):
            path.mkdir()
        self.paths = patch.multiple(
            service,
            BASE_DIR=self.root,
            DATA_DIR=self.data,
            OUTPUT_DIR=self.output,
            ARCHIVE_DIR=self.archive,
            PROCESSED_REPORT_PATH=self.output / "processed_vulnerabilities.csv",
            DASHBOARD_STATS_PATH=self.output / "dashboard_stats.json",
            IMPORT_MANIFEST_PATH=self.output / "import_manifest.json",
        )
        self.paths.start()
        self.addCleanup(self.paths.stop)

    def test_avs_update_marks_score_reduction_as_improved_or_treated(self):
        previous = {
            "applications": [{
                "AppSpaceId": "AS-00010",
                "AppSpaceName": "Document Management",
                "AVSScore": 501,
                "AVSLevel": "Medium",
            }],
        }
        current = {
            "applications": [{
                "AppSpaceId": "AS-00010",
                "AppSpaceName": "Document Management",
                "AVSScore": 1,
                "AVSLevel": "Low",
            }],
        }

        update = service._build_avs_update(current, previous, date(2026, 10, 29))

        self.assertEqual(update["rows"], [{
            "app_name": "Document Management",
            "avs": 1,
            "previous_avs": 501.0,
            "score_change": -500.0,
            "status": "Improved/Treated",
        }])

    def test_avs_update_marks_score_increase_as_new(self):
        current = {
            "applications": [
                {
                    "AppSpaceId": "AS-00011",
                    "AppSpaceName": "High scoring new app",
                    "AVSScore": 501,
                    "AVSLevel": "Medium",
                },
                {
                    "AppSpaceId": "AS-00012",
                    "AppSpaceName": "Low scoring new app",
                    "AVSScore": 499,
                    "AVSLevel": "Low",
                },
            ],
        }
        previous = {
            "applications": [
                {
                    "AppSpaceId": "AS-00011",
                    "AppSpaceName": "High scoring new app",
                    "AVSScore": 499,
                    "AVSLevel": "Low",
                },
                {
                    "AppSpaceId": "AS-00012",
                    "AppSpaceName": "Low scoring new app",
                    "AVSScore": 100,
                    "AVSLevel": "Low",
                },
            ],
        }

        update = service._build_avs_update(current, previous, date(2026, 10, 29))

        self.assertEqual(update["rows"], [{
            "app_name": "High scoring new app",
            "avs": 501,
            "previous_avs": 499.0,
            "score_change": 2.0,
            "status": "New",
        }])

    def write_report(self, name, findings):
        path = self.data / name
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_loader.STANDARD_COLUMNS)
            writer.writeheader()
            for finding in findings:
                row = {column: "" for column in csv_loader.STANDARD_COLUMNS}
                row.update({
                    "ServerName": finding["server"],
                    "OperatingSystem": "Linux",
                    "Environment": "PROD",
                    "AppSpaceId": "APP001",
                    "AppSpaceName": "Payment Gateway Hub",
                    "AppSpaceTeam": "Platform",
                    "QID": finding["qid"],
                    "VulnerabilityName": f"Finding {finding['qid']}",
                    "Severity": "High",
                    "AssetRiskScore": "70",
                    "PCIRequired": "no",
                    "Category": "Patch",
                    "CVE": f"CVE-2026-{finding['qid']}",
                    "VendorReference": "Vendor",
                    "FirstDetected": "2026-10-01",
                    "LastDetected": "2026-10-12",
                    "Resolved": "",
                    "SLABreach": "no",
                    "Status": "Open",
                })
                writer.writerow(row)
        return path

    def test_vul_key_formula(self):
        self.assertEqual(
            vul_key("APP001", "Payment Gateway Hub", "SERVER01", "PROD", "123456"),
            "APP001||Payment Gateway Hub||SERVER01||PROD||123456",
        )

    def test_current_active_plus_latest_resolved_are_written(self):
        first = self.write_report("week1.csv", [
            {"server": "SERVER01", "qid": "100"},
            {"server": "SERVER02", "qid": "200"},
        ])
        service._process_source_report(first, force=True)
        second = self.write_report("week2.csv", [
            {"server": "SERVER01", "qid": "100"},
            {"server": "SERVER03", "qid": "300"},
        ])

        result = service._process_source_report(second, force=True)

        with service.PROCESSED_REPORT_PATH.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            sorted(row["NewResolvedStatus"] for row in rows),
            ["New", "Resolved", "Unchanged"],
        )
        self.assertEqual(result["dashboard"]["meta"]["record_count"], 3)
        resolved = next(row for row in rows if row["NewResolvedStatus"] == "Resolved")
        self.assertEqual(resolved["ServerName"], "SERVER02")

        history = json.loads((self.root / "static" / "trend_history.json").read_text(encoding="utf-8"))
        # Week comes from the report's latest LastDetected (2026-10-12), not the import date.
        self.assertEqual(history[-1], {"week": "12-10-2026", "new": 1, "resolved": 1, "unchanged": 1})

        third = self.write_report("week3.csv", [{"server": "SERVER03", "qid": "300"}])
        service._process_source_report(third, force=True)
        with service.PROCESSED_REPORT_PATH.open("r", encoding="utf-8", newline="") as handle:
            latest_rows = list(csv.DictReader(handle))
        self.assertEqual(len(latest_rows), 2)
        self.assertEqual(
            {row["ServerName"]: row["NewResolvedStatus"] for row in latest_rows},
            {"SERVER03": "Unchanged", "SERVER01": "Resolved"},
        )
        self.assertNotIn("SERVER02", {row["ServerName"] for row in latest_rows})

    def test_trend_history_keeps_latest_seven_weeks(self):
        records, _ = csv_loader.load_vulnerabilities(
            self.write_report("retention.csv", [{"server": "SERVER01", "qid": "100"}]),
            today=date(2026, 9, 1),
        )
        start = date(2026, 9, 7)
        for offset in range(8):
            service._update_trend_history(records, [], start + timedelta(weeks=offset))
        history = json.loads((self.root / "static" / "trend_history.json").read_text(encoding="utf-8"))
        self.assertEqual(len(history), 7)
        self.assertEqual(history[0]["week"], "14-09-2026")
        self.assertEqual(history[-1]["week"], "26-10-2026")


class WeeklyMovementBrowserTests(unittest.TestCase):
    def test_filter_uses_shared_filter_framework(self):
        records = [
            {"NewResolvedStatus": "New"},
            {"NewResolvedStatus": "Resolved"},
            {"NewResolvedStatus": "Unchanged"},
        ]
        result = run_js(
            "CONTEXT.records.filter(r => recordMatchesFilters(r, {new_resolved_status:['Resolved']})).length",
            files=("filters.js",),
            context={"records": records},
        )
        self.assertEqual(result, 1)

    def test_assistant_answers_weekly_movement(self):
        answer = run_js(
            "answerAssistantQuestion(CONTEXT.question, CONTEXT)",
            context={
                "question": "How many vulnerabilities were resolved last week?",
                "records": [],
                "allRecords": [],
                "trendHistory": [{"week": "26-10-2026", "new": 8, "resolved": 14, "unchanged": 95}],
            },
        )
        self.assertEqual(answer["id"], "weekly-movement")
        self.assertIn("14 were resolved", answer["summary"])
