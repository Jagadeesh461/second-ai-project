import csv
import io
import json
import tempfile
import unittest
import zipfile
from datetime import date
from pathlib import Path
from unittest.mock import patch

import app as flask_app
import services.csv_loader as csv_loader
import services.vulnerability_service as service


class ImportWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.data_dir = self.root / "data"
        self.archive_dir = self.root / "archive"
        self.output_dir = self.root / "output"
        self.data_dir.mkdir()
        self.archive_dir.mkdir()
        self.output_dir.mkdir()
        self.paths_patch = patch.multiple(
            service,
            BASE_DIR=self.root,
            DATA_DIR=self.data_dir,
            ARCHIVE_DIR=self.archive_dir,
            OUTPUT_DIR=self.output_dir,
            PROCESSED_REPORT_PATH=self.output_dir / "processed_vulnerabilities.csv",
            DASHBOARD_STATS_PATH=self.output_dir / "dashboard_stats.json",
            IMPORT_MANIFEST_PATH=self.output_dir / "import_manifest.json",
        )
        self.paths_patch.start()
        self.addCleanup(self.paths_patch.stop)
        self.addCleanup(self.temp_dir.cleanup)

    def write_standard_csv(self, path: Path, row_updates: dict[str, str] | None = None) -> Path:
        row = {column: "" for column in csv_loader.STANDARD_COLUMNS}
        row.update(
            {
                "ServerName": "server-01",
                "OperatingSystem": "Windows Server",
                "Environment": "Prod",
                "AppSpaceId": "APP-1",
                "AppSpaceName": "Payments",
                "AppSpaceTeam": "Platform",
                "QID": "12345",
                "VulnerabilityName": "TLS weakness",
                "Severity": "High",
                "AssetRiskScore": "77.5",
                "PCIRequired": "yes",
                "Category": "Security Policy",
                "CVE": "CVE-2026-0001",
                "VendorReference": "Vendor Advisory",
                "FirstDetected": "2026-09-01",
                "LastDetected": "2026-09-12",
                "Resolved": "",
                "SLABreach": "no",
                "Status": "Open",
                "CVSS3Temporal": "8.1",
            }
        )
        if row_updates:
            row.update(row_updates)
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_loader.STANDARD_COLUMNS)
            writer.writeheader()
            writer.writerow(row)
        return path

    def write_standard_workbook(self, path: Path) -> Path:
        def cell(reference: str, value: str, inline: bool = True) -> str:
            if inline:
                return f'<c r="{reference}" t="inlineStr"><is><t>{value}</t></is></c>'
            return f'<c r="{reference}"><v>{value}</v></c>'

        def column_name(index: int) -> str:
            name = ""
            while index >= 0:
                index, remainder = divmod(index, 26)
                name = chr(65 + remainder) + name
                index -= 1
            return name

        header = "".join(cell(f"{column_name(index)}1", column) for index, column in enumerate(csv_loader.STANDARD_COLUMNS))
        values = {column: "" for column in csv_loader.STANDARD_COLUMNS}
        values.update(
            {
                "ServerName": "server-02",
                "OperatingSystem": "Linux",
                "Environment": "Prod",
                "AppSpaceId": "APP-2",
                "AppSpaceName": "Billing",
                "AppSpaceTeam": "Operations",
                "QID": "67890",
                "VulnerabilityName": "Kernel finding",
                "Severity": "4",
                "AssetRiskScore": "91",
                "PCIRequired": "yes",
                "Category": "Patch",
                "CVE": "CVE-2026-0002",
                "VendorReference": "Linux Vendor",
                "FirstDetected": "15-06-2026",
                "LastDetected": "46274",
                "Resolved": "",
                "SLABreach": "no",
                "Status": "In Progress",
            }
        )
        row = "".join(
            cell(f"{column_name(index)}2", values[column], not (column == "LastDetected" and values[column]))
            for index, column in enumerate(csv_loader.STANDARD_COLUMNS)
            if values[column]
        )
        worksheet = f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1">{header}</row><row r="2">{row}</row></sheetData></worksheet>'
        with zipfile.ZipFile(path, "w") as workbook:
            workbook.writestr("xl/worksheets/sheet1.xml", worksheet)
        return path

    def test_process_latest_report_writes_processed_csv_and_cached_stats(self):
        self.write_standard_csv(self.data_dir / "latest.csv")
        expected_age = str((date(2026, 9, 12) - date(2026, 9, 1)).days)
        expected_days_open = str((date.today() - date(2026, 9, 1)).days)

        result = service.process_latest_report(force=True)

        self.assertTrue(result["processed"])
        self.assertEqual(result["source"], "latest.csv")
        self.assertTrue(service.PROCESSED_REPORT_PATH.exists())
        self.assertTrue(service.DASHBOARD_STATS_PATH.exists())
        self.assertTrue(service.IMPORT_MANIFEST_PATH.exists())
        with service.PROCESSED_REPORT_PATH.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]["Vulnerability Age"], expected_age)
        self.assertEqual(rows[0]["Days Open"], expected_days_open)
        self.assertEqual(rows[0]["ServerName"], "server-01")
        dashboard = json.loads(service.DASHBOARD_STATS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(dashboard["meta"]["record_count"], 1)
        self.assertEqual(dashboard["records"][0]["Vulnerability Age"], int(expected_age))

    def test_missing_required_column_fails_validation(self):
        path = self.data_dir / "missing.csv"
        columns = [column for column in csv_loader.STANDARD_COLUMNS if column != "FirstDetected"]
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()

        with self.assertRaisesRegex(ValueError, "FirstDetected"):
            service.process_latest_report(force=True)

    def test_legacy_siabreach_column_accepted_as_alias(self):
        path = self.data_dir / "legacy_sia.csv"
        columns = [("SIABreach" if col == "SLABreach" else col) for col in csv_loader.STANDARD_COLUMNS]
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            row = {col: "test" for col in columns}
            row["FirstDetected"] = "2026-09-01"
            row["LastDetected"] = "2026-09-12"
            row["SIABreach"] = "TRUE"
            writer.writerow(row)

        result = service.process_latest_report(force=True)
        self.assertTrue(result["processed"])
        with service.PROCESSED_REPORT_PATH.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertIn("SLABreach", rows[0])
        self.assertEqual(rows[0]["SLABreach"], "TRUE")

    def test_workbook_named_csv_is_processed(self):
        self.write_standard_workbook(self.data_dir / "report.csv")

        result = service.process_latest_report(force=True)

        self.assertTrue(result["processed"])
        self.assertEqual(result["source"], "report.csv")
        self.assertEqual(result["dashboard"]["meta"]["source_format"], "workbook")
        self.assertEqual(result["dashboard"]["records"][0]["Severity"], "Critical")
        self.assertEqual(result["dashboard"]["records"][0]["Last Detected"], "2026-09-09")

    def test_archives_older_csv_files_after_successful_import(self):
        older = self.write_standard_csv(self.data_dir / "older.csv", {"ServerName": "old-server"})
        latest = self.write_standard_csv(self.data_dir / "latest.csv", {"ServerName": "new-server"})
        older_time = 1_700_000_000
        latest_time = 1_800_000_000
        older.touch()
        latest.touch()
        import os
        os.utime(older, (older_time, older_time))
        os.utime(latest, (latest_time, latest_time))

        result = service.process_latest_report(force=True)

        self.assertEqual(result["source"], "latest.csv")
        self.assertFalse(older.exists())
        self.assertTrue(latest.exists())
        self.assertEqual(len(list(self.archive_dir.glob("input_*_older.csv"))), 1)

    def test_reimport_archives_previous_output_and_keeps_latest_resolved_records(self):
        self.write_standard_csv(self.data_dir / "first.csv", {"ServerName": "first-server"})
        first_result = service.process_latest_report(force=True)
        self.assertTrue(first_result["processed"])
        self.assertTrue(service.PROCESSED_REPORT_PATH.exists())
        self.assertTrue(service.DASHBOARD_STATS_PATH.exists())

        # Simulate a new report landing in data/ alongside the old input file.
        second = self.write_standard_csv(self.data_dir / "second.csv", {"ServerName": "second-server"})
        import os
        os.utime(self.data_dir / "first.csv", (1_700_000_000, 1_700_000_000))
        os.utime(second, (1_800_000_000, 1_800_000_000))

        result = service.process_latest_report(force=True)

        self.assertTrue(result["processed"])
        self.assertEqual(result["source"], "second.csv")

        # The new output contains the current report plus findings resolved
        # by the latest comparison, but no resolved findings from older weeks.
        with service.PROCESSED_REPORT_PATH.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row["ServerName"]: row["NewResolvedStatus"] for row in rows},
            {"second-server": "New", "first-server": "Resolved"},
        )
        dashboard = json.loads(service.DASHBOARD_STATS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(dashboard["meta"]["record_count"], 2)
        self.assertEqual(dashboard["records"][0]["ServerName"], "second-server")

        # The previous input, processed output, and dashboard stats were archived
        # with timestamped names rather than overwritten or merged.
        archived_names = [path.name for path in self.archive_dir.iterdir()]
        self.assertTrue(any(name.startswith("input_") and name.endswith("first.csv") for name in archived_names))
        self.assertTrue(any(name.startswith("output_") and name.endswith("processed_vulnerabilities.csv") for name in archived_names))
        self.assertTrue(any(name.startswith("stats_") and name.endswith("dashboard_stats.json") for name in archived_names))
        self.assertEqual(result["archived"], [name for name in archived_names if name.startswith("input_")])
        self.assertIn("processed_report", result["archived_output"])
        self.assertIn("dashboard_stats", result["archived_output"])

    def test_first_import_does_not_attempt_to_archive_nonexistent_output(self):
        self.write_standard_csv(self.data_dir / "only.csv")

        result = service.process_latest_report(force=True)

        self.assertTrue(result["processed"])
        self.assertEqual(result["archived_output"], {})
        self.assertEqual(list(self.archive_dir.iterdir()), [])

    def test_flask_import_endpoint_processes_workbook_reports(self):
        self.write_standard_workbook(self.data_dir / "report.csv")
        client = flask_app.app.test_client()

        response = client.post("/api/import")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["record_count"], 1)

    def test_flask_upload_import_archives_previous_input(self):
        self.write_standard_csv(self.data_dir / "old.csv", {"ServerName": "old-server"})
        source = self.data_dir / "upload.csv"
        self.write_standard_csv(source, {"ServerName": "uploaded-server"})
        payload = {"report": (io.BytesIO(source.read_bytes()), "upload.csv")}
        source.unlink()
        client = flask_app.app.test_client()

        response = client.post("/api/import/upload", data=payload, content_type="multipart/form-data")

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result["ok"])
        self.assertEqual(result["record_count"], 1)
        self.assertTrue(any(path.name.endswith("old.csv") for path in self.archive_dir.iterdir()))
        self.assertTrue(service.PROCESSED_REPORT_PATH.exists())

    def test_flask_processed_output_downloads_cached_file(self):
        self.write_standard_csv(self.data_dir / "latest.csv")
        service.process_latest_report(force=True)
        client = flask_app.app.test_client()

        response = client.get("/api/export/output")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Vulnerability Age", response.get_data(as_text=True).splitlines()[0])
        response.close()


if __name__ == "__main__":
    unittest.main()
