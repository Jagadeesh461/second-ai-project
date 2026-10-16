"""Tests for the AVS List import/archive workflow (import_avs_list).

Verifies the flow required by the AVS Enhancements spec:
- Uploading a new AVS List CSV archives the previously active mapping with a
  timestamped filename in /archive.
- The newly uploaded file becomes the active static_mapping.csv.
- The vulnerability report/records are recomputed with the new AVS mapping
  (cards/table data refresh) without re-touching the vulnerability report
  input file or its own archive history.
- Invalid uploads are rejected and never overwrite the active mapping file.
"""

import csv
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as flask_app
import avs_calculator
import services.csv_loader as csv_loader
import services.vulnerability_service as service


class AvsImportWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.data_dir = self.root / "data"
        self.archive_dir = self.root / "archive"
        self.output_dir = self.root / "output"
        self.static_dir = self.root / "static"
        self.data_dir.mkdir()
        self.archive_dir.mkdir()
        self.output_dir.mkdir()
        self.static_dir.mkdir()

        self.service_patch = patch.multiple(
            service,
            BASE_DIR=self.root,
            DATA_DIR=self.data_dir,
            ARCHIVE_DIR=self.archive_dir,
            OUTPUT_DIR=self.output_dir,
            PROCESSED_REPORT_PATH=self.output_dir / "processed_vulnerabilities.csv",
            DASHBOARD_STATS_PATH=self.output_dir / "dashboard_stats.json",
            IMPORT_MANIFEST_PATH=self.output_dir / "import_manifest.json",
        )
        self.service_patch.start()
        self.addCleanup(self.service_patch.stop)

        self.mapping_path = self.static_dir / "static_mapping.csv"
        self.avs_patch = patch.object(avs_calculator, "STATIC_MAPPING_PATH", self.mapping_path)
        self.avs_patch.start()
        self.addCleanup(self.avs_patch.stop)

        # `compute_avs` calls `ensure_static_mapping()`/`load_static_mapping()`
        # with no arguments, and their `path` defaults are bound at function
        # definition time - patching STATIC_MAPPING_PATH alone would not
        # redirect them (see tests/test_avs_calculator.py). Patch the
        # functions themselves so they operate against this test's tmp file,
        # matching the same real read/write logic just at a different path.
        original_ensure = avs_calculator.ensure_static_mapping
        original_load = avs_calculator.load_static_mapping
        self.ensure_patcher = patch.object(
            avs_calculator, "ensure_static_mapping",
            lambda records, path=None: original_ensure(records, self.mapping_path),
        )
        self.load_patcher = patch.object(
            avs_calculator, "load_static_mapping",
            lambda path=None: original_load(self.mapping_path),
        )
        self.ensure_patcher.start()
        self.load_patcher.start()
        self.addCleanup(self.ensure_patcher.stop)
        self.addCleanup(self.load_patcher.stop)

        self.addCleanup(self.temp_dir.cleanup)

    def write_report_csv(self, path: Path) -> Path:
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
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_loader.STANDARD_COLUMNS)
            writer.writeheader()
            writer.writerow(row)
        return path

    def write_mapping_csv(self, path: Path, classification: str, zone: str, classification_header: str = "FundamentalClassification") -> Path:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["AppSpaceId", "AppSpaceName", "AppSpaceTeam", classification_header, "Zone"])
            writer.writeheader()
            writer.writerow({"AppSpaceId": "APP-1", "AppSpaceName": "Payments", "AppSpaceTeam": "Platform", classification_header: classification, "Zone": zone})
        return path

    def test_import_archives_previous_mapping_and_activates_new_file(self):
        self.write_report_csv(self.data_dir / "latest.csv")
        service.process_latest_report(force=True)
        self.assertTrue(self.mapping_path.exists())  # auto-generated on first process

        new_mapping = self.root / "upload.csv"
        self.write_mapping_csv(new_mapping, classification="Database", zone="External")

        with new_mapping.open("rb") as handle:
            result = service.import_avs_list(handle, "upload.csv")

        self.assertIsNotNone(result["archived"])
        archived_files = list(self.archive_dir.glob("avs_list_*"))
        self.assertEqual(len(archived_files), 1)
        self.assertEqual(archived_files[0].name, result["archived"])

        active = self.mapping_path.read_text(encoding="utf-8")
        self.assertIn("Database", active)
        self.assertIn("External", active)

    def test_import_recomputes_dashboard_with_new_avs_mapping(self):
        self.write_report_csv(self.data_dir / "latest.csv")
        first = service.process_latest_report(force=True)
        first_app = first["dashboard"]["avs"]["applications"][0]
        self.assertEqual(first_app["FundamentalClassification"], "Other")
        self.assertEqual(first_app["Zone"], "Internal")

        new_mapping = self.root / "upload.csv"
        self.write_mapping_csv(new_mapping, classification="Database", zone="External")
        with new_mapping.open("rb") as handle:
            result = service.import_avs_list(handle, "upload.csv")

        updated_app = result["dashboard"]["avs"]["applications"][0]
        self.assertEqual(updated_app["FundamentalClassification"], "Database")
        self.assertEqual(updated_app["Zone"], "External")

        cached = service._read_json(service.DASHBOARD_STATS_PATH)
        self.assertEqual(cached["avs"]["applications"][0]["FundamentalClassification"], "Database")

    def test_import_does_not_touch_report_input_or_its_archive(self):
        report_path = self.write_report_csv(self.data_dir / "latest.csv")
        service.process_latest_report(force=True)

        new_mapping = self.root / "upload.csv"
        self.write_mapping_csv(new_mapping, classification="Database", zone="External")
        with new_mapping.open("rb") as handle:
            service.import_avs_list(handle, "upload.csv")

        self.assertTrue(report_path.exists())
        self.assertEqual(len(list(self.archive_dir.glob("input_*"))), 0)
        self.assertEqual(len(list(self.archive_dir.glob("output_*"))), 0)
        self.assertEqual(len(list(self.archive_dir.glob("stats_*"))), 0)

    def test_invalid_mapping_csv_is_rejected_and_active_file_untouched(self):
        self.write_report_csv(self.data_dir / "latest.csv")
        service.process_latest_report(force=True)
        original_content = self.mapping_path.read_text(encoding="utf-8")

        bad_upload = self.root / "bad.csv"
        bad_upload.write_text("Name,Description\nfoo,bar\n", encoding="utf-8")

        with bad_upload.open("rb") as handle:
            with self.assertRaises(ValueError):
                service.import_avs_list(handle, "bad.csv")

        self.assertEqual(self.mapping_path.read_text(encoding="utf-8"), original_content)
        self.assertEqual(list(self.archive_dir.glob("avs_list_*")), [])

    def test_non_csv_upload_is_rejected(self):
        self.write_report_csv(self.data_dir / "latest.csv")
        service.process_latest_report(force=True)

        with self.assertRaises(ValueError):
            service.import_avs_list(io.BytesIO(b"data"), "upload.txt")

    def test_flask_avs_import_endpoint_refreshes_dashboard(self):
        self.write_report_csv(self.data_dir / "latest.csv")
        service.process_latest_report(force=True)

        new_mapping = self.root / "upload.csv"
        self.write_mapping_csv(new_mapping, classification="Database", zone="External")
        payload = {"avs_list": (io.BytesIO(new_mapping.read_bytes()), "upload.csv")}
        client = flask_app.app.test_client()

        response = client.post("/api/avs/import/upload", data=payload, content_type="multipart/form-data")

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertTrue(result["ok"])
        self.assertIsNotNone(result["archived"])
        self.assertEqual(result["dashboard"]["avs"]["applications"][0]["FundamentalClassification"], "Database")

    def test_flask_avs_export_endpoint_downloads_active_mapping(self):
        self.write_report_csv(self.data_dir / "latest.csv")
        service.process_latest_report(force=True)
        client = flask_app.app.test_client()

        response = client.get("/api/avs/export")

        self.assertEqual(response.status_code, 200)
        self.assertIn("AppSpaceId", response.get_data(as_text=True).splitlines()[0])
        response.close()

    def test_flask_avs_export_endpoint_reflects_imported_mapping(self):
        self.write_report_csv(self.data_dir / "latest.csv")
        service.process_latest_report(force=True)
        new_mapping = self.root / "upload.csv"
        self.write_mapping_csv(new_mapping, classification="Database", zone="External")
        with new_mapping.open("rb") as handle:
            service.import_avs_list(handle, "upload.csv")
        client = flask_app.app.test_client()

        response = client.get("/api/avs/export")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Database", response.get_data(as_text=True))
        response.close()


if __name__ == "__main__":
    unittest.main()
