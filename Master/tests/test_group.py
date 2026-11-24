import csv
import tempfile
import unittest
from datetime import date
from pathlib import Path

import services.csv_loader as csv_loader
import services.vulnerability_service as service
from utils.group import DEFAULT_GROUP, load_mapping, resolve_group


class GroupMappingTests(unittest.TestCase):
    def setUp(self):
        self.mapping = load_mapping(refresh=True)

    def test_mapping_file_exists_in_static(self):
        self.assertTrue((Path(__file__).resolve().parents[1] / "static" / "group_mapping.json").exists())

    def test_mapping_keys_are_lower_cased(self):
        self.assertTrue(all(team == team.lower() for team in self.mapping))

    def test_change_ito_maps_to_suncorp_bank(self):
        self.assertEqual(resolve_group("Change/ITO"), "Suncorp Bank")

    def test_matching_is_case_insensitive(self):
        for value in ("change/ito", "CHANGE/ITO", "Change/Ito"):
            self.assertEqual(resolve_group(value), "Suncorp Bank")

    def test_other_remit_teams_default_to_suncorp_group(self):
        for team in ("Wintel", "Midrange", "Dynatrace", "Control-M", "AppHealth", "Other"):
            self.assertEqual(resolve_group(team), DEFAULT_GROUP)

    def test_blank_remit_team_defaults_to_suncorp_group(self):
        self.assertEqual(resolve_group(""), DEFAULT_GROUP)
        self.assertEqual(resolve_group("   "), DEFAULT_GROUP)
        self.assertEqual(resolve_group(None), DEFAULT_GROUP)

    def test_custom_mapping_is_honoured(self):
        self.assertEqual(resolve_group("Custom Team", {"custom team": "Custom Org"}), "Custom Org")

    def test_missing_mapping_file_yields_empty_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(load_mapping(Path(temp_dir) / "absent.json"), {})


class GroupLoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def write_csv(self, rows: list[dict[str, str]]) -> Path:
        path = self.root / "report.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_loader.STANDARD_COLUMNS)
            writer.writeheader()
            for updates in rows:
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
                        "AssetRiskScore": "50",
                        "PCIRequired": "no",
                        "Category": "Security Policy",
                        "CVE": "CVE-2026-0001",
                        "VendorReference": "Vendor Advisory",
                        "FirstDetected": "2026-01-01",
                        "LastDetected": "2026-01-31",
                        "Resolved": "",
                        "SLABreach": "no",
                        "Status": "Open",
                    }
                )
                row.update(updates)
                writer.writerow(row)
        return path

    def load(self, rows, today=date(2026, 6, 1)):
        records, _ = csv_loader.load_vulnerabilities(self.write_csv(rows), today=today)
        return records

    def test_group_is_resolved_from_remit_team(self):
        records = self.load(
            [
                {"Detection": "/apps/home/app.conf"},  # Change/ITO -> Suncorp Bank
                {"Detection": "SPLUNK forwarder", "QID": "2"},  # AppHealth -> Suncorp Group
                {"Detection": "nothing relevant", "QID": "3"},  # Other -> Suncorp Group
            ]
        )
        self.assertEqual([record.group for record in records], ["Suncorp Bank", "Suncorp Group", "Suncorp Group"])

    def test_processed_output_contains_group_column(self):
        self.assertIn("Group", csv_loader.PROCESSED_COLUMNS)
        record = self.load([{"Detection": "/apps/home/app.conf"}])[0]
        self.assertEqual(csv_loader.processed_row(record)["Group"], "Suncorp Bank")

    def test_record_dict_exposes_group(self):
        record = self.load([{"Detection": "windows server 2019"}])[0]
        self.assertEqual(record.to_dict()["Group"], "Suncorp Group")


class GroupDashboardTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

    def build(self, detections):
        path = Path(self.temp_dir.name) / "report.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_loader.STANDARD_COLUMNS)
            writer.writeheader()
            for index, detection in enumerate(detections):
                row = {column: "" for column in csv_loader.STANDARD_COLUMNS}
                row.update(
                    {
                        "ServerName": f"server-{index}",
                        "OperatingSystem": "Linux",
                        "Environment": "Prod",
                        "AppSpaceId": "APP-1",
                        "AppSpaceName": "Payments",
                        "AppSpaceTeam": "Platform",
                        "QID": str(index),
                        "VulnerabilityName": "Finding",
                        "Severity": "High",
                        "AssetRiskScore": "50",
                        "PCIRequired": "no",
                        "Category": "Patch",
                        "CVE": f"CVE-2026-000{index}",
                        "VendorReference": "Vendor",
                        "FirstDetected": "2026-01-01",
                        "LastDetected": "2026-01-11",
                        "Resolved": "",
                        "SLABreach": "no",
                        "Status": "Open",
                        "Detection": detection,
                    }
                )
                writer.writerow(row)
        records, metadata = csv_loader.load_vulnerabilities(path, today=date(2026, 6, 1))
        return service.build_dashboard(records, metadata, today=date(2026, 6, 1))

    def test_dashboard_exposes_group_filter_values(self):
        dashboard = self.build(["/apps/home", "splunk agent", "unmapped finding"])
        self.assertEqual(dashboard["filters"]["group"], ["Suncorp Bank", "Suncorp Group"])

    def test_dashboard_counts_records_per_group(self):
        dashboard = self.build(["/apps/home", "/apps/java", "splunk agent"])
        self.assertEqual(dashboard["charts"]["group"], {"Suncorp Bank": 2, "Suncorp Group": 1})

    def test_dashboard_records_carry_group(self):
        dashboard = self.build(["/apps/home"])
        self.assertEqual(dashboard["records"][0]["Group"], "Suncorp Bank")


if __name__ == "__main__":
    unittest.main()
