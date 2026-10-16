import csv
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import services.csv_loader as csv_loader
import services.vulnerability_service as service
from utils.remit_team import DEFAULT_REMIT_TEAM, load_mapping, resolve_remit_team


class RemitTeamMappingTests(unittest.TestCase):
    def setUp(self):
        self.mapping = load_mapping(refresh=True)

    def test_mapping_file_exists_in_static(self):
        self.assertTrue((Path(__file__).resolve().parents[1] / "static" / "remit_team_mapping.json").exists())

    def test_mapping_keys_are_lower_cased(self):
        self.assertTrue(all(keyword == keyword.lower() for keyword in self.mapping))

    def test_known_path_keyword_matches(self):
        self.assertEqual(resolve_remit_team("/apps/home/config.xml"), "Change/ITO")

    def test_splunk_detection_maps_to_app_health(self):
        self.assertEqual(resolve_remit_team("Splunk Universal Forwarder detected"), "AppHealth")

    def test_windows_server_detection_maps_to_wintel(self):
        self.assertEqual(resolve_remit_team("Windows Server 2019 missing patch"), "Wintel")

    def test_microsoft_exchange_detection_maps_to_wintel(self):
        self.assertEqual(resolve_remit_team("Microsoft Exchange cumulative update"), "Wintel")

    def test_matching_is_case_insensitive(self):
        for value in ("SPLUNK", "splunk", "SpLuNk"):
            self.assertEqual(resolve_remit_team(f"{value} agent"), "AppHealth")

    def test_uppercase_path_keyword_matches(self):
        self.assertEqual(resolve_remit_team("/APPS/GRAFANA/bin"), "Grafana")

    def test_longest_keyword_wins_when_multiple_match(self):
        self.assertEqual(resolve_remit_team("/apps/ctm/backup/run.sh"), "Control-M")

    def test_multiple_distinct_keywords_prefer_most_specific(self):
        self.assertEqual(resolve_remit_team("/usr/local/dynatrace/agent"), "Midrange")

    def test_unmatched_detection_defaults_to_other(self):
        self.assertEqual(resolve_remit_team("Some unrelated finding"), DEFAULT_REMIT_TEAM)

    def test_blank_detection_defaults_to_other(self):
        self.assertEqual(resolve_remit_team(""), DEFAULT_REMIT_TEAM)
        self.assertEqual(resolve_remit_team("   "), DEFAULT_REMIT_TEAM)
        self.assertEqual(resolve_remit_team(None), DEFAULT_REMIT_TEAM)

    def test_custom_mapping_is_honoured(self):
        self.assertEqual(resolve_remit_team("/opt/custom/app", {"/opt/custom": "Custom Team"}), "Custom Team")

    def test_missing_mapping_file_yields_empty_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertEqual(load_mapping(Path(temp_dir) / "absent.json"), {})


class AgeAndRemitTeamLoaderTests(unittest.TestCase):
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

    def test_age_is_last_detected_minus_first_detected(self):
        record = self.load([{"FirstDetected": "2026-01-01", "LastDetected": "2026-01-31"}])[0]
        self.assertEqual(record.age_days, 30)

    def test_age_is_independent_of_today(self):
        rows = [{"FirstDetected": "2026-01-01", "LastDetected": "2026-03-02"}]
        first = self.load(rows, today=date(2026, 6, 1))[0]
        second = self.load(rows, today=date(2027, 6, 1))[0]
        self.assertEqual(first.age_days, 60)
        self.assertEqual(second.age_days, 60)

    def test_age_is_zero_when_detected_on_the_same_day(self):
        record = self.load([{"FirstDetected": "2026-01-01", "LastDetected": "2026-01-01"}])[0]
        self.assertEqual(record.age_days, 0)

    def test_age_is_never_negative(self):
        record = self.load([{"FirstDetected": "2026-02-01", "LastDetected": "2026-01-01"}])[0]
        self.assertEqual(record.age_days, 0)

    def test_age_is_zero_and_bucket_unknown_when_dates_missing(self):
        record = self.load([{"FirstDetected": "2026-01-01", "LastDetected": ""}])[0]
        self.assertEqual(record.age_days, 0)
        self.assertEqual(record.aging_bucket, "Unknown")

    def test_days_open_still_measured_from_first_detected(self):
        record = self.load([{"FirstDetected": "2026-01-01", "LastDetected": "2026-01-31"}], today=date(2026, 3, 2))[0]
        self.assertEqual(record.days_open, 60)

    def test_aging_bucket_uses_corrected_age(self):
        record = self.load([{"FirstDetected": "2026-01-01", "LastDetected": "2026-01-31"}])[0]
        self.assertEqual(record.aging_bucket, "8-30 Days")

    def test_remit_team_is_resolved_from_detection(self):
        records = self.load(
            [
                {"Detection": "/apps/home/app.conf"},
                {"Detection": "SPLUNK forwarder", "QID": "2"},
                {"Detection": "Microsoft Exchange", "QID": "3"},
                {"Detection": "nothing relevant", "QID": "4"},
            ]
        )
        self.assertEqual([record.remit_team for record in records], ["Change/ITO", "AppHealth", "Wintel", "Other"])

    def test_remit_team_defaults_to_other_without_detection_column_value(self):
        self.assertEqual(self.load([{"Detection": ""}])[0].remit_team, "Other")

    def test_processed_output_contains_remit_team_column(self):
        self.assertIn("RemitTeam", csv_loader.PROCESSED_COLUMNS)
        record = self.load([{"Detection": "/apps/grafana/bin"}])[0]
        self.assertEqual(csv_loader.processed_row(record)["RemitTeam"], "Grafana")

    def test_record_dict_exposes_remit_team(self):
        record = self.load([{"Detection": "vmware tools"}])[0]
        self.assertEqual(record.to_dict()["RemitTeam"], "Wintel")


class RemitTeamDashboardTests(unittest.TestCase):
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

    def test_dashboard_exposes_remit_team_filter_values(self):
        dashboard = self.build(["/apps/home", "splunk agent", "unmapped finding"])
        self.assertEqual(dashboard["filters"]["remit_team"], ["AppHealth", "Change/ITO", "Other"])

    def test_dashboard_no_longer_exposes_vendor_filter(self):
        dashboard = self.build(["/apps/home"])
        self.assertNotIn("vendor", dashboard["filters"])
        self.assertNotIn("vendor", dashboard["charts"])

    def test_dashboard_counts_records_per_remit_team(self):
        dashboard = self.build(["/apps/home", "/apps/java", "splunk agent"])
        self.assertEqual(dashboard["charts"]["remit_team"], {"Change/ITO": 2, "AppHealth": 1})

    def test_dashboard_records_carry_remit_team(self):
        dashboard = self.build(["windows server 2019"])
        self.assertEqual(dashboard["records"][0]["RemitTeam"], "Wintel")


class RemitTeamMappingFileTests(unittest.TestCase):
    def test_mapping_file_is_valid_json_object_of_strings(self):
        path = Path(__file__).resolve().parents[1] / "static" / "remit_team_mapping.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(payload, dict)
        self.assertTrue(payload)
        self.assertTrue(all(isinstance(key, str) and isinstance(value, str) for key, value in payload.items()))


if __name__ == "__main__":
    unittest.main()
