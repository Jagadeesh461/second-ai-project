"""Tests for the processed-report column updates.

Covers the renamed columns (FundamentalClassification, Zone, Remit Team) and
the new Exploit, Unique Vuln Name and VULN COUNT columns across the loader,
processed CSV, AVS calculation, dashboard API payload and the browser code.
"""

import csv
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import avs_calculator
import services.csv_loader as csv_loader
import services.vulnerability_service as service
from tests.js_harness import run_js
from utils.vuln_identity import is_exploit, unique_vuln_name, vuln_count_key


class VulnIdentityRuleTests(unittest.TestCase):
    def test_exploit_matches_exploit_or_active_case_insensitive(self):
        for text in ("Exploit Available", "exploit", "Actively Exploited", "ACTIVE ATTACKS", "Malware, Exploit_Public",
                     "No Known Exploit; Exploit Available"):
            self.assertTrue(is_exploit(text), text)
        for text in ("", None, "High Lateral Movement", "Denial of Service", "Public POC",
                     "No Known Exploit", "no known exploit", "Not Actively Exploited", "Non-exploitable"):
            self.assertFalse(is_exploit(text), text)

    def test_unique_vuln_name_is_coalesce_of_cve_and_vendor_reference(self):
        self.assertEqual(unique_vuln_name("CVE-2026-1", "KB-1"), "CVE-2026-1")
        self.assertEqual(unique_vuln_name("", "KB-1"), "KB-1")
        self.assertEqual(unique_vuln_name(None, "KB-1"), "KB-1")
        self.assertEqual(unique_vuln_name("  ", " KB-1 "), "KB-1")
        self.assertEqual(unique_vuln_name("N/A", "KB-1"), "KB-1")
        self.assertEqual(unique_vuln_name("", ""), "Unknown")

    def test_vuln_count_concatenates_server_app_and_unique_name(self):
        self.assertEqual(vuln_count_key("SRV-1", "Payments", "CVE-1"), "SRV-1PaymentsCVE-1")


class ProcessedReportColumnTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def write_csv(self, rows):
        path = Path(self.temp.name) / "report.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_loader.STANDARD_COLUMNS)
            writer.writeheader()
            for index, updates in enumerate(rows):
                row = {column: "" for column in csv_loader.STANDARD_COLUMNS}
                row.update({
                    "ServerName": "SRV-1", "OperatingSystem": "Linux", "Environment": "Production",
                    "AppSpaceId": "AS-1", "AppSpaceName": "Payments", "AppSpaceTeam": "Team", "QID": str(index),
                    "VulnerabilityName": "Java RCE", "Severity": "5", "AssetRiskScore": "50", "PCIRequired": "no",
                    "Category": "Java", "CVE": "CVE-2026-0001", "VendorReference": "KB-1", "ThreatIntel": "",
                    "FirstDetected": "2026-01-01", "LastDetected": "2026-03-31", "Resolved": "", "SLABreach": "no",
                    "Status": "Open",
                })
                row.update(updates)
                writer.writerow(row)
        return path

    def load(self, rows):
        records, _ = csv_loader.load_vulnerabilities(self.write_csv(rows), today=date(2026, 6, 1))
        return records

    def test_processed_columns_are_renamed_and_new_columns_added(self):
        columns = csv_loader.PROCESSED_COLUMNS
        for name in ("FundamentalClassification", "Zone", "RemitTeam", "Exploit", "Unique Vuln Name", "VULN COUNT"):
            self.assertIn(name, columns)
        for old in ("AVS Asset Type", "AVS Zone", "DependantTeam"):
            self.assertNotIn(old, columns)
        self.assertEqual(columns[-7:], (
            "ITORresponsiblePartner", "ThirdPartyComponent", "ThirdPartyComponentName",
            "CoveredInWintelCoreBaseline", "PatchAvailableNewMetric", "CVSS2Temporal", "CVSS3Temporal",
        ))

    def test_record_fields(self):
        records = self.load([
            {"ThreatIntel": "Exploit Available"},
            {"ThreatIntel": "Actively Attacked", "CVE": "", "VendorReference": "KB-9", "ServerName": "SRV-2"},
            {"ThreatIntel": "No Known Exploit", "CVE": "", "VendorReference": ""},
        ])
        first, second, third = (r.to_dict() for r in records)
        self.assertIs(first["Exploit"], True)
        self.assertEqual(first["Unique Vuln Name"], "CVE-2026-0001")
        self.assertEqual(first["VULN COUNT"], "SRV-1PaymentsCVE-2026-0001")
        self.assertIs(second["Exploit"], True)
        self.assertEqual(second["Unique Vuln Name"], "KB-9")
        self.assertEqual(second["VULN COUNT"], "SRV-2PaymentsKB-9")
        self.assertIs(third["Exploit"], False)
        self.assertEqual(third["Unique Vuln Name"], "Unknown")
        for old in ("AVS Asset Type", "AVS Zone", "DependantTeam"):
            self.assertNotIn(old, first)
        self.assertIn("RemitTeam", first)

    def test_processed_csv_writes_new_columns(self):
        records = self.load([{"ThreatIntel": "exploit kit"}, {"ThreatIntel": "", "CVE": "", "VendorReference": "KB-2"}])
        avs_calculator.attach_avs_to_records(records, _per_app(records))
        output = Path(self.temp.name) / "processed.csv"
        csv_loader.write_processed_csv(records, output)
        with output.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            header = reader.fieldnames
            rows = list(reader)
        self.assertEqual(header, list(csv_loader.PROCESSED_COLUMNS))
        self.assertEqual([row["Exploit"] for row in rows], ["TRUE", "FALSE"])
        self.assertEqual([row["Unique Vuln Name"] for row in rows], ["CVE-2026-0001", "KB-2"])
        self.assertEqual([row["VULN COUNT"] for row in rows], ["SRV-1PaymentsCVE-2026-0001", "SRV-1PaymentsKB-2"])
        self.assertEqual(rows[0]["FundamentalClassification"], "Essential")
        self.assertEqual(rows[0]["Zone"], "External")
        self.assertEqual(rows[0]["RemitTeam"], "Other")

    def test_dashboard_payload_uses_new_names(self):
        records = self.load([{"ThreatIntel": "Exploit"}, {"ThreatIntel": "", "QID": "x"}, {"ThreatIntel": "", "QID": "y", "ServerName": "SRV-2"}])
        dashboard = service.build_dashboard(records, {})
        self.assertIn("remit_team", dashboard["filters"])
        self.assertNotIn("dependant_team", dashboard["filters"])
        self.assertEqual(dashboard["filters"]["exploit"], ["FALSE", "TRUE"])
        self.assertIn("fundamental_classification", dashboard["filters"])
        self.assertIn("zone", dashboard["filters"])
        self.assertIn("remit_team", dashboard["charts"])
        self.assertEqual(dashboard["charts"]["exploit"], {"TRUE": 1, "FALSE": 2})
        self.assertEqual(dashboard["kpis"]["exploitable"], 1)
        # Two findings share SRV-1 + Payments + CVE, so only two distinct VULN COUNT values exist.
        self.assertEqual(dashboard["kpis"]["unique_vuln_instances"], 2)

    def test_dashboard_builds_unique_most_risky_records_from_all_criteria(self):
        records = self.load([
            {
                "Severity": "4", "Detection": "/apps/java", "PatchAvailable": "TRUE",
                "SLABreach": "TRUE", "ThreatIntel": "Exploit Available",
            },
            {
                "Severity": "4", "Detection": "/apps/java", "PatchAvailable": "TRUE",
                "SLABreach": "TRUE", "ThreatIntel": "Exploit Available", "QID": "duplicate",
            },
            {"Severity": "5", "Detection": "/apps/java", "PatchAvailable": "FALSE", "SLABreach": "TRUE", "ThreatIntel": "Exploit Available"},
        ])
        avs_calculator.attach_avs_to_records(records, _per_app(records))
        dashboard = service.build_dashboard(records, {})
        self.assertEqual(len(dashboard["most_risky_records"]), 1)
        self.assertEqual(dashboard["most_risky_records"][0]["Severity Level"], "4")
        self.assertEqual(dashboard["most_risky_records"][0]["SLABreach"], True)


def _per_app(records):
    mapping = avs_calculator.pd.DataFrame([
        {"AppSpaceId": "AS-1", "AppSpaceName": "Payments", "AppSpaceTeam": "Team", "FundamentalClassification": "Essential", "Zone": "External"},
    ])
    original_ensure, original_load = avs_calculator.ensure_static_mapping, avs_calculator.load_static_mapping
    avs_calculator.ensure_static_mapping = lambda records, path=None: None
    avs_calculator.load_static_mapping = lambda path=None: mapping
    try:
        return avs_calculator.compute_avs(records)
    finally:
        avs_calculator.ensure_static_mapping, avs_calculator.load_static_mapping = original_ensure, original_load


class AvsMappingHeaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def write(self, header):
        path = Path(self.temp.name) / "mapping.csv"
        path.write_text(f"AppSpaceId,AppSpaceName,AppSpaceTeam,{header},Zone\nAS-1,Payments,Team,Essential,External\n", encoding="utf-8")
        return path

    def test_new_and_legacy_headers_are_accepted(self):
        for header in ("FundamentalClassification", "AssetType"):
            path = self.write(header)
            avs_calculator.validate_mapping_csv(path)
            frame = avs_calculator.load_static_mapping(path)
            self.assertEqual(list(frame.columns), list(avs_calculator.STATIC_MAPPING_COLUMNS))
            self.assertEqual(frame.loc[0, "FundamentalClassification"], "Essential")

    def test_missing_classification_column_is_rejected(self):
        path = Path(self.temp.name) / "bad.csv"
        path.write_text("AppSpaceId,Zone\nAS-1,External\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "FundamentalClassification"):
            avs_calculator.validate_mapping_csv(path)

    def test_bundled_mapping_uses_new_header(self):
        header = avs_calculator.STATIC_MAPPING_PATH.read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(header, "AppSpaceId,AppSpaceName,AppSpaceTeam,FundamentalClassification,Zone")

    def test_avs_dedups_by_unique_vuln_name(self):
        from models.vulnerability import Vulnerability

        def make(cve, vendor, uvn=""):
            return Vulnerability(raw={}, record_id=cve + vendor, app_space_id="AS-1", app_space_name="Payments",
                                 severity="Critical", age_days=90, cve=cve, vendor=vendor, unique_vuln_name=uvn)

        records = [make("CVE-1", "KB-1", "CVE-1"), make("N/A", "KB-1", "KB-1"), make("N/A", "KB-1"), make("N/A", "Unknown", "Unknown")]
        per_app = _per_app(records)
        self.assertEqual(int(per_app.loc["AS-1", "AVSUniqueVulnCount"]), 2)
        self.assertEqual(per_app.loc["AS-1", "FundamentalClassification"], "Essential")
        self.assertEqual(float(per_app.loc["AS-1", "AVSScore"]), 2 * 5 * 2)


def js_record(**overrides):
    record = {
        "AppSpaceId": "AS-1", "AppSpaceName": "Payments", "AppSpaceTeam": "Team", "CVE": "CVE-1", "Vendor": "KB-1",
        "Unique Vuln Name": "CVE-1", "VULN COUNT": "SRV-1PaymentsCVE-1", "Severity": "Critical", "Severity Level": "5",
        "Vulnerability Age": 90, "Type Category": "Java", "Vulnerability Name": "Vuln", "First Detected": "2026-01-01",
        "Solution": "Patch", "Exploit": False, "FundamentalClassification": "Essential", "Zone": "External",
        "RemitTeam": "Wintel",
    }
    record.update(overrides)
    return record


class BrowserColumnTests(unittest.TestCase):
    def test_toolbar_excludes_classification_zone_and_resolution_filters(self):
        visible_filter_keys = json.loads(run_js(
            "JSON.stringify(FILTER_FIELDS.filter(function (filter) { return filter.showInToolbar !== false; }).map(function (filter) { return filter.key; }));",
            files=("filters.js",),
        ))
        self.assertNotIn("fundamental_classification", visible_filter_keys)
        self.assertNotIn("zone", visible_filter_keys)
        self.assertNotIn("resolution", visible_filter_keys)

    def test_avs_metrics_use_fundamental_classification_and_zone(self):
        records = [js_record(), js_record(**{"CVE": "N/A", "Unique Vuln Name": "KB-7"}), js_record(**{"CVE": "CVE-1", "Unique Vuln Name": "CVE-1"})]
        app = json.loads(run_js("JSON.stringify(computeAvsMetrics(CONTEXT.records)[0]);", files=("avs-core.js",), context={"records": records}))
        self.assertEqual(app["fundamentalClassification"], "Essential")
        self.assertEqual(app["zone"], "External")
        self.assertEqual(app["uniqueCount"], 2)
        self.assertEqual(app["score"], 2 * 5 * 2)

    def test_drilldown_flags_exploitable_unique_vulnerabilities(self):
        records = [
            js_record(Exploit=True), js_record(),
            js_record(**{"Unique Vuln Name": "CVE-2", "CVE": "CVE-2"}),
            js_record(**{"Unique Vuln Name": "CVE-3", "CVE": "CVE-3", "Exploit": "TRUE"}),
        ]
        drill = json.loads(run_js("JSON.stringify(computeAvsDrilldown(CONTEXT.records, 'AS-1'));", files=("avs-core.js",), context={"records": records}))
        exploit = {v["key"]: v["exploit"] for v in drill["vulnerabilities"]}
        self.assertEqual(exploit, {"CVE-1": True, "CVE-2": False, "CVE-3": True})
        self.assertEqual(drill["exploitable"], 2)

    def test_filters_support_new_fields(self):
        records = [js_record(Exploit=True), js_record(Exploit=False, Zone="Internal", RemitTeam="Other")]
        result = json.loads(run_js(
            "JSON.stringify({"
            " exploit: optionValues(CONTEXT.records, 'exploit'),"
            " remit: optionValues(CONTEXT.records, 'remit_team'),"
            " zone: optionValues(CONTEXT.records, 'zone'),"
            " classification: optionValues(CONTEXT.records, 'fundamental_classification'),"
            " onlyExploit: CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, { exploit: ['TRUE'] }); }).length,"
            " remitLabel: filterDefinition('remit_team').label });",
            files=("filters.js",), context={"records": records},
        ))
        self.assertEqual(result["exploit"], ["FALSE", "TRUE"])
        self.assertEqual(result["remit"], ["Other", "Wintel"])
        self.assertEqual(result["zone"], ["External", "Internal"])
        self.assertEqual(result["classification"], ["Essential"])
        self.assertEqual(result["onlyExploit"], 1)
        self.assertEqual(result["remitLabel"], "Remit Team")

    def test_assistant_answers_exploit_and_remit_team_questions(self):
        records = [js_record(Exploit=True, ServerName="SRV-1"), js_record(Exploit=True, RemitTeam="Other"), js_record(Exploit=False)]

        def ask(question):
            return run_js(
                "answerAssistantQuestion(CONTEXT.question, CONTEXT)",
                context={"question": question, "records": records, "allRecords": records, "rawFilters": {}, "filters": [], "search": ""},
            )

        answer = ask("How many exploitable vulnerabilities?")
        stats = {s["label"]: s["value"] for s in answer["stats"]}
        self.assertEqual(stats["Total"], "2")
        self.assertEqual(stats["Exploitable"], "2")
        self.assertIn("Exploit = TRUE", answer["notes"][0])

        answer = ask("How many vulnerabilities for remit team Wintel?")
        stats = {s["label"]: s["value"] for s in answer["stats"]}
        self.assertEqual(stats["Total"], "2")
        self.assertIn("Remit Team = Wintel", answer["notes"][0])


if __name__ == "__main__":
    unittest.main()
