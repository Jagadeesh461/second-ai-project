"""Tests for the Most Risky Vulnerability Movement enhancement.

Covers the import-time calculation (mostRiskyNew/Resolved/Unchanged), the
trend_history.json extension and 7-week retention, the browser-side filter
handling of the stored weekly breakdown, the chatbot answers and the
Most Risky tab layout.
"""

import csv
import json
import re
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from unittest.mock import patch

import avs_calculator
import services.csv_loader as csv_loader
import services.vulnerability_service as service
from tests.js_harness import run_js

ROOT = Path(__file__).resolve().parents[1]


def risky_record(vuln_count, status, **overrides):
    record = {
        "Severity Level": "5",
        "FundamentalClassification": "Essential",
        "PatchAvailable": "TRUE",
        "SLABreach": True,
        "Zone": "External",
        "Exploit": True,
        "VULN COUNT": vuln_count,
        "NewResolvedStatus": status,
        "Group": "Suncorp Group",
        "AppSpaceName": "Payments",
        "AppSpaceOwner": "Owner A",
        "AppSpaceTeam": "Team A",
        "RemitTeam": "Change/ITO",
        "Environment": "PROD",
        "Severity": "Critical",
        "Status": "Open",
        "Operating System": "Linux",
        "Type Category": "Java",
        "PCI Required": False,
        "Resolution Date": None,
    }
    record.update(overrides)
    return record


class MostRiskyMovementCalculationTests(unittest.TestCase):
    def test_counts_unique_most_risky_records_by_movement_status(self):
        records = [
            risky_record("V1", "New"),
            risky_record("V2", "New", AppSpaceName="Website"),
            risky_record("V3", "Unchanged"),
            risky_record("V4", "Resolved"),
            risky_record("V1", "New"),  # duplicate VULN COUNT
            risky_record("V5", "New", PatchAvailable="FALSE"),
            risky_record("V6", "Unchanged", Zone="Internal"),
            risky_record("V7", "Unchanged", **{"Severity Level": "3"}),
            risky_record("V8", "Resolved", FundamentalClassification="Other"),
            risky_record("V9", "New", SLABreach=False),
            risky_record("V10", "New", Exploit=False),
            risky_record("", "New"),
        ]

        movement = service.most_risky_movement(records)

        self.assertEqual(movement["mostRiskyNew"], 2)
        self.assertEqual(movement["mostRiskyResolved"], 1)
        self.assertEqual(movement["mostRiskyUnchanged"], 1)
        breakdown = movement["mostRiskyBreakdown"]
        self.assertIn("app_space_name", breakdown["fields"])
        self.assertNotIn("new_resolved_status", breakdown["fields"])
        offset = len(breakdown["fields"])
        app_index = breakdown["fields"].index("app_space_name")
        totals = {}
        for row in breakdown["rows"]:
            current = totals.setdefault(breakdown["values"][row[app_index]], [0, 0, 0])
            for position in range(3):
                current[position] += row[offset + position]
        self.assertEqual(totals, {"Payments": [1, 1, 1], "Website": [1, 0, 0]})

    def test_breakdown_values_match_browser_filter_values(self):
        movement = service.most_risky_movement([
            risky_record("V1", "New", **{"PCI Required": True, "Status": "Resolved"}),
        ])
        fields = movement["mostRiskyBreakdown"]["fields"]
        row = movement["mostRiskyBreakdown"]["rows"][0]
        values = {field: movement["mostRiskyBreakdown"]["values"][index] for field, index in zip(fields, row)}
        self.assertEqual(values["pci_required"], "Yes")
        self.assertEqual(values["sla_breach"], "Yes")
        self.assertEqual(values["exploit"], "TRUE")
        self.assertEqual(values["resolution"], "Resolved")
        self.assertEqual(values["zone"], "External")

    def test_encoded_breakdown_is_filtered_by_the_browser_module(self):
        entry = {"week": "26-10-2026", **service.most_risky_movement([
            risky_record("V1", "New"),
            risky_record("V2", "Unchanged", AppSpaceName="Website"),
            risky_record("V3", "Resolved", AppSpaceName="Website", Environment="UAT"),
        ])}
        rows = run_js(
            "[mostRiskyMovementHistory(CONTEXT.history, {app_space_name: ['Website']})[0],"
            " mostRiskyMovementHistory(CONTEXT.history, {app_space_name: ['Website'], environment: ['UAT']})[0]]",
            files=("most-risky-movement.js",),
            context={"history": [entry]},
        )
        self.assertEqual([(row["new"], row["resolved"], row["unchanged"]) for row in rows], [(0, 1, 1), (0, 1, 0)])

    def test_trend_history_writer_produces_equivalent_json(self):
        history = [
            {"week": "19-10-2026", "new": 1, "resolved": 2, "unchanged": 3},
            {"week": "26-10-2026", "new": 1, "resolved": 0, "unchanged": 0, **service.most_risky_movement([risky_record("V1", "New")])},
            {"week": "02-11-2026", "new": 0, "resolved": 0, "unchanged": 0, **service.most_risky_movement([])},
        ]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "trend_history.json"
            service._write_trend_history(path, history)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), history)
            service._write_trend_history(path, [])
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), [])


class MostRiskyMovementImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.output = self.root / "output"
        self.archive = self.root / "archive"
        for path in (self.data, self.output, self.archive):
            path.mkdir()
        patches = [
            patch.multiple(
                service,
                BASE_DIR=self.root,
                DATA_DIR=self.data,
                OUTPUT_DIR=self.output,
                ARCHIVE_DIR=self.archive,
                PROCESSED_REPORT_PATH=self.output / "processed_vulnerabilities.csv",
                DASHBOARD_STATS_PATH=self.output / "dashboard_stats.json",
                IMPORT_MANIFEST_PATH=self.output / "import_manifest.json",
            ),
            patch.object(avs_calculator, "ensure_static_mapping", lambda records, path=None: None),
            patch.object(avs_calculator, "load_static_mapping", lambda path=None: avs_calculator.pd.DataFrame([
                {"AppSpaceId": "AS-1", "AppSpaceName": "Payments", "AppSpaceTeam": "Team", "FundamentalClassification": "Essential", "Zone": "External"},
            ])),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def write_report(self, name, findings):
        path = self.data / name
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_loader.STANDARD_COLUMNS)
            writer.writeheader()
            for server, risky in findings:
                row = {column: "" for column in csv_loader.STANDARD_COLUMNS}
                row.update({
                    "ServerName": server, "OperatingSystem": "Linux", "Environment": "Production",
                    "AppSpaceId": "AS-1", "AppSpaceName": "Payments", "AppSpaceTeam": "Team", "QID": "100",
                    "VulnerabilityName": "Java RCE", "Severity": "5" if risky else "2", "AssetRiskScore": "50",
                    "PCIRequired": "no", "Category": "Java", "CVE": "CVE-2026-0001", "VendorReference": "KB-1",
                    "ThreatIntel": "Exploit Available", "Detection": "/apps/java", "PatchAvailable": "TRUE",
                    "FirstDetected": "2026-01-01", "LastDetected": "2026-10-12", "Resolved": "",
                    "SLABreach": "TRUE", "Status": "Open",
                })
                writer.writerow(row)
        return path

    def history(self):
        return json.loads((self.root / "static" / "trend_history.json").read_text(encoding="utf-8"))

    def test_import_records_most_risky_new_resolved_and_unchanged(self):
        first = self.write_report("week1.csv", [("SRV-A", True), ("SRV-B", True), ("SRV-L", False)])
        service._process_source_report(first, force=True)
        second = self.write_report("week2.csv", [("SRV-A", True), ("SRV-C", True), ("SRV-L", False), ("SRV-M", False)])

        result = service._process_source_report(second, force=True)

        latest = self.history()[-1]
        self.assertEqual(latest["week"], "12-10-2026")
        self.assertEqual((latest["new"], latest["resolved"], latest["unchanged"]), (2, 1, 2))
        self.assertEqual(
            (latest["mostRiskyNew"], latest["mostRiskyResolved"], latest["mostRiskyUnchanged"]),
            (1, 1, 1),
        )
        self.assertEqual(result["dashboard"]["trend_history"], self.history())

    def test_trend_history_keeps_latest_seven_weeks_with_most_risky_values(self):
        records, _ = csv_loader.load_vulnerabilities(self.write_report("retention.csv", [("SRV-A", True)]), today=date(2026, 9, 1))
        start = date(2026, 9, 7)
        for offset in range(8):
            service._update_trend_history(records, [], start + timedelta(weeks=offset), most_risky={
                "mostRiskyNew": offset, "mostRiskyResolved": offset + 1, "mostRiskyUnchanged": offset + 2,
            })
        history = self.history()
        self.assertEqual(len(history), 7)
        self.assertEqual(history[0]["week"], "14-09-2026")
        self.assertEqual(history[-1]["week"], "26-10-2026")
        self.assertEqual((history[0]["mostRiskyNew"], history[-1]["mostRiskyUnchanged"]), (1, 9))

    def test_backfill_populates_latest_week_from_cached_records_only(self):
        stored = [{"week": "19-10-2026", "new": 1, "resolved": 0, "unchanged": 0},
                  {"week": "26-10-2026", "new": 2, "resolved": 1, "unchanged": 3}]
        (self.root / "static").mkdir()
        (self.root / "static" / "trend_history.json").write_text(json.dumps(stored), encoding="utf-8")
        cached = {"trend_history": json.loads(json.dumps(stored)), "records": [risky_record("V1", "New"), risky_record("V2", "Resolved")]}

        self.assertTrue(service._backfill_most_risky_movement(cached))
        self.assertFalse(service._backfill_most_risky_movement(cached))

        history = self.history()
        self.assertNotIn("mostRiskyNew", history[0])
        self.assertEqual((history[1]["mostRiskyNew"], history[1]["mostRiskyResolved"], history[1]["mostRiskyUnchanged"]), (1, 1, 0))
        self.assertEqual(cached["trend_history"][1]["mostRiskyNew"], 1)


def breakdown_entry(week, rows):
    """rows: list of (app_space_name, environment, new, resolved, unchanged)."""
    fields = [name for name, _ in service.MOST_RISKY_BREAKDOWN_FIELDS]
    output = []
    for app, environment, new, resolved, unchanged in rows:
        values = [""] * len(fields)
        values[fields.index("app_space_name")] = app
        values[fields.index("environment")] = environment
        output.append(values + [new, resolved, unchanged])
    return {
        "week": week,
        "new": 999, "resolved": 999, "unchanged": 999,
        "mostRiskyNew": sum(row[2] for row in rows),
        "mostRiskyResolved": sum(row[3] for row in rows),
        "mostRiskyUnchanged": sum(row[4] for row in rows),
        "mostRiskyBreakdown": {"fields": fields, "rows": output},
    }


HISTORY = [
    {"week": "05-10-2026", "new": 5, "resolved": 5, "unchanged": 5},
    breakdown_entry("12-10-2026", [("Payments", "PROD", 100, 60, 600), ("Website", "UAT", 45, 35, 110)]),
    breakdown_entry("19-10-2026", [("Payments", "PROD", 90, 50, 560), ("Website", "UAT", 40, 40, 110)]),
    breakdown_entry("26-10-2026", [("Payments", "PROD", 80, 55, 500), ("Website", "UAT", 40, 30, 140)]),
]


class MostRiskyMovementBrowserTests(unittest.TestCase):
    def rows(self, filters):
        return run_js(
            "mostRiskyMovementHistory(CONTEXT.history, CONTEXT.filters)",
            files=("most-risky-movement.js",),
            context={"history": HISTORY, "filters": filters},
        )

    def test_unfiltered_rows_use_stored_most_risky_totals(self):
        rows = self.rows({})
        self.assertEqual(rows[-1], {"week": "26-10-2026", "new": 120, "resolved": 85, "unchanged": 640, "available": True})
        self.assertFalse(rows[0]["available"])

    def test_dimension_filters_apply_to_every_week(self):
        rows = self.rows({"app_space_name": ["Website"], "severity": []})
        self.assertEqual([(row["new"], row["resolved"], row["unchanged"]) for row in rows[1:]],
                         [(45, 35, 110), (40, 40, 110), (40, 30, 140)])
        self.assertFalse(rows[0]["available"])
        none = self.rows({"environment": ["DEV"]})
        self.assertEqual((none[-1]["new"], none[-1]["available"]), (0, True))

    def test_status_selection_never_zeroes_series(self):
        latest = self.rows({"new_resolved_status": ["Resolved"]})[-1]
        self.assertEqual((latest["new"], latest["resolved"], latest["unchanged"]), (120, 85, 640))
        filtered = self.rows({"new_resolved_status": ["New"], "app_space_name": ["Website"]})
        self.assertEqual([(row["new"], row["resolved"], row["unchanged"]) for row in filtered[1:]],
                         [(45, 35, 110), (40, 40, 110), (40, 30, 140)])

    def test_chart_series_keeps_all_three_and_highlights_selection(self):
        result = run_js(
            "[mostRiskyMovementChartSeries(''), mostRiskyMovementChartSeries('Resolved')]",
            files=("most-risky-movement.js",),
        )
        plain, selected = result
        self.assertEqual([item["key"] for item in plain], ["new", "resolved", "unchanged"])
        self.assertEqual({item["alpha"] for item in plain}, {1})
        self.assertEqual([item["key"] for item in selected], ["new", "resolved", "unchanged"])
        self.assertEqual([(item["alpha"], item["active"]) for item in selected], [(0.25, False), (1, True), (0.25, False)])

    def test_card_click_is_local_view_state(self):
        script = (ROOT / "static" / "js" / "dashboard.js").read_text(encoding="utf-8")
        start = script.index("let mostRiskyMovementSelected")
        section = script[start:script.index("function renderCharts(")]
        self.assertIn("selectMostRiskyMovementStatus(button.dataset.riskyMovementStatus)", section)
        self.assertNotIn("selectMovementStatus(", section)
        self.assertNotIn("isVisible(item) ? Number", section)
        self.assertIn("mostRiskyMovementChartSeries(active)", section)

    def test_pie_percentages_for_latest_week(self):
        result = run_js(
            "(function(){var r=mostRiskyMovementHistory(CONTEXT.history,{}).pop();var t=r.new+r.resolved+r.unchanged;"
            "return [assistantPercent(r.new,t),assistantPercent(r.resolved,t),assistantPercent(r.unchanged,t)];})()",
            context={"history": HISTORY},
        )
        self.assertEqual(result, ["14.2%", "10.1%", "75.7%"])

    def test_direction_compares_open_population(self):
        trend = run_js(
            "mostRiskyMovementDirection(mostRiskyMovementHistory(CONTEXT.history, {}))",
            files=("most-risky-movement.js",),
            context={"history": HISTORY},
        )
        self.assertEqual(trend["direction"], "decreasing")
        self.assertEqual(trend["change"], (120 + 640) - (130 + 670))


class MostRiskyMovementAssistantTests(unittest.TestCase):
    def ask(self, question, raw_filters=None):
        return run_js(
            "answerAssistantQuestion(CONTEXT.question, CONTEXT)",
            context={
                "question": question,
                "records": [{"AppSpaceName": "Payments"}],
                "allRecords": [{"AppSpaceName": "Payments"}],
                "rawFilters": raw_filters or {},
                "trendHistory": HISTORY,
            },
        )

    def test_movement_questions_route_to_most_risky_movement(self):
        for question in (
            "Show Most Risky Vulnerability trend.",
            "How many Most Risky Vulnerabilities were resolved last week?",
            "Show Most Risky Vulnerability movement.",
            "Are Most Risky Vulnerabilities increasing or decreasing?",
            "Show last 7 weeks of Most Risky Vulnerability movement.",
            "Show new Most Risky Vulnerabilities this week.",
        ):
            self.assertEqual(self.ask(question)["id"], "most-risky-movement", question)
        self.assertEqual(self.ask("Show Most Risky Vulnerabilities")["id"], "most-risky")

    def test_answers_contain_correct_movement_values(self):
        resolved = self.ask("How many Most Risky Vulnerabilities were resolved last week?")
        self.assertIn("85 Most Risky Vulnerabilities were resolved in the week of 26-10-2026", resolved["summary"])
        new = self.ask("Show new Most Risky Vulnerabilities this week.")
        self.assertIn("120 Most Risky Vulnerabilities were new", new["summary"])
        direction = self.ask("Are Most Risky Vulnerabilities increasing or decreasing?")
        self.assertIn("decreasing", direction["summary"])
        history = self.ask("Show last 7 weeks of Most Risky Vulnerability movement.")
        self.assertEqual([item["label"] for item in history["items"]], ["26-10-2026", "19-10-2026", "12-10-2026", "05-10-2026"])
        self.assertEqual(history["items"][0]["value"], "120 new | 85 resolved | 640 unchanged")
        self.assertEqual(history["items"][-1]["value"], "Not recorded")

    def test_answers_respect_dashboard_filters(self):
        answer = self.ask("Show Most Risky Vulnerability movement.", {"app_space_name": ["Website"]})
        self.assertIn("40 Most Risky Vulnerabilities were new, 30 were resolved and 140 were unchanged", answer["summary"])


class MostRiskyMovementLayoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
        start = cls.template.index('data-tabs="risky"')
        cls.risky = cls.template[start:cls.template.index('data-tabs="movement"')]

    def test_sections_are_ordered_inside_the_most_risky_tab(self):
        markers = ["mostRiskyDebugPanel", "mostRiskySummary", "mostRiskyCategoryChart", "mostRiskyApplicationChart",
                   "Most Risky Vulnerability Movement", "mostRiskyMovementKpis", "mostRiskyMovementTrendChart",
                   "mostRiskyMovementPieChart", "mostRiskyMovementTable", "Most Risky Vulnerabilities List"]
        positions = [self.risky.index(marker) for marker in markers]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(self.template.count('data-tab="'), 5)

    def test_debug_panel_is_collapsed_by_default(self):
        match = re.search(r'<details id="mostRiskyDebugDetails"([^>]*)>', self.risky)
        self.assertIsNotNone(match)
        self.assertNotIn("open", match.group(1))
        self.assertIn("Show Validation Details", self.risky)

    def test_movement_table_has_sticky_labelled_columns(self):
        self.assertIn('<th scope="col">Week</th><th scope="col">New</th><th scope="col">Resolved</th><th scope="col">Unchanged</th></tr></thead><tbody id="mostRiskyMovementTable">', self.risky)
        self.assertIn("most-risky-movement.js", self.template)
        script = (ROOT / "static" / "js" / "dashboard.js").read_text(encoding="utf-8")
        self.assertRegex(script, r"tbodyId: 'mostRiskyMovementTable'[\s\S]*?defaultPageSize: 7")


if __name__ == "__main__":
    unittest.main()
