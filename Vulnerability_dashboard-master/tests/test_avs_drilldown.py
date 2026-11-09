"""Tests for the AVS List application drill-down (category pie + detail table).

The calculation tests run the real static/js/avs-core.js through the dukpy
harness; the DOM tests load table-controller.js, charts.js, avs-core.js and
avs.js unmodified with a minimal DOM stub.
"""

import csv
import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

import services.csv_loader as csv_loader
import services.vulnerability_service as service
from tests.js_harness import run_js

CORE_FILES = ("avs-core.js",)
DOM_FILES = ("table-controller.js", "charts.js", "avs-core.js", "avs.js")


def rec(app="AS-1", cve="CVE-1", sev="5", age=60, category="Java", name=None, first="2026-01-01",
        solution="Patch it", vendor="Vendor", severity=None, app_name=None):
    return {
        "AppSpaceId": app, "AppSpaceName": app_name or f"App {app}", "AppSpaceTeam": "Team",
        "CVE": cve, "Vendor": vendor, "Severity": severity or ("Critical" if sev in ("4", "5") else "High"),
        "Severity Level": sev, "Vulnerability Age": age, "Type Category": category,
        "Vulnerability Name": name or f"Vuln {cve}", "First Detected": first, "Solution": solution,
    }


def drill(records, app="AS-1"):
    return json.loads(run_js(
        "JSON.stringify(computeAvsDrilldown(CONTEXT.records, CONTEXT.app));",
        files=CORE_FILES, context={"records": records, "app": app},
    ))


def by_name(categories):
    return {c["name"]: c for c in categories}


class AvsDrilldownCalculationTests(unittest.TestCase):
    def test_total_matches_avs_unique_count(self):
        records = [
            rec(cve="CVE-1"), rec(cve="CVE-1"), rec(cve="CVE-2", category="CoreOS"),
            rec(cve="", vendor="KB-1", category="Agents"), rec(cve="N/A", vendor="KB-1", category="Agents"),
            rec(app="AS-2", cve="CVE-9"),
        ]
        result = json.loads(run_js(
            "var apps = computeAvsMetrics(CONTEXT.records); var app = apps.filter(function (a) { return a.appId === 'AS-1'; })[0];"
            " JSON.stringify({ unique: app.uniqueCount, total: computeAvsDrilldown(CONTEXT.records, 'AS-1').total });",
            files=CORE_FILES, context={"records": records},
        ))
        self.assertEqual(result["unique"], 3)
        self.assertEqual(result["total"], 3)

    def test_only_selected_application_is_included(self):
        result = drill([rec(cve="CVE-1"), rec(app="AS-2", cve="CVE-2"), rec(app="AS-2", cve="CVE-3")])
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["name"], "App AS-1")

    def test_age_must_be_strictly_greater_than_45_days(self):
        result = drill([rec(cve="CVE-1", age=45), rec(cve="CVE-2", age=46), rec(cve="CVE-3", age=10)])
        self.assertEqual([v["cve"] for v in result["vulnerabilities"]], ["CVE-2"])

    def test_only_severity_4_and_5_are_included(self):
        result = drill([rec(cve="CVE-1", sev="3"), rec(cve="CVE-2", sev="4"), rec(cve="CVE-3", sev="5")])
        self.assertEqual(sorted(v["cve"] for v in result["vulnerabilities"]), ["CVE-2", "CVE-3"])

    def test_unique_logic_dedups_cve_and_falls_back_to_vendor(self):
        result = drill([
            rec(cve="CVE-1"), rec(cve="CVE-1"), rec(cve="CVE-1"),
            rec(cve="", vendor="KB-7"), rec(cve="Unknown", vendor="KB-7"),
            rec(cve="", vendor=""),  # neither CVE nor Vendor: not countable
        ])
        self.assertEqual(result["total"], 2)
        self.assertEqual(sorted(v["key"] for v in result["vulnerabilities"]), ["CVE-1", "KB-7"])

    def test_categories_group_into_five_buckets(self):
        result = drill([
            rec(cve="C1", category="CoreOS"), rec(cve="C2", category="Java"), rec(cve="C3", category="Agent"),
            rec(cve="C4", category="ThirdParty"), rec(cve="C5", category="Third-Party Component"),
            rec(cve="C6", category="Others"), rec(cve="C7", category="Security Policy"), rec(cve="C8", category=""),
        ])
        counts = {c["name"]: c["count"] for c in result["categories"]}
        self.assertEqual(counts, {"CoreOS": 1, "Java": 1, "Agents": 1, "ThirdParty": 2, "Others": 3})
        self.assertEqual([c["name"] for c in result["categories"]], ["CoreOS", "Java", "Agents", "ThirdParty", "Others"])

    def test_percentages_total_100(self):
        for spread in ([1, 1, 1], [35, 25, 15, 20, 5], [1, 2, 3, 4, 7], [1]):
            records = []
            for index, count in enumerate(spread):
                category = ["CoreOS", "Java", "Agents", "ThirdParty", "Others"][index]
                records += [rec(cve=f"{category}-{n}", category=category) for n in range(count)]
            result = drill(records)
            self.assertAlmostEqual(sum(c["percent"] for c in result["categories"]), 100.0, places=6, msg=spread)
            self.assertEqual(sum(c["count"] for c in result["categories"]), result["total"])

    def test_example_distribution_percentages(self):
        records = []
        for category, count in (("CoreOS", 42), ("Java", 30), ("Agents", 18), ("ThirdParty", 24), ("Others", 6)):
            records += [rec(cve=f"{category}-{n}", category=category) for n in range(count)]
        result = by_name(drill(records)["categories"])
        self.assertEqual({k: v["percent"] for k, v in result.items()},
                         {"CoreOS": 35.0, "Java": 25.0, "Agents": 15.0, "ThirdParty": 20.0, "Others": 5.0})

    def test_empty_app_has_zero_percentages(self):
        result = drill([rec(cve="CVE-1", age=5)])
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["averageAge"], 0)
        self.assertTrue(all(c["percent"] == 0 for c in result["categories"]))

    def test_average_age_uses_unique_vulnerabilities(self):
        # CVE-1 appears on two servers (ages 50 and 100) -> counted once at its oldest age.
        result = drill([rec(cve="CVE-1", age=50), rec(cve="CVE-1", age=100), rec(cve="CVE-2", age=60)])
        self.assertEqual(result["averageAge"], 80)

    def test_severity_counts_are_unique_vulnerability_counts(self):
        # CVE-1 has 1 Sev4 + 2 Sev5 findings -> ONE unique vulnerability, reported as Sev5.
        result = drill([rec(cve="CVE-1", sev="4"), rec(cve="CVE-1", sev="5"), rec(cve="CVE-1", sev="5"),
                        rec(cve="CVE-2", sev="4"), rec(cve="CVE-2", sev="4"), rec(cve="CVE-3", sev="5")])
        vulns = {v["cve"]: v for v in result["vulnerabilities"]}
        self.assertEqual(vulns["CVE-1"]["severity"], "Sev5")
        self.assertEqual(vulns["CVE-2"]["severity"], "Sev4")
        self.assertEqual(vulns["CVE-3"]["severity"], "Sev5")
        self.assertEqual((result["sev4"], result["sev5"]), (1, 2))
        self.assertEqual(result["sev4"] + result["sev5"], result["total"])

    def test_detail_columns_are_mapped_from_source(self):
        result = drill([
            rec(cve="CVE-1", name="Java RCE", first="2026-03-01", solution="Upgrade JDK", age=70),
            rec(cve="CVE-1", name="Java RCE", first="2026-02-01", solution="Upgrade JDK", age=90),
        ])
        vuln = result["vulnerabilities"][0]
        self.assertEqual(vuln["name"], "Java RCE")
        self.assertEqual(vuln["cve"], "CVE-1")
        self.assertEqual(vuln["firstDetected"], "2026-02-01")
        self.assertEqual(vuln["age"], 90)
        self.assertEqual(vuln["solution"], "Upgrade JDK")

    def test_slice_filter_returns_only_that_category(self):
        rows = json.loads(run_js(
            "JSON.stringify(avsDrilldownCategoryRows(computeAvsDrilldown(CONTEXT.records, 'AS-1'), 'Java'));",
            files=CORE_FILES,
            context={"records": [rec(cve="J1", category="Java"), rec(cve="J2", category="Java"),
                                 rec(cve="O1", category="CoreOS"), rec(app="AS-2", cve="J3", category="Java"),
                                 rec(cve="J4", category="Java", age=20), rec(cve="J5", category="Java", sev="3")]},
        ))
        self.assertEqual(sorted(v["cve"] for v in rows), ["J1", "J2"])

    def test_unique_vulnerability_is_counted_in_one_category_only(self):
        result = drill([rec(cve="CVE-1", category="Java"), rec(cve="CVE-1", category="Java"),
                        rec(cve="CVE-1", category="CoreOS")])
        counts = {c["name"]: c["count"] for c in result["categories"]}
        self.assertEqual(counts["Java"], 1)
        self.assertEqual(counts["CoreOS"], 0)

    def test_export_records_for_category_filters_by_app_and_category(self):
        records = [rec(cve="J1", category="Java"), rec(cve="O1", category="CoreOS"),
                   rec(app="AS-2", cve="J2", category="Java"), rec(cve="J3", category="Java", age=20),
                   rec(cve="J4", category="Java", sev="3")]
        rows = json.loads(run_js(
            "JSON.stringify(avsExportRecordsForCategory(CONTEXT.records, 'AS-1', 'Java'));",
            files=CORE_FILES, context={"records": records},
        ))
        self.assertEqual([r["CVE"] for r in rows], ["J1"])

    def test_export_records_for_total_includes_every_category(self):
        records = [rec(cve="J1", category="Java"), rec(cve="O1", category="CoreOS"),
                   rec(app="AS-2", cve="J2", category="Java")]
        rows = json.loads(run_js(
            "JSON.stringify(avsExportRecordsForCategory(CONTEXT.records, 'AS-1', 'Total'));",
            files=CORE_FILES, context={"records": records},
        ))
        self.assertEqual(sorted(r["CVE"] for r in rows), ["J1", "O1"])

    def test_existing_avs_metrics_unchanged(self):
        apps = json.loads(run_js(
            "JSON.stringify(computeAvsMetrics(CONTEXT.records));", files=CORE_FILES,
            context={"records": [rec(cve="CVE-1"), rec(cve="CVE-2"), rec(cve="CVE-3", age=10)]},
        ))
        self.assertEqual(apps[0]["uniqueCount"], 2)
        self.assertEqual(apps[0]["score"], 2)  # Internal (1) x Other (1)
        self.assertEqual(apps[0]["level"], "Low")

    def test_explicit_avs_score_override_is_used(self):
        records = [rec(cve="CVE-1")]
        records[0]["AVSScoreOverride"] = 501
        apps = json.loads(run_js(
            "JSON.stringify(computeAvsMetrics(CONTEXT.records));", files=CORE_FILES,
            context={"records": records},
        ))
        self.assertEqual(apps[0]["score"], 501)
        self.assertEqual(apps[0]["level"], "Medium")


DOM_STUB = """
function createStubElement(id) {
  var classes = [];
  return {
    id: id, hidden: false, innerHTML: '', textContent: '', value: '', dataset: {}, _attributes: {}, style: {},
    classList: {
      toggle: function (c, force) { var has = classes.indexOf(c) !== -1; if (force && !has) classes.push(c); if (!force && has) classes.splice(classes.indexOf(c), 1); },
      contains: function (c) { return classes.indexOf(c) !== -1; }
    },
    setAttribute: function (name, value) { this._attributes[name] = value; },
    getAttribute: function (name) { return this._attributes[name]; },
    addEventListener: function () {},
    querySelectorAll: function () { return []; },
    getBoundingClientRect: function () { return { width: 300, height: 300, left: 0, top: 0 }; },
    getContext: function () {
      var noop = function () {};
      return { setTransform: noop, clearRect: noop, beginPath: noop, moveTo: noop, lineTo: noop, arc: noop, closePath: noop,
               fill: noop, stroke: noop, fillRect: noop, fillText: noop, measureText: function () { return { width: 10 }; } };
    }
  };
}
var stubElements = {};
var document = {
  getElementById: function (id) { if (!stubElements[id]) stubElements[id] = createStubElement(id); return stubElements[id]; },
  querySelectorAll: function () { return []; }
};
var window = { devicePixelRatio: 1 };
function esc(value) { return String(value); }
function badge(value) { return String(value); }
function $(id) { return document.getElementById(id); }
"""


class AvsDrilldownDomTests(unittest.TestCase):
    RECORDS = [
        rec(cve="J1", category="Java", sev="4"), rec(cve="J1", category="Java", sev="5"),
        rec(cve="J2", category="Java", sev="4"), rec(cve="J2", category="Java", sev="4"),
        rec(cve="C1", category="CoreOS", sev="5"), rec(cve="C3", category="CoreOS", sev="4"),
        rec(cve="C2", category="CoreOS", sev="4", age=30),
        rec(app="AS-2", cve="X1", category="Java"),
    ]

    def run_dom(self, script):
        return run_js(script, files=DOM_FILES, prelude=DOM_STUB, context={"records": self.RECORDS})

    def test_section_hidden_until_application_selected(self):
        self.assertTrue(self.run_dom("renderAvs(CONTEXT.records); document.getElementById('avsDrilldown').hidden;"))

    def test_application_click_loads_pie_and_title(self):
        result = json.loads(self.run_dom(
            "renderAvs(CONTEXT.records); avsSelectApp('AS-1');"
            " JSON.stringify({ hidden: document.getElementById('avsDrilldown').hidden,"
            "  title: document.getElementById('avsDrilldownTitle').textContent,"
            "  kpis: document.getElementById('avsDrilldownKpis').innerHTML,"
            "  legend: document.getElementById('avsCategoryLegend').innerHTML,"
            "  detailHidden: document.getElementById('avsCategoryDetail').hidden,"
            "  slices: avsPieGeometry.slices.map(function (s) { return s.label; }) });"
        ))
        self.assertFalse(result["hidden"])
        self.assertEqual(result["title"], "App AS-1")
        self.assertIn("Total Unique Sev4/5 Vulnerabilities", result["kpis"])
        self.assertIn("Average Age", result["kpis"])
        self.assertIn("Java 50.0%", result["legend"])
        self.assertIn("CoreOS 50.0%", result["legend"])
        self.assertTrue(result["detailHidden"])
        self.assertEqual(result["slices"], ["CoreOS", "Java"])

    def test_slice_click_shows_category_detail_with_severity_counts(self):
        result = json.loads(self.run_dom(
            "renderAvs(CONTEXT.records); avsSelectApp('AS-1'); avsSelectCategory('Java');"
            " JSON.stringify({ hidden: document.getElementById('avsCategoryDetail').hidden,"
            "  rows: document.getElementById('avsDetailTable').innerHTML,"
            "  summary: document.getElementById('avsCategoryDetailSummary').textContent });"
        ))
        self.assertFalse(result["hidden"])
        self.assertEqual(result["rows"].count("<tr>"), 2)  # one row per unique vulnerability
        self.assertIn("J1", result["rows"])
        self.assertIn("J2", result["rows"])
        self.assertNotIn("C1", result["rows"])
        self.assertNotIn("X1", result["rows"])
        self.assertNotIn("Count", result["rows"])
        self.assertIn(">Sev5<", result["rows"])
        self.assertIn(">Sev4<", result["rows"])
        self.assertIn("2 unique Sev4/5 vulnerabilities", result["summary"])
        self.assertIn("Unique Sev4 Count : 1 · Unique Sev5 Count : 1", result["summary"])

    def test_kpis_show_unique_severity_counts(self):
        kpis = self.run_dom("renderAvs(CONTEXT.records); avsSelectApp('AS-1'); document.getElementById('avsDrilldownKpis').innerHTML;")
        # 4 unique (J1=Sev5, J2=Sev4, C1=Sev5, C3=Sev4); C2 excluded by age.
        self.assertRegex(kpis, r"Unique Sev4 Count.*?kpi-value\">2<")
        self.assertRegex(kpis, r"Unique Sev5 Count.*?kpi-value\">2<")

    def test_pie_hit_testing_maps_click_to_slice(self):
        result = json.loads(self.run_dom(
            "renderAvs(CONTEXT.records); avsSelectApp('AS-1');"
            # CoreOS is drawn first, clockwise from 12 o'clock (right half); Java second (left half).
            " JSON.stringify([pieSliceAt(avsPieGeometry, 220, 150), pieSliceAt(avsPieGeometry, 80, 150), pieSliceAt(avsPieGeometry, 0, 0)]);"
        ))
        self.assertEqual(result, ["CoreOS", "Java", None])

    def test_clicking_selected_app_again_hides_section(self):
        self.assertTrue(self.run_dom(
            "renderAvs(CONTEXT.records); avsSelectApp('AS-1'); avsSelectApp('AS-1');"
            " document.getElementById('avsDrilldown').hidden;"
        ))

    def test_close_hides_section(self):
        self.assertTrue(self.run_dom(
            "renderAvs(CONTEXT.records); avsSelectApp('AS-1'); avsCloseDrilldown();"
            " document.getElementById('avsDrilldown').hidden;"
        ))

    def test_section_hides_when_filters_remove_selected_app(self):
        self.assertTrue(self.run_dom(
            "renderAvs(CONTEXT.records); avsSelectApp('AS-1');"
            " renderAvs(CONTEXT.records.filter(function (r) { return r.AppSpaceId !== 'AS-1'; }));"
            " document.getElementById('avsDrilldown').hidden;"
        ))

    def test_avs_list_rows_are_clickable_and_highlight_selection(self):
        rows = self.run_dom(
            "renderAvs(CONTEXT.records); avsSelectApp('AS-1'); avsTable.update(computeAvsMetrics(CONTEXT.records));"
            " document.getElementById('avsTable').innerHTML;"
        )
        self.assertIn('data-app-id="AS-1"', rows)
        self.assertIn('data-app-id="AS-2"', rows)
        self.assertEqual(rows.count("avs-row-selected"), 1)


class AvsDrilldownSourceFieldTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def write_csv(self, rows):
        path = Path(self.temp.name) / "report.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=csv_loader.STANDARD_COLUMNS)
            writer.writeheader()
            for updates in rows:
                row = {column: "" for column in csv_loader.STANDARD_COLUMNS}
                row.update({
                    "ServerName": "srv", "OperatingSystem": "Linux", "Environment": "Production",
                    "AppSpaceId": "AS-1", "AppSpaceName": "App", "AppSpaceTeam": "Team", "QID": "1",
                    "VulnerabilityName": "Java RCE", "Severity": "5", "AssetRiskScore": "50", "PCIRequired": "no",
                    "Category": "Java", "CVE": "CVE-2026-0001", "VendorReference": "KB-1",
                    "FirstDetected": "2026-01-01", "LastDetected": "2026-03-31", "Resolved": "", "SLABreach": "no",
                    "Status": "Open", "Solution": "Upgrade JDK",
                })
                row.update(updates)
                writer.writerow(row)
        return path

    def test_record_exposes_raw_severity_level_and_solution(self):
        records, _ = csv_loader.load_vulnerabilities(self.write_csv([{}, {"Severity": "4", "QID": "2"}]), today=date(2026, 6, 1))
        first, second = (r.to_dict() for r in records)
        self.assertEqual(first["Severity"], "Critical")
        self.assertEqual(first["Severity Level"], "5")
        self.assertEqual(second["Severity Level"], "4")
        self.assertEqual(first["Solution"], "Upgrade JDK")
        self.assertEqual(first["Type Category"], "Java")
        self.assertEqual(first["Vulnerability Name"], "Java RCE")
        self.assertEqual(first["First Detected"], "2026-01-01")

    def test_processed_output_columns_unchanged(self):
        self.assertNotIn("Severity Level", csv_loader.PROCESSED_COLUMNS)

    def test_processed_csv_severity_is_numeric_from_input(self):
        rows = [{"Severity": str(level), "QID": str(level)} for level in (5, 4, 3, 2, 1)]
        rows += [{"Severity": "High", "QID": "6"}, {"Severity": "Critical", "QID": "7"}, {"Severity": "bogus", "QID": "8"}]
        records, _ = csv_loader.load_vulnerabilities(self.write_csv(rows), today=date(2026, 6, 1))
        output = Path(self.temp.name) / "processed.csv"
        csv_loader.write_processed_csv(records, output)
        with output.open("r", encoding="utf-8", newline="") as handle:
            severities = [row["Severity"] for row in csv.DictReader(handle)]
        self.assertEqual(severities, ["5", "4", "3", "2", "1", "3", "5", ""])
        # The dashboard/API record keeps the normalized label.
        self.assertEqual(records[0].to_dict()["Severity"], "Critical")

    def test_cache_without_severity_level_is_stale(self):
        self.assertTrue(service._cache_is_stale({"records": [{"Severity": "Critical"}]}))
        self.assertTrue(service._cache_is_stale({"records": [{"Severity": "Critical", "Severity Level": "5"}]}))
        fresh = {"Severity": "Critical", "Severity Level": "5", "FundamentalClassification": "Other", "Zone": "Internal", "RemitTeam": "Other", "Exploit": False, "Unique Vuln Name": "CVE-1", "VULN COUNT": "SRVAppCVE-1", "VulKey": "APP||App||SRV||PROD||1", "NewResolvedStatus": "New", "PatchAvailable": "FALSE", "SLABreach": False}
        self.assertFalse(service._cache_is_stale({"records": [fresh]}))
        self.assertFalse(service._cache_is_stale({"records": []}))


if __name__ == "__main__":
    unittest.main()
