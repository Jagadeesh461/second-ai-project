import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pandas as pd

import avs_calculator


def make_record(app_id, app_name, app_team, severity="Critical", age_days=46, cve="CVE-2026-0001", vendor="Acme"):
    return SimpleNamespace(
        app_space_id=app_id,
        app_space_name=app_name,
        app_space_team=app_team,
        severity=severity,
        age_days=age_days,
        cve=cve,
        vendor=vendor,
    )


class ClassifyAvsTests(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(avs_calculator.classify_avs(0), "Low")
        self.assertEqual(avs_calculator.classify_avs(499.99), "Low")
        self.assertEqual(avs_calculator.classify_avs(500), "Medium")
        self.assertEqual(avs_calculator.classify_avs(1000), "Medium")
        self.assertEqual(avs_calculator.classify_avs(1000.01), "High")
        self.assertEqual(avs_calculator.classify_avs(5000), "High")


class RatingLookupTests(unittest.TestCase):
    def test_zone_rating_known_and_default(self):
        self.assertEqual(avs_calculator.zone_rating("External"), 5)
        self.assertEqual(avs_calculator.zone_rating("Internal"), 1)
        self.assertEqual(avs_calculator.zone_rating("Internal & Protected"), 0.2)
        self.assertEqual(avs_calculator.zone_rating("Unmapped Zone"), avs_calculator.EXPOSURE_ZONE_RATINGS["Internal"])
        self.assertEqual(avs_calculator.zone_rating(""), avs_calculator.EXPOSURE_ZONE_RATINGS["Internal"])

    def test_fundamental_classification_rating_known_and_default(self):
        self.assertEqual(avs_calculator.fundamental_classification_rating("Essential"), 2)
        self.assertEqual(avs_calculator.fundamental_classification_rating("Fundamental"), 2)
        self.assertEqual(avs_calculator.fundamental_classification_rating("Other"), 1)
        self.assertEqual(avs_calculator.fundamental_classification_rating("Unmapped"), avs_calculator.FUNDAMENTAL_CLASSIFICATION_RATINGS["Other"])


class AvsCalculatorTestCase(unittest.TestCase):
    """Base class that isolates compute_avs from the real static_mapping.csv on disk.

    ``compute_avs`` calls ``ensure_static_mapping()``/``load_static_mapping()`` with
    no arguments, so patching the ``STATIC_MAPPING_PATH`` constant alone would not
    take effect (their ``path`` defaults are bound at function-definition time).
    Patching the functions themselves keeps these tests fully isolated from
    whatever is in the project's real static/static_mapping.csv file.
    """

    def setUp(self):
        self._mapping_frame = pd.DataFrame(columns=avs_calculator.STATIC_MAPPING_COLUMNS)
        self.ensure_patcher = patch.object(avs_calculator, "ensure_static_mapping", lambda records, path=None: None)
        self.load_patcher = patch.object(avs_calculator, "load_static_mapping", lambda path=None: self._mapping_frame)
        self.ensure_patcher.start()
        self.load_patcher.start()
        self.addCleanup(self.ensure_patcher.stop)
        self.addCleanup(self.load_patcher.stop)

    def set_mapping(self, rows):
        self._mapping_frame = pd.DataFrame(rows, columns=avs_calculator.STATIC_MAPPING_COLUMNS)


class ComputeAvsTests(AvsCalculatorTestCase):
    def test_only_critical_over_45_days_qualifies(self):
        records = [
            make_record("APP-1", "Payments", "Platform", severity="Critical", age_days=46),
            make_record("APP-1", "Payments", "Platform", severity="High", age_days=200, cve="CVE-2026-0002"),
            make_record("APP-1", "Payments", "Platform", severity="Critical", age_days=45, cve="CVE-2026-0003"),
        ]
        result = avs_calculator.compute_avs(records)
        self.assertEqual(result.loc["APP-1", "AVSUniqueVulnCount"], 1)

    def test_dedup_by_cve_falls_back_to_vendor_when_cve_blank(self):
        records = [
            make_record("APP-1", "Payments", "Platform", cve="CVE-2026-0001"),
            make_record("APP-1", "Payments", "Platform", cve="CVE-2026-0001"),  # duplicate CVE, not double-counted
            make_record("APP-1", "Payments", "Platform", cve="N/A", vendor="Acme"),
            make_record("APP-1", "Payments", "Platform", cve="N/A", vendor="Acme"),  # dup vendor fallback key
            make_record("APP-1", "Payments", "Platform", cve="N/A", vendor="N/A"),  # blank/blank is dropped entirely
        ]
        result = avs_calculator.compute_avs(records)
        # CVE-2026-0001 (1) + Acme fallback (1) = 2 unique keys; the fully-blank row never qualifies.
        self.assertEqual(result.loc["APP-1", "AVSUniqueVulnCount"], 2)

    def test_score_uses_zone_and_fundamental_classification_from_static_mapping(self):
        self.set_mapping([
            {"AppSpaceId": "APP-1", "AppSpaceName": "Payments", "AppSpaceTeam": "Platform", "FundamentalClassification": "Essential", "Zone": "External"},
        ])
        records = [make_record("APP-1", "Payments", "Platform", cve="CVE-A"), make_record("APP-1", "Payments", "Platform", cve="CVE-B")]
        result = avs_calculator.compute_avs(records)
        row = result.loc["APP-1"]
        # 2 unique vulns * zone rating 5 (External) * asset rating 2 (Essential) = 20
        self.assertEqual(row["AVSUniqueVulnCount"], 2)
        self.assertEqual(row["AVSScore"], 20)
        self.assertEqual(row["AVSLevel"], "Low")

    def test_unmapped_app_falls_back_to_defaults(self):
        records = [make_record("APP-UNMAPPED", "Unknown App", "Unknown Team")]
        result = avs_calculator.compute_avs(records)
        row = result.loc["APP-UNMAPPED"]
        self.assertEqual(row["FundamentalClassification"], avs_calculator.DEFAULT_FUNDAMENTAL_CLASSIFICATION)
        self.assertEqual(row["Zone"], avs_calculator.DEFAULT_ZONE)

    def test_empty_records_returns_empty_frame(self):
        result = avs_calculator.compute_avs([])
        self.assertTrue(result.empty)


class AttachAvsToRecordsTests(AvsCalculatorTestCase):
    def test_attaches_score_and_level_onto_every_matching_record(self):
        records = [
            make_record("APP-1", "Payments", "Platform", cve="CVE-A"),
            make_record("APP-1", "Payments", "Platform", cve="CVE-B"),
        ]
        avs_calculator.attach_avs_to_records(records)
        for record in records:
            self.assertEqual(record.avs_unique_vuln_count, 2)
            self.assertEqual(record.avs_level, "Low")
            self.assertEqual(record.zone, avs_calculator.DEFAULT_ZONE)
            self.assertEqual(record.fundamental_classification, avs_calculator.DEFAULT_FUNDAMENTAL_CLASSIFICATION)

    def test_records_with_no_qualifying_findings_get_zero_score(self):
        records = [make_record("APP-2", "Billing", "Ops", severity="Low", age_days=1)]
        avs_calculator.attach_avs_to_records(records)
        self.assertEqual(records[0].avs_score, 0.0)
        self.assertEqual(records[0].avs_level, "Low")


class BuildAvsSummaryTests(AvsCalculatorTestCase):
    def test_summary_totals_and_sort_order(self):
        records = (
            [make_record("APP-LOW", "Low App", "Team A", cve="CVE-LOW")]
            # 101 unique CVEs * zone rating 5 (External) * asset rating 2 (Essential) = 1010 -> High
            + [make_record("APP-HIGH", "High App", "Team B", cve=f"CVE-HIGH-{i}") for i in range(101)]
        )
        self.set_mapping([
            {"AppSpaceId": "APP-HIGH", "AppSpaceName": "High App", "AppSpaceTeam": "Team B", "FundamentalClassification": "Essential", "Zone": "External"},
        ])

        per_app = avs_calculator.compute_avs(records)
        summary = avs_calculator.build_avs_summary(per_app)

        self.assertEqual(summary["totals"]["total"], 2)
        self.assertEqual(summary["applications"][0]["AppSpaceId"], "APP-HIGH")
        self.assertEqual(summary["applications"][0]["AVSLevel"], "High")
        self.assertEqual(summary["totals"]["high"], 1)
        self.assertEqual(summary["totals"]["low"], 1)

    def test_empty_summary(self):
        summary = avs_calculator.build_avs_summary(pd.DataFrame())
        self.assertEqual(summary, {"applications": [], "totals": {"total": 0, "low": 0, "medium": 0, "high": 0}})


if __name__ == "__main__":
    unittest.main()
