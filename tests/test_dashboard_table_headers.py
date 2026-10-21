"""Regression tests for dashboard table headers."""

import unittest
from pathlib import Path


TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "templates" / "dashboard.html"


class DashboardTableHeadersTests(unittest.TestCase):
    def setUp(self):
        self.template = TEMPLATE_PATH.read_text(encoding="utf-8")

    def test_avs_table_body_is_separate_from_its_column_headings(self):
        self.assertIn(
            "<table><thead><tr><th>Application</th><th>Team</th><th>AVS Score</th>"
            "<th>AVS Level</th><th>Unique Vulnerabilities (&gt;45 Days)</th>"
            "<th>Fundamental Classification</th><th>Zone</th></tr></thead>"
            '<tbody id="avsTable"></tbody>',
            self.template,
        )

    def test_most_risky_table_body_is_separate_from_its_column_headings(self):
        self.assertIn(
            "<table><thead><tr><th>AppSpace ID</th><th>Application Name</th><th>Server Name</th>"
            "<th>Vulnerability Name</th><th>CVE</th><th>First Detected Date</th>"
            "<th>Age</th><th>Remit Team</th><th>Solution</th></tr></thead>"
            '<tbody id="mostRiskyTable"></tbody>',
            self.template,
        )
