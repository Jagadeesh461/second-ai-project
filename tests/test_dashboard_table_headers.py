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

    def test_weekly_movement_table_body_is_separate_from_its_column_headings(self):
        # createDataTable replaces the innerHTML of the element it is given, so
        # the id must sit on the <tbody>, never the <table>, or the headers vanish.
        self.assertIn(
            '<table class="movement-table"><thead><tr><th scope="col">Week</th><th scope="col">New</th>'
            '<th scope="col">Resolved</th><th scope="col">Unchanged</th></tr></thead>'
            '<tbody id="movementTable"></tbody>',
            self.template,
        )

    def test_weekly_movement_charts_use_fixed_height_boxes(self):
        css = (TEMPLATE_PATH.parents[1] / "static" / "css" / "dashboard.css").read_text(encoding="utf-8")
        self.assertIn('<div class="movement-chart-box movement-trend-box"><canvas id="movementTrendChart"', self.template)
        self.assertIn('<div class="movement-chart-box movement-pie-box"><canvas id="movementPieChart"', self.template)
        self.assertRegex(css, r"\.movement-trend-box \{\s*height: 360px;")
        self.assertRegex(css, r"\.chart-panel \.movement-chart-box canvas \{\s*position: absolute;")
