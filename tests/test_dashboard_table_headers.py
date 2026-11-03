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

    def test_avs_update_table_has_reference_column_headings(self):
        self.assertIn('<div id="avsUpdateGrid" class="avs-update-grid" hidden>', self.template)
        self.assertIn('<section id="avsWeeklyUpdate" class="panel avs-weekly-update">', self.template)
        self.assertIn('<canvas id="avsWeeklyMovementChart"></canvas>', self.template)
        self.assertIn('<div id="avsWeeklyMovementLegend" class="legend avs-movement-legend"></div>', self.template)
        self.assertIn('<ul id="avsWeeklyUpdateNotes" class="avs-update-notes" hidden></ul>', self.template)
        self.assertIn(
            '<table class="avs-update-table"><thead><tr><th scope="col">APP NAME</th>'
            '<th scope="col">AVS</th></tr></thead><tbody id="avsWeeklyUpdateTable"></tbody></table>',
            self.template,
        )
        self.assertIn(
            '<h2 id="avsWeeklyUpdateTitle"></h2><div class="avs-update-legend"'
            ' aria-label="AVS update status legend"><span class="avs-update-label avs-update-treated">'
            'Improved/Treated</span><span class="avs-update-label avs-update-new">New</span>'
            '<span class="avs-update-label avs-update-high">High</span>'
            '<span class="avs-update-label avs-update-med">Med</span>',
            self.template,
        )

    def test_avs_update_status_colours_apply_to_requested_cells(self):
        css = (TEMPLATE_PATH.parents[1] / "static" / "css" / "dashboard.css").read_text(encoding="utf-8")
        self.assertIn(".avs-update-grid {\n  display: grid;\n  grid-template-columns: repeat(2, minmax(0, 1fr));", css)
        self.assertIn(".avs-update-table th {\n  background: #d8e5e5;\n  border: 1px solid #6f8f8f;", css)
        self.assertIn(".avs-update-table td {\n  border: 1px solid #6f8f8f;\n  color: #17343a;", css)
        self.assertNotIn(".avs-update-row-treated td { background:", css)
        self.assertIn(".avs-update-treated-heading td {\n  background: #4ccfd0;", css)
        self.assertIn(".avs-update-row-new td:first-child { background: #f5a623; }", css)
        self.assertIn(".avs-update-row-high .avs-update-score { background: #ebc1cc; }", css)
        self.assertIn(".avs-update-row-med .avs-update-score { background: #e9d28f; }", css)
        self.assertIn(".avs-update-table .avs-update-row-treated td {\n  width: auto;\n  text-align: left;", css)
        self.assertIn(".avs-update-table .avs-update-treated-heading td {\n  width: auto;\n  text-align: center;", css)
        self.assertIn(".avs-update-table td:first-child {\n  font-weight: 700;", css)
        self.assertIn(".avs-update-notes {\n  margin: var(--space-3) 0 0;\n  padding: var(--space-3) 0 0 20px;", css)

    def test_weekly_movement_charts_use_fixed_height_boxes(self):
        css = (TEMPLATE_PATH.parents[1] / "static" / "css" / "dashboard.css").read_text(encoding="utf-8")
        self.assertIn('<div class="movement-chart-box movement-trend-box"><canvas id="movementTrendChart"', self.template)
        self.assertIn('<div class="movement-chart-box movement-pie-box"><canvas id="movementPieChart"', self.template)
        self.assertRegex(css, r"\.movement-trend-box \{\s*height: 360px;")
        self.assertRegex(css, r"\.chart-panel \.movement-chart-box canvas \{\s*position: absolute;")
