"""Unit tests for the pure (DOM/canvas-free) helpers in avs-report.js.

The PDF assembly itself (jsPDF calls, canvas.toDataURL, document.createElement)
needs a real browser and is out of scope for the dukpy harness used elsewhere
in this project. These tests cover the parts that contain actual logic:
the report filename format, the "Label = value" filter-line formatting, and
the hex-to-RGB color conversion used to theme the PDF to match the dashboard.
"""

import json
import unittest

from tests.js_harness import run_js

REPORT_FILES = ("avs-report.js",)

# avs-report.js's top-level IIFE wires a click handler onto a button looked
# up via document.getElementById, so a minimal document stub is required even
# though these tests only exercise pure helper functions.
PRELUDE = """
function activeFilterSummary() { return CONTEXT.summary || []; }
var document = { getElementById: function () { return null; } };
"""


def evaluate(script, summary=None):
    return run_js(script, files=REPORT_FILES, prelude=PRELUDE, context={"summary": summary or []})


class AvsReportFilenameTests(unittest.TestCase):
    def test_filename_matches_expected_pattern(self):
        name = evaluate("avsReportFilename();")
        self.assertRegex(name, r"^AVS_Report_\d{8}_\d{4}\.pdf$")

    def test_filename_date_parts_are_zero_padded(self):
        name = evaluate(
            "(function () {"
            "  var original = Date;"
            "  Date = function () { return new original(2026, 0, 5, 9, 7); };"
            "  Date.prototype = original.prototype;"
            "  var result = avsReportFilename();"
            "  Date = original;"
            "  return result;"
            "})();"
        )
        self.assertEqual(name, "AVS_Report_20260105_0907.pdf")


class AvsReportFilterLinesTests(unittest.TestCase):
    def test_no_filters_falls_back_to_a_scope_message(self):
        lines = evaluate("JSON.stringify(avsReportFilterLines());", summary=[])
        self.assertIn("No filters applied", lines)

    def test_single_filter_is_formatted_as_label_equals_value(self):
        lines = json.loads(evaluate(
            "JSON.stringify(avsReportFilterLines());",
            summary=[{"label": "Group", "values": ["Suncorp Bank"]}],
        ))
        self.assertEqual(lines, ["Group = Suncorp Bank"])

    def test_multi_value_filter_joins_values_with_commas(self):
        lines = json.loads(evaluate(
            "JSON.stringify(avsReportFilterLines());",
            summary=[{"label": "Environment", "values": ["Production", "Staging"]}],
        ))
        self.assertEqual(lines, ["Environment = Production, Staging"])

    def test_multiple_active_filters_each_get_their_own_line(self):
        lines = json.loads(evaluate(
            "JSON.stringify(avsReportFilterLines());",
            summary=[
                {"label": "Group", "values": ["Suncorp Bank"]},
                {"label": "Environment", "values": ["Production"]},
            ],
        ))
        self.assertEqual(lines, ["Group = Suncorp Bank", "Environment = Production"])


class AvsReportHexToRgbTests(unittest.TestCase):
    def test_converts_brand_orange(self):
        rgb = evaluate("JSON.stringify(avsReportHexToRgb('#f2661e'));")
        self.assertEqual(rgb, "[242,102,30]")

    def test_converts_without_leading_hash(self):
        rgb = evaluate("JSON.stringify(avsReportHexToRgb('182236'));")
        self.assertEqual(rgb, "[24,34,54]")


if __name__ == "__main__":
    unittest.main()
