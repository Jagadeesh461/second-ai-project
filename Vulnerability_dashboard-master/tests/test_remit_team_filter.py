"""Unit tests for the RemitTeam dashboard filter (filters.js).

The Vendor filter was replaced by a RemitTeam filter, so these tests run
the shipped filters.js with the dukpy harness and assert that the new filter is
registered, lists values from the processed records, and narrows the records
exactly like any other dashboard filter. The assistant is included so the
chatbot is proven to resolve RemitTeam questions through the same filter.
"""

import json
import unittest

from tests.js_harness import run_js


def make_record(**overrides):
    record = {
        "ServerName": "SRV-1",
        "Operating System": "Windows Server 2022",
        "Environment": "Production",
        "AppSpaceName": "Customer Portal",
        "AppSpaceId": "AS-1",
        "AppSpaceOwner": "Aisha Khan",
        "AppSpaceTeam": "Digital Platforms",
        "QID": "QID-1",
        "Vulnerability Name": "OpenSSL Vulnerability",
        "Severity": "Critical",
        "CVE": "CVE-2026-0001",
        "Vendor": "Acme",
        "RemitTeam": "Wintel",
        "Type Category": "Patch",
        "Status": "Open",
        "PCI Required": False,
        "SLA Due Date": "2026-01-10",
        "Vulnerability Age": 30,
        "Days Open": 90,
        "Days Overdue": 60,
        "SLABreach": True,
        "Overdue": True,
        "FundamentalClassification": "Other",
        "Zone": "Internal",
    }
    record.update(overrides)
    return record


def sample_records():
    return [
        make_record(ServerName="SRV-1", RemitTeam="Wintel", CVE="CVE-2026-0001"),
        make_record(ServerName="SRV-2", RemitTeam="Wintel", CVE="CVE-2026-0002"),
        make_record(ServerName="SRV-3", RemitTeam="Control-M", CVE="CVE-2026-0003"),
        make_record(ServerName="SRV-4", RemitTeam="AppHealth", CVE="CVE-2026-0004"),
        make_record(ServerName="SRV-5", RemitTeam="Other", CVE="CVE-2026-0005"),
    ]


def evaluate(script, records=None):
    return run_js(script, context={"records": records if records is not None else sample_records()})


class RemitTeamFilterTests(unittest.TestCase):
    def test_remit_team_filter_is_registered(self):
        definition = evaluate("JSON.stringify(FILTER_FIELDS.filter(function (f) { return f.key === 'remit_team'; })[0]);")
        self.assertEqual(json.loads(definition), {"key": "remit_team", "label": "Remit Team", "field": "RemitTeam"})

    def test_vendor_filter_is_removed(self):
        keys = json.loads(evaluate("JSON.stringify(FILTER_FIELDS.map(function (f) { return f.key; }));"))
        self.assertNotIn("vendor", keys)
        self.assertIn("remit_team", keys)

    def test_filter_options_come_from_the_records(self):
        values = json.loads(evaluate("JSON.stringify(optionValues(CONTEXT.records, 'remit_team'));"))
        self.assertEqual(values, ["AppHealth", "Control-M", "Other", "Wintel"])

    def test_record_filter_value_reads_the_remit_team_column(self):
        value = evaluate("recordFilterValue(CONTEXT.records[2], 'remit_team');")
        self.assertEqual(value, "Control-M")

    def test_missing_remit_team_value_is_blank(self):
        value = evaluate("recordFilterValue({ServerName: 'SRV-9'}, 'remit_team');")
        self.assertEqual(value, "")

    def test_filtering_by_a_single_remit_team(self):
        servers = json.loads(evaluate(
            "JSON.stringify(CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {remit_team: ['Wintel']}); })"
            ".map(function (r) { return r.ServerName; }));"
        ))
        self.assertEqual(servers, ["SRV-1", "SRV-2"])

    def test_filtering_by_multiple_remit_teams(self):
        servers = json.loads(evaluate(
            "JSON.stringify(CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {remit_team: ['Control-M', 'AppHealth']}); })"
            ".map(function (r) { return r.ServerName; }));"
        ))
        self.assertEqual(servers, ["SRV-3", "SRV-4"])

    def test_default_other_value_is_filterable(self):
        servers = json.loads(evaluate(
            "JSON.stringify(CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {remit_team: ['Other']}); })"
            ".map(function (r) { return r.ServerName; }));"
        ))
        self.assertEqual(servers, ["SRV-5"])

    def test_empty_selection_keeps_every_record(self):
        count = evaluate("CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {remit_team: []}); }).length;")
        self.assertEqual(count, len(sample_records()))

    def test_remit_team_combines_with_other_filters(self):
        records = sample_records()
        records[1]["Severity"] = "Low"
        servers = json.loads(evaluate(
            "JSON.stringify(CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {remit_team: ['Wintel'], severity: ['Critical']}); })"
            ".map(function (r) { return r.ServerName; }));",
            records,
        ))
        self.assertEqual(servers, ["SRV-1"])

    def test_assistant_resolves_remit_team_questions_to_the_filter(self):
        filters = json.loads(evaluate("JSON.stringify(assistantExtractFilters('How many findings for Control-M?', CONTEXT.records).filters);"))
        self.assertEqual(filters.get("remit_team"), ["Control-M"])

    def test_assistant_answer_is_scoped_to_the_remit_team(self):
        total = evaluate(
            "(function () {"
            "  var extracted = assistantExtractFilters('Summarize AppHealth findings', CONTEXT.records);"
            "  return CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, extracted.filters); }).length;"
            "})();"
        )
        self.assertEqual(total, 1)


if __name__ == "__main__":
    unittest.main()
