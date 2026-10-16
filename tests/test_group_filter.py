"""Unit tests for the Group dashboard filter (filters.js).

Group is the dashboard's primary/global filter: it is rendered as a static
select in the topbar (see dashboard.html) rather than among the regular
toolbar filters built from FILTER_FIELDS, but it must still behave like every
other filter - its value is read by getFilters()/recordMatchesFilters()
because those helpers operate generically on every element carrying a
`data-filter` attribute, wherever it lives in the DOM. These tests run the
shipped filters.js with the dukpy harness and assert all of that end to end.
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
        "RemitTeam": "Change/ITO",
        "Group": "Suncorp Bank",
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
        make_record(ServerName="SRV-1", RemitTeam="Change/ITO", Group="Suncorp Bank", CVE="CVE-2026-0001"),
        make_record(ServerName="SRV-2", RemitTeam="Change/ITO", Group="Suncorp Bank", CVE="CVE-2026-0002"),
        make_record(ServerName="SRV-3", RemitTeam="Wintel", Group="Suncorp Group", CVE="CVE-2026-0003"),
        make_record(ServerName="SRV-4", RemitTeam="Dynatrace", Group="Suncorp Group", CVE="CVE-2026-0004"),
    ]


def evaluate(script, records=None):
    return run_js(script, context={"records": records if records is not None else sample_records()})


class GroupFilterTests(unittest.TestCase):
    def test_group_filter_is_resolvable_but_not_auto_rendered_in_the_toolbar(self):
        keys = json.loads(evaluate("JSON.stringify(FILTER_FIELDS.map(function (f) { return f.key; }));"))
        self.assertNotIn("group", keys, "Group is a primary filter rendered separately from the toolbar filters")
        definition = evaluate("JSON.stringify(filterDefinition('group'));")
        self.assertEqual(json.loads(definition), {"key": "group", "label": "Group", "field": "Group"})

    def test_filter_options_come_from_the_records(self):
        values = json.loads(evaluate("JSON.stringify(optionValues(CONTEXT.records, 'group'));"))
        self.assertEqual(values, ["Suncorp Bank", "Suncorp Group"])

    def test_record_filter_value_reads_the_group_column(self):
        value = evaluate("recordFilterValue(CONTEXT.records[2], 'group');")
        self.assertEqual(value, "Suncorp Group")

    def test_missing_group_value_is_blank(self):
        value = evaluate("recordFilterValue({ServerName: 'SRV-9'}, 'group');")
        self.assertEqual(value, "")

    def test_filtering_by_suncorp_bank(self):
        servers = json.loads(evaluate(
            "JSON.stringify(CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {group: ['Suncorp Bank']}); })"
            ".map(function (r) { return r.ServerName; }));"
        ))
        self.assertEqual(servers, ["SRV-1", "SRV-2"])

    def test_filtering_by_suncorp_group(self):
        servers = json.loads(evaluate(
            "JSON.stringify(CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {group: ['Suncorp Group']}); })"
            ".map(function (r) { return r.ServerName; }));"
        ))
        self.assertEqual(servers, ["SRV-3", "SRV-4"])

    def test_empty_selection_keeps_every_record(self):
        count = evaluate("CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {group: []}); }).length;")
        self.assertEqual(count, len(sample_records()))

    def test_group_combines_with_other_filters(self):
        records = sample_records()
        records[1]["Severity"] = "Low"
        servers = json.loads(evaluate(
            "JSON.stringify(CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, {group: ['Suncorp Bank'], severity: ['Critical']}); })"
            ".map(function (r) { return r.ServerName; }));",
            records,
        ))
        self.assertEqual(servers, ["SRV-1"])

    def test_assistant_resolves_group_questions_to_the_filter(self):
        filters = json.loads(evaluate("JSON.stringify(assistantExtractFilters('How many findings for Suncorp Bank?', CONTEXT.records).filters);"))
        self.assertEqual(filters.get("group"), ["Suncorp Bank"])

    def test_assistant_answer_is_scoped_to_the_group(self):
        total = evaluate(
            "(function () {"
            "  var extracted = assistantExtractFilters('Summarize Suncorp Group findings', CONTEXT.records);"
            "  return CONTEXT.records.filter(function (r) { return recordMatchesFilters(r, extracted.filters); }).length;"
            "})();"
        )
        self.assertEqual(total, 2)


if __name__ == "__main__":
    unittest.main()
