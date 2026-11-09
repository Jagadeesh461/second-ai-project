"""Unit tests for the assistant's natural-language -> dashboard filter mapping.

These tests exercise the requirement that the chatbot never invents its own
filtering logic: every entity it recognises in a question (AppSpace, Owner,
Team, Environment, Severity, Status, AVS Level, SLA Breach, ...) must be
converted into the same filter object the dashboard filter dropdowns build
(FILTER_FIELDS / getFilters in filters.js), and applied with the dashboard's
own recordMatchesFilters() predicate. The dashboard-filter-equivalent result
is computed directly in each test and compared against the chatbot's answer
to prove both surfaces agree exactly.
"""

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
        "Status": "Open",
        "PCI Required": False,
        "SLA Due Date": "2026-01-10",
        "Vulnerability Age": 90,
        "Days Open": 90,
        "Days Overdue": 60,
        "SLABreach": True,
        "Overdue": True,
        "FundamentalClassification": "Other",
        "Zone": "Internal",
    }
    record.update(overrides)
    return record


def mixed_records():
    """A mix of owners, AppSpaces, teams and environments to disambiguate against."""
    records = []
    for index in range(3):
        records.append(make_record(
            ServerName=f"SRV-A{index}", AppSpaceName="Payment Gateway", AppSpaceId="AS-PAY",
            AppSpaceOwner="Aisha Khan", AppSpaceTeam="Payments Team", CVE=f"CVE-2026-10{index}",
            Severity="Critical", Environment="Production",
        ))
    for index in range(2):
        records.append(make_record(
            ServerName=f"SRV-B{index}", AppSpaceName="Trading Gateway", AppSpaceId="AS-TRD",
            AppSpaceOwner="Aisha Khan", AppSpaceTeam="Markets", CVE=f"CVE-2026-20{index}",
            Severity="High", Environment="Staging", **{"SLABreach": False, "Overdue": False},
        ))
    records.append(make_record(
        ServerName="SRV-C0", AppSpaceName="Intranet", AppSpaceId="AS-INT",
        AppSpaceOwner="Ravi Sharma", AppSpaceTeam="Digital Team", CVE="CVE-2026-3000",
        Severity="Medium", Environment="Production", **{"SLABreach": True, "Overdue": True},
    ))
    records.append(make_record(
        ServerName="SRV-C1", AppSpaceName="Intranet", AppSpaceId="AS-INT",
        AppSpaceOwner="Ravi Sharma", AppSpaceTeam="Digital Team", CVE="CVE-2026-3001",
        Severity="Low", Environment="Production", Status="Resolved", **{"SLABreach": False, "Overdue": False},
    ))
    return records


def ask(question, records, all_records=None, raw_filters=None):
    return run_js(
        "answerAssistantQuestion(CONTEXT.question, CONTEXT)",
        context={
            "question": question,
            "records": records,
            "allRecords": all_records if all_records is not None else records,
            "rawFilters": raw_filters or {},
            "filters": [],
            "search": "",
        },
    )


def dashboard_filter(records, filters):
    """Applies filters.js's own recordMatchesFilters() the same way the
    dashboard filter dropdowns do, so the expectation is derived from the
    real dashboard filter logic rather than reimplemented in Python."""
    return run_js(
        "CONTEXT.records.filter(r => recordMatchesFilters(r, CONTEXT.filters))",
        context={"records": records, "filters": filters},
    )


class EntityExtractionTests(unittest.TestCase):
    def test_appspace_owner_summary_matches_dashboard_filter(self):
        records = mixed_records()
        expected = dashboard_filter(records, {"app_space_owner": ["Aisha Khan"]})
        answer = ask("vulnerability summary AppSpace owner Aisha Khan", records)
        self.assertEqual(answer["id"], "summary")
        self.assertIn(f"{len(expected)} findings in scope", answer["summary"])

    def test_owner_and_severity_count_matches_dashboard_filter(self):
        records = mixed_records()
        expected = dashboard_filter(records, {"app_space_owner": ["Aisha Khan"], "severity": ["Critical"]})
        answer = ask("total critical vulnerabilities under AppSpace owner Aisha Khan", records)
        self.assertEqual(answer["id"], "count")
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertEqual(stats["Total"], str(len(expected)))
        affected_appspaces = {record["AppSpaceName"] for record in expected}
        self.assertEqual({item["label"] for item in answer["items"]}, affected_appspaces)

    def test_appspace_name_filter_matches_dashboard_filter(self):
        records = mixed_records()
        expected = dashboard_filter(records, {"app_space_name": ["Payment Gateway"]})
        answer = ask("show vulnerabilities for Payment Gateway", records)
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]} if answer["stats"] else {}
        self.assertIn(f"{len(expected)} findings in scope", answer["summary"])

    def test_team_sla_breach_count_matches_dashboard_filter(self):
        records = mixed_records()
        expected = dashboard_filter(records, {"app_space_team": ["Digital Team"], "sla_breach": ["Yes"]})
        answer = ask("how many SLA breaches for Digital Team", records)
        self.assertEqual(answer["id"], "count")
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertEqual(stats["Total"], str(len(expected)))

    def test_top_applications_owned_by_matches_dashboard_filter(self):
        records = mixed_records()
        expected = dashboard_filter(records, {"app_space_owner": ["Aisha Khan"]})
        answer = ask("top 10 vulnerable applications owned by Aisha Khan", records)
        self.assertEqual(answer["id"], "top-appspaces")
        total_in_items = sum(int(item["value"].split()[0]) for item in answer["items"])
        self.assertEqual(total_in_items, len(expected))

    def test_high_avs_owned_by_matches_owner_filter(self):
        records = mixed_records()
        expected = dashboard_filter(records, {"app_space_owner": ["Aisha Khan"]})
        answer = ask("applications with High AVS owned by Aisha Khan", records)
        self.assertEqual(answer["id"], "high-avs")
        self.assertIn("Applied dashboard filters from your question", answer["notes"][0])
        self.assertIn("AppSpace Owner = Aisha Khan", answer["notes"][0])
        # Every AppSpace referenced in the answer must belong to the owner-filtered set.
        owner_appspaces = {record["AppSpaceName"] for record in expected}
        for item in answer["items"]:
            self.assertIn(item["label"], owner_appspaces)

    def test_severity_and_environment_combine_like_dashboard_filters(self):
        records = mixed_records()
        expected = dashboard_filter(records, {"severity": ["Critical"], "environment": ["Production"]})
        answer = ask("critical vulnerabilities in production environment", records)
        self.assertEqual(answer["id"], "critical")
        self.assertIn(f"{len(expected)} Critical findings", answer["summary"])

    def test_unmapped_question_returns_the_required_fallback_message(self):
        answer = ask("what is the weather today", mixed_records())
        self.assertEqual(answer["id"], "fallback")
        self.assertEqual(
            answer["summary"],
            "Sorry, I couldn't understand that request. Try asking about AppSpace, "
            "Owner, Team, Severity, SLA, AVS or Vulnerability Summary.",
        )

    def test_active_dashboard_filters_still_combine_with_extracted_entities(self):
        records = mixed_records()
        expected = dashboard_filter(records, {"environment": ["Staging"], "app_space_owner": ["Aisha Khan"]})
        answer = ask(
            "vulnerability summary AppSpace owner Aisha Khan",
            records,
            raw_filters={"environment": ["Staging"]},
        )
        self.assertIn(f"{len(expected)} findings in scope", answer["summary"])


if __name__ == "__main__":
    unittest.main()
