"""Unit tests for the rule-based assistant engine (static/js/assistant-engine.js)."""

import unittest

from tests.js_harness import run_js

EXPECTED_QUESTIONS = [
    "Summarize vulnerability report",
    "Show Critical vulnerabilities",
    "Top 10 vulnerable AppSpaces",
    "Applications with High AVS",
    "SLA breach summary",
    "Top remediation actions",
    "AVS score explanation",
]


def make_record(**overrides):
    record = {
        "ServerName": "SRV-1",
        "Operating System": "Windows Server 2022",
        "Environment": "Production",
        "AppSpaceName": "Customer Portal",
        "AppSpaceId": "AS-1",
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


def sample_records():
    """Two AppSpaces with a deliberately different severity/SLA profile."""
    records = []
    for index in range(4):
        records.append(make_record(
            ServerName=f"SRV-P{index}",
            AppSpaceName="Payments",
            AppSpaceId="AS-PAY",
            AppSpaceTeam="Payments Team",
            CVE=f"CVE-2026-10{index}",
            Severity="Critical",
            Status="Open",
            **{"SLABreach": True, "Overdue": True, "PCI Required": True},
        ))
    for index in range(3):
        records.append(make_record(
            ServerName=f"SRV-W{index}",
            AppSpaceName="Website",
            AppSpaceId="AS-WEB",
            AppSpaceTeam="Web Team",
            CVE=f"CVE-2026-20{index}",
            Severity="High",
            Status="In Progress",
            **{"Vulnerability Name": "Apache Tomcat Vulnerability", "QID": "QID-2", "SLABreach": False, "Overdue": False},
        ))
    records.append(make_record(
        ServerName="SRV-W9",
        AppSpaceName="Website",
        AppSpaceId="AS-WEB",
        AppSpaceTeam="Web Team",
        CVE="CVE-2026-2099",
        Severity="Low",
        Status="Resolved",
        **{"SLABreach": False, "Overdue": False},
    ))
    return records


def high_avs_records():
    """External + Essential app with enough unique critical CVEs to score High."""
    records = []
    for index in range(120):
        records.append(make_record(
            ServerName=f"SRV-X{index}",
            AppSpaceName="Trading Gateway",
            AppSpaceId="AS-TRD",
            AppSpaceTeam="Markets",
            CVE=f"CVE-2026-9{index:03d}",
            **{"Zone": "External", "FundamentalClassification": "Essential"},
        ))
    records.append(make_record(
        ServerName="SRV-Y1",
        AppSpaceName="Intranet",
        AppSpaceId="AS-INT",
        AppSpaceTeam="Corporate IT",
        CVE="CVE-2026-8000",
        **{"Zone": "Internal & Protected", "FundamentalClassification": "Other"},
    ))
    return records


def most_risky_records():
    base = make_record(
        **{
            "Severity Level": "5",
            "RemitTeam": "Change/ITO",
            "FundamentalClassification": "Essential",
            "PatchAvailable": "TRUE",
            "SLABreach": "TRUE",
            "Zone": "External",
            "Exploit": "TRUE",
            "VULN COUNT": "SRV-1Customer PortalCVE-1",
            "Vulnerability Age": 120,
        }
    )
    duplicate = dict(base, ServerName="SRV-2")
    excluded = dict(base, **{"VULN COUNT": "excluded", "PatchAvailable": "FALSE"})
    return [base, duplicate, excluded]


def ask(question, records, filters=None, search=""):
    return run_js(
        "answerAssistantQuestion(CONTEXT.question, CONTEXT)",
        context={"records": records, "filters": filters or [], "search": search, "question": question},
    )


class PredefinedQuestionTests(unittest.TestCase):
    def test_exposes_the_seven_predefined_questions(self):
        labels = run_js("ASSISTANT_QUESTIONS.map(q => q.label)")
        self.assertEqual(labels, EXPECTED_QUESTIONS)

    def test_question_ids_are_unique(self):
        ids = run_js("ASSISTANT_QUESTIONS.map(q => q.id)")
        self.assertEqual(len(ids), len(set(ids)))

    def test_each_predefined_label_routes_to_its_own_handler(self):
        matched = run_js("ASSISTANT_QUESTIONS.map(q => [q.id, assistantMatchQuestion(q.label)])")
        for question_id, resolved in matched:
            self.assertEqual(resolved, question_id, f"{question_id} routed to {resolved}")

    def test_free_text_variants_route_to_the_right_handler(self):
        cases = {
            "give me a summary of the report": "summary",
            "show critical vulnerabilities please": "critical",
            "which appspaces are most vulnerable?": "top-appspaces",
            "what is breaching sla": "sla-breach",
            "what should we patch first": "remediation",
            "explain the avs score": "avs-explained",
        }
        for text, expected in cases.items():
            self.assertEqual(run_js(f"assistantMatchQuestion({text!r})"), expected, text)

    def test_unrelated_question_returns_the_fallback_answer(self):
        answer = ask("what is the weather today", sample_records())
        self.assertEqual(answer["id"], "fallback")
        self.assertEqual([item["label"] for item in answer["items"]], EXPECTED_QUESTIONS)

    def test_every_predefined_question_produces_an_answer(self):
        for label in EXPECTED_QUESTIONS:
            answer = ask(label, sample_records())
            self.assertNotEqual(answer["id"], "fallback", label)
            self.assertTrue(answer["title"])
            self.assertTrue(answer["summary"])


class FilteredDataAnswerTests(unittest.TestCase):
    def test_most_risky_answer_deduplicates_by_vuln_count(self):
        answer = ask("count most risky vulnerabilities", most_risky_records())
        self.assertEqual(answer["id"], "most-risky")
        self.assertIn("1 unique Most Risky Vulnerabilities", answer["summary"])
        self.assertEqual(answer["stats"][0]["value"], "1")

    def test_most_risky_handles_patch_available_as_numeric_one(self):
        records = most_risky_records()
        records[0]["PatchAvailable"] = "1"
        answer = ask("show most risky vulnerabilities", records)
        self.assertEqual(answer["id"], "most-risky")
        self.assertEqual(answer["stats"][0]["value"], "1")

    def test_summary_counts_come_from_the_supplied_records(self):
        answer = ask("Summarize vulnerability report", sample_records())
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertIn("8 findings in scope", answer["summary"])
        self.assertEqual(stats["Critical"], "4")
        self.assertEqual(stats["High"], "3")
        self.assertEqual(stats["Low"], "1")
        self.assertEqual(stats["SLA breached"], "4 (50%)")
        self.assertEqual(stats["PCI required"], "4")

    def test_summary_reflects_a_filtered_subset(self):
        filtered = [r for r in sample_records() if r["AppSpaceName"] == "Website"]
        answer = ask("Summarize vulnerability report", filtered)
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertIn("4 findings in scope", answer["summary"])
        self.assertEqual(stats["Critical"], "0")
        self.assertEqual(stats["High"], "3")
        self.assertEqual(stats["SLA breached"], "0 (0%)")

    def test_critical_answer_lists_breached_criticals_only(self):
        answer = ask("Show Critical vulnerabilities", sample_records())
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertIn("4 Critical findings", answer["summary"])
        self.assertEqual(stats["SLA breached"], "4")
        self.assertEqual(len(answer["items"]), 4)
        self.assertTrue(all("SRV-P" in item["label"] for item in answer["items"]))

    def test_critical_answer_when_filters_exclude_criticals(self):
        filtered = [r for r in sample_records() if r["Severity"] != "Critical"]
        answer = ask("Show Critical vulnerabilities", filtered)
        self.assertEqual(answer["items"], [])
        self.assertIn("No Critical findings", answer["summary"])

    def test_top_appspaces_ranks_by_count_and_caps_at_ten(self):
        records = sample_records()
        for index in range(12):
            records.append(make_record(
                ServerName=f"SRV-Z{index}",
                AppSpaceName=f"App {index}",
                AppSpaceId=f"AS-{index}",
                Severity="Medium",
            ))
        answer = ask("Top 10 vulnerable AppSpaces", records)
        self.assertEqual(len(answer["items"]), 10)
        self.assertTrue(answer["items"][0]["label"].endswith("Payments"))
        self.assertEqual(answer["items"][0]["value"], "4 findings")
        self.assertIn("4 Critical", answer["items"][0]["detail"])

    def test_high_avs_uses_the_shared_avs_calculation(self):
        answer = ask("Applications with High AVS", high_avs_records())
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertEqual(stats["High"], "1")
        self.assertEqual(answer["items"][0]["label"], "Trading Gateway")
        self.assertEqual(answer["items"][0]["value"], "AVS 1200.0")

    def test_high_avs_falls_back_when_filtered_scope_has_no_high_apps(self):
        filtered = [r for r in high_avs_records() if r["AppSpaceName"] == "Intranet"]
        answer = ask("Applications with High AVS", filtered)
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertEqual(stats["High"], "0")
        self.assertIn("No application scores High", answer["summary"])
        self.assertEqual(answer["items"][0]["label"], "Intranet")

    def test_sla_breach_summary_uses_filtered_records(self):
        answer = ask("SLA breach summary", sample_records())
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertIn("4 of 8 findings (50%)", answer["summary"])
        self.assertEqual(stats["Critical breached"], "4")
        self.assertEqual(stats["High breached"], "0")
        self.assertEqual(stats["Average days overdue"], "60")
        self.assertEqual(answer["items"][0]["label"], "Payments")

    def test_remediation_ranks_unresolved_work(self):
        answer = ask("Top remediation actions", sample_records())
        stats = {stat["label"]: stat["value"] for stat in answer["stats"]}
        self.assertIn("7 unresolved findings", answer["summary"])
        self.assertEqual(stats["Resolved"], "1")
        self.assertTrue(answer["items"][0]["label"].endswith("OpenSSL Vulnerability"))
        self.assertIn("4 Critical", answer["items"][0]["detail"])

    def test_avs_explanation_is_static_but_cites_current_scope(self):
        answer = ask("AVS score explanation", high_avs_records())
        self.assertIn("Zone rating", answer["summary"])
        self.assertIn("Trading Gateway", answer["notes"][0])

    def test_avs_explanation_works_without_any_records(self):
        answer = ask("AVS score explanation", [])
        self.assertEqual(answer["id"], "avs-explained")
        self.assertIn("every AVS score is 0", answer["notes"][0])

    def test_empty_scope_returns_a_guidance_answer(self):
        answer = ask("Summarize vulnerability report", [])
        self.assertEqual(answer["id"], "summary")
        self.assertEqual(answer["stats"], [])
        self.assertIn("No findings match the current filters", answer["summary"])

    def test_active_filters_are_reported_in_the_answer_scope(self):
        filters = [
            {"label": "Severity", "values": ["Critical"]},
            {"label": "Environment", "values": ["Production", "UAT"]},
        ]
        answer = ask("Summarize vulnerability report", sample_records(), filters=filters, search="srv-p")
        self.assertIn("Severity: Critical", answer["scope"])
        self.assertIn("Environment: Production, UAT", answer["scope"])
        self.assertIn('Search: "srv-p"', answer["scope"])

    def test_scope_states_when_no_filters_are_active(self):
        answer = ask("Summarize vulnerability report", sample_records())
        self.assertEqual(answer["scope"], "Scope - all findings (no filters applied)")


if __name__ == "__main__":
    unittest.main()
