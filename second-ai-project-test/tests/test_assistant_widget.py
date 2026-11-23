"""Unit tests for the assistant widget UI behavior (static/js/assistant.js).

The widget runs against a minimal DOM stub (see tests/js_harness.DOM_STUB), so
open/close, suggested questions, and message rendering are verified without a
browser.
"""

import unittest

from tests.js_harness import DOM_STUB, run_js

RECORDS = [
    {
        "ServerName": "SRV-1", "AppSpaceName": "Payments", "AppSpaceId": "AS-PAY",
        "AppSpaceTeam": "Payments Team", "QID": "QID-1", "Vulnerability Name": "OpenSSL Vulnerability",
        "Severity": "Critical", "CVE": "CVE-2026-0001", "Vendor": "Acme", "Status": "Open",
        "PCI Required": True, "SLA Due Date": "2026-01-10", "Vulnerability Age": 90,
        "Days Open": 90, "Days Overdue": 60, "SLABreach": True, "Overdue": True,
        "FundamentalClassification": "Other", "Zone": "Internal",
    },
    {
        "ServerName": "SRV-2", "AppSpaceName": "Website", "AppSpaceId": "AS-WEB",
        "AppSpaceTeam": "Web Team", "QID": "QID-2", "Vulnerability Name": "Tomcat Vulnerability",
        "Severity": "High", "CVE": "CVE-2026-0002", "Vendor": "Acme", "Status": "In Progress",
        "PCI Required": False, "SLA Due Date": "2026-03-10", "Vulnerability Age": 20,
        "Days Open": 20, "Days Overdue": 0, "SLABreach": False, "Overdue": False,
        "FundamentalClassification": "Other", "Zone": "Internal",
    },
]

# Boots the widget with the stub DOM and the sample scope from CONTEXT.
WIDGET_SETUP = """
var widget = createAssistantWidget({
  getContext: function () {
    return { records: CONTEXT.records, filters: CONTEXT.filters || [], search: CONTEXT.search || '' };
  }
});
var toggleButton = stubElements.assistantToggle;
var panel = stubElements.assistantPanel;
var closeButton = stubElements.assistantClose;
var suggestions = stubElements.assistantSuggestions;
var messages = stubElements.assistantMessages;
var input = stubElements.assistantInput;
var sendButton = stubElements.assistantSend;
"""


def run_widget(script, records=None, filters=None, search=""):
    return run_js(
        WIDGET_SETUP + script,
        prelude=DOM_STUB,
        context={"records": RECORDS if records is None else records, "filters": filters or [], "search": search},
    )


class OpenCloseTests(unittest.TestCase):
    def test_panel_starts_closed(self):
        state = run_widget("({hidden: panel.hidden, expanded: toggleButton.getAttribute('aria-expanded'), messages: widget.messages.length})")
        self.assertTrue(state["hidden"])
        self.assertEqual(state["expanded"], "false")
        self.assertEqual(state["messages"], 0)

    def test_toggle_button_opens_the_panel_and_greets(self):
        state = run_widget("""
          click(toggleButton);
          ({open: widget.isOpen(), hidden: panel.hidden, expanded: toggleButton.getAttribute('aria-expanded'),
            messages: widget.messages.length, html: messages.innerHTML, focus: input.focusCount})
        """)
        self.assertTrue(state["open"])
        self.assertFalse(state["hidden"])
        self.assertEqual(state["expanded"], "true")
        self.assertEqual(state["messages"], 1)
        self.assertIn("Dashboard assistant", state["html"])
        self.assertEqual(state["focus"], 1)

    def test_toggle_button_closes_an_open_panel(self):
        state = run_widget("""
          click(toggleButton);
          click(toggleButton);
          ({open: widget.isOpen(), hidden: panel.hidden, expanded: toggleButton.getAttribute('aria-expanded'),
            focus: toggleButton.focusCount})
        """)
        self.assertFalse(state["open"])
        self.assertTrue(state["hidden"])
        self.assertEqual(state["expanded"], "false")
        self.assertEqual(state["focus"], 1)

    def test_close_button_closes_the_panel(self):
        state = run_widget("widget.open(); click(closeButton); ({open: widget.isOpen(), hidden: panel.hidden})")
        self.assertFalse(state["open"])
        self.assertTrue(state["hidden"])

    def test_escape_key_closes_an_open_panel_only(self):
        state = run_widget("""
          document.dispatch('keydown', {key: 'Escape'});
          var closedWhileClosed = !widget.isOpen();
          widget.open();
          document.dispatch('keydown', {key: 'Escape'});
          ({closedWhileClosed: closedWhileClosed, open: widget.isOpen()})
        """)
        self.assertTrue(state["closedWhileClosed"])
        self.assertFalse(state["open"])

    def test_reopening_keeps_the_session_history(self):
        state = run_widget("""
          widget.open();
          widget.ask('Summarize vulnerability report');
          widget.close();
          widget.open();
          ({messages: widget.messages.length, html: messages.innerHTML})
        """)
        self.assertEqual(state["messages"], 3)
        self.assertIn("Vulnerability report summary", state["html"])

    def test_history_is_session_only_and_resets_with_a_new_widget(self):
        state = run_widget("""
          widget.open();
          widget.ask('Summarize vulnerability report');
          var before = widget.messages.length;
          var reloaded = createAssistantWidget({getContext: function () { return {records: CONTEXT.records}; }});
          ({before: before, after: reloaded.messages.length})
        """)
        self.assertEqual(state["before"], 3)
        self.assertEqual(state["after"], 0)


class SuggestedQuestionTests(unittest.TestCase):
    def test_all_predefined_questions_are_rendered_as_chips(self):
        state = run_widget("({html: suggestions.innerHTML, count: widget.questions.length})")
        self.assertEqual(state["count"], 7)
        for label in ["Summarize vulnerability report", "Show Critical vulnerabilities",
                      "Top 10 vulnerable AppSpaces", "Applications with High AVS",
                      "SLA breach summary", "Top remediation actions", "AVS score explanation"]:
            self.assertIn(label, state["html"])
        self.assertIn('data-question="summary"', state["html"])

    def test_clicking_a_suggestion_chip_answers_that_question(self):
        state = run_widget("""
          widget.open();
          click(suggestions, {target: {dataset: {question: 'sla-breach'}}});
          ({messages: widget.messages.length, user: widget.messages[1].text, html: messages.innerHTML})
        """)
        self.assertEqual(state["messages"], 3)
        self.assertEqual(state["user"], "SLA breach summary")
        self.assertIn("SLA breach summary", state["html"])

    def test_click_outside_a_chip_is_ignored(self):
        state = run_widget("widget.open(); click(suggestions, {target: {dataset: {}}}); widget.messages.length")
        self.assertEqual(state, 1)


class ChatInputTests(unittest.TestCase):
    def test_send_button_submits_and_clears_the_input(self):
        state = run_widget("""
          widget.open();
          input.value = 'Show Critical vulnerabilities';
          click(sendButton);
          ({messages: widget.messages.length, value: input.value, html: messages.innerHTML})
        """)
        self.assertEqual(state["messages"], 3)
        self.assertEqual(state["value"], "")
        self.assertIn("Critical vulnerabilities", state["html"])

    def test_enter_key_submits_the_question(self):
        state = run_widget("""
          widget.open();
          input.value = 'Top 10 vulnerable AppSpaces';
          input.dispatch('keydown', {key: 'Enter', preventDefault: function () {}});
          ({messages: widget.messages.length, html: messages.innerHTML})
        """)
        self.assertEqual(state["messages"], 3)
        self.assertIn("Top 10 vulnerable AppSpaces", state["html"])

    def test_empty_input_is_ignored(self):
        state = run_widget("widget.open(); input.value = '   '; click(sendButton); widget.messages.length")
        self.assertEqual(state, 1)

    def test_user_input_is_escaped_before_rendering(self):
        state = run_widget("""
          widget.open();
          input.value = '<img src=x onerror=alert(1)>';
          click(sendButton);
          messages.innerHTML
        """)
        self.assertNotIn("<img", state)
        self.assertIn("&lt;img", state)


class FilteredAnswerRenderingTests(unittest.TestCase):
    def test_answers_use_the_records_currently_in_scope(self):
        state = run_widget(
            "widget.open(); ({html: messages.innerHTML, answer: widget.ask('Summarize vulnerability report')})",
            records=[RECORDS[1]],
        )
        self.assertIn("1 findings in scope", state["answer"]["summary"])
        stats = {stat["label"]: stat["value"] for stat in state["answer"]["stats"]}
        self.assertEqual(stats["Critical"], "0")
        self.assertEqual(stats["High"], "1")

    def test_rendered_answer_shows_the_active_filter_scope(self):
        state = run_widget(
            "widget.open(); widget.ask('Summarize vulnerability report'); messages.innerHTML",
            filters=[{"label": "Severity", "values": ["Critical"]}],
            search="srv",
        )
        self.assertIn("Scope - Severity: Critical", state)
        self.assertIn("assistant-scope", state)

    def test_changing_scope_between_questions_changes_the_answer(self):
        state = run_widget("""
          widget.open();
          var first = widget.ask('Summarize vulnerability report');
          CONTEXT.records = [CONTEXT.records[0]];
          var second = widget.ask('Summarize vulnerability report');
          ({first: first.summary, second: second.summary})
        """)
        self.assertIn("2 findings in scope", state["first"])
        self.assertIn("1 findings in scope", state["second"])

    def test_unknown_question_renders_the_suggested_list(self):
        state = run_widget("widget.open(); widget.ask('tell me a joke'); messages.innerHTML")
        self.assertIn("Sorry, I couldn&#39;t understand that request", state)
        self.assertIn("Summarize vulnerability report", state)


if __name__ == "__main__":
    unittest.main()
