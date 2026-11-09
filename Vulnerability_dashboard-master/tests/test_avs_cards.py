"""Tests for the clickable AVS KPI cards -> AVS List table filter wiring.

These exercise the real static/js/table-controller.js and static/js/avs.js
files (unmodified) through the dukpy harness, proving the cards reuse the
shared createDataTable#setFilter mechanism instead of a separate filter
implementation.
"""

import unittest

from tests.js_harness import run_js

AVS_FILES = ("table-controller.js", "avs-core.js", "avs.js")

# Minimal DOM stub covering only what table-controller.js and avs.js touch
# when the AVS KPI cards are rendered/clicked and the AVS List table updates.
AVS_DOM_STUB = """
function createStubElement(id) {
  var classes = [];
  return {
    id: id,
    hidden: false,
    innerHTML: '',
    value: '',
    files: [],
    disabled: false,
    dataset: {},
    _attributes: {},
    classList: {
      add: function (c) { if (classes.indexOf(c) === -1) classes.push(c); },
      remove: function (c) { var i = classes.indexOf(c); if (i >= 0) classes.splice(i, 1); },
      toggle: function (c, force) {
        var has = classes.indexOf(c) !== -1;
        var want = force === undefined ? !has : force;
        if (want && !has) classes.push(c);
        if (!want && has) classes.splice(classes.indexOf(c), 1);
        return want;
      },
      contains: function (c) { return classes.indexOf(c) !== -1; },
      list: classes
    },
    setAttribute: function (name, value) { this._attributes[name] = value; },
    getAttribute: function (name) { return this._attributes[name]; },
    addEventListener: function () {},
    querySelectorAll: function () { return []; }
  };
}

var avsKpiCards = ['all', 'Low', 'Medium', 'High'].map(function (level) {
  var el = createStubElement('card-' + level);
  el.dataset.avsLevel = level;
  return el;
});

var stubElements = {};
['avsTable', 'avsSearch', 'avsPageSize', 'avsPreviousPage', 'avsNextPage',
 'avsPageInfo', 'avsCount', 'importAvsList', 'avsListFileInput', 'avsImportMessage',
 'avsKpis'].forEach(function (id) { stubElements[id] = createStubElement(id); });
stubElements.avsPageSize.value = '15';

var document = {
  getElementById: function (id) { return stubElements[id] || null; },
  querySelectorAll: function () { return avsKpiCards; }
};

function esc(value) { return String(value); }
function badge(value) { return String(value); }
"""


def card(level):
    return {
        'name': f'App-{level}', 'team': 'Team', 'fundamentalClassification': 'API',
        'zone': 'DMZ', 'level': level, 'score': 10, 'uniqueCount': 2,
    }


SAMPLE_APPS = [card('Low'), card('Low'), card('Medium'), card('High')]


class AvsCardFilterTests(unittest.TestCase):
    def _run(self, script):
        return run_js(script, files=AVS_FILES, prelude=AVS_DOM_STUB,
                       context={'apps': SAMPLE_APPS})

    def test_total_apps_shows_every_row(self):
        result = self._run(
            "avsTable.update(CONTEXT.apps); document.getElementById('avsTable').innerHTML;"
        )
        for level in ('Low', 'Medium', 'High'):
            self.assertIn(f'App-{level}', result)

    def test_avs_update_orders_scored_apps_by_descending_score(self):
        result = self._run(
            "stubElements.avsWeeklyUpdate = createStubElement('avsWeeklyUpdate');"
            "stubElements.avsWeeklyUpdateTable = createStubElement('avsWeeklyUpdateTable');"
            "stubElements.avsWeeklyUpdateNotes = createStubElement('avsWeeklyUpdateNotes');"
            "data = { avs_update: { rows: ["
            "{ app_name: 'Lower score', avs: 501, status: 'New' },"
            "{ app_name: 'Highest score', avs: 2910, status: 'High' },"
            "{ app_name: 'Treated app', avs: 100, status: 'Improved/Treated' }"
            "] } };"
            "renderAvsWeeklyUpdate();"
            "document.getElementById('avsWeeklyUpdateTable').innerHTML + document.getElementById('avsWeeklyUpdateNotes').innerHTML;"
        )
        self.assertLess(result.index('Highest score'), result.index('Lower score'))
        self.assertLess(result.index('Lower score'), result.index('Improved/Treated Apps'))
        self.assertIn('class="avs-update-row-new avs-update-row-med"', result)
        self.assertIn('<tr class="avs-update-row-treated"><td colspan="2">Treated app</td></tr>', result)
        self.assertIn('Treated app moved from Low to Treated', result)
        self.assertIn('Lower score moved from Low to New', result)

    def test_high_card_filters_to_high_rows_only(self):
        result = self._run(
            "avsTable.update(CONTEXT.apps); avsSetActiveLevel('High');"
            " document.getElementById('avsTable').innerHTML;"
        )
        self.assertIn('App-High', result)
        self.assertNotIn('App-Low', result)
        self.assertNotIn('App-Medium', result)

    def test_low_card_filters_to_low_rows_only(self):
        result = self._run(
            "avsTable.update(CONTEXT.apps); avsSetActiveLevel('Low');"
            " document.getElementById('avsTable').innerHTML;"
        )
        self.assertEqual(result.count('App-Low'), 2)
        self.assertNotIn('App-Medium', result)
        self.assertNotIn('App-High', result)

    def test_count_reflects_active_filter(self):
        result = self._run(
            "avsTable.update(CONTEXT.apps); avsSetActiveLevel('Medium');"
            " document.getElementById('avsCount').textContent;"
        )
        self.assertEqual(result, '1 matching')

    def test_switching_back_to_all_restores_every_row(self):
        result = self._run(
            "avsTable.update(CONTEXT.apps); avsSetActiveLevel('High');"
            " avsSetActiveLevel('all');"
            " document.getElementById('avsTable').innerHTML;"
        )
        for level in ('Low', 'Medium', 'High'):
            self.assertIn(f'App-{level}', result)

    def test_active_card_highlighting_toggles_exclusively(self):
        result = self._run(
            "avsTable.update(CONTEXT.apps); avsSetActiveLevel('High');"
            " JSON.stringify(avsKpiCards.map(function (c) {"
            "   return { level: c.dataset.avsLevel, active: c.classList.contains('kpi-active') };"
            " }));"
        )
        import json
        states = json.loads(result)
        active_levels = {entry['level'] for entry in states if entry['active']}
        self.assertEqual(active_levels, {'High'})

    def test_setfilter_is_generic_table_controller_feature_not_avs_specific(self):
        # Prove the mechanism AVS cards rely on (createDataTable#setFilter) is
        # a general table-controller capability, reusable by any table.
        result = run_js(
            "var t = createDataTable({ tbodyId: 'avsTable', colSpan: 1,"
            " renderRow: function (r) { return '<tr><td>' + r.name + '</td></tr>'; },"
            " matches: function (row, q) { return row.name.toLowerCase().indexOf(q) !== -1; } });"
            " t.update([{ name: 'a' }, { name: 'b' }, { name: 'c' }]);"
            " t.setFilter(function (row) { return row.name !== 'b'; });"
            " document.getElementById('avsTable').innerHTML;",
            files=("table-controller.js",), prelude=AVS_DOM_STUB,
        )
        self.assertIn('a', result)
        self.assertIn('c', result)
        self.assertNotIn('b', result)


if __name__ == '__main__':
    unittest.main()
