"""Helpers for unit-testing the dashboard's browser-side JavaScript.

There is no Node.js runtime in this project, so the JS files are executed with
dukpy (an embedded JavaScript engine) and a minimal DOM stub. The real files
from static/js are loaded unmodified, so the tests exercise shipped code.
"""

import json
from pathlib import Path

import dukpy

STATIC_JS = Path(__file__).resolve().parents[1] / "static" / "js"

ASSISTANT_FILES = ("filters.js", "avs-core.js", "assistant-engine.js", "assistant.js")

# Small DOM stub covering only what the assistant widget touches.
DOM_STUB = """
function createStubElement(id) {
  return {
    id: id,
    hidden: false,
    innerHTML: '',
    value: '',
    scrollTop: 0,
    scrollHeight: 420,
    dataset: {},
    attributes: {},
    focusCount: 0,
    listeners: {},
    setAttribute: function (name, value) { this.attributes[name] = value; },
    getAttribute: function (name) { return this.attributes[name]; },
    focus: function () { this.focusCount += 1; },
    addEventListener: function (type, handler) {
      if (!this.listeners[type]) this.listeners[type] = [];
      this.listeners[type].push(handler);
    },
    dispatch: function (type, event) {
      (this.listeners[type] || []).forEach(function (handler) { handler(event || {}); });
    }
  };
}

var STUB_ELEMENT_IDS = ['assistantToggle', 'assistantPanel', 'assistantClose',
  'assistantSuggestions', 'assistantMessages', 'assistantInput', 'assistantSend'];
var stubElements = {};
STUB_ELEMENT_IDS.forEach(function (id) { stubElements[id] = createStubElement(id); });

var document = {
  listeners: {},
  getElementById: function (id) { return stubElements[id] || null; },
  addEventListener: function (type, handler) {
    if (!this.listeners[type]) this.listeners[type] = [];
    this.listeners[type].push(handler);
  },
  dispatch: function (type, event) {
    (this.listeners[type] || []).forEach(function (handler) { handler(event || {}); });
  }
};

function click(element, event) { element.dispatch('click', event || {}); }
"""


def _source(*files):
    return "\n".join((STATIC_JS / name).read_text(encoding="utf-8") for name in files)


def run_js(script, files=ASSISTANT_FILES, prelude="", context=None):
    """Evaluate `script` after loading `files`; returns the script's value.

    Everything runs inside a single evaluation so that top-level `const`
    declarations stay visible across files, mirroring browser script scope.
    """
    setup = f"var CONTEXT = {json.dumps(context or {})};\n"
    program = "\n".join([prelude, setup, _source(*files), script])
    return dukpy.JSInterpreter().evaljs(program)
