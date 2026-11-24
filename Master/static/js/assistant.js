// Floating AI assistant widget: DOM wiring only.
// All answer generation lives in assistant-engine.js; this file renders the
// panel, keeps the session-only chat history, and asks the engine for answers
// using the dashboard records that are currently in scope.

function assistantEscapeHtml(value) {
  return String(value === undefined || value === null ? '' : value)
    .replace(/[&<>'"]/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
}

function renderAssistantAnswer(answer) {
  const stats = (answer.stats || []).length
    ? `<div class="assistant-stats">${answer.stats.map(stat => `<span class="assistant-stat"><span class="assistant-stat-label">${assistantEscapeHtml(stat.label)}</span><strong>${assistantEscapeHtml(stat.value)}</strong></span>`).join('')}</div>`
    : '';
  const items = (answer.items || []).length
    ? `<ul class="assistant-list">${answer.items.map(item => `<li><span class="assistant-item-label">${assistantEscapeHtml(item.label)}</span>${item.value ? `<span class="assistant-item-value">${assistantEscapeHtml(item.value)}</span>` : ''}${item.detail ? `<span class="assistant-item-detail">${assistantEscapeHtml(item.detail)}</span>` : ''}</li>`).join('')}</ul>`
    : '';
  const notes = (answer.notes || []).map(note => `<p class="assistant-note">${assistantEscapeHtml(note)}</p>`).join('');
  const scope = answer.scope ? `<p class="assistant-scope">${assistantEscapeHtml(answer.scope)}</p>` : '';
  return `<p class="assistant-answer-title">${assistantEscapeHtml(answer.title)}</p><p>${assistantEscapeHtml(answer.summary)}</p>${stats}${items}${notes}${scope}`;
}

function createAssistantWidget(options) {
  const settings = options || {};
  const doc = settings.doc || document;
  const getContext = settings.getContext || (() => ({ records: [] }));
  const answerFor = settings.answer || answerAssistantQuestion;
  const questions = settings.questions || ASSISTANT_QUESTIONS;

  const element = id => doc.getElementById(id);
  const toggleButton = element('assistantToggle');
  const panel = element('assistantPanel');
  const closeButton = element('assistantClose');
  const suggestionsHost = element('assistantSuggestions');
  const messagesHost = element('assistantMessages');
  const input = element('assistantInput');
  const sendButton = element('assistantSend');
  if (!toggleButton || !panel || !messagesHost) return null;

  // Session-only history: nothing is persisted, so a reload starts fresh.
  const messages = [];

  function renderMessages() {
    messagesHost.innerHTML = messages.map(message => (
      message.role === 'user'
        ? `<div class="assistant-message assistant-message-user"><div class="assistant-bubble">${assistantEscapeHtml(message.text)}</div></div>`
        : `<div class="assistant-message assistant-message-bot"><div class="assistant-bubble">${message.html}</div></div>`
    )).join('');
    messagesHost.scrollTop = messagesHost.scrollHeight;
  }

  function pushUserMessage(text) {
    messages.push({ role: 'user', text });
  }

  function pushBotMessage(html) {
    messages.push({ role: 'assistant', html });
  }

  function greet() {
    pushBotMessage('<p class="assistant-answer-title">Dashboard assistant</p><p>Ask about the findings currently in scope, or pick a suggested question below. Answers always respect the active dashboard filters.</p>');
    renderMessages();
  }

  function ask(question) {
    const text = String(question || '').trim();
    if (!text) return null;
    pushUserMessage(text);
    const answer = answerFor(text, getContext());
    pushBotMessage(renderAssistantAnswer(answer));
    renderMessages();
    return answer;
  }

  function isOpen() {
    return !panel.hidden;
  }

  function open() {
    panel.hidden = false;
    toggleButton.setAttribute('aria-expanded', 'true');
    if (!messages.length) greet();
    if (input && input.focus) input.focus();
  }

  function close() {
    panel.hidden = true;
    toggleButton.setAttribute('aria-expanded', 'false');
    if (toggleButton.focus) toggleButton.focus();
  }

  function toggle() {
    if (isOpen()) close();
    else open();
  }

  function submitInput() {
    if (!input) return null;
    const answer = ask(input.value);
    if (answer) input.value = '';
    return answer;
  }

  if (suggestionsHost) {
    suggestionsHost.innerHTML = questions
      .map(question => `<button type="button" class="assistant-chip" data-question="${assistantEscapeHtml(question.id)}">${assistantEscapeHtml(question.label)}</button>`)
      .join('');
    suggestionsHost.addEventListener('click', event => {
      const questionId = event.target && event.target.dataset ? event.target.dataset.question : '';
      if (!questionId) return;
      const question = questions.find(item => item.id === questionId);
      ask(question ? question.label : questionId);
    });
  }

  toggleButton.addEventListener('click', toggle);
  if (closeButton) closeButton.addEventListener('click', close);
  if (sendButton) sendButton.addEventListener('click', submitInput);
  if (input) {
    input.addEventListener('keydown', event => {
      if (event.key === 'Enter' && !event.shiftKey) {
        if (event.preventDefault) event.preventDefault();
        submitInput();
      }
    });
  }
  doc.addEventListener('keydown', event => {
    if (event.key === 'Escape' && isOpen()) close();
  });

  panel.hidden = true;
  toggleButton.setAttribute('aria-expanded', 'false');

  return { open, close, toggle, isOpen, ask, submitInput, messages, questions };
}

function initAssistant(options) {
  return createAssistantWidget(options);
}
