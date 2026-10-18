import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import SearchEcho, { MAX_ECHO_BYTES } from './SearchEcho.jsx';
import HopDetailSheet from './HopDetailSheet.jsx';

let node;
let root;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div');
  document.body.appendChild(node);
  root = createRoot(node);
});
afterEach(() => {
  act(() => root.unmount());
  node.remove();
});

test('renders only the exact reflected echo as live HTML in vulnerable mode', () => {
  const echo = '<strong>owned search echo</strong>';
  act(() => root.render(<SearchEcho echoHtml={echo} fixed={false} />));
  const section = node.querySelector('section[aria-label="Reflected preview"]');
  const result = section.querySelector('[data-testid="hop-echo-html"]');
  expect(section.textContent).toContain('Reflected preview (echo_html)');
  expect(result.innerHTML).toBe(echo);
  expect(result.querySelector('strong').textContent).toBe('owned search echo');
  expect(node.querySelectorAll('[data-testid="hop-echo-html"]')).toHaveLength(1);
});

test('renders the same bytes as inert text in fixed mode', () => {
  const echo = '<img src=x onerror=alert(1)>';
  act(() => root.render(<SearchEcho echoHtml={echo} fixed />));
  const result = node.querySelector('pre[data-testid="hop-echo-html"]');
  expect(result.textContent).toBe(echo);
  expect(result.querySelector('img')).toBeNull();
});

test('does not render missing, non-string, or over-limit echo values', () => {
  for (const echoHtml of ['', null, { echo_html: '<strong>bad</strong>' }, 'é'.repeat(MAX_ECHO_BYTES), '\ud800', 'a\0b']) {
    act(() => root.render(<SearchEcho echoHtml={echoHtml} fixed={false} />));
    expect(node.querySelector('[data-testid="hop-echo-html"]')).toBeNull();
  }
  act(() => root.render(<SearchEcho echoHtml={'a'.repeat(MAX_ECHO_BYTES)} fixed={false} />));
  expect(node.querySelector('[data-testid="hop-echo-html"]')).not.toBeNull();
});

test('saved search hop offers its own assessment action without changing generic preview', () => {
  const onCheck = jest.fn();
  const hop = { tool: 'catalog.search', step: 2, params: { search: 'owned' },
    searchSource: { sessionId: 'a', requestId: 'b', step: 2 },
    result: { echo_html: '<b>owned</b>', content: [{ type: 'text', text: '<i>separate preview</i>' }] } };
  act(() => root.render(<HopDetailSheet hop={hop} onClose={() => {}}
    searchAssessment={{ busy: false, blocked: false, saved: false, onCheck }} />));
  const button = [...node.querySelectorAll('button')].find(item => item.textContent === 'Check search echo');
  expect(button).toBeTruthy();
  act(() => button.click());
  expect(onCheck).toHaveBeenCalledTimes(1);
  expect(node.querySelector('[data-testid="hop-echo-html"] b')).not.toBeNull();
  expect(node.querySelector('.ss-sheet__body i')).not.toBeNull();
  act(() => root.render(<HopDetailSheet hop={hop} onClose={() => {}}
    searchAssessment={{ busy: false, blocked: true, saved: false, onCheck }} />));
  expect([...node.querySelectorAll('button')].find(item => item.textContent === 'Check search echo').disabled).toBe(true);
});
