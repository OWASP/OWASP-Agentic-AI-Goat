import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import ControlledSsrfLab from './ControlledSsrfLab.jsx';

globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const reply = (body, ok = true) => Promise.resolve({ ok, json: async () => body });
let root, container;
beforeEach(() => {
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
  let id = 0;
  Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {
    randomUUID: jest.fn(() => `10000000-0000-4000-8000-${String(++id).padStart(12, '0')}`),
  } });
  global.fetch = jest.fn();
});
afterEach(async () => { if (root) await act(async () => root.unmount()); container.remove(); });
const render = (props = {}) => act(async () => root.render(<ControlledSsrfLab enabled personaKey="1:customer" {...props} />));
const button = label => [...container.querySelectorAll('button')].find(element => element.textContent === label);

test('legacy and default-off instances do not expose new controls', async () => {
  await render({ enabled: false }); expect(fetch).not.toHaveBeenCalled(); expect(container.textContent).toBe('');
  fetch.mockImplementation(() => reply({ ready: false }));
  await render(); expect(fetch).toHaveBeenCalledTimes(1); expect(container.textContent).toBe('');
});

test('public/private requests use distinct identities and render escaped actual answers without claiming credit', async () => {
  fetch.mockImplementation((url, options) => url.endsWith('/readiness') ? reply({ ready: true })
    : reply({ resourceKind: JSON.parse(options.body).resource, response: '<img src=x onerror=alert(1)>', stopReason: 'end_turn' }));
  await render();
  await act(async () => button('Fetch public policy').click());
  await act(async () => button('Try internal policy').click());
  const bodies = fetch.mock.calls.filter(([url]) => url.endsWith('/run')).map(([, options]) => JSON.parse(options.body));
  expect(bodies.map(body => body.resource)).toEqual(['public-policy', 'private-policy']);
  expect(bodies[0].request_id).not.toBe(bodies[1].request_id);
  expect(container.querySelector('img')).toBeNull();
  expect(container.textContent).toContain('<img src=x onerror=alert(1)>');
  expect(container.textContent).toContain('a displayed answer alone is not a pass');
});

test('network failure retries the same request; a completed request permits an explicit fresh attempt', async () => {
  let attempt = 0;
  fetch.mockImplementation(url => {
    if (url.endsWith('/readiness')) return reply({ ready: true });
    if (++attempt === 1) return Promise.reject(new Error('Connection interrupted'));
    return reply({ resourceKind: 'private-policy', response: 'Recorded protected training observation', replayed: true, stopReason: 'end_turn' });
  });
  await render();
  await act(async () => button('Try internal policy').click());
  expect(container.querySelector('[role="alert"]').textContent).toBe('Connection interrupted');
  await act(async () => button('Try internal policy').click());
  await act(async () => button('Try internal policy').click());
  const ids = fetch.mock.calls.filter(([url]) => url.endsWith('/run')).map(([, options]) => JSON.parse(options.body).request_id);
  expect(ids[0]).toBe(ids[1]); expect(ids[2]).not.toBe(ids[1]);
  expect(container.textContent).toContain('without another tool call');
});

test('persona change aborts and discards an earlier answer', async () => {
  let complete, signal;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/readiness')) return reply({ ready: true });
    signal = options.signal; return new Promise(resolve => { complete = resolve; });
  });
  await render(); await act(async () => button('Try internal policy').click());
  await render({ personaKey: '2:customer' }); expect(signal.aborted).toBe(true);
  await act(async () => complete({ ok: true, json: async () => ({ response: 'Old persona record', resourceKind: 'private-policy' }) }));
  expect(container.textContent).not.toContain('Old persona record');
  expect(button('Try internal policy').disabled).toBe(false);
});

test('StrictMode preserves readiness and final unmount aborts live work', async () => {
  let signal;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/readiness')) return reply({ ready: true });
    signal = options.signal; return new Promise(() => {});
  });
  await act(async () => root.render(<React.StrictMode><ControlledSsrfLab enabled personaKey="1:customer" /></React.StrictMode>));
  expect(button('Try internal policy').disabled).toBe(false);
  await act(async () => button('Try internal policy').click()); expect(signal.aborted).toBe(false);
  await act(async () => root.unmount()); root = null; expect(signal.aborted).toBe(true);
});

test('blank successful response remains an error and retains the retry identity', async () => {
  fetch.mockImplementation(url => url.endsWith('/readiness') ? reply({ ready: true }) : reply({ response: null, stopReason: 'end_turn' }));
  await render(); await act(async () => button('Try internal policy').click());
  expect(container.querySelector('[role="alert"]').textContent).toContain('No agent answer');
  await act(async () => button('Try internal policy').click());
  const ids = fetch.mock.calls.filter(([url]) => url.endsWith('/run')).map(([, options]) => JSON.parse(options.body).request_id);
  expect(ids[0]).toBe(ids[1]);
});

test('nonterminal response remains an error and retains the retry identity', async () => {
  let attempt = 0;
  fetch.mockImplementation(url => url.endsWith('/readiness') ? reply({ ready: true })
    : (++attempt === 1
      ? reply({ resourceKind: 'private-policy', response: 'Partial answer', stopReason: 'budget_exhausted' })
      : reply({ resourceKind: 'private-policy', response: 'Verified answer', stopReason: 'end_turn' })));
  await render(); await act(async () => button('Try internal policy').click());
  expect(container.querySelector('[role="alert"]').textContent).toContain('did not finish its turn');
  expect(container.textContent).not.toContain('Partial answer');
  await act(async () => button('Try internal policy').click());
  const ids = fetch.mock.calls.filter(([url]) => url.endsWith('/run')).map(([, options]) => JSON.parse(options.body).request_id);
  expect(ids[0]).toBe(ids[1]);
  expect(container.textContent).toContain('Verified answer');
});

test('availability refresh clears a prior observation before reporting an error', async () => {
  let readiness = true;
  fetch.mockImplementation(url => {
    if (url.endsWith('/readiness')) {
      if (readiness) return reply({ ready: true });
      return Promise.reject(new Error('Availability interrupted'));
    }
    return reply({ resourceKind: 'public-policy', response: 'Prior observation', stopReason: 'end_turn' });
  });
  await render(); await act(async () => button('Fetch public policy').click());
  expect(container.textContent).toContain('Prior observation');
  readiness = false;
  await act(async () => button('Refresh availability').click());
  expect(container.querySelector('[role="alert"]').textContent).toBe('Availability interrupted');
  expect(container.textContent).not.toContain('Prior observation');
});

// V27 controlled UI projections only; these tests cannot establish model or browser credit.
const PolicyFinalHtmlLab = require('./PolicyFinalHtmlLab.jsx').default;
const { createPolicyFinalHtmlReferenceStore, POLICY_FINAL_HTML_KEY } = require('../utils/policyFinalHtmlReference.mjs');
const policySession = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const policyMode = effectiveMode => ({ version: 1, featureId: 'controlled_ssrf',
  policyVersion: 'owned-public-destination-v1', effectiveMode,
  scope: { kind: 'launch_feature', id: 'controlled_ssrf' } });
function policyStore(initial = null, flush = async () => {}) {
  const values = new Map(initial ? [[POLICY_FINAL_HTML_KEY, JSON.stringify(initial)]] : []);
  return createPolicyFinalHtmlReferenceStore({ storage: { getItem: k => values.get(k) ?? null,
    setItem: (k,v) => values.set(k,v), removeItem: k => values.delete(k) }, flush });
}
const renderPolicy = (store, extra = {}) => act(async () => root.render(<PolicyFinalHtmlLab enabled
  shopUserId={1} personaKey="1:customer" referenceStore={store} {...extra} />));
const typePolicy = async html => act(async () => {
  const textarea = container.querySelector('textarea[aria-label="Policy HTML"]');
  Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, html);
  textarea.dispatchEvent(new Event('input', { bubbles: true }));
});
const policyDto = (requestId, mode = 'vuln', replayed = false) => ({ sessionId: policySession,
  requestId, response: '<b>Original model policy answer</b>', stopReason: 'end_turn', replayed,
  modeCapability: policyMode(mode) });

test.each(['vuln','fixed'])('V27 %s renders only the original final response with its trusted mode', async mode => {
  const store = policyStore();
  fetch.mockImplementation((url, options) => url.endsWith('/readiness') ? reply({ ready: true })
    : reply(policyDto(JSON.parse(options.body).request_id, mode)));
  await renderPolicy(store); await typePolicy('<b>Source policy</b>');
  await act(async () => button('Fetch and explain policy').click());
  const result = container.querySelector('[data-testid="agent-turn-reply"]');
  expect(result.textContent).toBe(mode === 'vuln' ? 'Original model policy answer' : '<b>Original model policy answer</b>');
  expect(!!result.querySelector('b')).toBe(mode === 'vuln');
  expect(result.textContent).not.toContain('Source policy');
  expect(store.read(1).sessionId).toBe(policySession);
});

test('V27 lost run acknowledgement preserves intent and recovers by GET without a second POST', async () => {
  const store = policyStore(); let requestId;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/readiness')) return reply({ ready: true });
    if (options.method === 'POST') { requestId = JSON.parse(options.body).request_id; return Promise.reject(Error('Lost acknowledgement')); }
    return reply(policyDto(requestId, 'vuln', true));
  });
  await renderPolicy(store); await typePolicy('<b>Source</b>');
  await act(async () => button('Fetch and explain policy').click());
  expect(store.read(1).requestId).toBe(requestId); expect(store.read(1).sessionId).toBeNull();
  expect(button('Fetch and explain policy')).toBeUndefined();
  await act(async () => button('Check saved policy answer').click());
  expect(store.read(1).sessionId).toBe(policySession);
  expect(fetch.mock.calls.filter(([,o]) => o.method === 'POST')).toHaveLength(1);
});

test('V27 reload recovers original and pending assessment with GET only and latches unknown outcomes', async () => {
  const reference = { version: 1, shopUserId: 1, requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    sessionId: policySession, assessmentStarted: true, startedAt: 100 };
  const store = policyStore(reference);
  fetch.mockImplementation(url => url.endsWith('/readiness') ? reply({ ready: true })
    : url.includes('/assessment/') ? reply({ completed: false, status: 'unconfirmed', modelEvaluated: false })
      : reply(policyDto(reference.requestId, 'vuln', true)));
  await renderPolicy(store);
  expect(fetch.mock.calls.every(([,o]) => !o.method || o.method === 'GET')).toBe(true);
  expect(button('New policy request').disabled).toBe(true);
  expect(button('Check policy output')).toBeUndefined();
  expect(container.textContent).toContain('unconfirmed');
  await act(async () => button('Check saved policy answer').click());
  expect(store.read(1)).toEqual(reference);
});

test('V27 storage acknowledgement failure sends no run and preserves the saved intent', async () => {
  const store = policyStore(null, async () => { throw Error('State not acknowledged'); });
  fetch.mockImplementation(() => reply({ ready: true }));
  await renderPolicy(store); await typePolicy('<b>Source</b>');
  await act(async () => button('Fetch and explain policy').click());
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(store.read(1).sessionId).toBeNull();
  expect(container.textContent).toContain('State not acknowledged');
  expect(button('Fetch and explain policy')).toBeUndefined();
});

test('V27 saves assessment intent before POST and recovers a lost response without repeating grading', async () => {
  const store = policyStore(); let requestId;
  fetch.mockImplementation((url, options) => {
    if (url.endsWith('/readiness')) return reply({ ready: true });
    if (url.endsWith('/assess')) { expect(store.read(1).assessmentStarted).toBe(true); return Promise.reject(Error('Assessment acknowledgement lost')); }
    if (url.includes('/assessment/')) return reply({ completed: false, status: 'ineligible', modelEvaluated: false });
    if (options.method === 'POST') { requestId = JSON.parse(options.body).request_id; return reply(policyDto(requestId)); }
    return reply(policyDto(requestId, 'vuln', true));
  });
  await renderPolicy(store); await typePolicy('<b>Source</b>');
  await act(async () => button('Fetch and explain policy').click());
  await act(async () => button('Check policy output').click());
  expect(button('New policy request').disabled).toBe(true);
  await act(async () => button('Check saved policy answer').click());
  expect(button('New policy request').disabled).toBe(false);
  expect(fetch.mock.calls.filter(([url]) => url.endsWith('/assess'))).toHaveLength(1);
  await act(async () => button('New policy request').click()); expect(store.read(1)).toBeNull();
});
