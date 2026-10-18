import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { AdminAuditSearch, AdminSystemConfigRead, AdminUserLookup, decodeUserLookupAssessment } from './AdminSavedReads.jsx';

let root, node;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });

test('SQL result shows bounded rows and escapes raw teaching data', async () => {
  const events = Array.from({ length: 21 }, (_, index) => ({ id: index,
    params_json: '<img src=x onerror=alert(1)>' }));
  await act(async () => root.render(<AdminAuditSearch read={{ ok: true, count: 21,
    events, sql: 'SELECT <data>', error: null }} />));
  expect(node.querySelectorAll('[data-testid="saved-audit-sql-row"]')).toHaveLength(20);
  expect(node.textContent).toContain('Showing 20 of 21 saved rows');
  expect(node.querySelector('img')).toBeNull();
  await act(async () => node.querySelector('button').click());
  expect(node.querySelectorAll('[data-testid="saved-audit-sql-row"]')).toHaveLength(21);
  expect(node.textContent).toContain('Showing 21 of 21 saved rows');
});

test('System config content remains plain text in the saved read card', async () => {
  await act(async () => root.render(<AdminSystemConfigRead read={{ kind: 'content',
    size: 31, content: '<script>alert("teaching")</script>' }} />));
  expect(node.querySelector('script')).toBeNull();
  expect(node.querySelector('[data-testid="saved-system-config-content"]').textContent)
    .toContain('<script>alert("teaching")</script>');
});


test('System config assessment check uses only the saved role request and reports canonical recovery states', async () => {
  const reference = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  const check = jest.fn().mockResolvedValueOnce({ kind: 'judgment', completed: false, replayed: false,
    judgment: { verdict: 'unavailable', evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: true } });
  await act(async () => root.render(<AdminSystemConfigRead read={{ kind: 'content', size: 12,
    content: 'owned config' }} reference={reference} onCheck={check} />));
  expect(node.textContent).toContain('Assessment pending.');
  const button = [...node.querySelectorAll('button')].find(value => value.textContent === 'Check saved System assessment');
  await act(async () => button.click());
  expect(check).toHaveBeenCalledWith(reference);
  expect(node.textContent).toContain('Grading unavailable. The saved System read remains available.');
  expect(node.querySelector('[data-testid="open-saved-system-assessments"]')).not.toBeNull();
});

test('System config assessment card reports completed and ineligible results without optimistic credit', async () => {
  const reference = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  const check = jest.fn().mockResolvedValue({ kind: 'ineligible', status: 'ineligible' });
  await act(async () => root.render(<AdminSystemConfigRead read={{ kind: 'content', size: 12,
    content: 'owned config' }} reference={reference} onCheck={check} />));
  let button = [...node.querySelectorAll('button')].find(value => value.textContent === 'Check saved System assessment');
  await act(async () => button.click());
  expect(node.textContent).toContain('not eligible for objective credit');
  check.mockResolvedValueOnce({ kind: 'judgment', completed: true, replayed: false,
    judgment: { verdict: 'pass', evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: false } });
  await act(async () => root.render(<AdminSystemConfigRead read={{ kind: 'content', size: 12,
    content: 'owned config' }} reference={{ ...reference, requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }} onCheck={check} />));
  button = [...node.querySelectorAll('button')].find(value => value.textContent === 'Check saved System assessment');
  await act(async () => button.click());
  expect(node.textContent).toContain('Objective completed.');
});

test('System config assessment keeps the saved read visible after a protected retry error', async () => {
  const reference = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  const check = jest.fn().mockResolvedValue({ kind: 'error', message: 'Return to the original shop scene.' });
  await act(async () => root.render(<AdminSystemConfigRead read={{ kind: 'content', size: 12,
    content: 'owned config' }} reference={reference} onCheck={check} />));
  const button = [...node.querySelectorAll('button')].find(value => value.textContent === 'Check saved System assessment');
  await act(async () => button.click());
  expect(node.textContent).toContain('Return to the original shop scene.');
  expect(node.querySelector('[data-testid="saved-system-config-content"]').textContent).toBe('owned config');
});

test('policy instruction check is source-bound and never claims credit for ineligible saved reads', async () => {
  const reference = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  const check = jest.fn().mockResolvedValueOnce({ kind: 'ineligible', status: 'ineligible' })
    .mockResolvedValueOnce({ kind: 'judgment', completed: true, replayed: false,
      judgment: { verdict: 'pass', evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: false } });
  await act(async () => root.render(<AdminSystemConfigRead read={{ kind: 'content', size: 12,
    content: '<script>source text</script>' }} reference={reference} onCheckPolicy={check} />));
  const button = [...node.querySelectorAll('button')]
    .find(value => value.textContent === 'Check saved policy instruction assessment');
  expect(button).toBeDefined();
  expect(node.textContent).toContain('This does not rerun chat or read configuration again.');
  await act(async () => button.click());
  expect(check).toHaveBeenCalledWith(reference);
  expect(node.textContent).toContain('not eligible for policy instruction objective credit');
  expect(node.textContent).not.toContain('Policy instruction objective completed.');
  expect(node.querySelector('script')).toBeNull();
  await act(async () => root.render(<AdminSystemConfigRead read={{ kind: 'content', size: 12,
    content: '<script>source text</script>' }} reference={{ ...reference,
    requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' }} onCheckPolicy={check} />));
  await act(async () => [...node.querySelectorAll('button')]
    .find(value => value.textContent === 'Check saved policy instruction assessment').click());
  expect(node.textContent).toContain('Policy instruction objective completed.');
});

const lookupReference = { sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
const lookupRead = { version: 1, username: 'student_customer', status: 'complete', assessmentReady: true };
const lookupPending = { completed: false, status: 'unconfirmed', modelEvaluated: false };
const lookupResult = { completed: true, replayed: true, judgment: { evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', verdict: 'pass', canRetry: false } };
const lookupJson = (value, status = 200) => ({ ok: status === 200, status, headers: { get: () => 'application/json' }, json: async () => value });
const lookupButton = text => [...node.querySelectorAll('button')].find(button => button.textContent === text);
const mountLookup = (transport, props = {}) => act(async () => root.render(<AdminUserLookup read={lookupRead} reference={lookupReference} authorityKey="original" transport={transport} {...props} />));

test('saved lookup assessment requires authoritative GET before one IDs-only POST and recovers lost ACK by GET', async () => {
  const transport = jest.fn().mockResolvedValueOnce(lookupJson(lookupPending))
    .mockRejectedValueOnce(Error('lost acknowledgement')).mockResolvedValueOnce(lookupJson(lookupResult));
  await mountLookup(transport);
  expect(lookupButton('Check user lookup objective')).toBeUndefined();
  expect(transport).not.toHaveBeenCalled();
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  await act(async () => lookupButton('Check user lookup objective').click());
  expect(transport.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'POST', 'GET']);
  expect(JSON.parse(transport.mock.calls[1][1].body)).toEqual(lookupReference);
  expect(transport.mock.calls[0][0]).toBe(`/api/secureshop/agents/admin/assistant/sessions/${lookupReference.sessionId}/requests/${lookupReference.requestId}/user-lookup/assessment`);
  expect(node.textContent).toContain('User lookup objective completed.');
  expect(lookupButton('Check user lookup objective')).toBeUndefined();
});

test('lookup reload recovers canonical assessment through GET without lookup or grading POST', async () => {
  const transport = jest.fn().mockResolvedValue(lookupJson(lookupResult));
  await mountLookup(transport);
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  await act(async () => root.unmount()); root = createRoot(node);
  await mountLookup(transport);
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  expect(transport.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'GET']);
  expect(node.textContent).toContain('User lookup objective completed.');
});

test.each([409, 503])('unknown lookup HTTP%s stays blocked rather than authorizing another grading request', async status => {
  const transport = jest.fn().mockResolvedValue(lookupJson({ error: 'unavailable' }, status));
  await mountLookup(transport);
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  expect(lookupButton('Check user lookup objective')).toBeUndefined();
  expect(node.querySelector('[role="alert"]').textContent).toContain(`HTTP ${status}`);
  expect(transport.mock.calls.every(([, options]) => options.method === 'GET')).toBe(true);
});

test('Fixed safe lookup is assessed ineligible without duplicate sensitive row or grading call', async () => {
  const transport = jest.fn().mockResolvedValue(lookupJson({ completed: false, status: 'ineligible', modelEvaluated: false }));
  await mountLookup(transport, { read: { ...lookupRead, status: 'redacted' } });
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  expect(node.textContent).toContain('withheld in Fixed mode');
  expect(node.textContent).toContain('not eligible for objective credit');
  expect(lookupButton('Check user lookup objective')).toBeUndefined();
  expect(transport).toHaveBeenCalledTimes(1);
});

test('lookup authority change drops a late original assessment and unavailable capability performs no HTTP', async () => {
  let resolve;
  const transport = jest.fn(() => new Promise(done => { resolve = done; }));
  await mountLookup(transport);
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  await mountLookup(transport, { authorityKey: 'renewed', read: { ...lookupRead, assessmentReady: false } });
  await act(async () => resolve(lookupJson(lookupResult)));
  expect(node.textContent).not.toContain('User lookup objective completed.');
  expect(node.querySelector('button')).toBeNull();
  expect(transport).toHaveBeenCalledTimes(1);
});

test('lookup canonical projection rejects invented fields, false credit and numeric flags', () => {
  expect(decodeUserLookupAssessment(lookupResult)).toEqual(lookupResult);
  for (const value of [{ ...lookupResult, completed: 1 }, { ...lookupResult, extra: true },
    { ...lookupResult, judgment: { ...lookupResult.judgment, verdict: 'fail' } },
    { ...lookupResult, judgment: { ...lookupResult.judgment, explanation: 'invented' } },
    { ...lookupPending, modelEvaluated: 0 }]) expect(() => decodeUserLookupAssessment(value)).toThrow();
});


test('uncertain submitted lookup assessment stays GET-only when the stored outcome remains unconfirmed', async () => {
  const transport = jest.fn().mockResolvedValue(lookupJson(lookupPending));
  await mountLookup(transport);
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  await act(async () => lookupButton('Check user lookup objective').click());
  expect(lookupButton('Check user lookup objective')).toBeUndefined();
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  expect(transport.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'POST', 'GET', 'GET']);
});


test('lost grading acknowledgement followed by remount and admitted pending GET never offers another POST', async () => {
  const pending = { completed: false, status: 'pending', modelEvaluated: false };
  const transport = jest.fn().mockResolvedValueOnce(lookupJson(lookupPending))
    .mockRejectedValueOnce(Error('lost acknowledgement')).mockResolvedValue(lookupJson(pending));
  await mountLookup(transport);
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  await act(async () => lookupButton('Check user lookup objective').click());
  await act(async () => root.unmount()); root = createRoot(node);
  await mountLookup(transport);
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  expect(node.textContent).toContain('Assessment is pending.');
  expect(lookupButton('Check user lookup objective')).toBeUndefined();
  await act(async () => lookupButton('Check saved user lookup assessment').click());
  expect(transport.mock.calls.map(([, options]) => options.method)).toEqual(['GET', 'POST', 'GET', 'GET', 'GET']);
});
