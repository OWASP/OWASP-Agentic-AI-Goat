import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminSystemDiagnosticAssessment, { decodeSystemDiagnosticAssessment } from './AdminSystemDiagnosticAssessment.jsx';

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const ref = { sessionId, requestId, proposalId };
const base = '/api/secureshop/agents/admin/assistant/system/diagnostic/assess';
const saved = `${base}/${sessionId}/${requestId}/${proposalId}`;
const json = (value, status = 200) => ({ ok: status >= 200 && status < 300, status,
  headers: { get: () => 'application/json' }, json: async () => value });
const unconfirmed = { completed: false, status: 'unconfirmed', modelEvaluated: false };
const completed = { completed: true, replayed: false, judgment: {
  verdict: 'pass', evaluationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', canRetry: false } };
let node, root, transport;
const button = label => [...node.querySelectorAll('button')].find(item => item.textContent === label);
const render = async (reference = ref, authorityKey = 'current', ready = true, locked = false) => {
  await act(async () => root.render(<AdminSystemDiagnosticAssessment reference={reference}
    ready={ready} authorityKey={authorityKey} transport={transport} locked={locked} />));
};
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  transport = jest.fn(async path => path === saved ? json(unconfirmed) : json(completed));
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });

test('one IDs-only grading POST follows protected unconfirmed GET; saved GET settles outcome', async () => {
  let reads = 0;
  transport.mockImplementation(async path => path === saved
    ? json(++reads === 1 ? unconfirmed : completed) : json(completed));
  await render();
  await act(async () => button('Check saved System diagnostic assessment').click());
  expect(button('Check System diagnostic objective')).toBeTruthy();
  await act(async () => button('Check System diagnostic objective').click());
  expect(transport.mock.calls.map(([path]) => path)).toEqual([saved, base, saved]);
  expect(JSON.parse(transport.mock.calls[1][1].body)).toEqual(ref);
  expect(Object.keys(JSON.parse(transport.mock.calls[1][1].body)).sort())
    .toEqual(['proposalId', 'requestId', 'sessionId']);
  expect(node.textContent).toContain('Objective completed.');
  expect(button('Check System diagnostic objective')).toBeUndefined();
});

test('uncertain POST and remount remain saved-GET-only until explicit new grading action', async () => {
  transport.mockImplementation(async path => {
    if (path === base) throw Error('Lost acknowledgement');
    return json(unconfirmed);
  });
  await render();
  await act(async () => button('Check saved System diagnostic assessment').click());
  await act(async () => button('Check System diagnostic objective').click());
  expect(transport.mock.calls.filter(([path]) => path === base)).toHaveLength(1);
  expect(button('Check System diagnostic objective')).toBeUndefined();
  await act(async () => button('Check saved System diagnostic assessment').click());
  expect(transport.mock.calls.filter(([path]) => path === base)).toHaveLength(1);
  await act(async () => root.unmount()); root = createRoot(node);
  await render();
  await act(async () => button('Check saved System diagnostic assessment').click());
  expect(transport.mock.calls.filter(([path]) => path === base)).toHaveLength(1);
});

test('authority rotation aborts an in-flight GET and rejects its late result', async () => {
  let finish;
  transport.mockImplementation(async path => path === saved
    ? new Promise(resolve => { finish = resolve; }) : json(completed));
  await render();
  await act(async () => button('Check saved System diagnostic assessment').click());
  const signal = transport.mock.calls[0][1].signal;
  await render(ref, 'rotated');
  expect(signal.aborted).toBe(true);
  await act(async () => finish(json(completed)));
  expect(node.textContent).not.toContain('Objective completed.');
  expect(transport.mock.calls.filter(([path]) => path === base)).toHaveLength(0);
});

test('locked and foreign authority outcomes prevent grading without diagnostic execution', async () => {
  await render(ref, 'current', true, true);
  await act(async () => button('Check saved System diagnostic assessment').click());
  expect(button('Check System diagnostic objective').disabled).toBe(true);
  await render(ref, 'current', true, false);
  transport.mockImplementation(async () => json({ error: 'Forbidden' }, 403));
  await act(async () => button('Check saved System diagnostic assessment').click());
  expect(button('Check System diagnostic objective')).toBeUndefined();
  expect(node.textContent).toContain('unavailable');
  expect(transport.mock.calls.every(([path]) => path === saved)).toBe(true);
});

test('closed assessment decoder rejects private fields and inconsistent credit', () => {
  expect(decodeSystemDiagnosticAssessment(unconfirmed)).toEqual(unconfirmed);
  expect(decodeSystemDiagnosticAssessment(completed)).toEqual(completed);
  expect(() => decodeSystemDiagnosticAssessment({ ...completed, proof: 'private' })).toThrow();
  expect(() => decodeSystemDiagnosticAssessment({ ...completed, judgment: {
    ...completed.judgment, verdict: 'fail' } })).toThrow();
  expect(() => decodeSystemDiagnosticAssessment({ completed: false,
    status: 'pending', modelEvaluated: false })).toThrow();
});
