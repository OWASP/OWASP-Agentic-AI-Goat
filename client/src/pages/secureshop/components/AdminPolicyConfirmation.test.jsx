import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminPolicyConfirmation from './AdminPolicyConfirmation.jsx';
import { attachShopStorage, SHOP_PROMPT_POLICY_KEY } from '../utils/shopStorage.mjs';
import { policyDigest, policyMutationDigests, readSavedPolicyPending,
  savePolicyPending } from '../pages/admin/policyOperation.js';

const { webcrypto } = require('node:crypto');
const { createRolePolicyProposal, projectRolePolicyProposal } = require('../../../../../server/services/secureshopRolePolicyProposal.js');
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const mode = { version: 1, featureId: 'admin_assistant', policyVersion: 'owned-admin-read-and-confirmation-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const json = (value, status = 200) => ({ ok: status >= 200 && status < 300, status,
  json: async () => value });
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
const until = async predicate => {
  for (let attempt = 0; attempt < 30 && !predicate(); attempt += 1) await settle();
  expect(predicate()).toBe(true);
};
let node, root, release, values, flush, proposal, receipt, originalFetch;

beforeEach(async () => {
  originalFetch = globalThis.fetch;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  const source = { sessionId, requestId };
  const candidate = createRolePolicyProposal({ source, origin: { step: 1, callId: 'policy-create' },
    action: 'create', selected: null, before: null, after: { markdown: 'Policy **source** <img src=x>',
      targets: ['admin'] }, name: 'shop_returns', expectedVersion: '2', scopeKey: 'a'.repeat(64),
    modeCapability: mode }, ['admin', 'customer', 'merchant']);
  proposal = projectRolePolicyProposal(candidate, source, ['admin', 'customer', 'merchant']);
  const digests = await policyMutationDigests({ operationId: proposal.proposalId, name: proposal.name,
    markdown: proposal.after.markdown, injected_into: proposal.after.targets }, []);
  const rendered = 'Rendered <img src=x> from saved receipt';
  receipt = { operationId: proposal.proposalId, version: '3', requestSha256: digests.requestSha256,
    renderResult: { version: 1, operationId: proposal.proposalId, requestSha256: digests.requestSha256,
      isolation: 'bwrap-policy-template-v1', rendered, renderedSha256: await policyDigest(rendered),
      exitCode: 0, timedOut: false, truncated: false, drained: true } };
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  values = new Map(); flush = async () => {};
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => flush() });
});
afterEach(async () => { await act(async () => root.unmount()); release(); node.remove(); globalThis.fetch = originalFetch; });
const render = (transport, currentProposal = proposal) => {
  globalThis.fetch = transport;
  return act(async () => root.render(<AdminPolicyConfirmation proposal={currentProposal}
    sessionId={currentProposal ? sessionId : null} requestId={currentProposal ? requestId : null}
    authorityKey="admin-session" transport={transport} />));
};
const policies = () => json({ administration: { versionedPolicy: true, scopeKey: proposal.scopeKey },
  version: '2', policies: [], supported_targets: ['admin', 'customer', 'merchant'] });
const source = (value, modeCapability = { scope: { id: 'admin_assistant', kind: 'launch_feature' },
  effectiveMode: 'fixed', policyVersion: 'owned-admin-read-and-confirmation-v1',
  featureId: 'admin_assistant', version: 1 }) => json({ sessionId, requestId,
  status: 'completed', replayed: true, stopReason: 'end_turn', modeCapability,
  policyProposal: value });

test('full trusted source is escaped and one ACKed confirm resolves lost response through exact GET', async () => {
  let acknowledge, posts = 0, committed = false;
  flush = () => new Promise(resolve => { acknowledge = resolve; });
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/admin/policies')) return policies();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith(`/policies/operations/${proposal.proposalId}`)) return committed
      ? json({ ok: true, receipt }) : json(null, 404);
    if (url.endsWith('/policies/confirm')) {
      posts++;
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId: proposal.proposalId });
      committed = true; throw Error('lost response');
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(node.textContent).toContain('Policy **source** <img src=x>');
  expect(node.querySelector('img')).toBeNull();
  await act(async () => {
    const button = [...node.querySelectorAll('button')].find(item => item.textContent === 'Save policy');
    button.click(); button.click(); await Promise.resolve();
  });
  await until(() => !!acknowledge);
  expect(posts).toBe(0);
  expect(readSavedPolicyPending()).toHaveLength(1);
  flush = async () => {};
  await act(async () => { acknowledge(); await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(posts).toBe(1);
  expect(readSavedPolicyPending()).toHaveLength(0);
  expect(node.textContent).toContain('Policy change confirmed from the saved receipt');
  expect(node.textContent).toContain('Rendered <img src=x> from saved receipt');
  expect(node.querySelector('img')).toBeNull();
});

test.each([
  ['literal', false, 'Literal policy text; no template execution.'],
  ['isolated_template', true, 'Isolated template result. Command effect observed.'],
])('v2 %s saved result shows only the effect actually witnessed', async (kind, observed, label) => {
  receipt.renderResult = { version: 2, kind, operationId: proposal.proposalId,
    requestSha256: receipt.requestSha256, executionSha256: 'c'.repeat(64),
    rendered: 'Saved <img src=x> text', renderedSha256: await policyDigest('Saved <img src=x> text'),
    ...(kind === 'isolated_template' ? { isolation: 'bwrap-policy-template-v1', exitCode: 0,
      timedOut: false, truncated: false, drained: true,
      effectWitness: { version: 1, workerAttested: true, commandEffectObserved: observed,
        effectSha256: observed ? 'd'.repeat(64) : null,
        compilerSha256: 'e'.repeat(64), workerSha256: 'f'.repeat(64) } } : {}) };
  const transport = jest.fn(async url => {
    if (url.endsWith('/admin/policies')) return policies();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith(`/policies/operations/${proposal.proposalId}`)) return json({ ok: true, receipt });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => [...node.querySelectorAll('button')].find(button => button.textContent === 'Save policy').click());
  await until(() => node.textContent.includes(label));
  expect(node.querySelector('img')).toBeNull();
  expect(transport.mock.calls.some(([url, options]) => url.endsWith('/policies/confirm') && options?.method === 'POST')).toBe(false);
});

test('extra outer saved mode field blocks confirmation before a reference or POST', async () => {
  let posts = 0;
  const transport = jest.fn(async url => {
    if (url.endsWith('/admin/policies')) return policies();
    if (url.includes('/assistant/operations/')) return source(proposal, { ...mode, extra: true });
    if (url.endsWith('/policies/confirm')) { posts++; return json({ ok: true, receipt }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Save policy').click());
  await settle();
  expect(posts).toBe(0);
  expect(readSavedPolicyPending()).toHaveLength(0);
  expect(node.textContent).toContain('Saved policy proposal changed');
});

test('duplicate advertised task targets fail availability before policy confirmation', async () => {
  let posts = 0;
  const transport = jest.fn(async url => {
    if (url.endsWith('/admin/policies')) return json({ administration: { versionedPolicy: true,
      scopeKey: proposal.scopeKey }, version: '2', policies: [],
      supported_targets: ['admin','customer','merchant'],
      supported_task_targets: ['summarizer','summarizer'] });
    if (url.endsWith('/policies/confirm')) { posts++; return json({ ok: true, receipt }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(node.textContent).toContain('Policy availability is unavailable');
  expect([...node.querySelectorAll('button')].find(button => button.textContent === 'Save policy').disabled).toBe(true);
  expect(posts).toBe(0);
  expect(readSavedPolicyPending()).toHaveLength(0);
});

test('unknown result survives null proposal and recovers by exact operation GET without another POST', async () => {
  let posts = 0, committed = false;
  const transport = jest.fn(async url => {
    if (url.endsWith('/admin/policies')) return policies();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith(`/policies/operations/${proposal.proposalId}`)) return committed
      ? json({ ok: true, receipt }) : json(null, 404);
    if (url.endsWith('/policies/confirm')) { posts++; return json({ ok: false, state: 'pending', operationId: proposal.proposalId }, 202); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); }); await settle();
  expect(posts).toBe(1); expect(values.has(SHOP_PROMPT_POLICY_KEY)).toBe(true);
  await render(transport, null); await settle();
  expect(node.textContent).toContain('Check saved policy operation');
  expect(node.textContent).not.toContain('Save policy');
  committed = true;
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved policy operation').click());
  await settle();
  expect(posts).toBe(1); expect(values.has(SHOP_PROMPT_POLICY_KEY)).toBe(false);
  expect(node.textContent).toContain('Policy change confirmed from the saved receipt');
});

test('saved recovery waits for protected policy scope before enabling its exact GET', async () => {
  const saved = { scopeKey: proposal.scopeKey, operationId: proposal.proposalId,
    expectedVersion: '2', action: 'create', name: proposal.name,
    requestSha256: receipt.requestSha256 };
  await savePolicyPending(saved);
  let resolvePolicies, reads = 0, posts = 0;
  const delayedPolicies = new Promise(resolve => { resolvePolicies = resolve; });
  const transport = jest.fn(async url => {
    if (url.endsWith('/admin/policies')) return delayedPolicies;
    if (url.endsWith(`/policies/operations/${saved.operationId}`)) {
      reads++; return json({ ok: true, receipt });
    }
    if (url.endsWith('/policies/confirm')) { posts++; return json({ ok: true, receipt }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport, null); await settle();
  const button = [...node.querySelectorAll('button')]
    .find(item => item.textContent === 'Check saved policy operation');
  expect(button).toBeDefined();
  expect(button.disabled).toBe(true);
  await act(async () => button.click());
  expect(reads).toBe(0); expect(posts).toBe(0);
  expect(readSavedPolicyPending()).toEqual([saved]);
  await act(async () => { resolvePolicies(policies()); await Promise.resolve(); });
  await until(() => button.disabled === false);
  await act(async () => button.click()); await settle();
  expect(reads).toBe(1); expect(posts).toBe(0);
  expect(readSavedPolicyPending()).toHaveLength(0);
  expect(node.textContent).toContain('Policy change confirmed from the saved receipt');
});

test('unavailable policy scope retains saved recovery without claiming a foreign scope', async () => {
  const saved = { scopeKey: proposal.scopeKey, operationId: proposal.proposalId,
    expectedVersion: '2', action: 'create', name: proposal.name,
    requestSha256: receipt.requestSha256 };
  await savePolicyPending(saved);
  let reads = 0;
  const transport = jest.fn(async url => {
    if (url.endsWith('/admin/policies')) return json(null, 503);
    if (url.includes('/policies/operations/')) { reads++; return json({ ok: true, receipt }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport, null); await settle();
  const button = [...node.querySelectorAll('button')]
    .find(item => item.textContent === 'Check saved policy operation');
  expect(button.disabled).toBe(true);
  expect(node.textContent).toContain('Policy availability is unavailable.');
  expect(node.textContent).not.toContain('another policy scope');
  expect(reads).toBe(0);
  expect(readSavedPolicyPending()).toEqual([saved]);
});

test('replaced saved operation during exact preflight blocks confirmation', async () => {
  let posts = 0;
  const transport = jest.fn(async url => {
    if (url.endsWith('/admin/policies')) return policies();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith(`/policies/operations/${proposal.proposalId}`)) {
      const raw = JSON.parse(values.get(SHOP_PROMPT_POLICY_KEY));
      raw.scopes[0].pending.expectedVersion = '4';
      values.set(SHOP_PROMPT_POLICY_KEY, JSON.stringify(raw));
      return json(null, 404);
    }
    if (url.endsWith('/policies/confirm')) { posts++; return json({ ok: true, receipt }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); }); await settle();
  expect(posts).toBe(0);
  expect(node.textContent).toContain('Saved policy operation changed');
  expect(readSavedPolicyPending()[0].expectedVersion).toBe('4');
});

test('a foreign-scope saved reference cannot be cleared by a matching-looking current receipt', async () => {
  const old = { scopeKey: 'b'.repeat(64), operationId: proposal.proposalId,
    expectedVersion: '2', action: 'create', name: proposal.name,
    requestSha256: receipt.requestSha256 };
  await savePolicyPending(old);
  let reads = 0, posts = 0;
  const transport = jest.fn(async url => {
    if (url.endsWith('/admin/policies')) return policies();
    if (url.includes('/policies/operations/')) { reads++; return json({ ok: true, receipt }); }
    if (url.endsWith('/policies/confirm')) { posts++; return json({ ok: true, receipt }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport, null); await settle();
  expect(node.textContent).toContain('Check saved policy operation');
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved policy operation').click());
  expect(reads).toBe(0); expect(posts).toBe(0);
  expect(node.textContent).toContain('another policy scope');
  expect(readSavedPolicyPending()).toEqual([old]);
});
