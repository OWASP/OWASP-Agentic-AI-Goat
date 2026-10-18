import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Turn from './Turn.jsx';
import HopDetailSheet from './HopDetailSheet.jsx';

const fixed = { version: 1, featureId: 'analytics', policyVersion: 'postgres-restricted-capability-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'analytics' } };
const vuln = { ...fixed, effectiveMode: 'vuln' };
let node, root;
beforeEach(() => { globalThis.IS_REACT_ACT_ENVIRONMENT = true; node = document.createElement('div'); document.body.appendChild(node); root = createRoot(node); });
afterEach(() => { act(() => root.unmount()); node.remove(); });

test('fixed turn renders assistant markup as text; vulnerable and legacy turns preserve the tagged HTML sink', () => {
  const turn = { user: 'search', hops: [], reply: '<strong>untrusted output</strong>', status: 'done' };
  act(() => root.render(<Turn turn={{ ...turn, modeCapability: fixed }} role="merchant" />));
  expect(node.querySelector('[data-testid="agent-turn-reply"]').textContent).toBe('<strong>untrusted output</strong>');
  expect(node.querySelector('[data-testid="agent-turn-reply"] strong')).toBeNull();
  expect(node.textContent).toContain('MERCHANT-SUPERVISOR');
  act(() => root.render(<Turn turn={{ ...turn, modeCapability: vuln }} />));
  expect(node.querySelector('[data-testid="agent-turn-reply"] strong')).not.toBeNull();
  act(() => root.render(<Turn turn={turn} />));
  expect(node.querySelector('[data-testid="agent-turn-reply"] strong')).not.toBeNull();
});

test('fixed hop renders both reflected echo and result inert while vulnerable hop keeps both raw sinks', () => {
  const hop = { tool: 'product-search.search', params: {}, result: {
    echo_html: '<strong>echo</strong>', content: [{ type: 'text', text: '<em>tool result</em>' }],
  }, modeCapability: fixed };
  act(() => root.render(<HopDetailSheet hop={hop} onClose={() => {}} />));
  expect(node.querySelector('[data-testid="hop-echo-html"]').textContent).toBe('<strong>echo</strong>');
  expect(node.querySelector('[data-testid="hop-echo-html"] strong')).toBeNull();
  expect(node.querySelector('.ss-sheet__body em')).toBeNull();
  act(() => root.render(<HopDetailSheet hop={{ ...hop, modeCapability: vuln }} onClose={() => {}} />));
  expect(node.querySelector('[data-testid="hop-echo-html"] strong')).not.toBeNull();
  expect(node.querySelector('.ss-sheet__body em')).not.toBeNull();
});

test('compact customer activity hides technical params by default while preserving full safe detail', () => {
  const choiceId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const turn = { user: 'Show my cart', status: 'done', reply: 'Your cart is unchanged.',
    modeCapability: fixed, hops: [
      { id: 'view', tool: 'cart.view', status: 'done', latencyMs: 42, params: {} },
      { id: 'remove', tool: 'cart.remove_item', status: 'error', policyViolation: 'blocked',
        latencyMs: 0, params: { choiceId, search: '<img src=x onerror=alert(1)>' } },
    ] };
  act(() => root.render(<Turn turn={turn} compactHops />));
  const activity = node.querySelector('[data-testid="agent-activity"]');
  expect(activity).not.toBeNull();
  expect(activity.open).toBe(false);
  expect(activity.querySelector('summary').textContent).toContain('2 steps · 1 blocked');
  expect(activity.querySelector('summary').textContent).toContain('Viewed cart → Blocked cart remove item');
  expect(activity.querySelector('summary').textContent).not.toContain(choiceId);
  expect([...activity.querySelectorAll('.ss-hop__args')].at(-1).textContent).toContain(choiceId);
  expect(node.querySelector('img')).toBeNull();
  expect(node.querySelector('[data-testid="agent-turn-reply"]').textContent).toBe('Your cart is unchanged.');
  act(() => root.render(<Turn turn={turn} />));
  expect(node.querySelector('[data-testid="agent-activity"]')).toBeNull();
  expect(node.querySelectorAll('.ss-hop')).toHaveLength(2);
});

test('compact labels distinguish canonical prepared actions from blocked and in-flight attempts', () => {
  const turn = { user: 'Review actions', status: 'in-flight', reply: '', hops: [
    { tool: 'catalog.details', status: 'ok', params: {} },
    { tool: 'account.addresses', status: 'in-flight', params: {} },
    { tool: 'cart.remove', status: 'ok', params: { choiceId: 'saved-choice' } },
  ] };
  act(() => root.render(<Turn turn={turn} compactHops />));
  const summary = node.querySelector('[data-testid="agent-activity"] summary').textContent;
  expect(summary).toContain('Read product details');
  expect(summary).toContain('Running address read');
  expect(summary).toContain('Prepared cart removal');
});

test('compact cart addition labels an exact saved stock rejection without changing the trace', () => {
  const operationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const customerMode = { version: 1, featureId: 'customer_chat', policyVersion: 'customer-chat-v1',
    effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'customer_chat' } };
  const observed = { scopeKey: 'a'.repeat(64), version: 1, operationId,
    kind: 'cart.add', status: 'rejected',
    result: { code: 'INSUFFICIENT_STOCK', choiceId, quantity: 2 }, replayed: false };
  const hop = { tool: 'cart.add', status: 'ok', params: { choiceId, quantity: 2 },
    result: { content: [{ type: 'text', text: JSON.stringify(observed) }] } };
  const turn = { user: 'Add two', status: 'done', stopReason: 'end_turn', reply: '',
    modeCapability: customerMode, hops: [hop], operations: [{ operationId, status: 'completed',
      rejection: observed.result }] };
  const summary = () => node.querySelector('[data-testid="agent-activity"] summary').textContent;
  act(() => root.render(<Turn turn={turn} compactHops />));
  expect(summary()).toContain('Cart addition rejected');
  expect(node.querySelector('[data-testid="agent-activity"] .ss-hop__name').textContent).toBe('cart.add');
  act(() => root.render(<Turn turn={{ ...turn, operations: [] }} compactHops />));
  expect(summary()).toContain('Prepared cart addition');
  act(() => root.render(<Turn turn={{ ...turn, hops: [{ ...hop,
    result: { content: [{ type: 'text', text: JSON.stringify({ ...observed,
      result: { ...observed.result, code: 'OTHER' } }) }] } }] }} compactHops />));
  expect(summary()).toContain('Prepared cart addition');
  act(() => root.render(<Turn turn={{ ...turn, hops: [{ ...hop,
    result: { content: [{ type: 'text', text: JSON.stringify({ ...observed, extra: true }) }] } }] }} compactHops />));
  expect(summary()).toContain('Prepared cart addition');
  act(() => root.render(<Turn turn={{ ...turn, hops: [{ ...hop, status: 'error' }] }} compactHops />));
  expect(summary()).toContain('cart addition failed');
});
