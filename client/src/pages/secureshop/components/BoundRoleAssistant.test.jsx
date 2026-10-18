import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import BoundRoleAssistant from './BoundRoleAssistant.jsx';
import MerchantPricingConfirmation from './MerchantPricingConfirmation.jsx';
import MerchantListingEditConfirmation from './MerchantListingEditConfirmation.jsx';
import AdminSystemRestartConfirmation from './AdminSystemRestartConfirmation.jsx';
import { useBoundRoleAssistant } from '../hooks/useBoundRoleAssistant.js';
import { useRegisteredAdminStream } from '../hooks/useRegisteredAdminStream.js';
import { openStandaloneChatPasswordReset } from '../bridge/passwordResetIntent.mjs';
import { decodeMailReferences } from '../bridge/mailReferences.mjs';
import { shopStorage, SHOP_MAIL_KEY } from '../utils/shopStorage.mjs';

jest.mock('../hooks/useBoundRoleAssistant.js', () => ({ useBoundRoleAssistant: jest.fn() }));
jest.mock('../hooks/useRegisteredAdminStream.js', () => ({ useRegisteredAdminStream: jest.fn() }));
jest.mock('../bridge/passwordResetIntent.mjs', () => ({ openStandaloneChatPasswordReset: jest.fn(() => true) }));
jest.mock('./MerchantPricingConfirmation.jsx', () => jest.fn(() => null));
jest.mock('./MerchantListingEditConfirmation.jsx', () => jest.fn(() => null));
jest.mock('./MerchantMailConfirmation.jsx', () => jest.fn(() => null));
jest.mock('./AdminSystemRestartConfirmation.jsx', () => jest.fn(() => null));

let root, node, assistant, registered;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  assistant = { turns: [], pending: null, status: 'idle', error: null,
    send: jest.fn().mockResolvedValue(true), recover: jest.fn().mockResolvedValue(true) };
  useBoundRoleAssistant.mockReturnValue(assistant);
  registered = { turns: [], pending: null, status: 'idle', error: null,
    send: jest.fn().mockResolvedValue(true), recover: jest.fn().mockResolvedValue(true) };
  useRegisteredAdminStream.mockImplementation(() => registered);
});
afterEach(async () => { await act(async () => root.unmount()); node.remove(); jest.clearAllMocks(); });
const render = async (role, composerTarget = null, scrollContainerRef = null, authorityKey = 'persona-token') => act(async () => root.render(
  <BoundRoleAssistant role={role} shopUserId={7} authorityKey={authorityKey} instance="test"
    composerTarget={composerTarget} scrollContainerRef={scrollContainerRef} />));

test('merchant assistant advertises only read tools and sends through the role hook', async () => {
  await render('merchant');
  expect(node.textContent).toContain('Catalog search');
  expect(node.textContent).toContain('Storefront overview');
  expect(node.textContent).not.toContain('stock changes');
  const input = node.querySelector('textarea');
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
    .set.call(input, 'Show top products');
    input.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => { node.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })); });
  expect(assistant.send).toHaveBeenCalledWith('Show top products');
  expect(useBoundRoleAssistant).toHaveBeenCalledWith(expect.objectContaining({
    role: 'merchant', shopUserId: 7, authorityKey: 'persona-token',
  }));
});

test('physical portal composer button submits the named product message to the role hook', async () => {
  const slot = document.createElement('div'); document.body.append(slot);
  try {
    await render('merchant', slot);
    const input = slot.querySelector('textarea'), button = slot.querySelector('button[type="submit"]');
    expect(input).not.toBeNull(); expect(button.form).toBe(input.closest('form'));
    await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
      .set.call(input, 'Find my product named "Owned Pricing Fixture"');
      input.dispatchEvent(new Event('input', { bubbles: true })); });
    expect(button.disabled).toBe(false);
    await act(async () => button.click());
    expect(assistant.send).toHaveBeenCalledWith('Find my product named "Owned Pricing Fixture"');
  } finally { slot.remove(); }
});

test('merchant product selection appears in the portaled composer', async () => {
  const slot = document.createElement('div'); document.body.append(slot);
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', status: 'done',
    user: 'Find my product', reply: 'Found it', hops: [], cards: [{ version: 1,
      kind: 'merchant_product', choiceId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      title: 'Owned Pricing Fixture', detail: 'Current catalog item' }] }];
  try {
    await render('merchant', slot);
    await act(async () => node.querySelector('[aria-label="Use Owned Pricing Fixture in next message"]').click());
    const form = slot.querySelector('textarea').closest('form.ss-lane__composer');
    expect(form.querySelector('p[role="status"]')?.textContent)
      .toContain('Selected product for this message: Owned Pricing Fixture');
    expect(form.querySelector('p[role="status"] button')?.textContent).toContain('Clear selection');
    expect(node.textContent).not.toContain('Selected product for this message: Owned Pricing Fixture');
  } finally { slot.remove(); }
});

test('real merchant hook submits through a portal after the lane remounts', async () => {
  useBoundRoleAssistant.mockImplementation(jest.requireActual('../hooks/useBoundRoleAssistant.js').useBoundRoleAssistant);
  const slot = document.createElement('div'); document.body.append(slot);
  const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const transport = jest.fn(async url => url.endsWith('/session')
    ? { ok: true, headers: { get: () => 'application/json' }, json: async () => ({ sessionId }) }
    : { ok: false, status: 503 });
  try {
    const component = <BoundRoleAssistant role="merchant" shopUserId={7} authorityKey="persona-token"
      instance="test" composerTarget={slot} transport={transport} />;
    await act(async () => root.render(component));
    await act(async () => root.render(null));
    await act(async () => root.render(component));
    const input = slot.querySelector('textarea'), form = input.closest('form');
    const button = form.querySelector('button[type="submit"]');
    expect(button.form).toBe(form);
    let clicks = 0, submits = 0;
    button.addEventListener('click', () => { clicks += 1; });
    form.addEventListener('submit', () => { submits += 1; });
    await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
      .set.call(input, 'Find my product named "Owned Pricing Fixture"');
      input.dispatchEvent(new Event('input', { bubbles: true })); });
    expect(button.disabled).toBe(false);
    await act(async () => button.click());
    expect({ clicks, submits }).toEqual({ clicks: 1, submits: 1 });
    expect(transport.mock.calls.some(([url]) => url.endsWith('/session'))).toBe(true);
  } finally { slot.remove(); }
});

test('composer input keeps restart transports stable until the authority transport changes', async () => {
  const firstTransport = jest.fn();
  await act(async () => root.render(<BoundRoleAssistant role="admin" shopUserId={7}
    authorityKey="persona-token" instance="test" transport={firstTransport} />));
  const initial = AdminSystemRestartConfirmation.mock.calls.at(-1)[0];
  const input = node.querySelector('textarea');
  const prompt = 'Prepare a System restart for the exact owned service name "nginx; /usr/bin/uname -n". Keep the name unchanged and wait for my confirmation.';
  const setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set;
  for (const character of prompt) await act(async () => {
    setter.call(input, input.value + character);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  expect(input.value).toBe(prompt);
  for (const [props] of AdminSystemRestartConfirmation.mock.calls) {
    expect(props.confirmOperation).toBe(initial.confirmOperation);
    expect(props.readOperation).toBe(initial.readOperation);
  }
  const replacementTransport = jest.fn();
  await act(async () => root.render(<BoundRoleAssistant role="admin" shopUserId={7}
    authorityKey="persona-token" instance="test" transport={replacementTransport} />));
  const replaced = AdminSystemRestartConfirmation.mock.calls.at(-1)[0];
  expect(replaced.confirmOperation).not.toBe(initial.confirmOperation);
  expect(replaced.readOperation).not.toBe(initial.readOperation);
});

test('merchant Next products uses saved request and read-only product retains details only', async () => {
  const requestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ sessionId: requestId, requestId, status: 'done', user: 'Find products',
    reply: 'Products', hops: [], cards: [{ version: 1, kind: 'merchant_product', choiceId,
      title: 'Retired lamp', detail: 'Read only', readOnly: true }],
    catalogPage: { version: 1, total: 8, pageSize: 5, returnedCount: 5, hasMore: true },
    modeCapability: { version: 1, featureId: 'merchant_assistant', policyVersion: '1',
      effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'merchant_assistant' } } }];
  await render('merchant');
  expect(node.querySelector('[aria-label="View details for Retired lamp"]')).not.toBeNull();
  expect(node.textContent).not.toContain('Rewrite listing');
  expect(node.querySelector('[aria-label="Use Retired lamp in next message"]')).toBeNull();
  expect(node.querySelector('[aria-label="Competitor URL for Retired lamp"]')).toBeNull();
  expect(node.querySelector('[aria-label="Search manual for Retired lamp"]')).toBeNull();
  expect(node.querySelector('[aria-label="View reviews for Retired lamp"]')).toBeNull();
  const next = node.querySelector('[aria-label="Next merchant products"]');
  await act(async () => next.click());
  expect(assistant.send).toHaveBeenCalledWith('Show more products', null, null, null,
    { intent: 'catalog_next', sourceRequestId: requestId });
  assistant.turns = [{ ...assistant.turns[0], catalogPage: null }];
  await render('merchant');
  expect(node.querySelector('[aria-label="Next merchant products"]')).toBeNull();
});

test('a delayed role answer cannot erase a newer composer draft', async () => {
  let resolveFirst, resolveThird;
  assistant.send.mockReturnValueOnce(new Promise(resolve => { resolveFirst = resolve; }))
    .mockResolvedValueOnce(false)
    .mockReturnValueOnce(new Promise(resolve => { resolveThird = resolve; }))
    .mockResolvedValueOnce(true);
  await render('merchant');
  const input = node.querySelector('textarea');
  const type = async value => act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const submit = () => act(async () => node.querySelector('form').dispatchEvent(
    new Event('submit', { bubbles: true, cancelable: true })));
  await type('First question'); await submit();
  await type('Second draft');
  await act(async () => resolveFirst(true));
  expect(input.value).toBe('Second draft');
  expect(node.querySelector('button[type="submit"]').disabled).toBe(false);
  await submit();
  expect(input.value).toBe('Second draft');
  await submit();
  await type(''); await type('Second draft');
  await act(async () => resolveThird(true));
  expect(input.value).toBe('Second draft');
  await submit();
  expect(input.value).toBe('');
  expect(assistant.send.mock.calls.map(([message]) => message))
    .toEqual(['First question', 'Second draft', 'Second draft', 'Second draft']);
});

test('admin saved request disables composer and offers exact GET recovery', async () => {
  assistant.pending = { requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  assistant.status = 'unresolved';
  assistant.turns = [{ user: 'Saved role assistant request', status: 'error',
    reply: '<img src=x onerror=alert(1)>', hops: [] }];
  await render('admin');
  expect(node.textContent).toContain('User search');
  expect(node.textContent).toContain('Recent audit activity');
  expect(node.querySelector('button[type="submit"]').disabled).toBe(true);
  expect(node.querySelector('img')).toBeNull();
  const check = [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved assistant request');
  await act(async () => check.click());
  expect(assistant.recover).toHaveBeenCalledTimes(1);
});

test.each(['merchant', 'admin'])('%s offers local Stop watching only during an acknowledged stream', async role => {
  assistant.pending = { requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  assistant.status = 'thinking';
  assistant.canStopWatching = true;
  assistant.stopWatching = jest.fn(() => true);
  await render(role);
  const stop = [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Stop watching response');
  expect(stop).toBeDefined();
  expect(node.textContent).toContain('The saved request may still finish.');
  expect(node.querySelector('button[type="submit"]').disabled).toBe(true);
  await act(async () => stop.click());
  expect(assistant.stopWatching).toHaveBeenCalledTimes(1);
  expect(assistant.recover).not.toHaveBeenCalled();

  assistant.status = 'unresolved'; assistant.canStopWatching = false;
  await render(role);
  expect(node.textContent).not.toContain('Stop watching response');
  const check = [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved assistant request');
  expect(check.disabled).toBe(false);
  await act(async () => check.click());
  expect(assistant.recover).toHaveBeenCalledTimes(1);
  expect(assistant.send).not.toHaveBeenCalled();
});

test('admin saved audit read shows returned event fields as escaped text and honest page state', async () => {
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Show recent activity', status: 'done', reply: 'Recent activity', hops: [],
    auditRead: { events: [{ store: 'agents', id: 'agents:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      event_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      ts: '2026-10-11T12:34:56.123456Z', actor: 'Admin', action: 'policy_update',
      target: '<img src=x onerror=alert(1)>', params_json: '{"source":"<script>"}',
      outcome: 'completed', source_kind: 'policy', source_id: 'saved source',
      ip: null, user_agent: null }], hasMore: true, nextPageAvailable: true } }];
  await render('admin');
  const panel = node.querySelector('[aria-label="Admin audit activity"]');
  expect(panel.querySelector('li').style.overflowWrap).toBe('anywhere');
  expect(panel.textContent).toContain('policy_update · completed');
  expect(panel.textContent).toContain('<img src=x onerror=alert(1)>');
  expect(panel.textContent).toContain('Older matching events are available.');
  expect(panel.querySelector('img')).toBeNull();
  expect(panel.querySelector('script')).toBeNull();
  const details = panel.querySelector('details');
  expect(details.textContent).toContain('{"source":"<script>"}');
  expect(panel.querySelector('input')).toBeNull();
});

test('registered pending reload blocks assistant send but permits entry to exact recovery', async () => {
  registered.pending = { shopUserId: 7, sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', startedAt: 1234 };
  registered.status = 'unresolved';
  await render('admin');
  expect(node.querySelector('button[aria-label="Open registered tools"]').disabled).toBe(false);
  expect(node.querySelector('button[type="submit"]').disabled).toBe(true);
  await act(async () => node.querySelector('button[aria-label="Open registered tools"]').click());
  expect(node.querySelector('[data-testid="registered-admin-conversation"]').hidden).toBe(false);
  expect(node.querySelector('button[aria-label="Open Admin assistant"]').disabled).toBe(true);
  const recover = [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved registered-tools request');
  expect(recover).toBeDefined();
  await act(async () => recover.click());
  expect(registered.recover).toHaveBeenCalledTimes(1);
  expect(assistant.send).not.toHaveBeenCalled();
});

test('conversation and saved outcome appear before the bottom composer with safe formatted replies', async () => {
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', user: 'Find a user',
    status: 'done', reply: '**Result**\n<img src=x onerror=alert(1)>', hops: [] }];
  assistant.pending = { requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' };
  await render('admin');
  const log = node.querySelector('[role="log"]');
  const saved = [...node.querySelectorAll('[role="status"]')].find(element =>
    element.textContent.includes('Check its saved outcome'));
  const composer = node.querySelector('form');
  expect(log.compareDocumentPosition(saved) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(saved.compareDocumentPosition(composer) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  expect(node.querySelector('[data-safe-chat-body]')).not.toBeNull();
  expect(node.querySelector('[data-testid="role-assistant-reply"]').textContent)
    .toContain('<img src=x onerror=alert(1)>');
  expect(node.querySelector('img')).toBeNull();
});

test('optional composer target keeps the role composer outside the scrolling conversation', async () => {
  assistant.turns = Array.from({ length: 20 }, (_, index) => ({ user: `Question ${index}`,
    status: 'done', reply: `Answer ${index}`, hops: [] }));
  const target = document.createElement('div');
  target.dataset.testid = 'fixed-role-composer-slot';
  node.append(target);
  await render('admin', target);
  const log = node.querySelector('[role="log"]');
  const form = target.querySelector('form');
  expect(form).not.toBeNull();
  expect(log.contains(form)).toBe(false);
  const input = form.querySelector('textarea');
  expect(input).not.toBeNull();
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
    .set.call(input, 'Find my exact product');
    input.dispatchEvent(new Event('input', { bubbles: true })); });
  expect(target.querySelector('textarea').value).toBe('Find my exact product');
  await act(async () => form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(assistant.send).toHaveBeenCalledWith('Find my exact product');
});

test('role history follows the bottom until the user scrolls up', async () => {
  const target = document.createElement('div');
  const scrollContainer = document.createElement('div');
  Object.defineProperties(scrollContainer, {
    scrollHeight: { configurable: true, value: 1000 },
    clientHeight: { configurable: true, value: 400 },
    scrollTop: { configurable: true, writable: true, value: 600 },
  });
  node.append(scrollContainer, target);
  const scrollContainerRef = { current: scrollContainer };
  await render('admin', target, scrollContainerRef);
  assistant.turns = [{ user: 'New question', status: 'done', reply: 'New answer', hops: [] }];
  await render('admin', target, scrollContainerRef);
  expect(scrollContainer.scrollTop).toBe(1000);
  scrollContainer.scrollTop = 100;
  scrollContainer.dispatchEvent(new Event('scroll'));
  assistant.turns = [...assistant.turns, { user: 'Another question', status: 'done', reply: 'Another answer', hops: [] }];
  await render('admin', target, scrollContainerRef);
  expect(scrollContainer.scrollTop).toBe(100);
});

test('named role choices are selectable only on the latest completed saved turn', async () => {
  const oldId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [
    { user: 'Earlier search', status: 'done', reply: 'Earlier candidates', hops: [],
      cards: [{ version: 1, kind: 'merchant_product', choiceId: oldId,
        title: 'Old desk', detail: 'Earlier result' }] },
    { user: 'Latest search', status: 'done', reply: 'Current candidates', hops: [],
      cards: [{ version: 1, kind: 'merchant_product', choiceId,
        title: '<img src=x>', detail: 'Current catalog item' }] },
  ];
  await render('merchant');
  const choices = [...node.querySelectorAll('[aria-label="Merchant product choices"] button[aria-label^="View details for "]')];
  expect(choices).toHaveLength(2);
  expect(choices[0].disabled).toBe(true);
  expect(choices[1].disabled).toBe(false);
  expect(node.querySelector('img')).toBeNull();
  const currentGroup = node.querySelectorAll('[aria-label="Merchant product choices"]')[1];
  expect(currentGroup.querySelectorAll('strong')).toHaveLength(1);
  expect(currentGroup.textContent.match(/Current catalog item/g)).toHaveLength(1);
  expect(currentGroup.querySelectorAll('button')).toHaveLength(7);
  expect([...currentGroup.querySelectorAll('button')].filter(button =>
    button.textContent === 'Prepare image optimization')).toHaveLength(1);
  await act(async () => choices[1].click());
  expect(assistant.send).toHaveBeenCalledWith('Show my selected product details.',
    { choiceId, intent: 'product_details' });
  await act(async () => [...currentGroup.querySelectorAll('button')].find(button=>button.textContent==='Rewrite listing').click());
  expect(assistant.send).toHaveBeenLastCalledWith('Prepare to rewrite this listing.', {choiceId,intent:'listing_rewrite'});
  await act(async () => [...currentGroup.querySelectorAll('button')].find(button=>button.textContent==='Prepare image optimization').click());
  expect(assistant.send).toHaveBeenLastCalledWith('Prepare image optimization for this listing.', {choiceId,intent:'listing_optimize'});
  assistant.pending = { requestId: 'saved-id' };
  await render('merchant');
  expect([...node.querySelectorAll('[aria-label="Merchant product choices"] button')]
    .every(button => button.disabled)).toBe(true);
});

test('merchant stages manual search for one saved product and submits the typed question unchanged', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    status: 'done', reply: 'Owned product', hops: [], cards: [{ version: 1,
      kind: 'merchant_product', choiceId, title: 'Practice laptop', detail: 'Current catalog item' }] }];
  await render('merchant');
  await act(async () => node.querySelector('[aria-label="Search manual for Practice laptop"]').click());
  expect(node.textContent).toContain('Search manual for: Practice laptop');
  const input = node.querySelector('textarea');
  expect(input.placeholder).toContain('product manual');
  const query = 'How do I replace the battery?';
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
    .set.call(input, query); input.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  expect(assistant.send).toHaveBeenCalledWith(query, { choiceId, intent: 'manual_search' });
});

test('merchant mail choices expose only current typed mailbox and message reads', async () => {
  const recipientId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const messageId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    status: 'done', reply: 'Earlier recipient', hops: [], cards: [{ version: 1,
      kind: 'merchant_mail_recipient', choiceId: recipientId,
      title: '<script>merchant</script>', detail: 'merchant@example.test' }] },
  { requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    status: 'done', reply: 'Current messages', hops: [], cards: [{ version: 1,
      kind: 'merchant_mail_message', choiceId: messageId,
      title: '<img src=x>', detail: 'From merchant@example.test' }] }];
  await render('merchant');
  const groups = node.querySelectorAll('[aria-label="Merchant mail choices"]');
  expect(groups).toHaveLength(2);
  expect(node.querySelector('script')).toBeNull();
  expect(node.querySelector('img')).toBeNull();
  const mailbox = groups[0].querySelector('[aria-label="View mailbox for <script>merchant</script>"]');
  const message = groups[1].querySelector('[aria-label="View message: <img src=x>"]');
  expect(mailbox.disabled).toBe(true);
  expect(message.disabled).toBe(false);
  expect(groups[1].querySelector('[aria-label^="Choose "]')).toBeNull();
  await act(async () => message.click());
  expect(assistant.send).toHaveBeenCalledWith('Show this message.',
    { choiceId: messageId, intent: 'mail_detail' });
  await act(async () => groups[1].querySelector('[aria-label="Prepare reply to <img src=x>"]').click());
  expect(assistant.send).toHaveBeenCalledWith('Prepare a reply to this message.',
    { choiceId: messageId, intent: 'mail_reply' });
  assistant.turns = [assistant.turns[0]];
  await render('merchant');
  await act(async () => node.querySelector('[aria-label="View mailbox for <script>merchant</script>"]').click());
  expect(assistant.send).toHaveBeenCalledWith('Show this recipient’s mailbox.',
    { choiceId: recipientId, intent: 'mail_list' });
  await act(async () => node.querySelector('[aria-label="Compose message to <script>merchant</script>"]').click());
  expect(node.textContent).toContain('Draft a message to <script>merchant</script>');
  const input = node.querySelector('textarea');
  const prompt = 'Send a notice with subject Welcome and body <b>hello</b>';
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
    .set.call(input, prompt); input.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  expect(assistant.send).toHaveBeenCalledWith(prompt, { choiceId: recipientId, intent: 'mail_send' });
});

test('mail action clears a staged product context before the next freeform question', async () => {
  const productChoiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const recipientChoiceId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', status: 'done',
    reply: 'Named choices', hops: [], cards: [
      { version: 1, kind: 'merchant_product', choiceId: productChoiceId,
        title: 'Practice laptop', detail: 'Current product' },
      { version: 1, kind: 'merchant_mail_recipient', choiceId: recipientChoiceId,
        title: 'Practice merchant', detail: 'merchant@example.test' },
    ] }];
  await render('merchant');
  await act(async () => node.querySelector('[aria-label="Use Practice laptop in next message"]').click());
  expect(node.textContent).toContain('Selected product for this message: Practice laptop');
  await act(async () => node.querySelector('[aria-label="View mailbox for Practice merchant"]').click());
  expect(node.textContent).not.toContain('Selected product for this message: Practice laptop');
  expect(assistant.send).toHaveBeenCalledWith('Show this recipient’s mailbox.',
    { choiceId: recipientChoiceId, intent: 'mail_list' });
});

test('merchant saved mail shows escaped source and only the current page can continue', async () => {
  const sourceRequestId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  assistant.turns = [{ requestId: sourceRequestId, status: 'done', reply: 'Mailbox page',
    hops: [], cards: [], mailRead: { result: { kind: 'list', hasMore: true,
      recipient: { username: 'Practice merchant', email: 'merchant@example.test' },
      total: 6, offset: 0, headers: [{ sha256: 'a'.repeat(64),
        subject: '<script>subject</script>', from: 'buyer@example.test',
        to: 'merchant@example.test', createdAt: '2026-10-11T12:00:00.000Z' }] } } }];
  await render('merchant');
  const panel = node.querySelector('[aria-label="Merchant saved mail read"]');
  expect(panel.textContent).toContain('<script>subject</script>');
  expect(panel.querySelector('script')).toBeNull();
  await act(async () => node.querySelector('[aria-label="Older mail"]').click());
  expect(assistant.send).toHaveBeenCalledWith('Show older mail', null, null,
    { intent: 'mail_next', sourceRequestId });
  assistant.turns = [...assistant.turns, { requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    status: 'done', reply: 'Selected message', hops: [], cards: [], mailRead: { result: {
      kind: 'detail', status: 'complete', message: {
        subject: 'Saved source', from: 'buyer@example.test', to: 'merchant@example.test',
        createdAt: '2026-10-11T12:00:00.000Z', bodyMarkdown: '<script>alert(1)</script>',
        bodyHtml: '<img src=x onerror=alert(1)>', headersRaw: 'X-Test: raw',
      },
    } } }];
  await render('merchant');
  expect(node.querySelector('[aria-label="Older mail"]')).toBeNull();
  const details = node.querySelectorAll('[aria-label="Merchant saved mail read"]')[1];
  expect(details.textContent).toContain('<script>alert(1)</script>');
  expect(details.querySelector('script')).toBeNull();
  expect(details.querySelector('img')).toBeNull();
});


test('latest protected mail detail saves only opaque selectors and recovers its summary with GET', async () => {
  const scopeKey = 'a'.repeat(64);
  const readOperationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const originalFetch = globalThis.fetch;
  const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status,
    json: async () => body });
  const transport = jest.fn(async (url, options = {}) => {
    if (url === '/api/secureshop/email/readiness') return response({ ready: true, scopeKey });
    if (url === '/api/secureshop/email/inline/summary' && options.method === 'POST') {
      expect(JSON.parse(options.body)).toEqual({ requestId: expect.stringMatching(/^[a-f0-9-]{36}$/),
        readOperationId, messageId: 7 });
      return response({ ok: true, status: 'unconfirmed', requestId: JSON.parse(options.body).requestId }, 202);
    }
    if (/\/api\/secureshop\/email\/inline\/summary\/[a-f0-9-]{36}$/.test(url)) {
      const requestId = url.split('/').at(-1);
      return response({ ok: true, status: 'completed', requestId,
        sessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', text: '<img src=x onerror=alert(1)>',
        replayed: false, assessmentStatus: 'pending' });
    }
    if (url === '/api/secureshop/email/inline/assessment' && options.method === 'POST') {
      expect(JSON.parse(options.body)).toEqual({ sessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
        requestId: expect.stringMatching(/^[a-f0-9-]{36}$/) });
      return response({ completed: false, status: 'unconfirmed', modelEvaluated: false }, 202);
    }
    if (/\/api\/secureshop\/email\/inline\/assessment\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(url)) return response({
      completed: true, judgment: { verdict: 'pass', evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: false }, replayed: false,
    });
    throw new Error(`Unexpected mail request ${url}`);
  });
  globalThis.fetch = transport;
  shopStorage.removeItem(SHOP_MAIL_KEY);
  assistant.turns = [{ requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', status: 'done',
    reply: 'Selected message', hops: [], cards: [], mailRead: { result: {
      version: 1, kind: 'detail', readOperationId, receiptSha256: 'c'.repeat(64),
      mailModeCapability: { version: 1, featureId: 'mail', policyVersion: 'owned-mail-recipient-header-and-html-v1',
        effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'mail' } },
      recipient: { id: 7, username: 'Practice merchant', email: 'merchant@example.test', role: 'merchant' },
      messageId: 7, messageSha256: 'd'.repeat(64), status: 'complete', message: {
        id: 7, threadId: 8, from: 'buyer@example.test', to: 'merchant@example.test', subject: 'Saved source',
        createdAt: '2026-10-11T12:00:00.000Z', sha256: 'd'.repeat(64), bodyMarkdown: 'Body', bodyHtml: '',
        headersRaw: '', sourceBytes: 4, oversized: false,
      },
    } } }];
  try {
    await render('merchant');
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    const button = [...node.querySelectorAll('button')].find(item => item.textContent === 'Summarize selected message');
    expect(button).toBeDefined();
    expect(button.disabled).toBe(false);
    await act(async () => { button.click(); await Promise.resolve(); await Promise.resolve(); });
    const summaryPosts = transport.mock.calls.filter(([url, options]) => url === '/api/secureshop/email/inline/summary'
      && options?.method === 'POST');
    expect(summaryPosts).toHaveLength(1);
    expect(JSON.parse(summaryPosts[0][1].body)).toEqual({ requestId: expect.stringMatching(/^[a-f0-9-]{36}$/),
      readOperationId, messageId: 7 });
    expect(transport.mock.calls.filter(([url]) => /\/inline\/summary\/[a-f0-9-]{36}$/.test(url))).toHaveLength(1);
    const panel = node.querySelector('[aria-label="Saved merchant mail summary"]');
    expect(panel.textContent).toContain('<img src=x onerror=alert(1)>');
    expect(panel.querySelector('img')).toBeNull();
    expect(decodeMailReferences(shopStorage.getItem(SHOP_MAIL_KEY)).scopes[scopeKey].inlineSummary)
      .toEqual(expect.objectContaining({ readOperationId, messageId: 7, assessmentAttempted: false }));
    const stored = shopStorage.getItem(SHOP_MAIL_KEY) || '';
    expect(stored).not.toContain('buyer@example.test');
    expect(stored).not.toContain('Saved source');
    const assess = [...node.querySelectorAll('button')].find(item => item.textContent === 'Assess saved summary');
    await act(async () => { assess.click(); await Promise.resolve(); await Promise.resolve(); });
    expect(node.textContent).toContain('Objective completed.');
    expect(decodeMailReferences(shopStorage.getItem(SHOP_MAIL_KEY)).scopes[scopeKey].inlineSummary.assessmentAttempted).toBe(true);
    expect(transport.mock.calls.filter(([url, options]) => url === '/api/secureshop/email/inline/assessment'
      && options?.method === 'POST')).toHaveLength(1);
    await render('merchant', null, null, 'rotated-persona-token');
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(node.querySelector('[aria-label="Saved merchant mail summary"]')).toBeNull();
    const recoverSummary = [...node.querySelectorAll('button')].find(item => item.textContent === 'Check saved summary');
    await act(async () => { recoverSummary.click(); await Promise.resolve(); await Promise.resolve(); });
    const recoverAssessment = [...node.querySelectorAll('button')].find(item => item.textContent === 'Check saved assessment');
    await act(async () => { recoverAssessment.click(); await Promise.resolve(); await Promise.resolve(); });
    expect(transport.mock.calls.filter(([url, options]) => url === '/api/secureshop/email/inline/summary'
      && options?.method === 'POST')).toHaveLength(1);
    expect(transport.mock.calls.filter(([url, options]) => url === '/api/secureshop/email/inline/assessment'
      && options?.method === 'POST')).toHaveLength(1);
  } finally {
    globalThis.fetch = originalFetch;
    shopStorage.removeItem(SHOP_MAIL_KEY);
  }
});


test('authority rotation aborts an in-flight saved mail assessment read without repeating its effect', async () => {
  const scopeKey = 'a'.repeat(64);
  const readOperationId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const originalFetch = globalThis.fetch;
  const response = (body, status = 200) => ({ ok: status >= 200 && status < 300, status,
    json: async () => body });
  let resolveAssessmentRead, assessmentSignal, assessmentReads = 0;
  const transport = jest.fn((url, options = {}) => {
    if (url === '/api/secureshop/email/readiness') return Promise.resolve(response({ ready: true, scopeKey }));
    if (url === '/api/secureshop/email/inline/summary' && options.method === 'POST') {
      return Promise.resolve(response({ ok: true, status: 'unconfirmed', requestId: JSON.parse(options.body).requestId }, 202));
    }
    if (/\/api\/secureshop\/email\/inline\/summary\/[a-f0-9-]{36}$/.test(url)) {
      const requestId = url.split('/').at(-1);
      return Promise.resolve(response({ ok: true, status: 'completed', requestId,
        sessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', text: 'Saved summary', replayed: false,
        assessmentStatus: 'pending' }));
    }
    if (url === '/api/secureshop/email/inline/assessment' && options.method === 'POST') {
      return Promise.resolve(response({ completed: false, status: 'unconfirmed', modelEvaluated: false }, 202));
    }
    if (/\/api\/secureshop\/email\/inline\/assessment\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(url)) {
      assessmentReads += 1;
      if (assessmentReads === 1) return new Promise(resolve => {
        resolveAssessmentRead = resolve; assessmentSignal = options.signal;
      });
      return Promise.resolve(response({ completed: true,
        judgment: { verdict: 'pass', evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: false },
        replayed: true }));
    }
    throw new Error(`Unexpected mail request ${url}`);
  });
  globalThis.fetch = transport;
  shopStorage.removeItem(SHOP_MAIL_KEY);
  assistant.turns = [{ requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', status: 'done',
    reply: 'Selected message', hops: [], cards: [], mailRead: { result: {
      version: 1, kind: 'detail', readOperationId, receiptSha256: 'c'.repeat(64),
      mailModeCapability: { version: 1, featureId: 'mail', policyVersion: 'owned-mail-recipient-header-and-html-v1',
        effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'mail' } },
      recipient: { id: 7, username: 'Practice merchant', email: 'merchant@example.test', role: 'merchant' },
      messageId: 7, messageSha256: 'd'.repeat(64), status: 'complete', message: {
        id: 7, threadId: 8, from: 'buyer@example.test', to: 'merchant@example.test', subject: 'Saved source',
        createdAt: '2026-10-11T12:00:00.000Z', sha256: 'd'.repeat(64), bodyMarkdown: 'Body', bodyHtml: '',
        headersRaw: '', sourceBytes: 4, oversized: false,
      },
    } } }];
  try {
    await render('merchant');
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    await act(async () => {
      [...node.querySelectorAll('button')].find(item => item.textContent === 'Summarize selected message').click();
      await Promise.resolve(); await Promise.resolve();
    });
    await act(async () => {
      [...node.querySelectorAll('button')].find(item => item.textContent === 'Assess saved summary').click();
      await Promise.resolve(); await Promise.resolve();
    });
    expect(assessmentSignal).toBeDefined();
    expect(assessmentSignal.aborted).toBe(false);
    await render('merchant', null, null, 'rotated-persona-token');
    await act(async () => { await Promise.resolve(); });
    expect(assessmentSignal.aborted).toBe(true);
    await act(async () => {
      resolveAssessmentRead(response({ completed: true,
        judgment: { verdict: 'pass', evaluationId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', canRetry: false },
        replayed: false }));
      await Promise.resolve(); await Promise.resolve();
    });
    expect(node.textContent).not.toContain('Objective completed.');
    expect(transport.mock.calls.filter(([url, options]) => url === '/api/secureshop/email/inline/assessment'
      && options?.method === 'POST')).toHaveLength(1);
    const recoverSummary = [...node.querySelectorAll('button')].find(item => item.textContent === 'Check saved summary');
    await act(async () => { recoverSummary.click(); await Promise.resolve(); await Promise.resolve(); });
    const recoverAssessment = [...node.querySelectorAll('button')].find(item => item.textContent === 'Check saved assessment');
    await act(async () => { recoverAssessment.click(); await Promise.resolve(); await Promise.resolve(); });
    expect(assessmentReads).toBe(2);
    expect(transport.mock.calls.filter(([url, options]) => url === '/api/secureshop/email/inline/assessment'
      && options?.method === 'POST')).toHaveLength(1);
    expect(node.textContent).toContain('Objective completed.');
  } finally {
    globalThis.fetch = originalFetch;
    shopStorage.removeItem(SHOP_MAIL_KEY);
  }
});

test('merchant mail displays honest recipient overflow and no oversized body claim', async () => {
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    status: 'done', reply: 'Recipients', hops: [], cards: [],
    mailRead: { result: { kind: 'recipients', recipients: [], hasMore: true } } },
  { requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    status: 'done', reply: 'Oversized source', hops: [], cards: [],
    mailRead: { result: { kind: 'detail', status: 'oversized', message: null } } }];
  await render('merchant');
  const panels = node.querySelectorAll('[aria-label="Merchant saved mail read"]');
  expect(panels[0].textContent).toContain('More recipients match. Refine the name search.');
  expect(panels[1].textContent).toContain('too large for a verified chat answer');
  expect(panels[1].textContent).not.toContain('Message body');
  expect(node.querySelector('[aria-label="Older mail"]')).toBeNull();
});

test('merchant shows a saved manual excerpt as text in the conversation', async () => {
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Battery?', status: 'done', reply: 'Read the saved excerpt.', hops: [], cards: [],
    manualSearch: { result: { product: { name: 'Practice laptop' }, query: 'Battery?',
      count: 1, hasMore: false, status: 'complete', sources: [{ sourceId: 1, chunkIndex: 0,
        filename: 'laptop.pdf', completedAt: '2026-10-11T12:00:00.000Z', score: 0.8,
        text: '<script>alert(1)</script>', textBytes: 25, textSha256: 'a'.repeat(64),
        sourceSha256: 'b'.repeat(64) }] } } }];
  await render('merchant');
  const card = node.querySelector('[aria-label="Merchant manual search result"]');
  expect(card).not.toBeNull();
  expect(card.textContent).toContain('laptop.pdf');
  expect(card.textContent).toContain('<script>alert(1)</script>');
  expect(card.querySelector('script')).toBeNull();
});

test('merchant product card reviews an exact typed competitor URL without changing detail selection', async () => {
  const choiceId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns=[{status:'done',reply:'Owned products',hops:[],cards:[{
    version:1,kind:'merchant_product',choiceId,title:'Practice laptop',detail:'Current catalog item'}]}];
  await render('merchant');
  const input=node.querySelector('[aria-label="Competitor URL for Practice laptop"]');
  const button=node.querySelector('[aria-label="Review competitor comparison for Practice laptop"]');
  expect(button.disabled).toBe(true);
  const url='http://competitor.example/product?name=Practice%20laptop';
  await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')
    .set.call(input,url);input.dispatchEvent(new Event('input',{bubbles:true}));});
  expect(button.disabled).toBe(false);
  await act(async()=>button.click());
  expect(assistant.send).toHaveBeenCalledWith('Compare my selected product with this competitor URL.',
    {choiceId,intent:'pricing_compare',competitorUrl:url});
  expect(node.querySelector('[aria-label="View details for Practice laptop"]')).toBeTruthy();
  await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value')
    .set.call(input,'https://competitor.example/unsupported');
    input.dispatchEvent(new Event('input',{bubbles:true}));});
  expect(button.disabled).toBe(true);
});

test('admin policy choices keep full source as text and stage explicit preview before confirmation', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Find policy', status: 'done', reply: 'Current policy', hops: [],
    cards: [{ version: 1, kind: 'admin_policy', choiceId,
      title: 'shop_returns', detail: 'Current shop policy' }],
    policyDetail: { name: 'shop_returns', policyVersion: '4', targets: ['customer'],
      markdown: 'Original <img src=x onerror=alert(1)>' } }];
  await render('admin');
  expect(node.querySelector('[aria-label="Admin policy details"]').textContent)
    .toContain('Original <img src=x onerror=alert(1)>');
  expect(node.querySelector('img')).toBeNull();
  expect(node.querySelector('[aria-label="Choose shop_returns"]')).toBeNull();
  await act(async () => node.querySelector('[aria-label="Describe policy preview for shop_returns"]').click());
  expect(node.textContent).toContain('Preview policy shop_returns from this message');
  const input = node.querySelector('textarea');
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
    .set.call(input, 'Preview a new returns paragraph for customers.');
    input.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  expect(assistant.send).toHaveBeenCalledWith('Preview a new returns paragraph for customers.',
    { choiceId, intent: 'policy_preview' });
  await act(async () => node.querySelector('[aria-label="Review policy deletion for shop_returns"]').click());
  expect(assistant.send).toHaveBeenCalledWith('Prepare to delete this policy.',
    { choiceId, intent: 'policy_delete' });
});

test('admin user card requires a chosen role or a current typed ban reason', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Find a user', status: 'done', reply: 'Owned user', hops: [],
    cards: [{ version: 1, kind: 'tenant_user', choiceId,
      title: 'owned_customer', detail: 'Customer account' }] }];
  await render('admin');
  const review = node.querySelector('[aria-label="Review role change for owned_customer"]');
  expect(review.disabled).toBe(true);
  const select = node.querySelector('[aria-label="New role for owned_customer"]');
  await act(async () => { select.value = 'merchant'; select.dispatchEvent(new Event('change', { bubbles: true })); });
  expect(review.disabled).toBe(false);
  await act(async () => review.click());
  expect(assistant.send).toHaveBeenCalledWith("Review changing this user's role to merchant.",
    { choiceId, intent: 'user_role', newRole: 'merchant' });
  await act(async () => node.querySelector('[aria-label="Write ban reason for owned_customer"]').click());
  expect(assistant.send).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Ban reason for owned_customer');
  const input = node.querySelector('textarea');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
      .set.call(input, 'Documented account abuse');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  expect(assistant.send).toHaveBeenLastCalledWith('Documented account abuse',
    { choiceId, intent: 'user_ban' });
  assistant.pending = { requestId: 'saved-request' };
  await render('admin');
  expect(node.querySelector('[aria-label="Write ban reason for owned_customer"]').disabled).toBe(true);
});

test('admin reset card stages exact choice and only latest saved handoff opens parent panel', async () => {
  const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const requestId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ sessionId, requestId, status: 'done', reply: 'Review reset', hops: [],
    cards: [{ version: 1, kind: 'tenant_user', choiceId, title: 'owned_customer', detail: 'Customer account' }],
    passwordResetSetup: { version: 1, kind: 'password_reset_setup', sessionId, requestId,
      choiceId, userId: 17, username: 'owned_customer', identityKind: 'teaching_persona',
      channel: 'bound_persona', scopeKey: 'owned admin scope' } }];
  await render('admin');
  await act(async () => node.querySelector('[aria-label="Review password reset for owned_customer"]').click());
  expect(assistant.send).toHaveBeenCalledWith('Review a password reset for this user.',
    { choiceId, intent: 'user_password_reset' });
  expect(node.querySelector('[aria-label="Password reset handoff"]')).not.toBeNull();
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Open protected password reset').click());
  expect(openStandaloneChatPasswordReset).toHaveBeenCalledWith({ sessionId, requestId, choiceId });
  assistant.pending = { requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd' };
  await render('admin');
  expect(node.querySelector('[aria-label="Password reset handoff"]')).toBeNull();
  assistant.pending = null;
  assistant.turns.push({ sessionId, requestId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    status: 'done', reply: 'A newer turn', hops: [], cards: [] });
  await render('admin');
  expect(node.querySelector('[aria-label="Password reset handoff"]')).toBeNull();
});

test('merchant product cards expose a database-backed review-list action', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', user: 'Find products',
    status: 'done', reply: 'Choose a product', hops: [], cards: [{ version: 1, kind: 'merchant_product', choiceId,
      title: 'Shop notebook', detail: 'USD 5 · 3 in stock' }] }];
  await render('merchant');
  const details = node.querySelector('[aria-label="View details for Shop notebook"]');
  expect(details).not.toBeNull();
  await act(async () => details.click());
  expect(assistant.send).toHaveBeenCalledWith('Show my selected product details.',
    { choiceId, intent: 'product_details' });
  assistant.send.mockClear();
  const action = node.querySelector(`[aria-label="View reviews for Shop notebook"]`);
  expect(action).not.toBeNull();
  await act(async () => action.click());
  expect(assistant.send).toHaveBeenCalledWith('Show reviews for this product', { choiceId });
});

test('merchant review cards expose explicit detail and decision intents only', async () => {
  const choiceId = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', sessionId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
    user: 'Show pending reviews', status: 'done', reply: 'Select a review', hops: [],
    cards: [{ version: 1, kind: 'merchant_review', choiceId, title: 'Review · Practice laptop · 2 stars',
      detail: 'pending · Customer review' }] }];
  await render('merchant');
  const group = node.querySelector('[aria-label="Merchant review choices"]');
  expect(group).not.toBeNull();
  expect(group.querySelector('[aria-label^="Choose "]')).toBeNull();
  expect(group.querySelector('button').textContent).toBe('View review');
  const buttons = group.querySelectorAll('button');
  expect(buttons).toHaveLength(3);
  await act(async () => buttons[1].click());
  expect(assistant.send).toHaveBeenCalledWith('Use my selected review action.', { choiceId, intent: 'review_approve' });
});

test('rejecting a merchant review stages context until a typed reason is submitted', async () => {
  const choiceId = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Show pending reviews', status: 'done', reply: 'Select a review', hops: [],
    cards: [{ version: 1, kind: 'merchant_review', choiceId, title: 'Review · Practice laptop · 2 stars',
      detail: 'pending · Customer review' }] }];
  await render('merchant');
  const group = node.querySelector('[aria-label="Merchant review choices"]');
  await act(async () => group.querySelectorAll('button')[2].click());
  expect(assistant.send).not.toHaveBeenCalled();
  expect(node.textContent).toContain('Rejecting review: Review · Practice laptop · 2 stars');
  const input = node.querySelector('textarea');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
      .set.call(input, 'Contains a prohibited claim');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(assistant.send).toHaveBeenCalledWith('Contains a prohibited claim', { choiceId, intent: 'review_reject' });
});

test('merchant review recovery mounts from saved decision state without transcript turns', async () => {
  localStorage.setItem('ss_review_decision_pending', JSON.stringify({
    operationId: '11111111-1111-4111-8111-111111111111', reviewId: 41, action: 'reject',
    reason: 'Contains a prohibited claim', scopeKey: 'scope',
    sourceSessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    sourceRequestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', expectedSnapshotSha256: 'a'.repeat(64),
  }));
  await render('merchant');
  expect(node.querySelector('button')).not.toBeNull();
  expect(node.textContent).toContain('Check saved review decision');
  localStorage.removeItem('ss_review_decision_pending');
});

test('merchant order cards show owned-line details without a product mutation affordance', async () => {
  const choiceId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Show my orders', status: 'done', reply: 'Select an order', hops: [],
    cards: [{ version: 1, kind: 'merchant_order', choiceId,
      title: 'Order #41 · Practice laptop', detail: 'paid · Your items: USD 18.00' }],
    orderDetail: { orderId: 41, status: 'paid', orderDate: '2026-10-10', merchantSubtotal: 18,
      items: [{ name: '<Practice laptop>', quantity: 2, price: 10,
        discountAmount: 2, lineTotal: 18 }] } }];
  await render('merchant');
  const group = node.querySelector('[aria-label="Merchant order choices"]');
  expect(group.textContent).toContain('Your items: USD 18.00');
  expect(group.textContent).toContain('Ask about this order');
  expect(group.querySelectorAll('button')).toHaveLength(1);
  expect(node.querySelector('[aria-label^="Use Order #41 in next message"]')).toBeNull();
  const detail = node.querySelector('[data-testid="merchant-order-detail"]');
  expect(detail.textContent).toContain('Your items in Order #41');
  expect(detail.textContent).toContain('<Practice laptop> · 2 × USD 10.00');
  expect(detail.textContent).toContain('Your items subtotal: USD 18.00');
  expect(detail.textContent).not.toContain('Customer');
  expect(node.querySelector('img')).toBeNull();
  await act(async () => group.querySelector('button').click());
  expect(assistant.send).toHaveBeenCalledWith('Use my selected option.', { choiceId });
});

test('merchant filtered order page offers a plain older-orders turn from only the latest page', async () => {
  const order = { version: 1, kind: 'merchant_order',
    choiceId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
    title: 'Order #41 · Practice laptop', detail: 'Your items: USD 18.00' };
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Orders containing a laptop', status: 'done', reply: 'Owned orders', hops: [],
    cards: [order], ordersPage: { nextCursor: 'Ab9_-', productName: '<Practice laptop>' } }];
  await render('merchant');
  expect(node.textContent).toContain('Orders containing <Practice laptop>');
  expect(node.querySelector('img')).toBeNull();
  const older = node.querySelector('[aria-label="Older merchant orders"]');
  expect(older).not.toBeNull();
  await act(async () => older.click());
  expect(assistant.send).toHaveBeenCalledWith('Show older orders', null,
    { intent: 'orders_next', sourceRequestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' });
  assistant.turns = [{ ...assistant.turns[0], ordersPage: {
    nextCursor: null, productName: 'Practice laptop' } }];
  await render('merchant');
  expect(node.textContent).toContain('Orders containing Practice laptop');
  expect(node.querySelector('[aria-label="Older merchant orders"]')).toBeNull();
  assistant.turns = [...assistant.turns, { ...assistant.turns[0],
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', ordersPage: null }];
  await render('merchant');
  expect(node.querySelector('[aria-label="Older merchant orders"]')).toBeNull();
});

test('merchant can send a typed stock instruction with the latest named product choice', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Find a laptop', status: 'done', reply: 'Current product', hops: [],
    cards: [{ version: 1, kind: 'merchant_product', choiceId,
      title: 'Practice laptop', detail: 'Current catalog item' }] }];
  await render('merchant');
  const select = node.querySelector('[aria-label="Use Practice laptop in next message"]');
  await act(async () => select.click());
  expect(node.textContent).toContain('Selected product for this message: Practice laptop');
  const input = node.querySelector('textarea');
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
    .set.call(input, 'Set its absolute stock to 5');
    input.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => { node.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })); });
  expect(assistant.send).toHaveBeenCalledWith('Set its absolute stock to 5', { choiceId });
  expect(node.textContent).not.toContain('Selected product for this message: Practice laptop');
});

test('a newer merchant turn retires an unsent product selection', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Find a laptop', status: 'done', reply: 'Current product', hops: [],
    cards: [{ version: 1, kind: 'merchant_product', choiceId,
      title: 'Practice laptop', detail: 'Current catalog item' }] }];
  await render('merchant');
  await act(async () => node.querySelector('[aria-label="Use Practice laptop in next message"]').click());
  expect(node.textContent).toContain('Selected product for this message');
  assistant.turns = [...assistant.turns, { requestId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    user: 'New question', status: 'in-flight', reply: '', hops: [] }];
  await render('merchant');
  expect(node.textContent).not.toContain('Selected product for this message');
});

test('merchant can clear a named selection before sending a plain question', async () => {
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  assistant.turns = [{ requestId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    user: 'Find a laptop', status: 'done', reply: 'Current product', hops: [],
    cards: [{ version: 1, kind: 'merchant_product', choiceId,
      title: 'Practice laptop', detail: 'Current catalog item' }] }];
  await render('merchant');
  await act(async () => node.querySelector('[aria-label="Use Practice laptop in next message"]').click());
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Clear selection').click());
  expect(node.textContent).not.toContain('Selected product for this message');
  const input = node.querySelector('textarea');
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')
    .set.call(input, 'How is the store doing?');
    input.dispatchEvent(new Event('input', { bubbles: true })); });
  await act(async () => node.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  expect(assistant.send).toHaveBeenCalledWith('How is the store doing?');
});

test('only the latest idle completed role turn supplies a Pricing proposal', async () => {
  const proposal = { version: 1, proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' };
  assistant.turns = [{ sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', user: 'Pricing please',
    status: 'done', reply: 'Saved proposal', hops: [], pricingProposal: proposal }];
  await render('merchant');
  expect(MerchantPricingConfirmation).toHaveBeenLastCalledWith(expect.objectContaining({
    proposal, sessionId: assistant.turns[0].sessionId, requestId: assistant.turns[0].requestId,
  }), undefined);
  assistant.turns = [...assistant.turns, { requestId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    user: 'A newer request', status: 'in-flight', reply: '', hops: [] }];
  assistant.status = 'thinking';
  await render('merchant');
  expect(MerchantPricingConfirmation).toHaveBeenLastCalledWith(expect.objectContaining({
    proposal: null, sessionId: null, requestId: null,
  }), undefined);
});

test('only the latest idle completed merchant turn supplies a listing edit proposal', async () => {
  const proposal = { version: 1, proposalId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' };
  assistant.turns = [{ sessionId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    requestId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', user: 'Edit listing',
    status: 'done', reply: 'Saved proposal', hops: [], listingProposal: proposal }];
  await render('merchant');
  expect(MerchantListingEditConfirmation).toHaveBeenLastCalledWith(expect.objectContaining({
    proposal, sessionId: assistant.turns[0].sessionId, requestId: assistant.turns[0].requestId,
  }), undefined);
  assistant.pending = { requestId: 'saved-id' };
  assistant.status = 'unresolved';
  await render('merchant');
  expect(MerchantListingEditConfirmation).toHaveBeenLastCalledWith(expect.objectContaining({
    proposal: null, sessionId: null, requestId: null,
  }), undefined);
});
