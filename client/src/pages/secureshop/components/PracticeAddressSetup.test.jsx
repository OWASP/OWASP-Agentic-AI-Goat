import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import PracticeAddressSetup from './PracticeAddressSetup.jsx';
import { attachShopStorage, SHOP_ADDRESS_SETUP_KEY } from '../utils/shopStorage.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const scope = 'c'.repeat(64), sha = 'd'.repeat(64);
const blank = { label: null, line1: '', line2: null, city: null, state: null, zip: null, phone: null, isDefault: false };
const currentFields = { ...blank, label: 'Home', line1: '1 Main St', city: 'Town' };
const json = value => ({ ok: true, status: 200, json: async () => value });
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
const click = text => act(async () => {
  const button = [...node.querySelectorAll('button')].find(value => value.textContent === text);
  if (!button) throw Error(`Button missing: ${text}`);
  button.click();
});
let root, node, values, detach;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis, 'crypto', { value: { subtle: webcrypto.subtle, randomUUID: () => id }, configurable: true });
  values = new Map();
  detach = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key), flush: async () => {} });
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
});
afterEach(async () => { await act(async () => root.unmount()); detach(); node.remove(); });

test('checkout reviews a complete address, ACKs only opaque identity, then resolves a lost POST by exact GET', async () => {
  let posts = 0, completed = false, confirmed = 0;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/address-form?action=create')) return json({ scopeKey: scope, action: 'create', choiceId: null,
      fields: blank, expectedSnapshotSha256: null, defaultSetSha256: sha });
    if (url.includes(`/operations/${id}`)) return json(completed
      ? { scopeKey: scope, operationId: id, status: 'completed', receipt: { version: 1, operationId: id,
        kind: 'address.create', status: 'completed', replayed: true,
        result: { addressId: 14, fieldsSha256: JSON.parse(values.get(SHOP_ADDRESS_SETUP_KEY)).fieldsSha256,
          addressSnapshotSha256: sha, defaultSetSha256: sha } } }
      : { scopeKey: scope, operationId: id, status: 'not_found' });
    if (url.endsWith('/commerce/addresses') && options.method === 'POST') {
      posts += 1;
      expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(true);
      const body = JSON.parse(options.body);
      expect(body).toEqual({ operationId: id, action: 'create', choiceId: null,
        expectedSnapshotSha256: null, defaultSetSha256: sha, fields: currentFields });
      expect(values.get(SHOP_ADDRESS_SETUP_KEY)).not.toContain('1 Main St');
      completed = true; throw Error('lost response');
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<PracticeAddressSetup entryPoint="checkout" authorityKey="A"
    initialFields={currentFields} transport={transport} onConfirmed={() => { confirmed += 1; }} />));
  await settle();
  expect(node.querySelector('input[aria-label="Street address"]').value).toBe('1 Main St');
  await click('Review address'); await click('Confirm address save'); await settle();
  expect(posts).toBe(1); expect(confirmed).toBe(1);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(false);
  expect(node.textContent).toContain('Address saved.');
});

test('chat has no save affordance without exact completed-turn handoff', async () => {
  await act(async () => root.render(<PracticeAddressSetup entryPoint="chat" setup={null}
    authorityKey="A" transport={jest.fn()} />));
  await settle();
  expect(node.querySelector('button')).toBeNull();
});

const savedCreate = (operationId = id) => ({ version: 1, scopeKey: scope, operationId,
  action: 'create', choiceId: null, expectedSnapshotSha256: null,
  defaultSetSha256: sha, fieldsSha256: sha });
const completedCreate = saved => ({ scopeKey: saved.scopeKey, operationId: saved.operationId,
  status: 'completed', receipt: { version: 1, operationId: saved.operationId,
    kind: 'address.create', status: 'completed', replayed: true,
    result: { addressId: 14, fieldsSha256: saved.fieldsSha256,
      addressSnapshotSha256: sha, defaultSetSha256: sha } } });

test('blocked recovery handler preserves the saved reference and performs no transport or confirmation', async () => {
  const saved = savedCreate(); values.set(SHOP_ADDRESS_SETUP_KEY, JSON.stringify(saved));
  const transport = jest.fn(), confirmed = jest.fn();
  await act(async () => root.render(<PracticeAddressSetup setup={null} entryPoint="chat"
    authorityKey="A" interactionBlocked transport={transport} onConfirmed={confirmed} />));
  const button = node.querySelector('button'); expect(button.disabled).toBe(true);
  // Invoke the real rendered handler directly as well: the disabled DOM alone is not the guard.
  const propsKey = Object.keys(button).find(key => key.startsWith('__reactProps$'));
  expect(propsKey).toBeDefined();
  await act(async () => button[propsKey].onClick());
  expect(transport).not.toHaveBeenCalled(); expect(confirmed).not.toHaveBeenCalled();
  expect(JSON.parse(values.get(SHOP_ADDRESS_SETUP_KEY))).toEqual(saved);
  expect(node.textContent).toContain('Wait for the current conversation');
});

test('null-handoff saved recovery survives parent rerender and authority renewal with one exact GET only', async () => {
  const saved = savedCreate(); values.set(SHOP_ADDRESS_SETUP_KEY, JSON.stringify(saved));
  const confirmed = jest.fn();
  const transport = jest.fn(async (url, options) => {
    expect(url).toBe(`/api/secureshop/customer/commerce/operations/${id}`);
    expect(options.method).toBe('GET'); expect(options.signal.aborted).toBe(false);
    return json(completedCreate(saved));
  });
  const Parent = ({ authority, revision }) => <div data-revision={revision}>
    <PracticeAddressSetup setup={null} entryPoint="chat" authorityKey={authority}
      transport={transport} onConfirmed={confirmed} /></div>;
  await act(async () => root.render(<Parent authority="A" revision={1} />));
  await act(async () => root.render(<Parent authority="A" revision={2} />));
  await act(async () => root.render(<Parent authority="B" revision={3} />));
  expect(transport).not.toHaveBeenCalled();
  expect(node.querySelector('button').disabled).toBe(false);
  await click('Check saved address'); await settle();
  expect(transport).toHaveBeenCalledTimes(1); expect(confirmed).toHaveBeenCalledTimes(1);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(false);
  expect(node.textContent).toContain('Address saved.');
  expect(node.querySelector('button')).toBeNull();
});

test('late old-authority recovery cannot clear a newer saved reference or publish confirmation', async () => {
  const old = savedCreate(), newer = savedCreate(choiceId);
  values.set(SHOP_ADDRESS_SETUP_KEY, JSON.stringify(old));
  let releaseOld, oldSignal; const confirmed = jest.fn();
  const transport = jest.fn((url, options) => {
    expect(options.method).toBe('GET');
    if (url.endsWith(`/${id}`)) {
      oldSignal = options.signal;
      return new Promise(resolve => { releaseOld = () => resolve(json(completedCreate(old))); });
    }
    expect(url).toBe(`/api/secureshop/customer/commerce/operations/${choiceId}`);
    return Promise.resolve(json(completedCreate(newer)));
  });
  const view = authority => <PracticeAddressSetup setup={null} entryPoint="chat"
    authorityKey={authority} transport={transport} onConfirmed={confirmed} />;
  await act(async () => root.render(view('old')));
  await click('Check saved address');
  expect(transport).toHaveBeenCalledTimes(1);
  values.set(SHOP_ADDRESS_SETUP_KEY, JSON.stringify(newer));
  await act(async () => root.render(view('new')));
  expect(oldSignal.aborted).toBe(true);
  await act(async () => releaseOld()); await settle();
  expect(JSON.parse(values.get(SHOP_ADDRESS_SETUP_KEY))).toEqual(newer);
  expect(confirmed).not.toHaveBeenCalled();
  expect(node.querySelector('button').disabled).toBe(false);
  await click('Check saved address'); await settle();
  expect(transport).toHaveBeenCalledTimes(2); expect(confirmed).toHaveBeenCalledTimes(1);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(false);
});

test('protected edit preflight supplies full current fields and an opaque choice; unknown outcome stays GET-only', async () => {
  let posts = 0;
  const setup = { version: 1, kind: 'address_setup', action: 'update', choiceId, draft: { city: 'New Town' } };
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith(`/address-form?action=update&choiceId=${choiceId}`)) return json({ scopeKey: scope,
      action: 'update', choiceId, fields: currentFields, expectedSnapshotSha256: sha, defaultSetSha256: sha });
    if (url.includes(`/operations/${id}`)) return json({ scopeKey: scope, operationId: id, status: 'not_found' });
    if (url.endsWith('/commerce/addresses') && options.method === 'POST') {
      posts += 1; expect(JSON.parse(options.body).fields).toEqual({ ...currentFields, city: 'New Town' });
      return { ok: false, status: 503 };
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<PracticeAddressSetup entryPoint="chat" setup={setup}
    authorityKey="turn-1" transport={transport} />)); await settle();
  expect(node.querySelector('input[aria-label="Street address"]').value).toBe('1 Main St');
  expect(node.querySelector('input[aria-label="City"]').value).toBe('New Town');
  await click('Review address');
  expect(node.querySelector('[aria-label="Address changes to confirm"]').textContent).toContain('Town → New Town');
  await click('Confirm address update'); await settle();
  expect(posts).toBe(1); expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(true);
  await click('Check saved address'); await settle();
  expect(posts).toBe(1); expect(node.textContent).toContain('will not be retried');
});

test('a delayed parent ACK after authority renewal never sends the address', async () => {
  detach(); let releaseAck;
  detach = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => new Promise(resolve => { releaseAck = resolve; }) });
  let posts = 0;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/address-form?action=create')) return json({ scopeKey: scope, action: 'create', choiceId: null,
      fields: blank, expectedSnapshotSha256: null, defaultSetSha256: sha });
    if (url.endsWith('/commerce/addresses') && options.method === 'POST') posts += 1;
    return json({ scopeKey: scope, operationId: id, status: 'not_found' });
  });
  const view = key => <PracticeAddressSetup entryPoint="checkout" authorityKey={key}
    initialFields={currentFields} transport={transport} />;
  await act(async () => root.render(view('old'))); await settle();
  await click('Review address'); await click('Confirm address save'); await settle();
  await act(async () => root.render(view('renewed')));
  await act(async () => releaseAck()); await settle();
  expect(posts).toBe(0);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(true);
});

test('only a bound stale receipt releases an edit for a fresh review, without claiming success', async () => {
  let posts = 0, stale = false, confirmed = 0, staleCalls = 0;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith(`/address-form?action=update&choiceId=${choiceId}`)) return json({ scopeKey: scope,
      action: 'update', choiceId, fields: currentFields, expectedSnapshotSha256: sha, defaultSetSha256: sha });
    if (url.includes(`/operations/${id}`)) return json(stale
      ? { scopeKey: scope, operationId: id, status: 'completed', receipt: { version: 1,
        operationId: id, kind: 'address.update', status: 'stale', replayed: true,
        result: { fieldsSha256: JSON.parse(values.get(SHOP_ADDRESS_SETUP_KEY)).fieldsSha256 } } }
      : { scopeKey: scope, operationId: id, status: 'not_found' });
    if (url.endsWith('/commerce/addresses') && options.method === 'POST') {
      posts += 1; stale = true; return { ok: false, status: 409 };
    }
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<PracticeAddressSetup entryPoint="account" action="update"
    choiceId={choiceId} authorityKey="customer" transport={transport}
    onConfirmed={() => { confirmed += 1; }} onStale={() => { staleCalls += 1; }} />)); await settle();
  await click('Review address'); await click('Confirm address update'); await settle();
  expect(posts).toBe(1); expect(confirmed).toBe(0); expect(staleCalls).toBe(1);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(false);
  expect(node.textContent).toContain('Start a fresh review');
  expect(node.textContent).not.toContain('Confirm address update');
});

test('a terminal stale receipt on the pre-POST exact GET suppresses the address POST', async () => {
  let posts = 0, staleCalls = 0;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/address-form?action=create')) return json({ scopeKey: scope, action: 'create',
      choiceId: null, fields: blank, expectedSnapshotSha256: null, defaultSetSha256: sha });
    if (url.includes(`/operations/${id}`)) return json({ scopeKey: scope, operationId: id,
      status: 'completed', receipt: { version: 1, operationId: id, kind: 'address.create',
        status: 'stale', replayed: true,
        result: { fieldsSha256: JSON.parse(values.get(SHOP_ADDRESS_SETUP_KEY)).fieldsSha256 } } });
    if (url.endsWith('/commerce/addresses') && options.method === 'POST') posts += 1;
    throw Error(`Unexpected ${url}`);
  });
  await act(async () => root.render(<PracticeAddressSetup entryPoint="checkout" authorityKey="A"
    initialFields={currentFields} transport={transport} onStale={() => { staleCalls += 1; }} />)); await settle();
  await click('Review address'); await click('Confirm address save'); await settle();
  expect(posts).toBe(0); expect(staleCalls).toBe(1);
  expect(values.has(SHOP_ADDRESS_SETUP_KEY)).toBe(false);
});
