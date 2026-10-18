import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Account from './Account';

let mockToken = 'bound-persona-token';
let boundAddressMode = false;
const toast = { success: jest.fn(), error: jest.fn() };

jest.mock('framer-motion', () => ({
  motion: { section: ({ children, initial, animate, transition, ...props }) => (
    <section {...props}>{children}</section>
  ) },
}));
jest.mock('../context/AuthContext', () => ({
  useAuth: () => ({ user: { id: 7, username: 'student_customer', role: 'customer' },
    logout: jest.fn() }),
}));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../components/Button.jsx', () => ({ children, icon, loading, ...props }) => (
  <button {...props}>{icon}{children}</button>
));
jest.mock('../components/Card.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('../components/Input.jsx', () => ({ label, helper, ...props }) => <input aria-label={label} {...props} />);
jest.mock('../components/Badge.jsx', () => ({ children }) => <span>{children}</span>);
jest.mock('../components/UploadZone.jsx', () => () => null);
jest.mock('../utils/shopStorage.mjs', () => ({
  SHOP_ADDRESS_SETUP_KEY: 'secureshop.address-setup.operation.v1',
  shopStorage: { getItem: key => key === 'secureshop_v2_token' ? mockToken : null,
    setItem: jest.fn(), removeItem: jest.fn() }, flushShopStorage: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => boundAddressMode ? { standalone: true } : null }));

let container;
let root;

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status,
    json: jest.fn().mockResolvedValue(body) };
}

function deferred() {
  let resolve;
  const promise = new Promise(value => { resolve = value; });
  return { promise, resolve };
}

async function settle() {
  await act(async () => {
    await Promise.resolve();
    await Promise.resolve();
    await Promise.resolve();
  });
}

async function openTab(label) {
  const tab = [...container.querySelectorAll('[role="tab"]')]
    .find(element => element.textContent.includes(label));
  await act(async () => tab.click());
  await settle();
}

beforeEach(async () => {
  jest.clearAllMocks();
  mockToken = 'bound-persona-token';
  boundAddressMode = false;
  global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => root.render(<Account />));
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

test('load failures render the server error instead of a false empty state', async () => {
  global.fetch = jest.fn().mockResolvedValue(response({ error: 'address store unavailable' }, 503));
  await openTab('Addresses');
  expect(container.querySelector('[role="alert"]')?.textContent)
    .toContain('Unable to load addresses: address store unavailable');
  expect(container.textContent).not.toContain('No addresses yet');
});

test('bound customer Account chooses an owned opaque address for edit without numeric ID matching', async () => {
  boundAddressMode = true;
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', scopeKey = 'c'.repeat(64), sha = 'd'.repeat(64);
  const fields = { label: 'Home', line1: '1 Main St', line2: null, city: 'Town', state: null,
    zip: null, phone: null, isDefault: false };
  global.fetch = jest.fn(async url => {
    if (url.endsWith('/customer/commerce/addresses')) return response({ scopeKey,
      cards: [{ version: 1, kind: 'address', choiceId, title: 'Home', detail: '1 Main St' }],
      addresses: [{ addressId: 11, choiceId, fields }] });
    if (url.endsWith(`/address-form?action=update&choiceId=${choiceId}`)) return response({ scopeKey,
      action: 'update', choiceId, fields, expectedSnapshotSha256: sha, defaultSetSha256: sha });
    throw Error(`Unexpected ${url}`);
  });
  await openTab('Addresses');
  expect(container.textContent).toContain('1 Main St');
  expect(container.textContent).toContain('Town');
  expect(container.textContent).toContain('Delete');
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Edit').click());
  await settle();
  expect(container.querySelector('input[aria-label="Street address"]').value).toBe('1 Main St');
  expect(global.fetch).toHaveBeenCalledWith(expect.stringContaining(`choiceId=${choiceId}`), expect.any(Object));
  expect(container.textContent).not.toContain('Address ID');
});

test('bound customer Account retains the original Delete action using the protected current address row', async () => {
  boundAddressMode = true;
  const choiceId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', scopeKey = 'c'.repeat(64);
  const fields = { label: 'Home', line1: '1 Main St', line2: 'Suite 2', city: 'Town', state: 'CA',
    zip: '90210', phone: '555-0100', isDefault: true };
  let present = true;
  global.fetch = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/customer/commerce/addresses')) return response({ scopeKey,
      cards: present ? [{ version: 1, kind: 'address', choiceId, title: 'Home', detail: '1 Main St' }] : [],
      addresses: present ? [{ addressId: 11, choiceId, fields }] : [] });
    if (url.endsWith('/v2/auth/users/me/addresses/11') && options.method === 'DELETE') {
      present = false; return response({ ok: true });
    }
    throw Error(`Unexpected ${url}`);
  });
  await openTab('Addresses');
  expect(container.textContent).toContain('Suite 2');
  expect(container.textContent).toContain('90210');
  expect(container.textContent).toContain('555-0100');
  expect(container.textContent).toContain('Default');
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Delete').click());
  await settle();
  expect(global.fetch).toHaveBeenCalledWith('/api/secureshop/v2/auth/users/me/addresses/11',
    expect.objectContaining({ method: 'DELETE' }));
  expect(toast.success).toHaveBeenCalledWith('Address deleted');
  expect(container.textContent).toContain('No addresses yet');
});

test('a failed delete cannot report success or reload the inventory', async () => {
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response({ addresses: [{ id: 11, label: 'Home', line1: '1 Main St' }] }))
    .mockResolvedValueOnce(response({ ok: true, error: 'write unavailable' }, 503));
  await openTab('Addresses');
  const remove = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Delete'));
  await act(async () => remove.click());
  await settle();
  expect(toast.error).toHaveBeenCalledWith('Delete failed: write unavailable');
  expect(toast.success).not.toHaveBeenCalled();
  expect(global.fetch).toHaveBeenCalledTimes(2);
});

test('a failed save keeps the editor open and cannot report success', async () => {
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response({ addresses: [] }))
    .mockResolvedValueOnce(response({ ok: true }, 500));
  await openTab('Addresses');
  const add = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Add address'));
  await act(async () => add.click());
  const line1 = container.querySelector('input[aria-label="Street address"]');
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
    setter.call(line1, '1 Main St');
    line1.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const submit = [...container.querySelectorAll('button')]
    .find(element => element.textContent === 'Add');
  await act(async () => submit.click());
  await settle();
  expect(toast.error).toHaveBeenCalledWith('Save failed: save failed');
  expect(toast.success).not.toHaveBeenCalled();
  expect(container.querySelector('[role="dialog"]')).not.toBeNull();
  expect(global.fetch).toHaveBeenCalledTimes(2);
});

test('a delayed delete cannot toast or reload after the address tab unmounts', async () => {
  const pending = deferred();
  global.fetch = jest.fn()
    .mockResolvedValueOnce(response({ addresses: [{ id: 11, label: 'Home', line1: '1 Main St' }] }))
    .mockReturnValueOnce(pending.promise);
  await openTab('Addresses');
  const remove = [...container.querySelectorAll('button')]
    .find(element => element.textContent.includes('Delete'));
  await act(async () => remove.click());
  await openTab('Profile');
  await act(async () => pending.resolve(response({ ok: true })));
  await settle();
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).not.toHaveBeenCalled();
  expect(global.fetch.mock.calls.filter(([url]) => url.includes('/addresses'))).toHaveLength(2);
});

test('a delayed load cannot surface an error after the address tab unmounts', async () => {
  const pending = deferred();
  global.fetch = jest.fn().mockReturnValueOnce(pending.promise);
  await openTab('Addresses');
  await openTab('Profile');
  await act(async () => pending.resolve(response({ error: 'late failure' }, 503)));
  await settle();
  expect(toast.error).not.toHaveBeenCalled();
  expect(container.querySelector('[role="alert"]')).toBeNull();
});

test('a delayed load from an old token cannot replace the current address state', async () => {
  const pending = deferred();
  global.fetch = jest.fn().mockReturnValueOnce(pending.promise);
  await openTab('Addresses');
  mockToken = 'replacement-persona-token';
  await act(async () => pending.resolve(response({
    addresses: [{ id: 11, label: 'Old identity', line1: '1 Main St' }],
  })));
  await settle();
  expect(container.textContent).not.toContain('Old identity');
  expect(container.querySelector('[role="alert"]')).toBeNull();
});
