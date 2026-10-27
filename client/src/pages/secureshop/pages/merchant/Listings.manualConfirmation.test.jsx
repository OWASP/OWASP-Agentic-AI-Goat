import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import MerchantListings from './Listings';

const server = require('../../../../../../server/services/secureshopManualListingContract');
const listing = { name: 'New merchant listing', description: 'Raw <b>description</b>', price: 12.34,
  category: null, images: ['https://images.test/a.png'], templateSource: '{{ title }}' };
const preview = server.makeManualListingPreview({ version: 1, origin: 'manual', kind: 'create', listing,
  currency: 'USD', initialStock: 0, status: 'active', scopeKey: 'b'.repeat(64) });
const toast = { success: jest.fn(), error: jest.fn(), warn: jest.fn(), info: jest.fn() };
let mockAuth, mockManual;
jest.mock('./useBoundListings', () => ({ useBoundListings: () => ({ attached: true, ready: true, busy: false, references: {} }) }));
jest.mock('./useManualListings', () => ({ useManualListings: () => mockManual }));
jest.mock('../../context/AuthContext.jsx', () => ({ useAuth: () => mockAuth }));
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('framer-motion', () => {
  const ReactModule = require('react');
  const element = tag => ReactModule.forwardRef(function MotionElement(
    { initial, animate, exit, transition, whileHover, whileTap, ...props }, ref,
  ) { return ReactModule.createElement(tag, { ...props, ref }); });
  return { motion: { div: element('div'), tr: element('tr') },
    AnimatePresence: ({ children }) => <>{children}</>, useReducedMotion: () => true };
});
const response = body => ({ ok: true, json: async () => body });
let root, container;
const view = () => <MemoryRouter><MerchantListings /></MemoryRouter>;
beforeEach(async () => {
  jest.clearAllMocks(); global.IS_REACT_ACT_ENVIRONMENT = true;
  mockAuth = { user: { id: 12, role: 'merchant' }, token: 'owner-a' };
  mockManual = { attached: true, ready: true, checking: false, error: null, references: {}, terminal: {}, busy: false,
    preview: jest.fn(async () => preview), confirm: jest.fn(async () => ({ status: 'completed', productId: 19 })),
    recover: jest.fn(), clearCompleted: jest.fn(), retryReadiness: jest.fn() };
  global.fetch = jest.fn(url => Promise.resolve(url === '/api/secureshop/categories'
    ? response({ categories: [] }) : response({ products: [], total: 0, pages: 1, categories: [] })));
  container = document.createElement('div'); root = createRoot(container); document.body.appendChild(container);
  await act(async () => root.render(view()));
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });
const setControl = async (control, value) => act(async () => {
  const prototype = control instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(prototype, 'value').set.call(control, value);
  control.dispatchEvent(new Event('input', { bubbles: true }));
});
async function stage() {
  await act(async () => container.querySelector('[data-testid="listings-create-cta"]').click());
  const form = container.querySelector('form');
  await setControl(form.querySelectorAll('input[type="text"]')[0] || form.querySelector('input'), listing.name);
  await setControl(form.querySelectorAll('textarea')[0], listing.description);
  await setControl(form.querySelectorAll('textarea')[1], listing.templateSource);
  await setControl(form.querySelector('input[type="number"]'), String(listing.price));
  await setControl([...form.querySelectorAll('input')].at(-1), listing.images[0]);
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
}

test('form submit previews only; Cancel has no effect and Confirm sends immutable full consequence', async () => {
  await stage();
  expect(mockManual.preview).toHaveBeenCalledWith('create', listing, undefined);
  expect(mockManual.confirm).not.toHaveBeenCalled();
  expect(global.fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
  expect(container.textContent).toContain('initial stock 0 and a USD price');
  expect(container.textContent).toContain('Raw <b>description</b>');
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Cancel'
    && button.closest('[role="dialog"]')?.textContent.includes('REVIEW LISTING CONSEQUENCES')).click());
  expect(mockManual.confirm).not.toHaveBeenCalled();
  expect(container.textContent).not.toContain('REVIEW LISTING CONSEQUENCES');
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Confirm create').click());
  expect(mockManual.confirm).toHaveBeenCalledTimes(1);
  expect(mockManual.confirm).toHaveBeenCalledWith('create', preview);
  expect(container.querySelector('form')).toBeNull();
  expect(toast.success).toHaveBeenCalledWith('Created listing #19');
});

test('changing the form or authority discards reviewed consequences before confirmation', async () => {
  await stage();
  await setControl(container.querySelector('form input'), 'Changed name');
  expect(container.textContent).not.toContain('REVIEW LISTING CONSEQUENCES');
  expect(mockManual.confirm).not.toHaveBeenCalled();
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  mockAuth = { user: { id: 99, role: 'merchant' }, token: 'owner-b' };
  await act(async () => root.render(view()));
  expect(container.textContent).not.toContain('REVIEW LISTING CONSEQUENCES');
  expect(mockManual.confirm).not.toHaveBeenCalled();
});

test('listing-view A→B→A cannot restore a stale review or leave the editor inert', async () => {
  await stage();
  const search = container.querySelector('[data-testid="listings-search"]');
  await setControl(search, 'other view');
  expect(container.textContent).not.toContain('REVIEW LISTING CONSEQUENCES');
  await setControl(search, '');
  expect(container.textContent).not.toContain('REVIEW LISTING CONSEQUENCES');
  expect(container.querySelector('form').closest('[role="dialog"]').hasAttribute('inert')).toBe(false);
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  expect(container.textContent).toContain('REVIEW LISTING CONSEQUENCES');
  expect(mockManual.confirm).not.toHaveBeenCalled();
});

test('manual readiness failure disables direct CRUD fallback', async () => {
  mockManual = { ...mockManual, ready: false, error: 'Manual listing readiness unavailable.' };
  await act(async () => root.render(view()));
  await act(async () => container.querySelector('[data-testid="listings-create-cta"]').click());
  await setControl(container.querySelector('form input'), listing.name);
  expect(container.querySelector('form button[type="submit"]').disabled).toBe(true);
  expect(container.textContent).toContain('Manual listing readiness unavailable.');
  expect(global.fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});

test('uncertain confirmation keeps a saved read-only recovery affordance and never auto-repeats', async () => {
  mockManual.confirm.mockRejectedValue(Error('Manual listing outcome unresolved. Check the saved operation.'));
  await stage();
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Confirm create').click());
  expect(toast.error).toHaveBeenCalledWith('Manual listing outcome unresolved. Check the saved operation.');
  expect(container.textContent).not.toContain('REVIEW LISTING CONSEQUENCES');
  mockManual = { ...mockManual, references: { manualCreate: { operationId: 'saved-id' } },
    recover: jest.fn(async () => ({ status: 'not_found' })) };
  await act(async () => root.render(view()));
  expect(container.textContent).toContain('Saved manual create operation');
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved manual create').click());
  expect(mockManual.recover).toHaveBeenCalledWith('create');
  expect(mockManual.confirm).toHaveBeenCalledTimes(1);
  expect(toast.warn).toHaveBeenCalledWith(expect.stringContaining('remains unresolved'));
  expect(global.fetch.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});
