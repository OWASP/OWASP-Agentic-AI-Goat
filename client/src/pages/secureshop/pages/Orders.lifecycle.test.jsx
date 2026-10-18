import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import Orders from './Orders';
let mockUserId = 7;
let mockToken = "first";
let mockBridgeMetadata = {};
const mockRequestRefundTicket = jest.fn();
jest.mock('../context/AuthContext', () => ({ useAuth: () => ({ user: { id: mockUserId }, token: mockToken }) }));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => ({ info: jest.fn(), success: jest.fn(), error: jest.fn() }) }));
jest.mock('framer-motion', () => ({ useReducedMotion: () => true, motion: { tr: ({ children, initial, animate, transition, ...props }) => <tr {...props}>{children}</tr> } }));
jest.mock('../components/Button.jsx', () => ({ children, onClick, disabled }) => <button onClick={onClick} disabled={disabled}>{children}</button>);
jest.mock('../components/Dialog.jsx', () => ({ open, title, children, onClose }) => open ? <section role="dialog"><h2>{title}</h2><button onClick={onClose}>Dismiss</button>{children}</section> : null);
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => mockBridgeMetadata }));
jest.mock('../utils/refundRequest.mjs', () => ({ requestRefundTicket: (...args) => mockRequestRefundTicket(...args) }));
import { SHOP_REFUND_KEY } from '../utils/shopStorage.mjs';
const response = body => ({ ok: true, json: async () => body });
const order = id => ({ id, status: 'pending', order_date: '2026-09-18', total_amount: 10 });
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };
let root, container, first, second;
const render = () => root.render(<MemoryRouter><Orders /></MemoryRouter>);
const click = async text => { await act(async () => [...container.querySelectorAll('button')].find(b => b.textContent === text).click()); };
beforeEach(async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true; mockUserId = 7; mockToken = "first";
  mockBridgeMetadata = {};
  mockRequestRefundTicket.mockReset();
  localStorage.removeItem(SHOP_REFUND_KEY);
  first = deferred(); second = deferred();
  global.fetch = jest.fn(url => url.endsWith('/1') ? first.promise : url.endsWith('/2') ? second.promise : Promise.resolve(response({ orders: [order(1), order(2)] })));
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
  await act(async () => render());
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); localStorage.removeItem(SHOP_REFUND_KEY); });
async function view(index) { await act(async () => [...container.querySelectorAll('button')].filter(b => b.textContent === 'View')[index].click()); }
async function enterReason(value) {
  const textarea = container.querySelector('#ss-refund-reason');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set.call(textarea, value);
    textarea.dispatchEvent(new Event('input', { bubbles: true }));
  });
}
test('late detail response cannot reopen a dismissed dialog', async () => {
  await view(0); await click('Dismiss');
  await act(async () => first.resolve(response({ order: order(1), items: [] })));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
});
test('older detail response cannot replace the latest selection', async () => {
  await view(0); await view(1);
  await act(async () => second.resolve(response({ order: order(2), items: [] })));
  await act(async () => first.resolve(response({ order: order(1), items: [] })));
  expect(container.querySelector('[role="dialog"] h2').textContent).toBe('Order #2');
});
test('persona changes discard pending details', async () => {
  await view(0); mockUserId = 8; await act(async () => render());
  await act(async () => first.resolve(response({ order: order(1), items: [] })));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
});

test('HTTP failure is not an empty order history and Retry reloads', async () => {
  global.fetch=jest.fn().mockResolvedValueOnce({ok:false,json:async()=>({error:'unavailable'})})
    .mockResolvedValueOnce(response({orders:[order(3)]}));
  mockToken='retry-session';await act(async()=>render());
  expect(container.querySelector('[role="alert"]').textContent).toContain('Could not load orders');
  expect(container.textContent).not.toContain('No orders yet');
  await click('Retry');
  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect(container.textContent).toContain('1 of 1 orders');
});
test('same-persona session replacement discards pending details',async()=>{
  await view(0);mockToken='replacement';await act(async()=>render());
  await act(async()=>first.resolve(response({order:order(1),items:[]})));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
});

test('refund needs a reason and a matching ticket result before showing filed status', async () => {
  mockRequestRefundTicket.mockResolvedValue({ ticketId: 71, orderId: 1 });
  await view(0);
  expect([...container.querySelectorAll('button')].find(b => b.textContent === 'Request refund').disabled).toBe(true);
  await enterReason('  Item arrived damaged  ');
  await click('Request refund');
  expect(mockRequestRefundTicket).toHaveBeenCalledWith(expect.objectContaining({
    userId: 7, orderId: 1, reason: 'Item arrived damaged',
  }));
  expect(container.querySelector('[role="dialog"]').textContent).toContain('ticket #71');
  await click('Dismiss');
  expect(container.textContent).toContain('Refund request filed · ticket #71');
  await view(0);
  expect([...container.querySelectorAll('button')].find(b => b.textContent === 'Request refund').disabled).toBe(true);
  expect(mockRequestRefundTicket).toHaveBeenCalledTimes(1);
});

test('a clean model turn without a refund effect stays visibly unconfirmed', async () => {
  mockRequestRefundTicket.mockRejectedValue(Object.assign(new Error('no tool effect'), { code: 'not_confirmed' }));
  await view(0);
  await enterReason('Product did not work');
  await click('Request refund');
  await click('Dismiss');
  expect(container.textContent).toContain('No refund ticket was confirmed in this run');
  expect(container.textContent).not.toContain('Refund request filed');
});

test('rapid duplicate clicks dispatch one request, and identity replacement hides late results', async () => {
  const pending = deferred();
  mockRequestRefundTicket.mockReturnValue(pending.promise);
  await view(0);
  await enterReason('Damaged item');
  const button = [...container.querySelectorAll('button')].find(b => b.textContent === 'Request refund');
  act(() => { button.click(); button.click(); });
  expect(mockRequestRefundTicket).toHaveBeenCalledTimes(1);
  expect(container.querySelector('[role="dialog"]').textContent).toContain('Requesting a refund ticket');
  mockToken = 'replacement';
  await act(async () => render());
  await act(async () => pending.resolve({ ticketId: 72, orderId: 1 }));
  expect(container.textContent).not.toContain('ticket #72');
});

test('bound refund saves exact opaque reference before chat and verifies ticket by readback after reload', async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true,
    value: () => '22222222-2222-4222-8222-222222222222' });
  try {
    mockBridgeMetadata = { boundReviews: true };
    global.fetch = jest.fn(url => url.includes('/refund/operations/')
      ? Promise.resolve(response({ requestId: '22222222-2222-4222-8222-222222222222',
        status: 'saved', ticketId: '71', orderId: 1 }))
      : url.endsWith('/1') ? first.promise : Promise.resolve(response({ orders: [order(1), order(2)] })));
    mockRequestRefundTicket.mockImplementation(async ({ beforeChat }) => {
      await beforeChat('11111111-1111-4111-8111-111111111111');
      expect(JSON.parse(localStorage.getItem(SHOP_REFUND_KEY))).toEqual({ version: 1, references: [{
        orderId: 1, sessionId: '11111111-1111-4111-8111-111111111111',
        requestId: '22222222-2222-4222-8222-222222222222',
      }] });
      return { ticketId: 71, orderId: 1 };
    });
    await act(async () => render());
    await view(0);
    await enterReason('Damaged product');
    await click('Request refund');
    expect(container.textContent).toContain('Refund request filed · ticket #71');
    expect(mockRequestRefundTicket).toHaveBeenCalledTimes(1);
    await act(async () => root.unmount());
    root = createRoot(container);
    await act(async () => render());
    await view(0);
    expect(container.querySelector('[role="dialog"]').textContent).toContain('Refund outcome unconfirmed');
    await click('Check saved refund');
    expect(container.querySelector('[role="dialog"]').textContent).toContain('Refund request filed · ticket #71');
    expect(mockRequestRefundTicket).toHaveBeenCalledTimes(1);
  } finally {
    if (original) Object.defineProperty(globalThis.crypto, 'randomUUID', original);
    else delete globalThis.crypto.randomUUID;
  }
});

test('unconfirmed bound readback retains reference and blocks another refund POST for that order', async () => {
  const original = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true,
    value: () => '22222222-2222-4222-8222-222222222222' });
  try {
    mockBridgeMetadata = { boundReviews: true };
    global.fetch = jest.fn(url => url.includes('/refund/operations/')
      ? Promise.resolve(response({ requestId: '22222222-2222-4222-8222-222222222222', status: 'unconfirmed' }))
      : url.endsWith('/1') ? first.promise : Promise.resolve(response({ orders: [order(1), order(2)] })));
    mockRequestRefundTicket.mockImplementation(async ({ beforeChat }) => {
      await beforeChat('11111111-1111-4111-8111-111111111111');
      return { ticketId: 71, orderId: 1 };
    });
    await act(async () => render());
    await view(0);
    await enterReason('Damaged product');
    await click('Request refund');
    expect(container.textContent).toContain('Refund outcome unconfirmed');
    expect(container.textContent).not.toContain('Refund request filed');
    expect(localStorage.getItem(SHOP_REFUND_KEY)).not.toBeNull();
    expect([...container.querySelectorAll('button')].find(b => b.textContent === 'Request refund').disabled).toBe(true);
    await click('Check saved refund');
    expect(mockRequestRefundTicket).toHaveBeenCalledTimes(1);
  } finally {
    if (original) Object.defineProperty(globalThis.crypto, 'randomUUID', original);
    else delete globalThis.crypto.randomUUID;
  }
});

test.each(['replaced', 'removed'])('bound Orders rereads the exact saved refund after ACK when it is %s', async change => {
  const original = Object.getOwnPropertyDescriptor(globalThis.crypto, 'randomUUID');
  const sessionId = '11111111-1111-4111-8111-111111111111';
  const requestId = '22222222-2222-4222-8222-222222222222';
  let savedReference;
  let verificationError;
  let reachedDispatch = false;
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true, value: () => requestId });
  try {
    mockBridgeMetadata = { boundReviews: true };
    global.fetch = jest.fn(url => url.includes('/refund/operations/')
      ? Promise.resolve(response({ requestId, status: 'unconfirmed' }))
      : url.endsWith('/1') ? first.promise : Promise.resolve(response({ orders: [order(1), order(2)] })));
    mockRequestRefundTicket.mockImplementation(async ({ beforeChat, verifyBeforeChat }) => {
      await beforeChat(sessionId);
      savedReference = JSON.parse(localStorage.getItem(SHOP_REFUND_KEY)).references[0];
      if (change === 'removed') localStorage.removeItem(SHOP_REFUND_KEY);
      else localStorage.setItem(SHOP_REFUND_KEY, JSON.stringify({ version: 1, references: [{
        orderId: 1, sessionId, requestId: '33333333-3333-4333-8333-333333333333',
      }] }));
      try { verifyBeforeChat(sessionId); }
      catch (error) { verificationError = error; throw error; }
      reachedDispatch = true;
      return { ticketId: 71, orderId: 1 };
    });
    await act(async () => render()); await view(0);
    await enterReason('Damaged product'); await click('Request refund');
    expect(mockRequestRefundTicket).toHaveBeenCalledTimes(1);
    expect(savedReference).toEqual({ orderId: 1, sessionId, requestId });
    expect(verificationError).toBeInstanceOf(Error);
    expect(reachedDispatch).toBe(false);
    expect(global.fetch.mock.calls.some(([url, options]) => url.endsWith('/refund/chat')
      && options?.method === 'POST')).toBe(false);
    expect(container.textContent).not.toContain('Refund request filed');
  } finally {
    if (original) Object.defineProperty(globalThis.crypto, 'randomUUID', original);
    else delete globalThis.crypto.randomUUID;
  }
});

test('chat handoff re-fetches the selected owned order before opening an unsubmitted refund review', async () => {
  const refundSetup = { version: 1, kind: 'refund_setup',
    choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', orderId: 1 };
  mockBridgeMetadata = { boundReviews: true };
  await act(async () => root.unmount()); root = createRoot(container);
  await act(async () => root.render(<MemoryRouter initialEntries={[{
    pathname: '/secureshop/orders', state: { refundSetup },
  }]}><Orders /></MemoryRouter>));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
  expect(global.fetch).toHaveBeenCalledWith('/api/secureshop/orders/1', expect.objectContaining({ method: 'GET' }));
  await act(async () => first.resolve(response({ order: order(1), items: [] })));
  expect(container.querySelector('[role="dialog"] h2').textContent).toBe('Order #1');
  expect(container.querySelector('#ss-refund-reason').value).toBe('');
  expect([...container.querySelectorAll('button')].find(button => button.textContent === 'Request refund').disabled).toBe(true);
  expect(mockRequestRefundTicket).not.toHaveBeenCalled();
});

test('chat handoff refuses a missing or mismatched protected order detail', async () => {
  const refundSetup = { version: 1, kind: 'refund_setup',
    choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', orderId: 1 };
  mockBridgeMetadata = { boundReviews: true };
  await act(async () => root.unmount()); root = createRoot(container);
  await act(async () => root.render(<MemoryRouter initialEntries={[{
    pathname: '/secureshop/orders', state: { refundSetup },
  }]}><Orders /></MemoryRouter>));
  await act(async () => first.resolve(response({ order: order(2), items: [] })));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
  expect(container.textContent).toContain('could not be verified');
  expect(mockRequestRefundTicket).not.toHaveBeenCalled();
});

test('chat handoff cannot open a foreign order absent from the fresh owned list', async () => {
  const refundSetup = { version: 1, kind: 'refund_setup',
    choiceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', orderId: 99 };
  mockBridgeMetadata = { boundReviews: true };
  await act(async () => root.unmount()); root = createRoot(container);
  await act(async () => root.render(<MemoryRouter initialEntries={[{
    pathname: '/secureshop/orders', state: { refundSetup },
  }]}><Orders /></MemoryRouter>));
  expect(container.querySelector('[role="dialog"]')).toBeNull();
  expect(container.textContent).toContain('not in your current orders');
  expect(global.fetch).not.toHaveBeenCalledWith('/api/secureshop/orders/99', expect.anything());
  expect(mockRequestRefundTicket).not.toHaveBeenCalled();
});
