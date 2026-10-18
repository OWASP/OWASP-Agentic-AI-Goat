import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import { CartProvider, useCart } from './CartContext';
import Cart from '../pages/Cart.jsx';
import { disconnectShopStorage, flushShopStorage, shopStorage } from '../utils/shopStorage.mjs';
import { GuestCartChannelContext } from '../bridge/GuestCartChannelContext.jsx';
import { BOUND_CART_REFRESH_CHANNEL, BOUND_CART_REFRESH_EVENT } from '../bridge/cartRefresh.mjs';

let mockAuthState;
let mockBound = false;
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => mockBound ? {} : undefined }));
jest.mock('./AuthContext', () => ({ useAuth: () => mockAuthState }));

const mockToast = { info: jest.fn(), error: jest.fn(), success: jest.fn() };
jest.mock('./ToastContext.jsx', () => ({ useToast: () => mockToast }));
jest.mock('../utils/shopStorage.mjs', () => ({
  shopStorage: { getItem: jest.fn(), setItem: jest.fn(), removeItem: jest.fn() },
  SHOP_COUPON_KEY: 'secureshop.coupon.operation.v1',
  flushShopStorage: jest.fn(),
  disconnectShopStorage: jest.fn(),
}));

let root;
let container;
let cart;
let storedGuestCart;

function Probe() {
  cart = useCart();
  return null;
}

function jsonResponse(body, status = 200, contentType = 'application/json; charset=utf-8') {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => name.toLowerCase() === 'content-type' ? contentType : null },
    json: jest.fn().mockResolvedValue(body),
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

async function renderCart(auth = { user: null, isAuthed: false }, channel = null) {
  mockAuthState = auth;
  await act(async () => {
    root.render(<GuestCartChannelContext.Provider value={channel}><CartProvider><Probe /></CartProvider></GuestCartChannelContext.Provider>);
    await Promise.resolve();
  });
}

async function renderCartPage(auth = { user: null, isAuthed: false }, channel = null) {
  mockAuthState = auth;
  await act(async () => {
    root.render(<MemoryRouter><GuestCartChannelContext.Provider value={channel}><CartProvider><Cart /></CartProvider></GuestCartChannelContext.Provider></MemoryRouter>);
    await Promise.resolve();
  });
}

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.clearAllMocks();
  mockBound = false;
  mockAuthState = { user: null, isAuthed: false };
  storedGuestCart = JSON.stringify([{ id: 'guest-1', product_id: 7, quantity: 1, price: 10, name: 'Item' }]);
  shopStorage.getItem.mockImplementation(() => storedGuestCart);
  shopStorage.setItem.mockImplementation((key, value) => { storedGuestCart = value; });
  flushShopStorage.mockResolvedValue();
  global.fetch = jest.fn();
  container = document.createElement('div');
  root = createRoot(container);
});

afterEach(async () => {
  await act(async () => root.unmount());
});

test('bound cart readback confirms only imported quantities visible in the owned cart', async () => {
  mockBound = true;
  const send = jest.spyOn(window.parent, 'postMessage').mockImplementation(() => {});
  const detail = { requestId: '7f078c35-0bda-4bb4-9c9f-819807aa2668',
    nonce: 'a'.repeat(64), origin: 'http://localhost',
    items: [{ productId: 125, quantity: 2 }] };
  try {
    global.fetch.mockResolvedValueOnce(jsonResponse({ items: [], subtotal: 0 }))
      .mockResolvedValueOnce(jsonResponse({ items: [{ product_id: 125, quantity: 1 }], subtotal: 99.99 }))
      .mockResolvedValueOnce(jsonResponse({ items: [{ product_id: 125, quantity: 2 }], subtotal: 199.98 }));
    await renderCart({ user: { id: 2, role: 'customer' }, isAuthed: true });
    await act(async () => {
      window.dispatchEvent(new CustomEvent(BOUND_CART_REFRESH_EVENT, { detail }));
      await Promise.resolve();
    });
    expect(send).toHaveBeenLastCalledWith({ channel: BOUND_CART_REFRESH_CHANNEL,
      type: 'readback', nonce: detail.nonce, requestId: detail.requestId,
      confirmed: false }, detail.origin);
    await act(async () => {
      window.dispatchEvent(new CustomEvent(BOUND_CART_REFRESH_EVENT, { detail }));
      await Promise.resolve();
    });
    expect(send).toHaveBeenLastCalledWith({ channel: BOUND_CART_REFRESH_CHANNEL,
      type: 'readback', nonce: detail.nonce, requestId: detail.requestId,
      confirmed: true }, detail.origin);
  } finally { send.mockRestore(); }
});

test('repeated bound refresh while one GET is in flight sends only one readback', async () => {
  mockBound = true;
  const send = jest.spyOn(window.parent, 'postMessage').mockImplementation(() => {});
  const detail = { requestId: '7f078c35-0bda-4bb4-9c9f-819807aa2668',
    nonce: 'a'.repeat(64), origin: 'http://localhost', items: [{ productId: 125, quantity: 2 }] };
  const pending = deferred();
  try {
    global.fetch.mockResolvedValueOnce(jsonResponse({ items: [], subtotal: 0 }))
      .mockReturnValueOnce(pending.promise);
    await renderCart({ user: { id: 2, role: 'customer' }, isAuthed: true });
    await act(async () => {
      window.dispatchEvent(new CustomEvent(BOUND_CART_REFRESH_EVENT, { detail }));
      window.dispatchEvent(new CustomEvent(BOUND_CART_REFRESH_EVENT, { detail }));
      await Promise.resolve();
    });
    expect(global.fetch).toHaveBeenCalledTimes(2);
    await act(async () => pending.resolve(jsonResponse({ items: [{ product_id: 125, quantity: 2 }], subtotal: 199.98 })));
    expect(send).toHaveBeenCalledTimes(1);
    expect(send).toHaveBeenCalledWith(expect.objectContaining({ confirmed: true,
      nonce: detail.nonce, requestId: detail.requestId }), detail.origin);
  } finally { send.mockRestore(); }
});

test('bound readback completion after provider unmount sends no stale parent confirmation', async () => {
  mockBound = true;
  const send = jest.spyOn(window.parent, 'postMessage').mockImplementation(() => {});
  const detail = { requestId: '7f078c35-0bda-4bb4-9c9f-819807aa2668',
    nonce: 'a'.repeat(64), origin: 'http://localhost', items: [{ productId: 125, quantity: 2 }] };
  const pending = deferred();
  try {
    global.fetch.mockResolvedValueOnce(jsonResponse({ items: [], subtotal: 0 }))
      .mockReturnValueOnce(pending.promise);
    await renderCart({ user: { id: 2, role: 'customer' }, isAuthed: true });
    await act(async () => { window.dispatchEvent(new CustomEvent(BOUND_CART_REFRESH_EVENT, { detail })); await Promise.resolve(); });
    await act(async () => root.render(null));
    await act(async () => pending.resolve(jsonResponse({ items: [{ product_id: 125, quantity: 2 }], subtotal: 199.98 })));
    expect(send).not.toHaveBeenCalled();
  } finally { send.mockRestore(); }
});

for (const action of ['add', 'update', 'remove']) {
  test(`guest ${action} waits for persistence and avoids authenticated HTTP`, async () => {
    await renderCart();
    const write = deferred();
    flushShopStorage.mockReturnValueOnce(write.promise);
    let pending;
    await act(async () => {
      pending = action === 'add'
        ? cart.addItem(7, 1)
        : action === 'update'
          ? cart.updateQty('guest-1', 3)
          : cart.remove('guest-1');
      await Promise.resolve();
    });
    expect(cart.subtotal).toBe(10);
    expect(global.fetch).not.toHaveBeenCalled();

    await act(async () => { write.resolve(); await pending; });
    expect(cart.subtotal).toBe(action === 'add' ? 20 : action === 'update' ? 30 : 0);
  });
}

for (const action of ['add', 'update', 'remove']) {
  test(`guest ${action} disconnects failed persistence without publishing success`, async () => {
    await renderCart();
    flushShopStorage.mockRejectedValueOnce(new Error('quota'));
    await act(async () => {
      await (action === 'add'
        ? cart.addItem(7, 1)
        : action === 'update'
          ? cart.updateQty('guest-1', 3)
          : cart.remove('guest-1'));
    });
    expect(cart.subtotal).toBe(10);
    expect(disconnectShopStorage).toHaveBeenCalledTimes(1);
    expect(mockToast.error).toHaveBeenCalled();
    expect(mockToast.info).not.toHaveBeenCalled();
  });
}

test('a delayed guest persistence acknowledgement cannot overwrite a signed-in cart', async () => {
  await renderCart();
  const write = deferred();
  flushShopStorage.mockReturnValueOnce(write.promise);
  let pending;
  await act(async () => { pending = cart.updateQty('guest-1', 4); await Promise.resolve(); });

  global.fetch.mockResolvedValueOnce(jsonResponse({
    items: [{ id: 22, product_id: 8, quantity: 1, price: 25, name: 'Owned' }],
    subtotal: 25,
  }));
  await renderCart({ user: { id: 2 }, isAuthed: true });
  expect(cart.subtotal).toBe(25);

  await act(async () => { write.resolve(); await pending; });
  expect(cart.items).toEqual([{ id: 22, product_id: 8, quantity: 1, price: 25, name: 'Owned' }]);
  expect(cart.subtotal).toBe(25);
});

test('full-reload guest cart IDs rehydrate price and name only from a public product read', async () => {
  const channel = { ready: Promise.resolve([{ productId: 125, quantity: 2 }]),
    onError: jest.fn(() => () => {}), save: jest.fn() };
  global.fetch.mockResolvedValue(jsonResponse({ product: {
    id: 125, name: 'Public product', price: 160.81, stock_quantity: 4,
  } }));
  await renderCart({ user: null, isAuthed: false }, channel);
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(global.fetch).toHaveBeenCalledWith('/api/secureshop/products/125', expect.objectContaining({ signal: expect.any(AbortSignal) }));
  expect(cart.cartReady).toBe(true);
  expect(cart.items).toEqual([{ id: 'guest-125', product_id: 125,
    quantity: 2, name: 'Public product', price: 160.81 }]);
  expect(cart.subtotal).toBeCloseTo(321.62);
  expect(channel.save).not.toHaveBeenCalled();
  await act(async () => cart.updateQty('guest-125', 3));
  expect(channel.save).toHaveBeenCalledWith([{ productId: 125, quantity: 3 }]);
});

test('guest product-to-cart remount restores the latest local snapshot instead of initial empty hydration', async () => {
  let current = [];
  const channel = { ready: Promise.resolve([]), snapshot: () => current,
    onError: jest.fn(() => () => {}), save: jest.fn(items => { current = items; return true; }) };
  global.fetch.mockResolvedValue(jsonResponse({ product: {
    id: 125, name: 'Wireless Bluetooth Headphones', price: 160.81, stock_quantity: 4,
  } }));
  await renderCart({ user: null, isAuthed: false }, channel);
  await act(async () => cart.addItem(125, 1, { name: 'Wireless Bluetooth Headphones', price: 160.81 }));
  expect(cart.count).toBe(1);
  expect(channel.save).toHaveBeenCalledWith([{ productId: 125, quantity: 1 }]);
  await act(async () => root.unmount());
  root = createRoot(container);
  await renderCart({ user: null, isAuthed: false }, channel);
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(cart.cartReady).toBe(true);
  expect(cart.items).toEqual([{ id: 'guest-125', product_id: 125, quantity: 1,
    name: 'Wireless Bluetooth Headphones', price: 160.81 }]);
  expect(cart.subtotal).toBeCloseTo(160.81);
});

test('guest cart restore caps saved quantity at current public stock before publishing a subtotal', async () => {
  const channel = { ready: Promise.resolve([{ productId: 125, quantity: 9 }]),
    onError: jest.fn(() => () => {}), save: jest.fn() };
  global.fetch.mockResolvedValue(jsonResponse({ product: {
    id: 125, name: 'Public product', price: 160.81, stock_quantity: 2,
  } }));
  await renderCart({ user: null, isAuthed: false }, channel);
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(cart.items[0].quantity).toBe(2);
  expect(cart.subtotal).toBeCloseTo(321.62);
  expect(channel.save).toHaveBeenCalledWith([{ productId: 125, quantity: 2 }]);
  expect(cart.error).toMatch(/updated for current product availability/i);
});

test('guest cart restore does not fabricate a priced item when public detail is unavailable', async () => {
  const channel = { ready: Promise.resolve([{ productId: 125, quantity: 2 }]),
    onError: jest.fn(() => () => {}), save: jest.fn() };
  global.fetch.mockResolvedValue(jsonResponse({}, 503));
  await renderCart({ user: null, isAuthed: false }, channel);
  await act(async () => { await Promise.resolve(); await Promise.resolve(); });
  expect(cart.cartReady).toBe(false);
  expect(cart.items).toEqual([]);
  expect(cart.error).toMatch(/Could not restore your cart/i);
  expect(channel.save).not.toHaveBeenCalled();
});

test.each(['merchant', 'admin'])('%s persona does not load or mutate the customer cart', async role => {
  await renderCart({ user: { id: 7, role }, isAuthed: true });
  expect(cart.customerCart).toBe(false);
  expect(cart.items).toEqual([]);
  expect(global.fetch).not.toHaveBeenCalled();
  await act(async () => {
    await cart.reload();
    await cart.addItem(7, 1);
    await cart.updateQty(1, 2);
    await cart.remove(1);
    await cart.applyCoupon('SAVE');
  });
  expect(global.fetch).not.toHaveBeenCalled();
});

test.each([0, 100, 1.5, Number.POSITIVE_INFINITY, Number.NaN, Number.MAX_SAFE_INTEGER + 1])('cart mutations reject invalid quantity %p before optimistic state or HTTP', async quantity => {
  global.fetch.mockResolvedValueOnce(jsonResponse({
    items: [{ id: 1, product_id: 7, quantity: 2, price: 10, name: 'Existing' }], subtotal: 20,
  }));
  await renderCart({ user: { id: 3, role: 'customer' }, isAuthed: true });
  const beforeItems = cart.items;
  const beforeSubtotal = cart.subtotal;
  await act(async () => {
    await cart.updateQty(1, quantity);
    await cart.addItem(8, quantity, { name: 'Invalid', price: 20 });
  });
  expect(cart.items).toEqual(beforeItems);
  expect(cart.subtotal).toBe(beforeSubtotal);
  expect(global.fetch).toHaveBeenCalledTimes(1);
});

test('guest add at the per-item limit keeps the saved cart and storage binding intact', async () => {
  storedGuestCart = JSON.stringify([{ id: 'guest-1', product_id: 7, quantity: 99, price: 10, name: 'Item' }]);
  await renderCart();
  const beforeItems = cart.items;
  const beforeSubtotal = cart.subtotal;

  await act(async () => { await cart.addItem(7, 1, { name: 'Item', price: 10 }); });

  expect(cart.items).toEqual(beforeItems);
  expect(cart.subtotal).toBe(beforeSubtotal);
  expect(shopStorage.setItem).not.toHaveBeenCalled();
  expect(flushShopStorage).not.toHaveBeenCalled();
  expect(disconnectShopStorage).not.toHaveBeenCalled();
  expect(global.fetch).not.toHaveBeenCalled();
  expect(mockToast.error).toHaveBeenCalledWith('Maximum quantity per item is 99');
});

test('a stale guest persistence failure cannot disconnect the new persona storage binding', async () => {
  await renderCart();
  const write = deferred();
  flushShopStorage.mockReturnValueOnce(write.promise);
  let pending;
  await act(async () => { pending = cart.updateQty('guest-1', 4); await Promise.resolve(); });

  global.fetch.mockResolvedValueOnce(jsonResponse({ items: [], subtotal: 0 }));
  await renderCart({ user: { id: 2 }, isAuthed: true });
  await act(async () => { write.reject(new Error('old binding failed')); await pending; });

  expect(disconnectShopStorage).not.toHaveBeenCalled();
  expect(mockToast.error).not.toHaveBeenCalled();
});

test('a late reload from the prior persona cannot replace the current cart', async () => {
  const first = deferred();
  global.fetch.mockImplementation((url) => {
    if (url.includes('user_id=1')) return first.promise;
    return Promise.resolve(jsonResponse({
      items: [{ id: 22, product_id: 8, quantity: 1, price: 25, name: 'Second' }],
      subtotal: 25,
    }));
  });
  await renderCart({ user: { id: 1 }, isAuthed: true });
  await renderCart({ user: { id: 2 }, isAuthed: true });
  expect(cart.subtotal).toBe(25);

  await act(async () => {
    first.resolve(jsonResponse({
      items: [{ id: 11, product_id: 7, quantity: 9, price: 10, name: 'First' }],
      subtotal: 90,
    }));
    await first.promise;
    await Promise.resolve();
  });
  expect(cart.items[0].name).toBe('Second');
  expect(cart.subtotal).toBe(25);
});

test('identity changes clear coupons and fence late coupon completions', async () => {
  global.fetch.mockResolvedValueOnce(jsonResponse({ items: [], subtotal: 0 }));
  await renderCart({ user: { id: 1 }, isAuthed: true });
  const couponResponse = deferred();
  global.fetch.mockReturnValueOnce(couponResponse.promise);
  let pending;
  await act(async () => { pending = cart.applyCoupon("SAVE' OR 1=1 --"); await Promise.resolve(); });

  global.fetch.mockResolvedValueOnce(jsonResponse({ items: [], subtotal: 0 }));
  await renderCart({ user: { id: 2 }, isAuthed: true });
  await act(async () => {
    couponResponse.resolve(jsonResponse({ ok: true, code: 'STALE', discount_percent: 99, applied_amount: 99 }));
    await pending;
  });
  expect(cart.coupon).toBeNull();
});

test('callbacks retained from an old render cannot act under the new persona generation', async () => {
  global.fetch.mockResolvedValueOnce(jsonResponse({ items: [], subtotal: 0 }));
  await renderCart({ user: { id: 1 }, isAuthed: true });
  const old = {
    reload: cart.reload,
    addItem: cart.addItem,
    updateQty: cart.updateQty,
    remove: cart.remove,
    applyCoupon: cart.applyCoupon,
    clear: cart.clear,
  };

  global.fetch.mockResolvedValueOnce(jsonResponse({
    items: [{ id: 22, product_id: 8, quantity: 1, price: 25, name: 'Second' }],
    subtotal: 25,
  }));
  await renderCart({ user: { id: 2 }, isAuthed: true });
  const callsAfterSwitch = global.fetch.mock.calls.length;

  await act(async () => {
    await Promise.all([
      old.reload(),
      old.addItem(9, 1),
      old.updateQty(22, 4),
      old.remove(22),
      old.applyCoupon('OLD-PERSONA'),
      old.clear(),
    ]);
  });
  expect(global.fetch).toHaveBeenCalledTimes(callsAfterSwitch);
  expect(cart.items[0].name).toBe('Second');
  expect(cart.subtotal).toBe(25);
});

test('authenticated add failure restores both optimistic items and subtotal', async () => {
  global.fetch
    .mockResolvedValueOnce(jsonResponse({
      items: [{ id: 1, product_id: 7, quantity: 1, price: 10, name: 'Existing' }],
      subtotal: 10,
    }))
    .mockResolvedValueOnce(jsonResponse({ error: 'denied' }, 503));
  await renderCart({ user: { id: 3 }, isAuthed: true });

  await act(async () => { await cart.addItem(8, 2, { name: 'New', price: 5 }); });
  expect(cart.items).toHaveLength(1);
  expect(cart.subtotal).toBe(10);
  expect(mockToast.error).toHaveBeenCalledWith('Add failed: Cart request failed (503)');
});

test('immediately queued mutations use the cart reconciled by the preceding mutation', async () => {
  global.fetch
    .mockResolvedValueOnce(jsonResponse({ items: [], subtotal: 0 }))
    .mockResolvedValueOnce(jsonResponse({ ok: true, cart_item_id: 1 }))
    .mockResolvedValueOnce(jsonResponse({
      items: [{ id: 1, product_id: 7, quantity: 1, price: 10, name: 'First' }],
      subtotal: 10,
    }))
    .mockResolvedValueOnce(jsonResponse({ error: 'denied' }, 503));
  await renderCart({ user: { id: 3 }, isAuthed: true });

  let first;
  let second;
  await act(async () => {
    first = cart.addItem(7, 1, { name: 'First', price: 10 });
    second = cart.addItem(8, 1, { name: 'Second', price: 20 });
    await Promise.all([first, second]);
  });
  expect(cart.items).toEqual([{ id: 1, product_id: 7, quantity: 1, price: 10, name: 'First' }]);
  expect(cart.subtotal).toBe(10);
});

test('a newer reload does not suppress rollback of a failed optimistic mutation', async () => {
  global.fetch.mockResolvedValueOnce(jsonResponse({
    items: [{ id: 1, product_id: 7, quantity: 1, price: 10, name: 'Existing' }],
    subtotal: 10,
  }));
  await renderCart({ user: { id: 3 }, isAuthed: true });
  const mutationResponse = deferred();
  const reloadResponse = deferred();
  global.fetch
    .mockReturnValueOnce(mutationResponse.promise)
    .mockReturnValueOnce(reloadResponse.promise);

  let mutation;
  let reload;
  await act(async () => {
    mutation = cart.addItem(8, 1, { name: 'Optimistic', price: 20 });
    await Promise.resolve();
    reload = cart.reload();
    await Promise.resolve();
  });
  expect(cart.subtotal).toBe(30);

  await act(async () => {
    mutationResponse.resolve(jsonResponse({ error: 'denied' }, 503));
    await mutation;
  });
  expect(cart.items).toEqual([{ id: 1, product_id: 7, quantity: 1, price: 10, name: 'Existing' }]);
  expect(cart.subtotal).toBe(10);

  await act(async () => {
    reloadResponse.resolve(jsonResponse({
      items: [{ id: 1, product_id: 7, quantity: 1, price: 10, name: 'Existing' }],
      subtotal: 10,
    }));
    await reload;
  });
});

test('a failed coupon cannot steal loading ownership from a pending reload', async () => {
  const reloadResponse = deferred();
  global.fetch
    .mockReturnValueOnce(reloadResponse.promise)
    .mockResolvedValueOnce(jsonResponse({ error: 'coupon unavailable' }, 503));
  await renderCart({ user: { id: 3 }, isAuthed: true });
  expect(cart.loading).toBe(true);

  await act(async () => {
    await expect(cart.applyCoupon('SAVE')).rejects.toThrow('Cart request failed (503)');
  });
  expect(cart.loading).toBe(true);

  await act(async () => {
    reloadResponse.resolve(jsonResponse({ items: [], subtotal: 0 }));
    await reloadResponse.promise;
    await Promise.resolve();
  });
  expect(cart.loading).toBe(false);
});

for (const action of ['update', 'remove']) {
  test(`authenticated ${action} failure restores items and subtotal`, async () => {
    global.fetch
      .mockResolvedValueOnce(jsonResponse({
        items: [{ id: 1, product_id: 7, quantity: 2, price: 10, name: 'Existing' }],
        subtotal: 20,
      }))
      .mockResolvedValueOnce(jsonResponse({ ok: false, error: 'denied' }));
    await renderCart({ user: { id: 3 }, isAuthed: true });

    await act(async () => {
      await (action === 'update' ? cart.updateQty(1, 5) : cart.remove(1));
    });
    expect(cart.items).toEqual([{ id: 1, product_id: 7, quantity: 2, price: 10, name: 'Existing' }]);
    expect(cart.subtotal).toBe(20);
    expect(mockToast.error).toHaveBeenCalled();
  });
}

test('reload reports an unsuccessful or non-JSON response without leaking stale owner data', async () => {
  global.fetch
    .mockResolvedValueOnce(jsonResponse({ items: [{ id: 1 }], subtotal: 5 }))
    .mockResolvedValueOnce(jsonResponse({ error: 'offline' }, 503));
  await renderCart({ user: { id: 1 }, isAuthed: true });
  await renderCart({ user: { id: 2 }, isAuthed: true });
  expect(cart.items).toEqual([]);
  expect(cart.subtotal).toBe(0);
  expect(cart.error).toBe('Cart request failed (503)');

  global.fetch.mockResolvedValueOnce(jsonResponse({}, 200, 'text/html'));
  await act(async () => { await cart.reload(); });
  expect(cart.error).toBe('Cart response was not JSON');
});

test('clear synchronously fences a pending reload', async () => {
  global.fetch.mockResolvedValueOnce(jsonResponse({
    items: [{ id: 1, product_id: 7, quantity: 1, price: 10, name: 'Existing' }],
    subtotal: 10,
  }));
  await renderCart({ user: { id: 1 }, isAuthed: true });
  const pendingResponse = deferred();
  global.fetch.mockReturnValueOnce(pendingResponse.promise);
  let pending;
  await act(async () => { pending = cart.reload(); await Promise.resolve(); });
  expect(cart.loading).toBe(true);
  act(() => cart.clear());
  expect(cart.items).toEqual([]);
  expect(cart.subtotal).toBe(0);
  expect(cart.loading).toBe(false);

  await act(async () => {
    pendingResponse.resolve(jsonResponse({
      items: [{ id: 2, product_id: 8, quantity: 1, price: 30, name: 'Late' }],
      subtotal: 30,
    }));
    await pending;
  });
  expect(cart.items).toEqual([]);
  expect(cart.subtotal).toBe(0);
});

test('guest coupon retains the exact learner payload and deliberate user 1 endpoint behavior', async () => {
  await renderCart();
  const code = "' UNION SELECT 'OWNED',99 --";
  global.fetch.mockResolvedValueOnce(jsonResponse({
    ok: true, code, discount_percent: 99, applied_amount: 9.9,
  }));
  await act(async () => { await cart.applyCoupon(code); });
  expect(JSON.parse(global.fetch.mock.calls[0][1].body)).toEqual({ user_id: 1, code });
  expect(cart.coupon.code).toBe(code);
});


const scopeA = 'a'.repeat(64);
function couponHarness() {
  const storage = new Map();
  shopStorage.getItem.mockImplementation(key => storage.get(key) ?? null);
  shopStorage.setItem.mockImplementation((key, value) => storage.set(key, value));
  shopStorage.removeItem.mockImplementation(key => storage.delete(key));
  Object.defineProperty(global.crypto, 'subtle', { configurable: true, value: require('node:crypto').webcrypto.subtle });
  const state = { scope: scopeA, committed: false, lost: true, posts: [] };
  global.fetch.mockImplementation(async (url, options) => {
    if (options?.method === 'POST') {
      state.posts.push(JSON.parse(options.body)); state.committed = true;
      if (state.lost) throw Error('response lost after commit');
      return jsonResponse({ok:true,code:'SAVE',discount_percent:10,applied_amount:1});
    }
    return jsonResponse({items:[{id:1,price:10,quantity:1}],subtotal:10,couponAvailable:true,couponScopeKey:state.scope,
      coupon:state.committed ? {code:'SAVE',discount_percent:10,applied_amount:1} : null});
  });
  return {storage,state};
}

test('bound remount restores discount without POST and explicit retry retains exact UUID', async () => {
  mockBound = true; const {storage,state} = couponHarness();
  await renderCart({user:{id:3},isAuthed:true});
  await act(async()=>{await expect(cart.applyCoupon("' OR 1=1--")).rejects.toThrow('response lost');});
  const first=state.posts[0];
  expect([...storage.values()].join('')).not.toContain("OR 1=1");
  await act(async()=>root.unmount()); root=createRoot(container);
  await renderCart({user:{id:3},isAuthed:true});
  expect(cart.discount).toBe(1); expect(state.posts).toHaveLength(1);
  state.lost=false;
  await act(async()=>{await cart.applyCoupon("' OR 1=1--");});
  expect(state.posts[1]).toEqual(first); expect(storage.size).toBe(0);
});

test('bound coupon POST is denied when authoritative cart readiness is absent', async () => {
  mockBound = true;
  global.fetch.mockResolvedValue(jsonResponse({ items: [{ id: 1, price: 10, quantity: 1 }],
    subtotal: 10, couponScopeKey: scopeA, couponAvailable: false }));
  await renderCart({ user: { id: 3, role: 'customer' }, isAuthed: true });
  expect(cart.couponAvailable).toBe(false);
  await act(async () => {
    await expect(cart.applyCoupon('WELCOME10')).rejects.toThrow('Coupons are unavailable in this shop setup');
  });
  expect(global.fetch.mock.calls.every(([, options]) => options?.method !== 'POST')).toBe(true);
  expect(shopStorage.setItem).not.toHaveBeenCalled();
  expect(cart.items).toHaveLength(1);
});

test('invalid bound coupon shows the precise denial and preserves the applied discount', async () => {
  mockBound = true;
  const { state, storage } = couponHarness();
  state.lost = false;
  await renderCart({ user: { id: 3, role: 'customer' }, isAuthed: true });
  await act(async () => { await cart.applyCoupon('SAVE'); });
  const base = global.fetch.getMockImplementation();
  global.fetch.mockImplementation((url, options) => options?.method === 'POST'
    ? Promise.resolve(jsonResponse({ ok: false, error: 'coupon not found' }, 404))
    : base(url, options));

  await act(async () => {
    await expect(cart.applyCoupon('QA_INVALID_COUPON')).rejects.toThrow('Coupon not found');
  });
  expect(cart.error).toBe('Coupon not found');
  expect(mockToast.error).toHaveBeenLastCalledWith('Coupon error: Coupon not found');
  expect(cart.coupon.code).toBe('SAVE');
  expect(cart.discount).toBe(1);
  expect(cart.total).toBe(9);
  expect(storage.size).toBe(1);
});

for (const change of ['code','scope']) test(`coupon ${change} change never reuses an uncertain operation UUID`, async()=>{
  mockBound=true;const {state}=couponHarness();await renderCart({user:{id:3},isAuthed:true});
  await act(async()=>{await expect(cart.applyCoupon('SAVE')).rejects.toThrow();});
  if(change==='scope')state.scope='b'.repeat(64);
  await act(async()=>{await expect(cart.applyCoupon(change==='code'?'OTHER':'SAVE')).rejects.toThrow();});
  expect(state.posts[1].operationId).not.toBe(state.posts[0].operationId);
});

test('coupon parent persistence acknowledgement precedes POST and failure prevents effect',async()=>{
 mockBound=true;const {state}=couponHarness();await renderCart({user:{id:3},isAuthed:true});
 flushShopStorage.mockRejectedValueOnce(Error('parent unavailable'));
 await act(async()=>{await expect(cart.applyCoupon('SAVE')).rejects.toThrow('parent unavailable');});
 expect(state.posts).toHaveLength(0);
});

test('late old-scope 4xx cannot clear a newer mounted coupon reference',async()=>{
 mockBound=true;const {state,storage}=couponHarness();await renderCart({user:{id:3},isAuthed:true});
 const base=global.fetch.getMockImplementation(),held=deferred();
 global.fetch.mockImplementation((url,options)=>options?.method==='POST'?held.promise:base(url,options));
 let old;
 await act(async()=>{old=cart.applyCoupon('SAVE');await new Promise(resolve=>setTimeout(resolve,0));});
 await act(async()=>root.unmount());root=createRoot(container);
 state.scope='b'.repeat(64);global.fetch.mockImplementation(base);
 await renderCart({user:{id:4},isAuthed:true});
 await act(async()=>{await expect(cart.applyCoupon('OTHER')).rejects.toThrow();});
 const newer=[...storage.values()][0];
 await act(async()=>{held.resolve(jsonResponse({error:'denied'},401));await old;});
 expect([...storage.values()][0]).toBe(newer);
});


test('lost coupon response followed by rate limiting retains the same retry UUID',async()=>{
 mockBound=true;const {state}=couponHarness();await renderCart({user:{id:3},isAuthed:true});
 await act(async()=>{await expect(cart.applyCoupon('SAVE')).rejects.toThrow();});
 const original=state.posts[0],base=global.fetch.getMockImplementation();
 global.fetch.mockImplementation((url,options)=>{if(options?.method==='POST'){state.posts.push(JSON.parse(options.body));return Promise.resolve(jsonResponse({error:'rate limited'},429));}return base(url,options);});
 await act(async()=>{await expect(cart.applyCoupon('SAVE')).rejects.toThrow('429');});
 state.lost=false;global.fetch.mockImplementation(base);
 await act(async()=>{await cart.applyCoupon('SAVE');});
 expect(state.posts).toEqual([original,original,original]);
});


test('transient bound reload retains the authoritative cart for the same owner', async () => {
  mockBound = true;
  const { state } = couponHarness();
  state.lost = false;
  await renderCart({ user: { id: 3 }, isAuthed: true });
  await act(async () => { await cart.applyCoupon('SAVE'); });
  expect(cart.coupon.code).toBe('SAVE');
  expect(cart.discount).toBe(1);
  expect(cart.subtotal).toBe(10);

  global.fetch.mockResolvedValueOnce(jsonResponse({ error: 'unavailable' }, 503));
  await act(async () => { await cart.reload(); });
  expect(cart.error).toBe('Cart request failed (503)');
  expect(cart.coupon).toEqual({ code: 'SAVE', discount_percent: 10, applied_amount: 1 });
  expect(cart.discount).toBe(1);
  expect(cart.items).toEqual([{ id: 1, price: 10, quantity: 1 }]);
  expect(cart.subtotal).toBe(10);
});

test('identity change clears the previous owner snapshot before the new read completes', async () => {
  const nextOwner = deferred();
  global.fetch.mockResolvedValueOnce(jsonResponse({
    items: [{ id: 1, product_id: 7, quantity: 1, price: 10, name: 'First owner' }],
    subtotal: 10,
  }));
  await renderCart({ user: { id: 1 }, isAuthed: true });
  expect(cart.items).toHaveLength(1);

  global.fetch.mockReturnValueOnce(nextOwner.promise);
  await renderCart({ user: { id: 2 }, isAuthed: true });
  expect(cart.items).toEqual([]);
  expect(cart.subtotal).toBe(0);
  expect(cart.coupon).toBeNull();

  await act(async () => {
    nextOwner.resolve(jsonResponse({ error: 'unavailable' }, 503));
    await nextOwner.promise;
  });
  expect(cart.items).toEqual([]);
  expect(cart.error).toBe('Cart request failed (503)');
});

test('fresh cart read failure renders unavailable instead of an empty cart', async () => {
  global.fetch.mockResolvedValueOnce(jsonResponse({ error: 'unavailable' }, 503));
  await renderCartPage({ user: { id: 9 }, isAuthed: true });
  expect(container.textContent).toContain('Cart unavailable');
  expect(container.textContent).not.toContain('Your cart is empty');
  expect(container.querySelector('[role="alert"]')?.textContent).toBe('Cart request failed (503)');
});
