import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import CustomerChoiceCards from './CustomerChoiceCards.jsx';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
let root, node;
beforeEach(() => { globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div'); document.body.append(node); root = createRoot(node); });
afterEach(async () => { await act(async () => root.unmount()); node.remove(); });

test('product cards render safe text and separate detail and cart intents with a visible quantity', async () => {
  const onProductAction = jest.fn();
  await act(async () => root.render(<CustomerChoiceCards cards={[{
    version: 1, kind: 'product', choiceId: id,
    title: '<b>Practice laptop</b>', detail: 'Available in this shop',
  }]} onProductAction={onProductAction} />));
  expect(node.querySelector('section[aria-label="Customer choices"]')).not.toBeNull();
  expect(node.querySelector('section b')).toBeNull();
  expect(node.textContent).toContain('<b>Practice laptop</b>');
  const quantity = node.querySelector('input[aria-label^="Quantity for "]');
  expect(quantity.value).toBe('1');
  await act(async () => node.querySelector('button[aria-label^="View details:"]').click());
  expect(onProductAction).toHaveBeenCalledWith({ choiceId: id, intent: 'details' });
  await act(async () => node.querySelector('button[aria-label^="Add to cart:"]').click());
  expect(onProductAction).toHaveBeenLastCalledWith({ choiceId: id, intent: 'cart_add', quantity: 1 });
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(quantity, '100');
    quantity.dispatchEvent(new Event('input', { bubbles: true }));
  });
  expect(node.querySelector('button[aria-label^="Add to cart:"]').disabled).toBe(true);
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(quantity, '3');
    quantity.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => node.querySelector('button[aria-label^="Add to cart:"]').click());
  expect(onProductAction).toHaveBeenLastCalledWith({ choiceId: id, intent: 'cart_add', quantity: 3 });
});

test('order choice offers explicit details while preserving its opaque generic action', async () => {
  const onChoose = jest.fn();
  const onOrderAction = jest.fn();
  await act(async () => root.render(<CustomerChoiceCards cards={[{
    version: 1, kind: 'order', choiceId: id, title: 'Order #41', detail: 'Owned order',
  }]} onChoose={onChoose} onOrderAction={onOrderAction} />));
  await act(async () => node.querySelector('[aria-label="View details: Order #41"]').click());
  expect(onOrderAction).toHaveBeenCalledWith({ choiceId: id, intent: 'order_details' });
  expect(onChoose).not.toHaveBeenCalled();
  await act(async () => node.querySelector('[aria-label="Choose order: Order #41"]').click());
  expect(onChoose).toHaveBeenCalledWith(id);
  expect(node.querySelector('input')).toBeNull();
});

test('address card has distinct checkout and edit actions with only its opaque choice', async () => {
  const onAddressAction = jest.fn();
  await act(async () => root.render(<CustomerChoiceCards cards={[{
    version: 1, kind: 'address', choiceId: id, title: 'Home', detail: '1 Main St',
  }]} onAddressAction={onAddressAction} />));
  expect(node.querySelector('[aria-label="Choose address: Home"]')).toBeNull();
  await act(async () => node.querySelector('[aria-label="Use for checkout: Home"]').click());
  expect(onAddressAction).toHaveBeenLastCalledWith({ choiceId: id, intent: 'address_checkout' });
  await act(async () => node.querySelector('[aria-label="Edit address: Home"]').click());
  expect(onAddressAction).toHaveBeenLastCalledWith({ choiceId: id, intent: 'address_edit' });
  expect(onAddressAction).toHaveBeenCalledTimes(2);
  await act(async () => root.render(<CustomerChoiceCards disabled cards={[{
    version: 1, kind: 'address', choiceId: id, title: 'Home', detail: '1 Main St',
  }]} onAddressAction={onAddressAction} />));
  expect(node.querySelector('[aria-label="Use for checkout: Home"]').disabled).toBe(true);
  expect(node.querySelector('[aria-label="Edit address: Home"]').disabled).toBe(true);
});

test('cart item has separate bounded update and remove actions without exposing an item ID', async () => {
  const onCartAction = jest.fn();
  await act(async () => root.render(<CustomerChoiceCards cards={[{
    version: 1, kind: 'cart_item', choiceId: id,
    title: 'Practice laptop', detail: 'In your cart', quantity: 2,
  }]} onCartAction={onCartAction} />));
  expect(node.querySelector('[aria-label="Choose cart item: Practice laptop"]')).toBeNull();
  const quantity = node.querySelector('[aria-label="New quantity for cart item: Practice laptop"]');
  expect(quantity.value).toBe('2');
  expect(quantity.classList.contains('ss-customer-choices__quantity')).toBe(true);
  await act(async () => node.querySelector('[aria-label="Update quantity: Practice laptop"]').click());
  expect(onCartAction).toHaveBeenLastCalledWith({ choiceId: id, intent: 'cart_update', quantity: 2 });
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(quantity, '100');
    quantity.dispatchEvent(new Event('input', { bubbles: true }));
  });
  expect(node.querySelector('[aria-label="Update quantity: Practice laptop"]').disabled).toBe(true);
  expect(node.querySelector('[aria-label="Remove from cart: Practice laptop"]').disabled).toBe(false);
  await act(async () => node.querySelector('[aria-label="Remove from cart: Practice laptop"]').click());
  expect(onCartAction).toHaveBeenLastCalledWith({ choiceId: id, intent: 'cart_remove' });
  expect(node.querySelector('input[id*="item-id"]')).toBeNull();
});

test('historical five-field cart cards retain the safe quantity fallback', async () => {
  const onCartAction = jest.fn();
  await act(async () => root.render(<CustomerChoiceCards cards={[{
    version: 1, kind: 'cart_item', choiceId: id,
    title: 'Practice laptop', detail: 'Historical saved cart card',
  }]} onCartAction={onCartAction} />));
  const quantity = node.querySelector('[aria-label="New quantity for cart item: Practice laptop"]');
  expect(quantity.value).toBe('1');
  await act(async () => node.querySelector('[aria-label="Update quantity: Practice laptop"]').click());
  expect(onCartAction).toHaveBeenCalledWith({ choiceId: id, intent: 'cart_update', quantity: 1 });
});

test('disables choices while a durable request is unresolved', async () => {
  await act(async () => root.render(<CustomerChoiceCards disabled cards={[{
    version: 1, kind: 'payment_method', choiceId: id,
    title: 'Approved practice card', detail: 'Synthetic payment scenario',
  }]} onChoose={jest.fn()} />));
  expect(node.querySelector('button').disabled).toBe(true);
  expect(node.textContent).not.toMatch(/card number|cvv/i);
});

test('disabled product choice keeps its default quantity visible in a dedicated control', async () => {
  const onProductAction = jest.fn();
  await act(async () => root.render(<CustomerChoiceCards disabled cards={[{
    version: 1, kind: 'product', choiceId: id,
    title: 'Practice laptop', detail: 'Available in this shop',
  }]} onProductAction={onProductAction} />));
  const quantity = node.querySelector('input[aria-label="Quantity for Practice laptop"]');
  expect(quantity).not.toBeNull();
  expect(quantity.value).toBe('1');
  expect(quantity.disabled).toBe(true);
  expect(quantity.classList.contains('ss-customer-choices__quantity')).toBe(true);
  expect(node.querySelector('button[aria-label="View details: Practice laptop"]').disabled).toBe(true);
  expect(node.querySelector('button[aria-label="Add to cart: Practice laptop"]').disabled).toBe(true);
  expect(onProductAction).not.toHaveBeenCalled();
});
