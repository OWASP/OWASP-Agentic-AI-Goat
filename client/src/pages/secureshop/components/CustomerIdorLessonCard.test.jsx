import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import CustomerIdorLessonCard from './CustomerIdorLessonCard.jsx';

const cards = [
  { action: 'cart_remove', numericId: 41, label: 'Reserved lesson cart item' },
  { action: 'order_status', numericId: 72, label: 'Reserved lesson order' },
];

let root;
let node;
beforeEach(() => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div');
  document.body.append(node);
  root = createRoot(node);
});
afterEach(async () => {
  await act(async () => root.unmount());
  node.remove();
});

async function render(props = {}) {
  await act(async () => root.render(<CustomerIdorLessonCard cards={cards} mode="vuln" {...props} />));
}

test('renders only reserved synthetic targets and emits their exact server-provided selections', async () => {
  const onSelect = jest.fn();
  await render({ onSelect });
  expect(node.querySelector('section[aria-label="Customer access control lesson"]')).not.toBeNull();
  expect(node.textContent).toContain('Synthetic access-control lesson · Vulnerable mode');
  expect(node.textContent).toContain('Reserved lesson cart item #41');
  expect(node.textContent).toContain('Reserved lesson order #72');
  expect(node.querySelectorAll('button')[1].textContent).toBe('Read full order details');
  expect(node.textContent).not.toMatch(/victim|shipping address|payment method/i);
  await act(async () => node.querySelector('button').click());
  expect(onSelect).toHaveBeenLastCalledWith({ action: 'cart_remove', numericId: 41 });
  await act(async () => node.querySelectorAll('button')[1].click());
  expect(onSelect).toHaveBeenLastCalledWith({ action: 'order_status', numericId: 72 });
  expect(onSelect).toHaveBeenCalledTimes(2);
  expect(node.textContent).not.toMatch(/saved result:|completed/i);
});

test('distinct lesson actions may use the same number from separate store sequences', async () => {
  const onSelect = jest.fn();
  await render({ cards: [cards[0], { ...cards[1], numericId: 41 }], onSelect });
  expect(node.querySelectorAll('button')).toHaveLength(2);
  await act(async () => node.querySelectorAll('button')[1].click());
  expect(onSelect).toHaveBeenCalledWith({ action: 'order_status', numericId: 41 });
});

test('loading, busy, error, unavailable mode and missing callback cannot submit or imply success', async () => {
  const onSelect = jest.fn();
  for (const props of [
    { loading: true }, { busy: true }, { error: 'Request unavailable' }, { mode: 'unknown' },
    { onSelect: undefined },
  ]) {
    await render({ onSelect, ...props });
    if (props.loading) expect(node.textContent).toContain('Loading lesson targets');
    if (props.busy) expect(node.textContent).toContain('Waiting for the saved result');
    if (props.error) expect(node.querySelector('[role="alert"]').textContent).toBe('Request unavailable');
    expect([...node.querySelectorAll('button')].every(button => button.disabled)).toBe(true);
    expect(node.textContent).not.toMatch(/cart item removed|order details returned/i);
  }
  expect(onSelect).not.toHaveBeenCalled();
});

test('only a parent-verified closed saved result for an exact target is rendered', async () => {
  await render({ savedResult: { action: 'cart_remove', numericId: 41, status: 'deleted' } });
  expect(node.textContent).toContain('Saved result: cart item removed.');
  await render({ mode: 'fixed', savedResult: { action: 'order_status', numericId: 72, status: 'denied' } });
  expect(node.textContent).toContain('Fixed mode');
  expect(node.textContent).toContain('Saved result: access denied.');
  await render({ savedResult: { action: 'order_status', numericId: 72, status: 'disclosed' } });
  expect(node.textContent).toContain('Saved result: order details returned.');
  for (const savedResult of [
    { action: 'cart_remove', numericId: 41, status: 'disclosed' },
    { action: 'order_status', numericId: 41, status: 'disclosed' },
    { action: 'order_status', numericId: 72, status: 'disclosed', privateOrder: 'secret' },
  ]) {
    await render({ savedResult });
    expect(node.textContent).toContain('Saved result unavailable.');
    expect(node.textContent).not.toContain('secret');
  }
  await render({ mode: 'fixed', savedResult: { action: 'cart_remove', numericId: 41, status: 'deleted' } });
  expect(node.textContent).toContain('Saved result unavailable.');
  expect(node.textContent).not.toContain('cart item removed');
  await render({ mode: 'unknown', savedResult: { action: 'order_status', numericId: 72, status: 'disclosed' } });
  expect(node.textContent).toContain('Saved result unavailable.');
  expect(node.textContent).not.toContain('order details returned');
  await render({ savedResult: { action: 'cart_remove', numericId: 41, status: 'denied' } });
  expect(node.textContent).toContain('Saved result: access denied.');
});

test('malformed cards and extra private fields fail closed without rendering or selecting them', async () => {
  const onSelect = jest.fn();
  for (const invalidCards of [
    [cards[0]],
    [{ ...cards[0], numericId: 0 }, cards[1]],
    [{ ...cards[0], numericId: '41' }, cards[1]],
    [{ ...cards[0], privateOwner: '<img src=x>' }, cards[1]],
    [{ ...cards[0], label: 'Victim cart item' }, cards[1]],
    [cards[0], { ...cards[1], action: 'cart_remove', label: 'Reserved lesson cart item' }],
  ]) {
    await render({ cards: invalidCards, onSelect });
    expect(node.querySelectorAll('button')).toHaveLength(0);
    expect(node.textContent).toContain('Lesson targets unavailable.');
    expect(node.querySelector('img')).toBeNull();
  }
  expect(onSelect).not.toHaveBeenCalled();
});
