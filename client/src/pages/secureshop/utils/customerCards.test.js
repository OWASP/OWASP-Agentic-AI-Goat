import { decodeCustomerCards } from './customerCards.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const card = { version: 1, kind: 'product', choiceId: id, title: 'Practice laptop', detail: '$49.00 · in stock' };

test('accepts only the closed bounded server card shape and preserves plain text', () => {
  expect(decodeCustomerCards(undefined)).toBeUndefined();
  expect(decodeCustomerCards([card])).toEqual([card]);
  expect(decodeCustomerCards([{ ...card, title: '<b>Practice laptop</b>' }])[0].title)
    .toBe('<b>Practice laptop</b>');
});

test('accepts a bounded current cart quantity while retaining historical cart cards', () => {
  const cart = { ...card, kind: 'cart_item', quantity: 3 };
  const historical = { ...card, kind: 'cart_item' };
  expect(decodeCustomerCards([cart])).toEqual([cart]);
  expect(decodeCustomerCards([historical])).toEqual([historical]);
});

test.each([
  [{ ...card, productId: 7 }],
  [{ ...card, version: 2 }],
  [{ ...card, kind: 'payment_card' }],
  [{ ...card, choiceId: '7' }],
  [{ ...card, title: '😀'.repeat(65) }],
  [{ ...card, detail: '😀'.repeat(129) }],
  [{ ...card, quantity: 2 }],
  [{ ...card, kind: 'cart_item', quantity: 0 }],
  [{ ...card, kind: 'cart_item', quantity: 100 }],
  [{ ...card, kind: 'cart_item', quantity: '2' }],
  [{ ...card, kind: 'cart_item', quantity: 1.5 }],
  [{ ...card, kind: 'cart_item', quantity: undefined }],
  [{ ...card, kind: 'cart_item', quantity: null }],
  [card, card],
])('rejects untrusted or ambiguous cards', (...cards) => {
  expect(() => decodeCustomerCards(cards)).toThrow('Invalid customer choices');
});
