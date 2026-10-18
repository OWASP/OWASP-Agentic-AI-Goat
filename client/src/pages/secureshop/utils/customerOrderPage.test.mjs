import { decodeCustomerOrderPage } from './customerOrderPage.mjs';

const first = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const last = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const cards = [first, last].map(choiceId => ({ kind: 'order', choiceId }));

test('saved older-order cursor must match the last current opaque order card', () => {
  expect(decodeCustomerOrderPage({ nextCursor: last }, cards)).toEqual({ nextCursor: last });
  expect(decodeCustomerOrderPage({ nextCursor: null }, cards)).toEqual({ nextCursor: null });
  expect(decodeCustomerOrderPage(undefined, cards)).toBeNull();
  expect(() => decodeCustomerOrderPage({ nextCursor: first }, cards)).toThrow('Saved order page is invalid');
  expect(() => decodeCustomerOrderPage({ nextCursor: last, orderId: 42 }, cards)).toThrow('Saved order page is invalid');
  expect(() => decodeCustomerOrderPage({ nextCursor: [last] }, cards)).toThrow('Saved order page is invalid');
  expect(() => decodeCustomerOrderPage({ nextCursor: last.toUpperCase() }, cards)).toThrow('Saved order page is invalid');
});

test('saved filtered page binds the exact normalized product name to its cursor, including terminal page', () => {
  expect(decodeCustomerOrderPage({ nextCursor: last, productName: 'Practice laptop' }, cards))
    .toEqual({ nextCursor: last, productName: 'Practice laptop' });
  expect(decodeCustomerOrderPage({ nextCursor: null, productName: 'Practice laptop' }, cards))
    .toEqual({ nextCursor: null, productName: 'Practice laptop' });
  for (const productName of ['', ' Practice laptop', 'Practice laptop ', 'x'.repeat(129), null]) {
    expect(() => decodeCustomerOrderPage({ nextCursor: last, productName }, cards))
      .toThrow('Saved order page is invalid');
  }
  expect(() => decodeCustomerOrderPage({ nextCursor: first, productName: 'Practice laptop' }, cards))
    .toThrow('Saved order page is invalid');
});
