import { decodeMerchantOrdersPage } from './merchantOrdersPage.mjs';

test('merchant order pages preserve legacy and exact filtered cursor pairs', () => {
  expect(decodeMerchantOrdersPage(null)).toBeNull();
  expect(decodeMerchantOrdersPage({ nextCursor: 'Ab9_-' })).toEqual({ nextCursor: 'Ab9_-' });
  expect(decodeMerchantOrdersPage({ nextCursor: null, productName: 'Practice laptop' }))
    .toEqual({ nextCursor: null, productName: 'Practice laptop' });
  expect(decodeMerchantOrdersPage({ nextCursor: 'Ab9_-', productName: 'Practice laptop' }))
    .toEqual({ nextCursor: 'Ab9_-', productName: 'Practice laptop' });
});

test('merchant order page rejects invalid cursor, filter, and extra fields', () => {
  for (const value of [
    { nextCursor: 5 }, { nextCursor: '' }, { nextCursor: 'x'.repeat(161) },
    { nextCursor: 'bad=' }, { nextCursor: 'Ab9_-', productName: null },
    { nextCursor: 'Ab9_-', productName: ' Practice laptop' },
    { nextCursor: 'Ab9_-', productName: 'x'.repeat(129) },
    { nextCursor: 'Ab9_-', productName: '\ud800' },
    { nextCursor: 'Ab9_-', productName: 'Practice laptop', orderId: 41 },
  ]) expect(() => decodeMerchantOrdersPage(value)).toThrow('Saved merchant order page is invalid');
});
