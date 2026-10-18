import { validOrderPageProductName } from './orderPageProductName.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export function decodeCustomerOrderPage(value, cards = []) {
  if (value === undefined || value === null) return null;
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || !['nextCursor', 'nextCursor,productName'].includes(Object.keys(value).sort().join(','))
    || (Object.hasOwn(value, 'productName') && !validOrderPageProductName(value.productName))
    || (value.nextCursor !== null && (typeof value.nextCursor !== 'string'
      || !UUID.test(value.nextCursor)
      || cards.filter(card => card.kind === 'order').at(-1)?.choiceId !== value.nextCursor))) {
    throw new Error('Saved order page is invalid');
  }
  return Object.freeze({ nextCursor: value.nextCursor,
    ...(Object.hasOwn(value, 'productName') ? { productName: value.productName } : {}) });
}
