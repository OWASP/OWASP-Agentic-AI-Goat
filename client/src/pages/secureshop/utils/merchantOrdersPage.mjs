import { validOrderPageProductName } from './orderPageProductName.mjs';

const CURSOR = /^[A-Za-z0-9_-]{1,160}$/;

export function decodeMerchantOrdersPage(value) {
  if (value === undefined || value === null) return null;
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || !['nextCursor', 'nextCursor,productName'].includes(Object.keys(value).sort().join(','))
    || (value.nextCursor !== null && (typeof value.nextCursor !== 'string' || !CURSOR.test(value.nextCursor)))
    || (Object.hasOwn(value, 'productName') && !validOrderPageProductName(value.productName))) {
    throw new Error('Saved merchant order page is invalid');
  }
  return Object.freeze({ nextCursor: value.nextCursor,
    ...(Object.hasOwn(value, 'productName') ? { productName: value.productName } : {}) });
}
