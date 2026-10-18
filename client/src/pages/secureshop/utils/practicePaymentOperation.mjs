import { flushShopStorage, shopStorage, SHOP_PRACTICE_PAYMENT_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const bytes = value => new TextEncoder().encode(value).byteLength;
const same = (a, b) => !!a && Object.keys(a).length === Object.keys(b).length
  && Object.keys(a).every(key => a[key] === b[key]);
const text = (value, max) => typeof value === 'string' && value.trim() && value.isWellFormed()
  && !value.includes('\0') && bytes(value) <= max;

export function decodePracticePaymentSetup(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'kind', 'suggestedScenario']) || value.version !== 1
    || value.kind !== 'practice_payment_setup' || !['approved', 'declined'].includes(value.suggestedScenario)) {
    throw Error('Saved payment setup is invalid.');
  }
  return Object.freeze({ ...value });
}
export function decodePracticePaymentReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || bytes(raw) > 512) throw Error('Invalid saved payment reference.');
  let value; try { value = JSON.parse(raw); } catch { throw Error('Invalid saved payment reference.'); }
  if (!exact(value, ['version', 'scopeKey', 'operationId', 'scenario']) || value.version !== 1
    || !SHA.test(value.scopeKey || '') || !UUID.test(value.operationId || '')
    || !['approved', 'declined'].includes(value.scenario)) throw Error('Invalid saved payment reference.');
  return Object.freeze({ ...value });
}
export const readPracticePaymentReference = () => decodePracticePaymentReference(shopStorage.getItem(SHOP_PRACTICE_PAYMENT_KEY));
export async function savePracticePaymentReference(reference) {
  const next = decodePracticePaymentReference(JSON.stringify(reference));
  if (readPracticePaymentReference()) throw Error('Check the saved practice payment before creating another.');
  shopStorage.setItem(SHOP_PRACTICE_PAYMENT_KEY, JSON.stringify(next)); await flushShopStorage();
  if (!same(readPracticePaymentReference(), next)) throw Error('Saved practice payment changed. No payment was created.');
  return next;
}
export async function clearPracticePaymentReference(reference, current = () => true) {
  const expected = decodePracticePaymentReference(JSON.stringify(reference));
  if (!current() || !same(readPracticePaymentReference(), expected)) throw Error('Saved practice payment changed. Check it again.');
  try {
    shopStorage.removeItem(SHOP_PRACTICE_PAYMENT_KEY); await flushShopStorage();
    if (!current() || readPracticePaymentReference()) throw Error('Saved practice payment changed. Check it again.');
  } catch (error) {
    if (current()) try {
      if (!readPracticePaymentReference()) { shopStorage.setItem(SHOP_PRACTICE_PAYMENT_KEY, JSON.stringify(expected)); await flushShopStorage(); }
    } catch { /* A failed acknowledged restore keeps the outcome uncertain. */ }
    throw error;
  }
}
function decodeCards(value) {
  if (!exact(value, ['cards']) || !Array.isArray(value.cards)
    || value.cards.length !== 1 || !exact(value.cards[0], ['version', 'kind', 'choiceId', 'title', 'detail'])
    || value.cards[0].version !== 1 || value.cards[0].kind !== 'payment_method'
    || !UUID.test(value.cards[0].choiceId || '') || !text(value.cards[0].title, 256)
    || !text(value.cards[0].detail, 512)) throw Error('Saved practice payment receipt is invalid.');
  return Object.freeze(value.cards.map(card => Object.freeze({ ...card })));
}
export function decodePracticePaymentMethods(value) {
  if (!value || !SHA.test(value.scopeKey || '') || !Array.isArray(value.cards) || value.cards.length > 12) {
    throw Error('Practice payment choices are unavailable.');
  }
  for (const card of value.cards) {
    if (!exact(card, ['version', 'kind', 'choiceId', 'title', 'detail']) || card.version !== 1
      || card.kind !== 'payment_method' || !UUID.test(card.choiceId || '') || !text(card.title, 256) || !text(card.detail, 512)) {
      throw Error('Practice payment choices are unavailable.');
    }
  }
  return Object.freeze({ scopeKey: value.scopeKey, cards: Object.freeze(value.cards.map(card => Object.freeze({ ...card }))) });
}
export function decodePracticePaymentOperation(value, reference) {
  const saved = decodePracticePaymentReference(JSON.stringify(reference));
  if (exact(value, ['scopeKey', 'operationId', 'status']) && value.scopeKey === saved.scopeKey
    && value.operationId === saved.operationId && value.status === 'not_found') return Object.freeze({ status: 'not_found' });
  if (!exact(value, ['scopeKey', 'operationId', 'status', 'paymentScenario', 'receipt']) || value.scopeKey !== saved.scopeKey
    || value.operationId !== saved.operationId || value.status !== 'completed'
    || value.paymentScenario !== saved.scenario
    || !exact(value.receipt, ['version', 'operationId', 'kind', 'status', 'result', 'replayed'])
    || value.receipt.version !== 1 || value.receipt.operationId !== saved.operationId
    || value.receipt.kind !== 'payment.create' || value.receipt.status !== 'completed'
    || value.receipt.replayed !== true) throw Error('Saved practice payment receipt is invalid.');
  return Object.freeze({ status: 'completed', cards: decodeCards(value.receipt.result) });
}
