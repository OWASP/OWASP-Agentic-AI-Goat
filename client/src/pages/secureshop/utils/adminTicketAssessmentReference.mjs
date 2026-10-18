import { flushShopStorage, shopStorage, SHOP_ADMIN_TICKET_ASSESSMENT_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const KEYS = ['version', 'shopUserId', 'ticketId', 'requestId', 'startedAt'];
export const ADMIN_TICKET_ASSESSMENT_KEY = 'secureshop.admin-ticket.assessment.v1';
const exact = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...KEYS].sort().join(',');
const same = (a, b) => !!a && !!b && KEYS.every(key => a[key] === b[key]);
const invalid = () => { throw Error('Invalid saved ticket assessment'); };

export function decodeAdminTicketAssessmentReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 512) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value) || value.version !== 1
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || typeof value.ticketId !== 'string' || !/^[1-9]\d{0,18}$/.test(value.ticketId)
    || BigInt(value.ticketId) > 9223372036854775807n
    || typeof value.requestId !== 'string' || !UUID.test(value.requestId)
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze(value);
}

export function createAdminTicketAssessmentStore({ storage, flush,
  key = ADMIN_TICKET_ASSESSMENT_KEY } = {}) {
  if (typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function'
    || typeof storage?.removeItem !== 'function' || typeof flush !== 'function'
    || key !== ADMIN_TICKET_ASSESSMENT_KEY) invalid();
  const read = () => decodeAdminTicketAssessmentReference(storage.getItem(key));
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      const value = read();
      return value?.shopUserId === shopUserId ? value : null;
    },
    async save(reference, current = () => true) {
      const value = decodeAdminTicketAssessmentReference(JSON.stringify({ version: 1, ...reference }));
      if (current() !== true || read() !== null) invalid();
      storage.setItem(key, JSON.stringify(value));
      await flush();
      if (current() !== true || !same(read(), value)) invalid();
      return value;
    },
    async clear(reference, current = () => true) {
      const value = decodeAdminTicketAssessmentReference(JSON.stringify({ version: 1, ...reference }));
      if (current() !== true || !same(read(), value)) invalid();
      try {
        storage.removeItem(key); await flush();
        if (current() !== true || read() !== null) invalid();
      } catch (error) {
        if (current() === true) try {
          if (read() === null) { storage.setItem(key, JSON.stringify(value)); await flush(); }
        } catch { /* The hook retains the unresolved reference. */ }
        throw error;
      }
    },
  });
}

export const adminTicketAssessmentStore = createAdminTicketAssessmentStore({
  storage: shopStorage, flush: flushShopStorage, key: SHOP_ADMIN_TICKET_ASSESSMENT_KEY,
});
