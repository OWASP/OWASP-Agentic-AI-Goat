import { flushShopStorage, shopStorage, SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY } from './shopStorage.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const KEYS = ['version', 'shopUserId', 'scopeKey', 'sessionId', 'requestId',
  'proposalId', 'operationId', 'requestSha256', 'stage', 'startedAt'];
const discovery = value => value?.version === 2 && value.kind === 'discovery';
const awaiting = value => discovery(value) ? 'awaiting_registration' : 'awaiting_import';
const exact = value => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...KEYS, ...(discovery(value) ? ['kind'] : [])].sort().join(',');
const same = (left, right) => !!left && !!right && KEYS.every(key => left[key] === right[key]);
const invalid = () => { throw Error('Invalid saved MCP manifest assessment'); };

export function decodeAdminMcpManifestAssessmentReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).byteLength > 640) invalid();
  let value;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!exact(value) || !(value.version === 1 || discovery(value))
    || !Number.isSafeInteger(value.shopUserId) || value.shopUserId < 1
    || !SHA.test(value.scopeKey) || !SHA.test(value.requestSha256)
    || ![value.sessionId, value.requestId, value.proposalId, value.operationId]
      .every(id => typeof id === 'string' && UUID.test(id))
    || value.proposalId !== value.operationId
    || ![awaiting(value), 'ready', 'submitted'].includes(value.stage)
    || !Number.isSafeInteger(value.startedAt) || value.startedAt < 1) invalid();
  return Object.freeze(value);
}

export function createAdminMcpManifestAssessmentStore({ storage, flush,
  key = SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY } = {}) {
  if (typeof storage?.getItem !== 'function' || typeof storage?.setItem !== 'function'
    || typeof storage?.removeItem !== 'function' || typeof flush !== 'function'
    || key !== SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY) invalid();
  const read = () => decodeAdminMcpManifestAssessmentReference(storage.getItem(key));
  return Object.freeze({
    read(shopUserId) {
      if (!Number.isSafeInteger(shopUserId) || shopUserId < 1) invalid();
      const value = read(); return value?.shopUserId === shopUserId ? value : null;
    },
    async save(reference, current = () => true) {
      const value = decodeAdminMcpManifestAssessmentReference(JSON.stringify({ version: 1, ...reference }));
      if (value.stage !== awaiting(value) || current() !== true || read() !== null) invalid();
      storage.setItem(key, JSON.stringify(value)); await flush();
      if (current() !== true || !same(read(), value)) invalid();
      return value;
    },
    async advance(reference, stage, current = () => true) {
      const before = decodeAdminMcpManifestAssessmentReference(JSON.stringify(reference));
      if (current() !== true || !same(read(), before)
        || (before.stage === awaiting(before) && stage !== 'ready')
        || (before.stage === 'ready' && stage !== 'submitted')
        || before.stage === 'submitted') invalid();
      const next = Object.freeze({ ...before, stage });
      storage.setItem(key, JSON.stringify(next)); await flush();
      if (current() !== true || !same(read(), next)) invalid();
      return next;
    },
    async clear(reference, current = () => true) {
      const value = decodeAdminMcpManifestAssessmentReference(JSON.stringify(reference));
      if (current() !== true || !same(read(), value)) invalid();
      storage.removeItem(key); await flush();
      if (current() !== true || read() !== null) invalid();
    },
  });
}

export const adminMcpManifestAssessmentStore = createAdminMcpManifestAssessmentStore({
  storage: shopStorage, flush: flushShopStorage, key: SHOP_ADMIN_MCP_MANIFEST_ASSESSMENT_KEY,
});
