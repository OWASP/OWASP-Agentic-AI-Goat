'use strict';

const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { createLaunchScope } = require('./secureshopConversationBinding');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SHA = /^[a-f0-9]{64}$/;
const FIELDS = Object.freeze(['name', 'description', 'category', 'price']);
const LISTING_CREATE_INPUT_SCHEMA = Object.freeze({ type: 'object',
  properties: Object.freeze({
    presentation: { type: 'string', enum: ['html'] },
    name: { type: 'string', minLength: 1, maxLength: 4096 },
    description: { type: ['string', 'null'], maxLength: 65536 },
    category: { type: ['string', 'null'], maxLength: 1024 },
    price: { type: 'number', minimum: 0, maximum: 99999999.99, multipleOf: 0.01 },
  }), required: Object.freeze(['name', 'price']), additionalProperties: false });

const fail = (code = 'LISTING_CREATE_INVALID') =>
  Object.assign(new Error('Owned listing creation unavailable'), { code });
const exact = (value, keys) => value !== null && typeof value === 'object'
  && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

function normalizeListingCreateInput(value) {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).some(key => ![...FIELDS, 'presentation'].includes(key))
      || !Object.hasOwn(value, 'name') || !Object.hasOwn(value, 'price')) throw fail();
  if (typeof value.name !== 'string' || !value.name.trim()
      || Buffer.byteLength(value.name, 'utf8') > 4096) throw fail();
  const output = { name: value.name };
  for (const [key, max] of [['description', 65536], ['category', 1024]]) {
    const item = Object.hasOwn(value, key) ? value[key] : null;
    if (item !== null && (typeof item !== 'string' || Buffer.byteLength(item, 'utf8') > max)) throw fail();
    output[key] = item;
  }
  const price = value.price;
  if (typeof price !== 'number' || !Number.isFinite(price) || price < 0 || price > 99999999.99
      || Math.abs(price * 100 - Math.round(price * 100)) > 1e-8) throw fail();
  output.price = Number(price.toFixed(2));
  if (Object.hasOwn(value, 'presentation')) {
    if (value.presentation !== 'html' || typeof output.description !== 'string' || !output.description
        || !output.description.isWellFormed() || output.description.includes('\0')
        || Buffer.byteLength(output.description) > 8192) throw fail();
    output.presentation = 'html';
  }
  return Object.freeze(output);
}

function listingCreateScopeKey(binding, actorId, session) {
  if (!binding?.scene || ![binding.targetId, binding.launchId, binding.scenarioId,
    binding.scene.sceneId, binding.scene.grantId, session?.sessionId].every(value => UUID.test(value || ''))
      || ![binding.generation, binding.scene.sceneGeneration, binding.platformOwnerId,
        binding.platformSessionId, actorId].every(value => Number.isSafeInteger(value) && value >= 1)
      || !/^[1-9][0-9]*$/.test(session.authorityVersion || '')) throw fail('SHOP_AUTH_INVALID');
  return digest(['owned-merchant-listing-create.v1', binding.targetId.toLowerCase(), binding.launchId.toLowerCase(),
    binding.scenarioId.toLowerCase(), binding.generation, binding.platformOwnerId,
    binding.platformSessionId, binding.scene.sceneId.toLowerCase(), binding.scene.sceneGeneration,
    binding.scene.grantId.toLowerCase(), actorId, session.sessionId.toLowerCase(), session.authorityVersion]);
}

function escapeListingHtml(value) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function validateListingCreateExecution(value) {
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'mode', 'generation', 'modeStamp', 'scope'])
      || value.version !== 1 || value.featureId !== 'listings'
      || value.policyVersion !== require('./secureshopFeatureModeAuthority').POLICIES.listings
      || !['vuln', 'fixed'].includes(value.mode) || !Number.isSafeInteger(value.generation)
      || value.generation < 0 || value.generation > 2147483647
      || typeof value.modeStamp !== 'string' || !value.modeStamp || Buffer.byteLength(value.modeStamp) > 128
      || !exact(value.scope, ['launchId', 'scenarioId', 'generation', 'platformOwnerId', 'platformSessionId'])) throw fail();
  const scope = createLaunchScope(value.scope);
  if (!isDeepStrictEqual(scope, value.scope)) throw fail();
  return Object.freeze({ version: 1, featureId: 'listings', policyVersion: value.policyVersion,
    mode: value.mode, generation: value.generation, modeStamp: value.modeStamp, scope });
}
function validateListingCreateSource(value) {
  if (!exact(value, ['version', 'kind', 'listing', 'authoredHtml', 'storedHtml', 'preparation', 'execution'])
      || Buffer.byteLength(JSON.stringify(value)) > 131072
      || value.version !== 1 || value.kind !== 'merchant_authored_html'
      || !exact(value.listing, [...FIELDS, 'presentation'])) throw fail();
  const listing = normalizeListingCreateInput(value.listing), p = value.preparation;
  if (listing.presentation !== 'html' || value.authoredHtml !== listing.description
      || !exact(p, ['sessionId', 'requestId', 'step', 'callId', 'message'])
      || ![p.sessionId, p.requestId].every(id => UUID.test(id || '') && id === id.toLowerCase())
      || !Number.isSafeInteger(p.step) || p.step < 1 || p.step > 4
      || typeof p.callId !== 'string' || !p.callId || Buffer.byteLength(p.callId) > 128
      || typeof p.message !== 'string' || !p.message.isWellFormed() || p.message.includes('\0')
      || Buffer.byteLength(p.message) > 8192 || !p.message.includes(value.authoredHtml)) throw fail();
  const execution = validateListingCreateExecution(value.execution);
  if (value.storedHtml !== (execution.mode === 'vuln' ? value.authoredHtml : escapeListingHtml(value.authoredHtml))
      || Buffer.byteLength(value.storedHtml) > 65536) throw fail();
  return Object.freeze({ version: 1, kind: 'merchant_authored_html', listing, authoredHtml: value.authoredHtml,
    storedHtml: value.storedHtml, preparation: Object.freeze({ sessionId: p.sessionId,
      requestId: p.requestId, step: p.step, callId: p.callId, message: p.message }), execution });
}
function listingCreateSourceDigest(value) { return digest(validateListingCreateSource(value)); }
function listingCreateRequestDigest(value) {
  if (!SHA.test(value?.scopeKey || '') || value.currency !== 'USD'
      || value.initialStock !== 0 || value.status !== 'active') throw fail();
  const listing = normalizeListingCreateInput(value.listing);
  if (listing.presentation === 'html') {
    if (value.version !== 2) throw fail();
    const source = validateListingCreateSource(value.source);
    if (!isDeepStrictEqual(listing, source.listing)) throw fail();
    return digest({ version: 2, listing, currency: 'USD', initialStock: 0,
      status: 'active', templateSource: null, images: [], scopeKey: value.scopeKey, source });
  }
  if (value.version === 2 || Object.hasOwn(value, 'source')) throw fail();
  return digest({ version: 1, listing, currency: 'USD',
    initialStock: 0, status: 'active', templateSource: null, images: [], scopeKey: value.scopeKey });
}
function validateListingCreatePreview(value) {
  const raw = value?.version === 2;
  if (!exact(value, ['version', 'listing', 'currency', 'initialStock', 'status', 'scopeKey', 'requestSha256',
    ...(raw ? ['source'] : [])]) || ![1, 2].includes(value.version) || !SHA.test(value.requestSha256 || '')
      || !exact(value.listing, [...FIELDS, ...(raw ? ['presentation'] : [])])) throw fail();
  const listing = normalizeListingCreateInput(value.listing);
  if (listingCreateRequestDigest({ ...value, listing }) !== value.requestSha256) throw fail();
  return Object.freeze({ version: raw ? 2 : 1, listing, currency: 'USD', initialStock: 0,
    status: 'active', scopeKey: value.scopeKey, requestSha256: value.requestSha256,
    ...(raw ? { source: validateListingCreateSource(value.source) } : {}) });
}

function validateListingCreateReceipt(value, operationId) {
  if (!UUID.test(operationId || '') || !value || Object.getPrototypeOf(value) !== Object.prototype
      || value.operationId !== operationId.toLowerCase() || !SHA.test(value.scopeKey || '')) throw fail();
  if (value.status === 'not_found') {
    if (!exact(value, ['operationId', 'status', 'scopeKey'])) throw fail();
    return Object.freeze({ ...value });
  }
  const raw = value.version === 2;
  if (!exact(value, ['version', 'operationId', 'productId', 'status', 'scopeKey',
    'requestSha256', 'sourceSha256', 'receiptSha256', 'replayed',
    ...(raw ? ['source', 'sourceDocumentSha256'] : [])])
      || ![1, 2].includes(value.version) || value.status !== 'completed' || typeof value.replayed !== 'boolean'
      || !Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > 2147483647
      || ![value.requestSha256, value.sourceSha256, value.receiptSha256].every(hash => SHA.test(hash || '')))
    throw fail();
  if (raw) {
    const source = validateListingCreateSource(value.source);
    if (value.sourceDocumentSha256 !== listingCreateSourceDigest(source)
        || value.requestSha256 !== listingCreateRequestDigest({ version: 2, listing: source.listing,
          source, scopeKey: value.scopeKey, currency: 'USD', initialStock: 0, status: 'active' })) throw fail();
    return Object.freeze({ ...value, source });
  }
  return Object.freeze({ ...value });
}

module.exports = { escapeListingHtml, validateListingCreateExecution, validateListingCreateSource, listingCreateSourceDigest, LISTING_CREATE_INPUT_SCHEMA, normalizeListingCreateInput,
  listingCreateScopeKey, listingCreateRequestDigest, validateListingCreatePreview,
  validateListingCreateReceipt, listingCreateDigest: digest, LISTING_CREATE_SHA: SHA };
