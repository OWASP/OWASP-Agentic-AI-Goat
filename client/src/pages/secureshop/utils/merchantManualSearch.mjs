import { sameRolePolicyMode } from './rolePolicyProposal.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Reflect.ownKeys(value).length === keys.length
  && keys.every(key => Object.hasOwn(value, key)
    && Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), 'value'));
const text = (value, max) => typeof value === 'string' && value.trim()
  && value.isWellFormed() && !value.includes('\0') && encoder.encode(value).byteLength <= max;
const fail = () => { throw new Error('Saved merchant manual search invalid'); };
const sha256 = async value => [...new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256',
  encoder.encode(value)))].map(byte => byte.toString(16).padStart(2, '0')).join('');
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;

export async function decodeMerchantManualSearch(value, mode, hops, stopReason) {
  if (value == null) return null;
  if (stopReason !== 'end_turn'
    || !exact(value, ['version', 'choiceId', 'productId', 'modeCapability', 'result'])
    || value.version !== 1 || !UUID.test(value.choiceId)
    || !Number.isSafeInteger(value.productId) || value.productId < 1 || value.productId > 2147483647
    || !sameRolePolicyMode(value.modeCapability, mode)
    || mode.featureId !== 'merchant_assistant'
    || mode.policyVersion !== 'owned-merchant-read-and-confirmation-v1') fail();
  const result = value.result;
  if (!exact(result, ['product', 'query', 'limit', 'count', 'hasMore', 'revision', 'status', 'sources'])
    || !exact(result.product, ['id', 'name']) || result.product.id !== value.productId
    || !text(result.product.name, 4096) || !text(result.query, 4096)
    || result.limit !== 3 || !Number.isInteger(result.count) || result.count < 0 || result.count > 3
    || typeof result.hasMore !== 'boolean' || (result.hasMore && result.count !== 3)
    || !['complete', 'oversized'].includes(result.status)
    || !exact(result.revision, ['revisionId', 'runtimeFingerprint', 'sourceSetDigest'])
    || !UUID.test(result.revision.revisionId)
    || !SHA.test(result.revision.runtimeFingerprint) || !SHA.test(result.revision.sourceSetDigest)
    || !Array.isArray(result.sources) || result.sources.length !== result.count
    || (result.status === 'oversized' && result.count === 0)
    || encoder.encode(JSON.stringify(result)).byteLength > 16384) fail();
  const seen = new Set();
  for (const source of result.sources) {
    if (!exact(source, ['sourceKind', 'sourceId', 'chunkIndex', 'text', 'score', 'sourceSha256',
      'filename', 'operationId', 'receiptSha256', 'documentDigest', 'completedAt', 'textBytes', 'textSha256'])
      || source.sourceKind !== 'manual' || !Number.isSafeInteger(source.sourceId) || source.sourceId < 1
      || !Number.isInteger(source.chunkIndex) || source.chunkIndex < 0 || source.chunkIndex > 128
      || !Number.isFinite(source.score) || source.score < -1 || source.score > 1
      || !SHA.test(source.sourceSha256) || !text(source.filename, 4096)
      || !UUID.test(source.operationId) || !SHA.test(source.receiptSha256)
      || !SHA.test(source.documentDigest) || !SHA.test(source.textSha256)
      || typeof source.completedAt !== 'string' || !Number.isFinite(Date.parse(source.completedAt))
      || new Date(source.completedAt).toISOString() !== source.completedAt
      || !Number.isInteger(source.textBytes) || source.textBytes < 1 || source.textBytes > 65536
      || seen.has(`${source.sourceId}:${source.chunkIndex}`)) fail();
    seen.add(`${source.sourceId}:${source.chunkIndex}`);
    if (result.status === 'oversized') {
      if (source.text !== null) fail();
    } else if (!text(source.text, 65536)
      || encoder.encode(source.text).byteLength !== source.textBytes
      || await sha256(source.text) !== source.textSha256) fail();
  }
  const hop = Array.isArray(hops) ? hops.at(-1) : null;
  if (hop?.tool !== 'merchant.manual_search' || hop.error || hop.result?.isError === true
    || !exact(hop.params, ['choiceId']) || hop.params.choiceId !== value.choiceId
    || !exact(hop.result, ['content']) || !Array.isArray(hop.result.content)
    || hop.result.content.length !== 1 || !exact(hop.result.content[0], ['type', 'text'])
    || hop.result.content[0].type !== 'text'
    || typeof hop.result.content[0].text !== 'string'
    || encoder.encode(hop.result.content[0].text).byteLength > 16384) fail();
  let observed;
  try { observed = JSON.parse(hop.result.content[0].text); } catch { fail(); }
  if (JSON.stringify(canonical(observed)) !== JSON.stringify(canonical(result))) fail();
  return Object.freeze({ ...value, result: Object.freeze({ ...result,
    product: Object.freeze({ ...result.product }), revision: Object.freeze({ ...result.revision }),
    sources: Object.freeze(result.sources.map(source => Object.freeze({ ...source }))) }) });
}
