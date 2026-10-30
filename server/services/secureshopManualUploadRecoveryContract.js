'use strict';

const { createHash } = require('node:crypto');
const { createLaunchScope } = require('./secureshopConversationBinding');
const { executionScope } = require('./secureshopSceneBinding');
const SHA = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const FIELDS = Object.freeze(['productId', 'sha256', 'sizeBytes', 'filename', 'mime', 'isPublic']);
const invalid = () => Object.assign(new Error('Invalid manual upload recovery descriptor'), { code: 'INVALID_ARGUMENT' });
function descriptor(value) {
  const properties = value && [Object.prototype, null].includes(Object.getPrototypeOf(value))
    ? Object.getOwnPropertyDescriptors(value) : null;
  if (!properties || Reflect.ownKeys(properties).length !== FIELDS.length
      || FIELDS.some(key => !properties[key] || !Object.hasOwn(properties[key], 'value'))) throw invalid();
  const copy = Object.fromEntries(FIELDS.map(key => [key, properties[key].value]));
  if (!Number.isSafeInteger(copy.productId) || copy.productId < 1 || copy.productId > 2147483647
      || typeof copy.sha256 !== 'string' || !SHA.test(copy.sha256)
      || !Number.isSafeInteger(copy.sizeBytes) || copy.sizeBytes < 1 || copy.sizeBytes > 20 * 1024 * 1024
      || typeof copy.isPublic !== 'boolean'
      || [['filename', 255], ['mime', 128]].some(([key, limit]) => typeof copy[key] !== 'string'
        || !copy[key].trim() || Buffer.byteLength(copy[key]) > limit || /[\x00-\x1f\x7f]/.test(copy[key]))) throw invalid();
  return Object.freeze(copy);
}
function recoveryKey(value) {
  if (typeof value !== 'string' || !SHA.test(value)) throw invalid();
  return value;
}
function operationId(scope, merchantId, value) {
  const source = descriptor(value);
  if (!Number.isSafeInteger(merchantId) || merchantId < 1 || merchantId > 2147483647) throw invalid();
  // Keep the original v1 identity byte-for-byte. Size is checked against the
  // receipt, not added to the historical operation identity.
  const hash = createHash('sha256').update(JSON.stringify(['owasp-ai-goat-manual-v1', createLaunchScope(scope),
    merchantId, source.productId, source.sha256, source.filename, source.mime, source.isPublic])).digest('hex');
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-5${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}
function scopeKey(binding, merchantId, session) {
  if (!binding || !UUID.test(binding.targetId || '') || !Number.isSafeInteger(merchantId) || merchantId < 1
      || !UUID.test(session?.sessionId || '') || typeof session?.authorityVersion !== 'string'
      || !/^[1-9][0-9]*$/.test(session.authorityVersion)) throw invalid();
  const scope = createLaunchScope(executionScope(binding));
  return createHash('sha256').update(JSON.stringify(['owasp-ai-goat-manual-recovery-v1', scope,
    binding.targetId, binding.scene ? [binding.scene.sceneId, binding.scene.sceneGeneration, binding.scene.grantId] : null,
    merchantId, session.sessionId.toLowerCase(), session.authorityVersion])).digest('hex');
}
function projectReceipt(receipt, value, merchantId, expectedOperationId) {
  const source = descriptor(value);
  if (!receipt || receipt.operationId !== expectedOperationId || receipt.merchantId !== merchantId
      || receipt.productId !== source.productId || receipt.fileReceipt?.sha256 !== source.sha256
      || receipt.fileReceipt?.bytes !== source.sizeBytes || receipt.filename !== source.filename
      || receipt.mime !== source.mime || receipt.isPublic !== source.isPublic
      || !Number.isSafeInteger(receipt.documentCount) || receipt.documentCount < 1 || receipt.documentCount > 129
      || !Number.isSafeInteger(receipt.manualSourceId) || receipt.manualSourceId < 1
      || !Array.isArray(receipt.chunkIds) || receipt.chunkIds.length !== receipt.documentCount
      || Array.from({length:receipt.documentCount}, (_, i) => `manual:${receipt.manualSourceId}:${i}`)
        .some((id, i) => receipt.chunkIds[i] !== id)
      || typeof receipt.completedAt !== 'string' || !Number.isFinite(Date.parse(receipt.completedAt))) {
    throw Object.assign(new Error('Manual indexing receipt does not match'), { code: 'BOUND_MANUAL_INGEST_MISMATCH' });
  }
  return Object.freeze({...source, chunkCount:receipt.documentCount,
    chunkIds:Object.freeze([...receipt.chunkIds]), completedAt:receipt.completedAt});
}
module.exports = { normalizeManualUploadDescriptor:descriptor, manualUploadOperationId:operationId,
  manualUploadRecoveryScopeKey:scopeKey, validateManualUploadRecoveryKey:recoveryKey,
  projectManualUploadReceipt:projectReceipt };
