'use strict';
const { createHash } = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA = /^[0-9a-f]{64}$/;
const TEMPLATE_VERSION = 'synthetic-test-v1';
const OWNER_LIMIT = 3, SENDER_LIMIT = 20, PREPARE_MS = 600000, DISPATCH_MS = 20000;
const error = code => Object.assign(new Error('External test mail unavailable'), { code });
const exact = (v, keys) => v && Object.getPrototypeOf(v) === Object.prototype
  && Object.keys(v).sort().join(',') === [...keys].sort().join(',');
const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function address(value, domain) {
  if (typeof value !== 'string' || value.length > 254 || value !== value.trim()
    || !/^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}@[A-Za-z0-9.-]+$/.test(value)) throw error('INVALID_ARGUMENT');
  const normalized = value.toLowerCase(), [local, host] = normalized.split('@');
  if (local.endsWith('.') || local.includes('..') || host !== domain) throw error('INVALID_ARGUMENT');
  return normalized;
}
const normalizeExternalRecipient = value => address(value, 'sharklasers.com');
const normalizeExternalSender = value => address(value, 'gmail.com');
function makeExternalMailPreview({ operationId, sender, recipient }) {
  if (!UUID.test(operationId || '')) throw error('INVALID_ARGUMENT');
  return Object.freeze({ operationId, sender: normalizeExternalSender(sender),
    recipient: normalizeExternalRecipient(recipient), subject: 'SecureShop synthetic delivery test',
    text: `This is a manually requested SecureShop synthetic delivery test.\nNo shop, inbox, account or private document content is included.\nTest operation: ${operationId}\n` });
}
function validateExternalMailPreview(value) {
  if (!exact(value, ['operationId', 'sender', 'recipient', 'subject', 'text'])) throw error('INVALID_ARGUMENT');
  const canonical = makeExternalMailPreview(value);
  if (Object.keys(canonical).some(k => canonical[k] !== value[k])) throw error('INVALID_ARGUMENT');
  return canonical;
}
function externalMailRequestSha256(preview, scopeKey) {
  if (!SHA.test(scopeKey || '')) throw error('INVALID_ARGUMENT');
  return hash({ version: 1, origin: 'manual-external-test', scopeKey,
    templateVersion: TEMPLATE_VERSION, ...validateExternalMailPreview(preview) });
}
function prepareInput(value) {
  if (!exact(value, ['version','operationId','recipient','scopeKey']) || value.version !== 1
    || !UUID.test(value.operationId || '') || !SHA.test(value.scopeKey || '')) throw error('INVALID_ARGUMENT');
  return { ...value, recipient: normalizeExternalRecipient(value.recipient) };
}
function confirmationInput(value) {
  if (!exact(value, ['version','operationId','requestSha256']) || value.version !== 1
    || !UUID.test(value.operationId || '') || !SHA.test(value.requestSha256 || '')) throw error('INVALID_ARGUMENT');
  return value;
}
module.exports = { UUID, SHA, TEMPLATE_VERSION, OWNER_LIMIT, SENDER_LIMIT, PREPARE_MS, DISPATCH_MS,
  error, exact, hash, normalizeExternalRecipient, normalizeExternalSender, makeExternalMailPreview,
  validateExternalMailPreview, externalMailRequestSha256, prepareInput, confirmationInput };
