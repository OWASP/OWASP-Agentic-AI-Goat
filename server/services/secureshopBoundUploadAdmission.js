'use strict';

const {
  normalizeAdmission
} = require('./secureshopBoundUploadReceipt');
function uploadAdmission(value) {
  if (!value || typeof value !== 'object') throw new TypeError('Upload admission required');
  const rawKeys = ['operationId', 'uploadRequestId', 'storageKey', 'scope', 'request'];
  const extra = ['version', 'bindingSha256', 'requestSha256', 'replayed'];
  if (Reflect.ownKeys(value).some(k => !rawKeys.includes(k) && !extra.includes(k))) throw new TypeError('Unexpected upload admission field');
  const raw = Object.fromEntries(rawKeys.map(k => [k, value[k]]));
  const normalized = normalizeAdmission(raw);
  if ('version' in value && value.version !== 1 || 'replayed' in value && typeof value.replayed !== 'boolean' || 'bindingSha256' in value && value.bindingSha256 !== normalized.bindingSha256 || 'requestSha256' in value && value.requestSha256 !== normalized.requestSha256) throw new TypeError('Upload admission digest changed');
  return normalized;
}
module.exports = {
  uploadAdmission
};
