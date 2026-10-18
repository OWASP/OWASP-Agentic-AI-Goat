'use strict';
const crypto = require('node:crypto');
const VERSION = 1;
const ISOLATION = 'bwrap-system-config-v1';
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function normalizeRequest(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== 'operationId,path'
      || typeof value.operationId !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value.operationId)
      || typeof value.path !== 'string' || !value.path.isWellFormed() || value.path.includes('\0') || Buffer.byteLength(value.path) > 4096) throw new TypeError('Invalid System config request');
  return Object.freeze({ operationId: value.operationId, path: value.path });
}
function requestDigest(raw) { const request = normalizeRequest(raw); return hash(JSON.stringify({ version: VERSION, ...request })); }
module.exports = { VERSION, ISOLATION, hash, normalizeRequest, requestDigest };
