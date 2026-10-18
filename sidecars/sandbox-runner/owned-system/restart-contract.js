'use strict';

const { createHash } = require('node:crypto');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const sha256 = value => createHash('sha256').update(value, 'utf8').digest('hex');
const invalid = () => { throw Object.assign(new Error('Owned restart request unavailable'), { code: 'INVALID_ARGUMENT' }); };

function normalizeRestartRequest(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
    || JSON.stringify(Object.keys(raw).sort()) !== JSON.stringify(['name','operationId','version'].sort())
    || raw.version !== 1 || typeof raw.operationId !== 'string' || !UUID.test(raw.operationId)
    || typeof raw.name !== 'string' || !raw.name.isWellFormed() || raw.name.includes('\0')
    || Buffer.byteLength(raw.name, 'utf8') < 1 || Buffer.byteLength(raw.name, 'utf8') > 128) invalid();
  // Deliberately do not shell-escape `name`: interpolation is the teaching sink,
  // and the eventual executor must confine it to the owned synthetic target.
  return Object.freeze({ version: 1, operationId: raw.operationId.toLowerCase(), name: raw.name });
}

function restartRequestDigest(raw) {
  return sha256(JSON.stringify(normalizeRestartRequest(raw)));
}

module.exports = { normalizeRestartRequest, restartRequestDigest };
