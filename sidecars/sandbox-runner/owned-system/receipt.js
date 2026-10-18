'use strict';
// Pure fixed-executor receipt validation; no server, transport or filesystem IO.
const path = require('node:path');
const { VERSION, ISOLATION, hash, requestDigest } = require('./contract');
const MAX_FILE_BYTES = 512 * 1024;
function unavailable() { return Object.assign(new Error('Invalid System config receipt'), { code: 'SYSTEM_CONFIG_RECEIPT_INVALID' }); }
function exact(value, keys) { return value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).sort().join(',') === [...keys].sort().join(','); }
function validReceipt(request, value) {
  const common = ['version','isolation','operationId','requestSha256','status','exitCode','timedOut','truncated','drained'];
  if (!exact(value, value?.status === 'completed' ? [...common,'readResult'] : common)
      || value.version !== VERSION || value.isolation !== ISOLATION || value.operationId !== request.operationId
      || value.requestSha256 !== requestDigest(request) || !['completed','unavailable'].includes(value.status)
      || !['timedOut','truncated','drained'].every(key => typeof value[key] === 'boolean')
      || !(value.exitCode === null || (Number.isInteger(value.exitCode) && value.exitCode >= 0 && value.exitCode <= 255))) throw unavailable();
  if (value.status === 'unavailable') {
    if (value.exitCode === 0 && !value.timedOut && !value.truncated && value.drained) throw unavailable();
    return Object.freeze({ ...value });
  }
  if (value.exitCode !== 0 || value.timedOut || value.truncated || !value.drained) throw unavailable();
  const read = value.readResult;
  const sanitized = request.path.replace(/\.\.\//g, '').replace(/\.\.\\/g, '');
  const targetPath = path.posix.resolve('/app/config', sanitized);
  const absolute = request.path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(request.path) || request.path.startsWith('\\\\');
  const contained = targetPath === '/app' || targetPath.startsWith('/app/');
  if (read?.ok === true) {
    if (!exact(read, ['ok','input','sanitized','targetPath','size','content','contentSha256']) || absolute || !contained
        || read.input !== request.path || read.sanitized !== sanitized || read.targetPath !== targetPath
        || typeof read.content !== 'string' || !read.content.isWellFormed() || Buffer.byteLength(read.content) > MAX_FILE_BYTES
        || read.size !== Buffer.byteLength(read.content) || read.contentSha256 !== hash(Buffer.from(read.content))) throw unavailable();
  } else {
    // Match the qualified executor's fixed-tree negatives. Link/UTF-8/change
    // errors are impossible for its immutable checked fixtures and fail closed.
    const negativeCodes = ['absolute paths not allowed','path outside synthetic target','config not found','regular fixture file required','config read unavailable'];
    if (!exact(read, ['ok','error']) || read.ok !== false || !negativeCodes.includes(read.error)
        || (absolute !== (read.error === 'absolute paths not allowed'))
        || ((!absolute && !contained) !== (read.error === 'path outside synthetic target'))) throw unavailable();
  }
  return Object.freeze({ ...value, readResult: Object.freeze({ ...read }) });
}
module.exports = { validateSystemConfigReceipt: validReceipt };
