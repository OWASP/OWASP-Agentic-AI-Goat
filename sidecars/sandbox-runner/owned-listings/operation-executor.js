'use strict';
// Candidate durable execution journal. The trusted namespace launcher supplies
// identity and reader; this module does not establish OS/network isolation.
const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { normalizeListingRequest, listingRequestDigest } = require('../../../server/services/secureshopListingRequestContract');
const executeOwnedListingImport = args => require('./import-executor').executeOwnedListingImport(args);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const fail = code => Object.assign(new Error(code), { code });
const digest = value => crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
async function createListingOperationExecutor({ directory, identity, readResource, mode, executeImport = executeOwnedListingImport } = {}) {
  if (!path.isAbsolute(directory || '') || !/^[a-f0-9]{64}$/.test(identity || '')
      || typeof executeImport !== 'function' || (executeImport === executeOwnedListingImport && typeof readResource !== 'function') || !['fixed', 'vuln'].includes(mode)) throw TypeError('Trusted Listings bootstrap required');
  const stat = await fs.lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077)) throw fail('LISTING_JOURNAL_DIRECTORY');
  let active = false;
  const retiring = new Set(), inFlight = new Map();
  const filename = (id, suffix) => { if (!UUID.test(id || '')) throw fail('LISTING_OPERATION_ID'); return path.join(directory, `${id}.${suffix}.json`); };
  async function read(file) {
    let handle;
    try {
      handle = await fs.open(file, require('node:fs').constants.O_RDONLY | require('node:fs').constants.O_NOFOLLOW);
      const stat = await handle.stat();
      if (!stat.isFile() || stat.nlink !== 1 || stat.size > 8388608 || (stat.mode & 0o077)) throw fail('LISTING_JOURNAL_INTEGRITY');
      return JSON.parse(await handle.readFile('utf8'));
    } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    finally { await handle?.close(); }
  }
  async function immutable(file, value) {
    const temp = `${file}.${crypto.randomUUID()}.tmp`;
    let handle;
    try {
      handle = await fs.open(temp, 'wx', 0o600);
      await handle.writeFile(JSON.stringify(value)); await handle.sync();
      await handle.close(); handle = null;
      await fs.link(temp, file);
      const dir = await fs.open(directory, 'r');
      try { await dir.sync(); } finally { await dir.close(); }
    } finally {
      await handle?.close();
      await fs.unlink(temp).catch(error => { if (error.code !== 'ENOENT') throw error; });
    }
  }
  async function get(operationId) {
    const tombstone = await read(filename(operationId, 'retired'));
    if (tombstone) {
      const { tombstoneSha256, ...body } = tombstone;
      if (body.status !== 'retired' || body.version !== 1 || body.identity !== identity || body.operationId !== operationId || digest(body) !== tombstoneSha256) throw fail('LISTING_JOURNAL_INTEGRITY');
      return tombstone;
    }
    const admission = await read(filename(operationId, 'admission'));
    if (!admission) return null;
    const { admissionSha256, ...admitted } = admission;
    if (Object.keys(admitted).sort().join(',') !== 'identity,mode,operationId,requestSha256,version' || admitted.version !== 1 || digest(admitted) !== admissionSha256) throw fail('LISTING_JOURNAL_INTEGRITY');
    if (admission.identity !== identity || admission.mode !== mode || admission.operationId !== operationId) throw fail('LISTING_JOURNAL_IDENTITY');
    const receipt = await read(filename(operationId, 'receipt'));
    if (!receipt) return { version: 1, operationId, status: 'unknown', requestSha256: admission.requestSha256, identity };
    const { receiptSha256, ...body } = receipt;
    if (digest(body) !== receiptSha256 || body.identity !== identity || body.operationId !== operationId
        || body.requestSha256 !== admission.requestSha256 || body.mode !== mode) throw fail('LISTING_RECEIPT_INTEGRITY');
    // Retirement may have published while the receipt was being read.
    if (await read(filename(operationId, 'retired'))) return get(operationId);
    return receipt;
  }
  async function executeBody(raw, { signal } = {}) {
    const request = normalizeListingRequest(raw);
    if (request.action !== 'import') throw fail('LISTING_IMPORT_INVALID');
    const requestSha256 = listingRequestDigest(request);
    const existing = await get(request.operationId);
    if (existing) {
      if (existing.requestSha256 !== requestSha256) throw fail('LISTING_OPERATION_CONFLICT');
      return existing;
    }
    if (retiring.has(request.operationId)) throw fail('LISTING_OPERATION_RETIRING');
    if (active) throw fail('LISTING_EXECUTOR_BUSY');
    active = true;
    try {
      signal?.throwIfAborted();
      try {
        const admitted = { version: 1, identity, mode, operationId: request.operationId, requestSha256 };
        await immutable(filename(request.operationId, 'admission'), { ...admitted, admissionSha256: digest(admitted) });
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const found = await get(request.operationId);
        if (!found || found.requestSha256 !== requestSha256) throw fail('LISTING_OPERATION_CONFLICT');
        return found;
      }
      let outcome;
      try {
        const result = await executeImport({ request, mode, readResource, signal });
        outcome = { status: 'completed', result };
      } catch (error) {
        // Do not persist arbitrary exception text (it can contain private paths).
        outcome = { status: 'failed', error: /^LISTING_[A-Z_]+$/.test(error.code || '') ? error.code : 'LISTING_EXECUTION_FAILED' };
      }
      const body = { version: 1, identity, mode, operationId: request.operationId, requestSha256, ...outcome };
      await immutable(filename(request.operationId, 'receipt'), { ...body, receiptSha256: digest(body) });
      return get(request.operationId);
    } finally { active = false; }
  }
  function execute(raw, options) {
    const request = normalizeListingRequest(raw);
    if (inFlight.has(request.operationId)) return Promise.reject(fail('LISTING_EXECUTOR_BUSY'));
    const promise = executeBody(request, options);
    inFlight.set(request.operationId, promise);
    promise.then(() => inFlight.delete(request.operationId), () => inFlight.delete(request.operationId));
    return promise;
  }
  async function retire(operationId) {
    filename(operationId, 'retired');
    retiring.add(operationId);
    await inFlight.get(operationId)?.catch(() => {});
    const receipt = await get(operationId);
    if (!receipt) return null;
    if (receipt.status !== 'retired') {
      const body = { version: 1, status: 'retired', operationId, identity,
        requestSha256: receipt.requestSha256, receiptSha256: receipt.receiptSha256 || null };
      try { await immutable(filename(operationId, 'retired'), { ...body, tombstoneSha256: digest(body) }); }
      catch (error) { if (error.code !== 'EEXIST') throw error; }
    }
    // Tombstone is durable before any raw deletion. GET never exposes raw data
    // after this point even if the process crashes during deletion.
    for (const suffix of ['admission', 'receipt']) await fs.unlink(filename(operationId, suffix)).catch(error => { if (error.code !== 'ENOENT') throw error; });
    const dir = await fs.open(directory, 'r');
    try { await dir.sync(); } finally { await dir.close(); }
    return get(operationId);
  }
  return Object.freeze({ execute, get, retire });
}
module.exports = { createListingOperationExecutor };
