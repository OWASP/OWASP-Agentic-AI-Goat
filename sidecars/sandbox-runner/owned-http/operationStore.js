'use strict';
// Unmounted transport prerequisite. Executor must settle only after joining its
// entire process tree, including on abort. This store never grants objective credit.
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { parseUrl } = require('./worker');
const { canonicalDigest } = require('./canonical');
const ATTESTATIONS = ['zeroCapabilities','noNewPrivileges','loopbackOnly','noDefaultRoute','unshareDenied','setnsDenied','cloneNamespaceDenied','mountDenied','onlyListenerDescriptors','udpExternalRouteDenied','ipv6ExternalRouteDenied'];
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
function fail(code) { throw Object.assign(Error(code), { code }); }
async function directory(file) {
  const stat = await fs.lstat(file);
  if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077)) fail('HTTP_JOURNAL_UNSAFE');
}
async function read(file) {
  let handle;
  try {
    handle = await fs.open(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o077) || stat.size > 131072) fail('HTTP_JOURNAL_UNSAFE');
    return JSON.parse(await handle.readFile('utf8'));
  } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  finally { await handle?.close(); }
}
async function write(file, value) {
  const temp = `${file}.${crypto.randomUUID()}.tmp`;
  const handle = await fs.open(temp, 'wx', 0o600);
  try { await handle.writeFile(JSON.stringify(value)); await handle.sync(); }
  finally { await handle.close(); }
  await fs.rename(temp, file);
  const parent = await fs.open(path.dirname(file), constants.O_RDONLY | constants.O_NOFOLLOW);
  try { await parent.sync(); } finally { await parent.close(); }
}
function createOwnedHttpOperationStore({ targetStore, executor, checkReadiness, timeoutMs = 10000 } = {}) {
  if (typeof targetStore?.withTarget !== 'function' || typeof executor !== 'function'
      || typeof checkReadiness !== 'function' || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw TypeError('Trusted HTTP transport dependencies required');
  async function execute(capability, authority, request, { signal } = {}) {
    if (!request || Object.keys(request).sort().join(',') !== 'invocationId,mcpSessionId,mode,operationId,runId,url'
        || !['runId','invocationId','operationId'].every(key => UUID.test(request[key]))
        || !/^mcp_[1-9][0-9]*$/.test(request.mcpSessionId) || !['fixed','vuln'].includes(request.mode)) fail('HTTP_REQUEST_INVALID');
    parseUrl(request.url);
    // Copy authority before any await. Callers must obtain these coordinates from
    // trusted execution context; only url is a learner-controlled tool argument.
    const supplied = Object.freeze({ ...request });
    return targetStore.withTarget(capability, authority, async ({ rootfs, binding }) => {
      if (supplied.mcpSessionId !== `mcp_${binding.ownerId}`) fail('HTTP_OWNER_MISMATCH');
      const target = path.dirname(rootfs); await directory(target);
      const journal = path.join(target, 'http-operations');
      try { await fs.mkdir(journal, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
      await directory(journal);
      const identity = { ...supplied, binding: { targetId: binding.targetId, ownerId: String(binding.ownerId), platformSessionId: String(binding.platformSessionId), generation: String(binding.generation) } };
      const requestDigest = canonicalDigest(identity);
      const file = path.join(journal, `${supplied.operationId}.json`);
      const prior = await read(file);
      if (prior) {
        if (prior.requestDigest !== requestDigest) {
          const legacyDigest = canonicalDigest({ ...supplied, binding: { ...binding } });
          if (prior.requestDigest !== legacyDigest) fail('HTTP_REPLAY_MISMATCH');
          if (prior.state === 'completed' && (prior.receipt?.requestDigest !== legacyDigest
              || prior.receiptDigest !== canonicalDigest(prior.receipt))) fail('HTTP_JOURNAL_INVALID');
          // Old numeric-binding transport receipts never met the backend's
          // string-binding and current isolation-attestation requirements.
          fail('HTTP_LEGACY_RECEIPT_RESET_REQUIRED');
        }
        if (prior.state !== 'completed') fail('HTTP_OPERATION_UNCERTAIN');
        if (prior.receipt?.requestDigest !== requestDigest || prior.receiptDigest !== canonicalDigest(prior.receipt)) fail('HTTP_JOURNAL_INVALID');
        return prior.receipt;
      }
      if (signal?.aborted) fail('HTTP_OPERATION_ABORTED');
      const readiness = await checkReadiness();
      if (readiness?.ready !== true || !/^[a-f0-9]{64}$/.test(readiness.manifestSha256 || '')) fail('HTTP_TRANSPORT_UNAVAILABLE');
      const canary = crypto.randomBytes(32).toString('hex');
      await write(file, { state: 'pending', requestDigest });
      const controller = new AbortController();
      const abort = () => controller.abort();
      signal?.addEventListener('abort', abort, { once: true });
      if (signal?.aborted) abort();
      const timer = setTimeout(abort, timeoutMs);
      try {
        // Never Promise.race: keep the target lock until executor has drained.
        const execution = await executor({ rootfs, binding: Object.freeze({ ...binding }),
          input: Object.freeze({ url: supplied.url, mode: supplied.mode, canary }), signal: controller.signal });
        if (controller.signal.aborted || execution?.drained !== true) fail('HTTP_OPERATION_UNCERTAIN');
        const result = execution.result;
        if (!result || !ATTESTATIONS.every(key => result.isolationAttestation?.[key] === true)
            || !Array.isArray(result.hops) || result.hops.length > 4 || !Array.isArray(result.hits) || result.hits.length > 16
            || Buffer.byteLength(JSON.stringify(result)) > 65536
            || result.originalUrlSha256 !== crypto.createHash('sha256').update(supplied.url).digest('hex')
            || result.mode !== supplied.mode || !['completed','failed'].includes(result.status)) fail('HTTP_OPERATION_UNCERTAIN');
        const receipt = { version: 'mcp-owned-http-operation.v1', requestDigest, identity,
          manifestSha256: readiness.manifestSha256, canarySha256: crypto.createHash('sha256').update(canary).digest('hex'), result };
        await write(file, { state: 'completed', requestDigest, receipt, receiptDigest: canonicalDigest(receipt) });
        return receipt;
      } catch (error) {
        // A durable pending record is deliberately retained: transport failure
        // cannot establish whether a request took effect. Never repeat it.
        throw Object.assign(Error('HTTP_OPERATION_UNCERTAIN'), { code: 'HTTP_OPERATION_UNCERTAIN', cause: error });
      } finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
    });
  }
  async function readReceipt(capability,authority,{operationId,requestDigest}={}) {
    if(!UUID.test(operationId||'')||!/^[a-f0-9]{64}$/.test(requestDigest||''))fail('HTTP_REQUEST_INVALID');
    return targetStore.withTarget(capability,authority,async({rootfs})=>{
      const target=path.dirname(rootfs);await directory(target);const journal=path.join(target,'http-operations');
      try{await directory(journal);}catch(error){if(error.code==='ENOENT')return {state:'absent'};throw error;}
      const row=await read(path.join(journal,`${operationId}.json`));if(!row)return {state:'absent'};
      if(row.requestDigest!==requestDigest)fail('HTTP_REPLAY_MISMATCH');
      if(row.state!=='completed')return {state:'uncertain'};
      if(row.receipt?.requestDigest!==requestDigest||row.receiptDigest!==canonicalDigest(row.receipt))fail('HTTP_JOURNAL_INVALID');
      return {state:'completed',receipt:row.receipt};
    });
  }
  return Object.freeze({ execute, readReceipt });
}
module.exports = { createOwnedHttpOperationStore };
