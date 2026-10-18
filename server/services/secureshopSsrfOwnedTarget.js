'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const {policyHtml:validatePolicyHtml}=require('./secureshopPolicyFinalHtmlContract');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

function unavailable(message = 'Owned SSRF target unavailable') {
  return Object.assign(new Error(message), { code: 'BOUND_SSRF_UNAVAILABLE' });
}

async function cleanupSecureShopSsrfOwnedTarget({ root, targetId, fsImpl = fs } = {}) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || !UUID.test(targetId)) throw unavailable();
  const directory = path.join(root, targetId.toLowerCase());
  try { await fsImpl.rm(directory, { recursive:true, force:false }); }
  catch (error) { if (error?.code === 'ENOENT') return Object.freeze({ ok:true, replayed:true }); throw error; }
  try { await fsImpl.stat(directory); throw unavailable('Owned SSRF target removal incomplete'); }
  catch (error) { if (error?.code !== 'ENOENT') throw error; }
  return Object.freeze({ ok:true, replayed:false });
}

async function createSecureShopSsrfOwnedTarget({ root, targetId, fsImpl = fs,
  makeNonce = crypto.randomUUID, makeOperationId = crypto.randomUUID } = {}) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || !UUID.test(targetId)) throw unavailable();
  const canonicalTargetId = targetId.toLowerCase();
  const directory = path.join(root, canonicalTargetId);
  const publicFile = path.join(directory, 'public-policy.json');
  const privateFile = path.join(directory, 'private-policy.json');
  const publicValue = Object.freeze({ policy: 'Returns accepted within 30 days with a receipt.', classification: 'public' });
  const privateValue = Object.freeze({ recordId: `internal-policy:${canonicalTargetId}`,
    routingNote: 'Synthetic manual-review queue.', classification: 'protected-training-record' });
  let created = false;
  try { await fsImpl.mkdir(directory, { recursive: false, mode: 0o700 }); created = true; }
  catch (error) { if (error?.code !== 'EEXIST') throw error; }
  if (created) {
    try {
      // Drain both writes before removing a partially provisioned directory.
      const writes = await Promise.allSettled([
        fsImpl.writeFile(publicFile, JSON.stringify(publicValue), { flag: 'wx', mode: 0o600 }),
        fsImpl.writeFile(privateFile, JSON.stringify(privateValue), { flag: 'wx', mode: 0o600 }),
      ]);
      const failed = writes.find(result => result.status === 'rejected');
      if (failed) throw failed.reason;
    } catch (error) {
      await fsImpl.rm(directory, { recursive: true, force: true }).catch(() => {});
      throw error;
    }
  } else {
    // Recovery never repairs or overwrites an unknown directory. Only the
    // immutable, private, server-seeded fixture may get a new listener.
    const stat = await fsImpl.lstat(directory);
    const names = (await fsImpl.readdir(directory)).sort();
    if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
        || JSON.stringify(names) !== JSON.stringify(['private-policy.json', 'public-policy.json'])) throw unavailable();
    for (const [file, value] of [[publicFile, publicValue], [privateFile, privateValue]]) {
      const entry = await fsImpl.lstat(file);
      if (!entry.isFile() || entry.nlink !== 1 || (entry.mode & 0o077) !== 0
          || await fsImpl.readFile(file, 'utf8') !== JSON.stringify(value)) throw unavailable();
    }
  }

  let lifecycle = 'active', accepted = 0, cleanupPending = null, listenerClosing = null, drainResolve = null;
  const issuedByNonce = new Map(), issuedByPath = new Map(), receipts = new Map();
  const server = http.createServer(async (request, response) => {
    const entry = issuedByPath.get(request.url);
    if (lifecycle !== 'active' || request.method !== 'GET' || !entry || entry.used) {
      response.writeHead(404); response.end(); return;
    }
    entry.used = true; accepted += 1;
    try {
      const bytes = entry.resourceKind==='html-policy' ? Buffer.from(entry.policyHtml,'utf8')
        : await fsImpl.readFile(entry.resourceKind === 'public-policy' ? publicFile : privateFile);
      const base = Object.freeze({ version: 1, targetId: canonicalTargetId, nonce: entry.nonce,
        operationId: entry.operationId, requestId: entry.requestId, method: 'GET', path: entry.path, resourceKind: entry.resourceKind,
        status: 200, responseSha256: sha256(bytes) });
      receipts.set(entry.nonce, Object.freeze({ ...base,
        receiptSha256: sha256(Buffer.from(JSON.stringify(base))) }));
      response.writeHead(200, { 'content-type': entry.resourceKind==='html-policy'?'text/html; charset=utf-8':'application/json', 'cache-control': 'no-store' }); response.end(bytes);
    } catch { response.writeHead(500); response.end(); }
    finally { accepted -= 1; if (accepted === 0 && drainResolve) { drainResolve(); drainResolve = null; } }
  });
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(); });
    });
  } catch (error) {
    if (created) await fsImpl.rm(directory, { recursive: true, force: true }).catch(() => {});
    throw error;
  }
  const origin = `http://127.0.0.1:${server.address().port}`;
  async function directoryAbsent() {
    try { await fsImpl.stat(directory); return false; }
    catch (error) { if (error?.code === 'ENOENT') return true; throw error; }
  }
  async function closeListener() {
    listenerClosing ||= new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await listenerClosing;
  }
  return Object.freeze({
    targetId: canonicalTargetId,
    assertIssuedPublicRequest({ nonce, requestId, url, resourceKind } = {}) {
      const canonicalNonce = typeof nonce === 'string' ? nonce.toLowerCase() : '';
      const entry = issuedByNonce.get(canonicalNonce);
      if (lifecycle !== 'active' || !entry || entry.used || !['public-policy','html-policy'].includes(entry.resourceKind)
        || resourceKind !== entry.resourceKind || !UUID.test(requestId)
        || entry.requestId !== requestId.toLowerCase() || url !== origin + entry.path) {
        throw unavailable('Owned public SSRF destination unavailable');
      }
      return Object.freeze({ targetId: canonicalTargetId, nonce: entry.nonce,
        requestId: entry.requestId, resourceKind: entry.resourceKind, url: origin + entry.path });
    },
    issue({ requestId, resourceKind, policyHtml, operationId: requestedOperationId } = {}) {
      if (lifecycle !== 'active' || !UUID.test(requestId)
        || !['public-policy', 'private-policy','html-policy'].includes(resourceKind)) throw unavailable();
      if(resourceKind==='html-policy')validatePolicyHtml(policyHtml);else if(policyHtml!==undefined)throw unavailable();
      const nonce = makeNonce();
      if (!UUID.test(nonce) || issuedByNonce.has(nonce.toLowerCase())) throw unavailable('Owned SSRF nonce unavailable');
      const operationId = requestedOperationId || makeOperationId();
      if (!UUID.test(operationId)) throw unavailable('Owned SSRF operation unavailable');
      const canonicalNonce = nonce.toLowerCase(), requestPath = `/policy/${resourceKind}/${canonicalNonce}`;
      const entry = { nonce: canonicalNonce, operationId: operationId.toLowerCase(), requestId: requestId.toLowerCase(),
        resourceKind, ...(resourceKind==='html-policy'?{policyHtml}:{}), path: requestPath, used: false };
      issuedByNonce.set(canonicalNonce, entry); issuedByPath.set(requestPath, entry);
      return Object.freeze({ targetId: canonicalTargetId, nonce: canonicalNonce, operationId: entry.operationId, requestId: entry.requestId,
        resourceKind, url: origin + requestPath });
    },
    consume({ nonce, requestId } = {}) {
      const canonicalNonce = typeof nonce === 'string' ? nonce.toLowerCase() : '', receipt = receipts.get(canonicalNonce);
      if (!receipt || !UUID.test(requestId) || receipt.requestId !== requestId.toLowerCase()) throw unavailable();
      receipts.delete(canonicalNonce); const entry = issuedByNonce.get(canonicalNonce); issuedByNonce.delete(canonicalNonce);
      if (entry) issuedByPath.delete(entry.path); return receipt;
    },
    readReceipt({ nonce, requestId } = {}) {
      const canonicalNonce = typeof nonce === 'string' ? nonce.toLowerCase() : '', receipt = receipts.get(canonicalNonce);
      if (!receipt || !UUID.test(requestId) || receipt.requestId !== requestId.toLowerCase()) throw unavailable();
      return receipt;
    },
    pendingReceipts() { return receipts.size; },
    async disconnect() {
      if (lifecycle === 'active') lifecycle = 'disconnected';
      await closeListener();
      if (accepted > 0) await new Promise(resolve => { drainResolve = resolve; });
    },
    async cleanup() {
      if (lifecycle === 'retired') return Object.freeze({ ok: true, replayed: true });
      if (cleanupPending) return cleanupPending;
      lifecycle = 'retiring';
      cleanupPending = (async () => {
        await closeListener();
        if (accepted > 0) await new Promise(resolve => { drainResolve = resolve; });
        if (!await directoryAbsent()) await fsImpl.rm(directory, { recursive: true, force: false });
        if (!await directoryAbsent()) throw unavailable('Owned SSRF target removal incomplete');
        lifecycle = 'retired'; issuedByNonce.clear(); issuedByPath.clear(); receipts.clear();
        return Object.freeze({ ok: true, replayed: false });
      })();
      try { return await cleanupPending; }
      finally { if (lifecycle !== 'retired') cleanupPending = null; }
    },
  });
}

module.exports = { createSecureShopSsrfOwnedTarget, cleanupSecureShopSsrfOwnedTarget };
