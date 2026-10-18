'use strict';

// Candidate namespace component, never an Express-host import fallback.
const { spawn } = require('node:child_process');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { parseOwnedListingXml } = require('./xml-parser');
const { normalizeListingRequest, listingRequestDigest } = require('../../../server/services/secureshopListingRequestContract');
const MAX = 1024 * 1024;
const fail = code => Object.assign(new Error(code), { code });
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

function runJsonWorker(bytes, mode, signal) {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--max-old-space-size=64', path.join(__dirname, 'json-worker.js'), mode], {
      stdio: ['pipe', 'pipe', 'pipe'], env: { TZ: 'UTC' }, windowsHide: true,
    });
    let failure, stdoutBytes = 0, stderrBytes = 0;
    const chunks = [];
    const stop = error => { failure ||= error; child.kill('SIGKILL'); };
    const abort = () => stop(fail('LISTING_IMPORT_ABORTED'));
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    child.on('error', error => { failure ||= error; });
    child.stdin.on('error', error => stop(error));
    child.stdout.on('data', chunk => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX * 2) stop(fail('LISTING_IMPORT_LIMIT'));
      else chunks.push(chunk);
    });
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      if (stderrBytes > 4096) stop(fail('LISTING_IMPORT_LIMIT'));
    });
    // Resolve only after close: the process and its output pipes are settled.
    child.once('close', code => {
      signal.removeEventListener('abort', abort);
      if (failure) return reject(failure);
      if (code !== 0) return reject(fail('LISTING_JSON_INVALID'));
      try {
        const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (result.version !== 1 || result.mode !== mode || result.sourceSha256 !== sha(bytes)
            || !Array.isArray(result.products)) throw fail('LISTING_IMPORT_INTEGRITY');
        resolve(result);
      } catch (error) { reject(error); }
    });
    child.stdin.end(bytes);
  });
}

async function executeOwnedListingImport({ request: raw, mode, readResource, signal, timeoutMs = 10000 } = {}) {
  const request = normalizeListingRequest(raw);
  if (request.action !== 'import' || !['vuln', 'fixed'].includes(mode) || typeof readResource !== 'function'
      || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 15000) throw fail('LISTING_IMPORT_INVALID');
  const deadline = AbortSignal.timeout(timeoutMs);
  const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
  combined.throwIfAborted();
  let remaining = MAX;
  const products = [], sources = [];
  async function read(uri) {
    combined.throwIfAborted();
    const bytes = await readResource(uri, { signal: combined, maxBytes: remaining });
    combined.throwIfAborted();
    if (!Buffer.isBuffer(bytes) || bytes.length > remaining) throw fail('LISTING_IMPORT_LIMIT');
    remaining -= bytes.length;
    return bytes;
  }
  for (const [kind, uri] of [['json', request.json_url], ['xml', request.xml_url]]) {
    if (uri === null) continue;
    const bytes = await read(uri);
    const parsed = kind === 'json' ? await runJsonWorker(bytes, mode, combined)
      : await parseOwnedListingXml(new TextDecoder('utf8', { fatal: true }).decode(bytes), {
        mode, signal: combined, resolveEntity: read,
      });
    if (products.length + parsed.products.length > 100) throw fail('LISTING_IMPORT_LIMIT');
    products.push(...parsed.products);
    sources.push({ kind, uri, byteCount: bytes.length, sourceSha256: sha(bytes),
      ...(kind === 'json' ? { prototypeEffect: parsed.prototypeEffect } : { entityReads: parsed.entityReads }) });
  }
  combined.throwIfAborted();
  return { version: 1, operationId: request.operationId, requestSha256: listingRequestDigest(request), mode, products, sources };
}
module.exports = { executeOwnedListingImport };
