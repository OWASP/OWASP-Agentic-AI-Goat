'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { resourceDenial } = require('../sidecars/sandbox-runner/owned-listings/namespace-worker');
const { decodeNamespaceResult } = require('../sidecars/sandbox-runner/owned-listings/namespace-executor');
const { createListingOperationExecutor } = require('../sidecars/sandbox-runner/owned-listings/operation-executor');
const { listingRequestDigest } = require('../server/services/secureshopListingRequestContract');
const request = { version: 1, action: 'import', operationId: '10000000-0000-4000-8000-000000000001',
  json_url: 'http://169.254.169.254/catalog.json', xml_url: null };
const input = { mode: 'fixed', request };
const expected = { version: 1, operationId: request.operationId,
  requestSha256: listingRequestDigest(request), mode: 'fixed',
  namespaceAttested: true, error: 'LISTING_RESOURCE_DENIED' };

test('only an own resource policy denial emits a closed attested request-bound envelope', () => {
  assert.deepEqual(resourceDenial(input, Object.assign(Error('private'),
    { code: 'LISTING_RESOURCE_DENIED' })), expected);
  assert.equal(resourceDenial(input, Object.assign(Error('other'),
    { code: 'LISTING_RESOURCE_LIMIT' })), null);
  const inherited = Object.create({ code: 'LISTING_RESOURCE_DENIED' });
  assert.equal(resourceDenial(input, inherited), null);
  let accessed = false;
  const accessor = Object.defineProperty({}, 'code', { get() {
    accessed = true; return 'LISTING_RESOURCE_DENIED';
  } });
  assert.equal(resourceDenial(input, accessor), null);
  assert.equal(accessed, false);
  assert.equal(resourceDenial({ ...input, mode: 'unknown' },
    { code: 'LISTING_RESOURCE_DENIED' }), null);
  assert.throws(() => resourceDenial({ mode: 'fixed', request: { ...request,
    operationId: 'invalid' } }, { code: 'LISTING_RESOURCE_DENIED' }), { code: 'INVALID_ARGUMENT' });
});

test('parent accepts only the exact attested denial for its original request', () => {
  assert.throws(() => decodeNamespaceResult(Buffer.from(JSON.stringify(expected)), input),
    { code: 'LISTING_RESOURCE_DENIED' });
  for (const mutated of [
    { ...expected, operationId: '20000000-0000-4000-8000-000000000001' },
    { ...expected, requestSha256: '0'.repeat(64) },
    { ...expected, mode: 'vuln' },
    { ...expected, namespaceAttested: false },
    { ...expected, error: 'LISTING_EXECUTION_FAILED' },
    { ...expected, extra: 'unexpected' },
    { ...expected, version: 2 },
  ]) assert.throws(() => decodeNamespaceResult(Buffer.from(JSON.stringify(mutated)), input),
    { code: 'LISTINGS_RESULT_INTEGRITY' });
  const success = { version: 1, operationId: request.operationId,
    requestSha256: listingRequestDigest(request), mode: 'fixed',
    namespaceAttested: true, products: [], sources: [] };
  const { namespaceAttested: _attestation, ...effect } = success;
  assert.deepEqual(decodeNamespaceResult(Buffer.from(JSON.stringify(success)), input),
    effect);
});

test('durable executor stores only the allowlisted safe denial code', async () => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-listing-denial-'));
  try {
    await fs.chmod(directory, 0o700);
    const executor = await createListingOperationExecutor({ directory, identity: 'a'.repeat(64),
      mode: 'fixed', executeImport: async () => { throw Object.assign(Error('hidden'),
        { code: 'LISTING_RESOURCE_DENIED' }); } });
    const saved = await executor.execute(request);
    assert.equal(saved.status, 'failed');
    assert.equal(saved.error, 'LISTING_RESOURCE_DENIED');
    assert.equal(saved.requestSha256, listingRequestDigest(request));
    assert.deepEqual(await executor.get(request.operationId), saved);
    assert.doesNotMatch(JSON.stringify(saved), /hidden/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('fixed XML parser denial survives worker, parent and durable receipt without entity reads or secret text', async () => {
  const { parseOwnedListingXml } = require('../sidecars/sandbox-runner/owned-listings/xml-parser');
  const xmlInput = { mode: 'fixed', request: { ...request, json_url: null, xml_url: 'http://192.0.2.10/file.xml' } };
  let reads = 0, error;
  try { await parseOwnedListingXml('<!DOCTYPE products [<!ENTITY owned SYSTEM "file:///owned-listing-files/secret.txt">]><products><product><name>&owned;</name></product></products>',
    { mode: 'fixed', resolveEntity: async () => { reads++; throw Error('must not read'); } }); }
  catch (caught) { error = caught; }
  assert.equal(error?.code, 'LISTING_XML_ENTITIES_DISABLED'); assert.equal(reads, 0);
  error.message = 'private diagnostic /host/secret';
  const envelope = resourceDenial(xmlInput, error);
  assert.deepEqual(envelope, { ...expected, requestSha256: listingRequestDigest(xmlInput.request), error: error.code });
  assert.doesNotMatch(JSON.stringify(envelope), /private|host|secret/);
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-listing-xml-denial-'));
  try {
    await fs.chmod(directory, 0o700); let calls = 0;
    const executor = await createListingOperationExecutor({ directory, identity: 'a'.repeat(64), mode: 'fixed',
      executeImport: async received => { calls++; assert.deepEqual(received.request, xmlInput.request);
        return decodeNamespaceResult(Buffer.from(JSON.stringify(envelope)), xmlInput); } });
    const saved = await executor.execute(xmlInput.request);
    assert.equal(saved.status, 'failed'); assert.equal(saved.error, 'LISTING_XML_ENTITIES_DISABLED');
    assert.equal(saved.mode, 'fixed'); assert.equal(saved.requestSha256, listingRequestDigest(xmlInput.request));
    assert.deepEqual(await executor.get(request.operationId), saved);
    assert.deepEqual(await executor.execute(xmlInput.request), saved); assert.equal(calls, 1);
    assert.doesNotMatch(JSON.stringify(saved), /private|host|secret/);
  } finally { await fs.rm(directory, { recursive: true, force: true }); }
});

test('XML denial cannot be emitted or accepted for vulnerable or non-XML requests', () => {
  const code = { code: 'LISTING_XML_ENTITIES_DISABLED' };
  const xml = { ...request, json_url: null, xml_url: 'http://192.0.2.10/file.xml' };
  for (const denied of [{ mode: 'vuln', request: xml }, input]) {
    assert.equal(resourceDenial(denied, code), null);
    const forged = { ...expected, mode: denied.mode, requestSha256: listingRequestDigest(denied.request), error: code.code };
    assert.throws(() => decodeNamespaceResult(Buffer.from(JSON.stringify(forged)), denied), { code: 'LISTINGS_RESULT_INTEGRITY' });
  }
  const fixed = { mode: 'fixed', request: xml }, envelope = resourceDenial(fixed, code);
  for (const change of [{ error: 'LISTING_XML_PARSE_FAILED' }, { extra: 'private' }, { mode: 'vuln' },
    { requestSha256: '0'.repeat(64) }, { operationId: '20000000-0000-4000-8000-000000000002' }]) {
    assert.throws(() => decodeNamespaceResult(Buffer.from(JSON.stringify({ ...envelope, ...change })), fixed), { code: 'LISTINGS_RESULT_INTEGRITY' });
  }
  assert.equal(resourceDenial(fixed, Object.create(code)), null);
  let accessed = false;
  assert.equal(resourceDenial(fixed, Object.defineProperty({}, 'code', { get() { accessed = true; return code.code; } })), null);
  assert.equal(accessed, false);
});
