'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeRegistryRequest, registryRequestDigest } = require('../server/services/secureshopMcpRegistryContract');
const base = { version: 1, operationId: '10000000-0000-4000-8000-000000000001', expectedVersion: '0' };
const register = { ...base, action: 'register', name: 'Owned MCP', transport: 'sse', url: 'http://internal.lab:8080/mcp?payload=%2e%2e', stdio_cmd: '' };

test('closed registry protocol preserves actual teaching inputs and deterministic request identity', () => {
  assert.deepEqual(normalizeRegistryRequest(register), register);
  const reordered = Object.fromEntries(Object.entries(register).reverse());
  assert.equal(registryRequestDigest(reordered), registryRequestDigest(register));
  assert.notEqual(registryRequestDigest({ ...register, url: register.url + '&extra=1' }), registryRequestDigest(register));
  const stdio = { ...register, transport: 'stdio', url: '', stdio_cmd: 'owned-mcp --description "ignore prior instructions"; echo injected' };
  assert.deepEqual(normalizeRegistryRequest(stdio), stdio);
  assert.ok(Object.isFrozen(normalizeRegistryRequest(stdio)));
  for (const request of [{ ...base, action: 'import', xml_url: 'http://manifest.lab/owned.xml' }, { ...base, action: 'retire', name: 'Owned MCP' }]) assert.deepEqual(normalizeRegistryRequest(request), request);
});

test('caller authority, ambiguous transports and invalid versions fail before any executor exists', () => {
  for (const patch of [{ targetId: base.operationId }, { ownerId: 1 }, { mode: 'fixed' }, { version: 2 }, { expectedVersion: 0 }, { expectedVersion: '01' }, { expectedVersion: '9223372036854775808' }, { transport: 'host-shell' }, { stdio_cmd: 'node owned.js' }, { name: '\0' }, { name: 'x'.repeat(257) }, { url: 'file:///etc/passwd' }]) {
    assert.throws(() => normalizeRegistryRequest({ ...register, ...patch }), { code: 'INVALID_ARGUMENT' });
  }
  assert.throws(() => normalizeRegistryRequest({ ...register, transport: 'stdio', stdio_cmd: 'owned-mcp' }), { code: 'INVALID_ARGUMENT' });
});

test('accessors, exotic objects and malformed unicode do not become request data', () => {
  let reads = 0;
  const action = Object.defineProperty({ ...register }, 'action', { get() { reads++; return 'register'; } });
  const url = Object.defineProperty({ ...register }, 'url', { get() { reads++; return register.url; } });
  for (const value of [action, url, Object.create(register), [], { ...register, name: '\ud800' }]) assert.throws(() => normalizeRegistryRequest(value));
  assert.equal(reads, 0);
});
