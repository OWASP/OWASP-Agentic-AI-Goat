'use strict';

// Candidate owned-registry protocol. This module does not dispatch commands,
// fetch URLs, enable a route, or grant objective credit.
const { createHash } = require('node:crypto');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const fail = () => { throw Object.assign(new Error('Invalid owned MCP registry request'), { code: 'INVALID_ARGUMENT' }); };
function exact(value, keys) {
  if (!value || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== keys.length
      || keys.some(key => !Object.hasOwn(value, key))) fail();
  // Requests crossing the HTTP boundary are data, never accessor callbacks.
  if (Object.values(Object.getOwnPropertyDescriptors(value)).some(descriptor => !Object.hasOwn(descriptor, 'value'))) fail();
}
function text(value, max) {
  if (typeof value !== 'string' || !value.isWellFormed() || !value.trim()
      || value.includes('\0') || Buffer.byteLength(value, 'utf8') > max) fail();
  return value;
}
function url(value) {
  text(value, 4096);
  let parsed;
  try { parsed = new URL(value); } catch { fail(); }
  if (!['http:', 'https:'].includes(parsed.protocol)) fail();
  // Preserve submitted bytes for provenance and intentional URL-based lessons.
  // Only the separately isolated executor may resolve or fetch this address.
  return value;
}
function base(value, action) {
  if (value.version !== 1 || value.action !== action || typeof value.operationId !== 'string' || !UUID.test(value.operationId)
      || typeof value.expectedVersion !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(value.expectedVersion)
      || BigInt(value.expectedVersion) > 9223372036854775807n) fail();
  return { version: 1, action, operationId: value.operationId, expectedVersion: value.expectedVersion };
}
function normalizeRegistryRequest(raw) {
  // Inspect descriptors before reading action so even in-process callers cannot
  // sneak executable accessors through the closed contract.
  if (!raw || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))) fail();
  const descriptor = Object.getOwnPropertyDescriptor(raw, 'action');
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) fail();
  const action = descriptor.value;
  if (action === 'register') {
    exact(raw, ['version', 'action', 'operationId', 'expectedVersion', 'name', 'transport', 'url', 'stdio_cmd']);
    const common = base(raw, action), name = text(raw.name, 256);
    if (!['sse', 'streamable-http', 'stdio'].includes(raw.transport)) fail();
    if (raw.transport === 'stdio') {
      if (raw.url !== '') fail();
      return Object.freeze({ ...common, name, transport: raw.transport, url: '', stdio_cmd: text(raw.stdio_cmd, 4096) });
    }
    if (raw.stdio_cmd !== '') fail();
    return Object.freeze({ ...common, name, transport: raw.transport, url: url(raw.url), stdio_cmd: '' });
  }
  if (action === 'import') {
    exact(raw, ['version', 'action', 'operationId', 'expectedVersion', 'xml_url']);
    return Object.freeze({ ...base(raw, action), xml_url: url(raw.xml_url) });
  }
  if (action === 'retire') {
    exact(raw, ['version', 'action', 'operationId', 'expectedVersion', 'name']);
    return Object.freeze({ ...base(raw, action), name: text(raw.name, 256) });
  }
  fail();
}
function registryRequestDigest(raw) {
  return createHash('sha256').update(JSON.stringify(normalizeRegistryRequest(raw)), 'utf8').digest('hex');
}

module.exports = { normalizeRegistryRequest, registryRequestDigest };
