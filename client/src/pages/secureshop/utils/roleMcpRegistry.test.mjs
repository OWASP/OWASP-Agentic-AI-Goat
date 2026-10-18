import { decodeRoleMcpRegistryProposal, decodeMcpServerHeader,
  decodeRoleMcpDetail, decodeRegisteredMcpSetup } from './roleMcpRegistry.mjs';

const { webcrypto } = require('node:crypto');
const { createRoleMcpRegistryProposal, projectRoleMcpRegistryProposal,
  registryServerSnapshotDigest } = require('../../../../../server/services/secureshopRoleMcpRegistryProposal.js');
const source = { sessionId: '11111111-1111-4111-8111-111111111111',
  requestId: '22222222-2222-4222-8222-222222222222' };
const origin = { step: 1, callId: 'mcp-prepare-1' };
const scopeKey = 'a'.repeat(64);
const modeCapability = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'fixed',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const context = { source, origin, expectedVersion: '4', scopeKey,
  modeCapability, registryMode: 'vuln' };
const header = { provenance: 'owned_registry', id: '33333333-3333-4333-8333-333333333333',
  name: 'owned-server', transport: 'sse', url: 'http://owned.invalid/mcp',
  stdio_cmd: null, schemaSha256: 'b'.repeat(64), scenario: null };

beforeEach(() => { Object.defineProperty(globalThis.crypto, 'subtle', {
  configurable: true, value: webcrypto.subtle }); });

test('register replacement keeps full current server header and exact existing request digest', async () => {
  const before = { ...header, snapshotSha256: registryServerSnapshotDigest({ scopeKey,
    registryVersion: '4', server: header }) };
  const value = createRoleMcpRegistryProposal({ ...context, action: 'register', selected: null,
    before, candidate: { name: header.name, transport: 'sse', url: 'http://new.invalid/mcp',
      stdio_cmd: '' } });
  const publicValue = projectRoleMcpRegistryProposal(value, source);
  const decoded = await decodeRoleMcpRegistryProposal(publicValue);
  expect(decoded.before).toEqual(before);
  expect(decoded.request).toMatchObject({ action: 'register', name: header.name,
    url: 'http://new.invalid/mcp', operationId: decoded.proposalId });
  await expect(decodeRoleMcpRegistryProposal({ ...publicValue,
    before: { ...publicValue.before, url: 'http://swapped.invalid/mcp' } }))
    .rejects.toThrow('Saved MCP registry review invalid');
});

test('import and selected owned retirement match server public proposal and deny scenario retirement', async () => {
  const importValue = createRoleMcpRegistryProposal({ ...context, action: 'import', selected: null,
    before: null, candidate: { xml_url: 'http://owned.invalid/manifest.xml' } });
  expect((await decodeRoleMcpRegistryProposal(projectRoleMcpRegistryProposal(importValue, source)))
    .request.xml_url).toBe('http://owned.invalid/manifest.xml');
  const before = { ...header, snapshotSha256: registryServerSnapshotDigest({ scopeKey,
    registryVersion: '4', server: header }) };
  const retireValue = createRoleMcpRegistryProposal({ ...context, action: 'retire',
    selected: { choiceId: '44444444-4444-4444-8444-444444444444',
      snapshotSha256: before.snapshotSha256 }, before, candidate: null });
  const publicValue = projectRoleMcpRegistryProposal(retireValue, source);
  expect((await decodeRoleMcpRegistryProposal(publicValue)).before.name).toBe(header.name);
  await expect(decodeRoleMcpRegistryProposal({ ...publicValue,
    before: { ...before, provenance: 'scenario' } }))
    .rejects.toThrow('Saved MCP registry review invalid');
});

test('server headers are closed and remain plain untrusted text', () => {
  const before = { ...header, snapshotSha256: 'c'.repeat(64) };
  expect(decodeMcpServerHeader(before).name).toBe('owned-server');
  expect(() => decodeMcpServerHeader({ ...before, html: '<script>' }))
    .toThrow('Saved MCP registry review invalid');
});

test('protected detail preserves full schema, history, and malicious description as text data', async () => {
  const server = { ...header, snapshotSha256: registryServerSnapshotDigest({ scopeKey,
    registryVersion: '4', server: header }) };
  const detail = { version: 1, scopeKey, registryVersion: '4', server,
    schemaVersion: '1', choiceId: '44444444-4444-4444-8444-444444444444', oversized: false,
    tools: [{ name: 'lookup', description: '<img src=x onerror=alert(1)>',
      inputSchema: { type: 'object', properties: { query: { type: 'string' } } } }],
    history: [{ version: '1', schemaSha256: header.schemaSha256,
      observedAt: '2026-10-11T13:00:00.000Z' }] };
  expect((await decodeRoleMcpDetail(detail)).tools[0].description)
    .toBe('<img src=x onerror=alert(1)>');
  await expect(decodeRoleMcpDetail({ ...detail, server: { ...server, name: 'swapped' } }))
    .rejects.toThrow('Saved MCP registry review invalid');
});

test('registered-tools setup binds exact source request and separate feature mode', () => {
  const setup = { version: 1, kind: 'registered_mcp_setup', ...source, scopeKey,
    message: 'Ask all my registered tools for status', registeredModeCapability: {
      scope: { id: 'registered_mcp', kind: 'launch_feature' }, effectiveMode: 'fixed',
      policyVersion: 'registered-schema-approval-v1', featureId: 'registered_mcp', version: 1 } };
  expect(decodeRegisteredMcpSetup(setup, source.sessionId, source.requestId).message)
    .toBe(setup.message);
  expect(() => decodeRegisteredMcpSetup({ ...setup,
    registeredModeCapability: { ...setup.registeredModeCapability, featureId: 'admin_assistant' } },
  source.sessionId, source.requestId)).toThrow('Saved MCP registry review invalid');
  expect(() => decodeRegisteredMcpSetup(setup, source.sessionId,
    '55555555-5555-4555-8555-555555555555')).toThrow('Saved MCP registry review invalid');
});
