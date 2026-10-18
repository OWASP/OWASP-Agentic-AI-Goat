import { createHash, webcrypto } from 'node:crypto';
import { decodeUserLookup, decodeAuditSearchDescriptor, decodeAuditSearchOperation, decodeSystemHealth,
  decodeSystemConfigDescriptor, decodeSystemConfigOperation } from './adminSavedOperationReads.mjs';

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const adminMode = { version: 1, featureId: 'admin_assistant',
  policyVersion: 'owned-admin-read-and-confirmation-v1', effectiveMode: 'vuln',
  scope: { kind: 'launch_feature', id: 'admin_assistant' } };
const auditMode = { version: 1, featureId: 'audit', policyVersion: 'raw-audit-query-disabled-v1',
  effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'audit' } };
const hash = value => createHash('sha256').update(value).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort()
    .map(key => [key, canonical(value[key])])) : value;
const source = { sourceSha256: 'a'.repeat(64), payloadSha256: 'b'.repeat(64) };
const result = { ok: true, username: 'admin', sql: 'SELECT * FROM audit', count: 1,
  events: [{ params_json: '<img src=x onerror=alert(1)>', action: 'read', id: 4 }],
  error: null, durationMs: 4 };
const descriptor = { version: 1, kind: 'audit.sql_search', operationId: id,
  status: 'completed', resultSha256: hash(JSON.stringify(canonical(result))),
  resultBytes: Buffer.byteLength(JSON.stringify(result)), count: 1, ok: true,
  source, modeCapability: auditMode, oversized: true, result: null };

beforeAll(() => Object.defineProperty(globalThis, 'crypto', { configurable: true, value: webcrypto }));

test('audit SQL full GET matches digest, raw bytes, source and reordered mode before projecting rows', async () => {
  const saved = decodeAuditSearchDescriptor(descriptor, adminMode, 'end_turn');
  const full = { version: 1, operationId: id, status: 'completed', result,
    source: { payloadSha256: source.payloadSha256, sourceSha256: source.sourceSha256 },
    modeCapability: { scope: { id: 'audit', kind: 'launch_feature' }, effectiveMode: 'vuln',
      policyVersion: auditMode.policyVersion, featureId: 'audit', version: 1 } };
  expect((await decodeAuditSearchOperation(saved, full)).events[0].params_json).toContain('<img');
  await expect(decodeAuditSearchOperation(saved, { ...full, result: { ...result,
    events: [{ ...result.events[0], action: 'changed' }] } })).rejects.toThrow('invalid');
  await expect(decodeAuditSearchOperation(saved, { ...full, source: { ...source,
    payloadSha256: 'c'.repeat(64) } })).rejects.toThrow('invalid');
  await expect(decodeAuditSearchOperation(saved, { ...full, modeCapability: { ...auditMode,
    policyVersion: 'wrong' } })).rejects.toThrow('invalid');
});

test('audit SQL descriptor refuses nonterminal rows and malformed mode', () => {
  expect(() => decodeAuditSearchDescriptor({ ...descriptor, status: 'unconfirmed' },
    adminMode, 'end_turn')).toThrow('invalid');
  expect(() => decodeAuditSearchDescriptor(descriptor, { ...adminMode,
    unexpected: true }, 'end_turn')).toThrow('invalid');
  expect(() => decodeAuditSearchDescriptor(descriptor, adminMode, 'error')).toThrow('invalid');
});

test('System health accepts unavailable memory but rejects changed provenance', () => {
  const metrics = { version: 'secureshop-owned-system-metrics.v1', ok: true,
    hostname: 'owned', platform: 'linux', node: 'v22', uptime_s: 2, loadavg: null,
    freemem_mb: null, totalmem_mb: null, ts: '2026-10-11T00:00:00.000Z',
    metricsSource: 'owned-system-listener', memorySource: 'unavailable',
    uptimeSource: 'listener-process', loadSource: 'unavailable' };
  const value = { version: 1, kind: 'system.health', scopeKey: 'a'.repeat(64), metrics };
  expect(decodeSystemHealth(value, adminMode, 'end_turn')).toEqual(metrics);
  expect(() => decodeSystemHealth({ ...value, metrics: { ...metrics,
    memorySource: 'host' } }, adminMode, 'end_turn')).toThrow('invalid');
});

test('System config saved descriptor binds exact full journal result and content hash', async () => {
  const content = '<script>teaching text</script>';
  const read = { status: 'completed', ok: true, input: 'practice.txt',
    sanitized: 'practice.txt', targetPath: '/app/config/practice.txt',
    size: Buffer.byteLength(content), contentSha256: hash(content), content, oversized: false };
  const saved = decodeSystemConfigDescriptor({ version: 1, kind: 'system.config_read',
    scopeKey: 'a'.repeat(64), operationId: id, requestSha256: 'b'.repeat(64),
    state: 'completed', result: read }, adminMode, 'end_turn');
  const journal = { operationId: id, requestSha256: saved.requestSha256,
    state: 'completed', privateMetadata: 'ignored', receipt: { operationId: id,
      requestSha256: saved.requestSha256, status: 'completed',
      readResult: { ok: true, input: read.input, sanitized: read.sanitized,
        targetPath: read.targetPath, size: read.size, contentSha256: read.contentSha256,
        content } } };
  expect((await decodeSystemConfigOperation(saved, journal)).content).toBe(content);
  await expect(decodeSystemConfigOperation(saved, { ...journal, receipt: { ...journal.receipt,
    readResult: { ...journal.receipt.readResult, content: 'changed' } } })).rejects.toThrow('invalid');
  expect((await decodeSystemConfigOperation(saved, { operationId: id,
    requestSha256: saved.requestSha256, state: 'pending' })).state).toBe('pending');
});


test('synthetic user lookup exposes only a closed server-derived saved descriptor', () => {
  for (const status of ['complete', 'redacted', 'not_found']) {
    const value = { version: 1, username: 'student_customer', status, assessmentReady: true };
    expect(decodeUserLookup(value, adminMode, 'end_turn')).toEqual(value);
    for (const changed of [{ ...value, api_key: 'TRAINING' }, { ...value, assessmentReady: 1 },
      { ...value, username: 'bad\0name' }, { ...value, status: 'pending' }])
      expect(() => decodeUserLookup(changed, adminMode, 'end_turn')).toThrow('invalid');
    expect(() => decodeUserLookup(value, adminMode, 'error')).toThrow('invalid');
  }
  expect(decodeUserLookup(null, adminMode, 'end_turn')).toBeNull();
});
