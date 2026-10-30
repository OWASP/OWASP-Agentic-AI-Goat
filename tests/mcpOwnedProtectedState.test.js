'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createMcpProtectedState, RECEIPT_VERSION } = require('../sidecars/sandbox-runner/mcpProtectedState');

const canonical = value => JSON.stringify(Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]])));
async function targetFixture(t, { owner = 7, session = 11, generation = 0 } = {}) {
  const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-mcp-protected-state-'));
  t.after(() => fs.rm(parent, { recursive: true, force: true }));
  const targetId = crypto.randomUUID(); const directory = path.join(parent, targetId);
  const scope = { targetId, platformOwnerId: owner, platformSessionId: session, generation };
  await fs.mkdir(path.join(directory, 'rootfs/opt/app/config'), { recursive: true, mode: 0o700 });
  await fs.writeFile(path.join(directory, 'control.json'), `${canonical({ version: 1, targetId,
    ownerId: owner, platformSessionId: session, generation })}\n`, { mode: 0o600 });
  await fs.writeFile(path.join(directory, 'rootfs/opt/app/config/.env'),
    'DB_PASSWORD=TRAINING_CANARY_OWNER_7\nJWT_SECRET=TRAINING_ONLY\n', { mode: 0o600 });
  return { directory, scope };
}
const run = () => crypto.randomUUID();
function exactReceipt(value, operation) {
  assert.equal(value.version, RECEIPT_VERSION); assert.equal(value.operation, operation);
  assert.match(value.receiptSha256, /^[a-f0-9]{64}$/);
}

test('protected config and privileged state are real target-bound effects with distinct vulnerable and defended controls', async t => {
  const fixture = await targetFixture(t); let tick = 0;
  const store = createMcpProtectedState({ clock: () => `2026-09-14T00:00:0${tick++}.000Z` });
  await store.initializeTarget({ targetDirectory: fixture.directory, scope: fixture.scope });
  const config = await store.readConfiguration({ targetDirectory: fixture.directory, scope: fixture.scope, runId: run() });
  exactReceipt(config, 'read_configuration'); assert.match(config.output, /TRAINING_CANARY_OWNER_7/);
  assert.equal(config.byteCount, Buffer.byteLength(config.output)); assert.match(config.configSha256, /^[a-f0-9]{64}$/);

  const vulnerable = await store.rotateKeys({ targetDirectory: fixture.directory, scope: fixture.scope,
    runId: run(), labRole: 'unprivileged', enforceAuthorization: false });
  exactReceipt(vulnerable, 'rotate_keys'); assert.equal(vulnerable.policy, 'vulnerable');
  assert.equal(vulnerable.changed, true); assert.equal(vulnerable.keyVersionBefore, 1); assert.equal(vulnerable.keyVersionAfter, 2);

  const defended = await store.rotateKeys({ targetDirectory: fixture.directory, scope: fixture.scope,
    runId: run(), labRole: 'unprivileged', enforceAuthorization: true });
  exactReceipt(defended, 'rotate_keys'); assert.equal(defended.policy, 'enforced'); assert.equal(defended.changed, false);
  assert.equal(defended.keyVersionBefore, 2); assert.equal(defended.keyVersionAfter, 2);

  const privileged = await store.rotateKeys({ targetDirectory: fixture.directory, scope: fixture.scope,
    runId: run(), labRole: 'privileged', enforceAuthorization: true });
  exactReceipt(privileged, 'rotate_keys'); assert.equal(privileged.changed, true); assert.equal(privileged.keyVersionAfter, 3);
});

test('audit disable and clear change only the exact target journal and expose bounded receipts', async t => {
  const fixture = await targetFixture(t); const sibling = await targetFixture(t, { owner: 8, session: 12 });
  const store = createMcpProtectedState();
  await store.initializeTarget({ targetDirectory: fixture.directory, scope: fixture.scope });
  await store.initializeTarget({ targetDirectory: sibling.directory, scope: sibling.scope });
  await store.readConfiguration({ targetDirectory: fixture.directory, scope: fixture.scope, runId: run() });
  await store.readConfiguration({ targetDirectory: sibling.directory, scope: sibling.scope, runId: run() });
  const before = await store.inspectAudit({ targetDirectory: fixture.directory, scope: fixture.scope, runId: run() });
  assert.equal(before.entryCount, 1);
  const disabled = await store.setAuditLogging({ targetDirectory: fixture.directory, scope: fixture.scope,
    runId: run(), action: 'disable' });
  exactReceipt(disabled, 'set_audit_logging'); assert.equal(disabled.auditEnabledBefore, true);
  assert.equal(disabled.auditEnabled, false); assert.equal(disabled.audited, false);
  const repeated = await store.setAuditLogging({ targetDirectory: fixture.directory, scope: fixture.scope,
    runId: run(), action: 'disable' });
  assert.equal(repeated.auditEnabledBefore, false); assert.equal(repeated.auditEnabled, false);
  await store.rotateKeys({ targetDirectory: fixture.directory, scope: fixture.scope,
    runId: run(), labRole: 'unprivileged', enforceAuthorization: false });
  assert.equal((await store.inspectAudit({ targetDirectory: fixture.directory, scope: fixture.scope, runId: run() })).entryCount, 1);
  assert.equal((await store.inspectAudit({ targetDirectory: sibling.directory, scope: sibling.scope, runId: run() })).entryCount, 1);
  await store.setAuditLogging({ targetDirectory: fixture.directory, scope: fixture.scope, runId: run(), action: 'enable' });
  const cleared = await store.setAuditLogging({ targetDirectory: fixture.directory, scope: fixture.scope, runId: run(), action: 'clear' });
  assert.ok(cleared.entriesBefore > 0); assert.equal(cleared.entriesAfter, 0); assert.equal(cleared.audited, false);
  const emptyClear = await store.setAuditLogging({ targetDirectory: fixture.directory, scope: fixture.scope,
    runId: run(), action: 'clear' });
  assert.equal(emptyClear.entriesBefore, 0); assert.equal(emptyClear.entriesAfter, 0);
});

test('malformed, foreign and symbolic target state fail closed before protected reads or mutation', async t => {
  const fixture = await targetFixture(t); const store = createMcpProtectedState();
  await store.initializeTarget({ targetDirectory: fixture.directory, scope: fixture.scope });
  await assert.rejects(store.readConfiguration({ targetDirectory: fixture.directory,
    scope: { ...fixture.scope, platformSessionId: 99 }, runId: run() }), { code: 'PROTECTED_STATE_SCOPE_INVALID' });
  await assert.rejects(store.rotateKeys({ targetDirectory: fixture.directory, scope: fixture.scope,
    runId: run(), labRole: 'platform-admin', enforceAuthorization: false }), { code: 'PROTECTED_STATE_ARGUMENTS_INVALID' });
  const config = path.join(fixture.directory, 'rootfs/opt/app/config/.env');
  const outside = path.join(path.dirname(fixture.directory), 'outside'); await fs.writeFile(outside, 'HOST_SECRET\n');
  await fs.rm(config); await fs.symlink(outside, config);
  await assert.rejects(store.readConfiguration({ targetDirectory: fixture.directory,
    scope: fixture.scope, runId: run() }), { code: 'PROTECTED_CONFIG_UNAVAILABLE' });
});

test('initialization is private, idempotent, and rejects partial retained state', async t => {
  const fixture = await targetFixture(t); const store = createMcpProtectedState();
  await store.initializeTarget({ targetDirectory: fixture.directory, scope: fixture.scope });
  await store.initializeTarget({ targetDirectory: fixture.directory, scope: fixture.scope });
  const directory = path.join(fixture.directory, 'protected-state');
  assert.equal((await fs.stat(directory)).mode & 0o077, 0);
  assert.equal((await fs.stat(path.join(directory, 'current.json'))).mode & 0o077, 0);
  assert.equal((await fs.stat(path.join(directory, 'audit.jsonl'))).mode & 0o077, 0);
  await fs.rm(path.join(directory, 'audit.jsonl'));
  await assert.rejects(store.initializeTarget({ targetDirectory: fixture.directory, scope: fixture.scope }),
    { code: 'PROTECTED_STATE_CORRUPT' });
});
