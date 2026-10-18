'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { createDurableAgentFixture, execution } = require('./helpers/finflowDurableAgentFixture');
const {
  createSensitiveInfoWorkshopStateStore,
  executeVaultCorpTool,
} = require('../server/services/sensitiveInfoWorkshopAgent');
const { verifyFinflowAgentResourceActionReceipt } = require('../server/services/finflowAgentResourceActionReceipt');
const { verifyFinflowLogMutationReceipt } = require('../server/services/finflowLogMutationReceipt');
const { verifyFinflowLogArtifactReceipt } = require('../server/services/finflowLogArtifactReceipt');

const accessLogPath = path.join(__dirname, '../server/sensitive_files/logs/access.log');
const run = (owner, generation, suffix) => execution(owner, generation,
  `61000000-0000-4000-8000-${String(suffix).padStart(12, '0')}`);
const call = (name, params, result) => ({ name, params, ...result });

function assertResourceAction(name, params, result, currentExecution) {
  const toolCall = call(name, params, result);
  assert.equal(verifyFinflowAgentResourceActionReceipt({
    receipt: result.resourceActionReceipt,
    execution: currentExecution,
    toolCall,
    resourceAuthorityReceipt: result.resourceAuthorityReceipt,
  }), result.resourceActionReceipt);
  assert.equal(verifyFinflowAgentResourceActionReceipt({
    receipt: { ...result.resourceActionReceipt },
    execution: currentExecution,
    toolCall,
    resourceAuthorityReceipt: result.resourceAuthorityReceipt,
  }), null, 'serialized receipt data cannot recreate the private authority binding');
}

async function setup(t) {
  const fixture = createDurableAgentFixture(t);
  await fixture.files.assertReady();
  const store = createSensitiveInfoWorkshopStateStore({ durableResources: fixture.resources });
  return { fixture, store };
}

test('durable database deletion and backup resources are isolated by owner and trusted receipts', async t => {
  const { store } = await setup(t);
  const alice = store.getUserState('101');
  const bob = store.getUserState('202');
  const createExecution = run(101, 0, 1);
  const created = await executeVaultCorpTool('admin_create_backup', { backup_name: 'alice_only' },
    'vulnerable', alice, createExecution);
  assertResourceAction('admin_create_backup', { backup_name: 'alice_only' }, created, createExecution);

  const bobDownload = await executeVaultCorpTool('admin_download_backup',
    { backup_path: '/var/app/data/backups/alice_only.bak' }, 'vulnerable', bob, run(202, 0, 2));
  const bobListing = await executeVaultCorpTool('admin_list_directory',
    { directory_path: '/var/app/data/backups' }, 'vulnerable', bob, run(202, 0, 3));
  assert.equal(bobDownload.success, false);
  assert.doesNotMatch(bobListing.result, /alice_only\.bak/);

  const deleteExecution = run(101, 0, 4);
  const deleted = await executeVaultCorpTool('admin_delete_database', { confirm: true },
    'vulnerable', alice, deleteExecution);
  assertResourceAction('admin_delete_database', { confirm: true }, deleted, deleteExecution);
  const aliceAccounts = await executeVaultCorpTool('get_account_info', { account_id: '*' },
    'vulnerable', alice, run(101, 0, 5));
  const bobAccounts = await executeVaultCorpTool('get_account_info', { account_id: '*' },
    'vulnerable', bob, run(202, 0, 6));
  assert.match(aliceAccounts.result, /\(0 records\)/);
  assert.match(bobAccounts.result, /\(10 records\)/);
});

test('controlled logs use owner-generation overlays, trusted receipts, and immutable fixture bytes', async t => {
  const originalFixture = fs.readFileSync(accessLogPath, 'utf8');
  const { store } = await setup(t);
  const alice = store.getUserState('101');
  const bob = store.getUserState('202');
  const mutationExecution = run(101, 0, 7);
  const params = { log_type: 'access', action: 'modify', new_content: 'alice-only-log' };
  const modified = await executeVaultCorpTool('admin_modify_logs', params, 'vulnerable', alice, mutationExecution);
  assert.equal(verifyFinflowLogMutationReceipt({ receipt: modified.artifactReceipt,
    execution: mutationExecution, toolCall: call('admin_modify_logs', params, modified) }), modified.artifactReceipt);
  assert.equal(verifyFinflowLogMutationReceipt({ receipt: { ...modified.artifactReceipt },
    execution: mutationExecution, toolCall: call('admin_modify_logs', params, modified) }), null);

  const readExecution = run(101, 0, 8);
  const aliceAccess = await executeVaultCorpTool('admin_read_logs', { log_type: 'access' },
    'vulnerable', alice, readExecution);
  assert.equal(verifyFinflowLogArtifactReceipt({ receipt: aliceAccess.artifactReceipt,
    execution: readExecution, ownerId: 101, logType: 'access', filename: 'access.log',
    result: aliceAccess.result }), aliceAccess.artifactReceipt);
  const aliceAlias = await executeVaultCorpTool('admin_read_logs', { log_type: 'llm_requests' },
    'vulnerable', alice, run(101, 0, 9));
  const bobAccess = await executeVaultCorpTool('admin_read_logs', { log_type: 'access' },
    'vulnerable', bob, run(202, 0, 10));
  assert.match(aliceAccess.result, /alice-only-log/);
  assert.match(aliceAlias.result, /fixture-llm-001/);
  assert.doesNotMatch(aliceAlias.result, /alice-only-log/);
  assert.doesNotMatch(bobAccess.result, /alice-only-log/);
  assert.match(modified.result, /owner-local workshop overlay/i);
  assert.match(modified.result, /controlled fixture remains unchanged/i);
  assert.equal(fs.readFileSync(accessLogPath, 'utf8'), originalFixture);
});

test('in-memory reset preserves durable generation state; durable retirement advances to a clean generation', async t => {
  const { fixture, store } = await setup(t);
  const firstState = store.getUserState('101');
  await executeVaultCorpTool('admin_modify_logs',
    { log_type: 'audit', action: 'modify', new_content: 'alice-audit-overlay' },
    'vulnerable', firstState, run(101, 0, 11));

  assert.equal(store.resetUser('101'), true);
  const replacementSameGeneration = store.getUserState('101');
  assert.notEqual(replacementSameGeneration, firstState);
  const stillDurable = await executeVaultCorpTool('admin_read_logs', { log_type: 'audit' },
    'vulnerable', replacementSameGeneration, run(101, 0, 12));
  assert.match(stillDurable.result, /alice-audit-overlay/,
    'dropping process-local state must not pretend to reset durable generation 0');

  const operationId = randomUUID();
  const retired = await fixture.resources.retireGeneration({
    operationId, ownerId: 101, fromGeneration: 0, toGeneration: 1,
  });
  assert.deepEqual({ operationId: retired.operationId, ownerId: retired.ownerId,
    fromGeneration: retired.fromGeneration, toGeneration: retired.toGeneration, status: retired.status },
  { operationId, ownerId: 101, fromGeneration: 0, toGeneration: 1, status: 'completed' });
  assert.equal(store.resetUser('101'), true);
  const generationOne = store.getUserState('101');
  const baseline = await executeVaultCorpTool('admin_read_logs', { log_type: 'audit' },
    'vulnerable', generationOne, run(101, 1, 13));
  assert.match(baseline.result, /fixture-audit-001/);
  assert.doesNotMatch(baseline.result, /alice-audit-overlay/);
  await assert.rejects(executeVaultCorpTool('admin_read_logs', { log_type: 'audit' },
    'vulnerable', generationOne, run(101, 0, 14)),
  error => ['FINFLOW_RESOURCE_RETIRED', '55000'].includes(error?.code));
});

test('durable owner reset starts only that owner at the next generation and preserves sibling resources', async t => {
  const { fixture, store } = await setup(t);
  const alice = store.getUserState('101');
  const bobBefore = store.getUserState('202');
  const aliceCreate = run(101, 0, 15);
  const aliceBackup = await executeVaultCorpTool('admin_create_backup', { backup_name: 'alice_kept' },
    'vulnerable', alice, aliceCreate);
  assertResourceAction('admin_create_backup', { backup_name: 'alice_kept' }, aliceBackup, aliceCreate);
  await executeVaultCorpTool('admin_delete_database', { confirm: true }, 'vulnerable', alice, run(101, 0, 16));
  await executeVaultCorpTool('admin_create_backup', { backup_name: 'bob_old_generation' },
    'vulnerable', bobBefore, run(202, 0, 17));
  await executeVaultCorpTool('admin_delete_database', { confirm: true }, 'vulnerable', bobBefore, run(202, 0, 18));

  await fixture.resources.retireGeneration({ operationId: randomUUID(), ownerId: 202,
    fromGeneration: 0, toGeneration: 1 });
  assert.equal(store.resetUser('202'), true);
  const bobAfter = store.getUserState('202');
  const aliceListing = await executeVaultCorpTool('admin_list_directory',
    { directory_path: '/var/app/data/backups' }, 'vulnerable', alice, run(101, 0, 19));
  const aliceAccounts = await executeVaultCorpTool('get_account_info', { account_id: '*' },
    'vulnerable', alice, run(101, 0, 20));
  const bobListing = await executeVaultCorpTool('admin_list_directory',
    { directory_path: '/var/app/data/backups' }, 'vulnerable', bobAfter, run(202, 1, 21));
  const bobAccounts = await executeVaultCorpTool('get_account_info', { account_id: '*' },
    'vulnerable', bobAfter, run(202, 1, 22));
  assert.match(aliceListing.result, /alice_kept\.bak/);
  assert.match(aliceAccounts.result, /\(0 records\)/);
  assert.doesNotMatch(bobListing.result, /bob_old_generation\.bak/);
  assert.match(bobAccounts.result, /\(10 records\)/);
});

test('fixed and vulnerable modes share one durable owner generation without fixed-mode mutation', async t => {
  const { store } = await setup(t);
  const state = store.getUserState('101');
  const blocked = await executeVaultCorpTool('admin_create_backup', { backup_name: 'blocked' },
    'fixed', state, run(101, 0, 23));
  const listing = await executeVaultCorpTool('admin_list_directory',
    { directory_path: '/var/app/data/backups' }, 'vulnerable', state, run(101, 0, 24));
  await executeVaultCorpTool('admin_delete_database', { confirm: true },
    'vulnerable', state, run(101, 0, 25));
  const fixedRead = await executeVaultCorpTool('get_account_info', { account_id: 'FF-001' },
    'fixed', state, run(101, 0, 26));
  assert.equal(blocked.securityFlag, 'blocked');
  assert.equal(blocked.resourceActionReceipt, undefined);
  assert.doesNotMatch(listing.result, /blocked\.bak/);
  assert.equal(fixedRead.success, false);
});

test('state and durable execution ownership reject missing or foreign identities', async t => {
  const { fixture, store } = await setup(t);
  assert.throws(() => store.getUserState(), /user id/i);
  assert.throws(() => store.getUserState(''), /user id/i);
  await assert.rejects(executeVaultCorpTool('get_account_info', { account_id: 'FF-001' },
    'fixed'), /state/i);
  const alice = store.getUserState('101');
  await assert.rejects(executeVaultCorpTool('get_account_info', { account_id: 'FF-001' },
    'fixed', alice), error => error?.code === 'FINFLOW_RESOURCE_SCOPE_INVALID');
  await assert.rejects(fixture.resources.readDataset({ scope: { ownerId: 101, generation: 0 },
    execution: run(202, 0, 27) }), error => error?.code === 'FINFLOW_RESOURCE_SCOPE_INVALID');
});

test('Sensitive chat and reset derive owner from authentication and fence durable reset before state invalidation', () => {
  const routeSource = fs.readFileSync(path.join(__dirname, '../server/routes/sensitiveInfoWorkshop.js'), 'utf8');
  assert.match(routeSource, /agent\.runUserExclusive\(userId, async \(requestState,execution\) =>/);
  assert.match(routeSource, /agent\.processMessage\([^;]*userId,\s*requestState,\s*\{execution\}\)/s);
  assert.match(routeSource, /const userId = String\(req\.user\.id\)/);
  assert.match(routeSource, /aggregate\.reset\.reset\(req\.user\.id/);
  assert.match(routeSource, /router\.resetOwner=\(owner,work\)=>agent\.resetUserExclusive/);
  assert.match(routeSource, /await work\(\);\s*sensitiveStateStore\.resetUser\(String\(owner\)\)/s);
  assert.doesNotMatch(routeSource, /aggregate\.reset\.reset\(req\.body\.userId/);
});
