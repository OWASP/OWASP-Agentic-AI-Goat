'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { resetResponseIdentity, assertReplayPreserved,
 createStudentResetQ05Receipt, assertCompletedCleanupReceipts } = require('./postgres/adminStudentResetRecoveryBrowser');
const id = '12345678-1234-4234-8234-123456789012';
const endpoint = 'http://127.0.0.1:3001/api/admin/students/7/workshops/sensitive_info_disclosure/reset';
const event = { request: { method: 'POST', url: endpoint, headers: { 'X-Reset-Operation-Id': id } }, responseStatusCode: 200 };
test('response-loss selector requires exact owner route, method, UUID and real success', () => {
 assert.equal(resetResponseIdentity(event, endpoint), id);
 assert.equal(resetResponseIdentity({ ...event, request: { ...event.request, url: endpoint.replace('/7/', '/8/') } }, endpoint), null);
 assert.equal(resetResponseIdentity({ ...event, request: { ...event.request, method: 'GET' } }, endpoint), null);
 assert.throws(() => resetResponseIdentity({ ...event, responseStatusCode: 503 }, endpoint));
 assert.throws(() => resetResponseIdentity({ ...event, request: { ...event.request, headers: {} } }, endpoint));
});
test('replay oracle rejects new UUID, generation advancement, lost resumed state and sibling change', () => {
 const proof = { originalId: id, replayId: id, before: { generation: 3, resumed: ['marker'], journal: 'completed' }, after: { generation: 3, resumed: ['marker'], journal: 'completed' }, siblingBefore: { generation: 1 }, siblingAfter: { generation: 1 } };
 assertReplayPreserved(proof);
 for (const delta of [{ replayId: id.replace(/2$/, '3') }, { after: { ...proof.after, generation: 4 } }, { after: { ...proof.after, resumed: [] } }, { siblingAfter: { generation: 2 } }]) assert.throws(() => assertReplayPreserved({ ...proof, ...delta }));
});

test('distinct reset receipt binds all three real request IDs, state pairs and explicit exclusions', () => {
 const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
 const sibling = { controlled: 'sibling' }, resumed = { controlled: 'resumed' };
 const second = '12345678-1234-4234-8234-123456789013';
 const recovery = { status: 'passed', requestOperationIds: [id, id, second], realResetPostCount: 3,
  originalGeneration: 0, finalGeneration: 2, replayPreservedResumedState: true,
  siblingPreserved: true, modelCalls: 0,
  ackLoss: { method: 'POST', path: '/api/admin/students/7/workshops/sensitive_info_disclosure/reset',
   phase: 'after-real-http-200-before-browser-consumption' },
  phases: [{ phase: 'baseline', siblingSha256: hash(sibling) },
   { phase: 'resumed', snapshotSha256: hash(resumed) },
   { phase: 'replay-preserved', snapshotSha256: hash(resumed), siblingSha256: hash(sibling) }] };
 const input = { target: 7, sibling: 8, cancelBefore: { controlled: 'target' },
  cancelAfter: { controlled: 'target' }, authorityBefore: { controlled: 'target' },
  authorityAfter: { controlled: 'target' }, recovery, deniedResetPostCount: 1 };
 const receipt = createStudentResetQ05Receipt(input);
 assert.equal(receipt.workshopKey, 'sensitive_info_disclosure');
 assert.equal(receipt.requestOperationIds[1], id);
 assert.equal(receipt.requestOperationIds[2], second);
 assert.equal(receipt.deniedResetPostCount, 1);
 assert.equal(receipt.canonicalCredit, false);
 assert.equal(receipt.modelCalls, 0); assert.equal(receipt.judgeCalls, 0);
 assert(Object.values(receipt.facts).every(value => value === true));
 for (const pair of Object.values(receipt.snapshots)) assert.equal(pair.before, pair.after);
 assert(receipt.excluded.includes('bulk-reset'));
 assert(receipt.excluded.includes('full-Q05-denominator'));
 assert.throws(() => createStudentResetQ05Receipt({ ...input, deniedResetPostCount: 0 }));
 assert.throws(() => createStudentResetQ05Receipt({ ...input, cancelAfter: {} }));
 assert.throws(() => createStudentResetQ05Receipt({ ...input,
  recovery: { ...recovery, requestOperationIds: [id, second, second] } }));
 assert.throws(() => createStudentResetQ05Receipt({ ...input,
  recovery: { ...recovery, phases: recovery.phases.map(phase => phase.phase === 'replay-preserved'
   ? { ...phase, snapshotSha256: hash({ lost: 'resumed-state' }) } : phase) } }));
});

test('published cleanup receipt oracle enforces exact plan steps, owner and generations', () => {
 const base = { operation_id: id, owner_id: 7, from_generation: 2,
  to_generation: 3, completed_at: new Date('2026-01-01T00:00:00Z') };
 const make = version => ({ resets: [{ ...base, plan_version: version, status: 'completed' }],
  steps: (version === 2 ? ['finflow_store'] : ['legacy_store', 'finflow_store'])
   .map(step_key => ({ operation_id: id, step_key, status: 'completed' })),
  receipts: (version === 2 ? ['finflow_store'] : ['legacy_store', 'finflow_store'])
   .map(step_key => ({ ...base, step_key })) });
 for (const version of [1, 2]) {
  const valid = make(version);
  assert.equal(assertCompletedCleanupReceipts(valid, id, 7, 2), true);
  assert.throws(() => assertCompletedCleanupReceipts({ ...valid, receipts: [] }, id, 7, 2));
  assert.throws(() => assertCompletedCleanupReceipts({ ...valid,
   receipts: [...valid.receipts, { ...base, step_key: 'extra' }] }, id, 7, 2));
  assert.throws(() => assertCompletedCleanupReceipts({ ...valid,
   receipts: valid.receipts.map(row => ({ ...row, owner_id: 8 })) }, id, 7, 2));
  assert.throws(() => assertCompletedCleanupReceipts({ ...valid,
   receipts: valid.receipts.map(row => ({ ...row, from_generation: 1 })) }, id, 7, 2));
  assert.throws(() => assertCompletedCleanupReceipts({ ...valid,
   receipts: valid.receipts.map(row => ({ ...row, completed_at: null })) }, id, 7, 2));
  assert.throws(() => assertCompletedCleanupReceipts({ ...valid,
   steps: valid.steps.map(row => ({ ...row, status: 'pending' })) }, id, 7, 2));
 }
});

test('current-host reset wrapper orders Cancel then real denied confirmation before recovery', async () => {
 const { EventEmitter } = require('node:events');
 const { runStudentResetQ05Scenario } = require('./postgres/adminStudentResetRecoveryBrowser');
 const base = 'http://127.0.0.1:3001';
 const resetUrl = `${base}/api/admin/students/7/workshops/sensitive_info_disclosure/reset`;
 const order = [], records = [];
 class Page extends EventEmitter {
  async goto(url) { assert(url.startsWith(base + '/admin/student-workshop-view')); order.push('open'); }
  async waitForSelector() {}
  async $(selector) {
   assert(selector.includes('Erase all Sensitive Info'));
   return { evaluate: async () => true, click: async () => {
    const dialog = { type: () => 'confirm',
     message: () => 'Reset Sensitive Info Workshop Progress for controlled learner?',
     dismiss: async () => { order.push('cancel'); },
     accept: async () => {
      order.push('accept');
      const request = { url: () => resetUrl, method: () => 'POST' };
      this.emit('request', request);
      this.emit('response', { url: () => resetUrl, request: () => request, status: () => 403 });
     } };
    this.emit('dialog', dialog);
   } };
  }
  waitForResponse(predicate) { return new Promise(resolve => {
   const listener = response => { if (predicate(response)) { this.off('response', listener); resolve(response); } };
   this.on('response', listener);
  }); }
 }
 const page = new Page();
 const snapshots = { 7: { state: [{ generation: 0 }], completions: [{ id: 'controlled' }],
  time: [{ seconds: 0 }], tools: [{ marker: 'controlled' }] },
  8: { state: [{ generation: 0 }], completions: [{ id: 'sibling' }],
   time: [{ seconds: 0 }], tools: [{ marker: 'sibling' }] } };
 const support = { seedControlledCompletion: async id => { order.push('seed-' + id); },
  resume: async id => { order.push('resume-' + id); },
  snapshot: async id => structuredClone(snapshots[id]) };
 const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
 const replay = hash({ resumed: true }), siblingHash = hash(snapshots[8]);
 const recovery = { status: 'passed', requestOperationIds: [id, id, '12345678-1234-4234-8234-123456789013'],
  realResetPostCount: 3, originalGeneration: 0, finalGeneration: 2, modelCalls: 0,
  replayPreservedResumedState: true, siblingPreserved: true,
  ackLoss: { method: 'POST', path: '/api/admin/students/7/workshops/sensitive_info_disclosure/reset',
   phase: 'after-real-http-200-before-browser-consumption' },
  phases: [{ phase: 'baseline', siblingSha256: siblingHash },
   { phase: 'resumed', snapshotSha256: replay },
   { phase: 'replay-preserved', snapshotSha256: replay, siblingSha256: siblingHash }] };
 const receipt = await runStudentResetQ05Scenario({ page, base, target: 7, sibling: 8, support,
  revoke: async () => { order.push('revoke'); },
  restore: async () => { order.push('restore'); },
  recover: async () => { order.push('recover'); return recovery; },
  record: async value => records.push(value) });
 assert.deepEqual(order.slice(0, 8), ['seed-7', 'seed-8', 'resume-7', 'resume-8',
  'open', 'cancel', 'open', 'revoke']);
 assert(order.indexOf('accept') > order.indexOf('revoke'));
 assert(order.indexOf('recover') > order.indexOf('accept'));
 assert.equal(receipt.deniedResetPostCount, 1);
 assert.equal(records.at(-1).status, 'bounded-rendered-student-reset-observed');
 assert(records.some(value => value.phase === 'cancel-no-request'));
 assert(records.some(value => value.phase === 'authority-denied'));
 assert.equal(page.listenerCount('request'), 0);
});

test('response hook drops exactly one successful delivery and drains its handler', async () => {
 const { EventEmitter } = require('node:events');
 const { installOneResponseLoss } = require('./postgres/adminStudentResetRecoveryBrowser');
 const client = new EventEmitter(), commands = [];
 client.send = async (name, args) => commands.push({ name, args });
 client.detach = async () => commands.push({ name: 'detach' });
 const hook = await installOneResponseLoss({ createCDPSession: async () => client }, endpoint);
 client.emit('Fetch.requestPaused', { ...event, requestId: 'one' });
 await new Promise(resolve => setImmediate(resolve));
 assert.equal(hook.operationId(), id);
 client.emit('Fetch.requestPaused', { ...event, requestId: 'two' });
 await hook.close();
 assert.deepEqual(commands.filter(c => c.name === 'Fetch.failRequest').map(c => c.args.requestId), ['one']);
 assert.deepEqual(commands.filter(c => c.name === 'Fetch.continueRequest').map(c => c.args.requestId), ['two']);
 assert.equal(client.listenerCount('Fetch.requestPaused'), 0);
 assert.equal(commands.at(-1).name, 'detach');
});
test('native composition denies identity database substitution before pool creation', async () => {
 const { createResetSupport } = require('./postgres/adminStudentResetRecoverySupport');
 const saved = { ...process.env };
 try {
  process.env.FINFLOW_WORKSHOP_DATABASE_URL = 'postgresql://dvaia_finflow_runtime@127.0.0.1:1/owasp_ai_goat_test_student_reset_finflow_abcdef123456';
  process.env.FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL = 'postgresql://dvaia_finflow_migration@127.0.0.1:1/owasp_ai_goat_test_student_reset_finflow_abcdef123456';
  process.env.PG_ADMIN_BROWSER_TEST_RUNTIME_URL = process.env.FINFLOW_WORKSHOP_DATABASE_URL;
  await assert.rejects(createResetSupport({}), /strictly unequal|not equal|notStrictEqual/);
 } finally {
  for (const key of ['FINFLOW_WORKSHOP_DATABASE_URL','FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL','PG_ADMIN_BROWSER_TEST_RUNTIME_URL']) {
   if (saved[key] === undefined) delete process.env[key]; else process.env[key] = saved[key];
  }
 }
});
test('bounded readiness diagnostic distinguishes absent and disabled controls without page content', () => {
 const { resetReadinessSnapshot } = require('./postgres/adminStudentResetRecoveryBrowser');
 const prior = global.document;
 let reset = null;
 global.document = { body: { innerText: 'Loading private learner name' },
  querySelector: selector => selector.startsWith('button') ? reset : {},
  querySelectorAll: () => [{ textContent: 'Refresh', disabled: true }] };
 try {
  const absent = resetReadinessSnapshot();
  assert.equal(absent.resetPresent, false); assert.equal(absent.resetDisabled, null);
  assert.equal(absent.refreshDisabled, true); assert.equal(absent.loadingText, true);
  assert.equal(JSON.stringify(absent).includes('private learner'), false);
  reset = { disabled: true }; assert.equal(resetReadinessSnapshot().resetDisabled, true);
  reset.disabled = false; assert.equal(resetReadinessSnapshot().resetDisabled, false);
 } finally { if (prior === undefined) delete global.document; else global.document = prior; }
});
test('access-denial fixture requires real response observation around revoke and restore, without reset', async () => {
 const { runAccessDenialScenario } = require('./postgres/adminStudentResetRecoveryBrowser');
 const order = [], snapshots = { 7: { generation: 2 }, 8: { generation: 1 } };
 const page = { on() {}, off() {}, waitForSelector: async () => {},
  waitForResponse: async () => { order.push('observe'); }, waitForFunction: async () => {},
  $$: async () => [{ evaluate: async fn => fn({ textContent: 'Refresh' }), click: async () => order.push('refresh') }] };
 const result = await runAccessDenialScenario({ page, base: 'http://127.0.0.1:3001', target: 7, sibling: 8,
  support: { snapshot: async id => snapshots[id] }, revoke: async () => order.push('revoke'),
  restore: async () => order.push('restore'), announce: async () => order.push('announce') });
 assert.deepEqual(order, ['observe', 'observe', 'revoke', 'announce', 'restore', 'observe', 'refresh', 'restore']);
 assert.equal(result.resetPosts, 0); assert.equal(result.targetUnchanged, true);
 // This controlled helper test proves orchestration only; real403/SQL remain native-pending.
});
test('roster denial extension orders real-permission callbacks around response observations and preserves snapshots', async () => {
 const { runRosterDenialScenario } = require('./postgres/adminStudentResetRecoveryBrowser');
 const order = []; const element = { evaluate: async () => true, click: async () => order.push('click') };
 const page = { waitForResponse: async () => order.push('observe'), goto: async () => order.push('navigate'),
  waitForFunction: async () => {}, evaluate: async () => 'private-learner',
  evaluateHandle: async () => ({ asElement: () => element, dispose: async () => {} }) };
 const result = await runRosterDenialScenario({ page, base: 'http://127.0.0.1:1', target: 1, sibling: 2,
  support: { snapshot: async id => ({ id, generation: 3 }) }, privateUsername: 'private-learner',
  revoke: async () => order.push('revoke'), restore: async () => order.push('restore') });
 assert.deepEqual(order, ['observe', 'navigate', 'revoke', 'observe', 'click', 'restore', 'observe', 'click', 'restore']);
 assert.equal(result.targetUnchanged, true); assert.equal(result.siblingUnchanged, true);
 // Controlled orchestration only; these stubs cannot qualify authentication or rendered removal.
});
test('inspector denial extension restores without navigation and compares immutable owner/sibling evidence', async () => {
 const { runInspectorDenialScenario } = require('./postgres/adminStudentResetRecoveryBrowser');
 const order=[];const button={evaluate:async fn=>{const text=String(fn);return text.includes('textContent')?true:text.includes('getBoundingClientRect')?true:undefined;},click:async()=>order.push('refresh')};
 const page={on(){},off(){},waitForResponse:async()=>order.push('observe'),goto:async()=>order.push('navigate'),type:async()=>order.push('owner-filter'),waitForFunction:async()=>{},$$:async()=>[button]};
 const result=await runInspectorDenialScenario({page,base:'http://127.0.0.1:1',target:7,runId:'controlled-run',receiptText:'controlled receipt',revoke:async()=>order.push('revoke'),restore:async()=>order.push('restore'),snapshot:async()=>({runs:['owner','sibling'],receipts:['controlled']})});
 assert.equal(order.filter(x=>x==='navigate').length,1);
 assert.deepEqual(order,['observe','navigate','observe','owner-filter','revoke','observe','refresh','restore','observe','refresh','restore']);
 assert.equal(result.immutableRunsAndReceipts,true);assert.equal(result.postCount,0);
});
