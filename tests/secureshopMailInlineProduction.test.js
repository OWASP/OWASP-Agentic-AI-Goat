'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createMailInlineProduction, assertMailInlineSchema } = require('../server/services/secureshopMailInlineProduction');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const scene = require('../server/services/secureshopMailSceneBinding');
const { createFeatureModeAuthority } = require('../server/services/secureshopFeatureModeAuthority');
async function fixture() {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1, platformOwnerId: 7, platformSessionId: 9 };
  const context = { scope, persona: { id: 12, role: 'merchant' }, personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
  const birth = { ...scope, targetId: randomUUID() };
  const target = scene.attach(birth, createSceneBinding(birth, { sceneId: randomUUID(), sceneGeneration: 1,
    grantId: randomUUID(), execution: scope, withLease: work => work() }));
  const state = { target, revoked: false, sql: [], provision: 0, model: 0, unregistered: 0, cleanup: null,
    mode: { mode: 'vuln', generation: 0, modeStamp: 'initial' } };
  const client = { async query(sql) { state.sql.push(sql);
    if (sql.includes('SET LOCAL')) return { rows: [] };
    if (sql.includes('assert_mail_scene_execution_grant')) return { rows: [{ allowed: true }] };
    if (sql.includes('FROM secureshop_agents.turn_requests')) return { rows: [] };
    throw Error('Unexpected SQL'); } };
  const personaAuthority = { capture(value) { return { binding: { ...value.scope, personaId: value.personaId,
    role: value.role, sessionId: value.sessionId, authorityVersion: value.authorityVersion },
    async assertRemoteAdmission() { if (state.revoked) throw Error('revoked'); },
    async withPersonaEffect(work) { return work(client); } }; } };
  const launches = { async assertCurrent() { if (state.revoked) throw Error('revoked'); } };
  const unused = async () => { throw Error('Assessment execution not expected'); };
  const deps = { identityPool: { query: unused },
    assessmentDependencies: { judge: unused, personaBindings: { capture: unused },
      publicationModes: { getEvaluationScope: unused }, receipts: { beginEvaluation: unused, recordVerdict: unused },
      progress: { getGeneration: unused } },
    agentsPool: { query: unused, async connect() { return client; } }, shared: { personaAuthority,
    launches,
    conversationRepository: { getTraceEvents: unused, getBoundSession: unused, acquireBoundSession: unused },
    journal: { claim: unused, complete: unused, markUncertain: unused }, coordinator: { async run() { throw Error('No runs expected'); } } },
    mailRepository: { async recover() { return { found: false }; } },
    mailScenes: { async readRetained() { return state.target; } },
    async resolveTarget() { state.provision++; return state.target; }, async listPersonas() { return []; },
    provider: { async chat() { state.model++; throw Error('No model expected'); } },
    modeAuthority: createFeatureModeAuthority({ launches, progress: { async getEvaluationScope() { return state.mode; } } }),
    authenticatePersona(_req, _res, next) { next(); },
    resetComposition: { registerPersonaInboxTransportCleanup(callback) { state.cleanup = callback; return () => { state.unregistered++; }; },
      personaInbox: { repository: { async readCleanupReceipt(input, { operationId }) { return { version: 1, ...input, operationId }; } } } },
  };
  return { production: createMailInlineProduction(deps), state, context, deps, target };
}
test('production saved reads use current branded scene/persona and SELECT-only original purpose', async () => {
  const f = await fixture(), requestId = randomUUID();
  assert.equal((await f.production.application.readTeaching(f.context, { requestId })).status, 'unconfirmed');
  assert.equal((await f.production.application.readSummary(f.context, { requestId })).status, 'unconfirmed');
  assert.equal(f.state.provision, 0); assert.equal(f.state.model, 0);
  assert(f.state.sql.some(sql => sql.includes("s.conversation_purpose=$2")));
  f.state.revoked = true;
  await assert.rejects(f.production.application.readSummary(f.context, { requestId }), /revoked/);
  await f.production.close(); assert.equal(f.state.unregistered, 1);
});
test('captured current check rejects substituted grant or target and close fences future admission', async () => {
  const f = await fixture(), current = await f.production.current(f.context, { requestId: randomUUID() });
  f.state.target = scene.attach(f.target, createSceneBinding(f.target, { sceneId: randomUUID(), sceneGeneration: 1,
    grantId: randomUUID(), execution: f.context.scope, withLease: work => work() }));
  await assert.rejects(current.check());
  await f.production.close(); await assert.rejects(f.production.current(f.context, { requestId: randomUUID() }));
});
test('production requires durable invocation/current scene/cleanup seams and schema privileges', async () => {
  const f = await fixture(); await f.production.close();
  assert.throws(() => createMailInlineProduction({ ...f.deps, resetComposition: {} }));
  assert.throws(() => createMailInlineProduction({ ...f.deps, assessmentDependencies: undefined }));
  const pool = { async query(_sql, args) { return { rows: args ? args[0].map(name => ({ name, ready: true }))
    : [{ binding_private: true, invocation_private: true, purpose_ready: true }] }; } };
  assert.equal(await assertMailInlineSchema(pool), true);
  await assert.rejects(assertMailInlineSchema({ async query(sql, args) {
    const result = await pool.query(sql, args); if (!args) result.rows[0].invocation_private = false; return result;
  } }));
});
test('current grading capture retains the exact mail epoch and rejects a vulnerable/fixed/vulnerable cycle', async () => {
  const f = await fixture(), requestId = randomUUID();
  const original = await f.production.current(f.context, { requestId });
  assert.equal(original.executionMode.featureId, 'mail');
  assert.equal(original.executionMode.modeStamp, 'initial');
  f.state.mode = { mode: 'fixed', generation: 1, modeStamp: 'fixed' };
  await assert.rejects(original.check(), { code: 'ANALYTICS_MODE_STALE' });
  f.state.mode = { mode: 'vuln', generation: 2, modeStamp: 'returned' };
  await assert.rejects(original.check(), { code: 'ANALYTICS_MODE_STALE' });
  const current = await f.production.current(f.context, { requestId });
  assert.notDeepEqual(current.executionMode, original.executionMode);
  await f.production.close();
});


test('grading source compares original persona session before resolving protected message; historical read stays separate',async()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const source=fs.readFileSync(require.resolve('../server/services/secureshopMailInlineProduction'),'utf8');
 const start=source.indexOf('  async function readSavedSource('),end=source.indexOf('  const evidenceRepository',start);
 assert.ok(start>0&&end>start);
 const credential={sessionId:randomUUID(),authorityVersion:'1'},executionMode={mode:'vuln',generation:1,modeStamp:'original'};
 let resolved=0;const turn={sessionId:randomUUID(),taskMetadata:{mailSummary:{executionMode,personaSession:{...credential},selected:{}}}};
 const sandbox={current:async()=>({binding:{personaSession:credential},executionMode,check:async()=>{}}),readSaved:async()=>turn,
  resolveSelected:async()=>{resolved++;return{selected:{},originalRead:{},binding:{}};},equal:(a,b)=>JSON.stringify(a)===JSON.stringify(b),fail:()=>Error('denied'),PURPOSE:'secureshop_mail_summary'};
 vm.createContext(sandbox);vm.runInContext(source.slice(start,end),sandbox);
 const input={sessionId:turn.sessionId,requestId:randomUUID()};
 await sandbox.readSavedSource({},input);assert.equal(resolved,1);
 turn.taskMetadata.mailSummary.personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 await assert.rejects(sandbox.readSavedSource({},input),/denied/);assert.equal(resolved,1);
 turn.taskMetadata.mailSummary.personaSession={...credential,authorityVersion:'2'};
 await assert.rejects(sandbox.readSavedSource({},input),/denied/);assert.equal(resolved,1);
 delete turn.taskMetadata.mailSummary.personaSession;
 await assert.rejects(sandbox.readSavedSource({},input),/denied/);assert.equal(resolved,1);
});
