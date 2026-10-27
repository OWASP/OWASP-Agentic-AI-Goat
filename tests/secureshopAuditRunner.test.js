'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createRunCoordinator } = require('../server/agent-runtime/runCoordinator');
const { createBoundTurns } = require('../server/services/secureshopBoundTurns');
const { createSecureShopAuditRunner } = require('../server/services/secureshopAuditRunner');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { SECURESHOP_CONVERSATION_PURPOSES: PURPOSES } = require('../server/services/secureshopConversationPurpose');

const id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const scope = { launchId: id, scenarioId: id, generation: 1, platformOwnerId: 7, platformSessionId: 8 };
const admin = { id: 3, role: 'admin' };

function fixture({ failJob = false, failTrace = false, revokeOnFinish = false, assessmentResult, skipAssessment = false,
  capturePersonaAuthority, onAssessment, timing, onJob, conversationPurpose } = {}) {
  const rows = new Map();
  const calls = { claim: 0, complete: 0, uncertain: 0, job: 0, finish: 0, events: [] };
  const purposes = [];
  let revoked = false;
  const journal = {
    async claim(input) {
      calls.claim++;
      const request = createTurnRequest(input);
      const key = `${request.sessionId}:${request.requestId}`;
      const existing = rows.get(key);
      if (existing) {
        if (existing.hash !== request.hash) throw Object.assign(new Error('Turn request conflict'), { code: 'TURN_REQUEST_CONFLICT' });
        return { status: existing.status, claimId: existing.claimId,
          ...(existing.status === 'completed' ? { result: existing.result } : {}) };
      }
      const claimId = `${id}:${calls.claim}`;
      rows.set(key, { hash: request.hash, status: 'started', claimId });
      return { status: 'claimed', claimId };
    },
    async complete({ sessionId, requestId: rid, result }, fence) {
      calls.complete++;
      calls.completionFence=fence;
      const row = rows.get(`${sessionId}:${rid}`);
      assert.equal(row.status, 'started');
      row.status = 'completed'; row.result = structuredClone(result);
    },
    async markUncertain({ sessionId, requestId: rid }) {
      calls.uncertain++;
      const row = rows.get(`${sessionId}:${rid}`);
      if (row?.status === 'started') row.status = 'uncertain';
    },
  };
  const ledger = {
    supportsPreRunAdmission: true,
    async begin(_context, { admit }) {
      const decision = await admit();
      if (decision.skip) return { skipped: true, value: decision.value };
      return { durableGeneration: '1', admission: decision };
    },
    async assertCurrent() {},
    async recordEvent(_context,event) {
      calls.events.push(event);
      if (failTrace && event.node === 'audit_actor_verified') throw new Error('trace unavailable');
    },
    async finish(_context, { status }) {
      calls.finish++;
      if (revokeOnFinish && status === 'completed') revoked = true;
    },
  };
  const conversations = {
    async assertOwned(_sessionId, _binding, _persona, purpose) {
      purposes.push(purpose);
      if (revoked) throw Object.assign(new Error('launch revoked'), { code: 'STALE_LAUNCH' });
    },
  };
  const turns = createBoundTurns({ conversations,
    coordinator: createRunCoordinator({ family: 'AuditRunnerTest', ledger }) });
  const executeJob = async ({ boundary, requestedCount, assessment, workerBudget }, publicationFence) => {
    calls.jobFence=publicationFence;
    calls.job++;
    await boundary.check();
    if (failJob) throw new Error('audit worker failed');
    await onJob?.(workerBudget);
    if (assessment && !skipAssessment) await assessment.consume({ runId: boundary.identity.runId });
    return { runId: boundary.identity.runId, summary: 'controlled summary', provider: 'ollama', model: 'controlled',
      requestedCount, rowCount: 0, objectiveCredit: false };
  };
  const beginAssessment = assessmentResult === undefined && !skipAssessment ? undefined : async ({ binding, execution }, fence) => {
    assert.equal(binding.role, 'admin'); assert.equal(execution.runId.length > 0, true);
    onAssessment?.(fence,execution);
    return { async consume(evidence) { assert.equal(evidence.runId, execution.runId); }, outcome() {
      if (skipAssessment) throw new Error('Audit assessment did not complete');
      return assessmentResult;
    } };
  };
  const runner = createSecureShopAuditRunner({conversationPurpose, turns, conversations, journal, executeJob, beginAssessment, capturePersonaAuthority,
    ...(timing?{timing}:{}) });
  return { runner, calls, rows, purposes };
}

function input(overrides = {}) {
  return { sessionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', requestId, scope, persona: admin,
    requestedCount: 2, ...overrides };
}

test('completed replay returns the journal DTO and skips the second job', async () => {
  const f = fixture();
  const first = await f.runner.run(input());
  const second = await f.runner.run(input());
  assert.equal(f.calls.job, 1);
  assert.equal(f.calls.complete, 1);
  assert.equal(second.replayed, true);
  assert.deepEqual(second, { ...first, replayed: true });
  assert.ok(f.purposes.length > 0);
  assert.ok(f.purposes.every(value => value === PURPOSES.auditSummary));
  assert.deepEqual(f.calls.events.filter(event=>event.node==='audit_actor_verified'),[
    {node:'audit_actor_verified',type:'decision',data:{decisionSource:'model',provider:'ollama',model:'controlled'}}]);
});

test('verified actor metadata is retained after assessment and trace failure cannot complete the journal', async()=>{
  const f=fixture({assessmentResult:{completed:false,judgment:{verdict:'fail'}}});
  await f.runner.run(input());
  assert.equal(f.calls.events.at(-1).node,'audit_actor_verified');
  assert.equal(f.calls.complete,1);
  const broken=fixture({failTrace:true,assessmentResult:{completed:false,judgment:{verdict:'fail'}}});
  await assert.rejects(broken.runner.run(input()),/trace unavailable/);
  assert.equal(broken.calls.complete,0);
  assert.equal(broken.calls.uncertain,1);
  assert.equal(broken.calls.events.at(-1).node,'audit_actor_verified');
  const failed=fixture({failJob:true});
  await assert.rejects(failed.runner.run(input()),/audit worker failed/);
  assert.equal(failed.calls.events.some(event=>event.node==='audit_actor_verified'),false);
});

test('Audit run passes one monotonic deadline to its assessment and bounds the owner run',async()=>{
  let time=10,seen;
  const timing=require('../server/services/secureshopAuditTiming').createSecureShopAuditTiming({
    env:{SS_AUDIT_RUN_TIMEOUT_MS:'290000',SS_AUDIT_JUDGE_TIMEOUT_MS:'240000'},now:()=>time});
  const f=fixture({timing,assessmentResult:{completed:false,judgment:{verdict:'fail'}},
    onAssessment:(_fence,execution)=>{seen=execution.auditDeadline;}});
  await f.runner.run(input());
  assert.equal(seen,290010);
  time=100010;assert.equal(timing.remainingJudgeMs(seen),180000);
});

test('unbounded worker budget is sampled after preparation and never exports parent clock origin',async()=>{
  let time=1000,measured;
  const timing=require('../server/services/secureshopAuditTiming').createSecureShopAuditTiming({
    profile:'unbounded',env:{},now:()=>time});
  const f=fixture({timing,conversationPurpose:PURPOSES.auditUnbounded,onJob:async workerBudget=>{
    assert.equal(typeof workerBudget,'function');
    time+=40000;measured=workerBudget();
  }});
  await f.runner.run(input());
  assert.equal(measured,145000);
  const ordinary=fixture({onJob:async workerBudget=>assert.equal(workerBudget,undefined)});
  await ordinary.runner.run(input());
});

test('same request ID with a changed count is a durable request conflict', async () => {
  const f = fixture();
  await f.runner.run(input({ requestedCount: 2 }));
  await assert.rejects(f.runner.run(input({ requestedCount: 3 })), { code: 'TURN_REQUEST_CONFLICT' });
  assert.equal(f.calls.job, 1);
  assert.equal(f.calls.complete, 1);
});

test('uncertain job failure cannot automatically retry', async () => {
  const f = fixture({ failJob: true });
  await assert.rejects(f.runner.run(input()), /audit worker failed/);
  await assert.rejects(f.runner.run(input()), { code: 'TURN_RECOVERY_REQUIRED' });
  assert.equal(f.calls.job, 1);
  assert.equal(f.calls.uncertain, 1);
});

test('final ownership is checked after the completed job before returning', async () => {
  const f = fixture({ revokeOnFinish: true });
  await assert.rejects(f.runner.run(input()), { code: 'STALE_LAUNCH' });
  assert.equal(f.calls.job, 1);
  assert.equal(f.calls.complete, 1);
  assert.equal(f.rows.get(`${input().sessionId}:${requestId}`).status, 'completed');
});

test('non-admin and invalid counts reject before admission or job work', async () => {
  for (const value of [{ persona: { id: 3, role: 'customer' } }, { requestedCount: 0 }, { requestedCount: 1.5 }, { requestedCount: Infinity }]) {
    const f = fixture();
    await assert.rejects(f.runner.run(input(value)), TypeError);
    assert.equal(f.calls.claim, 0);
    assert.equal(f.calls.job, 0);
  }
});

test('assessment outcome is consumed before journal completion and only compact judgment is replayed', async () => {
  const f = fixture({ assessmentResult: { completed: true, judgment: { verdict: 'pass', explanation: 'controlled' }, receipt: { private: true } } });
  const result = await f.runner.run(input());
  assert.equal(result.objectiveCredit, true);
  assert.deepEqual(result.assessment, { completed: true, judgment: { verdict: 'pass', explanation: 'controlled' } });
  assert.equal(Object.hasOwn(result.assessment, 'receipt'), false);
  assert.equal(f.calls.complete, 1);
});

test('skipped assessment cannot complete the parent turn or journal', async () => {
  const f = fixture({ skipAssessment: true });
  await assert.rejects(f.runner.run(input()), /Audit assessment did not complete/);
  assert.equal(f.calls.job, 1);
  assert.equal(f.calls.complete, 0);
  assert.equal(f.calls.uncertain, 1);
});

test('persona authority is captured privately and fences assessment plus journal publication', async () => {
  const personaSession={sessionId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',authorityVersion:'4'};
  let checks=0,captured,assessmentFence;
  const fence={binding:{...scope,personaId:3,role:'admin',...personaSession},async assertRemoteAdmission(){checks++;},
    async withPersonaEffect(_input,operation){return operation();}};
  const f=fixture({assessmentResult:{completed:false,judgment:{verdict:'fail'}},
    capturePersonaAuthority:async input=>{captured=input;return fence;},onAssessment:value=>{assessmentFence=value;}});
  const result=await f.runner.run(input({personaSession}));
  assert.equal(result.objectiveCredit,false);
  assert.deepEqual(captured.personaSession,personaSession);
  assert.equal(assessmentFence,fence);
  assert.equal(f.calls.completionFence,fence);
  assert.equal(f.calls.jobFence,fence);
  assert.ok(checks>=3);
});

test('revoked persona fence rejects before audit job and journal claim',async()=>{
  const error=Object.assign(new Error('revoked'),{code:'SHOP_AUTH_REVOKED'});
  const f=fixture({capturePersonaAuthority:async()=>({binding:{...scope,personaId:3,role:'admin'},async assertRemoteAdmission(){throw error;}})});
  await assert.rejects(f.runner.run(input({personaSession:{sessionId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',authorityVersion:'4'}})),{code:'SHOP_AUTH_REVOKED'});
  assert.equal(f.calls.claim,0);assert.equal(f.calls.job,0);assert.equal(f.calls.complete,0);
});

test('persona revocation after held admission prevents job execution',async()=>{
  let checks=0;
  const f=fixture({capturePersonaAuthority:async()=>({binding:{...scope,personaId:3,role:'admin'},
    async assertRemoteAdmission(){if(++checks===3)throw Object.assign(new Error('revoked'),{code:'SHOP_AUTH_REVOKED'});}})});
  await assert.rejects(f.runner.run(input({personaSession:{sessionId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',authorityVersion:'4'}})),{code:'SHOP_AUTH_REVOKED'});
  assert.equal(f.calls.claim,1);assert.equal(f.calls.job,0);assert.equal(f.calls.complete,0);
});

test('exact replay is rechecked against current persona authority before projection',async()=>{
  let run=0;
  const f=fixture({capturePersonaAuthority:async()=>{run++;let checks=0;return{binding:{...scope,personaId:3,role:'admin'},
    async assertRemoteAdmission(){checks++;if(run===2&&checks===4)throw Object.assign(new Error('revoked'),{code:'SHOP_AUTH_REVOKED'});}};}});
  const value=input({personaSession:{sessionId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',authorityVersion:'4'}});
  await f.runner.run(value);
  await assert.rejects(f.runner.run(value),{code:'SHOP_AUTH_REVOKED'});
  assert.equal(f.calls.job,1);assert.equal(f.calls.complete,1);
});

test('fixed audit admission rejects excessive counts before job and original provenance survives mode flip replay',async()=>{
 const {captureFeatureMode,guardFeatureFence}=require('../server/services/secureshopFeatureModeAuthority');let mode='fixed';
 const f=fixture({capturePersonaAuthority:async()=>guardFeatureFence({async assertRemoteAdmission(){}},await captureFeatureMode(null,scope,'audit_summary',mode))});
 await assert.rejects(f.runner.run(input({requestedCount:101})),{code:'AUDIT_FIXED_COUNT_LIMIT'});assert.equal(f.calls.job,0);assert.equal(f.calls.claim,0);
 const first=await f.runner.run(input());assert.equal(first.modeCapability.effectiveMode,'fixed');mode='vuln';const replay=await f.runner.run(input());assert.equal(replay.replayed,true);assert.deepEqual(replay.modeCapability,first.modeCapability);assert.equal(f.calls.job,1);
});

test('audit mode stamp change before queued work prevents execution and publication',async()=>{
 const {createFeatureModeAuthority,guardFeatureFence}=require('../server/services/secureshopFeatureModeAuthority');let stamp='one',checks=0;
 const authority=createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode:'fixed',modeStamp:stamp,generation:0})},launches:{assertCurrent:async()=>{}}});
 const f=fixture({capturePersonaAuthority:async()=>guardFeatureFence({async assertRemoteAdmission(){if(++checks===2)stamp='two';}},await authority.capture(scope,'audit_summary'))});
 await assert.rejects(f.runner.run(input()),{code:'ANALYTICS_MODE_STALE'});assert.equal(f.calls.job,0);assert.equal(f.calls.complete,0);
});

test('mode change while audit worker runs prevents completed result publication',async()=>{
 const {createFeatureModeAuthority,guardFeatureFence}=require('../server/services/secureshopFeatureModeAuthority');let stamp='one';
 const authority=createFeatureModeAuthority({progress:{getEvaluationScope:async()=>({mode:'fixed',modeStamp:stamp,generation:0})},launches:{assertCurrent:async()=>{}}});
 const f=fixture({onJob:async()=>{stamp='two';},capturePersonaAuthority:async()=>guardFeatureFence({async assertRemoteAdmission(){}},await authority.capture(scope,'audit_summary'))});
 await assert.rejects(f.runner.run(input()),{code:'ANALYTICS_MODE_STALE'});assert.equal(f.calls.job,1);assert.equal(f.calls.complete,0);assert.equal(f.calls.uncertain,1);
});


test('separate unbounded constructor purpose stays exact through execution and replay',async()=>{
 const f=fixture({conversationPurpose:PURPOSES.auditUnbounded});
 const input={sessionId:id,requestId,scope,persona:admin,requestedCount:200};
 await f.runner.run(input);await f.runner.run({...input,assessmentVariant:'instruction',objectiveId:'ss_audit_instruction_followed'});
 assert.equal(f.calls.job,1);assert.ok(f.purposes.length>0);assert.ok(f.purposes.every(value=>value===PURPOSES.auditUnbounded));
 assert.throws(()=>fixture({conversationPurpose:'general'}),/conversation purpose/);
});
