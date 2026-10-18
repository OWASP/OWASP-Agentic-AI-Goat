'use strict';

// Controlled stores exercise the real assessment and canonical completion
// machinery. No executor, browser, database or configured model is started.
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { fixture: sourceFixture } = require('./secureshopMailAgentReadEvidence.test');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createLaunchScope } = require('../server/services/secureshopConversationBinding');
const { createTurnRequest } = require('../server/services/secureshopTurnRequest');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const implementation = require('../server/services/secureshopMailAgentReadAssessment');
const OBJECTIVE = 'ss_mail_agent_cross_persona_read';
const hash = value => createHash('sha256').update(value).digest('hex');

function fixture({ original: suppliedOriginal, readSource: protectedReader } = {}) {
  const original = suppliedOriginal || sourceFixture(), a = original.input;
  const scope = createLaunchScope(a.binding), persona = { id: a.binding.shopUserId, role: 'merchant' };
  const session = { ...a.personaSession };
  const source = original.raw;
  const envelope = JSON.parse(source.envelope);
  const scene = createSceneBinding({ ...scope, targetId: envelope.targetId }, {
    sceneId: envelope.sceneId, sceneGeneration: envelope.sceneGeneration, grantId: randomUUID(),
    execution: scope, withLease: work => work(),
  });
  const assessmentSession = randomUUID(), assessmentRun = randomUUID();
  const owner = JSON.stringify(['SecureShopBoundConversation', assessmentSession]);
  const publication = { mode: 'vuln', generation: 1, modeStamp: 'a'.repeat(64) };
  const adminMode = a.assistantExecution;
  let currentScene = scene, enabled = true, active = true, sourceError = null;
  let journalRow = null, canonicalRow = null, packet = null, onJudge = () => {}, afterAdmission = () => {}, completeError = null, judgePass = false;
  const calls = { source: 0, judge: 0, claim: 0, complete: 0, verdict: 0, acquire: 0, effects: 0, uncertain: 0 };
  const check = async () => { if (!active) throw Object.assign(Error('revoked'), { code: 'SHOP_AUTH_INVALID' }); };
  const identityPool = { async query(sql, params) {
    if (sql.includes('identity.secureshop_authority_owners')) return { rows: [{ realm: 'platform', shop_tenant_id: null }] };
    if (sql.includes('workshop_platform.objectives')) return { rows: enabled ? [{ objective_id: OBJECTIVE }] : [] };
    if (sql.includes('FROM secureshop_auth.execution_authority_state')) {
      if (sql.includes('j.run_id=$5')) {
        assert.match(sql, /NOT EXISTS[\s\S]*retry\.child_id=j\.evaluation_id/);
        assert.match(sql, /current_tenant_id[\s\S]*current_principal_id[\s\S]*current_membership_version[\s\S]*live_owner_generation/);
        assert.deepEqual(params, [scope.platformSessionId, scope.platformOwnerId, persona.id,
          OBJECTIVE, canonicalRow.run_id, canonicalRow.owner_key, canonicalRow.packet, canonicalRow.evidence_digest]);
      }
      return { rows: canonicalRow ? [canonicalRow] : [] };
    }
    throw Error('Unexpected controlled identity query: ' + sql);
  } };
  const journal = {
    async claim(input) {
      calls.claim++;
      if (journalRow) return { status: journalRow.status, result: journalRow.result_json, claimId: 'controlled-claim' };
      const request = createTurnRequest(input);
      journalRow = { session_id: input.sessionId, request_id: input.requestId,
        request_hash: request.hash, request_version: request.version, status: 'started', result_json: null };
      return { status: 'claimed', claimId: 'controlled-claim' };
    },
    async complete(input) {
      await check(); if (completeError) throw completeError;
      calls.complete++; journalRow.status = 'completed'; journalRow.result_json = structuredClone(input.result);
    },
    async markUncertain() { calls.uncertain++; if (journalRow?.status !== 'completed') journalRow.status = 'uncertain'; },
  };
  const conversationRepository = {
    async getBoundSession(id) {
      return id === assessmentSession ? { id, state: 'active', purpose: 'persona_inbox', binding: a.binding }
        : id === a.sessionId ? { id, state: 'active', purpose: 'secureshop_merchant_assistant', binding: a.binding } : null;
    },
    async acquireBoundSession() { calls.acquire++; return { id: assessmentSession, state: 'active' }; },
  };
  const tenantId = randomUUID(), principalId = randomUUID();
  const service = implementation.createMailAgentReadAssessment({ identityPool,
    agentsPool: { async query(sql) {
      assert.match(sql, /secureshop_agents\.turn_requests/);
      return { rows: journalRow ? [journalRow] : [] };
    } }, launches: { assertCurrent: check }, conversationRepository, journal,
    coordinator: { async run(_id, options, work) {
      const admitted = await options.admit(); if (admitted.skip) return admitted.value;
      await afterAdmission();
      return work({ runId: assessmentRun, ownerKey: owner, durableGeneration: '0', check,
        async effectWithReceipt() { calls.effects++; throw Error('Assessment cannot execute diagnostic'); } });
    } },
    personaAuthority: { capture: input => ({ binding: { ...createLaunchScope(input.scope),
      personaId: input.personaId, role: input.role, sessionId: input.sessionId,
      authorityVersion: input.authorityVersion }, assertRemoteAdmission: check }) },
    personaBindings: { capture: async () => ({ controlled: true }) },
    scenes: { readRetained: async () => currentScene },
    modeAuthority: { async capture(_scope, feature) {
      const current = () => feature === 'mail' ? a.mailExecution : adminMode;
      const snapshot = structuredClone(current());
      return { snapshot, async assertCurrent() { await check(); assert.deepEqual(current(), snapshot); } };
    }, assertToken: value => value },
    publicationModes: { getEvaluationScope: async () => publication },
    progress: { getGeneration: async () => publication.generation, getEvaluationScope: async () => publication },
    receipts: {
      async beginEvaluation(input) {
        const rubric = JSON.parse(input.recovery.packet).rubric;
        canonicalRow = { tenant_id: tenantId, principal_id: principalId, evaluation_id: input.evaluationId,
          shop_user_id: persona.id, workshop_key: 'secureshop_agent_security', objective_id: OBJECTIVE,
          family: rubric.family, scenario: rubric.scenario, rubric_version: rubric.version,
          mode: publication.mode, generation: publication.generation, mode_stamp: publication.modeStamp,
          owner_key: owner, owner_generation: '0', live_owner_generation: '0',
          current_tenant_id: tenantId, current_principal_id: principalId, current_membership_version: '1',
          run_id: assessmentRun, execution_json: { tenantId, principalId, membershipVersion: '1', scope,
            personaSessionId: session.sessionId, personaAuthorityVersion: session.authorityVersion,
            role: 'merchant', runId: assessmentRun }, packet: input.recovery.packet,
          evidence_digest: hash(input.recovery.packet), child_id: null };
        return { verdict: null };
      },
      async recordVerdict({ result }) {
        calls.verdict++; const serialized = JSON.stringify(result);
        Object.assign(canonicalRow, { verdict: result.verdict, disposition: 'not_pass',
          result_json: result, result_serialized: serialized, result_digest: hash(serialized) });
        return { verdict: result.verdict, disposition: 'not_pass', result };
      },
    },
    qualifyModel: a.qualifyModel,
    async readSource(input) {
      calls.source++; await check();
      assert.equal(input.sessionId, a.sessionId); assert.equal(input.requestId, a.requestId);
      assert.equal(input.proposalId, undefined);
      if (sourceError) throw sourceError;
      return protectedReader ? protectedReader(input) : structuredClone(source);
    },
    async judge(input) {
      calls.judge++; packet = prepareJudgeInput(input).packet; await onJudge();
      if (judgePass) return { verdict: 'pass', explanation: 'Controlled positive verdict is not registered model provenance',
        criteria: [{ id: 'foreign_body_observed', satisfied: true,
          evidenceRefs: ['mail_agent_read'],
          citations: [{ evidenceId: 'mail_agent_read', quote: input.evidence[0].content.observation.observedBodyExcerpt }] }] };
      return { verdict: 'fail', explanation: 'Controlled negative Judge; no credit', criteria: [] };
    },
  });
  const input = { scope, persona, personaSession: session, sessionId: a.sessionId,
    requestId: a.requestId };
  return { service, input, source, original, calls, publication,
    get journalRow() { return journalRow; }, get canonicalRow() { return canonicalRow; }, get packet() { return packet; },
    revoke() { active = false; }, disable() { enabled = false; },
    setScene(value) { currentScene = value; }, sourceError(error) { sourceError = error; },
    onJudge(fn) { onJudge = fn; }, afterAdmission(fn) { afterAdmission = fn; }, onCompleteError(error) { completeError = error; },
    controlledPositiveJudge() { judgePass = true; } };
}

module.exports = { fixture };
if (require.main === module) {
test('V11 assessment and GET recovery never dispatch diagnostics or regrade terminal evidence', async () => {
  const f = fixture();
  assert.deepEqual(await f.service.readOutcome(f.input), { completed: false, status: 'unconfirmed', modelEvaluated: false });
  const result = await f.service.runAttempt(f.input);
  assert.equal(result.completed, false); assert.equal(result.judgment.verdict, 'fail');
  assert.equal(f.calls.judge, 1); assert.equal(f.calls.verdict, 1); assert.equal(f.calls.effects, 0);
  assert.deepEqual(await f.service.readOutcome(f.input), { ...result, replayed: true });
  assert.deepEqual(await f.service.runAttempt(f.input), { ...result, replayed: true });
  assert.equal(f.calls.judge, 1); assert.equal(f.calls.complete, 1); assert.equal(f.calls.effects, 0);
});

test('V11 fixed, disabled and unconfirmed source cannot claim a grading turn', async () => {
  for (const change of [f => { f.original.input.mailExecution.mode = 'fixed'; },
    f => { f.publication.mode = 'fixed'; }, f => f.disable(),
    f => { f.source.mail.message.bodyMarkdown = ''; f.source.mail.message.bodyHtml = ''; }]) {
    const f = fixture(); change(f);
    assert.deepEqual(await f.service.runAttempt(f.input), { completed: false, status: 'ineligible', modelEvaluated: false });
    assert.equal(f.calls.judge, 0); assert.equal(f.calls.claim, 0); assert.equal(f.calls.effects, 0);
  }
});

test('V11 original source read outage propagates before admission and permits an explicit retry', async () => {
  const f = fixture(); f.sourceError(Object.assign(Error('database offline'), { code: '57P01' }));
  await assert.rejects(f.service.runAttempt(f.input), { code: '57P01' });
  assert.equal(f.calls.claim, 0); assert.equal(f.calls.judge, 0);
  f.sourceError(null); const result = await f.service.runAttempt(f.input);
  assert.equal(result.completed, false); assert.equal(f.calls.judge, 1); assert.equal(f.calls.effects, 0);
});

test('V11 foreign owner and session cannot read original evidence or admit assessment', async () => {
  for (const mutate of [f => { f.input.scope = { ...f.input.scope, platformOwnerId: 999 }; },
    f => { f.input.sessionId = randomUUID(); }, f => { f.input.persona.role = 'customer'; }]) {
    const f = fixture(); mutate(f);
    await assert.rejects(f.service.runAttempt(f.input));
    await assert.rejects(f.service.readOutcome(f.input));
    assert.equal(f.calls.source, 0); assert.equal(f.calls.claim, 0); assert.equal(f.calls.judge, 0);
  }
});

test('V11 revocation, scene reset, source change and disable during Judge block verdict publication', async () => {
  for (const change of [f => f.revoke(), f => f.setScene(null), f => f.disable(),
    f => { f.source.turn.result_json.text = 'changed original response'; f.source.traces[3].result_json = JSON.stringify({...JSON.parse(f.source.traces[3].result_json),text:'changed original response'}); },
    f => { f.source.mail.receiptSha256 = 'b'.repeat(64); },
    f => { f.original.input.mailExecution.modeStamp = 'changed'; },
    f => { f.publication.modeStamp = 'changed'; }]) {
    const f = fixture(); f.onJudge(() => change(f));
    await assert.rejects(f.service.runAttempt(f.input));
    assert.equal(f.calls.judge, 1); assert.equal(f.calls.verdict, 0); assert.equal(f.calls.complete, 0);
    assert.equal(f.calls.effects, 0);
  }
});

test('V11 mismatched original scene denies before grading', async()=>{
 const f=fixture(); const envelope=JSON.parse(f.source.envelope);envelope.targetId=randomUUID();f.source.envelope=JSON.stringify(envelope);
 await assert.rejects(f.service.runAttempt(f.input));assert.equal(f.calls.claim,0);assert.equal(f.calls.judge,0);
});

test('V11 controlled positive Judge response cannot establish genuine grading provenance or credit', async () => {
  const f = fixture(); f.controlledPositiveJudge();
  const result = await f.service.runAttempt(f.input);
  assert.equal(f.calls.judge, 1);
  assert.equal(result.judgment.verdict, 'pass');
  assert.equal(result.completed, false, 'a coherent positive test double is not the configured canonical Judge');
  assert.equal(f.calls.effects, 0);
});

test('V11 saved canonical packet, session, run, mode and result tampering fail without new work', async () => {
  for (const change of [r => { r.execution_json.personaSessionId = randomUUID(); },
    r => { r.run_id = randomUUID(); }, r => { r.packet += ' '; },
    r => { r.mode_stamp = 'changed'; }, r => { r.rubric_version = 'unknown'; },
    r => { r.result_digest = '0'.repeat(64); }]) {
    const f = fixture(); await f.service.runAttempt(f.input); change(f.canonicalRow);
    await assert.rejects(f.service.readOutcome(f.input));
    assert.equal(f.calls.judge, 1); assert.equal(f.calls.complete, 1); assert.equal(f.calls.effects, 0);
  }
});

test('V11 historical v1 and v2 judgments remain immutable and cannot retry, recover or mint under v3', async () => {
  for (const version of ['secureshop-mail-agent-disclosure-v1','secureshop-mail-agent-disclosure-v2']) {
    const f = fixture(); const original = await f.service.runAttempt(f.input);
    const saved = structuredClone(f.canonicalRow); f.canonicalRow.rubric_version = version;
    const before = structuredClone(f.calls);
    await assert.rejects(f.service.readOutcome(f.input));
    await assert.rejects(f.service.runAttempt(f.input));
    assert.deepEqual({judge:f.calls.judge,verdict:f.calls.verdict,complete:f.calls.complete,effects:f.calls.effects},
      {judge:before.judge,verdict:before.verdict,complete:before.complete,effects:before.effects});
    assert.deepEqual(f.canonicalRow, {...saved,rubric_version:version});
    assert.equal(original.completed,false);
  }
});

test('V11 uncertain assessment journal publication cannot automatically replay Judge or source effect', async () => {
  const f = fixture(); f.onCompleteError(Error('controlled lost journal acknowledgement'));
  await assert.rejects(f.service.runAttempt(f.input));
  assert.equal(f.journalRow.status, 'uncertain');
  await assert.rejects(f.service.runAttempt(f.input), { code: 'TURN_RECOVERY_REQUIRED' });
  assert.equal(f.calls.judge, 1); assert.equal(f.calls.effects, 0);
});

test('V11 retained canonical parent survives uncertain journal while returned guard rejects source or grant drift', async () => {
  for (const mutate of [f => { f.source.turn.result_json.text = 'changed original response'; f.source.traces[3].result_json = JSON.stringify({...JSON.parse(f.source.traces[3].result_json),text:'changed original response'}); },
    f => { f.source.mail.receiptSha256 = 'b'.repeat(64); }]) {
    const f = fixture();
    f.onCompleteError(Error('controlled lost journal acknowledgement'));
    await assert.rejects(f.service.runAttempt(f.input));
    assert.equal(f.journalRow.status, 'uncertain');
    assert.equal(f.canonicalRow.packet, f.packet, 'the original canonical parent remains persisted');
    const guard = await f.service.assertRetainedPacket({ ...f.input, packet: f.packet });
    await guard.assertCurrent();
    const before = { judge: f.calls.judge, effects: f.calls.effects,
      claim: f.calls.claim, complete: f.calls.complete, verdict: f.calls.verdict };
    assert.deepEqual(before, { judge: 1, effects: 0, claim: 1, complete: 0, verdict: 1 });
    mutate(f);
    await assert.rejects(guard.assertCurrent());
    assert.deepEqual({ judge: f.calls.judge, effects: f.calls.effects,
      claim: f.calls.claim, complete: f.calls.complete, verdict: f.calls.verdict }, before);
    assert.equal(f.journalRow.status, 'uncertain');
  }
});


test('V11 eligibility revoked after admission preserves the closed ineligible result without Judge work', async () => {
  const f = fixture(); f.afterAdmission(() => f.disable());
  assert.deepEqual(await f.service.runAttempt(f.input), { completed: false, status: 'ineligible', modelEvaluated: false });
  assert.equal(f.calls.claim, 1); assert.equal(f.calls.judge, 0);
  assert.equal(f.calls.verdict, 0); assert.equal(f.calls.effects, 0);
});
}
if(require.main===module){
 test('V11 exact valid source over canonical packet cap returns unavailable without claiming or asking Judge',async()=>{
  const f=fixture(),raw=f.source;
  raw.mail.message.bodyMarkdown='x'.repeat(8000);raw.mail.message.bodyHtml='';raw.mail.message.headersRaw='';raw.mail.message.sourceBytes=8000;
  const observation={content:[{type:'text',text:JSON.stringify({mail:raw.mail,origin:raw.origin})}]};
  raw.traces[2].result_json=JSON.stringify(observation);
  raw.traces[3].result_json=JSON.stringify({...JSON.parse(raw.traces[3].result_json),text:'y'.repeat(16000)});
  const expected={completed:false,status:'unavailable',modelEvaluated:false,reason:'evidence_size_limit'};
  assert.deepEqual(await f.service.runAttempt(f.input),expected);
  assert.deepEqual(await f.service.readOutcome(f.input),expected);
  assert.equal(f.calls.claim,0);assert.equal(f.calls.judge,0);assert.equal(f.calls.effects,0);
 });
 test('V11 qualified catalog identity stays distinct, disabled by default and has bounded hints/solutions',()=>{
  const c=require('../server/config/secureshopCurriculum');
  const row=c.OBJECTIVES.find(r=>r.id===OBJECTIVE);assert.equal(row.qualification,'native-browser-judge');assert.equal(row.defaultEnabled,false);
  assert.ok(c.EXERCISES.find(r=>r.id==='ss_mail').objectiveIds.includes(OBJECTIVE));
  assert.notEqual(c.OBJECTIVES.find(r=>r.id==='ss_mail_cross_persona_read').qualification,'pending');
  assert.ok(c.HINTS[OBJECTIVE].hints.length>0);
  assert.match(c.SOLUTIONS[OBJECTIVE].examples[0].action,/saved original detail turn/);
  assert.match(c.SOLUTIONS[OBJECTIVE].examples[0].explanation,/canonical Judge acceptance/);
  assert.match(c.SOLUTIONS[OBJECTIVE].examples[0].explanation,/Saved GET recovery never repeats the source turn/);
 });
}
if(require.main===module){
 test('V11 original mail and assistant epochs reject a Vulnerable→Fixed→Vulnerable cycle before first assessment',async()=>{
  for(const feature of ['mailExecution','assistantExecution']){
   const f=fixture();
   const current=feature==='mailExecution'?f.original.input.mailExecution:f.original.input.assistantExecution;
   current.mode='fixed';current.generation++;current.modeStamp='b'.repeat(64);
   current.mode='vuln';current.generation++;current.modeStamp='c'.repeat(64);
   await assert.rejects(f.service.runAttempt(f.input),{code:'MAIL_AGENT_READ_EVIDENCE_UNAVAILABLE'});
   await assert.rejects(f.service.readOutcome(f.input),{code:'MAIL_AGENT_READ_EVIDENCE_UNAVAILABLE'});
   assert.equal(f.calls.claim,0);assert.equal(f.calls.judge,0);assert.equal(f.calls.effects,0);
  }
 });
 test('V11 historical detail lacking original mode epochs cannot acquire current epochs for grading',async()=>{
  const f=fixture();delete f.source.turn.result_json.taskMetadata.roleChat.mailReadExecution;
  await assert.rejects(f.service.runAttempt(f.input),{code:'MAIL_AGENT_READ_EVIDENCE_UNAVAILABLE'});
  assert.equal(f.calls.claim,0);assert.equal(f.calls.judge,0);
 });
}
