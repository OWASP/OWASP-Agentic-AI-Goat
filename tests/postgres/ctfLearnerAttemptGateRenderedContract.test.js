'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const facet = require('./support/ctfLearnerAttemptGateRenderedCases');

test('click failure can retire an already-started response waiter without an unhandled rejection', async () => {
  const owned = facet.createBrowserWorkTracker();
  const waiter = owned.track(() => new Promise((_, reject) => {
    owned.signal.addEventListener('abort', () => reject(owned.signal.reason), { once: true });
  }));
  // The physical click fails before its caller can await waiter.
  owned.abortWaiters();
  await assert.rejects(owned.drain(), /asynchronous work failed/);
  assert.equal(owned.pendingCount(), 0);
  await assert.rejects(waiter, /waiter retired/);
});

test('interception and response-read failures are observed immediately and retained at retirement', async () => {
  const owned = facet.createBrowserWorkTracker();
  owned.track(() => { throw new Error('synchronous interception failure'); });
  owned.track(() => Promise.reject(new Error('request closed during retirement')));
  await new Promise(resolve => setImmediate(resolve));
  await assert.rejects(owned.drain(), error => error instanceof AggregateError && error.errors.length === 2);
  assert.equal(owned.pendingCount(), 0);
});

test('browser work retirement joins completion and never claims absence for an unsettled waiter', async () => {
  const owned = facet.createBrowserWorkTracker();
  let settle;
  owned.track(() => new Promise(resolve => { settle = resolve; }));
  await assert.rejects(owned.drain(5), /did not settle/);
  assert.equal(owned.pendingCount(), 1);
  settle();
  await owned.drain();
  assert.equal(owned.pendingCount(), 0);
});

const uuid = n => `${String(n).padStart(8, '0')}-1111-4111-8111-111111111111`;
function receipt() {
  return { version: 1, profile: facet.PROFILE, transport: 'controlled-synthetic',
    actorId: '2402', sessionId: '9', participantId: '2402', stageId: 1,
    siblingOwnerId: 1001,
    gate: { configured: 3, initialAttempts: 0, initialHintVisible: false,
      deniedStatus: 409,
      deniedError: 'Hint availability changed; refresh stage status',
      deniedOutboxDelta: 0, deniedProgressUnchanged: true,
      deniedProviderCalls: 0,
      afterAttempts: [1, 2, 3].map(count => ({ count,
        hintVisible: count === 3, status: 'in_progress' })),
      afterThirdHintVisible: true },
    attempts: [1, 2, 3].map(ordinal => ({ ordinal,
      runId: uuid(ordinal), admissionId: uuid(ordinal + 3),
      decisionId: uuid(ordinal + 6), requestStatus: 202,
      publicationStatus: 200, verdict: 'fail', accepted: false,
      guardianCalls: 1, judgeCalls: 1, sameIdGets: 2,
      recoveryResumePosts: 0, recoveryAuthorizePosts: 0,
      ownerSessionBound: true, decisionApplied: true,
      publicationCurrent: true, noProviderReplay: true })),
    browserPosts: { register: 1, start: 1, attempt: 3, hint: 0,
      resume: 0, authorize: 0 },
    serverPosts: { register: 1, start: 1, attempt: 3, hint: 1,
      resume: 0, authorize: 0 },
    lifecycle: { register: { operationId: uuid(10), sequence: '1', originalStatus: 200 },
      start: { operationId: uuid(11), sequence: '2', originalStatus: 202 } },
    reset: { operationId: uuid(12), sequence: '9', originalStatus: 200,
      deniedStatus: 409, deniedError: 'CTF request is no longer current',
      generationBefore: '1', generationAfter: '2' },
    providerCalls: { guardian: 3, judge: 3, total: 6 },
    storeWitness: Object.fromEntries([
      'progressAttemptsThree', 'threeAttemptRows', 'threeJudgmentRows',
      'noCompletion', 'noHintPurchased', 'identityBindingCurrent',
      'siblingBeforeNonempty', 'siblingUnchanged', 'resetReferenceFenced',
      'historicalEvidenceRetained'].map(key => [key, true])),
    facts: Object.fromEntries(facet.FACTS.map(key => [key, true])),
    excluded: [...facet.EXCLUDED], unexpectedApiPaths: [],
    browserActions: 48, apiRequests: 70, genuineCredit: 0,
    stage: 'complete' };
}
const tamper = change => { const value = receipt(); change(value);
  assert.throws(() => facet.assertControlledReceipt(value)); };

test('default three-attempt gate and three scored submissions are exact controlled evidence', () => {
  assert.equal(facet.assertControlledReceipt(receipt()), true);
  assert.equal(facet.POST_PATHS.attempt, '/api/ctf/stage/1/attempt');
  assert(facet.EXCLUDED.includes('actual-model-qualification'));
  assert.equal(facet.LIMITS.guardianCalls, 3);
  assert.equal(facet.LIMITS.judgeCalls, 6);
});

test('receipt rejects weak gate, transport, count, recovery and credit claims', () => {
  tamper(r => { r.transport = 'actual-model'; });
  tamper(r => { r.gate.configured = 0; });
  tamper(r => { r.gate.deniedStatus = 503; });
  tamper(r => { r.gate.afterAttempts[1].hintVisible = true; });
  tamper(r => { r.gate.afterAttempts[2].count = 2; });
  tamper(r => { r.browserPosts.attempt = 2; });
  tamper(r => { r.serverPosts.hint = 0; });
  tamper(r => { r.lifecycle.start.operationId = r.lifecycle.register.operationId; });
  tamper(r => { r.lifecycle.start.sequence = '1'; });
  tamper(r => { r.reset.deniedStatus = 503; });
  tamper(r => { r.reset.deniedError = 'Authentication required'; });
  tamper(r => { r.reset.generationAfter = '1'; });
  tamper(r => { r.reset.sequence = '2'; });
  tamper(r => { r.attempts[2].runId = r.attempts[0].runId; });
  tamper(r => { r.attempts[1].accepted = true; });
  tamper(r => { r.attempts[0].publicationCurrent = false; });
  tamper(r => { r.attempts[0].sameIdGets = 33; });
  tamper(r => { r.providerCalls.judge = 7; });
  tamper(r => { r.storeWitness.siblingBeforeNonempty = false; });
  tamper(r => { r.actorId = '1002'; });
  tamper(r => { r.participantId = '1001'; });
  tamper(r => { r.genuineCredit = 1; });
  tamper(r => { r.extra = true; });
});

test('retirement replays final browser, server, API and provider counters', () => {
  const value = receipt();
  assert.equal(facet.assertRetiredCounts(value, value.browserPosts,
    value.serverPosts, value.apiRequests, value.providerCalls, []), true);
  assert.throws(() => facet.assertRetiredCounts(value,
    { ...value.browserPosts, attempt: 4 }, value.serverPosts,
    value.apiRequests, value.providerCalls, []));
  assert.throws(() => facet.assertRetiredCounts(value, value.browserPosts,
    { ...value.serverPosts, start: 2 }, value.apiRequests,
    value.providerCalls, []));
  assert.throws(() => facet.assertRetiredCounts(value, value.browserPosts,
    value.serverPosts, value.apiRequests + 1, value.providerCalls, []));
  assert.throws(() => facet.assertRetiredCounts(value, value.browserPosts,
    value.serverPosts, value.apiRequests,
    { ...value.providerCalls, total: value.providerCalls.total + 1 }, []));
});

test('early pending 202 resolves only through the observed same-run browser chain', () => {
  const runId = uuid(21), admissionId = uuid(22), decisionId = uuid(23);
  const pending = { success: false, pending: true, runId,
    operationId: admissionId, admissionId: null, decisionId: null };
  const events = [
    { path: `/api/ctf/predefense/${runId}`, status: 200,
      body: { version: 1, state: 'proposal_staged', runId,
        admissionId, blockedOperationId: uuid(24), decisionId: null,
        currentCompletion: false } },
    { path: `/api/ctf/decisions/${admissionId}`, status: 200,
      body: { state: 'historical_receipt', admissionId, decisionId,
        currentCompletion: false } },
    { path: `/api/ctf/publications/${decisionId}`, status: 200,
      body: { success: false } },
  ];
  assert.deepEqual(facet.assertObservedAttemptRecovery(pending, events),
    { runId, admissionId, decisionId, publicationStatus: 200, sameIdGets: 1,
      recoveryResumePosts: 0, recoveryAuthorizePosts: 0 });
  const changed = mutate => { const copy = structuredClone(events); mutate(copy);
    assert.throws(() => facet.assertObservedAttemptRecovery(pending, copy)); };
  changed(rows => { rows[0].body.runId = uuid(25); });
  changed(rows => { rows[1].body.admissionId = uuid(25); });
  changed(rows => { rows[1].body.decisionId = uuid(25); });
  changed(rows => { rows[2].status = 503; });
  assert.throws(() => facet.assertObservedAttemptRecovery(pending,
    events.slice(1)), 'No skipped predefense binding');
  assert.throws(() => facet.assertObservedAttemptRecovery(pending,
    events.slice(0, 2)), 'No promotion without browser publication');
});

test('initial same-run decision may publish directly without inventing a predefense read', () => {
  const runId=uuid(41),decisionId=uuid(42),foreign=uuid(43);
  const pending={success:false,pending:true,runId,operationId:null,
    admissionId:null,decisionId};
  const current=[{path:`/api/ctf/publications/${decisionId}`,status:200,
    body:{success:false}}];
  assert.deepEqual(facet.assertObservedAttemptRecovery(pending,current),{
    runId,admissionId:null,decisionId,publicationStatus:200,sameIdGets:1,
    recoveryResumePosts:0,recoveryAuthorizePosts:0,
  });
  assert.throws(()=>facet.assertObservedAttemptRecovery(pending,[]));
  assert.throws(()=>facet.assertObservedAttemptRecovery(pending,[{
    ...current[0],path:`/api/ctf/publications/${foreign}`,
  }]));
  assert.throws(()=>facet.assertObservedAttemptRecovery(pending,[
    {path:`/api/ctf/predefense/${runId}`,status:202,
      body:{version:1,state:'recovery_pending',runId,currentCompletion:false}},
    ...current,
  ]), 'A direct decision cannot borrow an unneeded alternate recovery path');
  assert.throws(()=>facet.assertObservedAttemptRecovery(pending,[
    {path:`/api/ctf/decisions/${foreign}/authorize`,status:202,body:{}},
    ...current,
  ]));
});

test('failure-only recovery trail records bounded validated opaque refs and path/status, never bodies', () => {
  const runId=uuid(51),decisionId=uuid(52);
  const trail=facet.boundedRecoveryFailureTrail(1,{runId,admissionId:null,decisionId,
    bearer:'Bearer must-not-persist'},[{path:`/api/ctf/publications/${decisionId}`,
    status:503,body:{secret:'must-not-persist'}},
  {path:'/api/ctf/publications/foreign?token=must-not-persist',status:false,
    body:'must-not-persist'}]);
  assert.deepEqual(trail,{version:1,profile:facet.PROFILE,
    stage:'attempt-recovery-incomplete',ordinal:1,
    initial:{runId,admissionId:null,decisionId},observed:[
      {path:`/api/ctf/publications/${decisionId}`,status:503},
      {path:null,status:null},
    ]});
  assert.equal(JSON.stringify(trail).includes('must-not-persist'),false);
  assert.equal(facet.boundedRecoveryFailureTrail(1,{runId},Array.from({length:100},
    ()=>({path:`/api/ctf/predefense/${runId}`,status:202}))).observed.length,84);
});

test('direct decision derives its unobserved admission only from exact durable owner/run/decision joins', () => {
  const runId=uuid(61),decisionId=uuid(62),admissionId=uuid(63),proposalId=uuid(64);
  const fixture={pending:{runId,admissionId:null,decisionId},
    settled:{runId,admissionId:null,decisionId},
    proposal:{proposal_id:proposalId,run_id:runId,
      admission_operation_id:admissionId,owner_id:'2402',session_id:'17'},
    admission:{operation_id:admissionId,owner_id:'2402',
      participant_id:'3011',stage_id:'1'},
    decision:{decision_id:decisionId,proposal_id:proposalId,run_id:runId,
      owner_id:'2402',session_id:'17'},
    locator:{run_id:runId,owner_id:'2402',session_id:'17'},
    ownerId:'2402',sessionId:'17',participantId:'3011'};
  assert.equal(facet.assertDirectDecisionDurableBinding(fixture),admissionId);
  for(const mutate of [
    value=>{value.proposal.owner_id='1001';},
    value=>{value.proposal.run_id=uuid(65);},
    value=>{value.decision.decision_id=uuid(65);},
    value=>{value.decision.run_id=uuid(65);},
    value=>{value.decision.proposal_id=uuid(65);},
    value=>{value.locator.session_id='18';},
    value=>{value.admission.stage_id='2';},
  ]) { const wrong=structuredClone(fixture);mutate(wrong);
    assert.throws(()=>facet.assertDirectDecisionDurableBinding(wrong)); }
});

test('browser recovery mutations are at most once, same-reference, same bearer and empty body', () => {
  const runId = uuid(31), admissionId = uuid(32), decisionId = uuid(33);
  const pending = { success: false, pending: true, runId,
    operationId: admissionId, admissionId: null, decisionId: null };
  const events = [
    { path: `/api/ctf/predefense/${runId}`, status: 200,
      body: { version: 1, state: 'admission_pending', runId,
        admissionId, blockedOperationId: uuid(34), decisionId: null,
        currentCompletion: false } },
    { path: `/api/ctf/predefense/${runId}/resume`, status: 202, body: {} },
    { path: `/api/ctf/decisions/${admissionId}`, status: 200,
      body: { state: 'proposal_staged', admissionId } },
    { path: `/api/ctf/decisions/${admissionId}/authorize`, status: 200, body: {} },
    { path: `/api/ctf/decisions/${admissionId}`, status: 200,
      body: { state: 'historical_receipt', admissionId, decisionId } },
    { path: `/api/ctf/publications/${decisionId}`, status: 200, body: {} },
  ];
  const settled = facet.assertObservedAttemptRecovery(pending, events);
  assert.equal(settled.recoveryResumePosts, 1);
  assert.equal(settled.recoveryAuthorizePosts, 1);
  const bearer = 'Bearer controlled-test-token';
  const rows = { resume: [{ path: events[1].path, bearer, body: '{}' }],
    authorize: [{ path: events[3].path, bearer, body: '{}' }] };
  assert.equal(facet.assertRecoveryMutationPosts(rows, settled, bearer), true);
  assert.throws(() => facet.assertObservedAttemptRecovery(pending,
    [...events.slice(0, 2), events[1], ...events.slice(2)]));
  assert.throws(() => facet.assertObservedAttemptRecovery(pending,
    events.map((value, index) => index === 1 ?
      { ...value, path: `/api/ctf/predefense/${uuid(35)}/resume` } : value)));
  assert.throws(() => facet.assertObservedAttemptRecovery(pending,
    events.map((value, index) => index === 3 ?
      { ...value, path: `/api/ctf/decisions/${uuid(35)}/authorize` } : value)));
  assert.throws(() => facet.assertRecoveryMutationPosts({ ...rows,
    resume: [{ ...rows.resume[0], bearer: 'Bearer other' }] }, settled, bearer));
  assert.throws(() => facet.assertRecoveryMutationPosts({ ...rows,
    authorize: [{ ...rows.authorize[0], body: '{"retry":true}' }] }, settled, bearer));
});

test('denied hint requires canonical 409 with zero outbox, progress, receipt and provider effect', () => {
  const before = { outboxCount: 3, progress: [{ attempts_count: 0 }],
    hintReceipts: [] };
  const after = structuredClone(before);
  const response = { status: 409,
    body: { error: 'Hint availability changed; refresh stage status' } };
  assert.equal(facet.assertDefaultHintDenial(before, after, response, 0, 0), true);
  assert.throws(() => facet.assertDefaultHintDenial(before, after,
    { status: 503, body: response.body }, 0, 0));
  assert.throws(() => facet.assertDefaultHintDenial(before,
    { ...after, outboxCount: 4 }, response, 0, 0));
  assert.throws(() => facet.assertDefaultHintDenial(before, after, response, 0, 1));
});

test('three exact disposable database names share one nonce', () => {
  const nonce = 'abcdef123456';
  assert.equal(facet.assertDatabaseName(`/owasp_ai_goat_test_ctf_learner_attempt_gate_f_i_${nonce}`,
    'FRESH', 'IDENTITY'), nonce);
  assert.equal(facet.assertDatabaseName(`/owasp_ai_goat_test_ctf_learner_attempt_gate_p_c_${nonce}`,
    'POPULATED', 'CTF', nonce), nonce);
  assert.throws(() => facet.assertDatabaseName(
    `/owasp_ai_goat_test_ctf_learner_entry_hint_f_i_${nonce}`, 'FRESH', 'IDENTITY'));
  assert.throws(() => facet.assertDatabaseName(
    `/owasp_ai_goat_test_ctf_learner_attempt_gate_p_i_${nonce}`, 'FRESH', 'IDENTITY'));
});

test('physical call accounting rejects defense reviewer and uncounted failures', () => {
  assert.deepEqual(facet.countProviderCalls([
    ...Array.from({ length: 3 }, () => ({ route: '/api/generate' })),
    ...Array.from({ length: 6 }, () => ({ route: '/api/chat' })),
  ]), { guardian: 3, judge: 6, total: 9 });
  assert.throws(() => facet.countProviderCalls([{ route: '/v1/chat/completions' }]));
  assert.throws(() => facet.countProviderCalls([...Array.from({ length: 4 },
    () => ({ route: '/api/generate' }))]));
});

test('concurrent provider reservations consume the finite cap before any body read', () => {
  const entries = [];
  for (let n = 0; n < 3; n++) facet.reserveScoredProvider(entries, '/api/generate', 'fail');
  assert.throws(() => facet.reserveScoredProvider(entries, '/api/generate', 'fail'));
  for (let n = 0; n < 6; n++) facet.reserveScoredProvider(entries, '/api/chat', 'fail');
  assert.throws(() => facet.reserveScoredProvider(entries, '/api/chat', 'fail'));
  assert.equal(entries.length, 9);
  assert.throws(() => facet.reserveScoredProvider(entries, '/v1/chat/completions', 'fail'));
  assert.throws(() => facet.reserveScoredProvider([], '/api/generate', 'pass'));
});

test('physical default gate readiness waits for rendered input and visible locked notice', () => {
  const prior = global.document;
  let ready = false, unlocked = false;
  const visible = { getClientRects: () => [1] };
  global.document = {
    querySelector: () => ready ? visible : null,
    querySelectorAll: selector => selector === 'p' && ready
      ? [{ ...visible, textContent: 'Hints unlock after 3 attempts.' }]
      : selector === 'button' && unlocked
        ? [{ ...visible, textContent: 'Unlock Hint 1' }] : [],
  };
  try {
    assert.equal(facet.physicalLockedHintReady(), false,
      'A completed server start does not imply React has rendered the stage');
    ready = true;
    assert.equal(facet.physicalLockedHintReady(), true);
    unlocked = true;
    assert.equal(facet.physicalLockedHintReady(), false,
      'A visible unlocked button can never satisfy the locked witness');
  } finally { global.document = prior; }
});

test('scored POST binds one mounted UI locator, not the server registration locator', () => {
  const registeredDigest = facet.sha('a'.repeat(64));
  const body = JSON.stringify({ payload: 'controlled question',
    sessionToken: '00000000-1111-4111-8111-111111111111' });
  const mountedDigest = facet.assertScoredAttemptBody(body,
    'controlled question', registeredDigest);
  assert.equal(facet.assertScoredAttemptBody(body,
    'controlled question', registeredDigest, mountedDigest), mountedDigest);
  assert.throws(() => facet.assertScoredAttemptBody(JSON.stringify({
    payload: 'controlled question', sessionToken: 'a'.repeat(64),
  }), 'controlled question', registeredDigest));
  assert.throws(() => facet.assertScoredAttemptBody(JSON.stringify({
    payload: 'controlled question', sessionToken: 'new-route-owner',
  }), 'controlled question', registeredDigest, mountedDigest));
  assert.throws(() => facet.assertScoredAttemptBody(JSON.stringify({
    payload: 'wrong question', sessionToken: '00000000-1111-4111-8111-111111111111',
  }), 'controlled question', registeredDigest));
  assert.throws(() => facet.assertScoredAttemptBody(JSON.stringify({
    payload: 'controlled question', sessionToken: '00000000-1111-4111-8111-111111111111',
    extra: true,
  }), 'controlled question', registeredDigest));
  assert.throws(() => facet.assertScoredAttemptBody('not-json',
    'controlled question', registeredDigest),
  { message: 'Physical scored request body must be valid JSON' });
});

test('durable locator digest joins the exact claim run and mounted principal', () => {
  const runId = uuid(1), locatorSha = facet.sha('mounted-ui-route-owner');
  const row = { run_id: runId, owner_id: '2402', session_id: '9',
    locator_sha256: locatorSha };
  assert.equal(facet.assertDurableScoredLocator([row], runId, 2402, 9,
    locatorSha), true);
  for (const changed of [
    { ...row, run_id: uuid(2) }, { ...row, owner_id: '1001' },
    { ...row, session_id: '10' },
    { ...row, locator_sha256: facet.sha('other-route-owner') },
  ]) assert.throws(() => facet.assertDurableScoredLocator([changed],
    runId, 2402, 9, locatorSha));
  assert.throws(() => facet.assertDurableScoredLocator([], runId,
    2402, 9, locatorSha));
  const source = fs.readFileSync(path.join(__dirname,
    'support/ctfLearnerAttemptGateRenderedCases.js'), 'utf8');
  assert.match(source, /FROM identity\.ctf_predefense_registration_locators l\s+JOIN identity\.ctf_predefense_claims claim/);
  assert.match(source, /encode\(sha256\(convert_to\(l\.registration_token,'UTF8'\)\),'hex'\)/);
});

test('rendered admission allows only bounded original attempt and same-reference reads', () => {
  for (const [method, pathname] of [
    ['POST', facet.POST_PATHS.register], ['POST', facet.POST_PATHS.start],
    ['POST', facet.POST_PATHS.attempt], ['GET', '/api/ctf/status'],
    ['GET', `/api/ctf/publications/${uuid(1)}`],
  ]) assert.equal(facet.browserAllowed(method, pathname), true);
  for (const [method, pathname] of [
    ['POST', facet.POST_PATHS.hint], ['POST', '/api/ctf/stage/1/practice'],
    ['POST', '/api/ctf/admin/reset'], ['POST', '/other'],
    ['GET', '/api/ctf/admin/attempts'],
  ]) assert.equal(facet.browserAllowed(method, pathname), false);
});

test('synthetic learner exists before canonical bootstrap and helper only reads it after activation', () => {
  const integration = fs.readFileSync(path.join(__dirname,
    'ctfAuthorityApplication.integration.test.js'), 'utf8');
  const helper = fs.readFileSync(path.join(__dirname,
    'support/ctfLearnerAttemptGateRenderedCases.js'), 'utf8');
  const seed = integration.indexOf("VALUES(2402,'learner-attempt-gate-2402'");
  const bootstrap = integration.indexOf('const repository=createCtfAuthorityBootstrapRepository');
  assert(seed > 0 && seed < bootstrap);
  assert(helper.includes('Pre-bootstrap synthetic learner must already exist'));
  assert(!helper.includes('INSERT INTO identity.users'));
});

test('shared integration routes scored default gate through its own fixture, never Learner-A', () => {
  const integration = fs.readFileSync(path.join(__dirname,
    'ctfAuthorityApplication.integration.test.js'), 'utf8');
  assert.match(integration, /attemptGateOnly=process\.env\.CTF_LEARNER_ATTEMPT_GATE_RENDERED_ISOLATED==='1'/);
  assert.match(integration, /runControlledRenderedCases/);
  assert.match(integration, /reserveScoredProvider\(ledger,req\.url,mode\)/);
  assert.match(integration, /attemptGateOnly\?800:fixedPracticeOnly\?240:1200/);
  assert.match(integration, /assert\(Number\(contentOnly\).*Number\(attemptGateOnly\)\+Number\(fixedPracticeOnly\)===1/);
  assert.equal(typeof facet.runControlledRenderedCases, 'function');
});
