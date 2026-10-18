'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { qualifyStandaloneMailDisclosure, createStandaloneMailDisclosureObservations,
  observeMailDisclosureBoundary, OBJECTIVE, _internals } = require('./fixtures/secureshopStandaloneMailDisclosureQualification');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { buildMailDisclosureCandidate, MAIL_DISCLOSURE_RUBRIC } = require('../server/services/secureshopMailDisclosureEvidence');
const { normalize: normalizeMailBinding } = require('../server/database/postgres/secureshopBoundMailRepository');
const sha = value => createHash('sha256').update(value).digest('hex');

// Controlled records exercise the inspection contract only. No DB, browser,
// configured Judge or model runs occur here and no qualification is promoted.
async function fixture({ realScope = false } = {}) {
  const scope = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 1, platformSessionId: 2 };
  const issuedScope = realScope ? { ...scope, credentialVersion: '1',
    expiresAt: '2026-10-12T12:00:00.000Z', status: 'active' } : scope;
  const subject = { tenantId: randomUUID(), principalId: randomUUID(), targetId: randomUUID(),
    binding: { ...issuedScope, shopUserId: 3, role: 'merchant' } };
  const sibling = { tenantId: randomUUID(), principalId: randomUUID(), targetId: randomUUID(),
    binding: { ...scope, launchId: randomUUID(), platformOwnerId: 4, platformSessionId: 5,
      shopUserId: 6, role: 'merchant' },
    personaSession: { sessionId: randomUUID(), authorityVersion: '1' } };
  const readId = randomUUID(), evaluationId = randomUUID(), runId = randomUUID();
  const readBinding = { scope: issuedScope, targetId: subject.targetId, operationId: readId,
    persona: { id: 3, role: 'merchant' }, personaSession: { sessionId: randomUUID(), authorityVersion: '1' }, mode: 'vuln' };
  const receipt = { operation_id: readId, target_id: subject.targetId, caller_id: 3,
    persona_session_id: readBinding.personaSession.sessionId, authority_version: '1', role: 'merchant',
    action: 'read', mode: 'vuln', request_sha256: Buffer.from('a'.repeat(64), 'hex'),
    result: { userId: 7, messages: [{ id: 8, sha256: 'b'.repeat(64) }] } };
  const source = { binding: normalizeMailBinding(readBinding), receipt: receipt.result, requestSha256: 'a'.repeat(64),
    messages: [{ id: 8, subject: 'Synthetic mail' }] };
  const prepared = prepareJudgeInput({ rubric: { ...MAIL_DISCLOSURE_RUBRIC, mode: 'vuln' },
    ...buildMailDisclosureCandidate(source) });
  const criteria = [{ id: 'owned_foreign_mail_disclosed', satisfied: true, evidenceRefs: ['mail_disclosure'] }];
  const raw = { provider: 'ollama', model: 'controlled-record-only', verdict: 'pass', explanation: 'Controlled record only', criteria, runId,
    evidenceDigest: prepared.evidenceDigest };
  const row = { tenant_id: subject.tenantId, principal_id: subject.principalId, shop_user_id: 3,
    objective_id: OBJECTIVE, evaluation_id: evaluationId, run_id: runId, mode: 'vuln', verdict: 'pass',
    disposition: 'awarded', owner_key: 'owner', owner_generation: '1',
    execution_json: { scope, tenantId: subject.tenantId, principalId: subject.principalId, shopUserId: 3,
      role: 'merchant', personaSessionId: readBinding.personaSession.sessionId, personaAuthorityVersion: '1',
      runId, ownerKey: 'owner', ownerGeneration: '1' },
    packet: prepared.packet, evidence_digest: prepared.evidenceDigest, result_json: raw,
    result_serialized: JSON.stringify(raw), result_digest: sha(JSON.stringify(raw)),
    judge_result_json: JSON.stringify(raw), judge_observations: { version: 1, runId,
      evidenceDigest: prepared.evidenceDigest, resultSha256: sha(JSON.stringify(raw)) } };
  const input = [{ role: 'user', content: prepared.packet }], response = JSON.stringify({ verdict: 'pass', explanation: raw.explanation, criteria });
  const request = JSON.stringify({ model: raw.model, messages: input });
  const wireResponse = JSON.stringify({ message: { content: response }, done: true });
  const capture = { wire: { model: raw.model, digest: 'c'.repeat(64), calls: [{ kind: 'judge', model: raw.model,
    status: 200, responseComplete: true, responseCaptureTruncated: false, request, requestSha256: sha(request),
    response: wireResponse, responseSha256: sha(wireResponse) }] }, transcripts: [] };
  const recorder = require('../server/agent-runtime/judgeExecutionTranscript').createJudgeExecutionTranscript(
    value => capture.transcripts.push(value), { maximumCalls: 1, packet: prepared.packet,
      evidenceDigest: prepared.evidenceDigest, runId });
  const call = recorder.begin('primary', 1, { input });
  recorder.returned(call, { response, provider: 'ollama', model: raw.model, mocked: false, fallback: false });
  recorder.parsed('primary', 1, response); recorder.disposition('primary', 1, 'accepted');
  await recorder.finish(raw);
  const state = { receipts: [receipt], judgments: [row], reset: false, mode: 'vuln', credited: true };
  const statements = [];
  const identityRuntime = { async query(sql, args) {
    assert.match(sql.trim(), /^SELECT /); statements.push(sql);
    if (sql.includes('assessment_judgments')) return { rows: args[0] === subject.tenantId ? state.judgments : [] };
    if (sql.includes('active_assessment_contributions')) return { rows: args[0] === subject.tenantId && state.credited ? [{ evaluation_id: evaluationId }] : [] };
    if (sql.includes('assessment_completions')) return { rows: [{ evaluation_id: evaluationId }] };
    if (sql.includes('tenant_modes')) return { rows: [{ mode: state.mode }] };
    if (sql.includes('execution_authority_state')) return { rows: [{ tenant_id: subject.tenantId,
      principal_id: subject.principalId, shop_user_id: 3, role: 'merchant' }] };
    if (sql.includes('secureshop_launch_resets')) return { rows: state.reset ? [{ reset_id: randomUUID(), to_generation: 2 }] : [] };
    if (sql.includes('secureshop_launches')) return { rows: [{ status: 'active', generation: state.reset ? 2 : 1 }] };
    throw Error('Unexpected query');
  } };
  const agentsRuntime = { async query(sql, args) {
    assert.match(sql.trim(), /^SELECT /); assert(sql.includes('lab_mail_operation_receipts')); statements.push(sql);
    return { rows: args[0] === subject.targetId ? state.receipts : [] };
  } };
  const boundary = observeMailDisclosureBoundary({ async disclose() {
    throw Object.assign(Error('Mailbox forbidden'), { code: '42501' }); }, async assessDisclosure(context) {
    if (context.scope.platformOwnerId === sibling.binding.platformOwnerId)
      throw Object.assign(Error('Mail operation conflict'), { code: '23505' });
    throw Object.assign(Error('Canonical mail disclosure unavailable'), { code: 'MAIL_EVIDENCE_UNAVAILABLE' }); } });
  const options = { identityRuntime, agentsRuntime, subject, sibling, readBinding, boundary,
    disclosureRepository: { async readDisclosure(binding) {
      assert.deepEqual(normalizeMailBinding(binding), source.binding);
      return structuredClone(source); } },
    snapshotJudge: () => capture, model: raw.model, digest: capture.wire.digest };
  const observe = createStandaloneMailDisclosureObservations(options);
  return { observe, options, state, capture, row, source, statements,
    read: { requestId: readId, merchantId: 3, recipientId: 7, emails: source.messages },
    assessment: { assessment: { completed: true, judgment: { evaluationId, verdict: 'pass', runId,
      evidenceDigest: prepared.evidenceDigest } }, readOperationId: readId, recipientId: 7 } };
}

test('inspects concrete saved receipt, registered credit and hash-linked transcript/wire records', async () => {
  const f = await fixture(); await f.observe.assertAuthority(); await f.observe.verifyRead(f.read); await f.observe.assertActualJudge(f.assessment);
  assert.deepEqual(await f.observe.counts(), { reads: 1, judgments: 1, completions: 1, judgeCalls: 1 });
  assert(f.statements.every(sql => !sql.includes('workshop_platform.')));
});

test('real issued launch metadata is projected without dropping required scope mismatches', async () => {
  const f = await fixture({ realScope: true });
  await f.observe.assertAuthority(); await f.observe.verifyRead(f.read);
  await f.observe.assertActualJudge(f.assessment);
  const input = { requestId: randomUUID(), userId: 7 };
  await assert.rejects(f.options.boundary.application.disclose({ scope: f.options.readBinding.scope,
    persona: f.options.readBinding.persona,
    personaSession: f.options.readBinding.personaSession }, input), { code: '42501' });
  f.observe.assertFixedReadDenied(input);
  assert.throws(() => createStandaloneMailDisclosureObservations({ ...f.options,
    readBinding: { ...f.options.readBinding, scope: {
      ...f.options.readBinding.scope, platformOwnerId: 99 } } }));
});

test('fixed mode denial requires the exact application error and owned caller, not a 503 claim', async () => {
  const f = await fixture(), input = { requestId: randomUUID(), userId: 7 };
  assert.throws(() => f.observe.assertFixedReadDenied(input));
  await assert.rejects(f.options.boundary.application.disclose({ scope: f.options.readBinding.scope,
    persona: f.options.readBinding.persona, personaSession: f.options.readBinding.personaSession }, input),
  { code: '42501' });
  f.observe.assertFixedReadDenied(input);
  const stale = { ...input, requestId: randomUUID() };
  await assert.rejects(f.options.boundary.application.disclose({ scope: f.options.readBinding.scope,
    persona: { id: 99, role: 'merchant' }, personaSession: f.options.readBinding.personaSession }, stale));
  assert.throws(() => f.observe.assertFixedReadDenied(stale));
});

for (const [name, mutate] of [
  ['foreign target receipt', f => { f.state.receipts[0].target_id = randomUUID(); }],
  ['recovered source owner substitution', f => { f.source.binding = {
    ...f.source.binding, scope: { ...f.source.binding.scope, platformOwnerId: 99 } }; }],
  ['changed message bytes', f => { f.read.emails = [{ id: 8, subject: 'changed' }]; }],
  ['receipt session substitution', f => { f.state.receipts[0].persona_session_id = randomUUID(); }],
]) test(`rejects ${name}`, async () => {
  const f = await fixture(); mutate(f); await assert.rejects(f.observe.verifyRead(f.read));
});

for (const [name, mutate] of [
  ['Boolean transcript claim', f => { f.capture.transcripts = [{ actualModel: true, transcriptVerified: true }]; }],
  ['foreign execution authority', f => { f.row.execution_json.principalId = randomUUID(); }],
  ['changed original packet', f => { f.row.packet += ' '; }],
  ['wire response substitution', f => { f.capture.wire.calls[0].response = '{}'; }],
  ['incomplete wire response', f => { f.capture.wire.calls[0].responseComplete = false; }],
  ['wrong model digest', f => { f.capture.wire.digest = 'd'.repeat(64); }],
  ['missing canonical credit', f => { f.state.credited = false; }],
]) test(`rejects ${name}`, async () => {
  const f = await fixture(); await f.observe.verifyRead(f.read); mutate(f);
  await assert.rejects(f.observe.assertActualJudge(f.assessment));
});

test('fixed read cannot pass merely because no completed field was returned', () => {
  assert.throws(() => _internals.assertDenied({ status: 200, value: { emails: [{ id: 8 }] } }, 'fixed read'));
  assert.throws(() => _internals.assertDenied({ status: 503, value: { ok: false, error: 'denied', emails: [] } }, 'fixed read'));
  assert.throws(() => _internals.assertDenied({ status: 500, value: { ok: false, error: 'crash' } }, 'fixed read'));
  assert.throws(() => _internals.assertDenied({ status: 200,
    value: { ok: true, completed: false, status: 'disabled', modelEvaluated: false } }, 'sibling owner'));
  _internals.assertDenied({ status: 503, value: { ok: false, error: 'Bound mail unavailable' } }, 'fixed read');
  _internals.assertDenied({ status: 200, value: { ok: true, completed: false, status: 'ineligible', modelEvaluated: false } }, 'fixed assessment', { kind: 'ineligible' });
  _internals.assertDenied({ status: 401, value: { error: 'Shop authentication required' } },
    'retired session', { kind: 'auth', error: 'Shop authentication required' });
  assert.throws(() => _internals.assertDenied({ status: 401,
    value: { ok: false, error: 'Shop authentication required' } }, 'retired session',
  { kind: 'auth', error: 'Shop authentication required' }));
});

test('reset requires persisted committed transition and new scope, not status string', async () => {
  const f = await fixture(), restored = { ...f.options.subject.binding, generation: 2 };
  await assert.rejects(f.observe.assertReset(restored)); f.state.reset = true;
  await f.observe.assertReset(restored);
  await assert.rejects(f.observe.assertReset(f.options.subject.binding));
});

test('opaque observation callbacks cannot be used as a qualification observer', async () => {
  await assert.rejects(qualifyStandaloneMailDisclosure({ origin: 'http://127.0.0.1:3000',
    page: { on() {}, off() {}, waitForResponse() {} }, frame: { waitForFunction() {}, click() {} },
    observe: { verifyRead: async () => ({ sameOwnedTarget: true }), assertActualJudge: async () => ({ actualModel: true }) } }),
  /SQL\/repository observation factory/);
});

test('physical control driver calls browser click and never a DOM click callback', async () => {
  const events = [];
  await _internals.clickInboxControl({ waitForFunction: async (_fn, opts, label) => events.push(label),
    click: async selector => events.push(selector), evaluate: async () => events.push('cleanup') }, 'Read for assessment');
  assert.deepEqual(events, ['Read for assessment', '[data-m23-click="selected"]', 'cleanup']);
});

test('mounted launch and persona middleware preserve typed fixed and reset mail responses', async () => {
  const express = require('express');
  const jwt = require('jsonwebtoken');
  const { createSecureShopBoundPersonaAuth, ISSUER, AUDIENCE } = require('../server/services/secureshopBoundPersonaAuth');
  const { requireSecureShopLaunch } = require('../server/middleware/secureshopLaunch');
  const { createBoundMailRouter } = require('../server/routes/secureshop/boundMail');
  const bearer = 'a'.repeat(43), secret = 'controlled-mail-auth-secret-at-least-32-bytes';
  const initial = { launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 72, platformSessionId: 73 };
  let live = initial, mode = 'vuln', boundaryCalls = 0, unexpectedEffects = 0;
  const launches = {
    async resolveCapability(value) { assert.equal(value, bearer); return live; },
    async assertCurrent(value) { assert.deepEqual(value, live); return { ...live,
      expiresAt: new Date(Date.now() + 60000).toISOString() }; },
  };
  const repository = {
    findCredential() {}, createSession() {}, extendSession() {}, revokeSession() {},
    listSessions() {}, revokeOwnedSession() {}, changePassword() {}, readApiKey() {},
    rotateApiKey() {}, authenticateApiKey() {},
    async readSession({ jti }) { return jti === 'current' ? {
      session_id: randomUUID(), shop_user_id: 12, username: 'student_merchant',
      email: 'merchant@owned.invalid', role: 'merchant', full_name: null, phone: null,
      expires_at: new Date(Date.now() + 60000).toISOString(),
    } : null; },
  };
  const auth = createSecureShopBoundPersonaAuth({ repository, launches, jwtSecret: secret });
  const token = (scope, jti) => jwt.sign({ role: 'merchant', username: 'student_merchant',
    ss_launch_id: scope.launchId, ss_scenario_id: scope.scenarioId,
    ss_generation: scope.generation, ss_owner_id: scope.platformOwnerId,
    ss_platform_session_id: scope.platformSessionId }, secret, {
    algorithm: 'HS256', issuer: ISSUER, audience: AUDIENCE, subject: '12', jwtid: jti,
    expiresIn: 3600,
  });
  const oldToken = token(initial, 'current'), revokedToken = token(initial, 'revoked');
  const application = {
    readiness() {}, read() { unexpectedEffects++; }, send() { unexpectedEffects++; },
    reply() { unexpectedEffects++; }, recover() { unexpectedEffects++; },
    async disclose() { boundaryCalls++; throw Object.assign(Error('Mailbox forbidden'), { code: '42501' }); },
    async assessDisclosure() {
      boundaryCalls++;
      if (mode === 'fixed') return { ok: true, completed: false, status: 'ineligible', modelEvaluated: false };
      throw Object.assign(Error(live.generation === 2 ? 'Mail operation conflict'
        : 'Canonical mail disclosure unavailable'), { code: live.generation === 2 ? '23505' : 'MAIL_EVIDENCE_UNAVAILABLE' });
    },
  };
  const app = express(); app.use(express.json());
  app.use(requireSecureShopLaunch({ launches }));
  app.use(createBoundMailRouter({ application, authenticatePersona: auth.authenticatePersona }));
  const server = await new Promise(resolve => { const opened = app.listen(0, '127.0.0.1', () => resolve(opened)); });
  const endpoint = `http://127.0.0.1:${server.address().port}/email`;
  const request = async (path, credential, body) => {
    const response = await fetch(endpoint + path, { method: 'POST', headers: {
      'x-dvaia-secureshop-launch': bearer, authorization: `Bearer ${credential}`,
      'content-type': 'application/json',
    }, body: JSON.stringify(body), signal: AbortSignal.timeout(3000) });
    return { status: response.status, value: await response.json() };
  };
  const assess = { requestId: randomUUID(), readOperationId: randomUUID() };
  try {
    const retired = await request('/disclosure-assessment', revokedToken, assess);
    _internals.assertDenied(retired, 'retired persona session',
      { kind: 'auth', error: 'Shop authentication required' });
    assert.equal(boundaryCalls, 0);
    mode = 'fixed';
    const fixedRead = await request('/disclosure', oldToken,
      { requestId: randomUUID(), userId: 21 });
    _internals.assertDenied(fixedRead, 'fixed foreign read', { status: 503 });
    const fixed = await request('/disclosure-assessment', oldToken, assess);
    _internals.assertDenied(fixed, 'fixed assessment', { kind: 'ineligible' });
    mode = 'vuln';
    _internals.assertDenied(await request('/disclosure-assessment', oldToken, assess),
      'mode roundtrip');
    const beforeReset = boundaryCalls;
    live = { ...initial, generation: 2 };
    // Launch reset retains the handle, so it resolves to generation 2. The
    // generation-1 persona JWT fails at decode before any mail application call.
    const oldLaunch = await request('/disclosure-assessment', oldToken, assess);
    _internals.assertDenied(oldLaunch, 'old launch after reset',
      { kind: 'auth', error: 'Shop authentication required' });
    assert.equal(boundaryCalls, beforeReset);
    const restoredToken = token(live, 'current');
    const staleReceipt = await request('/disclosure-assessment', restoredToken, assess);
    _internals.assertDenied(staleReceipt, 'old receipt with restored authority', { status: 409 });
    assert.equal(boundaryCalls, beforeReset + 1);
    assert.equal(unexpectedEffects, 0);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

for (const hostRequests of [false, true]) test(`complete controlled ${hostRequests ? 'host bridge' : 'direct frame'} workflow retains evidence without claiming actual qualification`, async () => {
  const f = await fixture(), savedReceipt = f.state.receipts[0], savedJudgment = f.row;
  const wire = f.capture.wire.calls, transcripts = f.capture.transcripts;
  f.state.receipts = []; f.state.judgments = []; f.state.credited = false;
  f.capture.wire.calls = []; f.capture.transcripts = [];
  const actors = Object.fromEntries([['merchant', 3], ['foreign', 7], ['empty', 9], ['sibling', 6]]
    .map(([name, id]) => [name, { id, username: name, email: `${name}@example.invalid` }]));
  const origin = 'http://127.0.0.1:3100', listeners = new Set(), waiters = [];
  const assessmentBody = { requestId: randomUUID(), readOperationId: f.read.requestId };
  let selected = '', label, selectorChecks = 0, roundtrip = false;
  const control = { click: async () => {}, press: async key => { if (key === 'Backspace') selected = ''; },
    type: async value => { selected += value; } };
  const frame = { waitForSelector: async () => control,
    waitForFunction: async (_fn, _opts, value) => { if (typeof value === 'string' && !/^\d+$/.test(value)) label = value; },
    evaluate: async () => ++selectorChecks === 2
      ? { connected: true, sameNode: true, focused: true, value: selected }
      : { connected: true, sameNode: true, focused: true },
    async click() {
      if (label === 'Reload') emit(`/api/secureshop/email/inbox/7`, 'GET', {}, {});
      if (label === 'Read for assessment') {
        f.state.receipts.push(savedReceipt);
        emit('/api/secureshop/email/disclosure', 'POST', { requestId: f.read.requestId, userId: 7 },
          { operationId: f.read.requestId, emails: f.read.emails });
      }
      if (label === 'Check saved disclosure') {
        f.state.judgments.push(savedJudgment); f.state.credited = true;
        f.capture.wire.calls = wire; f.capture.transcripts = transcripts;
        emit('/api/secureshop/email/disclosure-assessment', 'POST', assessmentBody, f.assessment.assessment);
      }
    } };
  const requestFrame = hostRequests ? { name: 'trusted host frame' } : frame;
  const page = { on: (_name, fn) => listeners.add(fn), off: (_name, fn) => listeners.delete(fn),
    keyboard: { down: async () => {}, up: async () => {} },
    waitForResponse: predicate => new Promise(resolve => waiters.push({ predicate, resolve })) };
  function emit(path, method, body, value) {
    const decoy = { url: () => origin + path, method: () => method, frame: () => ({ name: 'unrelated frame' }),
      postData: () => JSON.stringify(body) };
    for (const listener of listeners) listener(decoy);
    const unrelated = { url: decoy.url, request: () => decoy, status: () => 200, json: async () => value };
    assert(waiters.every(waiter => !waiter.predicate(unrelated)), 'Same-path traffic from another frame must not satisfy the waiter');
    const request = { url: () => origin + path, method: () => method, frame: () => requestFrame,
      postData: () => JSON.stringify(body) };
    for (const listener of listeners) listener(request);
    const response = { url: request.url, request: () => request, status: () => 200, json: async () => value };
    const index = waiters.findIndex(row => row.predicate(response)); assert(index >= 0);
    waiters.splice(index, 1)[0].resolve(response);
  }
  const rejected = { status: 503, value: { ok: false, error: 'Bound mail unavailable' } };
  const context = { scope: f.options.readBinding.scope, persona: f.options.readBinding.persona,
    personaSession: f.options.readBinding.personaSession };
  const siblingContext = { scope: f.options.sibling.binding,
    persona: { id: f.options.sibling.binding.shopUserId, role: 'merchant' },
    personaSession: f.options.sibling.personaSession };
  const api = {
    async disclose(body) {
      if (f.state.mode === 'fixed') {
        await assert.rejects(f.options.boundary.application.disclose(context, body)); return rejected;
      }
      const messages = body.userId === 3 ? [{ id: 10, sha256: 'a'.repeat(64) }] : [];
      f.state.receipts.push({ ...savedReceipt, operation_id: body.requestId, result: { userId: body.userId, messages } });
      return { status: 200, value: { emails: messages } };
    },
    async assess(body, options) {
      if (options?.actor === 'sibling') {
        await assert.rejects(f.options.boundary.application.assessDisclosure(siblingContext, body),
          { code: '23505' });
        return { status: 409, value: { ok: false, error: 'Bound mail unavailable' } };
      }
      if (options?.actor === 'staleSession') return { status: 401,
        value: { error: 'Shop authentication required' } };
      if (options?.actor === 'oldSession') return { status: 401,
        value: { error: 'Shop authentication required' } };
      if (f.state.mode === 'fixed') return { status: 200, value: { ok: true, completed: false, status: 'ineligible', modelEvaluated: false } };
      if (body.requestId !== assessmentBody.requestId) {
        await assert.rejects(f.options.boundary.application.assessDisclosure(context, body)); return rejected;
      }
      if (roundtrip || f.state.reset) return rejected;
      return { status: 200, value: { ...f.assessment.assessment, replayed: true } };
    },
    async savedAssessments() { return { status: 200, value: { judgments: f.state.judgments.map(row =>
      ({ objectiveId: row.objective_id, evaluationId: row.evaluation_id })) } }; },
  };
  const result = await qualifyStandaloneMailDisclosure({ page, frame, actors, api, observe: f.observe, origin,
    ...(hostRequests ? { requestFrame } : {}),
    lifecycle: { async setMode(mode) { f.state.mode = mode; roundtrip = true; },
      async reset() { f.state.reset = true; f.state.credited = false; return { status: 'committed' }; },
      async restore() { return { ...f.options.subject.binding, generation: 2 }; } } });
  assert.equal(result.status, 'assertions_passed'); assert.equal(result.actualQualification, false);
  const reads = f.statements.length, evidence = f.observe.snapshotEvidence();
  assert.equal(f.statements.length, reads, 'Retaining evidence must not issue another SQL query');
  assert.equal(evidence.read.receipt.operation_id, f.read.requestId);
  assert.equal(evidence.read.source.requestSha256, f.source.requestSha256);
  assert.equal(evidence.judgment.row.evaluation_id, f.row.evaluation_id);
  assert.equal(evidence.fixedRead.error.code, '42501');
  assert.equal(evidence.negativeReads.length, 2);
  assert.equal(evidence.immutableSnapshots.length, 2);
  assert.equal(evidence.siblingSnapshots.length, 3);
  assert.equal(evidence.negativeResponses.length, 8);
  assert.deepEqual(evidence.negativeResponses.filter(probe => probe.response.status === 401)
    .map(probe => probe.response.value),
  [{ error: 'Shop authentication required' }, { error: 'Shop authentication required' }]);
  assert.equal(evidence.siblingAssessments.length, 2);
  assert.deepEqual(evidence.siblingAssessments.map(probe => probe.label),
    ['reused_assessment_request', 'foreign_read_operation']);
  assert.equal(evidence.siblingAssessments[0].boundary[0].input.requestId, assessmentBody.requestId);
  assert.notEqual(evidence.siblingAssessments[1].boundary[0].input.requestId, assessmentBody.requestId);
  assert.equal(evidence.siblingAssessments[1].boundary[0].input.readOperationId, f.read.requestId);
  assert(evidence.siblingAssessments.every(probe => probe.response.status === 409
    && probe.boundary[0].error.code === '23505'));
  const unrelatedConflict = structuredClone(evidence.siblingAssessments[1]);
  unrelatedConflict.boundary[0].error = { code: 'TURN_RECOVERY_REQUIRED',
    message: 'Unrelated turn conflict' };
  assert.throws(() => f.observe.assertSiblingAssessment(unrelatedConflict,
    unrelatedConflict.boundary[0].input), /23505/,
  'A generic HTTP 409 cannot establish the foreign read operation fence');
  assert.equal(evidence.reset.resets.length, 1);
  assert(evidence.read.receipt.request_sha256 instanceof Uint8Array);
  evidence.read.receipt.result.userId = -1;
  assert.equal(f.observe.snapshotEvidence().read.receipt.result.userId, 7,
    'Private evidence projection must not mutate the observed source');
  assert.equal(listeners.size, 0); assert.equal(waiters.length, 0);
});
