'use strict';

// An assertion adapter for the current standalone, registered-principal Inbox.
// The caller owns disposable stores, a mounted app, a real Judge, and a browser.
// This file neither creates evidence nor substitutes a controlled Judge for one.
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { selectInboxUser } = require('./secureshopMailDisclosureBrowser');
const { createLaunchScope } = require('../../server/services/secureshopConversationBinding');
const { normalize: normalizeMailBinding } = require('../../server/database/postgres/secureshopBoundMailRepository');
const { buildMailDisclosureCandidate, MAIL_DISCLOSURE_RUBRIC } = require('../../server/services/secureshopMailDisclosureEvidence');
const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');

const OBJECTIVE = 'ss_mail_cross_persona_read';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const keys = ['reads', 'judgments', 'completions', 'judgeCalls'];
const sha = value => createHash('sha256').update(value).digest('hex');
const hex = value => Buffer.isBuffer(value) ? value.toString('hex') : value;
const observers = new WeakSet();
const boundaries = new WeakSet();

// Install this transparent observer around the production mail application when
// constructing the fixture router. It never supplies a response or swallows an
// error. HTTP 503 alone cannot distinguish a deliberate denial from an outage.
function observeMailDisclosureBoundary(application) {
  for (const name of ['disclose', 'assessDisclosure']) assert.equal(typeof application?.[name], 'function');
  const calls = [], wrapped = { ...application };
  for (const name of ['disclose', 'assessDisclosure']) wrapped[name] = async function(context, input, ...rest) {
    const call = { method: name, scope: structuredClone(context.scope), persona: structuredClone(context.persona),
      personaSession: structuredClone(context.personaSession), input: structuredClone(input), status: 'pending' };
    calls.push(call);
    try { const value = await application[name](context, input, ...rest); call.status = 'returned'; return value; }
    catch (error) { call.status = 'rejected'; call.error = { code: error.code, message: error.message }; throw error; }
  };
  const recorder = Object.freeze({ application: Object.freeze(wrapped), snapshot: () => structuredClone(calls) });
  boundaries.add(recorder); return recorder;
}

// Root owns the four disposable stores, mounted production composition, exact
// registered merchant/sibling authority, real browser, pinned actual mail wire
// controller, configured Judge transcript observer and joined cleanup. Supply
// the ORIGINAL trusted readBinding (including its scene attachment), not a JSON
// reconstruction. All queries here are read-only. The production evidence reader
// replays an existing operation and verifies original send/content hashes.
// snapshotJudge returns {wire:{model,digest,calls},transcripts:[...]}; wire is the
// unmodified createMailActualTransport capture. These artifacts must be privately
// persisted by the caller, which alone can establish resource provenance.
function createStandaloneMailDisclosureObservations({ identityRuntime, agentsRuntime,
  subject, sibling, readBinding, disclosureRepository, snapshotJudge, boundary, model, digest }) {
  for (const pool of [identityRuntime, agentsRuntime]) assert.equal(typeof pool?.query, 'function');
  assert.equal(typeof disclosureRepository?.readDisclosure, 'function');
  assert.equal(typeof snapshotJudge, 'function');
  assert(boundaries.has(boundary), 'The real mounted mail application needs a transparent boundary observer');
  assert.equal(typeof model, 'string'); assert(model.trim()); assert.match(digest, /^[a-f0-9]{64}$/);
  for (const actor of [subject, sibling]) {
    assert.match(actor.tenantId, UUID); assert.match(actor.principalId, UUID);
    createLaunchScope(actor.binding); assert.match(actor.targetId, UUID);
  }
  assert.match(sibling.personaSession?.sessionId, UUID);
  assert(/^[1-9]\d*$/.test(String(sibling.personaSession.authorityVersion)));
  assert.notEqual(subject.tenantId, sibling.tenantId); assert.notEqual(subject.targetId, sibling.targetId);
  assert.equal(subject.binding.role, 'merchant');
  const scope = createLaunchScope(subject.binding);
  assert.deepEqual(createLaunchScope(readBinding.scope), scope);
  assert.equal(readBinding.targetId, subject.targetId);
  assert.equal(readBinding.persona.id, subject.binding.shopUserId);
  // These snapshots come only from reads the assertions already perform.
  const evidence = { version: 1, objectiveId: OBJECTIVE, authority: null, read: null,
    judgment: null, fixedRead: null, reset: null, negativeReads: [],
    immutableSnapshots: [], siblingSnapshots: [], siblingAssessments: [], negativeResponses: [], modes: [] };
  const rows = async (pool, sql, args) => (await pool.query(sql, args)).rows;
  const judgments = actor => rows(identityRuntime, `SELECT * FROM secureshop_auth.assessment_judgments
    WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,
  [actor.tenantId, actor.principalId, OBJECTIVE]);
  const receipts = actor => rows(agentsRuntime, `SELECT * FROM secureshop_agents.lab_mail_operation_receipts
    WHERE target_id=$1 ORDER BY operation_id`, [actor.targetId]);
  const credits = actor => rows(identityRuntime, `SELECT * FROM secureshop_auth.active_assessment_contributions
    WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,
  [actor.tenantId, actor.principalId, OBJECTIVE]);
  const immutable = async actor => structuredClone({ receipts: await receipts(actor), judgments: await judgments(actor) });
  const captured = () => {
    const capture = snapshotJudge(); assert.equal(capture.wire.model, model); assert.equal(capture.wire.digest, digest);
    assert(Array.isArray(capture.wire.calls)); assert(Array.isArray(capture.transcripts));
    assert(capture.wire.calls.every(call => call.kind === 'judge'), 'Manual disclosure must not call an actor');
    return capture;
  };
  let source;
  const observed = {
    async assertAuthority() {
      const result = await rows(identityRuntime, `SELECT e.tenant_id,e.principal_id,p.shop_user_id,p.role
        FROM secureshop_auth.execution_authority_state e JOIN secureshop_auth.principals p USING(principal_id)
        JOIN identity.secureshop_authority_owners o ON o.id=e.owner_id
        WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
          AND o.realm='shop' AND o.shop_tenant_id=e.tenant_id AND p.is_active`, [scope.platformSessionId, scope.platformOwnerId]);
      assert.equal(result.length, 1); assert.equal(result[0].tenant_id, subject.tenantId);
      assert.equal(result[0].principal_id, subject.principalId);
      assert.equal(Number(result[0].shop_user_id), subject.binding.shopUserId); assert.equal(result[0].role, 'merchant');
      evidence.authority = structuredClone(result);
    },
    async counts() { return { reads: (await receipts(subject)).filter(r => r.action === 'read').length,
      judgments: (await judgments(subject)).length, completions: (await credits(subject)).length,
      judgeCalls: captured().wire.calls.length }; },
    async immutableSnapshot() { const value = await immutable(subject);
      evidence.immutableSnapshots.push(structuredClone(value)); return value; },
    async siblingSnapshot() { const value = { ...await immutable(sibling), credits: await credits(sibling) };
      evidence.siblingSnapshots.push(structuredClone(value)); return value; },
    recordSiblingAssessment(label, response, input) {
      assert(['reused_assessment_request', 'foreign_read_operation'].includes(label));
      const probe = structuredClone({ label, response, boundary: boundary.snapshot().filter(call =>
        call.method === 'assessDisclosure' && call.input.requestId === input.requestId
        && createLaunchScope(call.scope).platformOwnerId === sibling.binding.platformOwnerId) });
      evidence.siblingAssessments.push(probe); return probe;
    },
    boundaryCount() { return boundary.snapshot().length; },
    recordNegative(label, response, before) {
      const calls = boundary.snapshot();
      assert(Number.isSafeInteger(before) && before >= 0 && before <= calls.length);
      const probe = structuredClone({ label, response, boundary: calls.slice(before) });
      evidence.negativeResponses.push(probe); return probe;
    },
    assertSiblingAssessment(probe, input) {
      assert.equal(probe.response.status, 409, 'Foreign mail operation must be rejected as a conflict');
      assert.equal(probe.response.value?.ok, false);
      assert.equal(probe.response.value?.error, 'Bound mail unavailable');
      assert.equal(probe.boundary.length, 1, 'One exact sibling assessment reached the real application');
      const call = probe.boundary[0];
      assert.deepEqual(call.input, input);
      assert.deepEqual(createLaunchScope(call.scope), createLaunchScope(sibling.binding));
      assert.deepEqual(call.persona, { id: sibling.binding.shopUserId, role: sibling.binding.role });
      assert.deepEqual(call.personaSession, sibling.personaSession);
      assert.equal(call.status, 'rejected');
      assert.equal(call.error.code, '23505');
      assert.equal(call.error.message, 'Mail operation conflict');
    },
    async assertMode(mode) {
      const result = await rows(identityRuntime, `SELECT mode FROM secureshop_auth.tenant_modes
        WHERE tenant_id=$1 AND principal_id=$2`, [subject.tenantId, subject.principalId]);
      assert.deepEqual(result, [{ mode }]);
      evidence.modes.push(structuredClone(result[0]));
    },
    assertFixedReadDenied(input) {
      const calls = boundary.snapshot().filter(call => call.method === 'disclose' && call.input.requestId === input.requestId);
      assert.equal(calls.length, 1); const call = calls[0]; assert.deepEqual(call.input, input);
      assert.deepEqual(createLaunchScope(call.scope), scope);
      assert.deepEqual(call.persona, readBinding.persona);
      assert.deepEqual(call.personaSession, readBinding.personaSession); assert.equal(call.status, 'rejected');
      assert.deepEqual(call.error, { code: '42501', message: 'Mailbox forbidden' });
      evidence.fixedRead = structuredClone(call);
    },
    async assertIneligibleRead(input, actor) {
      const found = (await receipts(subject)).filter(r => r.operation_id === input.readOperationId);
      assert.equal(found.length, 1); const row = found[0];
      assert.equal(row.target_id, subject.targetId); assert.equal(row.caller_id, subject.binding.shopUserId);
      assert.equal(row.persona_session_id, readBinding.personaSession.sessionId);
      assert.equal(row.action, 'read'); assert.equal(row.result.userId, actor.id);
      assert(Array.isArray(row.result.messages));
      if (actor.id === subject.binding.shopUserId) assert(row.result.messages.length > 0);
      else assert.equal(row.result.messages.length, 0);
      const calls = boundary.snapshot().filter(call => call.method === 'assessDisclosure' && call.input.requestId === input.requestId);
      assert.equal(calls.length, 1); assert.deepEqual(calls[0].input, input);
      assert.deepEqual(createLaunchScope(calls[0].scope), scope);
      assert.equal(calls[0].status, 'rejected'); assert.equal(calls[0].error.code, 'MAIL_EVIDENCE_UNAVAILABLE');
      evidence.negativeReads.push(structuredClone({ receipt: row, assessmentBoundary: calls[0] }));
    },
    async verifyRead({ requestId, merchantId, recipientId, emails }) {
      const before = await receipts(subject);
      const receipt = before.filter(row => row.operation_id === requestId); assert.equal(receipt.length, 1);
      const r = receipt[0]; assert.equal(r.target_id, subject.targetId); assert.equal(r.caller_id, merchantId);
      assert.equal(r.persona_session_id, readBinding.personaSession.sessionId);
      assert.equal(String(r.authority_version), String(readBinding.personaSession.authorityVersion));
      assert.equal(r.role, 'merchant'); assert.equal(r.action, 'read'); assert.equal(r.mode, 'vuln');
      // copy preserves the scene capability held in the original binding.
      const binding = require('../../server/services/secureshopMailSceneBinding').copy(readBinding,
        { ...readBinding, operationId: requestId });
      source = await disclosureRepository.readDisclosure(binding);
      assert.deepEqual(source.binding, normalizeMailBinding(binding));
      assert.deepEqual(source.receipt, r.result);
      assert.equal(source.requestSha256, hex(r.request_sha256));
      assert.equal(source.receipt.userId, recipientId); assert.notEqual(recipientId, merchantId);
      assert(source.receipt.messages.length > 0); assert.deepEqual(source.messages, emails);
      assert.deepEqual(await receipts(subject), before, 'Evidence read must not create or mutate receipts');
      evidence.read = structuredClone({ receipt: r, source });
    },
    async assertActualJudge({ assessment, readOperationId, recipientId }) {
      assert(source); assert.equal(source.binding.operationId, readOperationId); assert.equal(source.receipt.userId, recipientId);
      const found = (await judgments(subject)).filter(row => row.evaluation_id === assessment.judgment.evaluationId);
      assert.equal(found.length, 1); const row = found[0], e = row.execution_json;
      assert.equal(row.tenant_id, subject.tenantId); assert.equal(row.principal_id, subject.principalId);
      assert.equal(Number(row.shop_user_id), subject.binding.shopUserId); assert.equal(row.objective_id, OBJECTIVE);
      assert.deepEqual(createLaunchScope(e.scope), scope);
      assert.equal(e.tenantId, subject.tenantId); assert.equal(e.principalId, subject.principalId);
      assert.equal(e.shopUserId, subject.binding.shopUserId); assert.equal(e.role, 'merchant');
      assert.equal(e.personaSessionId, readBinding.personaSession.sessionId);
      assert.equal(String(e.personaAuthorityVersion), String(readBinding.personaSession.authorityVersion));
      assert.equal(e.runId, row.run_id); assert.equal(e.ownerKey, row.owner_key);
      assert.equal(String(e.ownerGeneration), String(row.owner_generation));
      const prepared = prepareJudgeInput({ rubric: { ...MAIL_DISCLOSURE_RUBRIC, mode: 'vuln' },
        ...buildMailDisclosureCandidate(source) });
      assert.equal(row.packet, prepared.packet); assert.equal(row.evidence_digest, prepared.evidenceDigest);
      assert.equal(sha(row.packet), row.evidence_digest); assert.equal(row.mode, 'vuln');
      assert.equal(row.verdict, 'pass'); assert.equal(row.disposition, 'awarded');
      assert.equal(sha(row.result_serialized), row.result_digest);
      assert.deepEqual(JSON.parse(row.result_serialized), row.result_json);
      const raw = JSON.parse(row.judge_result_json), proof = row.judge_observations;
      assert.equal(proof.version, 1); assert.equal(proof.runId, row.run_id); assert.equal(proof.evidenceDigest, row.evidence_digest);
      assert.equal(proof.resultSha256, sha(row.judge_result_json));
      for (const result of [raw, row.result_json]) {
        assert.equal(result.provider, 'ollama'); assert.equal(result.model, model);
        assert.equal(result.runId, row.run_id); assert.equal(result.evidenceDigest, row.evidence_digest); assert.equal(result.verdict, 'pass');
      }
      assert.equal(assessment.judgment.runId, row.run_id); assert.equal(assessment.judgment.evidenceDigest, row.evidence_digest);
      assert.equal((await credits(subject)).filter(r => r.evaluation_id === row.evaluation_id).length, 1);
      const completion = await rows(identityRuntime, `SELECT evaluation_id FROM secureshop_auth.assessment_completions
        WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`, [subject.tenantId, subject.principalId, row.evaluation_id]);
      assert.deepEqual(completion, [{ evaluation_id: row.evaluation_id }]);
      const capture = captured(), matches = capture.transcripts.filter(t => t.header?.runId === row.run_id
        && t.header?.packet === row.packet && t.header?.evidenceDigest === row.evidence_digest);
      assert.equal(matches.length, 1); const t = matches[0], { transcriptSha256, ...document } = t;
      assert.equal(sha(JSON.stringify(document)), transcriptSha256); assert.equal(t.version, 1);
      assert.equal(t.complete, true); assert.equal(t.failure, null); assert(t.calls.length > 0);
      assert.equal(t.outcome.sha256, sha(t.outcome.bytes)); assert.deepEqual(JSON.parse(t.outcome.bytes), raw);
      assert.deepEqual(t.outcome.value, raw); assert.equal(capture.wire.calls.length, t.calls.length);
      for (const [index, call] of t.calls.entries()) {
        const wire = capture.wire.calls[index]; assert.equal(wire.status, 200); assert.equal(wire.model, model);
        assert.equal(wire.responseComplete, true); assert.equal(wire.responseCaptureTruncated, false);
        assert.equal(wire.error, undefined); assert.equal(sha(wire.request), wire.requestSha256);
        assert.equal(sha(wire.response), wire.responseSha256); assert.equal(call.transport, 'returned');
        assert.equal(sha(JSON.stringify(call.request)), call.requestSha256);
        assert.equal(sha(call.response), call.responseSha256); assert.equal(call.validatedTextSha256, call.responseSha256);
        assert(['accepted', 'rejected'].includes(call.disposition));
        assert.equal(call.metadata.provider, 'ollama'); assert.equal(call.metadata.model, model);
        assert.notEqual(call.metadata.mocked, true); assert.notEqual(call.metadata.fallback, true);
        const request = JSON.parse(wire.request); assert.equal(request.model, model); assert.deepEqual(request.messages, call.request.input);
        const text = wire.response.trim().split('\n').map(line => JSON.parse(line).message?.content || '').join('');
        assert.equal(text, call.response);
      }
      const accepted = t.calls.filter(call => call.disposition === 'accepted');
      assert.equal(accepted.length, 1); assert.equal(accepted[0].stage, 'primary');
      const decision = JSON.parse(accepted[0].response);
      assert.equal(decision.verdict, 'pass'); assert.equal(decision.explanation, raw.explanation);
      assert.deepEqual(decision.criteria, raw.criteria);
      assert.equal(decision.criteria.length, 1); assert.equal(decision.criteria[0].id, 'owned_foreign_mail_disclosed');
      assert.equal(decision.criteria[0].satisfied, true); assert.deepEqual(decision.criteria[0].evidenceRefs, ['mail_disclosure']);
      evidence.judgment = structuredClone({ row, completion });
    },
    async assertReset(restored) {
      const launch = await rows(identityRuntime, `SELECT status,generation FROM identity.secureshop_launches WHERE launch_id=$1`, [scope.launchId]);
      assert.equal(launch.length, 1); assert(Number(launch[0].generation) > scope.generation);
      const resets = await rows(identityRuntime, `SELECT reset_id,to_generation FROM identity.secureshop_launch_resets
        WHERE launch_id=$1 AND from_generation=$2 AND status='committed' AND committed_at IS NOT NULL`, [scope.launchId, scope.generation]);
      assert.equal(resets.length, 1); assert.equal(Number(resets[0].to_generation), Number(launch[0].generation));
      const next = createLaunchScope(restored); assert.equal(next.platformOwnerId, scope.platformOwnerId);
      assert(next.launchId !== scope.launchId || next.generation > scope.generation, 'Restore must supply new authoritative scope');
      evidence.reset = structuredClone({ launch, resets, restored: next });
    },
    snapshotEvidence() {
      assert(evidence.authority && evidence.read && evidence.judgment && evidence.fixedRead
        && evidence.siblingAssessments.length === 2 && evidence.reset,
        'Complete already-observed M23 evidence required');
      assert.equal(evidence.negativeReads.length, 2);
      assert(evidence.immutableSnapshots.length >= 2 && evidence.siblingSnapshots.length >= 2);
      const snapshot = structuredClone(evidence);
      assert(Buffer.byteLength(JSON.stringify(snapshot)) <= 16 * 1024 * 1024,
        'Bounded private M23 evidence required');
      return snapshot;
    },
  };
  observers.add(observed); return Object.freeze(observed);
}

function validActor(actor, name) {
  assert(Number.isSafeInteger(actor?.id) && actor.id > 0, `${name} needs a registered shop ID`);
  assert(typeof actor.email === 'string' && actor.email.includes('@'), `${name} needs a registered email`);
  assert(typeof actor.username === 'string' && actor.username.trim(), `${name} needs a registered username`);
}
function validateCounts(value) {
  for (const key of keys) assert(Number.isSafeInteger(value?.[key]) && value[key] >= 0,
    `Observation must provide ${key}`);
  return value;
}
function sameCounts(actual, expected, label) {
  for (const key of keys) assert.equal(actual[key], expected[key], `${label} changed ${key}`);
}
function assertDenied(response, label, { kind = 'application', status, error } = {}) {
  assert(response && Number.isInteger(response.status), `${label} needs a real HTTP status`);
  if (kind === 'ineligible') {
    assert.equal(response.status, 200); assert.equal(response.value?.ok, true);
    assert.equal(response.value?.completed, false); assert.equal(response.value?.status, 'ineligible');
    assert.equal(response.value?.modelEvaluated, false);
  } else if (kind === 'auth') {
    assert.equal(response.status, 401);
    assert.deepEqual(response.value, { error });
  } else {
    assert.equal(kind, 'application');
    if (status === undefined) assert([409, 503].includes(response.status), `${label} requires a mail application rejection`);
    else assert.equal(response.status, status);
    assert.equal(response.value?.ok, false);
    assert.equal(response.value?.error, 'Bound mail unavailable');
  }
  assert.equal(response.value?.emails, undefined, `${label} must not return mailbox content`);
  assert.notEqual(response.value?.completed, true, `${label} must not award credit`);
}
function assertPassed(response) {
  assert.equal(response.status, 200, 'Real disclosure assessment HTTP status');
  assert.equal(response.value?.completed, true, 'Foreign nonempty read must complete');
  assert.equal(response.value?.judgment?.verdict, 'pass', 'Actual Judge must pass');
}
function readPost(posts, path) {
  const found = posts.filter(row => row.path === path);
  assert.equal(found.length, 1, `Expected one ${path} browser POST`);
  return found[0].body;
}

async function clickInboxControl(frame, label) {
  assert(['Reload', 'Read for assessment', 'Check saved disclosure'].includes(label));
  await frame.waitForFunction(label => {
    const buttons = [...document.querySelectorAll('button')].filter(b => b.textContent.trim() === label
      && !b.disabled && b.getClientRects().length);
    if (buttons.length !== 1) return false;
    const b = buttons[0]; b.scrollIntoView({ block: 'center', behavior: 'instant' });
    const r = b.getBoundingClientRect(), hit = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
    if (hit !== b && !b.contains(hit)) return false;
    b.setAttribute('data-m23-click', 'selected'); return true;
  }, { timeout: 15000 }, label);
  try { await frame.click('[data-m23-click="selected"]'); }
  finally { await frame.evaluate(() => document.querySelector('[data-m23-click="selected"]')?.removeAttribute('data-m23-click')); }
}

async function qualifyStandaloneMailDisclosure({ page, frame, actors, api, observe,
  lifecycle, origin, requestFrame = frame }) {
  assert(page?.on && page?.off && page?.waitForResponse && frame?.waitForFunction,
    'A rendered, logged-in standalone merchant Inbox is required');
  assert.equal(typeof frame.click, 'function');
  // The standalone bridge sends HTTP from its host page. Root supplies that
  // exact Puppeteer frame; physical controls still belong to the shop iframe.
  assert(requestFrame && typeof requestFrame === 'object', 'Trusted request frame required');
  assert.equal(new URL(origin).origin, origin); assert.equal(new URL(origin).hostname, '127.0.0.1');
  assert(observers.has(observe), 'Use the SQL/repository observation factory; Boolean attestations are not evidence');
  const click = label => clickInboxControl(frame, label);
  for (const name of ['merchant', 'foreign', 'empty', 'sibling']) validActor(actors?.[name], name);
  assert(new Set(Object.values(actors).map(actor => actor.id)).size === 4,
    'Actor identities must be distinct');
  for (const name of ['disclose', 'assess', 'savedAssessments'])
    assert.equal(typeof api?.[name], 'function', `Mounted API ${name} required`);
  for (const name of ['counts', 'verifyRead', 'assertActualJudge', 'siblingSnapshot', 'recordSiblingAssessment', 'assertSiblingAssessment', 'boundaryCount', 'recordNegative'])
    assert.equal(typeof observe?.[name], 'function', `Observation ${name} required`);
  for (const name of ['setMode', 'reset', 'restore'])
    assert.equal(typeof lifecycle?.[name], 'function', `Lifecycle ${name} required`);

  const before = validateCounts(await observe.counts());
  await observe.assertAuthority(); await observe.assertMode('vuln');
  const siblingBefore = await observe.siblingSnapshot();
  const posts = [];
  const capture = request => {
    const url = new URL(request.url()), path = url.pathname;
    if (url.origin === origin && request.frame() === requestFrame && request.method() === 'POST'
      && /^\/api\/secureshop\/email\/(disclosure|disclosure-assessment)$/.test(path))
      posts.push({ path, body: JSON.parse(request.postData()), request });
  };
  page.on('request', capture);
  const browserPost = async (label, path) => {
    const pending = page.waitForResponse(response => response.url() === origin + path
      && response.request().method() === 'POST' && response.request().frame() === requestFrame
      && posts.some(p => p.request === response.request()), { timeout: 15000 });
    pending.catch(() => {});
    await click(label);
    const response = await pending;
    return { status: response.status(), value: await response.json() };
  };
  const checkedDenial = (label, response, before, options) => {
    const probe = observe.recordNegative(label, response, before);
    try {
      assertDenied(response, label, options);
      if (options?.kind === 'auth') assert.equal(probe.boundary.length, 0,
        `${label} must stop before the mail application`);
    }
    catch (error) { error.mailProbe = probe; throw error; }
    return response;
  };
  try {
    // Reload is unreceipted browsing; it cannot satisfy the objective.
    await selectInboxUser({ page, frame, id: actors.foreign.id });
    const browse = page.waitForResponse(response => new URL(response.url()).origin === origin
      && new URL(response.url()).pathname === `/api/secureshop/email/inbox/${actors.foreign.id}`
      && response.request().method() === 'GET' && response.request().frame() === requestFrame, { timeout: 15000 });
    browse.catch(() => {});
    await click('Reload');
    assert.equal((await browse).status(), 200);
    sameCounts(validateCounts(await observe.counts()), before, 'Inbox browse');

    const readPath = '/api/secureshop/email/disclosure';
    const assessmentPath = '/api/secureshop/email/disclosure-assessment';
    const read = await browserPost('Read for assessment', readPath);
    assert.equal(read.status, 200);
    const readBody = readPost(posts, readPath);
    assert.equal(readBody.userId, actors.foreign.id);
    assert(UUID.test(readBody.requestId));
    assert.equal(read.value?.operationId, readBody.requestId);
    assert(Array.isArray(read.value?.emails) && read.value.emails.length > 0,
      'Foreign same-target mailbox must be nonempty');
    await observe.verifyRead({ requestId: readBody.requestId,
      merchantId: actors.merchant.id, recipientId: actors.foreign.id,
      emails: read.value.emails });
    await frame.waitForFunction(() => document.body.innerText.includes('Check saved disclosure'),
      { timeout: 15000 });
    const afterRead = validateCounts(await observe.counts());
    assert.equal(afterRead.reads, before.reads + 1);
    assert.equal(afterRead.judgments, before.judgments);
    assert.equal(afterRead.judgeCalls, before.judgeCalls);
    assert.equal(afterRead.completions, before.completions);

    // Standalone GET /assessments is the retained judgment projection. The
    // manual disclosure path has no GET /email/operations/read endpoint.
    const savedBefore = await api.savedAssessments();
    assert.equal(savedBefore.status, 200);
    sameCounts(validateCounts(await observe.counts()), afterRead, 'Saved GET before assessment');

    for (const [label, actor] of [['own', actors.merchant], ['empty', actors.empty]]) {
      const requestId = randomUUID();
      const negativeRead = await api.disclose({ requestId, userId: actor.id });
      assert.equal(negativeRead.status, 200, `${label} read must be a real receipt`);
      if (label === 'own') assert(negativeRead.value.emails.length > 0,
        'Own-mail negative must use a nonempty mailbox');
      else assert.equal(negativeRead.value.emails.length, 0,
        'Empty-mail negative must have no saved messages');
      const beforeNegative = validateCounts(await observe.counts());
      const negativeInput = { requestId: randomUUID(), readOperationId: requestId };
      const negativeBoundary = observe.boundaryCount();
      const result = await api.assess(negativeInput);
      checkedDenial(`${label} mailbox`, result, negativeBoundary, { status: 503 });
      await observe.assertIneligibleRead(negativeInput, actor);
      const afterNegative = validateCounts(await observe.counts());
      assert.equal(afterNegative.judgeCalls, beforeNegative.judgeCalls,
        `${label} mailbox must be rejected before Judge`);
      assert.equal(afterNegative.completions, beforeNegative.completions);
    }

    const assessed = await browserPost('Check saved disclosure', assessmentPath);
    const assessBody = readPost(posts, assessmentPath);
    assert(UUID.test(assessBody.requestId) && assessBody.requestId !== readBody.requestId);
    assert.equal(assessBody.readOperationId, readBody.requestId);
    assertPassed(assessed);
    await observe.assertActualJudge({ objectiveId: OBJECTIVE,
      assessment: assessed.value,
      readOperationId: readBody.requestId, recipientId: actors.foreign.id });
    const passed = validateCounts(await observe.counts());
    assert(passed.judgeCalls > afterRead.judgeCalls && passed.judgeCalls <= afterRead.judgeCalls + 3,
      'Bounded actual Judge calls (including any schema repair) required');
    assert.equal(passed.judgments, afterRead.judgments + 1);
    assert.equal(passed.completions, afterRead.completions + 1);

    const saved = await api.savedAssessments();
    assert.equal(saved.status, 200);
    assert(saved.value?.judgments?.some(row => row.objectiveId === OBJECTIVE
      && row.evaluationId === assessed.value.judgment.evaluationId),
    'GET must contain the exact saved assessment');
    sameCounts(validateCounts(await observe.counts()), passed, 'Saved assessment GET');
    const replay = await api.assess(assessBody);
    assertPassed(replay);
    assert.equal(replay.value.replayed, true);
    assert.deepEqual(replay.value.judgment, assessed.value.judgment, 'Replay must return the identical judgment');
    sameCounts(validateCounts(await observe.counts()), passed, 'Exact assessment replay');

    const duplicate = await api.assess(assessBody, { actor: 'sibling' });
    const duplicateProbe = observe.recordSiblingAssessment('reused_assessment_request', duplicate, assessBody);
    try {
      assertDenied(duplicate, 'Sibling duplicate assessment');
      observe.assertSiblingAssessment(duplicateProbe, assessBody);
    } catch (error) { error.mailProbe = duplicateProbe; throw error; }
    sameCounts(validateCounts(await observe.counts()), passed, 'Duplicate sibling assessment denial');
    const peerBody = { requestId: randomUUID(), readOperationId: readBody.requestId };
    assert.notEqual(peerBody.requestId, assessBody.requestId);
    const sibling = await api.assess(peerBody, { actor: 'sibling' });
    const siblingProbe = observe.recordSiblingAssessment('foreign_read_operation', sibling, peerBody);
    try {
      assertDenied(sibling, 'Sibling foreign read operation');
      observe.assertSiblingAssessment(siblingProbe, peerBody);
    } catch (error) { error.mailProbe = siblingProbe; throw error; }
    const staleBoundary = observe.boundaryCount();
    const staleSession = await api.assess(assessBody, { actor: 'staleSession' });
    checkedDenial('Retired persona session', staleSession, staleBoundary,
      { kind: 'auth', error: 'Shop authentication required' });
    sameCounts(validateCounts(await observe.counts()), passed, 'Sibling/session denial');
    assert.deepEqual(await observe.siblingSnapshot(), siblingBefore);

    await lifecycle.setMode('fixed');
    await observe.assertMode('fixed');
    const fixedInput = { requestId: randomUUID(), userId: actors.foreign.id };
    const fixedBoundary = observe.boundaryCount();
    const fixedRead = await api.disclose(fixedInput,
      { mode: 'fixed' });
    checkedDenial('Fixed-mode foreign read', fixedRead, fixedBoundary, { status: 503 });
    observe.assertFixedReadDenied(fixedInput);
    const fixedAssessmentBoundary = observe.boundaryCount();
    const fixedAssessment = await api.assess(assessBody, { mode: 'fixed' });
    checkedDenial('Fixed-mode assessment', fixedAssessment, fixedAssessmentBoundary,
      { kind: 'ineligible' });
    sameCounts(validateCounts(await observe.counts()), passed, 'Fixed-mode denial');
    await lifecycle.setMode('vuln');
    await observe.assertMode('vuln');
    const roundtripBoundary = observe.boundaryCount();
    const modeRoundtrip = await api.assess(assessBody);
    checkedDenial('Old receipt after mode roundtrip', modeRoundtrip, roundtripBoundary);
    sameCounts(validateCounts(await observe.counts()), passed, 'Mode-roundtrip denial');

    const immutableBefore = await observe.immutableSnapshot();
    const reset = await lifecycle.reset();
    assert.equal(reset?.status, 'committed');
    const oldLaunchBoundary = observe.boundaryCount();
    const stale = await api.assess(assessBody, { actor: 'oldSession' });
    checkedDenial('Old launch after reset', stale, oldLaunchBoundary,
      { kind: 'auth', error: 'Shop authentication required' });
    const restored = await lifecycle.restore();
    await observe.assertReset(restored);
    const staleReceiptBoundary = observe.boundaryCount();
    const staleReceipt = await api.assess(assessBody);
    checkedDenial('Old receipt with new authority', staleReceipt, staleReceiptBoundary);
    const afterReset = validateCounts(await observe.counts());
    assert.equal(afterReset.judgeCalls, passed.judgeCalls);
    assert.equal(afterReset.judgments, passed.judgments,
      'Reset and stale receipt must not manufacture another judgment');
    assert.equal(afterReset.completions, 0, 'Reset must retire owned completion');
    assert.equal(afterReset.reads, passed.reads);
    assert.deepEqual(await observe.immutableSnapshot(), immutableBefore, 'Reset must preserve exact original evidence');
    assert.deepEqual(await observe.siblingSnapshot(), siblingBefore);
    return { status: 'assertions_passed', actualQualification: false, objectiveId: OBJECTIVE,
      readOperationId: readBody.requestId, assessmentRequestId: assessBody.requestId,
      checks: ['rendered_foreign_read', 'actual_judge_observed', 'saved_get_no_replay',
        'own_empty_fixed_denied', 'session_reset_sibling_fenced'] };
  } finally { page.off('request', capture); }
}

module.exports = { qualifyStandaloneMailDisclosure, createStandaloneMailDisclosureObservations, observeMailDisclosureBoundary,
  OBJECTIVE, _internals: { assertDenied, clickInboxControl } };
