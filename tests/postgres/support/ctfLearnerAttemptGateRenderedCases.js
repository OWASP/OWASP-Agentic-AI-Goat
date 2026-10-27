'use strict';
// A controlled rendered contract for the default three-attempt gate. A synthetic
// provider can exercise the mounted route, but cannot establish model credit.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const learnerA = require('./ctfLearnerEntryHintRenderedCases');
const content = require('./ctfRecoveryRenderedCases');

const PROFILE = 'ctf-learner-attempt-gate-q05';
const POST_PATHS = Object.freeze({ register: '/api/ctf/register',
  start: '/api/ctf/stage/1/start', hint: '/api/ctf/stage/1/hint',
  attempt: '/api/ctf/stage/1/attempt' });
const LIMITS = Object.freeze({ browserActions: 800, apiRequests: 800,
  deadlineMs: 360000, sameIdGets: 32, guardianCalls: 3, judgeCalls: 6,
  totalProviderCalls: 9 });
const EXCLUDED = Object.freeze(['actual-model-qualification',
  'guaranteed-secret-extraction', 'genuine-gameplay-credit',
  'fixed-practice', 'post-reset-credit']);
const FACTS = Object.freeze(['physicalJoinAndStart', 'defaultGateIsThree',
  'lockedHintBeforeAttempts', 'canonicalHintDenialBeforeAttempts',
  'threePhysicalScoredSubmissions', 'sameReferenceRecoveryNoResubmit',
  'gateUnlockOnlyAfterThirdAttempt', 'mountedSessionBound',
  'canonicalAttemptProjectionBound', 'nonemptySiblingUnchanged',
  'noActualModelOrGenuineCreditClaim']);
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const DECIMAL = /^[1-9][0-9]*$/;
const GENERATION = /^(0|[1-9][0-9]*)$/;
const exact = (value, keys) => {
  assert(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
};
const sha = value => createHash('sha256').update(value).digest('hex');

function createBrowserWorkTracker() {
  const pending = new Set(), failures = [], waits = new AbortController();
  const track = action => {
    let work;
    try { work = Promise.resolve(action()); } catch (error) { work = Promise.reject(error); }
    pending.add(work);
    void work.then(() => pending.delete(work), error => {
      pending.delete(work); failures.push(error);
    });
    return work;
  };
  return { track, signal: waits.signal,
    abortWaiters: () => waits.abort(new Error('Owned browser waiter retired')),
    pendingCount: () => pending.size,
    async drain(timeoutMs = 5000) {
      const end = Date.now() + timeoutMs;
      while (pending.size) {
        const left = end - Date.now();
        if (left <= 0) throw new Error('Owned browser work did not settle');
        let timer;
        try { await Promise.race([Promise.allSettled([...pending]),
          new Promise((_, reject) => { timer = setTimeout(() =>
            reject(new Error('Owned browser work did not settle')), left); })]);
        } finally { clearTimeout(timer); }
      }
      if (failures.length) throw new AggregateError(failures,
        'Owned browser asynchronous work failed');
    } };
}

function assertDatabaseName(pathname, state, kind, nonce = null) {
  assert(['FRESH', 'POPULATED'].includes(state));
  assert(['IDENTITY', 'CTF'].includes(kind));
  const match = pathname.match(new RegExp(
    `^/dvaia_test_ctf_learner_attempt_gate_${state[0].toLowerCase()}_${kind[0].toLowerCase()}_([a-f0-9]{12})$`));
  assert(match, 'Exact disposable scored learner database name required');
  if (nonce !== null) assert.equal(match[1], nonce);
  return match[1];
}

function assertGateProgression(gate) {
  exact(gate, ['configured', 'initialAttempts', 'initialHintVisible',
    'deniedStatus', 'deniedError', 'deniedOutboxDelta',
    'deniedProgressUnchanged', 'deniedProviderCalls', 'afterAttempts',
    'afterThirdHintVisible']);
  assert.equal(gate.configured, 3);
  assert.equal(gate.initialAttempts, 0);
  assert.equal(gate.initialHintVisible, false);
  assert.equal(gate.deniedStatus, 409);
  assert.equal(gate.deniedError, 'Hint availability changed; refresh stage status');
  assert.equal(gate.deniedOutboxDelta, 0);
  assert.equal(gate.deniedProgressUnchanged, true);
  assert.equal(gate.deniedProviderCalls, 0);
  assert.deepEqual(gate.afterAttempts, [
    { count: 1, hintVisible: false, status: 'in_progress' },
    { count: 2, hintVisible: false, status: 'in_progress' },
    { count: 3, hintVisible: true, status: 'in_progress' },
  ]);
  assert.equal(gate.afterThirdHintVisible, true);
  return true;
}

function assertAttempt(attempt, ordinal) {
  exact(attempt, ['ordinal', 'runId', 'admissionId', 'decisionId',
    'requestStatus', 'publicationStatus', 'verdict', 'accepted',
    'guardianCalls', 'judgeCalls', 'sameIdGets', 'recoveryResumePosts',
    'recoveryAuthorizePosts', 'ownerSessionBound',
    'decisionApplied', 'publicationCurrent', 'noProviderReplay']);
  assert.equal(attempt.ordinal, ordinal);
  for (const key of ['runId', 'admissionId', 'decisionId'])
    assert.match(attempt[key], UUID);
  assert.equal(attempt.requestStatus, 202);
  assert.equal(attempt.publicationStatus, 200);
  assert.equal(attempt.verdict, 'fail');
  assert.equal(attempt.accepted, false);
  assert.equal(attempt.guardianCalls, 1);
  assert(Number.isSafeInteger(attempt.judgeCalls) && attempt.judgeCalls >= 1 &&
    attempt.judgeCalls <= 2);
  assert(Number.isSafeInteger(attempt.sameIdGets) && attempt.sameIdGets >= 1 &&
    attempt.sameIdGets <= LIMITS.sameIdGets);
  for (const key of ['recoveryResumePosts', 'recoveryAuthorizePosts'])
    assert(Number.isSafeInteger(attempt[key]) && attempt[key] >= 0 &&
      attempt[key] <= 1);
  for (const key of ['ownerSessionBound', 'decisionApplied',
    'publicationCurrent', 'noProviderReplay']) assert.equal(attempt[key], true);
}

function assertResetFence(reset) {
  exact(reset, ['operationId', 'sequence', 'originalStatus',
    'deniedStatus', 'deniedError', 'generationBefore', 'generationAfter']);
  assert.match(reset.operationId, UUID);
  assert.match(reset.sequence, DECIMAL);
  assert([200, 202].includes(reset.originalStatus));
  assert.equal(reset.deniedStatus, 409);
  assert.equal(reset.deniedError, 'CTF request is no longer current');
  assert.match(reset.generationBefore, GENERATION);
  assert.match(reset.generationAfter, DECIMAL);
  assert.equal(BigInt(reset.generationAfter), BigInt(reset.generationBefore) + 1n);
  return true;
}

function assertControlledReceipt(receipt) {
  exact(receipt, ['version', 'profile', 'transport', 'actorId', 'sessionId',
    'participantId', 'stageId', 'siblingOwnerId', 'gate', 'attempts',
    'browserPosts', 'serverPosts', 'lifecycle', 'reset',
    'providerCalls', 'storeWitness', 'facts',
    'excluded', 'unexpectedApiPaths', 'browserActions', 'apiRequests',
    'genuineCredit', 'stage']);
  assert.equal(receipt.version, 1);
  assert.equal(receipt.profile, PROFILE);
  assert.equal(receipt.transport, 'controlled-synthetic');
  for (const key of ['actorId', 'sessionId', 'participantId'])
    assert.match(receipt[key], DECIMAL);
  assert.equal(receipt.actorId, '2402',
    'Receipt must name the one pre-bootstrap synthetic learner');
  assert.notEqual(receipt.participantId, '1001');
  assert.equal(receipt.stageId, 1);
  assert.equal(receipt.siblingOwnerId, 1001);
  assertGateProgression(receipt.gate);
  assert(Array.isArray(receipt.attempts) && receipt.attempts.length === 3);
  receipt.attempts.forEach((attempt, index) => assertAttempt(attempt, index + 1));
  for (const key of ['runId', 'admissionId', 'decisionId'])
    assert.equal(new Set(receipt.attempts.map(value => value[key])).size, 3);
  exact(receipt.browserPosts, ['register', 'start', 'attempt', 'hint',
    'resume', 'authorize']);
  assert.equal(receipt.browserPosts.register, 1);
  assert.equal(receipt.browserPosts.start, 1);
  assert.equal(receipt.browserPosts.attempt, 3);
  assert.equal(receipt.browserPosts.hint, 0);
  for (const [key, field] of [['resume', 'recoveryResumePosts'],
    ['authorize', 'recoveryAuthorizePosts']])
    assert.equal(receipt.browserPosts[key], receipt.attempts.reduce(
      (sum, value) => sum + value[field], 0));
  exact(receipt.serverPosts, ['register', 'start', 'attempt', 'hint',
    'resume', 'authorize']);
  assert.deepEqual(receipt.serverPosts, { ...receipt.browserPosts, hint: 1 },
    'The one direct denied hint is separate from physical browser posts');
  exact(receipt.lifecycle, ['register', 'start']);
  for (const kind of ['register', 'start']) {
    const value = receipt.lifecycle[kind];
    exact(value, ['operationId', 'sequence', 'originalStatus']);
    assert.match(value.operationId, UUID);
    assert.match(value.sequence, DECIMAL);
    assert([200, 202].includes(value.originalStatus));
  }
  assert.notEqual(receipt.lifecycle.register.operationId,
    receipt.lifecycle.start.operationId);
  assert(BigInt(receipt.lifecycle.register.sequence) <
    BigInt(receipt.lifecycle.start.sequence));
  assertResetFence(receipt.reset);
  assert(BigInt(receipt.lifecycle.start.sequence) <
    BigInt(receipt.reset.sequence));
  exact(receipt.providerCalls, ['guardian', 'judge', 'total']);
  assert.equal(receipt.providerCalls.guardian, 3);
  assert.equal(receipt.providerCalls.judge,
    receipt.attempts.reduce((sum, value) => sum + value.judgeCalls, 0));
  assert(receipt.providerCalls.judge >= 3 &&
    receipt.providerCalls.judge <= LIMITS.judgeCalls);
  assert.equal(receipt.providerCalls.total,
    receipt.providerCalls.guardian + receipt.providerCalls.judge);
  assert(receipt.providerCalls.total <= LIMITS.totalProviderCalls);
  exact(receipt.storeWitness, ['progressAttemptsThree', 'threeAttemptRows',
    'threeJudgmentRows', 'noCompletion', 'noHintPurchased',
    'identityBindingCurrent', 'siblingBeforeNonempty', 'siblingUnchanged',
    'resetReferenceFenced', 'historicalEvidenceRetained']);
  for (const value of Object.values(receipt.storeWitness)) assert.equal(value, true);
  exact(receipt.facts, FACTS);
  for (const value of Object.values(receipt.facts)) assert.equal(value, true);
  assert.deepEqual(receipt.excluded, [...EXCLUDED]);
  assert.deepEqual(receipt.unexpectedApiPaths, []);
  for (const [key, max] of [['browserActions', LIMITS.browserActions],
    ['apiRequests', LIMITS.apiRequests]])
    assert(Number.isSafeInteger(receipt[key]) && receipt[key] > 0 &&
      receipt[key] <= max);
  assert.equal(receipt.genuineCredit, 0);
  assert.equal(receipt.stage, 'complete');
  return true;
}

function assertDefaultHintDenial(before, after, response, providerBefore,
  providerAfter) {
  assert.equal(response.status, 409);
  assert.deepEqual(response.body,
    { error: 'Hint availability changed; refresh stage status' });
  assert.equal(before.outboxCount, after.outboxCount);
  assert.deepEqual(after.progress, before.progress);
  assert.deepEqual(after.hintReceipts, before.hintReceipts);
  assert.equal(providerAfter, providerBefore);
  return true;
}

function countProviderCalls(entries) {
  assert(Array.isArray(entries));
  const guardian = entries.filter(value => value.route === '/api/generate').length;
  const judge = entries.filter(value => value.route === '/api/chat').length;
  assert.equal(entries.length, guardian + judge,
    'No defense-reviewer, unknown provider, or failed uncounted entry');
  assert(guardian <= LIMITS.guardianCalls && judge <= LIMITS.judgeCalls &&
    entries.length <= LIMITS.totalProviderCalls);
  return { guardian, judge, total: entries.length };
}

function reserveScoredProvider(entries, route, mode) {
  assert(Array.isArray(entries));
  assert.equal(mode, 'fail', 'Controlled gate proof cannot manufacture completion');
  assert(['/api/generate', '/api/chat'].includes(route),
    'Only original Stage-1 guardian and Objective Judge are admitted');
  const current = countProviderCalls(entries);
  assert(current.total < LIMITS.totalProviderCalls);
  if (route === '/api/generate') assert(current.guardian < LIMITS.guardianCalls);
  else assert(current.judge < LIMITS.judgeCalls);
  const entry = { route, mode, model: null, settlement: 'started' };
  entries.push(entry); // Synchronous reservation precedes body reads and provider work.
  return entry;
}

function assertRetiredCounts(receipt, browserPosts, serverPosts,
  apiRequests, providerCalls, unexpectedApiPaths) {
  assert.deepEqual(browserPosts, receipt.browserPosts,
    'No late physical POST may follow the final state snapshot');
  assert.deepEqual(serverPosts, receipt.serverPosts,
    'No late server POST may follow the final state snapshot');
  assert.equal(apiRequests, receipt.apiRequests,
    'No late API request may follow the final state snapshot');
  assert.deepEqual(providerCalls, receipt.providerCalls,
    'No late provider call may follow the final state snapshot');
  assert.deepEqual(unexpectedApiPaths, []);
  return true;
}

function assertScoredAttemptBody(raw, expectedPayload, registeredDigest,
  mountedDigest = null) {
  let body;
  try { body = JSON.parse(raw); }
  catch { assert.fail('Physical scored request body must be valid JSON'); }
  exact(body, ['payload', 'sessionToken']);
  assert.equal(sha(body.payload), sha(expectedPayload),
    'Physical scored payload bytes must match the typed input');
  assert(typeof body.sessionToken === 'string' &&
    body.sessionToken.length > 0 && body.sessionToken.isWellFormed() &&
    !body.sessionToken.includes('\0') &&
    Buffer.byteLength(body.sessionToken) <= 256,
  'A bounded mounted UI locator is required');
  const digest = sha(body.sessionToken);
  assert.notEqual(digest, registeredDigest,
    'Route-owner locator and server registration locator are distinct');
  if (mountedDigest !== null) assert.equal(digest, mountedDigest,
    'Three scored submissions must retain one mounted route owner');
  return digest;
}

function assertDurableScoredLocator(rows, runId, ownerId, sessionId, digest) {
  assert.deepEqual(rows, [{ run_id: runId, owner_id: String(ownerId),
    session_id: String(sessionId), locator_sha256: digest }],
  'The mounted UI locator must be durably bound to this exact run and principal');
  return true;
}

// A 202 may precede admission and decision creation. Only the mounted page's
// observed same-run recovery may supply those later references.
function assertObservedAttemptRecovery(pending, events) {
  exact(pending, ['success', 'pending', 'runId', 'operationId',
    'admissionId', 'decisionId']);
  assert.equal(pending.success, false);
  assert.equal(pending.pending, true);
  assert.match(pending.runId, UUID);
  for (const key of ['operationId', 'admissionId', 'decisionId'])
    assert(pending[key] === null || UUID.test(pending[key]));
  assert(Array.isArray(events) && events.length > 0 && events.length <= 84);
  const admissions = new Set(pending.admissionId ? [pending.admissionId] : []);
  const decisions = new Set(pending.decisionId ? [pending.decisionId] : []);
  const publications = [];
  let predefenseReads = 0, decisionReads = 0;
  const resumePaths = [], authorizePaths = [];
  for (const event of events) {
    exact(event, ['path', 'status', 'body']);
    if (event.path === `/api/ctf/predefense/${pending.runId}`) {
      predefenseReads++;
      if (event.status === 202) {
        assert.deepEqual(event.body, { version: 1, state: 'recovery_pending',
          runId: pending.runId, currentCompletion: false });
        continue;
      }
      assert.equal(event.status, 200);
      exact(event.body, ['version', 'state', 'runId', 'admissionId',
        'blockedOperationId', 'decisionId', 'currentCompletion']);
      assert.equal(event.body.version, 1);
      assert.equal(event.body.runId, pending.runId);
      assert.equal(event.body.currentCompletion, false);
      if (event.body.admissionId !== null) {
        assert.match(event.body.admissionId, UUID);
        admissions.add(event.body.admissionId);
      }
      if (event.body.decisionId !== null) {
        assert.match(event.body.decisionId, UUID);
        decisions.add(event.body.decisionId);
      }
    } else if (/^\/api\/ctf\/decisions\/[a-f0-9-]+$/.test(event.path)) {
      decisionReads++;
      assert.equal(event.status, 200);
      const admissionId = event.path.slice('/api/ctf/decisions/'.length);
      assert.match(admissionId, UUID);
      assert(admissions.has(admissionId),
        'Decision recovery must use a reference from the same-run response');
      assert.equal(event.body?.admissionId, admissionId);
      if (event.body.decisionId !== undefined && event.body.decisionId !== null) {
        assert.match(event.body.decisionId, UUID);
        decisions.add(event.body.decisionId);
      }
    } else if (/^\/api\/ctf\/publications\/[a-f0-9-]+$/.test(event.path)) {
      const decisionId = event.path.slice('/api/ctf/publications/'.length);
      assert.match(decisionId, UUID);
      assert(decisions.has(decisionId),
        'Publication must use a decision from a prior same-run response');
      publications.push({ decisionId, status: event.status });
    } else if (/^\/api\/ctf\/predefense\/[a-f0-9-]+\/resume$/.test(event.path)) {
      resumePaths.push(event.path);
      assert.equal(event.path, `/api/ctf/predefense/${pending.runId}/resume`);
      assert([200, 202].includes(event.status));
    } else if (/^\/api\/ctf\/decisions\/[a-f0-9-]+\/authorize$/.test(event.path)) {
      authorizePaths.push(event.path);
      assert([200, 202].includes(event.status));
    } else assert.fail('Unexpected browser recovery reference');
  }
  const directDecision = pending.admissionId === null && pending.decisionId !== null;
  if (pending.admissionId === null && !directDecision) assert(predefenseReads >= 1,
    'An early pending run without a decision needs a physical same-run predefense read');
  if (pending.decisionId === null) assert(predefenseReads + decisionReads >= 1,
    'The browser must observe a later decision reference');
  if (directDecision) {
    // The mounted recovery client prioritizes an initial decision reference:
    // it reads current publication directly and does not invent an admission
    // GET. The admission is joined independently from this exact run and
    // decision in the durable proposal/admission tables below.
    assert.equal(predefenseReads + decisionReads, 0,
      'A direct-decision recovery cannot borrow a different reference path');
    assert.equal(admissions.size, 0);
    assert.equal(resumePaths.length, 0);
    assert.equal(authorizePaths.length, 0);
  } else assert.equal(admissions.size, 1, 'One observed admission must bind the pending run');
  assert.equal(decisions.size, 1, 'One decision must bind the pending run');
  assert(resumePaths.length <= 1 && authorizePaths.length <= 1,
    'One explicit recovery mutation per exact reference at most');
  assert(authorizePaths.every(value =>
    value === `/api/ctf/decisions/${[...admissions][0]}/authorize`));
  assert(publications.some(value => value.status === 200),
    'The browser must observe current publication');
  assert(publications.every(value => value.decisionId === [...decisions][0]));
  return { runId: pending.runId, admissionId: [...admissions][0] ?? null,
    decisionId: [...decisions][0], publicationStatus: 200,
    sameIdGets: publications.length,
    recoveryResumePosts: resumePaths.length,
    recoveryAuthorizePosts: authorizePaths.length };
}

function boundedRecoveryFailureTrail(ordinal, pending, events) {
  assert(Number.isInteger(ordinal) && ordinal >= 1 && ordinal <= 3);
  const reference = value => typeof value === 'string' && UUID.test(value) ? value : null;
  const safePath = value => typeof value === 'string' &&
    /^\/api\/ctf\/(?:predefense\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?:\/resume)?|decisions\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?:\/authorize)?|publications\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$/.test(value)
    ? value : null;
  assert(Array.isArray(events));
  return { version: 1, profile: PROFILE, stage: 'attempt-recovery-incomplete',
    ordinal, initial: { runId: reference(pending?.runId),
      admissionId: reference(pending?.admissionId),
      decisionId: reference(pending?.decisionId) },
    observed: events.slice(0, 84).map(value => ({ path: safePath(value?.path),
      status: Number.isInteger(value?.status) && value.status >= 100 &&
        value.status <= 599 ? value.status : null })) };
}

function assertDirectDecisionDurableBinding({ pending, settled, proposal,
  admission, decision, locator, ownerId, sessionId, participantId }) {
  assert.equal(settled.admissionId, null);
  assert.equal(pending.decisionId, settled.decisionId);
  assert.match(proposal.admission_operation_id, UUID);
  assert.equal(proposal.run_id, settled.runId);
  assert.equal(proposal.owner_id, String(ownerId));
  assert.equal(proposal.session_id, String(sessionId));
  assert.equal(admission.operation_id, proposal.admission_operation_id);
  assert.equal(admission.owner_id, String(ownerId));
  assert.equal(admission.participant_id, String(participantId));
  assert.equal(admission.stage_id, '1');
  assert.equal(decision.decision_id, settled.decisionId);
  assert.equal(decision.proposal_id, proposal.proposal_id);
  assert.equal(decision.run_id, settled.runId);
  assert.equal(decision.owner_id, String(ownerId));
  assert.equal(decision.session_id, String(sessionId));
  assert.equal(locator.run_id, settled.runId);
  assert.equal(locator.owner_id, String(ownerId));
  assert.equal(locator.session_id, String(sessionId));
  return proposal.admission_operation_id;
}

function assertRecoveryMutationPosts(rows, settled, bearer) {
  exact(rows, ['resume', 'authorize']);
  for (const [kind, reference] of [['resume', settled.runId],
    ['authorize', settled.admissionId]]) {
    assert(Array.isArray(rows[kind]) && rows[kind].length ===
      settled[kind === 'resume' ? 'recoveryResumePosts' : 'recoveryAuthorizePosts']);
    const expected = kind === 'resume'
      ? `/api/ctf/predefense/${reference}/resume`
      : `/api/ctf/decisions/${reference}/authorize`;
    for (const row of rows[kind]) {
      exact(row, ['path', 'bearer', 'body']);
      assert.equal(row.path, expected);
      assert.equal(sha(row.bearer), sha(bearer));
      assert.deepEqual(JSON.parse(row.body), {});
    }
  }
  return true;
}

const APP_READS = new Set(['/api/auth/status', '/api/auth/signup-config',
  '/api/changes/revisions', '/api/workshop/challenges',
  '/api/workshop/time/summary', '/api/workshop/config',
  '/api/workshop/config/snapshot', '/api/workshop/config/revision',
  '/api/ctf/config', '/api/ctf/stages', '/api/ctf/status',
  '/api/ctf/leaderboard']);
function browserAllowed(method, pathname) {
  if (method === 'POST') return Object.values(POST_PATHS)
    .filter(value => value !== POST_PATHS.hint).includes(pathname) ||
    /^\/api\/ctf\/(?:predefense|decisions)\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\/(?:resume|authorize)$/.test(pathname);
  return method === 'GET' && (APP_READS.has(pathname) ||
    /^\/api\/ctf\/(?:operations|predefense|decisions|publications|blocked-publications)\/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(pathname));
}

function physicalLockedHintState() {
  const visible = node => Boolean(node?.getClientRects().length);
  return {
    scoredInputReady: visible(document.querySelector(
      'textarea[placeholder="Enter your prompt injection attempt..."]:not(:disabled)')),
    lockedNoticeVisible: [...document.querySelectorAll('p')].some(node =>
      visible(node) && node.textContent.replace(/\s+/g, ' ').trim() ===
      'Hints unlock after 3 attempts.'),
    unlockedButtonVisible: [...document.querySelectorAll('button')].some(button =>
      visible(button) && button.textContent.includes('Unlock Hint 1')),
  };
}

function physicalLockedHintReady() {
  const state = physicalLockedHintState();
  return state.scoredInputReady && state.lockedNoticeVisible &&
    !state.unlockedButtonVisible;
}

async function runControlledRenderedCases({ state, i, c, ledger, web, origin,
  jwtSecret, contentHttp, request, userRequest, admin, serverCounts }) {
  assert.equal(process.env.CTF_LEARNER_ATTEMPT_GATE_RENDERED_ISOLATED, '1');
  const runtime = fs.realpathSync(process.env.CTF_CONTENT_RUNTIME_DIRECTORY);
  const receiptPath = path.resolve(process.env.CTF_LEARNER_ATTEMPT_GATE_Q05_RECEIPT);
  assert.equal(receiptPath, path.join(runtime, 'ctf-learner-attempt-gate-q05-result.json'));
  if (state === 'POPULATED') {
    learnerA.assertPrivateReceipt(receiptPath);
    const earlier = JSON.parse(fs.readFileSync(receiptPath, 'utf8'));
    assertControlledReceipt(earlier);
    assert.deepEqual(countProviderCalls(ledger), earlier.providerCalls,
      'POPULATED migration cannot rerun an attempt');
    return;
  }
  assert.equal(state, 'FRESH'); assert.equal(fs.existsSync(receiptPath), false);
  const evidence = fs.realpathSync(process.env.CTF_RENDERED_EVIDENCE);
  const prior = {};
  for (const [key, value] of Object.entries({
    IDENTITY_DATABASE_URL: process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_RUNTIME_URL,
    IDENTITY_MIGRATION_DATABASE_URL: process.env.PG_CTF_AUTHORITY_APPLICATION_FRESH_IDENTITY_MIGRATION_URL,
    JWT_SECRET: jwtSecret,
  })) { prior[key] = process.env[key]; process.env[key] = value; }
  let mounted, browser, pages, page, primary, receipt;
  const unexpected = [], seen = { register: [], start: [], attempt: [],
    hint: [], resume: [], authorize: [] };
  const responses = [], recoveryResponses = [];
  const browserWork = createBrowserWorkTracker();
  const beforeServer = serverCounts(), beforeApi = contentHttp.apiRequests;
  const startedAt = Date.now(); let actions = 0;
  const active = () => { assert(actions <= LIMITS.browserActions);
    assert(Date.now() - startedAt <= LIMITS.deadlineMs); countProviderCalls(ledger); };
  const action = async fn => { actions++; active(); return fn(); };
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  const maxSequence = async () => (await i.migration.query(
    'SELECT COALESCE(max(sequence),0)::text AS value FROM identity.ctf_outbox')).rows[0].value;
  const progress = async participantId => (await c.runtime.query(`SELECT id::text,
    participant_id::text,stage_id,status,attempts_count,hints_used,hint_penalty_total
    FROM ctf.ctf_progress WHERE participant_id=$1 AND stage_id=1`,
  [participantId])).rows;
  const snapshotDenied = async participantId => ({
    outboxCount: (await i.migration.query(
      "SELECT count(*)::int AS n FROM identity.ctf_outbox WHERE kind='hint'" )).rows[0].n,
    progress: await progress(participantId),
    hintReceipts: (await c.runtime.query(
      "SELECT operation_id::text FROM ctf.projection_receipts WHERE kind='hint' ORDER BY sequence" )).rows,
  });
  const sibling = async () => ({
    progress: (await c.runtime.query('SELECT to_jsonb(t)::text AS row FROM ctf.ctf_progress t WHERE participant_id=1001 ORDER BY id')).rows,
    attempts: (await c.runtime.query('SELECT to_jsonb(t)::text AS row FROM ctf.ctf_attempts t WHERE participant_id=1001 ORDER BY id')).rows,
    sessions: (await c.runtime.query('SELECT to_jsonb(t)::text AS row FROM ctf.ctf_sessions t WHERE participant_id=1001 ORDER BY id')).rows,
  });
  const waitUntil = async (predicate, label) => {
    const until = Date.now() + 15000;
    while (Date.now() < until) { active(); const value = await predicate();
      if (value) return value; await pause(100); }
    assert.fail(`${label} bounded observation missing`);
  };
  const responseFor = pathname => browserWork.track(() => page.waitForResponse(value =>
    new URL(value.url()).origin === origin &&
    new URL(value.url()).pathname === pathname &&
    value.request().method() === 'POST', { timeout: 15000, signal: browserWork.signal }));
  const pointer = async handle => { try {
    await content.contentPointerClick(page, handle, action);
  } finally { await handle.dispose(); } };
  const handle = fn => action(() => page.waitForFunction(fn,
    { timeout: 15000, polling: 100 }));
  const pageRequest = value => { browserWork.track(() => {
    const url = new URL(value.url());
    if (['data:', 'blob:', 'about:'].includes(url.protocol)) return value.continue();
    if (url.origin !== origin) { unexpected.push('external'); return value.abort(); }
    if ((url.pathname.startsWith('/api/') || value.method() !== 'GET') &&
      !browserAllowed(value.method(), url.pathname)) {
      unexpected.push(`${value.method()} ${url.pathname}`); return value.abort();
    }
    if (url.pathname.startsWith('/api/ctf/') && value.method() === 'POST') {
      for (const [kind, pathname] of Object.entries(POST_PATHS))
        if (url.pathname === pathname) seen[kind].push({
          bearer: value.headers().authorization || null,
          body: value.postData() || '' });
      if (/^\/api\/ctf\/predefense\/[a-f0-9-]+\/resume$/.test(url.pathname))
        seen.resume.push({ path: url.pathname,
          bearer: value.headers().authorization || null,
          body: value.postData() || '' });
      if (/^\/api\/ctf\/decisions\/[a-f0-9-]+\/authorize$/.test(url.pathname))
        seen.authorize.push({ path: url.pathname,
          bearer: value.headers().authorization || null,
          body: value.postData() || '' });
    }
    return value.continue();
  }); };
  const pageResponse = value => { const url = new URL(value.url());
    if (url.origin === origin && url.pathname.startsWith('/api/ctf/')) {
      responses.push({ path: url.pathname, status: value.status() });
      if (/^\/api\/ctf\/(?:predefense|decisions|publications)\//.test(url.pathname))
        recoveryResponses.push({ path: url.pathname, status: value.status(),
          body: browserWork.track(() => value.json()).catch(() => null) });
    } };
  try {
    await require('../../../server/database/postgres/workshopPlatformSeed')
      .seedWorkshopPlatform(i.migration);
    const adapter = require('../../../server/services/postgresIdentityAdapter')
      .getPostgresIdentityAdapter();
    const stores = require('../../../server/services/postgresPlatformStores')
      .getPostgresPlatformStores();
    mounted = await require('../../fixtures/legacyFileSsiFullAppParity')
      .mountLegacyParityRoutes({ app: web, adapter, pool: i.runtime,
        migration: i.migration, progress: stores.progress,
        config: stores.config, identity: adapter.repository });
    const learnerId = 2402;
    assert.equal((await i.runtime.query(`SELECT count(*)::int AS n FROM
      identity.users WHERE id=$1 AND username=$2 AND role='student'`,
    [learnerId, 'learner-attempt-gate-2402'])).rows[0].n, 1,
    'Pre-bootstrap synthetic learner must already exist');
    const learner = await userRequest(learnerId);
    const authority = await adapter.validateSession(learner.headers.authorization.slice(7));
    assert.equal(authority?.user?.id, learnerId);
    assert.equal(String(authority?.session?.id), String(learner.identitySession.id));
    const gate = (await c.runtime.query(
      "SELECT value FROM ctf.ctf_config WHERE key='ctf_hint_gating_attempts'")).rows;
    assert.deepEqual(gate, [{ value: '3' }], 'Original default hint gate required');
    const siblingBefore = await sibling();
    assert(siblingBefore.progress.length && siblingBefore.attempts.length &&
      siblingBefore.sessions.length, 'Nonempty peer evidence required');
    const report = JSON.parse(fs.readFileSync(process.env.CTF_CONTENT_BUILD_REPORT, 'utf8'));
    const root = path.resolve(__dirname, '../../..');
    const build = fs.realpathSync(process.env.CTF_CONTENT_BUILD_DIRECTORY);
    assert.equal(build, report.inputMode === 'private-external-v1'
      ? fs.realpathSync(report.outputRoot) : path.join(root, 'client/build'));
    assert(fs.existsSync(path.join(build, 'index.html')));
    web.use('/api', (_req, res) => res.status(404).json({ error: 'Unmapped learner API' }));
    web.use(require('express').static(build));
    web.get('/{*path}', (_req, res) => res.sendFile(path.join(build, 'index.html')));
    browser = await require('../../fixtures/ctfTenContentBrowserAdmission')
      .launchCtfLearnerAttemptGateBrowser(evidence, 'attemptGate');
    pages = content.contentActorPages(browser); page = await pages.newPage();
    await page.setViewport({ width: 1280, height: 900 });
    await page.setRequestInterception(true);
    page.on('request', pageRequest); page.on('response', pageResponse);
    await action(() => page.evaluateOnNewDocument(token =>
      localStorage.setItem('token', token), learner.headers.authorization.slice(7)));
    await action(() => page.goto(origin + '/ctf', { waitUntil: 'domcontentloaded' }));
    const registerBefore = await maxSequence();
    const registerReply = responseFor(POST_PATHS.register);
    await pointer(await handle(learnerA.joinButton));
    const registerResponse = await registerReply;
    assert([200, 202].includes(registerResponse.status()));
    const registered = await learnerA.outboxFor(i, c, registerBefore, 'register',
      String(learnerId), String(learner.identitySession.id));
    assert.equal(seen.register.length, 1);
    assert.equal(sha(seen.register[0].bearer), sha(learner.headers.authorization));
    assert.deepEqual(Object.keys(JSON.parse(seen.register[0].body)), ['displayName']);
    const registeredLocator = JSON.parse(registered.canonical_command)
      .body.teachingSessionToken;
    assert(typeof registeredLocator === 'string' &&
      /^[a-f0-9]{64}$/.test(registeredLocator));
    const registeredDigest = sha(registeredLocator);
    const participant = (await c.runtime.query(
      'SELECT id::text FROM ctf.ctf_participants WHERE user_id=$1 AND is_active=1',
      [learnerId])).rows;
    assert.equal(participant.length, 1);
    const participantId = participant[0].id;
    assert.equal((await c.runtime.query(`SELECT count(*)::int AS n FROM
      ctf.ctf_sessions WHERE participant_id=$1 AND session_token=$2 AND is_active=1`,
    [participantId, registeredLocator])).rows[0].n, 1,
    'The server registration locator must be owned by the actual participant');
    const startBefore = await maxSequence();
    const startReply = responseFor(POST_PATHS.start);
    await pointer(await handle(learnerA.stageOneCard));
    const startResponse = await startReply;
    assert([200, 202].includes(startResponse.status()));
    const started = await learnerA.outboxFor(i, c, startBefore, 'start',
      String(learnerId), String(learner.identitySession.id), participantId, 1);
    assert.equal(seen.start.length, 1);
    assert.equal(sha(seen.start[0].bearer), sha(learner.headers.authorization));
    assert.deepEqual(JSON.parse(seen.start[0].body), {});
    const initial = await progress(participantId);
    assert.equal(initial.length, 1); assert.equal(initial[0].attempts_count, 0);
    try {
      await waitUntil(async () => {
        const ui = await action(() => page.evaluate(physicalLockedHintState));
        return ui.scoredInputReady && ui.lockedNoticeVisible &&
          !ui.unlockedButtonVisible;
      }, 'physical default hint gate');
    } catch (error) {
      // Only finite UI booleans and relevant HTTP status codes are retained.
      // Never serialize DOM text, bearer tokens, payloads, or model content.
      let ui = { probeUnavailable: true };
      try { ui = await action(() => page.evaluate(physicalLockedHintState)); }
      catch { /* Preserve the original readiness failure. */ }
      const statuses = responses.filter(value =>
        ['/api/ctf/config', '/api/ctf/stages', '/api/ctf/status',
          POST_PATHS.start].includes(value.path))
        .slice(-12).map(value => ({ path: value.path, status: value.status }));
      throw new Error(`Physical default hint gate readiness failed: ${JSON.stringify({ ui, statuses })}`,
        { cause: error });
    }
    const deniedBefore = await snapshotDenied(participantId);
    const deniedCalls = ledger.length;
    const denied = await request('POST', '/stage/1/hint', learner,
      { hintIndex: 0 });
    assertDefaultHintDenial(deniedBefore, await snapshotDenied(participantId),
      denied, deniedCalls, ledger.length);
    const attempts = [], afterAttempts = [], initialSession = learner.identitySession.id;
    let mountedLocatorDigest = null;
    for (let ordinal = 1; ordinal <= 3; ordinal++) {
      const responseStart = responses.length;
      const recoveryStart = recoveryResponses.length;
      const resumeStart = seen.resume.length, authorizeStart = seen.authorize.length;
      const input = await handle(() => document.querySelector(
        'textarea[placeholder="Enter your prompt injection attempt..."]:not(:disabled)'));
      await action(() => input.type(`Ordinary controlled stage-one question ${ordinal}`));
      await input.dispose();
      const beforeCalls = countProviderCalls(ledger);
      const reply = responseFor(POST_PATHS.attempt);
      await pointer(await handle(() => document.querySelector(
        'button[aria-label="Send attempt"]:not(:disabled)')));
      const attempted = await reply;
      assert.equal(attempted.status(), 202);
      assert.equal(seen.attempt.length, ordinal,
        'Exactly one physical scored request per visible submission');
      assert.equal(sha(seen.attempt[ordinal - 1].bearer),
        sha(learner.headers.authorization));
      mountedLocatorDigest = assertScoredAttemptBody(
        seen.attempt[ordinal - 1].body,
        `Ordinary controlled stage-one question ${ordinal}`,
        registeredDigest, mountedLocatorDigest);
      const pending = await attempted.json();
      assert.match(pending.runId, UUID);
      let lastCheckCount = -1, checks = 0;
      const published = await waitUntil(async () => {
        const current = responses.slice(responseStart).find(value =>
          /^\/api\/ctf\/publications\/[a-f0-9-]+$/.test(value.path) &&
          value.status === 200);
        if (current) return current;
        const ready = await action(() => page.evaluate(() =>
          [...document.querySelectorAll('button')].some(button =>
            button.textContent.trim() === 'Check status' && !button.disabled &&
            button.getClientRects().length > 0)));
        if (ready && recoveryResponses.length > lastCheckCount && checks < 6) {
          lastCheckCount = recoveryResponses.length; checks++;
          await pointer(await handle(() => [...document.querySelectorAll('button')]
            .find(button => button.textContent.trim() === 'Check status' &&
              !button.disabled && button.getClientRects().length > 0)));
        }
        return null;
      }, 'current publication through mounted recovery');
      assert.equal(published.status, 200);
      const observed = await Promise.all(recoveryResponses.slice(recoveryStart)
        .map(async value => ({ path: value.path, status: value.status,
          body: await value.body })));
      let settled;
      try { settled = assertObservedAttemptRecovery(pending, observed); }
      catch (error) {
        // This is a private, bounded failure-only path/status/reference trail.
        // It never serializes a bearer, response body, payload, or model text.
        try { fs.writeFileSync(path.join(runtime,
          'ctf-learner-attempt-gate-recovery-failure.json'),
        JSON.stringify(boundedRecoveryFailureTrail(ordinal, pending, observed)),
        { flag: 'wx', mode: 0o600 }); } catch { /* Preserve the source failure. */ }
        throw error;
      }
      assertRecoveryMutationPosts({ resume: seen.resume.slice(resumeStart),
        authorize: seen.authorize.slice(authorizeStart) }, settled,
      learner.headers.authorization);
      const row = await waitUntil(async () => {
        const next = await progress(participantId);
        return next.length === 1 && next[0].attempts_count === ordinal ? next[0] : null;
      }, 'attempt projection');
      assert.equal(row.status, 'in_progress');
      if (ordinal < 3) {
        const lockedState = await action(() => page.waitForFunction(count =>
          document.body.textContent.includes(`(${count} so far)`) &&
          document.body.textContent.includes('Hints unlock after 3 attempts.'),
        { timeout: 15000, polling: 100 }, ordinal));
        await lockedState.dispose();
      } else await (await handle(learnerA.hintButton)).dispose();
      const visible = await action(() => page.evaluate(() =>
        [...document.querySelectorAll('button')].some(button =>
          button.textContent.includes('Unlock Hint 1') && button.getClientRects().length)));
      assert.equal(visible, ordinal === 3);
      afterAttempts.push({ count: ordinal, hintVisible: visible, status: row.status });
      const afterCalls = countProviderCalls(ledger);
      assert.equal(afterCalls.guardian - beforeCalls.guardian, 1);
      assert(afterCalls.judge - beforeCalls.judge >= 1 &&
        afterCalls.judge - beforeCalls.judge <= 2);
      assert.equal(seen.attempt.length, ordinal,
        'Recovery/publication must never repeat the original scored POST');
      const proposal = (await i.runtime.query(`SELECT proposal_id::text,run_id::text,
        admission_operation_id::text,owner_id::text,session_id::text,
        canonical_evidence,evidence_hash FROM
        identity.ctf_decision_proposals WHERE run_id=$1`, [settled.runId])).rows;
      assert.equal(proposal.length, 1);
      assert.equal(proposal[0].run_id, settled.runId);
      const admissionId = settled.admissionId ?? proposal[0].admission_operation_id;
      assert.match(admissionId, UUID);
      if (settled.admissionId !== null)
        assert.equal(proposal[0].admission_operation_id, settled.admissionId);
      else assert.equal(pending.decisionId, settled.decisionId,
        'Only an observed initial decision permits durable admission resolution');
      assert.equal(proposal[0].owner_id, String(learnerId));
      assert.equal(proposal[0].session_id, String(initialSession));
      assert.equal(sha(proposal[0].canonical_evidence), proposal[0].evidence_hash);
      const admission = (await i.runtime.query(`SELECT operation_id::text,
        owner_id::text,owner_generation::text,participant_id::text,
        progress_id::text,stage_id::text,attempt_number FROM
        identity.ctf_attempt_admissions WHERE operation_id=$1`,
      [admissionId])).rows;
      assert.equal(admission.length, 1);
      assert.equal(admission[0].operation_id, admissionId);
      assert.equal(admission[0].owner_id, String(learnerId));
      assert.equal(admission[0].participant_id, participantId);
      assert.equal(admission[0].progress_id, row.id);
      assert.equal(admission[0].stage_id, '1');
      assert.equal(admission[0].attempt_number, ordinal);
      const run = (await i.runtime.query(`SELECT owner_key,generation::text,status
        FROM graph_runtime.runs WHERE run_id=$1`, [settled.runId])).rows;
      assert.equal(run.length, 1);
      assert.deepEqual(run[0], { owner_key: JSON.stringify(['CTF', String(learnerId)]),
        generation: admission[0].owner_generation, status: 'completed' });
      const locatorRows = (await i.runtime.query(`SELECT l.run_id::text,
        claim.owner_id::text,claim.session_id::text,
        encode(sha256(convert_to(l.registration_token,'UTF8')),'hex')
          AS locator_sha256
        FROM identity.ctf_predefense_registration_locators l
        JOIN identity.ctf_predefense_claims claim ON claim.run_id=l.run_id
        WHERE l.run_id=$1 AND claim.owner_id=$2 AND claim.session_id=$3`,
      [settled.runId, learnerId, initialSession])).rows;
      assertDurableScoredLocator(locatorRows, settled.runId, learnerId,
        initialSession, mountedLocatorDigest);
      const evidenceRow = JSON.parse(proposal[0].canonical_evidence);
      assert.equal(evidenceRow.binding.ownerId, String(learnerId));
      assert.equal(evidenceRow.binding.sessionId, String(initialSession));
      assert.equal(evidenceRow.binding.admissionId, admissionId);
      assert.equal(evidenceRow.binding.runId, settled.runId);
      assert.equal(evidenceRow.judgment.verdict, 'fail');
      assert.equal(evidenceRow.observedSecret, false);
      const decision = (await i.runtime.query(`SELECT decision_id::text,
        proposal_id::text,run_id::text,owner_id::text,session_id::text FROM
        identity.ctf_decisions WHERE decision_id=$1`, [settled.decisionId])).rows;
      assert.equal(decision.length, 1);
      assert.deepEqual(decision[0], { decision_id: settled.decisionId,
        proposal_id: proposal[0].proposal_id, run_id: settled.runId,
        owner_id: String(learnerId), session_id: String(initialSession) },
      'The published decision must authorize this exact run and mounted owner');
      if (settled.admissionId === null)
        assert.equal(assertDirectDecisionDurableBinding({ pending, settled,
          proposal: proposal[0], admission: admission[0], decision: decision[0],
          locator: locatorRows[0], ownerId: learnerId,
          sessionId: initialSession, participantId }), admissionId);
      const stored = (await c.runtime.query(`SELECT attempt_number,session_id FROM ctf.ctf_attempts
        WHERE participant_id=$1 AND stage_id=1 ORDER BY attempt_number`,
      [participantId])).rows;
      assert.equal(stored.length, ordinal);
      assert.equal(stored.at(-1).attempt_number, ordinal);
      assert.equal(stored.at(-1).session_id, null,
        'Unmatched UI telemetry locator cannot impersonate the registered session');
      attempts.push({ ordinal, runId: settled.runId,
        admissionId, decisionId: settled.decisionId,
        requestStatus: 202, publicationStatus: 200, verdict: 'fail',
        accepted: false, guardianCalls: 1,
        judgeCalls: afterCalls.judge - beforeCalls.judge,
        sameIdGets: settled.sameIdGets,
        recoveryResumePosts: settled.recoveryResumePosts,
        recoveryAuthorizePosts: settled.recoveryAuthorizePosts,
        ownerSessionBound: true, decisionApplied: true,
        publicationCurrent: true, noProviderReplay: true });
    }
    assert.deepEqual(await sibling(), siblingBefore);
    const finalProgress = await progress(participantId);
    assert.equal(finalProgress[0].attempts_count, 3);
    assert.equal(finalProgress[0].status, 'in_progress');
    assert.equal(finalProgress[0].hints_used, 0);
    const binding = (await i.runtime.query(`SELECT participant_id::text,
      progress_id::text,attempts_count,hints_used,status FROM
      identity.ctf_progress_bindings WHERE owner_id=$1 AND stage_id=1 AND
      owner_generation=(SELECT owner_generation FROM identity.ctf_authority
      WHERE scope_key=$2)`, [learnerId, `owner:${learnerId}`])).rows;
    assert.deepEqual(binding, [{ participant_id: participantId,
      progress_id: finalProgress[0].id, attempts_count: 3, hints_used: 0,
      status: 'in_progress' }]);
    const judges = (await c.runtime.query(`SELECT run_id,verdict,accepted FROM
      ctf.ctf_judgments WHERE participant_id=$1 AND stage_id=1`,
    [participantId])).rows;
    assert.deepEqual(judges.map(value => value.run_id).sort(),
      attempts.map(value => value.runId).sort());
    for (const judgment of judges) {
      assert.equal(judgment.verdict, 'fail');
      assert.equal(judgment.accepted, 0);
    }
    const leaderboard = (await c.runtime.query(`SELECT total_score,
      total_stages_completed FROM ctf.ctf_leaderboard WHERE participant_id=$1`,
    [participantId])).rows;
    assert(leaderboard.length <= 1);
    if (leaderboard.length) assert.deepEqual(leaderboard[0],
      { total_score: 0, total_stages_completed: 0 });
    const oldDecision = attempts[0].decisionId;
    const beforeResetCalls = ledger.length;
    const historicalBefore = (await i.runtime.query(`SELECT proposal_id::text,run_id::text FROM
      identity.ctf_decision_proposals WHERE run_id=ANY($1::uuid[])
      ORDER BY run_id`,
    [attempts.map(value => value.runId)])).rows;
    assert.equal(historicalBefore.length, 3);
    const resetBeforeSequence = await maxSequence();
    const generationBefore = (await i.runtime.query(`SELECT owner_generation::text
      FROM identity.ctf_authority WHERE scope_key=$1`,
    [`owner:${learnerId}`])).rows[0]?.owner_generation;
    assert.match(generationBefore, GENERATION);
    const reset = await request('POST', `/admin/participants/${learnerId}/reset`,
      admin, {});
    assert([200, 202].includes(reset.status));
    if (reset.status === 202) await waitUntil(async () => {
      const recovered = await request('GET', `/operations/${reset.body.operationId}`, admin);
      return recovered.status === 200 ? recovered : null;
    }, 'owner reset projection');
    const resetRows = await waitUntil(async () => {
      const rows = (await i.runtime.query(`SELECT sequence::text,operation_id::text,
        actor_id::text,session_id::text,state,canonical_command,command_hash,
        canonical_result,result_hash FROM identity.ctf_outbox
        WHERE sequence>$1 AND kind='owner_reset' ORDER BY sequence`,
      [resetBeforeSequence])).rows;
      assert(rows.length <= 1, 'Exactly one owner reset may follow three attempts');
      return rows.length === 1 && rows[0].state === 'applied' ? rows[0] : null;
    }, 'canonical owner reset');
    assert.equal(resetRows.actor_id, String(admin.user.id));
    assert.equal(resetRows.session_id, String(admin.identitySession.id));
    assert.equal(sha(resetRows.canonical_command), resetRows.command_hash);
    assert.equal(sha(resetRows.canonical_result), resetRows.result_hash);
    const resetCommand = JSON.parse(resetRows.canonical_command);
    assert.equal(resetCommand.kind, 'owner_reset');
    assert.equal(resetCommand.operationId, resetRows.operation_id);
    assert.equal(resetCommand.actorId, String(admin.user.id));
    assert.equal(resetCommand.scope.ownerId, String(learnerId));
    assert.equal(resetCommand.scope.participantId, participantId);
    if (reset.body.operationId !== undefined)
      assert.equal(reset.body.operationId, resetRows.operation_id);
    const resetProjection = (await c.runtime.query(`SELECT sequence::text,
      operation_id::text,kind,command_hash,canonical_result,result_hash
      FROM ctf.projection_receipts WHERE operation_id=$1`,
    [resetRows.operation_id])).rows;
    assert.deepEqual(resetProjection, [{ sequence: resetRows.sequence,
      operation_id: resetRows.operation_id, kind: 'owner_reset',
      command_hash: resetRows.command_hash,
      canonical_result: resetRows.canonical_result,
      result_hash: resetRows.result_hash }]);
    const currentOwner = (await i.runtime.query(`SELECT owner_generation::text,
      lifecycle_state FROM identity.ctf_authority WHERE scope_key=$1`,
    [`owner:${learnerId}`])).rows;
    assert.equal(currentOwner.length, 1);
    assert.equal(BigInt(currentOwner[0].owner_generation),
      BigInt(generationBefore) + 1n);
    assert.equal(currentOwner[0].lifecycle_state, 'ready');
    assert.deepEqual(await progress(participantId), []);
    assert.deepEqual((await i.runtime.query(`SELECT progress_id FROM
      identity.ctf_progress_bindings WHERE owner_id=$1 AND
      owner_generation=$2`,
    [learnerId, currentOwner[0].owner_generation])).rows, []);
    const deniedOld = await request('GET', `/publications/${oldDecision}`, learner);
    assert.deepEqual(deniedOld, { status: 409,
      body: { error: 'CTF request is no longer current' } },
    'Only canonical stale-publication fencing proves reset invalidated the old decision');
    assert.equal(ledger.length, beforeResetCalls);
    const historicalAfter = (await i.runtime.query(`SELECT proposal_id::text,run_id::text FROM
      identity.ctf_decision_proposals WHERE run_id=ANY($1::uuid[])
      ORDER BY run_id`,
    [attempts.map(value => value.runId)])).rows;
    assert.deepEqual(historicalAfter, historicalBefore);
    assert.deepEqual(await sibling(), siblingBefore);
    const providerCalls = countProviderCalls(ledger), currentServer = serverCounts();
    receipt = { version: 1, profile: PROFILE, transport: 'controlled-synthetic',
      actorId: String(learnerId), sessionId: String(initialSession), participantId,
      stageId: 1, siblingOwnerId: 1001,
      gate: { configured: 3, initialAttempts: 0, initialHintVisible: false,
        deniedStatus: 409,
        deniedError: 'Hint availability changed; refresh stage status',
        deniedOutboxDelta: 0, deniedProgressUnchanged: true,
        deniedProviderCalls: 0, afterAttempts, afterThirdHintVisible: true },
      attempts, lifecycle: {
        register: { operationId: registered.operation_id,
          sequence: registered.sequence, originalStatus: registerResponse.status() },
        start: { operationId: started.operation_id,
          sequence: started.sequence, originalStatus: startResponse.status() },
      }, reset: { operationId: resetRows.operation_id,
        sequence: resetRows.sequence, originalStatus: reset.status,
        deniedStatus: deniedOld.status, deniedError: deniedOld.body.error,
        generationBefore, generationAfter: currentOwner[0].owner_generation },
      browserPosts: Object.fromEntries(Object.keys(seen)
        .map(key => [key, seen[key].length])),
      serverPosts: Object.fromEntries(Object.keys(currentServer)
        .map(key => [key, currentServer[key] - beforeServer[key]])),
      providerCalls,
      storeWitness: Object.fromEntries(['progressAttemptsThree',
        'threeAttemptRows', 'threeJudgmentRows', 'noCompletion',
        'noHintPurchased', 'identityBindingCurrent', 'siblingBeforeNonempty',
        'siblingUnchanged', 'resetReferenceFenced',
        'historicalEvidenceRetained'].map(key => [key, true])),
      facts: Object.fromEntries(FACTS.map(key => [key, true])),
      excluded: [...EXCLUDED], unexpectedApiPaths: unexpected,
      browserActions: actions, apiRequests: contentHttp.apiRequests - beforeApi,
      genuineCredit: 0, stage: 'complete' };
    assertControlledReceipt(receipt);
  } catch (error) { primary = error; throw error; } finally {
    const failures = [];
    browserWork.abortWaiters();
    for (const close of [() => pages?.close(), () => browser?.close()])
      try { await close(); } catch (error) { failures.push(error); }
    try { if (page) page.off('request', pageRequest); } catch (error) { failures.push(error); }
    try { if (page) page.off('response', pageResponse); } catch (error) { failures.push(error); }
    try { await browserWork.drain(); } catch (error) { failures.push(error); }
    try { await mounted?.close(); } catch (error) { failures.push(error); }
    for (const [key, value] of Object.entries(prior))
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    if (failures.length) throw new AggregateError(primary ? [primary, ...failures] : failures,
      'Scored learner rendered cleanup incomplete', { cause: primary });
  }
  const retiredServer = serverCounts();
  assertRetiredCounts(receipt,
    Object.fromEntries(Object.keys(seen).map(key => [key, seen[key].length])),
    Object.fromEntries(Object.keys(retiredServer)
      .map(key => [key, retiredServer[key] - beforeServer[key]])),
    contentHttp.apiRequests - beforeApi, countProviderCalls(ledger), unexpected);
  fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2),
    { flag: 'wx', mode: 0o600 });
  learnerA.assertPrivateReceipt(receiptPath);
  assertControlledReceipt(JSON.parse(fs.readFileSync(receiptPath, 'utf8')));
}

module.exports = { PROFILE, POST_PATHS, LIMITS, EXCLUDED, FACTS,
  createBrowserWorkTracker,
  assertDatabaseName, assertGateProgression, assertAttempt,
  assertControlledReceipt, assertDefaultHintDenial, countProviderCalls,
  reserveScoredProvider, assertRetiredCounts, assertScoredAttemptBody,
  assertDurableScoredLocator,
  assertObservedAttemptRecovery,
  boundedRecoveryFailureTrail,
  assertDirectDecisionDurableBinding,
  assertRecoveryMutationPosts,
  browserAllowed,
  physicalLockedHintState, physicalLockedHintReady,
  runControlledRenderedCases, sha };
