'use strict';
// Controlled rendered Fixed-practice facet. Canonical stage edits create actual
// stale authority while practice itself remains read-only and unscored.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');

const PROFILE = 'ctf-fixed-practice-q05';
const POST_PATH = '/api/ctf/stage/1/practice';
const FACTS = Object.freeze([
  'visibleFixedModeDisclosureBeforeSubmit',
  'modeSelectionNoDispatch',
  'oneBoundPracticePost',
  'staleBeforeDispatchNoProviderOrPublication',
  'staleBeforeProviderNoProviderOrPublication',
  'staleAfterDispatchNoPublication',
  'unscoredPublicContextBoundary',
  'noAttemptProgressJudgeLeaderboardCreditWrites',
  'noAutomaticRetryOrOperationRecovery',
  'nonemptySiblingPreserved',
  'canonicalAuthorityStalenessBound',
  'onlyExpectedAuthorityOutboxMutations',
  'controlledProviderNotQualification',
]);
const EXCLUDED = Object.freeze([
  'native-browser-proof',
  'actual-model-qualification',
  'objective-judge',
  'gameplay-credit',
  'operation-id-recovery',
  'automatic-retry',
]);
const WITNESS = Object.freeze([
  'attemptsUnchanged', 'progressUnchanged', 'judgmentsUnchanged',
  'leaderboardUnchanged', 'authorityOutboxExact', 'siblingBeforeNonempty',
  'siblingUnchanged', 'controlledFixtureCleaned',
]);
const LIMITS = Object.freeze({ browserActions: 240, apiRequests: 240, deadlineMs: 120000,
  providerCalls: 2 });
const DECIMAL = /^[1-9][0-9]*$/;
const exact = (value, keys) => {
  assert(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
};

function fixedPracticeQueryAllowed(method, url) {
  if (url.hash) return false;
  if (!url.search) return true;
  const entries = [...url.searchParams];
  return method === 'GET' && url.pathname === '/api/changes/revisions' &&
    entries.length === 1 && entries[0][0] === 'workshops' && entries[0][1] === '*';
}

function fixedPracticeApiAllowed(method, pathname) {
  if (method === 'POST') return pathname === POST_PATH;
  // Practice has no operation-reference recovery. These are only ordinary page reads.
  return method === 'GET' && new Set(['/api/auth/status','/api/auth/signup-config',
    '/api/changes/revisions','/api/workshop/challenges',
    '/api/workshop/time/summary','/api/workshop/config',
    '/api/workshop/config/snapshot','/api/workshop/config/revision',
    '/api/ctf/config','/api/ctf/stages','/api/ctf/status',
    '/api/ctf/leaderboard']).has(pathname);
}

function fixedPracticeTab() {
  const tabs = [...document.querySelectorAll('button[role="tab"]')].filter(button =>
    button.textContent.trim() === 'Fixed practice' && !button.disabled && button.getClientRects().length);
  return tabs.length === 1 ? tabs[0] : null;
}

function fixedPracticeNotice() {
  const notices = [...document.querySelectorAll('[role="status"]')].filter(node =>
    node.textContent.replace(/\s+/g, ' ').trim() ===
      'Fixed practice — unscored. Responses use the fixed practice path and cannot award credit, points, or stage progression.' &&
    node.getClientRects().length);
  return notices.length === 1 ? notices[0] : null;
}

function assertFixedPracticeReceipt(receipt) {
  exact(receipt, ['version', 'profile', 'actorId', 'sessionId', 'participantId', 'stageId',
    'siblingOwnerId', 'cases', 'providerDiagnostics', 'storeWitness', 'facts', 'excluded',
    'cleanup', 'authorityOperations', 'unexpectedApiPaths', 'browserActions', 'apiRequests', 'stage', 'judgeCalls',
    'genuineCredit']);
  assert.equal(receipt.version, 1); assert.equal(receipt.profile, PROFILE);
  for (const key of ['actorId', 'sessionId', 'participantId', 'siblingOwnerId'])
    assert.match(String(receipt[key]), DECIMAL);
  assert.equal(receipt.stageId, 1);
  exact(receipt.cases, ['modeSelection', 'submit', 'staleBeforeDispatch',
    'staleBeforeProvider', 'staleAfterDispatch']);
  assert.deepEqual(receipt.cases.modeSelection, { browserPosts: 0, serverPosts: 0,
    providerStarts: 0, responsePublished: false, stateInvariant: true });
  assert.deepEqual(receipt.cases.submit, { browserPosts: 1, serverPosts: 1,
    providerStarts: 1, responsePublished: true, status: 200,
    scoringEligible: false, protectedContextIncluded: false, serverSecretProvided: false });
  assert.deepEqual(receipt.cases.staleBeforeDispatch, { browserPosts: 0, serverPosts: 0,
    providerStarts: 0, responsePublished: false, stateInvariant: true });
  assert.deepEqual(receipt.cases.staleBeforeProvider, { browserPosts: 1, serverPosts: 1,
    providerStarts: 0, responsePublished: false, status: 409, stateInvariant: true });
  assert.deepEqual(receipt.cases.staleAfterDispatch, { browserPosts: 1, serverPosts: 1,
    providerStarts: 1, responsePublished: false, status: 409, stateInvariant: true });
  assert.deepEqual(receipt.providerDiagnostics, { kind: 'controlled-synthetic-provider',
    physicalStarted: 2, completed: 1, staleAfterDispatch: 1, maxPhysicalCalls: 2 });
  assert(Array.isArray(receipt.authorityOperations) && receipt.authorityOperations.length === 4);
  const phases = ['pre-provider-stale','pre-provider-restore','post-provider-stale','post-provider-restore'];
  const ids = new Set(); let prior = 0n;
  for (const [index, operation] of receipt.authorityOperations.entries()) {
    exact(operation, ['phase','operationId','sequence','actorId','sessionId','stageId']);
    assert.equal(operation.phase, phases[index]);
    assert.match(operation.operationId, /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/);
    assert(!ids.has(operation.operationId)); ids.add(operation.operationId);
    assert.match(operation.sequence, DECIMAL); assert(BigInt(operation.sequence) > prior);
    prior = BigInt(operation.sequence);
    assert.match(operation.actorId, DECIMAL); assert.match(operation.sessionId, DECIMAL);
    assert.equal(operation.stageId, 1);
  }
  exact(receipt.storeWitness, WITNESS);
  for (const key of WITNESS) assert.equal(receipt.storeWitness[key], true);
  exact(receipt.cleanup, ['providerDrained', 'ownedBrowserHandles', 'ownedStoreHandles']);
  assert.deepEqual(receipt.cleanup, { providerDrained: true, ownedBrowserHandles: 0,
    ownedStoreHandles: 0 });
  exact(receipt.facts, FACTS);
  for (const key of FACTS) assert.equal(receipt.facts[key], true);
  assert.deepEqual(receipt.excluded, EXCLUDED);
  assert.deepEqual(receipt.unexpectedApiPaths, []);
  assert(Number.isSafeInteger(receipt.browserActions) && receipt.browserActions >= 1 &&
    receipt.browserActions <= LIMITS.browserActions);
  assert(Number.isSafeInteger(receipt.apiRequests) && receipt.apiRequests >= 1 &&
    receipt.apiRequests <= LIMITS.apiRequests);
  assert.equal(receipt.stage, 'complete'); assert.equal(receipt.judgeCalls, 0);
  assert.equal(receipt.genuineCredit, 0);
  return true;
}

function exactStoreSnapshot(value) {
  exact(value, ['attempts', 'progress', 'judgments', 'leaderboard', 'outbox', 'sibling']);
  for (const key of Object.keys(value)) assert(Array.isArray(value[key]), `${key} rows required`);
  assert(value.sibling.length > 0, 'Fixed-practice fixture requires a nonempty sibling snapshot');
  return value;
}

function fixedPracticeStoreWitness(before, after, authorityOperations = []) {
  exactStoreSnapshot(before); exactStoreSnapshot(after);
  for (const key of ['attempts','progress','judgments','leaderboard','sibling'])
    assert(isDeepStrictEqual(after[key], before[key]), `Fixed practice cannot write ${key}`);
  assert.equal(after.outbox.length, before.outbox.length + authorityOperations.length);
  assert(isDeepStrictEqual(after.outbox.slice(0,before.outbox.length), before.outbox),
    'Historical outbox prefix changed');
  assert.deepEqual(after.outbox.slice(before.outbox.length).map(row =>
    ({operationId:row.operation_id,sequence:String(row.sequence)})),
    authorityOperations.map(operation => ({operationId:operation.operationId,
      sequence:operation.sequence})), 'Only four exact canonical stage edits may enter outbox');
  return { attemptsUnchanged: true, progressUnchanged: true, judgmentsUnchanged: true,
    leaderboardUnchanged: true, authorityOutboxExact: true, siblingBeforeNonempty: true,
    siblingUnchanged: true, controlledFixtureCleaned: true };
}

function fixedPracticeResponse(response, publish) {
  assert(response && typeof response === 'object');
  assert.equal(response.status, publish ? 200 : 409);
  assert(response.body && typeof response.body === 'object');
  if (publish) {
    exact(response.body, ['response', 'mode', 'practice', 'unscored', 'scoringEligible',
      'protectedContextIncluded', 'serverSecretProvided']);
    assert.equal(typeof response.body.response, 'string');
    assert.equal(response.body.mode, 'fixed');
    assert.equal(response.body.practice, true);
    assert.equal(response.body.unscored, true);
    assert.equal(response.body.scoringEligible, false);
    assert.equal(response.body.protectedContextIncluded, false);
    assert.equal(response.body.serverSecretProvided, false);
  } else {
    // This is the authority router's canonical stale response, not an arbitrary non-2xx.
    assert.deepEqual(response.body, { error: 'CTF practice is no longer current' });
  }
  return response;
}

async function oneVisible(page, predicate, label) {
  const handle = await page.waitForFunction(predicate, { timeout: 15000, polling: 100 });
  assert(handle?.asElement?.(), `${label} must be one visible production element`);
  return handle;
}

async function pointer(handle) {
  try { await handle.click(); } finally { await handle.dispose(); }
}

async function selectFixedPractice(page) {
  const tab = await oneVisible(page, () => {
    const found = [...document.querySelectorAll('button[role="tab"]')].filter(button =>
      button.textContent.trim() === 'Fixed practice' && !button.disabled && button.getClientRects().length);
    return found.length === 1 ? found[0] : null;
  }, 'Fixed-practice tab');
  await pointer(tab);
  const notice = await oneVisible(page, () => {
    const expected = 'Fixed practice — unscored. Responses use the fixed practice path and cannot award credit, points, or stage progression.';
    const found = [...document.querySelectorAll('[role="status"]')].filter(node =>
      node.textContent.replace(/\s+/g, ' ').trim() === expected && node.getClientRects().length);
    return found.length === 1 ? found[0] : null;
  }, 'Fixed-practice disclosure');
  await notice.dispose();
}

async function physicalFixedSubmit(page, origin, text, expectResponse = true, beforePointer = null) {
  assert.equal(typeof text, 'string'); assert(text.trim().length > 0);
  assert(beforePointer === null || (!expectResponse && typeof beforePointer === 'function'));
  const controller = new AbortController();
  const response = expectResponse && page.waitForResponse(candidate => {
    const url = new URL(candidate.url());
    return url.origin === origin && candidate.request().method() === 'POST' &&
      candidate.request().url() === `${origin}${POST_PATH}`;
  }, { timeout: 15000, signal: controller.signal });
  // Attach a rejection observer before typing or waiting for the control:
  // either step can outlast the bounded response waiter. The original await
  // below still propagates the response failure to the measurement.
  if (response) response.catch(() => {});
  try {
    await page.type('textarea[placeholder="Try the same prompt against the fixed practice path..."]', text);
    const submit = await oneVisible(page, () => {
      const found = [...document.querySelectorAll('button[type="submit"]')].filter(button =>
        button.getAttribute('aria-label') === 'Send attempt' && !button.disabled && button.getClientRects().length);
      return found.length === 1 ? found[0] : null;
    }, 'Fixed-practice submit');
    try {
      // The stale-authority facet must first type under a current owner and
      // obtain the genuinely enabled control. Invalidate the captured owner
      // only at the physical pointer boundary so React's input rerender cannot
      // replace the intended click with a disabled-button observation.
      if (beforePointer) await beforePointer();
      await submit.click();
    } finally { await submit.dispose(); }
  } catch (error) {
    controller.abort();
    if (response) await response.catch(() => {});
    throw error;
  }
  if (!expectResponse) return null;
  const value = await response;
  return { status: value.status(), body: await value.json() };
}

async function practicePublication(page, answer = '') {
  return page.evaluate(expected => {
    const text = document.body?.textContent || '';
    const marker = 'Fixed response confirmed: protected context withheld, server secret withheld, and scoring disabled.';
    const occurrences = value => value ? text.split(value).length - 1 : 0;
    return { confirmations: occurrences(marker), answerOccurrences: occurrences(expected) };
  }, answer);
}

async function assertPracticeRequest(request, expectedText, resolveAuthorization,
  actorId, sessionId, participantId) {
  assert.equal(request.method, 'POST');
  assert.equal(request.path, POST_PATH);
  assert(typeof request.authorization === 'string' && request.authorization.startsWith('Bearer '),
    'Physical practice request requires a bearer');
  let principal;
  try { principal = await resolveAuthorization(request.authorization); }
  catch { assert.fail('Physical bearer authority resolution failed'); }
  assert.deepEqual(principal, { actorId: String(actorId), sessionId: String(sessionId),
    participantId: String(participantId) },
  'Physical bearer must resolve to the mounted owner, session and participant');
  let body;
  try { body = JSON.parse(request.body); }
  catch { assert.fail('Physical practice body must be JSON'); }
  exact(body, ['payload', 'sessionToken']);
  assert.equal(createHash('sha256').update(body.payload).digest('hex'),
    createHash('sha256').update(expectedText).digest('hex'));
  assert(typeof body.sessionToken === 'string' && body.sessionToken.length > 0 &&
    body.sessionToken.isWellFormed() && !body.sessionToken.includes('\0') &&
    Buffer.byteLength(body.sessionToken) <= 256);
  return createHash('sha256').update(body.sessionToken).digest('hex');
}

function authoritativeProviderDelta(before, after) {
  exact(before, ['physicalStarted', 'completed', 'staleAfterDispatch']);
  exact(after, ['physicalStarted', 'completed', 'staleAfterDispatch']);
  for (const key of Object.keys(before)) assert(Number.isSafeInteger(before[key]) && Number.isSafeInteger(after[key]));
  return { physicalStarted: after.physicalStarted - before.physicalStarted,
    completed: after.completed - before.completed,
    staleAfterDispatch: after.staleAfterDispatch - before.staleAfterDispatch };
}

// This helper owns real page clicks and obtains its observations from mounted-server
// counters, controlled-provider telemetry, and raw SQL snapshots. The only injected
// capabilities are narrowly scoped authority fault arms/reset and final resource close.
// It is not mounted in the shared runner yet, so calling it remains controlled-only.
async function runCtfFixedPracticeRenderedCases({ page, origin, actorId, sessionId, participantId,
  siblingOwnerId, serverCounts, providerCounts, snapshotStores, resolveAuthorization,
  authority, drain, cleanup }) {
  assert(page && typeof page.on === 'function' && typeof page.off === 'function');
  const address = new URL(origin);
  assert(address.protocol === 'http:' && address.hostname === '127.0.0.1' &&
    address.pathname === '/' && !address.username && !address.password &&
    !address.search && !address.hash && address.origin === origin);
  for (const value of [actorId, sessionId, participantId, siblingOwnerId]) assert.match(String(value), DECIMAL);
  assert(typeof serverCounts === 'function' && typeof providerCounts === 'function' &&
    typeof snapshotStores === 'function' && typeof resolveAuthorization === 'function');
  exact(authority, ['beforeDispatch', 'beforeProvider', 'afterDispatch', 'restoreCurrent']);
  for (const key of Object.keys(authority)) assert.equal(typeof authority[key], 'function');
  assert.equal(typeof drain, 'function'); assert.equal(typeof cleanup, 'function');
  const requests = [];
  const responses = [];
  const unexpected = [], interceptionFailures = [], authorityOperations = [];
  const posts = () => requests.filter(value => value.method === 'POST');
  const startedAt = Date.now();
  let actions = 0;
  const active = () => {
    assert(Date.now() - startedAt <= LIMITS.deadlineMs,
      'Fixed practice work deadline exceeded');
    assert(actions <= LIMITS.browserActions);
    assert(requests.length <= LIMITS.apiRequests);
    if (providerBaseline) assert(providerCounts().physicalStarted <=
      providerBaseline.physicalStarted + LIMITS.providerCalls,
    'Controlled provider exceeded its initial count plus two physical calls');
  };
  const requestListener = request => {
    const settle = async () => {
      const url = new URL(request.url());
      if (['data:', 'blob:', 'about:'].includes(url.protocol)) {
        await request.continue(); return;
      }
      if (url.origin !== origin || request.method() !== 'GET' &&
        !url.pathname.startsWith('/api/')) {
        unexpected.push('external-or-non-api'); await request.abort(); return;
      }
      if (url.pathname.startsWith('/api/')) {
        if (!fixedPracticeQueryAllowed(request.method(), url) || !fixedPracticeApiAllowed(request.method(), url.pathname) ||
          requests.length >= LIMITS.apiRequests) {
          unexpected.push(`${request.method()} ${url.pathname}`);
          await request.abort(); return;
        }
        requests.push({ method: request.method(), path: url.pathname,
          authorization: request.headers().authorization || null,
          body: request.postData() || '' });
      }
      await request.continue();
    };
    settle().catch(error => interceptionFailures.push(error));
  };
  const responseListener = response => {
    const url = new URL(response.url());
    if (url.origin === origin && url.pathname.startsWith('/api/')) responses.push({
      method: response.request().method(), path: url.pathname, status: response.status(),
    });
  };
  page.on('request', requestListener);
  page.on('response', responseListener);
  let primary, cleanupResult, result, serverBaseline, providerBaseline;
  try {
    await page.setRequestInterception(true);
    const before = await snapshotStores();
    const serverStart = serverCounts(), providerStart = providerCounts();
    serverBaseline = serverStart; providerBaseline = providerStart;
    active();
    exact(serverStart, ['practice']);
    assert(Number.isSafeInteger(serverStart.practice) && serverStart.practice >= 0);
    authoritativeProviderDelta(providerStart, providerStart);
    const selectionStart = posts().length;
    actions++; await selectFixedPractice(page);
    active();
    assert.equal(posts().length, selectionStart, 'mode selection must not POST');
    fixedPracticeStoreWitness(before, await snapshotStores(), authorityOperations);
    assert.deepEqual(serverCounts(), serverStart);
    assert.deepEqual(providerCounts(), providerStart);

    const submitStart = posts().length, submitProvider = providerCounts();
    assert(submitProvider.physicalStarted - providerStart.physicalStarted < LIMITS.providerCalls,
      'Provider budget must be checked before physical submit');
    const uiBefore = await practicePublication(page);
    actions++;
    const submit = fixedPracticeResponse(await physicalFixedSubmit(page, origin, 'fixed practice baseline'), true);
    const submitRequests = posts().slice(submitStart);
    assert.equal(submitRequests.length, 1);
    const mountedLocatorDigest = await assertPracticeRequest(submitRequests[0], 'fixed practice baseline', resolveAuthorization,
      actorId, sessionId, participantId);
    active();
    const normalProvider = authoritativeProviderDelta(submitProvider, providerCounts());
    assert.deepEqual(normalProvider, { physicalStarted: 1, completed: 1, staleAfterDispatch: 0 });
    const visible = await page.waitForFunction(answer => {
      const text = document.body?.textContent || '';
      return text.includes(answer) && text.includes(
        'Fixed response confirmed: protected context withheld, server secret withheld, and scoring disabled.');
    }, { timeout: 15000, polling: 100 }, submit.body.response);
    await visible.dispose();
    const uiAfter = await practicePublication(page, submit.body.response);
    assert.equal(uiAfter.confirmations, uiBefore.confirmations + 1);
    assert(uiAfter.answerOccurrences >= 1, 'The fixed response must be visible in the mounted UI');
    fixedPracticeStoreWitness(before, await snapshotStores(), authorityOperations);

    const preProviderFault = await authority.beforeProvider();
    assert(preProviderFault && typeof preProviderFault.settled?.then === 'function');
    const staleBeforeProviderStart = posts().length, preProvider = providerCounts();
    actions++;
    const staleBeforeReply = await physicalFixedSubmit(
      page, origin, 'fixed practice stale before provider');
    // The canonical edit is committed outside the released identity read.
    // Surface its bounded result before interpreting the route's status;
    // otherwise a hook failure is hidden behind a generic HTTP 503.
    authorityOperations.push(await preProviderFault.settled);
    const staleBeforeProvider = fixedPracticeResponse(staleBeforeReply, false);
    const preProviderRequests = posts().slice(staleBeforeProviderStart);
    assert.equal(preProviderRequests.length, 1);
    const preProviderDigest = await assertPracticeRequest(preProviderRequests[0], 'fixed practice stale before provider',
      resolveAuthorization, actorId, sessionId, participantId);
    assert.equal(preProviderDigest, mountedLocatorDigest,
      'Mounted route locator must remain stable across practice cases');
    active();
    assert.deepEqual(authoritativeProviderDelta(preProvider, providerCounts()),
      { physicalStarted: 0, completed: 0, staleAfterDispatch: 0 });
    fixedPracticeStoreWitness(before, await snapshotStores(), authorityOperations);
    assert.deepEqual(await practicePublication(page, submit.body.response), uiAfter);

    authorityOperations.push(await authority.restoreCurrent('pre-provider-restore'));
    const postProviderFault = await authority.afterDispatch();
    assert(postProviderFault && typeof postProviderFault.settled?.then === 'function');
    const staleAfterStart = posts().length, staleAfterProvider = providerCounts();
    assert(staleAfterProvider.physicalStarted - providerStart.physicalStarted < LIMITS.providerCalls,
      'Provider budget must be checked before physical submit');
    actions++;
    const staleAfter = fixedPracticeResponse(await physicalFixedSubmit(
      page, origin, 'fixed practice stale after provider'), false);
    authorityOperations.push(await postProviderFault.settled);
    const staleAfterRequests = posts().slice(staleAfterStart);
    assert.equal(staleAfterRequests.length, 1);
    const postProviderDigest = await assertPracticeRequest(staleAfterRequests[0], 'fixed practice stale after provider',
      resolveAuthorization, actorId, sessionId, participantId);
    assert.equal(postProviderDigest, mountedLocatorDigest,
      'Mounted route locator must remain stable across practice cases');
    active();
    assert.deepEqual(authoritativeProviderDelta(staleAfterProvider, providerCounts()),
      { physicalStarted: 1, completed: 0, staleAfterDispatch: 1 });
    fixedPracticeStoreWitness(before, await snapshotStores(), authorityOperations);
    assert.deepEqual(await practicePublication(page, submit.body.response), uiAfter);
    authorityOperations.push(await authority.restoreCurrent('post-provider-restore'));

    // Client-side stale authority is distinct: the click occurs, but no HTTP
    // practice request exists. A server-side 409 necessarily follows a POST.
    const staleBeforeStart = posts().length, clientStaleProvider = providerCounts();
    const clientStaleServer = serverCounts();
    actions++;
    await physicalFixedSubmit(page, origin, 'fixed practice stale in client', false,
      () => authority.beforeDispatch());
    active();
    assert.equal(posts().length, staleBeforeStart);
    assert.deepEqual(serverCounts(), clientStaleServer);
    assert.deepEqual(providerCounts(), clientStaleProvider);
    assert.deepEqual(await practicePublication(page, submit.body.response), uiAfter);
    fixedPracticeStoreWitness(before, await snapshotStores(), authorityOperations);

    await drain();
    active();
    const after = await snapshotStores();
    const storeWitness = fixedPracticeStoreWitness(before, after, authorityOperations);
    const serverEnd = serverCounts(), provider = authoritativeProviderDelta(providerStart, providerCounts());
    assert.deepEqual(serverEnd, { practice: serverStart.practice + 3 });
    assert.deepEqual(provider, { physicalStarted: 2, completed: 1, staleAfterDispatch: 1 });
    assert.equal(posts().length, 3);
    assert.deepEqual(unexpected, []);
    assert.deepEqual(interceptionFailures, []);
    assert.deepEqual(responses.filter(item => item.method === 'POST').map(item =>
      [item.path, item.status]), [[POST_PATH, 200], [POST_PATH, 409], [POST_PATH, 409]]);
    result = { version: 1, profile: PROFILE, actorId: String(actorId), sessionId: String(sessionId),
      participantId: String(participantId), stageId: 1, siblingOwnerId: String(siblingOwnerId),
      cases: {
        modeSelection: { browserPosts: 0, serverPosts: 0, providerStarts: 0, responsePublished: false, stateInvariant: true },
        submit: { browserPosts: submitRequests.length, serverPosts: 1, providerStarts: normalProvider.physicalStarted,
          responsePublished: true, status: submit.status, scoringEligible: submit.body.scoringEligible,
          protectedContextIncluded: submit.body.protectedContextIncluded, serverSecretProvided: submit.body.serverSecretProvided },
        staleBeforeDispatch: { browserPosts: posts().length - staleBeforeStart,
          serverPosts: 0, providerStarts: 0, responsePublished: false, stateInvariant: true },
        staleBeforeProvider: { browserPosts: preProviderRequests.length, serverPosts: 1,
          providerStarts: 0, responsePublished: false, status: staleBeforeProvider.status,
          stateInvariant: true },
        staleAfterDispatch: { browserPosts: staleAfterRequests.length, serverPosts: 1,
          providerStarts: 1, responsePublished: false, status: staleAfter.status, stateInvariant: true },
      }, providerDiagnostics: { kind: 'controlled-synthetic-provider', physicalStarted: provider.physicalStarted,
        completed: provider.completed, staleAfterDispatch: provider.staleAfterDispatch, maxPhysicalCalls: 2 },
      storeWitness, authorityOperations, cleanup: null, facts: Object.fromEntries(FACTS.map(key => [key, true])),
      excluded: [...EXCLUDED], unexpectedApiPaths: [...unexpected],
      browserActions: actions, apiRequests: requests.length,
      stage: 'complete', judgeCalls: 0, genuineCredit: 0 };
  } catch (error) { primary = error; } finally {
    const closeErrors = [];
    try { cleanupResult = await cleanup(); } catch (closeError) { closeErrors.push(closeError); }
    for (const listener of [['request', requestListener], ['response', responseListener]]) {
      try { page.off(...listener); } catch (closeError) { closeErrors.push(closeError); }
    }
    if (closeErrors.length) primary = new AggregateError(primary ? [primary, ...closeErrors] : closeErrors,
      'Fixed-practice rendered cleanup failed', { cause: primary });
  }
  if (primary) throw primary;
  assert(result, 'Fixed-practice measurement did not complete');
  // Counters remain independently readable after the owned browser/provider
  // retirement. A late POST or provider dispatch cannot inherit a prior pass.
  assert.equal(posts().length, 3);
  assert.equal(requests.length, result.apiRequests);
  assert.deepEqual(unexpected, []);
  assert.deepEqual(interceptionFailures, []);
  assert.deepEqual(serverCounts(), { practice: serverBaseline.practice + 3 });
  assert.deepEqual(authoritativeProviderDelta(providerBaseline, providerCounts()), { physicalStarted: 2,
    completed: 1, staleAfterDispatch: 1 });
  result.cleanup = cleanupResult;
  assertFixedPracticeReceipt(result);
  return result;
}

module.exports = { PROFILE, POST_PATH, FACTS, EXCLUDED, WITNESS, LIMITS,
  fixedPracticeApiAllowed, fixedPracticeQueryAllowed, fixedPracticeTab, fixedPracticeNotice,
  exactStoreSnapshot, fixedPracticeStoreWitness, fixedPracticeResponse,
  physicalFixedSubmit, assertFixedPracticeReceipt, runCtfFixedPracticeRenderedCases };
