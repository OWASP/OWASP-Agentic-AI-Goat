'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { QUALIFIED_OBJECTIVE_IDS } = require('../server/config/secureshopCurriculum');
const { assertNativeEvidence, assertSameLaunch, collectRunIds,
  configureSecureShopCurriculum, verifyForeignRunIsolation,
  mountWorkshop, loginShopPersona, mountVerifiedShopPersona, openProduct, captureResetRecovery,
  renderedQualificationFailureDiagnostic, readBoundedFailureEvidence,
  projectSsrfClassifications, reviewQualificationPlan, resolvedReviewQualificationPlan,
  createFullBackendRenderedSecureShop, STORED_BROWSER_PROBE_BODY } = require('./fixtures/fullBackendRenderedSecureShop');

const launch = Object.freeze({ launchId: '11111111-1111-4111-8111-111111111111',
  scenarioId: '22222222-2222-4222-8222-222222222222', generation: 4,
  platformOwnerId: 11, platformSessionId: 21 });

test('stored browser probe triggers onerror through a same-origin missing asset', () => {
  const source = STORED_BROWSER_PROBE_BODY.match(/\bsrc="([^"]+)"/)?.[1];
  assert.equal(source, '/owned-parent-missing.png');
  const resolved = new URL(source, 'http://127.0.0.1:35001');
  assert.equal(resolved.origin, 'http://127.0.0.1:35001');
  assert.match(STORED_BROWSER_PROBE_BODY, /\bonerror="alert\('owned-parent-frame'\)"/);
  assert.doesNotMatch(STORED_BROWSER_PROBE_BODY, /(?:invalid|blob|file|javascript):/i);
});

test('reset recovery capture bounds and drains absent and hung response bodies',async()=>{
  const origin='http://127.0.0.1:35001',mainFrame={};let waiterAborted=0;
  const absent={mainFrame:()=>mainFrame,waitForResponse(_predicate,{signal,timeout}){
    assert.equal(timeout,10);return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>{
      waiterAborted++;reject(Object.assign(new Error('Aborted'),{name:'AbortError'}));},{once:true})); }};
  const missing=captureResetRecovery(absent,origin,10);await missing.close();assert.equal(waiterAborted,1);
  let rawBodyObserved=false;
  const request={method:()=> 'POST',frame:()=>mainFrame};
  const response={url:()=>origin+'/api/auth/secureshop-launch/recover',request:()=>request,status:()=>200,
    json(){const raw=new Promise(()=>{});void raw.catch(()=>{rawBodyObserved=true;});return raw;}};
  const hung={mainFrame:()=>mainFrame,waitForResponse(predicate,{timeout}){
    assert.equal(timeout,10);assert.equal(predicate(response),true);return Promise.resolve(response); }};
  const captured=captureResetRecovery(hung,origin,10),result=await captured.pending;
  assert.equal(result.status,200);await captured.close();await assert.rejects(result.body,{name:'AbortError'});
  assert.equal(rawBodyObserved,false,'Non-cancellable raw CDP body remains observed until browser teardown');
});

function personaActivationHarness() {
  const page = new EventEmitter(), client = new EventEmitter();
  let frameUrl = 'http://127.0.0.1:35001/workshop/secureshop', sequence = 0;
  let currentLoaderId = null, currentFrameId = null, cacheFailure = null;
  const lifecycle = [], waitTimeouts = [];
  const mainFrame = { url: () => frameUrl };let currentMainFrame = mainFrame;
  const childFrame = { url: () => 'about:srcdoc', parentFrame: () => mainFrame, detached: false };
  page._client = () => client;
  page.setCacheEnabled = async enabled => {
    lifecycle.push(`cache:${enabled}`);if (cacheFailure) throw cacheFailure;
  };
  page.mainFrame = () => currentMainFrame;
  page.waitForResponse = (predicate, { signal, timeout } = {}) => new Promise((resolve, reject) => {
    waitTimeouts.push(timeout);
    const cleanup = () => { page.off('response', onResponse);signal?.removeEventListener('abort', onAbort); };
    const onResponse = response => {
      let matched;try { matched = predicate(response); } catch (error) { cleanup();reject(error);return; }
      if (matched) { cleanup();resolve(response); }
    };
    const onAbort = () => { cleanup();reject(Object.assign(new Error('aborted'), { name: 'AbortError' })); };
    page.on('response', onResponse);signal?.addEventListener('abort', onAbort, { once: true });
  });
  const request = ({ url, method = 'GET', frame = mainFrame, navigation = false,
    id = `request-${++sequence}`, redirects = [] }) => Object.freeze({
    id,
    url: () => url, method: () => method, frame: () => frame,
    isNavigationRequest: () => navigation, redirectChain: () => redirects,
  });
  const response = ({ request: source, status = 200, json }) => Object.freeze({
    request: () => source, status: () => status, json,
  });
  const navigate = (url = 'http://127.0.0.1:35001/workshop/secureshop', {
    commitFirst = false, frameId = 'main-frame', loaderId = `loader-${++sequence}`,
    commitFrameId = frameId, commitLoaderId = loaderId, status = 200, redirects = [],
    puppeteerRequestId = loaderId,
  } = {}) => {
    lifecycle.push('navigate');
    const source = request({ url, navigation: true, frame: currentMainFrame,
      id: puppeteerRequestId, redirects });
    const rawRequest = () => client.emit('Network.requestWillBeSent', {
      requestId: loaderId, loaderId, frameId, type: 'Document', request: { url, method: 'GET' },
      ...(redirects.length ? { redirectResponse: {} } : {}),
    });
    const commit = () => {
      frameUrl = url;client.emit('Page.frameNavigated', {
        frame: { id: commitFrameId, loaderId: commitLoaderId, url }, type: 'Navigation',
      });
    };
    currentLoaderId = loaderId;currentFrameId = frameId;
    if (commitFirst) { commit();rawRequest(); } else { rawRequest();commit(); }
    page.emit('request', source);
    page.emit('response', response({ request: source, status, json: async () => ({}) }));
    return source;
  };
  const navigateCommitFirst = (url = 'http://127.0.0.1:35001/workshop/secureshop', options = {}) =>
    navigate(url, { ...options, commitFirst: true });
  const whoami = ({ frame = mainFrame, suffix = '', method = 'GET', frameId = currentFrameId,
    loaderId = currentLoaderId, id = `identity-${++sequence}`, rawRequestId = id } = {}) => {
    const source = request({ url: `http://127.0.0.1:35001/api/secureshop/v2/auth/whoami${suffix}`,
      method, frame, id });
    client.emit('Network.requestWillBeSent', { requestId: rawRequestId, loaderId, frameId,
      type: 'Fetch', request: { url: source.url(), method } });
    page.emit('request', source);return source;
  };
  const sameDocument = (url = 'http://127.0.0.1:35001/workshop/secureshop') => {
    frameUrl = url;client.emit('Page.navigatedWithinDocument', { frameId: 'main-frame', url });
  };
  const assertClean = () => {
    assert.equal(page.listenerCount('request'), 0);
    assert.equal(page.listenerCount('response'), 0);
    assert.equal(client.listenerCount('Network.requestWillBeSent'), 0);
    assert.equal(client.listenerCount('Page.frameNavigated'), 0);
  };
  const setFrameUrl = value => { frameUrl = value; };
  const replaceMainFrame = value => { currentMainFrame = value; };
  const setCacheFailure = error => { cacheFailure = error; };
  return { page, client, mainFrame, childFrame, request, response, navigate, navigateCommitFirst,
    whoami, sameDocument, assertClean, lifecycle, waitTimeouts, setCacheFailure,
    setFrameUrl, replaceMainFrame };
}

test('persona remount ignores old traffic and consumes the exact fresh host identity before mount completes', async () => {
  const h = personaActivationHarness(), order = [];let evicted = false, freshJsonCalls = 0;
  const oldRequest = h.request({ url: 'http://127.0.0.1:35001/api/secureshop/v2/auth/whoami' });
  const active = { page: h.page, frame: h.childFrame };
  const result = await mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
    role: 'merchant', mount: async () => {
      h.page.emit('response', h.response({ request: oldRequest, json: async () => {
        throw new Error('Old response must not be consumed');
      } }));
      h.navigate();
      const queryRequest = h.whoami({ suffix: '?stale=1' });
      h.page.emit('response', h.response({ request: queryRequest, json: async () => {
        throw new Error('Non-exact identity URL must not be consumed');
      } }));
      const freshRequest = h.whoami();
      h.page.emit('response', h.response({ request: freshRequest, json: async () => {
        freshJsonCalls++;order.push('json-start');
        if (evicted) throw new Error('Body was read after the mount lifetime');
        return { user: { username: 'student_merchant', role: 'merchant' } };
      } }));
      await Promise.resolve();evicted = true;order.push('mount-complete');return active;
    } });
  assert.equal(result, active);assert.equal(freshJsonCalls, 1);
  assert.deepEqual(order, ['json-start', 'mount-complete']);h.assertClean();
});

test('persona remount admits the same exact epoch when CDP reports its commit before its request', async () => {
  const h = personaActivationHarness();
  const active = { page: h.page, frame: h.childFrame };
  const result = await mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
    role: 'customer', mount: async () => {
      h.navigateCommitFirst();const source = h.whoami();
      h.page.emit('response', h.response({ request: source, json: async () => ({
        user: { username: 'student_customer', role: 'customer' },
      }) }));
      return active;
    } });
  assert.equal(result, active);h.assertClean();
  assert.deepEqual(h.lifecycle.slice(0, 2), ['cache:false', 'navigate']);
  assert.deepEqual(h.waitTimeouts, [15_000, 15_000]);
});

test('persona remount configures a fresh response contract before listeners or mount', async () => {
  const h = personaActivationHarness(), failure = new Error('cache setup failed');let mounted = false;
  h.setCacheFailure(failure);
  await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
    role: 'customer', mount: async () => { mounted = true;return {}; } }), error => error === failure);
  assert.equal(mounted, false);assert.deepEqual(h.lifecycle, ['cache:false']);h.assertClean();
});

test('persona remount bounds a hung identity body without abandoning its raw rejection observer', async () => {
  const h = personaActivationHarness(), active = { page: h.page, frame: h.childFrame };
  await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
    role: 'customer', identityResponseTimeoutMs: 5, mount: async () => {
      h.navigate();const source = h.whoami();
      h.page.emit('response', h.response({ request: source, json: async () => new Promise(() => {}) }));
      return active;
  } }), error => error?.name === 'TimeoutError'
      && error.message === 'Inspector response body deadline exceeded');
  assert.deepEqual(h.waitTimeouts, [5, 5]);
  h.assertClean();
});

test('persona remount rejects wrong navigation and non-host identity initiators and cleans listeners', async t => {
  await t.test('wrong navigation', async () => {
    const h = personaActivationHarness();
    await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => { h.navigate('http://127.0.0.1:35001/workshop/other');return {}; } }),
    /Unexpected main-frame (navigation|commit)/);
    h.assertClean();
  });
  await t.test('wrong frame', async () => {
    const h = personaActivationHarness();
    await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => { h.navigate();h.whoami({ frame: h.childFrame });return {}; } }),
    /fresh host main document/);
    h.assertClean();
  });
  await t.test('duplicate navigation epoch', async () => {
    const h = personaActivationHarness();
    await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => { h.navigate();h.navigate();return {}; } }),
    /exactly one (navigation|document) epoch/);
    h.assertClean();
  });
  await t.test('same-document events do not substitute for or duplicate the full document commit', async () => {
    const h = personaActivationHarness();
    const active = { page: h.page, frame: h.childFrame };
    const result = await mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => {
        h.sameDocument();h.navigate();h.sameDocument();const source = h.whoami();
        h.page.emit('response', h.response({ request: source, json: async () => ({
          user: { username: 'student_customer', role: 'customer' },
        }) }));return active;
      } });
    assert.equal(result, active);
    h.assertClean();
  });
  await t.test('duplicate fresh identity request', async () => {
    const h = personaActivationHarness();
    await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => { h.navigate();h.whoami();h.whoami();return {}; } }),
    /one (fresh identity request|identity epoch)/);
    h.assertClean();
  });
  for (const [name, navigationOptions, identityOptions, pattern] of [
    ['commit loader mismatch', { commitLoaderId: 'other-loader' }, {}, /one loader/],
    ['commit frame mismatch', { commitFrameId: 'other-frame' }, {}, /one frame/],
    ['identity loader mismatch', {}, { loaderId: 'other-loader' }, /identity request must use the admitted document loader/],
    ['identity frame mismatch', {}, { frameId: 'other-frame' }, /identity request must use the admitted document frame/],
    ['Puppeteer navigation identity mismatch', { puppeteerRequestId: 'other-request' }, {}, /Puppeteer navigation request must match/],
    ['Puppeteer identity mismatch', {}, { rawRequestId: 'other-request' }, /Puppeteer identity request must match/],
  ]) await t.test(name, async () => {
    const h = personaActivationHarness(), active = { page: h.page, frame: h.childFrame };
    await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => {
        h.navigate(undefined, navigationOptions);const source = h.whoami(identityOptions);
        h.page.emit('response', h.response({ request: source, json: async () => ({
          user: { username: 'student_customer', role: 'customer' },
        }) }));return active;
      } }), pattern);
    h.assertClean();
  });
  await t.test('redirected document epoch is rejected', async () => {
    const h = personaActivationHarness();
    await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => {
        h.navigate(undefined, { redirects: [{}] });return {};
      } }), /navigation cannot redirect|document epoch is invalid/);
    h.assertClean();
  });
  await t.test('non-200 workshop document is rejected', async () => {
    const h = personaActivationHarness(), active = { page: h.page, frame: h.childFrame };
    await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => {
        h.navigate(undefined, { status: 304 });const source = h.whoami();
        h.page.emit('response', h.response({ request: source, json: async () => ({
          user: { username: 'student_customer', role: 'customer' },
        }) }));return active;
      } }), /requires an HTTP 200 workshop document/);
    h.assertClean();
  });
});

test('persona remount rejects wrong or detached mounted frame bindings and navigation drift', async t => {
  const run = async mutate => {
    const h = personaActivationHarness();let active = { page: h.page, frame: h.childFrame };
    const pending = mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => {
        h.navigate();const source = h.whoami();
        h.page.emit('response', h.response({ request: source, json: async () => ({
          user: { username: 'student_customer', role: 'customer' },
        }) }));
        active = mutate(h, active) || active;return active;
      } });
    return { h, pending };
  };
  await t.test('wrong returned page', async () => {
    const { h, pending } = await run((_h, active) => ({ ...active, page: {} }));
    await assert.rejects(pending, /must return the page that performed the identity request/);h.assertClean();
  });
  await t.test('wrong child parent', async () => {
    const { h, pending } = await run((_h, active) => ({ ...active,
      frame: { detached: false, parentFrame: () => ({}) } }));
    await assert.rejects(pending, /child must belong to the admitted main frame/);h.assertClean();
  });
  await t.test('detached child', async () => {
    const { h, pending } = await run((_h, active) => ({ ...active,
      frame: { detached: true, parentFrame: () => h.mainFrame } }));
    await assert.rejects(pending, /must return an attached child frame/);h.assertClean();
  });
  await t.test('child detaches while identity body is pending', async () => {
    const h = personaActivationHarness(), active = { page: h.page, frame: h.childFrame };
    let resolveBody, mounted;const body = new Promise(resolve => { resolveBody = resolve; });
    const mountReturned = new Promise(resolve => { mounted = resolve; });
    const pending = mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => {
        h.navigate();const source = h.whoami();
        h.page.emit('response', h.response({ request: source, json: async () => body }));
        mounted();return active;
      } });
    await mountReturned;active.frame.detached = true;
    resolveBody({ user: { username: 'student_customer', role: 'customer' } });
    await assert.rejects(pending, /must return an attached child frame/);h.assertClean();
  });
  await t.test('main-frame identity changed', async () => {
    const { h, pending } = await run((value, active) => {
      value.replaceMainFrame({ url: () => 'http://127.0.0.1:35001/workshop/secureshop' });return active;
    });
    await assert.rejects(pending, /must retain the admitted main frame/);h.assertClean();
  });
  await t.test('committed URL changed', async () => {
    const { h, pending } = await run((value, active) => {
      value.setFrameUrl('http://127.0.0.1:35001/workshop/other');return active;
    });
    await assert.rejects(pending, /must remain on the committed workshop document/);h.assertClean();
  });
});

test('persona remount preserves mount rejection and drains every observer', async () => {
  const h = personaActivationHarness(), expected = new Error('controlled mount failure');let actual;
  try {
    await mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'customer', mount: async () => { throw expected; } });
  } catch (error) { actual = error; }
  assert.equal(actual, expected);h.assertClean();
});

test('persona remount rejects non-200 and mismatched server identity without a fallback request', async t => {
  for (const [label, status, body, pattern] of [
    ['status', 401, { error: 'denied' }, /must retain its separate shop session/],
    ['username', 200, { user: { username: 'student_customer', role: 'merchant' } }, /student_merchant/],
    ['role', 200, { user: { username: 'student_merchant', role: 'customer' } }, /merchant/],
  ]) await t.test(label, async () => {
    const h = personaActivationHarness();let requestCount = 0;
    await assert.rejects(mountVerifiedShopPersona({ page: h.page, origin: 'http://127.0.0.1:35001',
      role: 'merchant', mount: async () => {
        h.navigate();const source = h.whoami();requestCount++;
        h.page.emit('response', h.response({ request: source, status, json: async () => body }));
        return { page: h.page, frame: h.childFrame };
      } }), pattern);
    assert.equal(requestCount, 1);h.assertClean();
  });
});

function ssrfTurn(runId, resource, outcome = 'first_call_success') {
  const recovered = outcome === 'recovered', ambiguous = outcome === 'recovery_not_proven';
  return { runId, resource, recovery: {
    outcome, failedAttempts: ambiguous ? null : recovered ? 1 : 0, successfulAttempts: 1,
    actualModelDecision: true, failureCodes: recovered ? ['INVALID_TOOL_ARGUMENTS'] : [],
  } };
}

test('owned cohort setup uses authenticated config APIs and fails closed on missing or denied routes', async () => {
  const objectives = enabled => QUALIFIED_OBJECTIVE_IDS.map(objective_id => ({ objective_id, is_enabled: enabled }));
  const calls = [];
  const replies = [
    { success: true, workshopKey: 'secureshop_agent_security', objectives: objectives(false) },
    { success: true, affectedCount: QUALIFIED_OBJECTIVE_IDS.length },
    { success: true, challengeKey: 'secureshop_agent_security', enabled: true,
      exercise: { workshopKey: 'secureshop_agent_security', isVisible: true } },
    { success: true, workshopKey: 'secureshop_agent_security', objectives: objectives(true) },
    { success: true, challenges: [{ id: 'secureshop_agent_security',
      workshopKey: 'secureshop_agent_security', enabled: true }] },
  ];
  const request = async (url, options) => {
    calls.push({ pathname: new URL(url).pathname, method: options.method,
      authorization: options.headers.authorization, body: options.body && JSON.parse(options.body) });
    return { status: 200, async json() { return replies.shift(); } };
  };
  const result = await configureSecureShopCurriculum({ origin: 'http://127.0.0.1:35001',
    token: 'owned-admin-token-long-enough', request });
  assert.equal(result.visible, true);assert.deepEqual([...result.objectiveIds].sort(), [...QUALIFIED_OBJECTIVE_IDS].sort());
  assert.deepEqual(calls.map(row => [row.method, row.pathname]), [
    ['GET', '/api/admin/workshops/secureshop_agent_security/objectives'],
    ['POST', '/api/admin/workshops/secureshop_agent_security/objectives/bulk-toggle'],
    ['POST', '/api/admin/challenges/toggle'],
    ['GET', '/api/admin/workshops/secureshop_agent_security/objectives'],
    ['GET', '/api/admin/challenges'],
  ]);
  assert.ok(calls.every(row => row.authorization === 'Bearer owned-admin-token-long-enough'));
  assert.deepEqual(calls[1].body, { enabled: true });
  assert.deepEqual(calls[2].body, { challengeKey: 'secureshop_agent_security', enabled: true });
  for (const status of [403, 404]) {
    let count = 0;
    await assert.rejects(configureSecureShopCurriculum({ origin: 'http://127.0.0.1:35001',
      token: 'owned-admin-token-long-enough', request: async () => {
        count++;return { status, async json() { return { error: 'controlled rejection' }; } };
      } }), /Config API denied/);
    assert.equal(count, 1, 'Denied or missing config API must stop without a fallback mutation');
  }
});

function completeNative(log, reviewOutcome = 'attack_success') {
  let generation = launch.generation;
  const binding = (ownerId, role) => Object.freeze({ ...launch,
    generation: ownerId === 11 ? generation : launch.generation, platformOwnerId: ownerId,
    shopUserId: { customer: 31, merchant: 32, admin: 33 }[role] + (ownerId === 12 ? 10 : 0), role });
  return {
    version: 'secureshop-rendered-native-evidence-v1', capabilities: {
      persistedBindings: true, semanticVerifiers: true, authorityHistoryProgress: true,
      completeLifecycle: true, runInspector: true, foreignRunIsolation: true,
      resetReplay: true, reentry: true, logoutRevocation: true,
    },
    async forPersona({ ownerId, role }) {
      log.push(`persona:${ownerId}:${role}`);return { binding: binding(ownerId, role),
        evidence: { ssrf: `${role}-ssrf`, browser: `${role}-browser`, persona: `${role}-persona`,
          mcpTrust: `${role}-mcp`, review: `${role}-review` } };
    },
    async prepareScenario() { log.push('scenario');return { productId: 7,
      reviewInstructionBody: 'Reviewed existing indirect-injection scenario input',
      storedBrowserBody: 'Reviewed existing isolated renderer marker', personaMessageId: 9,
      personaSubject: 'Owned support fixture', reviewExpectation: reviewOutcome === 'defensive_control'
        ? { mode: 'defensive_control', decision: 'reject' }
        : { mode: 'attack_success', decision: 'approve' } }; },
    async expectedProgress(ownerId) { return { objectiveIds: QUALIFIED_OBJECTIVE_IDS,
      completedObjectiveIds: ownerId === 11 ? (reviewOutcome === 'defensive_control'
        ? QUALIFIED_OBJECTIVE_IDS.filter(id => id !== 'ss_content_followed') : QUALIFIED_OBJECTIVE_IDS)
        : ['ss_controlled_ssrf'],
      totalObjectives: 10, completedObjectives: ownerId === 11
        ? (reviewOutcome === 'defensive_control' ? 9 : 10) : 1 }; },
    async expectedStudentView(ownerId) { return { completedObjectives: ownerId === 11
      ? (reviewOutcome === 'defensive_control' ? 9 : 10) : 1,
      totalObjectives: 10, secureShopCompletedObjectives: ownerId === 11
        ? (reviewOutcome === 'defensive_control' ? 9 : 10) : 1,
      secureShopTotalObjectives: 10 }; },
    async verifyRunDetail() { return { verified: true }; },
    async verifyForeignRunIsolation() { log.push('foreign');return { persistedOwnerVerified: true }; },
    async snapshotLifecycle() { log.push('snapshot');return { stage: 'initial' }; },
    async snapshotBeforeReset() { log.push('before-reset');return { stage: 'before-reset' }; },
    async verifyReset(value) { assert.equal(value.response.cleanupComplete, true);generation++;log.push('reset');
      return { authorityHistoryProgressVerified: true, resourceCleanupVerified: true,
        credentialRevocationVerified: true }; },
    async captureResetReplayBaseline(value) {
      assert.equal(value.recoveryResponse.launch.credentialVersion,
        value.firstResponse.launch.credentialVersion + 1);
      log.push('recovery');return { recoveryVerified: true };
    },
    async verifyResetReplay(value) { assert.equal(value.firstResponse.resetId, value.replayResponse.resetId);
      log.push('replay');return { replayVerified: true }; },
    async verifyReentry(value) { assert.equal(value.afterBinding.generation, value.beforeBinding.generation + 1);
      log.push('reentry');return { reentryVerified: true }; },
    async verifyLogout() { log.push('logout');return { persistedPlatformSessionRevoked: true }; },
    assertLifecycleComplete() { log.push('lifecycle'); },
  };
}

test('review qualification plan keeps the positive goal and defensive lifecycle terminal distinct', () => {
  const positive = reviewQualificationPlan({ mode: 'attack_success', decision: 'approve' });
  assert.equal(positive.scope, 'rendered_secureshop_all_objectives');
  assert.equal(positive.qualified, true);assert.deepEqual(positive.completedObjectiveIds,
    QUALIFIED_OBJECTIVE_IDS);assert.deepEqual(positive.unqualifiedObjectiveIds, []);
  const defensive = reviewQualificationPlan({ mode: 'defensive_control', decision: 'reject' });
  assert.equal(defensive.scope, 'rendered_secureshop_defensive_review_lifecycle');
  assert.equal(defensive.qualified, false);assert.equal(defensive.defensive, true);
  assert.deepEqual(defensive.reviewObjectiveIds, ['ss_loop_observation', 'ss_content_persist']);
  assert.deepEqual(defensive.completedObjectiveIds,
    QUALIFIED_OBJECTIVE_IDS.filter(id => id !== 'ss_content_followed'));
  assert.deepEqual(defensive.unqualifiedObjectiveIds, ['ss_content_followed']);
  assert.throws(() => reviewQualificationPlan({ mode: 'observed_outcome' }));
  const observed = resolvedReviewQualificationPlan({ admissionMode: 'observed_outcome',
    resolvedMode: 'defensive_control', resolvedDecision: 'reject' },
  { mode: 'observed_outcome' });
  assert.equal(observed.scope, 'rendered_secureshop_defensive_review_lifecycle');
  assert.throws(() => resolvedReviewQualificationPlan({ admissionMode: 'observed_outcome',
    resolvedMode: 'attack_success', resolvedDecision: 'reject' }, { mode: 'observed_outcome' }));
  assert.throws(() => resolvedReviewQualificationPlan({ admissionMode: 'attack_success',
    resolvedMode: 'defensive_control', resolvedDecision: 'reject' },
  { mode: 'attack_success', decision: 'approve' }));
});

test('incomplete native lifecycle or inspector support fails before browser work', async () => {
  const partial = { version: 'secureshop-rendered-native-evidence-v1',
    capabilities: { persistedBindings: true, semanticVerifiers: true,
      authorityHistoryProgress: true, completeLifecycle: false, runInspector: false,
      foreignRunIsolation: false, resetReplay: false, reentry: false, logoutRevocation: false } };
  assert.throws(() => assertNativeEvidence(partial), error => error.code === 'SECURESHOP_RENDERED_QUALIFICATION_UNAVAILABLE'
    && error.message.includes('completeLifecycle') && error.message.includes('runInspector')
    && error.message.includes('foreignRunIsolation') && error.message.includes('resetReplay')
    && error.message.includes('logoutRevocation') && error.message.includes('prepareScenario'));
  let opened = 0;
  const qualify = createFullBackendRenderedSecureShop({ sessions: { async platformLogin() { opened++; } } });
  await assert.rejects(qualify({ browser: {}, origin: 'http://127.0.0.1:1', admin: { id: 1 },
    students: [{ id: 2 }, { id: 3 }], password: 'x', verifySession() {}, nativeEvidence: partial }),
  error => error.code === 'SECURESHOP_RENDERED_QUALIFICATION_UNAVAILABLE');
  assert.equal(opened, 0);
});

test('binding and run collectors require one exact launch, three shop identities and durable run coverage', () => {
  const bundles = Object.fromEntries(['customer', 'merchant', 'admin'].map((role, index) => [role,
    { binding: { ...launch, shopUserId: 31 + index, role } }]));
  assert.deepEqual(assertSameLaunch(bundles, 11), bundles.customer.binding);
  assert.throws(() => assertSameLaunch({ ...bundles,
    admin: { binding: { ...bundles.admin.binding, generation: 5 } } }, 11));
  assert.throws(() => assertSameLaunch({ ...bundles,
    admin: { binding: { ...bundles.admin.binding, shopUserId: 31 } } }, 11));
  const runs = collectRunIds({ a: { runId: 'a' }, b: [{ runId: 'b' }, { runId: 'c' }],
    c: [{ runId: 'd' }, { runId: 'e' }, { runId: 'f' }, { runId: 'g' }] });
  assert.deepEqual(runs, ['a', 'b', 'c', 'd', 'e', 'f', 'g']);
  assert.throws(() => collectRunIds({ runId: 'only-one' }));
});

test('shop login failure reports only bounded public diagnostics', async () => {
  const response = error => ({ status: () => 401, async json() { return { error }; },
    url: () => 'http://127.0.0.1:35001/api/secureshop/v2/auth/login',
    request: () => ({ method: () => 'POST' }) });
  const session = error => ({ page: { waitForResponse: async predicate => {
    const value = response(error);assert.equal(predicate(value), true);return value;
  } }, frame: { async waitForSelector() {},async click() {},async type() {} } });
  await assert.rejects(loginShopPersona(session('SecureShop launch unavailable'),
    'http://127.0.0.1:35001', 'customer'), error => error.code === 'SECURESHOP_PERSONA_LOGIN_REJECTED'
      && error.message.endsWith('SecureShop launch unavailable'));
  await assert.rejects(loginShopPersona(session('private repository detail'),
    'http://127.0.0.1:35001', 'customer'), error => error.code === 'SECURESHOP_PERSONA_LOGIN_REJECTED'
      && error.message.endsWith('Shop login rejected') && !error.message.includes('private repository detail'));
});

test('qualification failure diagnostic retains useful WaitTask cause without raw fixture values', () => {
  const secret = 'https://127.0.0.1/private?bearer=abcdefghijklmnopqrstuvwxyzABCDEFG123456';
  const error = Object.assign(new Error('Waiting failed'), { cause: Object.assign(
    new Error(`Protocol error (Runtime.callFunctionOn): ${secret} at /private/tmp/owned/source.js`),
    { name: 'ProtocolError' }) });
  const diagnostic = renderedQualificationFailureDiagnostic(error, 'mcp_trust');
  assert.deepEqual({ scope: diagnostic.scope, stage: diagnostic.stage, errorName: diagnostic.errorName,
    category: diagnostic.category, causeName: diagnostic.causeName }, {
    scope: 'rendered_secureshop_qualification_failure', stage: 'mcp_trust', errorName: 'Error',
    category: 'protocol_error', causeName: 'ProtocolError' });
  assert.ok(diagnostic.causeMessage.includes('Runtime.callFunctionOn'));
  assert.equal(diagnostic.causeMessage.includes(secret), false);
  assert.equal(diagnostic.causeMessage.includes('/private/'), false);
  assert.equal(diagnostic.causeMessage.length <= 320, true);
  assert.deepEqual(renderedQualificationFailureDiagnostic(new Error('Waiting failed'), 'persona_inbox'), {
    scope: 'rendered_secureshop_qualification_failure', stage: 'persona_inbox', errorName: 'Error',
    category: 'wait_cause_missing', causeName: null, causeMessage: null });
  assert.equal(renderedQualificationFailureDiagnostic(
    Object.assign(new Error('Waiting failed: 1000ms exceeded'), { name: 'TimeoutError' }), 'stored_browser').category,
  'wait_timeout');
});
test('optional persisted failure capture cannot replace or mask the primary diagnostic path', async () => {
  assert.equal(await readBoundedFailureEvidence(), null);
  assert.equal(await readBoundedFailureEvidence(async () => { throw Error('private diagnostic failure'); }), null);
  assert.deepEqual(await readBoundedFailureEvidence(async () => ({ scope: 'safe' })), { scope: 'safe' });
});
test('SSRF recovery projection retains only bounded enums, counts, codes and booleans', () => {
  const secret = 'http://127.0.0.1:39999/private?credential=do-not-export';
  const projected = projectSsrfClassifications('owner', { results: [
    { ...ssrfTurn('private-run-id', 'public-policy'), args: { policy_url: secret }, response: secret },
    { ...ssrfTurn('another-private-id', 'private-policy', 'recovery_not_proven'), rawTrace: secret },
  ] });
  assert.deepEqual(projected, {
    scope: 'rendered_secureshop_ssrf_recovery_classification', subject: 'owner', available: true,
    turns: [
      { resource: 'public-policy', outcome: 'first_call_success', failedAttempts: 0,
        successfulAttempts: 1, actualModelDecision: true, failureCodes: [],
        terminalWithoutTool: false, refusalProven: false },
      { resource: 'private-policy', outcome: 'recovery_not_proven', failedAttempts: null,
        successfulAttempts: 1, actualModelDecision: true, failureCodes: [],
        terminalWithoutTool: false, refusalProven: false },
    ],
  });
  const serialized = JSON.stringify(projected);
  assert.equal(serialized.includes(secret), false);assert.equal(serialized.includes('private-run-id'), false);
  assert.deepEqual(projectSsrfClassifications('sibling', { results: [
    ssrfTurn('one', 'public-policy'), { ...ssrfTurn('two', 'private-policy'),
      recovery: { outcome: secret, failedAttempts: 0, successfulAttempts: 1,
        actualModelDecision: true, failureCodes: [] } },
  ] }), { scope: 'rendered_secureshop_ssrf_recovery_classification', subject: 'sibling',
    available: false, turns: [] });
});

function catalogMountFixture({ orphan304 = false } = {}) {
  const origin = 'http://127.0.0.1:35001';
  const page = new EventEmitter();
  const context = { async newPage() { return page; },async close() {} };
  const frame = { async waitForFunction() {} };
  const body = { success: true, challenges: [{ workshopKey: 'secureshop_agent_security',
    objectives: QUALIFIED_OBJECTIVE_IDS.map(id => ({ id })), totalObjectives: QUALIFIED_OBJECTIVE_IDS.length }] };
  const response = status => ({ url: () => origin + '/api/workshop/challenges', status: () => status,
    headers: () => ({ etag: 'W/"catalog"' }),
    request: () => ({ method: () => 'GET', headers: () => ({ 'if-none-match': 'W/"catalog"' }) }),
    frame: () => ({ page: () => page }),json: async () => { assert.equal(status, 200);return body; } });
  page.browserContext = () => context;page.setDefaultTimeout = () => {};
  page._client = () => ({ async send(method, limits) {
    assert.equal(method, 'Network.configureDurableMessages');
    assert.deepEqual(limits, { maxTotalBufferSize: 64 * 1024 * 1024,
      maxResourceBufferSize: 8 * 1024 * 1024 });
  } });
  page.setRequestInterception = async () => {};page.evaluateOnNewDocument = async () => {};
  page.waitForResponse = predicate => new Promise(resolve => { page.goto = async () => {
    if (!orphan304) page.emit('response', response(200));
    const cached = response(304);assert.equal(predicate(cached), true);page.emit('response', cached);resolve(cached);
  }; });
  page.waitForSelector = async selector => {
    assert.equal(selector, 'iframe[title="SecureShop workshop"]');
    return { async contentFrame() { return frame; } };
  };
  return { origin, browser: { async createBrowserContext() { return context; } }, context, page };
}

test('each mounted persona owns catalog evidence that resolves only its observed prior 200', async () => {
  const contexts = [], catalogObservers = [], blocked = [], errors = [];
  for (const label of ['customer', 'merchant']) {
    const fixture = catalogMountFixture();
    const mounted = await mountWorkshop({ browser: fixture.browser, origin: fixture.origin,
      token: `${label}-token`, contexts, catalogObservers, blocked, errors });
    assert.equal(mounted.catalogEvidence, catalogObservers.at(-1));
    assert.equal(mounted.page, fixture.page);
  }
  assert.equal(contexts.length, 2);assert.equal(catalogObservers.length, 2);
  await Promise.all(catalogObservers.map(observer => observer.settle()));
  await Promise.all(catalogObservers.map(observer => observer.close()));
  assert.deepEqual(blocked, []);assert.deepEqual(errors, []);
});

test('a mounted persona rejects an orphan catalog 304 and retains failure through cleanup', async () => {
  const fixture = catalogMountFixture({ orphan304: true });
  const contexts = [], catalogObservers = [];
  await assert.rejects(mountWorkshop({ browser: fixture.browser, origin: fixture.origin,
    token: 'merchant-token', contexts, catalogObservers, blocked: [], errors: [] }),
  /304 requires a captured 200 representation/);
  assert.equal(contexts.length, 1);assert.equal(catalogObservers.length, 1);
  const cleanup = await Promise.allSettled(catalogObservers.map(observer => observer.close()));
  assert.equal(cleanup[0].status, 'rejected');
});

function renderedCatalogFrame(pages, { responseStatus = 200,
  responseOrigin = 'http://127.0.0.1:35001', responseFrame = 'main' } = {}) {
  assert.ok(Array.isArray(pages) && pages.length > 0);
  const state = { route: 'landing', pageIndex: 0, requests: [], productClicks: [], pending: null };
  let frame;const hostFrame = Object.freeze({ kind: 'controlled-host-main-frame' });
  const productLinks = () => pages[state.pageIndex].map(href => ({
    getAttribute(name) { return name === 'href' ? href : null; },
    click() { state.productClicks.push(href);state.route = 'detail'; },
  }));
  const nextButton = () => ({ textContent: 'Next', disabled: state.pageIndex >= pages.length - 1,
    click() {
      assert.ok(state.pending, 'Rendered page response must be observed before clicking Next');
      assert.equal(this.disabled, false);
      const nextIndex = state.pageIndex + 1;
      const response = { status: () => responseStatus,
        url: () => `${responseOrigin}/api/secureshop/products?limit=24&offset=${nextIndex * 24}&sort=newest`,
        request: () => ({ method: () => 'GET' }),
        frame: () => responseFrame === 'main' ? hostFrame : frame };
      assert.equal(state.pending.predicate(response), true, 'Only the exact next catalog request may complete the page');
      state.requests.push(response.url());state.pageIndex = nextIndex;
      state.pending.resolve(response);state.pending = null;
    } });
  const nav = () => ({
    querySelector(selector) {
      if (selector !== 'button[aria-current="page"]') return null;
      return { textContent: String(state.pageIndex + 1) };
    },
    querySelectorAll(selector) { return selector === 'button' ? [
      { textContent: 'Prev', disabled: state.pageIndex === 0 }, nextButton(),
    ] : []; },
  });
  const document = {
    querySelectorAll(selector) {
      if (selector === 'a') {
        if (state.route === 'landing') return [{ getAttribute: name => name === 'href' ? '/secureshop/catalog' : null,
          click() { state.route = 'catalog'; } }];
        return state.route === 'catalog' ? productLinks() : [];
      }
      if (selector === 'a[href^="/secureshop/product/"]') {
        return state.route === 'catalog' ? productLinks() : [];
      }
      return [];
    },
    querySelector(selector) {
      if (selector === 'nav[aria-label="Pagination"]') return state.route === 'catalog' ? nav() : null;
      if (selector === '.ss-skel') return null;
      return null;
    },
  };
  function inDocument(fn) {
    const prior = global.document;global.document = document;
    try { return fn(); } finally {
      if (prior === undefined) delete global.document;else global.document = prior;
    }
  }
  const page = { mainFrame: () => hostFrame,waitForResponse(predicate, { signal } = {}) {
    assert.equal(state.pending, null, 'Catalog page requests are sequential');
    return new Promise((resolve, reject) => {
      const abort = () => { state.pending = null;reject(Object.assign(Error('controlled response wait aborted'),
        { name: 'AbortError' })); };
      if (signal?.aborted) return abort();
      signal?.addEventListener('abort', abort, { once: true });
      state.pending = { predicate, resolve(value) {
        signal?.removeEventListener('abort', abort);resolve(value);
      } };
    });
  } };
  frame = {
    page: () => page,
    async evaluate(fn, ...args) { return inDocument(() => fn(...args)); },
    async waitForFunction(fn, _options, ...args) {
      assert.equal(inDocument(() => Boolean(fn(...args))), true, 'Rendered wait predicate must observe completed state');
    },
    async waitForSelector(selector) {
      if (selector === 'a[href^="/secureshop/product/"]') {
        assert.equal(state.route, 'catalog');assert.ok(productLinks().length > 0);return;
      }
      assert.equal(selector, 'textarea[aria-label="Review body"]');assert.equal(state.route, 'detail');
    },
  };
  return { frame, state };
}

test('owned product navigation follows completed rendered catalog pages and clicks only the exact assigned link', async () => {
  const fixture = renderedCatalogFrame([
    ['/secureshop/product/125', '/secureshop/product/124'],
    ['/secureshop/product/101'],
    ['/secureshop/product/77'],
    ['/secureshop/product/53'],
    ['/secureshop/product/29'],
    ['/secureshop/product/5', '/secureshop/product/1'],
  ]);
  await openProduct(fixture.frame, 1, 'http://127.0.0.1:35001');
  assert.equal(fixture.state.pageIndex, 5);
  assert.deepEqual(fixture.state.requests.map(value => new URL(value).searchParams.get('offset')),
    ['24', '48', '72', '96', '120']);
  assert.deepEqual(fixture.state.productClicks, ['/secureshop/product/1']);
});

test('owned product navigation fails closed when rendered pagination is exhausted', async () => {
  const fixture = renderedCatalogFrame([
    ['/secureshop/product/125'], ['/secureshop/product/101'], ['/secureshop/product/77'],
  ]);
  await assert.rejects(openProduct(fixture.frame, 1, 'http://127.0.0.1:35001'),
    /Exact owned product link was not found in the rendered catalog/);
  assert.equal(fixture.state.pageIndex, 2);
  assert.deepEqual(fixture.state.productClicks, []);
});

test('owned product navigation enforces a bounded exact and unique rendered target', async () => {
  const tooMany = renderedCatalogFrame(Array.from({ length: 65 }, (_, index) =>
    [`/secureshop/product/${200 - index}`]));
  await assert.rejects(openProduct(tooMany.frame, 1, 'http://127.0.0.1:35001'),
    /exceeded the rendered catalog page bound/);
  assert.equal(tooMany.state.pageIndex, 63, 'The qualifier must not request an unbounded sixty-fifth page');
  const duplicate = renderedCatalogFrame([['/secureshop/product/1', '/secureshop/product/1']]);
  await assert.rejects(openProduct(duplicate.frame, 1, 'http://127.0.0.1:35001'), /must be unique/);
  assert.deepEqual(duplicate.state.productClicks, []);
});

test('owned product navigation rejects a catalog response from another origin and drains its waiter', async () => {
  const fixture = renderedCatalogFrame([
    ['/secureshop/product/125'], ['/secureshop/product/1'],
  ], { responseOrigin: 'http://127.0.0.1:35002' });
  await assert.rejects(openProduct(fixture.frame, 1, 'http://127.0.0.1:35001'),
    /Only the exact next catalog request may complete the page/);
  assert.equal(fixture.state.pending, null);
  assert.deepEqual(fixture.state.productClicks, []);
});

test('owned product navigation accepts only the parent host fetch and rejects a forged iframe response', async () => {
  const fixture = renderedCatalogFrame([
    ['/secureshop/product/125'], ['/secureshop/product/1'],
  ], { responseFrame: 'iframe' });
  await assert.rejects(openProduct(fixture.frame, 1, 'http://127.0.0.1:35001'),
    /Only the exact next catalog request may complete the page/);
  assert.equal(fixture.state.pending, null);
  assert.deepEqual(fixture.state.productClicks, []);
});

test('foreign-run gate requires HTTP denial, an owner-free sibling list, and persisted ownership', async () => {
  const requested = [];
  const make = (role, detailStatus = 404) => ({ token: `${role}-token`, page: {
    async evaluate(fn, input) {
      requested.push([role, input.method, input.pathname]);
      if (input.pathname === '/api/admin/agent-runs') return { status: 403, body: {} };
      if (input.pathname === '/api/agent-runs') return { status: 200,
        body: { runs: role === 'sibling' ? [{ runId: 'sibling-run' }] : [] } };
      return { status: detailStatus, body: {} };
    },
  } });
  let persisted = 0;
  const nativeEvidence = { async verifyForeignRunIsolation(value) {
    assert.deepEqual(value, { ownerId: 11, siblingId: 12, runIds: ['owner-run-a', 'owner-run-b'] });
    persisted++;return { persistedOwnerVerified: true };
  } };
  const result = await verifyForeignRunIsolation({ owner: make('owner'), sibling: make('sibling'),
    ownerId: 11, siblingId: 12, runIds: ['owner-run-a', 'owner-run-b'], nativeEvidence });
  assert.equal(result.persistedOwnerVerified, true);assert.equal(persisted, 1);
  assert.deepEqual(requested, [
    ['owner', 'GET', '/api/admin/agent-runs'], ['sibling', 'GET', '/api/agent-runs'],
    ['sibling', 'GET', '/api/agent-runs/owner-run-a'],
    ['sibling', 'GET', '/api/agent-runs/owner-run-b'],
  ]);
  await assert.rejects(verifyForeignRunIsolation({ owner: make('owner'),
    sibling: make('sibling', 200), ownerId: 11, siblingId: 12,
    runIds: ['owner-run-a'], nativeEvidence }));
  assert.equal(persisted, 1, 'HTTP isolation failure must stop before a native success receipt');
});

test('controlled composition exercises every helper and lifecycle gate in fail-closed order', async () => {
  const log = [], closed = [], diagnostics = [], responseWaits = new Map(), mainFrames = new Map(), workshopFrames = new Map();
  const context = label => ({ async close() { log.push(`close:${label}`);closed.push(label); } });
  const page = label => ({ label,
    mainFrame() { if(!mainFrames.has(label))mainFrames.set(label,{label:`${label}-main`});return mainFrames.get(label); },
    async $(selector) { assert.equal(selector, 'iframe[title="SecureShop workshop"]');const frame={label,isConnected:true,
      async dispose() { log.push(`disposed:${label}`); }};workshopFrames.set(label,frame);return frame; },
    async goto() { log.push(`goto:${label}`); },
    async waitForFunction(fn, options, oldFrame) { assert.deepEqual(options, { timeout: 15000, polling: 'mutation' });
      assert.equal(oldFrame.label, label);const current={isConnected:true};let busy='false';
      const prior=global.document;global.document={querySelector:()=>({getAttribute:()=>busy,querySelector:()=>current})};
      try { assert.equal(fn(oldFrame),true);busy='true';assert.equal(fn(oldFrame),false);busy='false';current.isConnected=false;assert.equal(fn(oldFrame),false); }
      finally { if(prior===undefined)delete global.document;else global.document=prior; }
      log.push(`recovered:${label}`); },
    waitForResponse(predicate,options) { const count=(responseWaits.get(label)||0)+1;responseWaits.set(label,count);
      assert.equal(options.timeout,15000);assert.ok(options.signal instanceof AbortSignal);
      const recovered=count===2,request={ method:()=> 'POST',frame:()=>this.mainFrame(),postData:()=>JSON.stringify(recovered
          ? { launchId:launch.launchId,expectedCredentialVersion:12 }
          : { launchId:launch.launchId,expectedGeneration:launch.generation,idempotencyKey:'reset-owned-1' }) };
      const response={url:()=>`http://127.0.0.1:35001/api/auth/secureshop-launch/${recovered?'recover':'reset'}`,status:()=>200,request:()=>request,
        json: async () => recovered
          ? { preparationOnly:false,bearer:'a'.repeat(43),launch:{launchId:launch.launchId,
            generation:launch.generation+1,credentialVersion:13,expiresAt:'2030-01-02T03:04:05.000Z'} }
          : { cleanupComplete:true,resetId:'99999999-9999-4999-8999-999999999999',
            launch:{launchId:launch.launchId,generation:launch.generation+1,
              credentialVersion:12,expiresAt:'2030-01-02T03:04:05.000Z'} } };
      assert.equal(predicate(response),true);return Promise.resolve(response); },
    async evaluate(fn, input) {
      if (!input?.pathname) { const frame=workshopFrames.get(label);if(frame)frame.isConnected=false;log.push(`reset-click:${label}`);return undefined; }
      log.push(`api:${label}:${input.method}:${input.pathname}`);
      if (input.pathname === '/api/auth/secureshop-launch/reset') return { status: 200,
        body: { cleanupComplete: true, resetId: '99999999-9999-4999-8999-999999999999',
          launch: { launchId: launch.launchId, generation: launch.generation + 1,
            credentialVersion: 13, expiresAt: '2030-01-02T03:04:05.000Z' } } };
      if (input.pathname === '/api/auth/logout') return { status: 200, body: { success: true } };
      if (input.pathname === '/api/agent-runs') return { status: label === 'owner' ? 401 : 200,
        body: { runs: [] } };
      throw Error(`Unexpected API call ${label} ${input.pathname}`);
    },
  });
  const pages = { owner: page('owner'), merchant: page('merchant'), shopAdmin: page('shop-admin'),
    sibling: page('sibling'), platformAdmin: page('platform-admin') };
  let extraMount = 0;let activeOwnerPersona = null;
  const sessions = {
    async platformLogin({ user, contexts, catalogObservers }) {
      const label = user.id === 11 ? 'owner' : user.id === 12 ? 'sibling' : 'platformAdmin';
      const catalogEvidence = { async settle() { log.push('catalog-settle'); },
        async close() { log.push('catalog-close'); } };
      const value = { context: context(label), page: pages[label], token: `server-token-${label}`,
        catalogEvidence };
      catalogObservers.push(catalogEvidence);
      contexts.push(value.context);log.push(`platform:${label}`);return value;
    },
    async mountWorkshop({ contexts, reuse, catalogObservers }) {
      if (reuse) {
        if (reuse.page.label === 'owner') activeOwnerPersona = 'owner';
        return { ...reuse, frame: { label: `${reuse.page.label}-frame` } };
      }
      const label = extraMount++ === 0 ? 'merchant' : 'shopAdmin';
      const catalogEvidence = { async settle() { log.push('catalog-settle'); },
        async close() { log.push('catalog-close'); } };
      const value = { context: context(label), page: pages[label], frame: { label: `${label}-frame` },
        catalogEvidence };
      catalogObservers.push(catalogEvidence);
      contexts.push(value.context);activeOwnerPersona = value.page.label;return value;
    },
    async loginShopPersona(session, origin, role) {
      if (session.page.label !== 'sibling') assert.equal(activeOwnerPersona, session.page.label,
        'A later recovery must not rotate the bearer before this persona login');
      log.push(`shop:${session.page.label}:${role}`);
    },
    async activateShopPersona({ session, role }) {
      activeOwnerPersona = session.page.label;log.push(`recover:${session.page.label}:${role}`);return session;
    },
    async clickRoute(frame, href) { log.push(`route:${frame.label}:${href}`); },
    async openProduct(frame, productId) { log.push(`product:${frame.label}:${productId}`); },
  };
  let ssrfCalls = 0;
  const flows = {
    async ssrf(value) { assert.equal(value.evidence, 'customer-ssrf');ssrfCalls++;
      if (ssrfCalls === 1) assert.equal(activeOwnerPersona, 'owner');
      log.push(ssrfCalls === 1 ? 'flow:ssrf' : 'flow:sibling-ssrf');
      return { results: ssrfCalls === 1
        ? [ssrfTurn('run-1', 'public-policy'), ssrfTurn('run-2', 'private-policy', 'recovered')]
        : [ssrfTurn('sibling-run-1', 'public-policy', 'recovery_not_proven'),
          ssrfTurn('sibling-run-2', 'private-policy')] }; },
    async ssrfReplay(value) { assert.equal(value.result.results[1].runId, 'run-2');
      log.push('flow:ssrf-replay');return { replayed: true }; },
    async staleSsrfDenied(value) { assert.equal(value.result.results[1].runId, 'run-2');
      log.push('flow:stale-denial');return { staleLaunchHttpDenied: true }; },
    async browser(value) { assert.equal(activeOwnerPersona, 'owner');assert.equal(value.body, 'Reviewed existing isolated renderer marker');log.push('flow:browser');return { runId: 'run-3' }; },
    async persona(value) { assert.equal(activeOwnerPersona, 'merchant');assert.equal(value.evidence, 'merchant-persona');log.push('flow:persona');
      return { results: [{ runId: 'run-4' }, { runId: 'run-5' }] }; },
    async mcp(value) { assert.equal(activeOwnerPersona, 'shop-admin');assert.equal(value.evidence, 'admin-mcp');log.push('flow:mcp');
      return { results: [{ runId: 'run-6' }, { runId: 'run-7' }, { runId: 'run-8' }] }; },
    async review(value) { assert.equal(value.evidence, 'merchant-review');
      assert.equal(activeOwnerPersona, 'owner');assert.equal(value.merchantPage, pages.merchant);
      const active = await value.activateMerchant();assert.equal(active.page, pages.merchant);
      assert.equal(activeOwnerPersona, 'merchant');log.push('flow:review');return { runId: 'run-9',
        admissionMode: 'attack_success', resolvedMode: 'attack_success', resolvedDecision: 'approve',
        qualified: true, defensiveReviewVerified: false,
        objectiveIds: ['ss_loop_observation', 'ss_content_persist', 'ss_content_followed'] }; },
  };
  const parity = {
    async verifyProgressParity() { log.push('parity');return { completedObjectives: 10 }; },
    async verifyRunInspector({ runIds, sibling }) { assert.equal(runIds.length, 9);
      assert.equal(sibling.page, pages.sibling);log.push('inspector'); },
  };
  const nativeEvidence = completeNative(log);
  const configureCurriculum = async ({ token }) => {
    assert.equal(token, 'server-token-platformAdmin');log.push('curriculum');
    return { workshopKey: 'secureshop_agent_security', objectiveIds: QUALIFIED_OBJECTIVE_IDS, visible: true };
  };
  const qualify = createFullBackendRenderedSecureShop({ sessions, flows, parity, configureCurriculum,
    writeDiagnostic(value) { diagnostics.push(value); } });
  const result = await qualify({ browser: {}, origin: 'http://127.0.0.1:35001',
    admin: { id: 10 }, students: [{ id: 11 }, { id: 12 }], password: 'server-password',
    verifySession() {}, nativeEvidence, timeoutMs: 420000 });
  assert.equal(result.qualified, true);assert.deepEqual([...result.objectiveIds].sort(), [...QUALIFIED_OBJECTIVE_IDS].sort());
  assert.equal(result.ssrfClassifications.length, 2);
  assert.deepEqual(result.ssrfClassifications.map(value => [value.subject, value.available,
    value.turns.map(turn => turn.outcome)]), [
    ['owner', true, ['first_call_success', 'recovered']],
    ['sibling', true, ['recovery_not_proven', 'first_call_success']],
  ]);
  assert.deepEqual(log.filter(value => value.startsWith('flow:')),
    ['flow:ssrf', 'flow:ssrf-replay', 'flow:sibling-ssrf', 'flow:browser', 'flow:persona',
      'flow:mcp', 'flow:review', 'flow:stale-denial']);
  assert.ok(log.indexOf('scenario') > log.indexOf('route:owner-frame:/secureshop/catalog'));
  assert.ok(log.indexOf('curriculum') < log.indexOf('platform:owner'));
  assert.ok(log.indexOf('scenario') > log.indexOf('route:merchant-frame:/secureshop/merchant/inbox'));
  assert.ok(log.indexOf('shop:owner:customer') < log.indexOf('shop:merchant:merchant'));
  assert.ok(log.indexOf('shop:merchant:merchant') < log.indexOf('shop:shop-admin:admin'));
  assert.ok(log.filter(value => value.startsWith('recover:')).length >= 6,
    'Each role segment reacquires the sole current launch capability through the rendered workshop');
  assert.ok(log.indexOf('parity') > log.indexOf('flow:review'));
  assert.ok(log.indexOf('inspector') > log.indexOf('parity'));
  const resetClick = log.indexOf('reset-click:owner');
  assert.equal(log[resetClick - 1], 'recover:owner:customer',
    'Reset waits for a freshly recovered rendered customer session');
  assert.ok(log.indexOf('lifecycle') > log.indexOf('reset'));
  assert.ok(log.indexOf('recovered:owner') > log.indexOf('reset'));
  assert.ok(log.indexOf('recovery') > log.indexOf('flow:stale-denial'));
  assert.ok(log.indexOf('replay') > log.indexOf('recovery'));
  assert.ok(log.indexOf('reentry') > log.indexOf('replay'));
  assert.ok(log.indexOf('logout') > log.indexOf('lifecycle'));
  assert.ok(log.indexOf('catalog-close') < log.findIndex(value => value.startsWith('close:')),
    'Catalog observer closes before browser context cleanup');
  assert.deepEqual(closed.sort(), ['merchant', 'owner', 'platformAdmin', 'shopAdmin', 'sibling'].sort());
  assert.deepEqual(diagnostics, [], 'Successful qualification must not emit failure evidence');
});

test('failure in a semantic flow closes every created context and never reaches lifecycle success', async () => {
  const log = [], closed = [], observersClosed = [], diagnostics = [];
  const base = completeNative(log);
  const originalForPersona = base.forPersona.bind(base);let captures = 0;
  base.forPersona = async input => {
    const value = await originalForPersona(input);
    if (input.ownerId !== 11 || input.role !== 'customer') return value;
    return { ...value, evidence: { ...value.evidence, ssrf: { async captureFailure() { captures++;
      return { scope: 'rendered_secureshop_ssrf_failure_evidence', ownerScopeVerified: true,
        attemptPresent: true, requestBound: true, requestMissing: false, requestAmbiguous: false,
        requestTurnBound: false, requestTurnMissing: true, requestTurnAmbiguous: false,
        errorCategory: 'selected_request_invalid', selectedExpectedTool: true };
    } } } };
  };
  const sessions = {
    async platformLogin({ user, contexts, catalogObservers }) {
      const catalogEvidence = { async close() { observersClosed.push(user.id); } };
      const value = { context: { async close() { closed.push(user.id); } },
        page: {}, token: `token-${user.id}`, catalogEvidence };
      contexts.push(value.context);catalogObservers.push(catalogEvidence);return value;
    },
    async mountWorkshop({ contexts, reuse, catalogObservers }) { if (reuse) return { ...reuse, frame: {} };
      const catalogEvidence = { async close() { observersClosed.push('extra'); } };
      const value = { context: { async close() { closed.push('extra'); } }, page: {}, frame: {},
        catalogEvidence };
      contexts.push(value.context);catalogObservers.push(catalogEvidence);return value; },
    async loginShopPersona() {},async activateShopPersona({ session }) { return session; },
    async clickRoute() {},async openProduct() {},
  };
  const original = Object.assign(new Error('Waiting failed'), { cause: Object.assign(
    new Error('Protocol error (Runtime.callFunctionOn): controlled closed context'), { name: 'ProtocolError' }) });
  const flows = { async ssrf() { return { results: [ssrfTurn('failure-run-1', 'public-policy'),
      ssrfTurn('failure-run-2', 'private-policy', 'recovery_not_proven')] }; },
    async ssrfReplay() { throw original; } };
  const qualify = createFullBackendRenderedSecureShop({ sessions, flows,
    configureCurriculum: async () => ({ workshopKey: 'secureshop_agent_security',
      objectiveIds: QUALIFIED_OBJECTIVE_IDS, visible: true }),
    parity: { verifyProgressParity() {}, verifyRunInspector() {} },
    writeDiagnostic(value) { diagnostics.push(value); } });
  let caught;try { await qualify({ browser: {}, origin: 'http://127.0.0.1:35001', admin: { id: 10 },
    students: [{ id: 11 }, { id: 12 }], password: 'x', verifySession() {}, nativeEvidence: base,
    timeoutMs: 1000 }); } catch (error) { caught = error; }
  assert.equal(caught, original, 'Central diagnostics must preserve the original failure object');
  assert.equal(closed.length, 5);assert.ok(!log.includes('lifecycle'));
  assert.equal(observersClosed.length, 5, 'Every mounted or login-page observer closes on failure');
  assert.equal(diagnostics.length, 1);assert.equal(diagnostics[0].stage, 'owner_ssrf_replay');
  assert.equal(diagnostics[0].category, 'protocol_error');
  assert.deepEqual(diagnostics[0].ssrfClassifications.map(value => [value.subject,
    value.turns.map(turn => turn.outcome)]), [
    ['owner', ['first_call_success', 'recovery_not_proven']],
  ]);
  assert.equal(captures, 1);assert.deepEqual(diagnostics[0].failureEvidence, {
    scope: 'rendered_secureshop_ssrf_failure_evidence', ownerScopeVerified: true,
    attemptPresent: true, requestBound: true, requestMissing: false, requestAmbiguous: false,
    requestTurnBound: false, requestTurnMissing: true, requestTurnAmbiguous: false,
    errorCategory: 'selected_request_invalid', selectedExpectedTool: true,
  });
});
