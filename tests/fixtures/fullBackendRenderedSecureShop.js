'use strict';

const assert = require('node:assert/strict');
const { QUALIFIED_OBJECTIVE_IDS, WORKSHOP_KEY } = require('../../server/config/secureshopCurriculum');
const { assertCanonicalSecureShopChallenge } = require('./renderedSecureShopSession');
const { runRenderedControlledSsrf, replayRenderedControlledSsrf,
  verifyStaleRenderedSsrfDenied } = require('./renderedSecureShopSsrf');
const { runRenderedStoredBrowser, getStoredBrowserResponseFailure } = require('./renderedSecureShopBrowser');
const { runRenderedPersonaInbox } = require('./renderedSecureShopPersona');
const { runRenderedMcpTrust } = require('./renderedSecureShopMcpTrust');
const { runRenderedSecureShopReviewWorkflow, projectModerationFailureDiagnostic,
  validateReviewExpectation }
  = require('./renderedSecureShopReviewWorkflow');
const { createSecureShopCatalogEvidence } = require('./secureShopCatalogEvidence');
const { configureDurableNetworkMessages } = require('./configureDurableNetworkMessages');

const STORED_BROWSER_PROBE_BODY = '<img src="/owned-parent-missing.png" onerror="alert(\'owned-parent-frame\')">';

const ROLES = Object.freeze(['customer', 'merchant', 'admin']);
const SHOP_USERS = Object.freeze({ customer: 'student_customer', merchant: 'student_merchant',
  admin: 'student_admin' });
const SHOP_LOGIN_ERRORS = new Set(['SecureShop launch unavailable', 'Invalid shop credentials',
  'Shop session capacity reached', 'Bound SecureShop operation unavailable']);
const RENDERED_CATALOG_PAGE_SIZE = 24;
const MAX_RENDERED_CATALOG_PAGES = 64;
const MAX_INSPECTOR_RUN_ORDINAL = 64;
const INSPECTOR_RESPONSE_TIMEOUT_MS = 15_000;
const RUN_INSPECTOR_PROJECTIONS = new Set(['student', 'admin']);
const RUN_INSPECTOR_PHASES = new Set(['cache', 'list_wait', 'list_status', 'list_body',
  'filter_wait', 'filter_status', 'filter_body', 'target_presence', 'target_selection',
  'detail_wait', 'detail_status', 'detail_body', 'detail_binding', 'native_verify']);
const REQUIRED_CAPABILITIES = Object.freeze(['persistedBindings', 'semanticVerifiers',
  'authorityHistoryProgress', 'completeLifecycle', 'runInspector',
  'foreignRunIsolation', 'resetReplay', 'reentry', 'logoutRevocation']);

function reviewQualificationPlan(expectation) {
  const reviewed = validateReviewExpectation(expectation);
  assert.notEqual(reviewed.mode, 'observed_outcome',
    'Observed moderation outcome must be resolved from verified effect evidence');
  const defensive = reviewed.mode === 'defensive_control';
  return Object.freeze({ mode: reviewed.mode, defensive,
    scope: defensive ? 'rendered_secureshop_defensive_review_lifecycle'
      : 'rendered_secureshop_all_objectives',
    qualified: !defensive,
    completedObjectiveIds: Object.freeze(defensive
      ? QUALIFIED_OBJECTIVE_IDS.filter(id => id !== 'ss_content_followed')
      : [...QUALIFIED_OBJECTIVE_IDS]),
    reviewObjectiveIds: Object.freeze(defensive
      ? ['ss_loop_observation', 'ss_content_persist']
      : ['ss_loop_observation', 'ss_content_persist', 'ss_content_followed']),
    unqualifiedObjectiveIds: Object.freeze(defensive ? ['ss_content_followed'] : []),
  });
}
function resolvedReviewQualificationPlan(result, admission) {
  const admitted = validateReviewExpectation(admission);
  assert.ok(result && typeof result === 'object');
  assert.deepEqual(Object.keys(result).filter(key => ['admissionMode', 'resolvedMode', 'resolvedDecision']
    .includes(key)).sort(), ['admissionMode', 'resolvedDecision', 'resolvedMode']);
  assert.equal(result.admissionMode, admitted.mode);
  const expectation = result.resolvedMode === 'attack_success'
    ? { mode: 'attack_success', decision: 'approve' }
    : result.resolvedMode === 'defensive_control'
      ? { mode: 'defensive_control', decision: 'reject' } : null;
  assert.ok(expectation, 'Verified moderation result must resolve a reviewed branch');
  assert.equal(result.resolvedDecision, expectation.decision);
  if (admitted.mode !== 'observed_outcome') assert.equal(result.resolvedMode, admitted.mode);
  return reviewQualificationPlan(expectation);
}
const DIAGNOSTIC_NAMES = new Set(['Error', 'AssertionError', 'TimeoutError', 'ProtocolError',
  'TargetCloseError', 'AbortError', 'TypeError', 'ReferenceError', 'AggregateError']);

function safeErrorName(value) {
  return DIAGNOSTIC_NAMES.has(value?.name) ? value.name : 'UnknownError';
}
function safeWaitCauseMessage(error) {
  if (error?.message !== 'Waiting failed' || typeof error?.cause?.message !== 'string') return null;
  return error.cause.message.replace(/[\r\n\t]+/g, ' ')
    .replace(/https?:\/\/\S+/gi, '[url]')
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/gi, '[uuid]')
    .replace(/\b[A-Za-z0-9_-]{32,}\b/g, '[token]')
    .replace(/(?:\/private|\/Users|\/tmp)\/\S+/g, '[path]')
    .replace(/\{[^{}\r\n]{0,500}\}/g, '[object]')
    .replace(/\s+/g, ' ').trim().slice(0, 320) || null;
}
function renderedQualificationFailureDiagnostic(error, stage = 'unknown') {
  const message = typeof error?.message === 'string' ? error.message : '';
  const cause = error?.cause, causeMessage = typeof cause?.message === 'string' ? cause.message : '';
  let category = 'unknown';
  if (/^Waiting failed: \d+ms exceeded$/.test(message)) category = 'wait_timeout';
  else if (message === 'Waiting failed') {
    if (!cause) category = 'wait_cause_missing';
    else if (/detached frame|Frame detached/.test(causeMessage)) category = 'frame_detached';
    else if (/Execution context was destroyed|Cannot find context with specified id|DiscardedBrowsingContextError/.test(causeMessage)) category = 'execution_context_changed';
    else if (/Target closed|Session closed|Page closed|Browser has disconnected/.test(causeMessage)) category = 'target_closed';
    else if (causeMessage.startsWith('Protocol error')) category = 'protocol_error';
    else if (cause?.name === 'TypeError' || cause?.name === 'ReferenceError') category = 'predicate_error';
    else if (cause?.name === 'AbortError') category = 'aborted';
    else category = 'wait_other';
  } else if (error?.name === 'AssertionError') category = 'assertion';
  else if (error?.name === 'AbortError') category = 'aborted';
  const runInspector = projectRunInspectorFailure(error?.runInspectorFailure);
  return Object.freeze({ scope: 'rendered_secureshop_qualification_failure', stage,
    errorName: safeErrorName(error), category, causeName: cause ? safeErrorName(cause) : null,
    causeMessage: safeWaitCauseMessage(error), ...(runInspector ? { runInspector } : {}) });
}
function projectRunInspectorFailure(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== 'phase,projection,runOrdinal'
    || !RUN_INSPECTOR_PROJECTIONS.has(value.projection)
    || !RUN_INSPECTOR_PHASES.has(value.phase)
    || !Number.isInteger(value.runOrdinal) || value.runOrdinal < 1
    || value.runOrdinal > MAX_INSPECTOR_RUN_ORDINAL) return null;
  return Object.freeze({ projection: value.projection, phase: value.phase,
    runOrdinal: value.runOrdinal });
}
function attachRunInspectorFailure(error, projection, phase, runOrdinal) {
  const original = error instanceof Error ? error : new Error('Run inspector verification failed');
  const projected = projectRunInspectorFailure({ projection, phase, runOrdinal });
  assert.ok(projected, 'Bounded run inspector diagnostic required');
  try { Object.defineProperty(original, 'runInspectorFailure', { value: projected,
    configurable: true, enumerable: false }); } catch {}
  return original;
}
async function writeBoundedDiagnostic(writeDiagnostic, value) {
  let timer;const pending = Promise.resolve().then(() => writeDiagnostic(value));pending.catch(() => {});
  try { await Promise.race([pending, new Promise(resolve => {
    timer = setTimeout(resolve, 1000);timer.unref?.();
  })]); } catch {} finally { clearTimeout(timer); }
}
async function readBoundedFailureEvidence(readEvidence) {
  if (typeof readEvidence !== 'function') return null;
  let timer;const pending=Promise.resolve().then(readEvidence);pending.catch(()=>{});
  try{return await Promise.race([pending,new Promise(resolve=>{
    timer=setTimeout(()=>resolve(null),1000);timer.unref?.();
  })]);}catch{return null;}finally{clearTimeout(timer);}
}

function assertNativeEvidence(nativeEvidence) {
  assert.equal(nativeEvidence?.version, 'secureshop-rendered-native-evidence-v1');
  const missing = REQUIRED_CAPABILITIES.filter(key => nativeEvidence.capabilities?.[key] !== true);
  for (const method of ['forPersona', 'prepareScenario', 'expectedProgress', 'expectedStudentView',
    'verifyRunDetail', 'snapshotLifecycle', 'snapshotBeforeReset', 'verifyReset',
    'verifyForeignRunIsolation', 'captureResetReplayBaseline', 'verifyResetReplay', 'verifyReentry', 'verifyLogout',
    'assertLifecycleComplete']) {
    if (typeof nativeEvidence?.[method] !== 'function') missing.push(method);
  }
  if (missing.length) {
    throw Object.assign(new Error(`SecureShop rendered qualification prerequisites unavailable: ${[...new Set(missing)].join(', ')}`),
      { code: 'SECURESHOP_RENDERED_QUALIFICATION_UNAVAILABLE' });
  }
  return nativeEvidence;
}

function assertSameLaunch(bundles, ownerId) {
  assert.deepEqual(Object.keys(bundles).sort(), [...ROLES].sort());
  const reference = bundles.customer.binding;
  for (const role of ROLES) {
    const binding = bundles[role]?.binding;
    assert.equal(binding?.platformOwnerId, ownerId);assert.equal(binding?.role, role);
    for (const key of ['launchId', 'scenarioId', 'generation', 'platformSessionId']) {
      assert.equal(binding?.[key], reference[key], `All shop personas must use one platform ${key}`);
    }
    assert.ok(Number.isSafeInteger(binding.shopUserId) && binding.shopUserId > 0);
  }
  assert.equal(new Set(ROLES.map(role => bundles[role].binding.shopUserId)).size, 3,
    'Customer, merchant and admin must be distinct persisted shop identities');
  return reference;
}

function collectRunIds(results) {
  const ids = new Set();
  function visit(value) {
    if (!value || typeof value !== 'object') return;
    if (typeof value.runId === 'string' && value.runId) ids.add(value.runId);
    if (Array.isArray(value)) value.forEach(visit);
    else for (const [key, child] of Object.entries(value)) if (key !== 'binding') visit(child);
  }
  visit(results);
  assert.ok(ids.size >= 7, 'All model/browser workflows must expose their durable run IDs');
  return Object.freeze([...ids]);
}

async function configurePage(page, origin, blocked, errors, token) {
  await configureDurableNetworkMessages(page);
  page.setDefaultTimeout(15000);
  page.on('pageerror', error => errors.push(error.message));
  await page.setRequestInterception(true);
  page.on('request', request => {
    const url = new URL(request.url());
    if (url.protocol === 'data:' || url.origin === origin) void request.continue();
    else { blocked.push(url.origin);void request.abort('blockedbyclient'); }
  });
  if (token) await page.evaluateOnNewDocument(value => {
    try { if (window.parent === window) localStorage.setItem('token', value); } catch {}
  }, token);
}

function responseMatches(origin, pathname, method) {
  return response => {
    const url = new URL(response.url());
    return url.origin === origin && url.pathname === pathname && response.request().method() === method;
  };
}

async function configureSecureShopCurriculum({ origin, token, request = fetch }) {
  assert.equal(typeof token, 'string');assert.ok(token.length > 20);
  const parsed = new URL(origin);assert.equal(parsed.origin, origin);assert.equal(parsed.protocol, 'http:');
  assert.equal(parsed.hostname, '127.0.0.1');assert.ok(parsed.port);assert.equal(typeof request, 'function');
  const call = async (pathname, method = 'GET', body) => {
    const response = await request(origin + pathname, {
      signal: AbortSignal.timeout(10000), redirect: 'error',
      method, headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    assert.equal(typeof response?.status, 'number', `Missing config response for ${pathname}`);
    let value;
    try { value = await response.json(); } catch { throw new Error(`Invalid config response for ${pathname}`); }
    assert.equal(response.status, 200, `Config API denied ${method} ${pathname}`);
    assert.equal(value?.success, true, `Config API failed ${method} ${pathname}`);
    return value;
  };
  const objectivesPath = `/api/admin/workshops/${WORKSHOP_KEY}/objectives`;
  const assertObjectives = value => {
    assert.equal(value.workshopKey, WORKSHOP_KEY);assert.ok(Array.isArray(value.objectives));
    assert.deepEqual(value.objectives.map(row => row.objective_id).sort(), [...QUALIFIED_OBJECTIVE_IDS].sort());
    assert.equal(new Set(value.objectives.map(row => row.objective_id)).size, QUALIFIED_OBJECTIVE_IDS.length);
    return value.objectives;
  };
  assertObjectives(await call(objectivesPath));
  const enabled = await call(`${objectivesPath}/bulk-toggle`, 'POST', { enabled: true });
  assert.equal(enabled.affectedCount, QUALIFIED_OBJECTIVE_IDS.length);
  const visible = await call('/api/admin/challenges/toggle', 'POST', {
    challengeKey: WORKSHOP_KEY, enabled: true,
  });
  assert.equal(visible.challengeKey, WORKSHOP_KEY);assert.equal(visible.enabled, true);
  assert.equal(visible.exercise?.workshopKey, WORKSHOP_KEY);assert.equal(visible.exercise?.isVisible, true);
  const readback = assertObjectives(await call(objectivesPath));
  assert.ok(readback.every(row => row.is_enabled === true), 'All qualified SecureShop objectives must be enabled');
  const catalog = await call('/api/admin/challenges');
  const matches = catalog.challenges.filter(row => row.workshopKey === WORKSHOP_KEY || row.id === WORKSHOP_KEY);
  assert.equal(matches.length, 1, 'Exactly one SecureShop admin catalog row');assert.equal(matches[0].enabled, true);
  return Object.freeze({ workshopKey: WORKSHOP_KEY,
    objectiveIds: Object.freeze(readback.map(row => row.objective_id)), visible: true });
}

async function platformLogin({ browser, origin, user, password, verifySession, contexts,
  blocked, errors, catalogObservers }) {
  assert.ok(Array.isArray(catalogObservers), 'Shared catalog observer registry required');
  const context = await browser.createBrowserContext();contexts.push(context);
  const page = await context.newPage();await configurePage(page, origin, blocked, errors);
  const catalogEvidence = createSecureShopCatalogEvidence({ page, origin });
  catalogObservers.push(catalogEvidence);
  await page.goto(origin + '/workshop-login', { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('input[placeholder="Enter your username"]', { visible: true });
  await page.type('input[placeholder="Enter your username"]', user.username);
  await page.type('input[placeholder="Enter your password"]', password);
  const pending = page.waitForResponse(responseMatches(origin, '/api/auth/login', 'POST'));
  await page.click('button[type="submit"]');const response = await pending;assert.equal(response.status(), 200);
  const body = await response.json();assert.equal(Number(body.user.id), user.id);
  assert.ok(typeof body.token === 'string' && body.token.length > 20);
  await verifySession(body.token, user.id);
  return Object.freeze({ context, page, token: body.token, catalogEvidence });
}

async function mountWorkshop({ browser, origin, token, contexts, blocked, errors, reuse,
  catalogObservers }) {
  assert.ok(Array.isArray(catalogObservers), 'Shared catalog observer registry required');
  const context = reuse?.context || await browser.createBrowserContext();
  if (!reuse) contexts.push(context);
  const page = reuse?.page || await context.newPage();
  if (!reuse) await configurePage(page, origin, blocked, errors, token);
  const catalogEvidence = reuse?.catalogEvidence || createSecureShopCatalogEvidence({ page, origin });
  if (!reuse?.catalogEvidence) catalogObservers.push(catalogEvidence);
  const catalog = page.waitForResponse(responseMatches(origin, '/api/workshop/challenges', 'GET'));
  await page.goto(origin + '/workshop/secureshop', { waitUntil: 'domcontentloaded' });
  const catalogResponse = await catalog;
  const catalogBody = await catalogEvidence.read(catalogResponse);
  assertCanonicalSecureShopChallenge(catalogBody);
  const element = await page.waitForSelector('iframe[title="SecureShop workshop"]', { visible: true });
  const frame = await element.contentFrame();assert.ok(frame);await frame.waitForFunction(() => window.origin === 'null', { polling: 100 });
  return Object.freeze({ context, page, frame, element, token,
    catalogEvidence });
}

async function loginShopPersona(session, origin, role) {
  assert.ok(ROLES.includes(role));const { page, frame } = session;
  await frame.waitForSelector('a[href="/secureshop/login"]');await frame.click('a[href="/secureshop/login"]');
  await frame.waitForSelector('#ss-login-user');
  await frame.type('#ss-login-user', SHOP_USERS[role]);await frame.type('#ss-login-pw', 'student123');
  const pending = page.waitForResponse(responseMatches(origin, '/api/secureshop/v2/auth/login', 'POST'));
  await frame.click('button[type="submit"]');const response = await pending;
  let body = null;try { body = await response.json(); } catch {}
  if (response.status() !== 200) {
    const reason = SHOP_LOGIN_ERRORS.has(body?.error) ? body.error : 'Shop login rejected';
    throw Object.assign(new Error(`SecureShop persona login rejected (${response.status()}): ${reason}`),
      { code: 'SECURESHOP_PERSONA_LOGIN_REJECTED' });
  }
  assert.equal(body?.user?.username, SHOP_USERS[role]);assert.equal(body.user?.role, role);
  await frame.waitForSelector('button[aria-label="Account menu"]');
  return Object.freeze({ id: Number(body.user.id), username: body.user.username, role });
}

async function mountVerifiedShopPersona({ page, origin, role, mount,
  identityResponseTimeoutMs = INSPECTOR_RESPONSE_TIMEOUT_MS }) {
  assert.ok(page && typeof page.mainFrame === 'function' && typeof page.waitForResponse === 'function');
  assert.ok(ROLES.includes(role));assert.equal(typeof mount, 'function');
  assert.ok(Number.isSafeInteger(identityResponseTimeoutMs) && identityResponseTimeoutMs > 0
    && identityResponseTimeoutMs <= INSPECTOR_RESPONSE_TIMEOUT_MS,
  'Persona identity response timeout must be bounded');
  assert.equal(typeof page.setCacheEnabled, 'function', 'Pinned Puppeteer cache control required');
  await page.setCacheEnabled(false);
  const mainFrame = page.mainFrame();assert.ok(mainFrame);
  assert.equal(typeof page._client, 'function', 'Pinned Puppeteer CDP session required');
  const client = page._client();assert.ok(client && typeof client.on === 'function'
    && typeof client.off === 'function');
  const workshopUrl = new URL('/workshop/secureshop', origin).href;
  const whoamiUrl = new URL('/api/secureshop/v2/auth/whoami', origin);
  let navigationRequest = null, navigationEpoch = null, navigationCommit = null;
  let identityRequest = null, identityEpoch = null;
  let observerError = null;
  const fail = message => { if (!observerError) observerError = new Error(message); };
  const exactWhoami = request => {
    if (request?.method?.() !== 'GET') return false;
    let url;try { url = new URL(request.url()); } catch { return false; }
    return url.origin === whoamiUrl.origin && url.pathname === whoamiUrl.pathname
      && url.search === '' && url.hash === '' && url.username === '' && url.password === '';
  };
  const onRequest = request => {
    const requestFrame = request?.frame?.();
    if (request?.isNavigationRequest?.() && requestFrame === mainFrame) {
      if (request.method?.() !== 'GET' || request.url?.() !== workshopUrl) {
        fail('Unexpected main-frame navigation during SecureShop persona activation');return;
      }
      if (request.redirectChain?.().length) {
        fail('SecureShop persona activation navigation cannot redirect');return;
      }
      if (navigationRequest) fail('SecureShop persona activation requires exactly one navigation epoch');
      else navigationRequest = request;
      return;
    }
    if (!exactWhoami(request)) return;
    if (requestFrame !== mainFrame) {
      fail('SecureShop identity request must originate from the fresh host main document');return;
    }
    if (identityRequest) fail('SecureShop persona activation requires one fresh identity request');
    else identityRequest = request;
  };
  const onRequestWillBeSent = event => {
    const url = event?.request?.url, method = event?.request?.method;
    if (event?.type === 'Document' && url === workshopUrl) {
      if (method !== 'GET' || event.redirectResponse || event.requestId !== event.loaderId) {
        fail('SecureShop persona activation document epoch is invalid');return;
      }
      if (navigationEpoch) fail('SecureShop persona activation requires exactly one document epoch');
      else navigationEpoch = Object.freeze({ requestId: event.requestId,
        loaderId: event.loaderId, frameId: event.frameId });
      return;
    }
    if (method !== 'GET' || url !== whoamiUrl.href) return;
    if (identityEpoch) fail('SecureShop persona activation requires one identity epoch');
    else identityEpoch = Object.freeze({ requestId: event.requestId,
      loaderId: event.loaderId, frameId: event.frameId });
  };
  const onFrameNavigated = event => {
    const frame = event?.frame;
    if (!frame || frame.parentId !== undefined) return;
    if (frame.url !== workshopUrl) {
      fail('Unexpected main-frame commit during SecureShop persona activation');return;
    }
    if (!frame.id || !frame.loaderId) {
      fail('SecureShop persona activation commit identity is incomplete');return;
    }
    if (navigationCommit) fail('SecureShop persona activation requires exactly one document commit');
    else navigationCommit = Object.freeze({ frameId: frame.id, loaderId: frame.loaderId });
  };
  page.on('request', onRequest);
  client.on('Network.requestWillBeSent', onRequestWillBeSent);
  client.on('Page.frameNavigated', onFrameNavigated);
  const waiterAbort = new AbortController();
  const navigation = page.waitForResponse(response => response.request() === navigationRequest,
    { signal: waiterAbort.signal, timeout: identityResponseTimeoutMs });
  void navigation.catch(() => {});
  const identity = page.waitForResponse(response => response.request() === identityRequest,
    { signal: waiterAbort.signal, timeout: identityResponseTimeoutMs }).then(async response => Object.freeze({
    request: response.request(), status: response.status(),
    body: await readInspectorResponseJson(response, waiterAbort.signal, identityResponseTimeoutMs),
  }));
  void identity.catch(() => {});
  try {
    const active = await mount();
    if (observerError) throw observerError;
    const [navigationResponse, captured] = await Promise.all([navigation, identity]);
    if (observerError) throw observerError;
    assert.equal(page.mainFrame(), mainFrame,
      'SecureShop persona activation must retain the admitted main frame');
    assert.equal(mainFrame.url(), workshopUrl,
      'SecureShop persona activation must remain on the committed workshop document');
    assert.equal(active?.page, page,
      'SecureShop persona activation must return the page that performed the identity request');
    const activeFrame = active?.frame;assert.ok(activeFrame);
    const detached = typeof activeFrame.detached === 'boolean' ? activeFrame.detached
      : typeof activeFrame.isDetached === 'function' ? Boolean(activeFrame.isDetached()) : null;
    assert.equal(detached, false, 'SecureShop persona activation must return an attached child frame');
    assert.equal(activeFrame.parentFrame?.(), mainFrame,
      'SecureShop persona activation child must belong to the admitted main frame');
    assert.ok(navigationRequest && navigationEpoch && navigationCommit,
      'SecureShop persona activation requires one committed navigation epoch');
    assert.equal(navigationRequest.id, navigationEpoch.requestId,
      'Puppeteer navigation request must match the admitted CDP document request');
    assert.equal(navigationEpoch.frameId, navigationCommit.frameId,
      'SecureShop document request and commit must use one frame');
    assert.equal(navigationEpoch.loaderId, navigationCommit.loaderId,
      'SecureShop document request and commit must use one loader');
    assert.equal(navigationResponse.request(), navigationRequest,
      'SecureShop navigation response must bind the admitted document request');
    assert.equal(navigationResponse.status(), 200,
      'SecureShop persona activation requires an HTTP 200 workshop document');
    assert.ok(identityRequest && identityEpoch,
      'SecureShop persona activation requires one bound identity request');
    assert.equal(identityRequest.id, identityEpoch.requestId,
      'Puppeteer identity request must match the admitted CDP identity request');
    assert.equal(identityEpoch.frameId, navigationEpoch.frameId,
      'SecureShop identity request must use the admitted document frame');
    assert.equal(identityEpoch.loaderId, navigationEpoch.loaderId,
      'SecureShop identity request must use the admitted document loader');
    assert.equal(captured.request, identityRequest,
      'SecureShop persona identity must use the request admitted in this navigation epoch');
    assert.equal(captured.status, 200, `Recovered ${role} frame must retain its separate shop session`);
    assert.equal(captured.body?.user?.username, SHOP_USERS[role]);
    assert.equal(captured.body.user?.role, role);
    return active;
  } finally {
    page.off('request', onRequest);
    client.off('Network.requestWillBeSent', onRequestWillBeSent);
    client.off('Page.frameNavigated', onFrameNavigated);
    waiterAbort.abort();await Promise.allSettled([navigation, identity]);
  }
}

async function activateShopPersona({ browser, origin, session, role, contexts, blocked, errors,
  catalogObservers }) {
  assert.ok(ROLES.includes(role));assert.ok(session?.page);
  const active = await mountVerifiedShopPersona({ page: session.page, origin, role,
    mount: () => mountWorkshop({ browser, origin, token: session.token, contexts, blocked, errors,
      reuse: session, catalogObservers }) });
  await active.frame.waitForSelector('button[aria-label="Account menu"]');
  return active;
}

async function clickRoute(frame, href, ready) {
  await frame.waitForFunction(path => [...document.querySelectorAll('a')].some(node => node.getAttribute('href') === path),
    { polling: 'mutation' }, href);
  await frame.evaluate(path => {
    const links = [...document.querySelectorAll('a')].filter(node => node.getAttribute('href') === path);
    if (links.length < 1) throw Error('Exact SecureShop navigation target required');
    links[0].click();
  }, href);
  await frame.waitForSelector(ready);
}

async function openProduct(frame, productId, origin) {
  const expectedOrigin = new URL(origin).origin;
  await clickRoute(frame, '/secureshop/catalog', 'a[href^="/secureshop/product/"]');
  const href = `/secureshop/product/${productId}`;
  for (let visited = 0; visited < MAX_RENDERED_CATALOG_PAGES; visited++) {
    const rendered = await frame.evaluate(path => {
      const hrefs = [...document.querySelectorAll('a[href^="/secureshop/product/"]')]
        .map(node => node.getAttribute('href')).filter(Boolean).sort();
      return { hrefs, matchCount: hrefs.filter(value => value === path).length };
    }, href);
    const { matchCount } = rendered;
    if (matchCount > 1) throw Error('Exact owned product link must be unique');
    if (matchCount === 1) {
      await frame.evaluate(path => {
        const links = [...document.querySelectorAll('a')].filter(node => node.getAttribute('href') === path);
        if (links.length !== 1) throw Error('Exact owned product link required');links[0].click();
      }, href);
      await frame.waitForSelector('textarea[aria-label="Review body"]');
      return;
    }
    const pagination = await frame.evaluate(() => {
      const nav = document.querySelector('nav[aria-label="Pagination"]');
      const next = nav ? [...nav.querySelectorAll('button')]
        .filter(node => node.textContent.trim() === 'Next') : [];
      return { nextCount: next.length, nextDisabled: next.length === 1 && next[0].disabled === true };
    });
    if (pagination.nextCount !== 1 || pagination.nextDisabled) {
      throw Error('Exact owned product link was not found in the rendered catalog');
    }
    if (visited === MAX_RENDERED_CATALOG_PAGES - 1) {
      throw Error('Exact owned product link exceeded the rendered catalog page bound');
    }
    const nextPage = visited + 2;
    const controller = new AbortController();
    const page = frame.page();
    const hostFrame = page.mainFrame();
    const completed = page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.origin === expectedOrigin && url.pathname === '/api/secureshop/products'
        && response.request().method() === 'GET' && response.frame() === hostFrame
        && [...url.searchParams.keys()].sort().join(',') === 'limit,offset,sort'
        && url.searchParams.get('sort') === 'newest'
        && url.searchParams.get('limit') === String(RENDERED_CATALOG_PAGE_SIZE)
        && url.searchParams.get('offset') === String((nextPage - 1) * RENDERED_CATALOG_PAGE_SIZE);
    }, { signal: controller.signal });
    void completed.catch(() => {});
    try {
      await frame.evaluate(() => {
        const nav = document.querySelector('nav[aria-label="Pagination"]');
        const next = nav ? [...nav.querySelectorAll('button')]
          .filter(node => node.textContent.trim() === 'Next') : [];
        if (next.length !== 1 || next[0].disabled) throw Error('Exact rendered catalog next action required');
        next[0].click();
      });
    } catch (error) {
      controller.abort();await completed.catch(() => {});throw error;
    }
    const response = await completed;
    assert.equal(response.status(), 200, 'Rendered catalog page request must succeed');
    await frame.waitForFunction(previous => {
      const hrefs = [...document.querySelectorAll('a[href^="/secureshop/product/"]')]
        .map(node => node.getAttribute('href')).filter(Boolean).sort();
      return !document.querySelector('.ss-skel') && hrefs.length > 0
        && JSON.stringify(hrefs) !== JSON.stringify(previous);
    }, { polling: 'mutation' }, rendered.hrefs);
  }
  throw Error('Exact owned product link exceeded the rendered catalog page bound');
}

async function api(session, pathname, method = 'GET', body) {
  return session.page.evaluate(async ({ pathname, method, body, token }) => {
    const response = await fetch(pathname, { method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    let value = null;
    try { value = await response.json(); } catch {}
    return { status: response.status, body: value };
  }, { pathname, method, body, token: session.token });
}

async function verifyForeignRunIsolation({ owner, sibling, ownerId, siblingId, runIds,
  nativeEvidence }) {
  assert.equal((await api(owner, '/api/admin/agent-runs')).status, 403);
  const siblingRuns = await api(sibling, '/api/agent-runs');assert.equal(siblingRuns.status, 200);
  assert.ok(Array.isArray(siblingRuns.body?.runs));
  for (const runId of runIds) {
    assert.equal((await api(sibling, `/api/agent-runs/${runId}`)).status, 404);
    assert.ok(!siblingRuns.body.runs.some(row => row.runId === runId));
  }
  const receipt = await nativeEvidence.verifyForeignRunIsolation({ ownerId, siblingId, runIds });
  assert.equal(receipt?.persistedOwnerVerified, true);
  return receipt;
}

async function readInspectorResponseJson(response, signal, timeoutMs) {
  if (signal.aborted) throw Object.assign(new Error('Aborted'), { name: 'AbortError' });
  let rejectAborted, timer;
  const aborted = new Promise((_resolve, reject) => { rejectAborted = reject; });
  const onAbort = () => rejectAborted(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
  signal.addEventListener('abort', onAbort, { once: true });
  // CDP response.json() itself is not cancellable. Keep the raw read observed,
  // but detach it after this bounded wrapper settles; owned browser teardown is
  // the authority that ultimately releases the underlying protocol operation.
  let reading;
  try { reading = Promise.resolve(response.json()); }
  catch (error) { reading = Promise.reject(error); }
  void reading.catch(() => {});
  const deadline = new Promise((_resolve, reject) => {
    timer = setTimeout(() => reject(Object.assign(
      new Error('Inspector response body deadline exceeded'), { name: 'TimeoutError' })), timeoutMs);
    timer.unref?.();
  });
  try { return await Promise.race([reading, aborted, deadline]); }
  finally { clearTimeout(timer);signal.removeEventListener('abort', onAbort); }
}
function captureInspectorResponse(page, predicate, timeoutMs, signal) {
  const state = { body: null };
  const pending = page.waitForResponse(predicate, { signal, timeout: timeoutMs })
    .then(response => {
      const status = response.status();
      state.body = status === 200 ? readInspectorResponseJson(response, signal, timeoutMs)
        : Promise.resolve(null);
      void state.body.catch(() => {});
      return Object.freeze({ status, body: state.body });
    });
  void pending.catch(() => {});
  return Object.freeze({ pending, async drain() {
    await Promise.allSettled([pending]);
    if (state.body) await Promise.allSettled([state.body]);
  } });
}
function captureResetRecovery(page, origin, timeoutMs) {
  assert.ok(Number.isInteger(timeoutMs) && timeoutMs > 0
    && timeoutMs <= INSPECTOR_RESPONSE_TIMEOUT_MS, 'Reset recovery response deadline required');
  const controller = new AbortController(), mainFrame = page.mainFrame(), state = { body: null };
  const matches = responseMatches(origin, '/api/auth/secureshop-launch/recover', 'POST');
  const pending = page.waitForResponse(response => matches(response)
    && response.request().frame() === mainFrame, { signal: controller.signal, timeout: timeoutMs })
    .then(response => {
      const status = response.status(), request = response.request();
      state.body = status === 200 ? readInspectorResponseJson(response, controller.signal, timeoutMs)
        : Promise.resolve(null);
      void state.body.catch(() => {});
      return Object.freeze({ status, request, body: state.body });
    });
  void pending.catch(() => {});
  return Object.freeze({ pending, async close() {
    controller.abort();await Promise.allSettled([pending]);
    if (state.body) await Promise.allSettled([state.body]);
  } });
}

async function verifyRunInspector({ owner, sibling, administrator, ownerId, siblingId, runIds,
  nativeEvidence, origin, inspectorResponseTimeoutMs = INSPECTOR_RESPONSE_TIMEOUT_MS }) {
  assert.ok(Array.isArray(runIds) && runIds.length > 0
    && runIds.length <= MAX_INSPECTOR_RUN_ORDINAL, 'Bounded run inspector targets required');
  assert.ok(Number.isInteger(inspectorResponseTimeoutMs) && inspectorResponseTimeoutMs > 0
    && inspectorResponseTimeoutMs <= INSPECTOR_RESPONSE_TIMEOUT_MS,
  'Bounded run inspector response deadline required');
  for (const [session, prefix, route, projection] of [[owner, '/api/agent-runs', '/workshop/agent-runs', 'student'],
    [administrator, '/api/admin/agent-runs', '/admin/agent-runs', 'admin']]) {
    let phase = 'cache', runOrdinal = 1;
    try {
      // Qualify fresh authenticated responses. Puppeteer can expose the network
      // 304 behind a browser's effective cached 200; that is not a fresh body.
      await session.page.setCacheEnabled(false);
      for (const [index, runId] of runIds.entries()) {
        runOrdinal = index + 1;
        const controller = new AbortController(), captures = [];
        try {
          // Arm exact detail capture before navigation because the component may
          // auto-select the target from the first list response. Capture its JSON
          // in the response callback so Chromium cannot evict the body meanwhile.
          phase = 'detail_wait';
          const detail = captureInspectorResponse(session.page,
            responseMatches(origin, `${prefix}/${runId}`, 'GET'), inspectorResponseTimeoutMs,
            controller.signal);captures.push(detail);
          phase = 'list_wait';
          const listed = captureInspectorResponse(session.page,
            responseMatches(origin, prefix, 'GET'), inspectorResponseTimeoutMs,
            controller.signal);captures.push(listed);
          await session.page.goto(origin + route, { waitUntil: 'domcontentloaded' });
          const listResponse = await listed.pending;
          phase = 'list_status';assert.equal(listResponse.status, 200);
          phase = 'list_body';let rows = (await listResponse.body)?.runs;
          if (projection === 'admin') {
            await session.page.waitForSelector('[aria-label="Owner ID"]');
            phase = 'filter_wait';
            const filtered = captureInspectorResponse(session.page, response => {
              const url = new URL(response.url());return url.origin === origin && url.pathname === prefix
                && url.searchParams.get('ownerId') === String(ownerId)
                && response.request().method() === 'GET';
            }, inspectorResponseTimeoutMs, controller.signal);captures.push(filtered);
            await session.page.type('[aria-label="Owner ID"]', String(ownerId));
            const filteredResponse = await filtered.pending;
            phase = 'filter_status';assert.equal(filteredResponse.status, 200);
            phase = 'filter_body';rows = (await filteredResponse.body)?.runs;
          }
          assert.ok(Array.isArray(rows) && rows.some(row => row.runId === runId));
          phase = 'target_presence';
          await session.page.waitForFunction(id => [...document.querySelectorAll('[aria-label="Agent runs"] button[data-run-id]')]
            .some(node => node.dataset.runId === id), { polling: 'mutation' }, runId);
          phase = 'target_selection';
          await session.page.evaluate(id => {
            const matches = [...document.querySelectorAll('[aria-label="Agent runs"] button[data-run-id]')]
              .filter(node => node.dataset.runId === id);
            if (matches.length !== 1) throw Error('Expected exact run target');
            if (matches[0].getAttribute('aria-pressed') !== 'true') matches[0].click();
          }, runId);
          phase = 'detail_wait';const response = await detail.pending;
          phase = 'detail_status';assert.equal(response.status, 200);
          phase = 'detail_body';const body = await response.body;
          assert.ok(body && typeof body === 'object' && !Array.isArray(body));
          phase = 'detail_binding';assert.equal(body.run?.runId, runId);
          if (projection === 'admin') assert.equal(String(body.run.ownerId), String(ownerId));
          else assert.equal(body.run.ownerId, undefined);
          phase = 'native_verify';
          const verified = await nativeEvidence.verifyRunDetail({ ownerId, runId, body, projection });
          assert.equal(verified?.verified, true);
        } finally {
          controller.abort();await Promise.allSettled(captures.map(capture => capture.drain()));
        }
      }
    } catch (error) {
      throw attachRunInspectorFailure(error, projection, phase, runOrdinal);
    }
  }
  return verifyForeignRunIsolation({ owner, sibling, ownerId, siblingId, runIds, nativeEvidence });
}

async function verifyProgressParity({ owner, administrator, ownerId, siblingId, nativeEvidence,
  origin, timeoutMs, expectedCompletedObjectiveIds = QUALIFIED_OBJECTIVE_IDS }) {
  const expected = await nativeEvidence.expectedProgress(ownerId);
  assert.equal(expected.totalObjectives, QUALIFIED_OBJECTIVE_IDS.length);
  assert.deepEqual([...expected.completedObjectiveIds].sort(), [...expectedCompletedObjectiveIds].sort());
  assert.equal(expected.completedObjectives, expectedCompletedObjectiveIds.length);
  const siblingExpected = await nativeEvidence.expectedProgress(siblingId);
  assert.equal(siblingExpected.totalObjectives, QUALIFIED_OBJECTIVE_IDS.length);
  assert.deepEqual(siblingExpected.completedObjectiveIds, ['ss_controlled_ssrf']);
  assert.equal(siblingExpected.completedObjectives, 1);
  await owner.page.goto(origin + '/workshop/secureshop', { waitUntil: 'domcontentloaded' });
  await owner.page.waitForFunction((completed, total) => document.body.textContent.includes(`${completed} of ${total} objectives completed`),
    { timeout: timeoutMs, polling: 'mutation' }, expectedCompletedObjectiveIds.length,
    QUALIFIED_OBJECTIVE_IDS.length);
  for (const id of [ownerId, siblingId]) {
    const expectedView = await nativeEvidence.expectedStudentView(id);
    const pathname = `/api/admin/student-workshop-view/${id}`;
    const pending = administrator.page.waitForResponse(responseMatches(origin, pathname, 'GET'));
    await administrator.page.goto(origin + `/admin/student-workshop-view?studentId=${id}`, { waitUntil: 'domcontentloaded' });
    const response = await pending;assert.equal(response.status(), 200);const view = await response.json();
    assert.equal(Number(view.student?.id), id);
    assert.equal(view.overview.completedObjectives, expectedView.completedObjectives);
    assert.equal(view.overview.totalObjectives, expectedView.totalObjectives);
    const card = view.challenges?.find(row => row.workshopKey === 'secureshop_agent_security');
    assert.equal(card?.completedObjectives, expectedView.secureShopCompletedObjectives);
    assert.equal(card?.totalObjectives, expectedView.secureShopTotalObjectives);
  }
  return expected;
}

const SSRF_RECOVERY_OUTCOMES = new Set([
  'first_call_success', 'recovered', 'recovery_not_proven', 'no_effect',
]);
const SSRF_RECOVERY_CODES = new Set(['INVALID_TOOL_ARGUMENTS', 'INVALID_TOOL_SELECTION']);
function projectSsrfClassifications(subject, value) {
  assert.ok(['owner', 'sibling'].includes(subject));
  const unavailable = () => Object.freeze({
    scope: 'rendered_secureshop_ssrf_recovery_classification', subject, available: false,
    turns: Object.freeze([]),
  });
  if (!Array.isArray(value?.results) || value.results.length !== 2) return unavailable();
  const resources = value.results.map(row => row?.resource);
  if (resources[0] !== 'public-policy' || resources[1] !== 'private-policy') return unavailable();
  const turns = [];
  for (const row of value.results) {
    const recovery = row?.recovery, outcome = recovery?.outcome;
    const codes = Array.isArray(recovery?.failureCodes) ? recovery.failureCodes : null;
    if (!SSRF_RECOVERY_OUTCOMES.has(outcome) || !codes || codes.length > 8
      || codes.some(code => !SSRF_RECOVERY_CODES.has(code))
      || !Number.isInteger(recovery?.successfulAttempts) || recovery.successfulAttempts < 0
      || recovery.successfulAttempts > 1 || typeof recovery?.actualModelDecision !== 'boolean'
      || !(recovery.failedAttempts === null || (Number.isInteger(recovery.failedAttempts)
        && recovery.failedAttempts >= 0 && recovery.failedAttempts <= 8))) return unavailable();
    if ((outcome === 'first_call_success' && (recovery.failedAttempts !== 0
        || recovery.successfulAttempts !== 1 || codes.length !== 0 || recovery.actualModelDecision !== true))
      || (outcome === 'recovered' && (recovery.failedAttempts < 1
        || recovery.successfulAttempts !== 1 || codes.length !== recovery.failedAttempts
        || recovery.actualModelDecision !== true))
      || (outcome === 'recovery_not_proven' && (recovery.failedAttempts !== null
        || recovery.successfulAttempts !== 1 || codes.length !== 0 || recovery.actualModelDecision !== true))
      || (outcome === 'no_effect' && recovery.successfulAttempts !== 0)) return unavailable();
    turns.push(Object.freeze({ resource: row.resource, outcome,
      failedAttempts: recovery.failedAttempts, successfulAttempts: recovery.successfulAttempts,
      actualModelDecision: recovery.actualModelDecision, failureCodes: Object.freeze([...codes]),
      terminalWithoutTool: recovery.terminalWithoutTool === true,
      refusalProven: recovery.refusalProven === true }));
  }
  return Object.freeze({ scope: 'rendered_secureshop_ssrf_recovery_classification', subject,
    available: true, turns: Object.freeze(turns) });
}

function createFullBackendRenderedSecureShop(dependencies = {}) {
  const flows = Object.freeze({ ssrf: runRenderedControlledSsrf, browser: runRenderedStoredBrowser,
    persona: runRenderedPersonaInbox, mcp: runRenderedMcpTrust,
    review: runRenderedSecureShopReviewWorkflow, ssrfReplay: replayRenderedControlledSsrf,
    staleSsrfDenied: verifyStaleRenderedSsrfDenied, ...(dependencies.flows || {}) });
  const sessions = dependencies.sessions || { platformLogin, mountWorkshop, loginShopPersona,
    activateShopPersona, clickRoute, openProduct };
  const parity = dependencies.parity || { verifyRunInspector, verifyProgressParity };
  const configureCurriculum = dependencies.configureCurriculum || configureSecureShopCurriculum;
  const writeDiagnostic = dependencies.writeDiagnostic
    || (value => process.stderr.write(`# ${JSON.stringify(value)}\n`));
  return async function qualify({ browser, origin, admin, students, password, verifySession,
    nativeEvidence, timeoutMs = 420000 }) {
    assertNativeEvidence(nativeEvidence);
    assert.equal(students?.length, 2);assert.equal(new Set([admin.id, students[0].id, students[1].id]).size, 3);
    assert.equal(typeof verifySession, 'function');assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 420000);
    const contexts = [], catalogObservers = [], blocked = [], errors = [], ssrfClassifications = [];
    let stage = 'setup',ssrfFailureEvidence=null;
    try {
      const adminLogin = await sessions.platformLogin({ browser, origin, user: admin, password,
        verifySession, contexts, blocked, errors, catalogObservers });
      stage = 'curriculum';const curriculum = await configureCurriculum({ origin, token: adminLogin.token });
      assert.equal(curriculum?.workshopKey, WORKSHOP_KEY);assert.equal(curriculum?.visible, true);
      assert.deepEqual([...curriculum.objectiveIds].sort(), [...QUALIFIED_OBJECTIVE_IDS].sort());
      const login = await sessions.platformLogin({ browser, origin, user: students[0], password,
        verifySession, contexts, blocked, errors, catalogObservers });
      let owner = await sessions.mountWorkshop({ browser, origin, token: login.token, contexts,
        blocked, errors, reuse: login, catalogObservers });
      await sessions.loginShopPersona(owner, origin, 'customer');
      let merchant = await sessions.mountWorkshop({ browser, origin, token: login.token, contexts,
        blocked, errors, catalogObservers });
      await sessions.loginShopPersona(merchant, origin, 'merchant');
      let shopAdmin = await sessions.mountWorkshop({ browser, origin, token: login.token, contexts,
        blocked, errors, catalogObservers });
      await sessions.loginShopPersona(shopAdmin, origin, 'admin');
      const siblingLogin = await sessions.platformLogin({ browser, origin, user: students[1], password,
        verifySession, contexts, blocked, errors, catalogObservers });
      const sibling = await sessions.mountWorkshop({ browser, origin, token: siblingLogin.token, contexts,
        blocked, errors, reuse: siblingLogin, catalogObservers });
      await sessions.loginShopPersona(sibling, origin, 'customer');
      const bundles = {};
      for (const role of ROLES) bundles[role] = await nativeEvidence.forPersona({ ownerId: students[0].id, role });
      const siblingBundle = await nativeEvidence.forPersona({ ownerId: students[1].id, role: 'customer' });
      const launch = assertSameLaunch(bundles, students[0].id);assert.equal(siblingBundle.binding.platformOwnerId, students[1].id);

      // These owned rows are provisioned only when the real sandboxed UI asks
      // for Catalog and Inbox. Never replace this with repository fixture setup.
      owner = await sessions.activateShopPersona({ browser, origin, session: owner, role: 'customer',
        contexts, blocked, errors, catalogObservers });
      await sessions.clickRoute(owner.frame, '/secureshop/catalog', 'a[href^="/secureshop/product/"]');
      merchant = await sessions.activateShopPersona({ browser, origin, session: merchant, role: 'merchant',
        contexts, blocked, errors, catalogObservers });
      await sessions.clickRoute(merchant.frame, '/secureshop/merchant/inbox', '[data-testid="persona-inbox-acl"]');
      stage = 'scenario';const scenario = await nativeEvidence.prepareScenario({ ownerId: students[0].id, launch, bundles });
      assert.ok(Number.isSafeInteger(scenario.productId) && scenario.productId > 0);
      for (const key of ['reviewInstructionBody', 'storedBrowserBody', 'personaSubject']) assert.ok(typeof scenario[key] === 'string' && scenario[key].length > 0);
      assert.ok(scenario.reviewExpectation && typeof scenario.reviewExpectation === 'object');
      validateReviewExpectation(scenario.reviewExpectation);
      assert.ok(Number.isSafeInteger(scenario.personaMessageId) && scenario.personaMessageId > 0);
      const lifecycleBefore = await nativeEvidence.snapshotLifecycle({ ownerId: students[0].id,
        siblingId: students[1].id });

      const results = {};
      stage = 'owner_activation';
      owner = await sessions.activateShopPersona({ browser, origin, session: owner, role: 'customer',
        contexts, blocked, errors, catalogObservers });
      await sessions.clickRoute(owner.frame, '/secureshop/home', 'section[aria-labelledby="controlled-ssrf-title"]');
      ssrfFailureEvidence=bundles.customer.evidence.ssrf;
      stage = 'owner_ssrf';results.ssrf = await flows.ssrf({ page: owner.page, frame: owner.frame, origin,
        evidence: bundles.customer.evidence.ssrf, timeoutMs });
      ssrfClassifications.push(projectSsrfClassifications('owner', results.ssrf));
      stage = 'owner_ssrf_replay';const ssrfReplay = await flows.ssrfReplay({ frame: owner.frame, result: results.ssrf,
        evidence: bundles.customer.evidence.ssrf, timeoutMs });
      assert.equal(ssrfReplay?.replayed, true);
      // Give the sibling genuine durable state before the owner reset. The
      // reset verifier must prove this independently earned credit survives.
      ssrfFailureEvidence=siblingBundle.evidence.ssrf;
      stage = 'sibling_ssrf';const siblingResult = await flows.ssrf({ page: sibling.page, frame: sibling.frame, origin,
        evidence: siblingBundle.evidence.ssrf, timeoutMs });
      ssrfClassifications.push(projectSsrfClassifications('sibling', siblingResult));
      await sessions.openProduct(owner.frame, scenario.productId, origin);
      stage = 'stored_browser';results.browser = await flows.browser({ page: owner.page, frame: owner.frame, origin,
        productId: scenario.productId, body: scenario.storedBrowserBody,
        evidence: bundles.customer.evidence.browser, timeoutMs });
      stage = 'persona_activation';
      merchant = await sessions.activateShopPersona({ browser, origin, session: merchant, role: 'merchant',
        contexts, blocked, errors, catalogObservers });
      await sessions.clickRoute(merchant.frame, '/secureshop/merchant/inbox', '[data-testid="persona-inbox-acl"]');
      stage = 'persona_inbox';results.persona = await flows.persona({ page: merchant.page, frame: merchant.frame, origin,
        messageId: scenario.personaMessageId, subject: scenario.personaSubject,
        evidence: bundles.merchant.evidence.persona, timeoutMs });
      stage = 'mcp_activation';
      shopAdmin = await sessions.activateShopPersona({ browser, origin, session: shopAdmin, role: 'admin',
        contexts, blocked, errors, catalogObservers });
      await sessions.clickRoute(shopAdmin.frame, '/secureshop/admin/mcp', 'section[aria-label="Controlled MCP trust lab"]');
      stage = 'mcp_trust';results.mcp = await flows.mcp({ page: shopAdmin.page, frame: shopAdmin.frame, origin,
        evidence: bundles.admin.evidence.mcpTrust, timeoutMs });
      stage = 'review_activation';
      owner = await sessions.activateShopPersona({ browser, origin, session: owner, role: 'customer',
        contexts, blocked, errors, catalogObservers });
      await sessions.openProduct(owner.frame, scenario.productId, origin);
      stage = 'review_workflow';results.review = await flows.review({ page: owner.page, merchantPage: merchant.page,
        customerFrame: owner.frame,
        merchantFrame: merchant.frame, origin, productId: scenario.productId,
        reviewBody: scenario.reviewInstructionBody, evidence: bundles.merchant.evidence.review,
        expectation: scenario.reviewExpectation,
        activateMerchant: async () => {
          stage = 'review_merchant_activation';
          merchant = await sessions.activateShopPersona({ browser, origin, session: merchant, role: 'merchant',
            contexts, blocked, errors, catalogObservers });
          await sessions.clickRoute(merchant.frame, '/secureshop/merchant/reviews', '[data-testid="reviews-moderate-all"]');
          stage = 'review_workflow';
          return merchant;
        },
        timeoutMs });
      const reviewPlan = resolvedReviewQualificationPlan(results.review, scenario.reviewExpectation);
      const expectedCompletedObjectiveIds = reviewPlan.completedObjectiveIds;
      assert.deepEqual([...results.review.objectiveIds].sort(),
        [...reviewPlan.reviewObjectiveIds].sort());
      stage = 'progress_parity';const expected = await parity.verifyProgressParity({ owner, administrator: adminLogin,
        ownerId: students[0].id, siblingId: students[1].id, nativeEvidence, origin, timeoutMs,
        expectedCompletedObjectiveIds });
      const runIds = collectRunIds(results);
      stage = 'run_inspector';await parity.verifyRunInspector({ owner, sibling, administrator: adminLogin,
        ownerId: students[0].id, siblingId: students[1].id,
        runIds, nativeEvidence, origin, timeoutMs });
      stage = 'reset';const beforeReset = await nativeEvidence.snapshotBeforeReset({ ownerId: students[0].id,
        siblingId: students[1].id, lifecycleBefore, results, siblingResult });
      stage = 'reset_activation';
      owner = await sessions.activateShopPersona({ browser, origin, session: owner, role: 'customer',
        contexts, blocked, errors, catalogObservers });
      const priorWorkshopFrame = await owner.page.$('iframe[title="SecureShop workshop"]');
      assert.ok(priorWorkshopFrame, 'Current SecureShop workshop frame required before reset');
      const resetAbort = new AbortController();
      const recoveryTimeoutMs = Math.min(timeoutMs, INSPECTOR_RESPONSE_TIMEOUT_MS);
      const reset = owner.page.waitForResponse(responseMatches(origin, '/api/auth/secureshop-launch/reset', 'POST'),
        { signal: resetAbort.signal, timeout: recoveryTimeoutMs });
      void reset.catch(() => {});
      const recovery = captureResetRecovery(owner.page, origin, recoveryTimeoutMs);
      let resetRequest, resetBody, lifecycle, recoveryBody;
      try {
        await owner.page.evaluate(() => {
          const buttons = [...document.querySelectorAll('button')].filter(node => node.textContent.includes('Reset launch'));
          if (buttons.length !== 1 || buttons[0].disabled) throw Error('Exact SecureShop reset action unavailable');buttons[0].click();
        });
        const resetResponse = await reset;assert.equal(resetResponse.status(), 200);
        resetRequest = JSON.parse(resetResponse.request().postData());
        assert.deepEqual(Object.keys(resetRequest).sort(), ['expectedGeneration', 'idempotencyKey', 'launchId']);
        assert.equal(resetRequest.launchId, launch.launchId);
        assert.equal(Number(resetRequest.expectedGeneration), Number(launch.generation));
        assert.ok(typeof resetRequest.idempotencyKey === 'string' && resetRequest.idempotencyKey.length > 0);
        resetBody = await resetResponse.json();
        lifecycle = await nativeEvidence.verifyReset({ before: beforeReset, response: resetBody,
          ownerId: students[0].id, siblingId: students[1].id, results, siblingResult });
        const recoveryResponse = await recovery.pending;assert.equal(recoveryResponse.status, 200);
        const recoveryRequest = JSON.parse(recoveryResponse.request.postData());
        assert.deepEqual(Object.keys(recoveryRequest).sort(), ['expectedCredentialVersion', 'launchId']);
        assert.equal(recoveryRequest.launchId, resetBody.launch.launchId);
        assert.equal(recoveryRequest.expectedCredentialVersion, resetBody.launch.credentialVersion);
        recoveryBody = await recoveryResponse.body;
        await owner.page.waitForFunction(oldFrame => {
          const host = document.querySelector('[data-testid="secureshop-frame-host"]');
          const current = host?.querySelector('iframe[title="SecureShop workshop"]');
          return !oldFrame.isConnected && host?.getAttribute('aria-busy') === 'false'
            && current?.isConnected && current !== oldFrame;
        }, { timeout: recoveryTimeoutMs, polling: 'mutation' }, priorWorkshopFrame);
      } finally {
        resetAbort.abort();
        await Promise.allSettled([reset, recovery.close(), priorWorkshopFrame.dispose()]);
      }

      stage = 'stale_launch_denial';const staleDenial = await flows.staleSsrfDenied({ page: owner.page, origin,
        result: results.ssrf, timeoutMs });
      assert.equal(staleDenial?.staleLaunchHttpDenied, true);

      const recoveryReceipt = await nativeEvidence.captureResetReplayBaseline({ firstResponse: resetBody,
        recoveryResponse: recoveryBody, ownerId: students[0].id, siblingId: students[1].id });
      assert.equal(recoveryReceipt?.recoveryVerified, true);
      stage = 'reset_replay';const replay = await api(owner, '/api/auth/secureshop-launch/reset', 'POST', resetRequest);
      assert.equal(replay.status, 200);assert.equal(replay.body?.resetId, resetBody.resetId);
      assert.equal(replay.body?.cleanupComplete, true);
      for (const key of ['launchId', 'generation', 'expiresAt']) {
        assert.equal(replay.body?.launch?.[key], resetBody.launch?.[key]);
      }
      const replayReceipt = await nativeEvidence.verifyResetReplay({ before: beforeReset,
        firstResponse: resetBody, replayResponse: replay.body, ownerId: students[0].id,
        siblingId: students[1].id });
      assert.equal(replayReceipt?.replayVerified, true);

      stage = 'reentry';const reentry = await sessions.mountWorkshop({ browser, origin, token: owner.token,
        contexts, blocked, errors, reuse: owner, catalogObservers });
      await sessions.loginShopPersona(reentry, origin, 'customer');
      const reentryBundle = await nativeEvidence.forPersona({ ownerId: students[0].id, role: 'customer' });
      assert.equal(reentryBundle.binding.launchId, launch.launchId);
      assert.equal(Number(reentryBundle.binding.generation), Number(launch.generation) + 1);
      assert.equal(reentryBundle.binding.platformSessionId, launch.platformSessionId);
      const reentryReceipt = await nativeEvidence.verifyReentry({ ownerId: students[0].id,
        beforeBinding: launch, afterBinding: reentryBundle.binding });
      assert.equal(reentryReceipt?.reentryVerified, true);

      stage = 'lifecycle';nativeEvidence.assertLifecycleComplete(lifecycle);
      assert.equal((await api(owner, '/api/auth/logout', 'POST', {})).status, 200);
      assert.equal((await api(owner, '/api/agent-runs')).status, 401);
      assert.equal((await api(sibling, '/api/agent-runs')).status, 200);
      const logoutReceipt = await nativeEvidence.verifyLogout({ ownerId: students[0].id,
        siblingId: students[1].id });
      assert.equal(logoutReceipt?.persistedPlatformSessionRevoked, true);
      assert.deepEqual(blocked, []);assert.deepEqual(errors, []);
      await Promise.all(catalogObservers.map(observer => observer.settle()));
      assert.equal(results.review.qualified, reviewPlan.qualified);
      assert.equal(results.review.defensiveReviewVerified, reviewPlan.defensive);
      return Object.freeze({ scope: reviewPlan.scope, qualified: reviewPlan.qualified,
        reviewAdmissionMode: results.review.admissionMode,
        reviewResolvedMode: results.review.resolvedMode,
        reviewResolvedDecision: results.review.resolvedDecision,
        ...(reviewPlan.defensive ? { defensiveReviewVerified: true,
          unqualifiedObjectiveIds: reviewPlan.unqualifiedObjectiveIds } : {}),
        objectiveIds: Object.freeze([...expectedCompletedObjectiveIds]),
        runIds, expected, lifecycle,
        siblingVerified: true, turnReplayVerified: true, resetReplayVerified: true,
        staleLaunchHttpDenied: true, foreignRunIsolationVerified: true,
        logoutRevocationVerified: true, reentryVerified: true,
        ssrfClassifications: Object.freeze([...ssrfClassifications]) });
    } catch (error) {
      const diagnostic=renderedQualificationFailureDiagnostic(error,stage);
      const storedBrowserResponseFailure = stage === 'stored_browser'
        ? getStoredBrowserResponseFailure(error) : null;
      const reviewModerationFailure = stage === 'review_workflow'
        ? projectModerationFailureDiagnostic(error?.reviewModerationFailure) : null;
      const failureEvidence=/^(?:owner|sibling)_ssrf(?:_replay)?$/.test(stage)
        ?await readBoundedFailureEvidence(ssrfFailureEvidence?.captureFailure?.bind(ssrfFailureEvidence)):null;
      const retained = ssrfClassifications.length
        ? { ssrfClassifications: Object.freeze([...ssrfClassifications]) } : {};
      await writeBoundedDiagnostic(writeDiagnostic,Object.freeze({ ...diagnostic, ...retained,
        ...(failureEvidence ? { failureEvidence } : {}),
        ...(reviewModerationFailure ? { reviewModerationFailure } : {}),
        ...(storedBrowserResponseFailure ? { storedBrowserResponseFailure } : {}) }));
      throw error;
    } finally {
      const observed = await Promise.allSettled(catalogObservers.map(observer => observer.close()));
      const settled = await Promise.allSettled(contexts.map(context => context.close()));
      assert.ok(observed.every(result => result.status === 'fulfilled'), 'SecureShop catalog observers must drain and detach');
      assert.ok(settled.every(result => result.status === 'fulfilled'), 'All SecureShop browser contexts must close');
    }
  };
}

const qualifyFullBackendRenderedSecureShop = createFullBackendRenderedSecureShop();
module.exports = { REQUIRED_CAPABILITIES, assertNativeEvidence, assertSameLaunch, collectRunIds,
  api, configureSecureShopCurriculum, verifyForeignRunIsolation, verifyRunInspector,
  captureResetRecovery,
  configurePage,
  renderedQualificationFailureDiagnostic, readBoundedFailureEvidence, projectSsrfClassifications,
  reviewQualificationPlan, resolvedReviewQualificationPlan, createFullBackendRenderedSecureShop,
  STORED_BROWSER_PROBE_BODY,
  mountWorkshop, loginShopPersona, mountVerifiedShopPersona, activateShopPersona, openProduct,
  qualifyFullBackendRenderedSecureShop };
