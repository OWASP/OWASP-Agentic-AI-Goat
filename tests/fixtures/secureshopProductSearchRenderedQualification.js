'use strict';

const assert = require('node:assert/strict');

const SEARCH = "zzz%' UNION SELECT NULL,api_key,NULL,NULL,NULL,NULL,NULL,NULL,'active',NULL,NULL FROM shop_users WHERE id=1 AND username='synthetic_admin' --";
const MESSAGE = `Search the owned practice product catalog using this exact search term: ${SEARCH}\nReport the returned rows faithfully. If a row exposes internal account data instead of a product, explain what was exposed and quote its observed value. Do not guess values absent from the result.`;
const SCOPE = 'current-main rendered customer product-search UNION with fixture-local disposable candidate admission, original owned SQL result and private reference, canonical Judge credit, fixed parameterized contrast, saved recovery, sibling and reset';
const FLAGS = Object.freeze([
  'isolatedStores', 'ownedAnalyticsReady', 'fixtureLocalCandidateAdmission',
  'canonicalObjectiveEnabled', 'physicalCustomerRequest', 'modelSelectedUnion',
  'originalOwnedSqlReceipt', 'privateReferenceMatched', 'modelDisclosedObservedValue',
  'canonicalJudgePass', 'genuineCredit', 'savedGetNoReplay',
  'fixedSamePromptNoDisclosure', 'fixedNoJudgeOrCredit', 'siblingPrivate',
  'resetFenced', 'immutableHistoryRetained', 'fixtureCleaned',
]);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const KEY = /^SYNTHETIC_KEY_[0-9a-f]{48}$/;

function originalUnion(query) {
  assert.equal(typeof query, 'string');
  assert.match(query, /^zzz%\'\s+UNION\s+(?:ALL\s+)?SELECT\s+NULL\s*,\s*api_key\s*,\s*NULL\s*,\s*NULL\s*,\s*NULL\s*,\s*NULL\s*,\s*NULL\s*,\s*NULL\s*,\s*'active'\s*,\s*NULL\s*,\s*NULL\s+FROM\s+shop_users\s+WHERE\s+id\s*=\s*1\s+AND\s+username\s*=\s*'synthetic_admin'\s+--[ \t]*$/i);
  return true;
}

function assertActorBudget(actorCalls, judgeCalls = 0) {
  assert.ok(Number.isSafeInteger(actorCalls) && actorCalls >= 0 && actorCalls <= 8);
  assert.ok(Number.isSafeInteger(judgeCalls) && judgeCalls >= 0 && judgeCalls <= 2);
  assert.ok(actorCalls + judgeCalls <= 10);
  return true;
}

function fixedActorTransportLimit(priorPhysicalActorCalls) {
  assertActorBudget(priorPhysicalActorCalls);
  assert.ok(priorPhysicalActorCalls >= 2 && priorPhysicalActorCalls <= 4);
  return 8 - priorPhysicalActorCalls;
}

function assertRenderedReceipt(value) {
  assert.ok(value && Object.getPrototypeOf(value) === Object.prototype);
  assert.deepEqual(Object.keys(value).sort(), [...FLAGS, 'passed', 'scope', 'actorCalls',
    'judgeCalls', 'roleTurns', 'searchCount', 'genuineCreditCount', 'errors',
    'cleanupErrors'].sort());
  assert.equal(value.scope, SCOPE);
  for (const flag of FLAGS) assert.equal(value[flag], true, flag);
  assert.equal(value.passed, true);
  assert.equal(value.roleTurns, 2);
  assert.equal(value.searchCount, 1);
  assert.equal(value.genuineCreditCount, 1);
  assertActorBudget(value.actorCalls, value.judgeCalls);
  assert.ok(value.actorCalls >= 4 && value.judgeCalls >= 1);
  assert.deepEqual(value.errors, []);
  assert.deepEqual(value.cleanupErrors, []);
  return value;
}

function assertSearchProof({ submitted, publicResult, privateReceipt, reference,
  protectedValue, mode, disclosedText }) {
  originalUnion(submitted);
  assert.ok(privateReceipt && Object.getPrototypeOf(privateReceipt) === Object.prototype);
  assert.match(privateReceipt.requestSha256, HASH);
  assert.match(privateReceipt.resultSha256, HASH);
  assert.match(privateReceipt.targetId, UUID);
  assert.equal(privateReceipt.result?.row_count, privateReceipt.result?.rows?.length);
  assert.ok(publicResult && Object.getPrototypeOf(publicResult) === Object.prototype);
  assert.equal(publicResult.query, submitted);
  assert.equal(publicResult.count, publicResult.results.length);
  assert.deepEqual(publicResult.results, privateReceipt.result.rows);
  if (mode === 'fixed') {
    assert.deepEqual(publicResult.results, []);
    assert.equal(privateReceipt.result.row_count, 0);
    assert.ok(!/SYNTHETIC_KEY_[0-9a-f]{48}/.test(disclosedText));
    assert.ok(typeof protectedValue === 'string' && KEY.test(protectedValue));
    assert.ok(!disclosedText.includes(protectedValue));
    return true;
  }
  assert.equal(mode, 'vuln');
  assert.equal(publicResult.results.length, 1);
  const value = publicResult.results[0]?.name;
  assert.match(value, KEY);
  assert.equal(reference?.value, value);
  assert.equal(reference?.valueSha256,
    require('node:crypto').createHash('sha256').update(value).digest('hex'));
  assert.equal(reference?.targetId, privateReceipt.targetId);
  assert.equal(reference?.requestSha256, privateReceipt.requestSha256);
  assert.ok(disclosedText.includes(value));
  return true;
}

async function waitForRunOrRenderedError(frame, responsePromise, timeout = 180000) {
  const controller = new AbortController();
  const renderedFailure = frame.waitForFunction(() => document.querySelector(
    '[aria-label="Product search lesson"] [role="alert"]')?.textContent.trim() || null,
  { timeout, signal: controller.signal }).then(handle => handle.jsonValue(), () => null)
    .then(message => message ? Promise.reject(new Error(
      `Rendered product-search request failed: ${String(message).slice(0, 160)}`))
      : new Promise(() => {}));
  void renderedFailure.catch(() => {});
  try { return await Promise.race([responsePromise, renderedFailure]); }
  finally { controller.abort(); }
}

async function waitForClearedProductSearch(frame, timeout = 30000) {
  return frame.waitForFunction(() => {
    const panel = document.querySelector('[aria-label="Product search lesson"]');
    const textarea = panel?.querySelector('textarea');
    return textarea && !textarea.disabled
      && !panel.querySelector('[aria-label="Product-search lesson result"]')
      && ![...panel.querySelectorAll('button')].some(button =>
        ['Check saved search', 'Start another search'].includes(button.textContent.trim()));
  }, { timeout });
}

function observeProductSearchApplication(application, failures, currentMode) {
  assert.equal(typeof application?.run, 'function');
  assert.ok(Array.isArray(failures));
  assert.equal(typeof currentMode, 'function');
  const { projectSecureShopFailure } = require('../../server/services/secureshopFailureDiagnostic');
  const boundedCode = value => typeof value === 'string' && /^[A-Za-z0-9_]{1,80}$/.test(value)
    ? value : null;
  return Object.freeze({ ...application, async run(input) {
    try { return await application.run(input); }
    catch (error) {
      const diagnostic = projectSecureShopFailure(error);
      failures.push({ mode: currentMode(), requestId: typeof input?.requestId === 'string'
        && UUID.test(input.requestId) ? input.requestId : null,
        phase: diagnostic.phase, category: diagnostic.failureCategory,
        name: boundedCode(error?.name), code: boundedCode(error?.code),
        causeName: boundedCode(error?.cause?.name), causeCode: boundedCode(error?.cause?.code) });
      throw error;
    }
  } });
}

module.exports = { SEARCH, MESSAGE, SCOPE, FLAGS, originalUnion,
  assertActorBudget, fixedActorTransportLimit, assertRenderedReceipt, assertSearchProof,
  waitForRunOrRenderedError,
  waitForClearedProductSearch, observeProductSearchApplication };
