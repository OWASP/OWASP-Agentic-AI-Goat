'use strict';

// Separate customer-only qualification: production composition, no Listings
// manager or merchant phases, and no substituted model/tool results.
const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { randomUUID } = require('node:crypto');
const commerceContract = require('../../server/services/secureshopConversationalCommerceContract');
const { Pool } = require('pg');
const { migrate } = require('../../db/postgres/migrate');

const CART_LIFECYCLE = process.env.SECURESHOP_CUSTOMER_CART_LIFECYCLE_NATIVE === '1';
const CHECKOUT_FENCES = process.env.SECURESHOP_CUSTOMER_CHECKOUT_FENCES_NATIVE === '1';
const V01_AUDIT = process.env.SECURESHOP_V01_AUDIT_BROWSER_NATIVE === '1';
const V29_AGENCY = process.env.SECURESHOP_V29_AGENCY_BROWSER_NATIVE === '1';
const V07_POLYGLOT = process.env.SECURESHOP_V07_POLYGLOT_BROWSER_NATIVE === '1';
const V06_UPLOAD = process.env.SECURESHOP_V06_UPLOAD_BROWSER_NATIVE === '1';
const V08_SVG = process.env.SECURESHOP_V08_SVG_BROWSER_NATIVE === '1';
const V44_PATH_SUMMARY = process.env.SECURESHOP_V44_FILE_PATH_SUMMARY_BROWSER_NATIVE === '1';
const V46_TRAVERSAL = process.env.SECURESHOP_V46_TRAVERSAL_BROWSER_NATIVE === '1';
const V19_SUMMARY = process.env.SECURESHOP_V19_FILE_SUMMARY_BROWSER_NATIVE === '1';
const V19_DIAGNOSTIC = process.env.SECURESHOP_V19_FILE_SUMMARY_DIAGNOSTIC_NATIVE === '1';
if (V19_DIAGNOSTIC && !V19_SUMMARY) throw new Error('V19 diagnostic requires the V19 rendered cohort');
const V19 = V19_SUMMARY ? require('../fixtures/secureshopV19RenderedCohort') : null;
const UPLOAD_BROWSER = V07_POLYGLOT || V06_UPLOAD || V08_SVG || V46_TRAVERSAL;
const CHECKOUT_LIFECYCLE = process.env.SECURESHOP_CUSTOMER_CHECKOUT_NATIVE === '1' || V01_AUDIT;
const PAYMENT_SETUP = process.env.SECURESHOP_CUSTOMER_PAYMENT_SETUP_NATIVE === '1';
const ADDRESS_SETUP = process.env.SECURESHOP_CUSTOMER_ADDRESS_SETUP_NATIVE === '1';
const PROFILE = process.env.SECURESHOP_CUSTOMER_PROFILE_NATIVE === '1';
const REFUND_HANDOFF = process.env.SECURESHOP_CUSTOMER_REFUND_HANDOFF_NATIVE === '1';
const OLDER_ORDERS = process.env.SECURESHOP_CUSTOMER_OLDER_ORDERS_NATIVE === '1';
const PRODUCT_DETAILS = process.env.SECURESHOP_CUSTOMER_PRODUCT_DETAILS_NATIVE === '1';
const STOCK_REJECTION = process.env.SECURESHOP_CUSTOMER_OUT_OF_STOCK_NATIVE === '1';
if ([V29_AGENCY, V44_PATH_SUMMARY, V19_SUMMARY, V07_POLYGLOT, V06_UPLOAD, V08_SVG, V46_TRAVERSAL, CHECKOUT_FENCES, CART_LIFECYCLE, CHECKOUT_LIFECYCLE, PAYMENT_SETUP, ADDRESS_SETUP, PROFILE, REFUND_HANDOFF, OLDER_ORDERS, PRODUCT_DETAILS, STOCK_REJECTION].filter(Boolean).length > 1)
  throw new Error('Customer checkout, cart, payment, address, profile, refund, and product-detail gates are mutually exclusive');
const PREFIX = STOCK_REJECTION ? 'PG_SECURESHOP_CUSTOMER_OUT_OF_STOCK_'
  : PRODUCT_DETAILS ? 'PG_SECURESHOP_CUSTOMER_PRODUCT_DETAILS_'
  : OLDER_ORDERS ? 'PG_SECURESHOP_CUSTOMER_OLDER_ORDERS_'
  : REFUND_HANDOFF ? 'PG_SECURESHOP_CUSTOMER_REFUND_HANDOFF_'
  : ADDRESS_SETUP ? 'PG_SECURESHOP_CUSTOMER_ADDRESS_SETUP_'
  : PROFILE ? 'PG_SECURESHOP_CUSTOMER_PROFILE_'
  : PAYMENT_SETUP ? 'PG_SECURESHOP_CUSTOMER_PAYMENT_SETUP_'
  : CART_LIFECYCLE ? 'PG_SECURESHOP_CUSTOMER_CART_LIFECYCLE_' : 'PG_SECURESHOP_CUSTOMER_CHECKOUT_';
const STORES = Object.freeze({ IDENTITY: 'identity', AGENTS: 'secureshop_agents',
  REVIEW: 'secureshop_review', COMMERCE: 'secureshop' });
const MODEL = 'llama3.1:8b';
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
function v29JudgeRequestRecord(input) {
  const prepared = require('../../server/agent-runtime/objectiveJudge').prepareJudgeInput(input);
  assert.equal(prepared.evidenceError, undefined);
  const execution = input.execution;
  assert.equal(typeof execution?.check, 'function');
  assert.match(execution.runId, UUID);
  return { packet: prepared.packet, evidenceDigest: prepared.evidenceDigest,
    execution: { runId: execution.runId, ownerKey: execution.ownerKey,
      durableGeneration: execution.durableGeneration } };
}
const ADDRESS_DRAFT_KEYS = Object.freeze(['label', 'line1', 'line2', 'city', 'state', 'zip', 'phone']);
function addressDiagnosticArgs(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { invalidShape: true };
  const keys = Object.keys(value);
  const result = { presentKeys: keys.slice(0, 8).map(key =>
    ['action', 'choiceId', 'draft'].includes(key) ? key : '[other]'),
  otherKeyCount: keys.filter(key => !['action', 'choiceId', 'draft'].includes(key)).length };
  if (Object.hasOwn(value, 'action')) result.action = ['create', 'update'].includes(value.action)
    ? value.action : '[other]';
  if (Object.hasOwn(value, 'choiceId')) result.choiceId = { type: value.choiceId === null
    ? 'null' : typeof value.choiceId, uuid: typeof value.choiceId === 'string' && UUID.test(value.choiceId) };
  if (Object.hasOwn(value, 'draft')) {
    const draft = value.draft;
    result.draft = !draft || typeof draft !== 'object' || Array.isArray(draft)
      ? { invalidShape: true }
      : { fieldNames: Object.keys(draft).slice(0, 8).map(key =>
        ADDRESS_DRAFT_KEYS.includes(key) ? key : '[other]'),
      otherFieldCount: Object.keys(draft).filter(key => !ADDRESS_DRAFT_KEYS.includes(key)).length,
      fields: ADDRESS_DRAFT_KEYS.filter(key => Object.hasOwn(draft, key)).map(key => ({
        key, type: typeof draft[key], nonempty: typeof draft[key] === 'string' && draft[key].length > 0,
        currentMessageIncludes: typeof draft[key] === 'string' && typeof message === 'string'
          && message.includes(draft[key]) })) };
  }
  return result;
}
function addressDiagnosticCode(value) {
  return typeof value === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(value) ? value : null;
}
function profileErrorDiagnostic(error) {
  const chain = [];
  for (let current = error, depth = 0; current && depth < 3; current = current.cause, depth++) {
    chain.push({ code: typeof current.code === 'string' && /^[A-Z0-9_]{1,64}$/.test(current.code)
      ? current.code : null,
    name: typeof current.name === 'string' && /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(current.name)
      ? current.name : null,
    constraint: typeof current.constraint === 'string' && /^[a-z][a-z0-9_]{0,127}$/.test(current.constraint)
      ? current.constraint : null });
  }
  return chain;
}
function v01AssessmentErrorDiagnostic(error, workspace) {
  const chain = [];
  for (let current = error, depth = 0; current && depth < 4; current = current.cause, depth++) {
    const stack = typeof current.stack === 'string' ? current.stack.split('\n').slice(0, 10).map(line =>
      privateToolFailureText(line.replaceAll(workspace, '[workspace]'))) : [];
    chain.push({
      ...profileErrorDiagnostic(current)[0],
      message: privateToolFailureText(current.message),
      stack,
      executionBoundary: current.executionBoundary === true,
      effectCallbackCompleted: typeof current.effectCallbackCompleted === 'boolean'
        ? current.effectCallbackCompleted : null,
    });
  }
  return chain;
}
function addressResultCode(result) {
  const text = result?.content?.find?.(item => item?.type === 'text')?.text;
  if (typeof text !== 'string' || text.length > 512) return null;
  try { return addressDiagnosticCode(JSON.parse(text)?.code); } catch { return null; }
}
const CHECKOUT_FENCES_SCOPE = 'current-main customer checkout stock and price quote invalidation, two-tab recovery of one confirmation, and later real-session denial with actual local llama3.1:8b';
const CHECKOUT_FENCES_FLAGS = ['isolatedStores', 'modelPreparedThreeQuotes', 'renderedStockStaleNoEffect',
  'renderedPriceStaleNoEffect', 'renderedFreshQuoteCurrentFacts', 'renderedTwoTabRecoveryOneEffect',
  'exactDuplicateReceipt', 'changedPrepareIntentDenied', 'laterRealSessionDenied', 'noObjectiveCredit', 'fixtureCleaned'];
const CHECKOUT_SCOPE = 'current-main standalone customer checkout and owned order chat with synthetic payments and actual local llama3.1:8b';
const CART_SCOPE = 'current-main standalone customer cart chat with physical cart confirmation and actual local llama3.1:8b; add, update, remove, and exact recovery';
const PAYMENT_SCOPE = 'current-main standalone customer practice payment setup with actual local llama3.1:8b, trusted synthetic choice, and exact recovery';
const ADDRESS_SCOPE = 'current-main standalone customer address setup and edit with actual local llama3.1:8b, trusted confirmation, and exact recovery';
const PROFILE_SCOPE = 'current-main customer profile read and no-effect model preparation, trusted profile confirmation, and exact recovery with actual local llama3.1:8b';
const REFUND_SCOPE = 'current-main seeded owned-order refund handoff and trusted ticket recovery with actual local llama3.1:8b';
const OLDER_ORDERS_SCOPE = 'current-main customer owned older-order pagination, protected recovery, and selected detail with actual local llama3.1:8b';
const PRODUCT_SCOPE = 'current-main customer ambiguous product search and selected owned product detail with actual local llama3.1:8b';
const STOCK_SCOPE = 'current-main customer explicit zero-stock cart add rejected durably after real local llama3.1:8b, with exact saved recovery';
const CHECKOUT_FLAGS = ['isolatedStores', 'renderedOwnedAddressChoices', 'renderedSyntheticPaymentChoices',
  'renderedExactCheckoutProposal', 'renderedSyntheticDeclineNoEffect',
  'renderedApprovedCheckoutAtomicReceipt', 'renderedCheckoutRecoveryNoReplay',
  'renderedOwnedOrderListAndDetail', 'siblingChoicesDenied', 'noObjectiveCredit', 'fixtureCleaned'];
const V01_CHECKOUT_FLAGS = CHECKOUT_FLAGS.filter(flag => flag !== 'renderedSyntheticDeclineNoEffect');
const V06_SCOPE = 'current-main rendered customer avatar upload prohibited-extension lesson with physical session and attachment, genuine model graph/file/first-serve effect, canonical Judge credit, fixed denial, recovery, sibling and reset fences';
const V46_SCOPE = 'current-main rendered customer avatar traversal upload with distinct physical and logical filename, genuine model graph, same-operation escaped file/readback, learner-visible safe destination, canonical Judge credit, fixed denial, recovery, sibling and reset fences';
const V08_SCOPE = 'current-main rendered customer SVG upload with genuine model upload, exact stored bytes, real first serve, owned Chrome execution receipt, canonical Judge, fixed denial, sibling and reset fences';
const V08_FLAGS = ['isolatedStores','fixtureLocalCandidateAdmission','physicalSessionAdmission','physicalFileChooser','originalMultipart','actualModelGraph','savedGetNoReplay','firstServe','physicalSandboxPreview','exactSvgSource','physicalSvgAssessment','exactBrowserEffect','canonicalJudgeCredit','durableProgress','assessmentGetNoReplay','fixedModelChoice','fixedRouteIneligibleZeroEffect','siblingPrivate','resetFenced','immutableHistoryRetained','fixtureCleaned','passed'];
const V46_FLAGS = ['isolatedStores','fixtureLocalCandidateAdmission','physicalSessionAdmission','physicalFileChooser','originalMultipart','actualModelGraph','sameOperationEscapedWrite','exactPhysicalReadback','learnerVisibleSafeDestination','savedGetNoReplay','canonicalJudgeCredit','durableProgress','assessmentGetNoReplay','fixedModelChoice','fixedNoWriteJudgeCredit','siblingPrivate','resetFenced','immutableHistoryRetained','fixtureCleaned','passed'];
const V29_SCOPE = 'current-main rendered customer teaching-role escalation with original denied ACL, immutable effect, canonical Judge, fixed graph denial and saved lifecycle';
const V29_FLAGS = ['isolatedStores','freshRoleSchema','fixtureLocalCandidateAdmission','registeredCustomerAuthority','fixedOriginalModelSelection','fixedGraphBlockNoEffect','vulnerableOriginalModelSelection','realAclDenialDispatch','ownedImmutableRoleEffect','actualAuthorityUnchanged','canonicalJudgeDecision','publicProgress','savedGetNoReplay','learnerVisibleAssessment','siblingPreserved','sessionDenied','resetFenced','immutableHistoryRetained','fixtureCleaned','passed'];
const V44_SCOPE = 'current-main rendered customer synthetic file path traversal with original JSON/model/wire/read/disclosure, canonical Judge credit, fixed no-read, saved recovery, sibling and reset fences';
const V44_FLAGS = ['isolatedStores','fixtureLocalCandidateAdmission','physicalPathRequest','originalGraphAndWire','ownedSyntheticRead','canonicalJudgeCredit','durableProgress','savedGetNoReplay','assessmentGetNoReplay','fixedModelChoice','fixedNoReadJudgeCredit','siblingPrivate','resetFenced','immutableHistoryRetained','fixtureCleaned','passed'];
const V07_SCOPE='current-main rendered original GIF polyglot upload and separately selected legacy Node preview with externally observed owned canary, canonical Judge credit, fixed reencoding and durable lifecycle fences';
const V07_FLAGS=['isolatedStores','fixtureLocalCandidateAdmission','physicalSessionAdmission','physicalFileChooser','originalMultipart','actualUploadModelGraph','firstServe','actualPreviewModelGraph','sameByteExecution','externalCanaryObserved','canonicalJudgeCredit','publicProgress','previewLostAckGetOnly','savedReloadGetOnly','fixedModelChoice','fixedReencodedNoOriginalExecution','fixedNoJudgeCredit','siblingPrivate','personaSessionFenced','resetFenced','immutableHistoryRetained','fixtureCleaned','passed'];
const V06_FLAGS = ['isolatedStores','fixtureLocalCandidateAdmission','physicalSessionAdmission',
  'physicalFileChooser','originalMultipart','actualModelGraph','savedGetNoReplay','firstServe',
  'canonicalJudgeCredit','durableProgress','assessmentGetNoReplay','fixedModelChoice',
  'fixedNoEffectServeJudgeCredit','siblingPrivate','resetFenced','immutableHistoryRetained',
  'fixtureCleaned','passed'];
const CART_FLAGS = ['isolatedStores', 'renderedCartAddPrepared', 'renderedCartAddConfirmed',
  'renderedCartUpdatePrepared', 'renderedCartUpdateLostAckRecovery', 'renderedCartRemovePrepared',
  'renderedCartRemoveConfirmed', 'exactGetNoReplay', 'zeroEffectBeforeConfirm',
  'siblingCartOperationDenied', 'noObjectiveCredit', 'fixtureCleaned'];
const PAYMENT_FLAGS = ['isolatedStores', 'renderedPaymentSetupHandoff', 'noEffectBeforeConfirm',
  'renderedExplicitScenario', 'renderedOneMethodReceipt', 'renderedLostAckExactRecovery',
  'renderedRefreshedMethodCard', 'siblingMethodDenied', 'resetSessionDenied',
  'noOrderOrJudge', 'fixtureCleaned'];
const ADDRESS_FLAGS = ['isolatedStores', 'renderedAddressSetupHandoff', 'missingDraftCompletedByUser',
  'zeroEffectBeforeConfirm', 'renderedAddressCreateReceipt', 'renderedAddressEditReceipt',
  'defaultUniqueness', 'lostAckExactRecovery', 'staleEditDenied', 'siblingAddressDenied',
  'resetSessionDenied', 'fixtureCleaned'];
const PROFILE_FLAGS = ['passed', 'isolatedStores', 'renderedProfileRead',
  'renderedNoEffectProposal', 'zeroEffectBeforeConfirm', 'renderedExplicitProfileReview',
  'renderedOneProfileReceipt', 'lostAckExactRecovery', 'accountProfileParity',
  'siblingProfilePrivate', 'controlledProfileFences', 'resetSessionDenied',
  'noJudgeOrCommerceEffect', 'fixtureCleaned'];
const REFUND_FLAGS = ['isolatedStores', 'seededOwnedOrder', 'renderedOwnedOrderChoice',
  'renderedRefundSetupHandoff', 'zeroTicketBeforeConfirm', 'renderedExplicitRefundRequest',
  'renderedOneOwnedTicket', 'renderedLostAckGetRecovery', 'siblingRefundPrivate',
  'noOrderOrJudgeEffect', 'fixtureCleaned'];
const OLDER_ORDERS_FLAGS = ['isolatedStores', 'controlledSeededOrderPages', 'stableTieTimestampKeyset',
  'foreignTamperedStaleCursorsDenied', 'renderedLatestOwnedOrderPage', 'protectedPageGetRecovery',
  'renderedPhysicalOlderOrders', 'renderedSelectedOlderOrderDetail', 'siblingOrdersPrivate',
  'readOnlyOrderRowsUnchanged', 'resetSessionDenied', 'noObjectiveCredit', 'fixtureCleaned'];
const PRODUCT_FLAGS = ['isolatedStores', 'seededSimilarOwnedProducts', 'renderedAmbiguousProductChoices',
  'renderedSelectedProductDetails', 'siblingChoicePrivate', 'noCommerceOrJudgeEffect', 'fixtureCleaned'];
const STOCK_FLAGS = ['isolatedStores', 'seededZeroStockProducts', 'renderedAmbiguousProductChoices',
  'modelSelectedRejectedAdd', 'renderedSavedStockRejection', 'exactGetRecoveryNoReplay',
  'siblingRejectionPrivate', 'noCommerceOrJudgeEffect', 'controlledRestockReplay', 'fixtureCleaned'];
const SCOPE = V29_AGENCY ? V29_SCOPE : V44_PATH_SUMMARY ? V44_SCOPE : V19_SUMMARY ? V19.SCOPE : V46_TRAVERSAL ? V46_SCOPE : V08_SVG ? V08_SCOPE : V07_POLYGLOT ? V07_SCOPE : V06_UPLOAD ? V06_SCOPE : CHECKOUT_FENCES ? CHECKOUT_FENCES_SCOPE : STOCK_REJECTION ? STOCK_SCOPE : PRODUCT_DETAILS ? PRODUCT_SCOPE : OLDER_ORDERS ? OLDER_ORDERS_SCOPE : REFUND_HANDOFF ? REFUND_SCOPE : ADDRESS_SETUP ? ADDRESS_SCOPE : PROFILE ? PROFILE_SCOPE
  : PAYMENT_SETUP ? PAYMENT_SCOPE : CART_LIFECYCLE ? CART_SCOPE : CHECKOUT_SCOPE;
const FLAGS = V29_AGENCY ? V29_FLAGS : V44_PATH_SUMMARY ? V44_FLAGS : V19_SUMMARY ? V19.FLAGS : V46_TRAVERSAL ? V46_FLAGS : V08_SVG ? V08_FLAGS : V07_POLYGLOT ? V07_FLAGS : V06_UPLOAD ? V06_FLAGS : CHECKOUT_FENCES ? CHECKOUT_FENCES_FLAGS : STOCK_REJECTION ? STOCK_FLAGS : PRODUCT_DETAILS ? PRODUCT_FLAGS : OLDER_ORDERS ? OLDER_ORDERS_FLAGS : REFUND_HANDOFF ? REFUND_FLAGS : ADDRESS_SETUP ? ADDRESS_FLAGS : PROFILE ? PROFILE_FLAGS
  : PAYMENT_SETUP ? PAYMENT_FLAGS : CART_LIFECYCLE ? CART_FLAGS : V01_AUDIT ? V01_CHECKOUT_FLAGS : CHECKOUT_FLAGS;
const ENABLED = (V29_AGENCY || V44_PATH_SUMMARY || V19_SUMMARY || UPLOAD_BROWSER || V01_AUDIT || CHECKOUT_FENCES || CART_LIFECYCLE || CHECKOUT_LIFECYCLE || PAYMENT_SETUP || ADDRESS_SETUP || PROFILE || REFUND_HANDOFF || OLDER_ORDERS || PRODUCT_DETAILS || STOCK_REJECTION)
  && process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.LIVE_OLLAMA_TEST === '1'
  && Object.keys(STORES).every(store => ['MIGRATION', 'RUNTIME']
    .every(role => process.env[`${PREFIX}${store}_${role}_URL`]));

function urls() {
  const result = {}; let nonce, port;
  for (const [store, database] of Object.entries(STORES)) for (const role of ['MIGRATION', 'RUNTIME']) {
    const key = `${store}_${role}`, value = new URL(process.env[`${PREFIX}${key}_URL`]);
    assert.equal(value.protocol, 'postgresql:'); assert.equal(value.hostname, '127.0.0.1');
    assert.match(value.port, /^[1-9][0-9]{0,4}$/); assert.ok(Number(value.port) <= 65535);
    assert.equal(value.password, ''); assert.equal(value.search, ''); assert.equal(value.hash, '');
    const match = new RegExp(`^/dvaia_test_agent_host_([a-f0-9]{12})_${database}$`).exec(value.pathname);
    assert.ok(match); nonce ??= match[1]; port ??= value.port;
    assert.equal(match[1], nonce); assert.equal(value.port, port);
    assert.equal(value.username, `dvaia_${database}_${role.toLowerCase()}`);
    result[key] = value.href;
  }
  return result;
}
async function waitFor(read, label, timeout = 30000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await read(); if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw Object.assign(new Error(label), { code: 'OBSERVATION_TIMEOUT' });
}
async function reservePort(host) { const net=require('node:net');const server=net.createServer();await new Promise((ok,no)=>server.once('error',no).listen(0,host,ok));const port=server.address().port;await new Promise((ok,no)=>server.close(error=>error?no(error):ok()));return port;}
async function frameFor(page) {
  return waitFor(async () => {
    const element = await page.$('iframe[title="SecureShop"]');
    const frame = element && await element.contentFrame().catch(() => null);
    return frame && !frame.detached ? frame : null;
  }, 'shop frame');
}
async function click(frame, text) {
  const handle = await frame.waitForFunction(label => [...document.querySelectorAll('button')]
    .find(button => button.textContent.trim() === label && !button.disabled
      && button.getClientRects().length && getComputedStyle(button).visibility !== 'hidden'),
  { timeout: 30000 }, text);
  const button = handle.asElement(); assert.ok(button);
  if (CHECKOUT_FENCES) {
    await bounded(button.evaluate(node => node.scrollIntoView({ block: 'center' })), 'checkout control scroll');
    await bounded(button.click(), 'checkout physical control click');
    return;
  }
  await button.evaluate(node => node.scrollIntoView({ block: 'center' })); await button.click();
}
async function choose(frame, aria) {
  const handle = await frame.waitForFunction(label => [...document.querySelectorAll('button[aria-label]')]
    .find(button => button.getAttribute('aria-label') === label && !button.disabled
      && button.getClientRects().length && getComputedStyle(button).visibility !== 'hidden'),
  { timeout: 30000 }, aria);
  const button = handle.asElement(); assert.ok(button);
  await button.evaluate(node => node.scrollIntoView({ block: 'center' })); await button.click();
}
async function chooseCartItem(frame, choiceId, aria) {
  const handle = await frame.waitForFunction(({ choiceId, aria }) => {
    const article = document.getElementById(`cart-item-quantity-${choiceId}`)?.closest('article');
    return [...(article?.querySelectorAll('button[aria-label]') || [])]
      .find(button => button.getAttribute('aria-label') === aria && !button.disabled
        && button.getClientRects().length && getComputedStyle(button).visibility !== 'hidden');
  }, { timeout: 30000 }, { choiceId, aria });
  const button = handle.asElement(); assert.ok(button);
  await button.evaluate(node => node.scrollIntoView({ block: 'center' })); await button.click();
}
function response(page, pathname, method) {
  // Handle rejection immediately, even if a preceding physical click fails.
  return page.waitForResponse(value => new URL(value.url()).pathname === pathname
    && value.request().method() === method, { timeout: 30000 })
    .then(value => ({ value }), error => ({ error }));
}
async function readResponse(pending) {
  const { value, error } = await pending; if (error) throw error; return value;
}
function privateToolFailureText(value) {
  if (typeof value !== 'string') return null;
  return value.slice(0, 512)
    .replace(/\b[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\b/gi, '[uuid]')
    .replace(/\b(?:Bearer|token|password|secret)\s*[:=]?\s*\S+/gi, '[credential]')
    .slice(0, 240);
}
function privateOrdersListArguments(value) {
  if (!value || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype)
    return { complete: false, inputStage: 'arguments', reason: 'not_plain_object' };
  const keys = Object.keys(value);
  const raw = JSON.stringify(value);
  if (keys.length > 16 || typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 2048)
    return { complete: false, inputStage: 'arguments', reason: 'bounded_capture_limit', keys: keys.slice(0, 16) };
  const secret = /(?:bearer|password|secret|token|authorization)/i;
  if (keys.some(key => secret.test(key)) || secret.test(raw))
    return { complete: false, inputStage: 'arguments', reason: 'credential_redacted', keys };
  const unexpected = keys.filter(key => !['cursor', 'productName'].includes(key));
  const cursor = value.cursor;
  const productName = value.productName;
  const reason = unexpected.length ? 'unexpected_keys'
    : cursor !== undefined && cursor !== '' && (typeof cursor !== 'string' || !commerceContract.UUID.test(cursor))
      ? 'invalid_cursor_shape'
      : productName !== undefined && (typeof productName !== 'string' || !productName.isWellFormed()
        || productName.includes('\0') || !productName.trim()
        || Buffer.byteLength(productName.trim(), 'utf8') > 128)
        ? 'invalid_product_name_shape' : 'static_input_shape_valid';
  return { complete: true, inputStage: reason === 'static_input_shape_valid' ? 'later_adapter_or_context' : 'arguments',
    reason, args: JSON.parse(raw) };
}
async function reauthenticateV07OriginalLaunch({page,actorFor,originalActor,originalReady,requireNewSession=false}){
  const response=await page.evaluate(async()=>{
    const result=await fetch('/api/secureshop/auth/bootstrap',{method:'POST',credentials:'same-origin',
      headers:{'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(10000)});
    return {status:result.status,body:await result.json()};
  });
  assert.equal(response.status,200);
  const actor=await actorFor(response.body);
  const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
  assert.deepEqual(createLaunchScope(actor.scope),createLaunchScope(originalActor.scope));
  assert.equal(response.body.bearer,originalReady.bearer);
  assert.equal(actor.scope.status,'active');
  assert.ok(Number.isSafeInteger(actor.scope.credentialVersion)&&actor.scope.credentialVersion>originalActor.scope.credentialVersion);
  assert.equal(response.body.launch.credentialVersion,actor.scope.credentialVersion);
  const originalExpiry=new Date(originalActor.scope.expiresAt).getTime(),renewedExpiry=new Date(actor.scope.expiresAt).getTime();
  assert.ok(Number.isFinite(originalExpiry)&&Number.isFinite(renewedExpiry)&&renewedExpiry>=originalExpiry);
  assert.equal(new Date(response.body.launch.expiresAt).getTime(),renewedExpiry);
  assert.deepEqual(actor.persona,originalActor.persona);
  assert.equal(actor.personaSession.authorityVersion,originalActor.personaSession.authorityVersion);
  if(requireNewSession)assert.notEqual(actor.personaSession.sessionId,originalActor.personaSession.sessionId);
  else {
    assert.equal(actor.personaSession.sessionId,originalActor.personaSession.sessionId);
    const stillCurrent=await actorFor(originalReady);
    assert.deepEqual(createLaunchScope(stillCurrent.scope),createLaunchScope(originalActor.scope));
    assert.deepEqual(stillCurrent.persona,originalActor.persona);
    assert.deepEqual(stillCurrent.personaSession,originalActor.personaSession);
  }
  return {ready:response.body,actor,renewal:{fromCredentialVersion:originalActor.scope.credentialVersion,
    toCredentialVersion:actor.scope.credentialVersion,fromExpiresAt:new Date(originalExpiry).toISOString(),
    toExpiresAt:new Date(renewedExpiry).toISOString(),bearerPreserved:true}};
}
async function readV07AssessmentHistory({identity,objectiveId,scope,persona}){
  const values=[objectiveId,persona.id,scope.launchId,scope.scenarioId,String(scope.generation),String(scope.platformOwnerId),String(scope.platformSessionId)];
  const history={};
  for(const table of ['assessment_judgments','assessment_completions','assessment_contributions']){
    history[table]=(await identity.query(`SELECT to_jsonb(t) row FROM secureshop_auth.${table} t
      JOIN secureshop_auth.assessment_judgments j
        ON j.tenant_id=t.tenant_id AND j.principal_id=t.principal_id AND j.evaluation_id=t.evaluation_id
      WHERE j.objective_id=$1 AND j.shop_user_id=$2
        AND j.execution_json->'scope'->>'launchId'=$3 AND j.execution_json->'scope'->>'scenarioId'=$4
        AND j.execution_json->'scope'->>'generation'=$5 AND j.execution_json->'scope'->>'platformOwnerId'=$6
        AND j.execution_json->'scope'->>'platformSessionId'=$7
      ORDER BY t.tenant_id,t.principal_id,t.evaluation_id`,values)).rows;
  }
  return JSON.parse(JSON.stringify(history));
}
async function readV07ActiveAssessments({identity,objectiveId,scope,persona}){
  return (await identity.query(`SELECT c.evaluation_id FROM secureshop_auth.active_assessment_contributions c
    JOIN secureshop_auth.assessment_judgments j
      ON j.tenant_id=c.tenant_id AND j.principal_id=c.principal_id AND j.evaluation_id=c.evaluation_id
    WHERE j.objective_id=$1 AND j.shop_user_id=$2
      AND j.execution_json->'scope'->>'launchId'=$3 AND j.execution_json->'scope'->>'scenarioId'=$4
      AND j.execution_json->'scope'->>'generation'=$5 AND j.execution_json->'scope'->>'platformOwnerId'=$6
      AND j.execution_json->'scope'->>'platformSessionId'=$7
    ORDER BY c.evaluation_id`,[objectiveId,persona.id,scope.launchId,scope.scenarioId,String(scope.generation),String(scope.platformOwnerId),String(scope.platformSessionId)])).rows;
}
function createV07CommittedAckObserver({records,save}){
 assert.ok(Array.isArray(records));assert.equal(typeof save,'function');
 const {writeTruncatedJsonAcknowledgement}=require('../fixtures/secureshopStandaloneSsrfRenderedQualification');
 let droppedPreview=false,droppedAssessment=false;
 return(req,res,next)=>{
  const preview=req.path==='/agents/customer/avatar-upload/polyglot-preview',assessment=req.path==='/agents/customer/avatar-upload/polyglot-assess';
  if(req.method==='POST'&&(preview||assessment)){
   assert.deepEqual(Object.keys(req.body).sort(),['requestId','sessionId']);for(const value of Object.values(req.body))assert.match(value,UUID);
   assert.ok(records.filter(row=>row.method==='POST'&&row.path===req.path).length<2);
  }
  if(!req.path.startsWith('/agents/customer/avatar-upload/polyglot-'))return next();
  const end=res.end;res.end=function(chunk,encoding,callback){
   const bytes=Buffer.isBuffer(chunk)?chunk:typeof chunk==='string'?Buffer.from(chunk,typeof encoding==='string'?encoding:'utf8'):null;
   if(bytes){assert.ok(bytes.length<=262144);const body=JSON.parse(bytes.toString('utf8'));
    const record={method:req.method,path:req.path,request:req.method==='POST'?structuredClone(req.body):null,status:res.statusCode,body,droppedAcknowledgement:false};records.push(record);
    if(req.method==='POST'&&res.statusCode===200&&((preview&&!droppedPreview)||(assessment&&!droppedAssessment))){
     if(preview)droppedPreview=true;else droppedAssessment=true;record.droppedAcknowledgement=true;
     const originalBody=bytes.toString('utf8');record.acknowledgement={mode:'headers-and-original-byte',originalStatus:res.statusCode,contentType:'application/json',originalBody,originalBodySha256:require('node:crypto').createHash('sha256').update(bytes).digest('hex'),originalByteCount:bytes.length,transmittedPrefixBase64:bytes.subarray(0,1).toString('base64'),prefixWritten:false,responseClosed:false};
     res.once('close',()=>{record.acknowledgement.responseClosed=true;save();});save();
     writeTruncatedJsonAcknowledgement(res,bytes,error=>{record.acknowledgement.prefixWritten=!error;save();res.destroy();});return res;
    }save();
   }
   return end.apply(this,arguments);
  };next();
 };
}
function assertV07HttpPosts(records,references,evaluationId){
 assert.equal(references.length,2);assert.match(evaluationId,UUID);
 for(const suffix of ['polyglot-preview','polyglot-assess']){
  const posts=records.filter(row=>row.method==='POST'&&row.path===`/agents/customer/avatar-upload/${suffix}`);assert.equal(posts.length,2);
  for(let index=0;index<2;index++){
   const record=posts[index],ref=references[index];assert.deepEqual(record.request,{sessionId:ref.sessionId,requestId:ref.requestId});assert.equal(record.status,200);assert.equal(record.droppedAcknowledgement,index===0);
   if(index===0){
    const ack=record.acknowledgement;assert.deepEqual(Object.keys(ack||{}).sort(),['mode','originalStatus','contentType','originalBody','originalBodySha256','originalByteCount','transmittedPrefixBase64','prefixWritten','responseClosed'].sort());
    assert.equal(ack.mode,'headers-and-original-byte');assert.equal(ack.originalStatus,200);assert.equal(ack.contentType,'application/json');assert.equal(ack.prefixWritten,true);assert.equal(ack.responseClosed,true);
    assert.equal(typeof ack.originalBody,'string');assert.deepEqual(JSON.parse(ack.originalBody),record.body);const bytes=Buffer.from(ack.originalBody);assert.equal(ack.originalByteCount,bytes.length);assert.equal(ack.transmittedPrefixBase64,bytes.subarray(0,1).toString('base64'));assert.equal(ack.originalBodySha256,require('node:crypto').createHash('sha256').update(bytes).digest('hex'));
   }else assert.equal(record.acknowledgement,undefined);
   if(suffix==='polyglot-preview'){
    assert.deepEqual(Object.keys(record.body).sort(),['operationId','uploadOperationId','status','sourceSha256','text','replayed'].sort());assert.equal(record.body.uploadOperationId,ref.operationId);assert.equal(record.body.status,index===0?'executed':'fixed_reencoded');assert.equal(record.body.replayed,false);assert.equal(typeof record.body.text,'string');
   }else if(index===0){assert.equal(record.body.completed,true);assert.equal(record.body.judgment.verdict,'pass');assert.equal(record.body.judgment.evaluationId,evaluationId);assert.equal(record.body.replayed,false);}
   else assert.deepEqual(record.body,{completed:false,status:'ineligible',modelEvaluated:false});
  }
 }
 return true;
}
async function bounded(promise, label, timeout = 15000) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error(label), { code: 'OBSERVATION_TIMEOUT' })), timeout);
    })]);
  } finally { clearTimeout(timer); }
}

test(V29_AGENCY ? 'rendered customer teaching role escalation proves denied ACL, owned effect, canonical judgment, fixed block and recovery'
  : V44_PATH_SUMMARY ? 'rendered customer file path traversal proves original owned disclosure, canonical assessment, fixed denial and recovery'
  : V19_DIAGNOSTIC ? 'rendered V19 file summary captures one original graph exception without qualification'
  : V19_SUMMARY ? 'rendered V19 file summary records original answers, canonical verdicts, fixed contrast and saved recovery'
  : V46_TRAVERSAL ? 'rendered customer avatar traversal proves an owned same-operation escaped file, exact readback, canonical assessment, fixed denial and recovery'
  : V08_SVG ? 'rendered customer SVG upload proves exact stored bytes, real browser execution, canonical assessment, fixed denial and recovery'
  : V07_POLYGLOT ? 'rendered customer GIF polyglot proves separate genuine preview decision, owned Node execution, canonical assessment, fixed reencoding and recovery'
  : V06_UPLOAD ? 'rendered customer avatar upload proves owned storage, inline serve, canonical assessment, fixed denial and recovery'
  : CHECKOUT_FENCES ? 'standalone customer checkout invalidates changed stock and price and recovers one confirmation across two tabs'
  : STOCK_REJECTION ? 'standalone customer chat durably rejects an explicit zero-stock add and recovers the exact saved outcome'
  : PRODUCT_DETAILS ? 'standalone customer chat disambiguates similar owned products and reads the physically selected detail'
  : OLDER_ORDERS ? 'standalone customer chat paginates owned older orders and reads the physically selected detail'
  : REFUND_HANDOFF ? 'standalone customer chat opens trusted refund review and exactly recovers one owned ticket'
  : ADDRESS_SETUP ? 'standalone customer chat opens trusted address setup and exactly recovers owned address create and edit'
  : PROFILE ? 'standalone customer chat prepares and confirms an owned profile update with exact recovery'
  : PAYMENT_SETUP ? 'standalone customer chat opens trusted practice payment setup and exactly recovers one method'
  : CART_LIFECYCLE ? 'standalone customer chat prepares, confirms, and exactly recovers bound cart mutations'
    : 'standalone customer checkout and owned order chat require real model, trusted confirmation, and exact recovery',
  { skip: !ENABLED, timeout: V19_SUMMARY ? 1800000 : 600000 }, async () => {
    const root = path.resolve(process.env.DVAIA_CURRENT_MAIN_WORKSPACE || '/');
    assert.equal(root, process.cwd());
    const build = path.resolve((CHECKOUT_FENCES
      ? process.env.SECURESHOP_CUSTOMER_CHECKOUT_FENCES_BUILD
      : STOCK_REJECTION
      ? process.env.SECURESHOP_CUSTOMER_OUT_OF_STOCK_BUILD
      : PRODUCT_DETAILS
      ? process.env.SECURESHOP_CUSTOMER_PRODUCT_DETAILS_BUILD
      : OLDER_ORDERS
      ? process.env.SECURESHOP_CUSTOMER_OLDER_ORDERS_BUILD
      : REFUND_HANDOFF
      ? process.env.SECURESHOP_CUSTOMER_REFUND_HANDOFF_BUILD
      : ADDRESS_SETUP
      ? process.env.SECURESHOP_CUSTOMER_ADDRESS_SETUP_BUILD
      : PROFILE
      ? process.env.SECURESHOP_CUSTOMER_PROFILE_BUILD
      : PAYMENT_SETUP
      ? process.env.SECURESHOP_CUSTOMER_PAYMENT_SETUP_BUILD
      : CART_LIFECYCLE
      ? process.env.SECURESHOP_CUSTOMER_CART_LIFECYCLE_BUILD
      : process.env.SECURESHOP_CUSTOMER_CHECKOUT_BUILD) || '/');
    assert.equal(build, path.join(root, 'client/build'));
    await fs.access(path.join(build, 'secureshop-frame.html'));
    const v01ReceiptPath = V01_AUDIT ? process.env.SECURESHOP_V01_AUDIT_BROWSER_EVIDENCE_PATH : null;
    if(V01_AUDIT)assert.ok(path.isAbsolute(v01ReceiptPath||'')&&!path.resolve(v01ReceiptPath).startsWith(`${root}${path.sep}`));
    const v06ReceiptPath = V07_POLYGLOT ? process.env.SECURESHOP_V07_POLYGLOT_BROWSER_EVIDENCE_PATH : V46_TRAVERSAL ? process.env.SECURESHOP_V46_TRAVERSAL_BROWSER_EVIDENCE_PATH : V08_SVG ? process.env.SECURESHOP_V08_SVG_BROWSER_EVIDENCE_PATH : V06_UPLOAD ? process.env.SECURESHOP_V06_UPLOAD_BROWSER_EVIDENCE_PATH : null;
    if(UPLOAD_BROWSER)assert.ok(path.isAbsolute(v06ReceiptPath||'')&&!path.resolve(v06ReceiptPath).startsWith(`${root}${path.sep}`));
    const v29ReceiptPath=V29_AGENCY?process.env.SECURESHOP_V29_AGENCY_EVIDENCE_PATH:null;
    if(V29_AGENCY)assert.ok(path.isAbsolute(v29ReceiptPath||'')&&!path.resolve(v29ReceiptPath).startsWith(`${root}${path.sep}`));
    const v44ReceiptPath=V44_PATH_SUMMARY?process.env.SECURESHOP_V44_FILE_PATH_SUMMARY_EVIDENCE_PATH:null;
    const v44FilesRoot=V44_PATH_SUMMARY?path.resolve(process.env.SECURESHOP_V44_FILES_ROOT||'/'):null;
    if(V44_PATH_SUMMARY)for(const value of [v44ReceiptPath,v44FilesRoot])assert.ok(path.isAbsolute(value||'')&&!path.resolve(value).startsWith(`${root}${path.sep}`));
    const uploadRoot=UPLOAD_BROWSER?path.resolve(process.env.SECURESHOP_UPLOAD_ROOT||'/'):null;
    if(UPLOAD_BROWSER)assert.ok(path.isAbsolute(uploadRoot)&&!uploadRoot.startsWith(`${root}${path.sep}`));
    const receiptPath = (CHECKOUT_FENCES
      ? process.env.SECURESHOP_CUSTOMER_CHECKOUT_FENCES_EVIDENCE_PATH
      : STOCK_REJECTION
      ? process.env.SECURESHOP_CUSTOMER_OUT_OF_STOCK_EVIDENCE_PATH
      : PRODUCT_DETAILS
      ? process.env.SECURESHOP_CUSTOMER_PRODUCT_DETAILS_EVIDENCE_PATH
      : OLDER_ORDERS
      ? process.env.SECURESHOP_CUSTOMER_OLDER_ORDERS_EVIDENCE_PATH
      : REFUND_HANDOFF
      ? process.env.SECURESHOP_CUSTOMER_REFUND_HANDOFF_EVIDENCE_PATH
      : ADDRESS_SETUP
      ? process.env.SECURESHOP_CUSTOMER_ADDRESS_SETUP_EVIDENCE_PATH
      : PROFILE
      ? process.env.SECURESHOP_CUSTOMER_PROFILE_EVIDENCE_PATH
      : PAYMENT_SETUP
      ? process.env.SECURESHOP_CUSTOMER_PAYMENT_SETUP_EVIDENCE_PATH
      : CART_LIFECYCLE
      ? process.env.SECURESHOP_CUSTOMER_CART_LIFECYCLE_EVIDENCE_PATH
      : V29_AGENCY ? process.env.SECURESHOP_V29_AGENCY_EVIDENCE_PATH
      : process.env.SECURESHOP_CUSTOMER_CHECKOUT_EVIDENCE_PATH) || '';
    assert.ok(path.isAbsolute(receiptPath) && !path.resolve(receiptPath).startsWith(`${root}${path.sep}`));
    const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || '';
    assert.ok(path.isAbsolute(executablePath)); await fs.access(executablePath);
    const modelURL = new URL(process.env.OLLAMA_BASE_URL || '');
    assert.equal(modelURL.href, 'http://127.0.0.1:11434/'); assert.equal(process.env.OLLAMA_MODEL, MODEL);
    const config = urls(), pools = {};
    for (const [key, connectionString] of Object.entries(config)) pools[key] = new Pool({
      connectionString, max: key.endsWith('RUNTIME') ? 12 : 3,
      connectionTimeoutMillis: 5000, statement_timeout: 10000 });
    const leasePool = new Pool({ connectionString: config.IDENTITY_RUNTIME, max: 4,
      connectionTimeoutMillis: 5000, statement_timeout: 10000 });
    const status = { scope: SCOPE, passed: false, ...Object.fromEntries(FLAGS.map(key => [key, false])),
      actualModelCalls: 0, chatTurns: 0, ...(REFUND_HANDOFF ? { refundModelCalls: 0 } : {}),
      judgeCalls: 0, cleanupErrors: [] };
    let stage = 'setup', failure, composition, reset, browser, server, profile, cdp, page, uploadAssetService;
    const pendingInterceptions = new Set();
    const checkoutHttpResponses = [];
    // Capture the actual JSON bytes sent by these protected HTTP endpoints.
    // Do not defer CDP body reads until after UI/SQL settlement: Chromium may
    // evict their bodies. Every record still requires a finished server response
    // and its matching browser response, and never substitutes a saved receipt.
    function checkoutResponse(surface, matches, timeout = 30000) {
      const first = checkoutHttpResponses.length;
      return surface.waitForResponse(matches, { timeout }).then(async value => {
        const pathname = new URL(value.url()).pathname, method = value.request().method();
        const captured = await waitFor(() => {
          const record = checkoutHttpResponses.slice(first).find(record => !record.claimed
            && record.pathname === pathname && record.method === method && record.status === value.status());
          // Claim synchronously so two tabs cannot reuse one finished response.
          if (record) record.claimed = true;
          return record;
        }, 'finished protected HTTP JSON response', 15000);
        if (captured.error) throw Object.assign(new Error('Protected HTTP JSON capture failed'), { code: captured.error });
        return { value, body: captured.body };
      }).then(value => ({ value }), error => ({ error }));
    }
    const decisions = [], posts = [], v01Posts = [], v01AssessmentPosts = [], v01AssessmentDiagnostics = [], v01ActorSpans = [], v06Posts = [], v06AssessmentPosts = [], v06Multipart = [], v06AssetPosts = [], v06ActorSpans = [], v06SessionResponses = [], v06SessionServerResponses = [], v06SessionDiagnostics = [], judgePackets = [], customerChatReads = [], refundPosts = [], refundReads = [], stockTurnReads = [], confirms = [], cartConfirms = [], paymentCreates = [], addressSaves = [], profileConfirms = [], directProfileSaves = [],
      operationReads = [], faultedOperationReads = [], completedTurns = [], turnObservations = [], addressTurnEvidence = [];
    let interceptionFailure, profileConfirmFailure = null, profileConfirmResponse = null,
      expectedConfirm, expectedCartConfirm, expectedPayment, selectedPaymentScenario, hideCheckoutReads = false;
    let hideCartReads = false, hidePaymentReads = false, hideAddressReads = false, hideProfileReads = false,
      refundReadFailuresRemaining = 0, olderReadFailuresRemaining = 0,
      hideStockTurnReads = false, seededRefundOrderId = null, lostReceipt;
    let productTraceFloor = null, checkoutRecoveryDiagnostic = null, checkoutChoiceEvidence = null, v01Receipt = null, v06Receipt = null, v08Receipt = null, v06FixturePath = null;
    const v06Evidence=UPLOAD_BROWSER?{version:1,actorSpans:v06ActorSpans,actorRequests:v06Posts,
      multipart:v06Multipart,sessionResponses:v06SessionResponses,sessionServerResponses:v06SessionServerResponses,sessionDiagnostics:v06SessionDiagnostics,assessmentRequests:v06AssessmentPosts,fixture:null,vulnerable:null,fixed:null,judgeTranscripts:judgePackets}:null;
    const v07Document=V07_POLYGLOT?{subject:null,vuln:null,fixed:null,judge:null,wire:[]}:null;
    if(V07_POLYGLOT)v06Evidence.polyglot=v07Document;
    let v07CurrentTurn=null,v07JudgeResult;
    const saveV07=()=>{if(!V07_POLYGLOT)return;const text=JSON.stringify(v06Evidence,null,2);assert.ok(Buffer.byteLength(text)<=8*1024*1024);require('node:fs').writeFileSync(path.join(path.dirname(v06ReceiptPath),'v07-original-evidence.json'),text,{mode:0o600});};
    const v01Evidence = V01_AUDIT ? { version: 1, actorSpans: v01ActorSpans, actorRequests: v01Posts,
      assessmentRequests: v01AssessmentPosts, source: null, traces: [], effects: [], judgeTranscripts: judgePackets,
      fixedSource: null, protectedReadCounts: null } : null;
    let v44Transport,v44OriginalJudgeURL,v44JudgeResult,v44Candidate,v44ActiveCase,v44Receipt,v44PeerTenantSlug;
    const v44Document={version:1,catalogAdmission:null,actorSpans:[],wire:[],jsonRequests:[],assessmentRequests:[],judgeRequests:[],judgeTranscripts:[],vulnerable:null,fixed:null,history:null,sibling:null,reset:null,errors:[]};
    const saveV44=()=>{if(!V44_PATH_SUMMARY)return;const text=JSON.stringify(v44Document,null,2);assert.ok(Buffer.byteLength(text)<=4*1024*1024);require('node:fs').writeFileSync(path.join(path.dirname(v44ReceiptPath),'v44-original-evidence.json'),text,{mode:0o600});};
    const v29Document={version:1,sourceVersion:332,actorSpans:[],wire:[],browserRequests:[],fixed:null,vulnerable:null,
      catalogAdmission:null,freshSchema:null,judgeRequests:[],judgeTranscripts:[],sibling:null,history:null,reset:null,errors:[]};
    const saveV29=()=>{if(!V29_AGENCY)return;const text=JSON.stringify(v29Document,null,2);
      assert.ok(Buffer.byteLength(text)<=4*1024*1024);
      require('node:fs').writeFileSync(path.join(path.dirname(v29ReceiptPath),'v29-original-evidence.json'),text,{mode:0o600});};
    let v19;
    try {
      if (V19_SUMMARY) { v19 = V19.createV19RenderedCohort({ root, status, diagnosticOnly: V19_DIAGNOSTIC,
        receiptPath: process.env.SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH }); await v19.start(); }
      for (const [store, directory] of [['IDENTITY', 'identity-migrations'],
        ['AGENTS', 'workshop-migrations/secureshop_agents'], ['REVIEW', 'workshop-migrations/secureshop_review'],
        ['COMMERCE', 'workshop-migrations/secureshop']]) {
        if(V29_AGENCY&&store==='AGENTS'){
          const before=(await pools.AGENTS_MIGRATION.query("SELECT to_regclass('secureshop_agents.owned_agency_role_targets') AS target,to_regclass('secureshop_agents.owned_agency_role_effects') AS effect")).rows[0];
          assert.deepEqual(before,{target:null,effect:null});
        }
        const applied=await migrate(pools[`${store}_MIGRATION`], path.join(root, 'db/postgres', directory));
        if(V29_AGENCY&&store==='AGENTS'){
          const names=['0113_owned_agency_role_state.sql','0114_customer_agency_role_registry_successor.sql'];
          assert(names.every(name=>applied.includes(name)));
          const ledger=(await pools.AGENTS_MIGRATION.query('SELECT name,checksum FROM dvaia_migrations.ledger WHERE name=ANY($1::text[]) ORDER BY name',[names])).rows;
          assert.deepEqual(ledger,names.map(name=>({name,checksum:require('node:crypto').createHash('sha256')
            .update(require('node:fs').readFileSync(path.join(root,'db/postgres',directory,name))).digest('hex')})));
          assert.deepEqual(await migrate(pools.AGENTS_MIGRATION,path.join(root,'db/postgres',directory)),[]);
          const role='dvaia_secureshop_agents_runtime';
          for(const table of ['owned_agency_role_targets','owned_agency_role_effects']){
            for(const privilege of ['SELECT','INSERT'])assert.equal((await pools.AGENTS_MIGRATION.query(
              'SELECT has_table_privilege($1,$2,$3) ok',[role,`secureshop_agents.${table}`,privilege])).rows[0].ok,true);
            for(const privilege of ['UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'])assert.equal((await pools.AGENTS_MIGRATION.query(
              'SELECT has_table_privilege($1,$2,$3) ok',[role,`secureshop_agents.${table}`,privilege])).rows[0].ok,false);
          }
          for(const column of ['teaching_role','revision','lifecycle'])assert.equal((await pools.AGENTS_MIGRATION.query(
            "SELECT has_column_privilege($1,'secureshop_agents.owned_agency_role_targets',$2,'UPDATE') ok",
            [role,column])).rows[0].ok,true);
          assert.equal((await pools.AGENTS_MIGRATION.query(
            "SELECT has_column_privilege($1,'secureshop_agents.owned_agency_role_targets','customer_id','UPDATE') ok",
            [role])).rows[0].ok,false);
          for(const name of ['guard_owned_agency_role_target','retire_owned_agency_roles'])assert.equal((await pools.AGENTS_MIGRATION.query(
            "SELECT has_function_privilege($1,$2,'EXECUTE') ok",[role,`secureshop_agents.${name}()`])).rows[0].ok,false);
          const empty=(await pools.AGENTS_MIGRATION.query('SELECT (SELECT count(*)::int FROM secureshop_agents.owned_agency_role_targets) AS targets,(SELECT count(*)::int FROM secureshop_agents.owned_agency_role_effects) AS effects')).rows[0];
          assert.deepEqual(empty,{targets:0,effects:0});
          v29Document.freshSchema={applied:names,ledger,empty};saveV29();status.freshRoleSchema=true;
        }
      }
      await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(pools.IDENTITY_MIGRATION);
      await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(pools.IDENTITY_MIGRATION);
      const seed = await pools.COMMERCE_MIGRATION.connect();
      try { await seed.query('BEGIN'); await require('../../server/database/postgres/secureshopSeed').seedSecureShop(seed);
        await seed.query('COMMIT'); } catch (error) { await seed.query('ROLLBACK'); throw error; } finally { seed.release(); }
      status.isolatedStores = true;
      const identity = pools.IDENTITY_RUNTIME, agents = pools.AGENTS_RUNTIME, review = pools.REVIEW_RUNTIME;
      const auth = require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({
        repository: require('../../server/database/postgres/secureshopStandaloneAuthRepository')
          .createSecureShopStandaloneAuthRepository({ pool: identity }) });
      const suffix = randomUUID().slice(0, 8), username = `checkout_${suffix}`, password = 'owned-customer-checkout';
      const registration = await auth.register({ username, password, email: `${username}@example.invalid`, role: 'customer' });
      const siblingUsername = `checkout_peer_${suffix}`;
      const sibling = await auth.register({ username: siblingUsername, password,
        email: `${siblingUsername}@example.invalid`, role: 'customer' });
      const baseAudit = require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({
        agentsPool: agents, reviewPool: review, includeRunArtifacts: true });
      const v01ProtectedAuditReads = { total: 0, expected: 0, unexpected: 0 };
      let v01ProtectedAuditExpectation = null;
      const observeV01ProtectedAuditQuery = (input, values) => {
        const sql = typeof input === 'string' ? input : input?.text;
        const protectedSelect = V01_AUDIT && typeof sql === 'string'
          && sql.includes('FROM secureshop_review.bound_audit_events e')
          && sql.includes('JOIN secureshop_review.product_target_orders o')
          && sql.includes('AND ($9::uuid IS NULL OR e.event_id=$9::uuid)')
          && sql.includes('ORDER BY e.created_at DESC,e.event_id DESC LIMIT 2');
        if (!protectedSelect) return;
        v01ProtectedAuditReads.total += 1;
        const expected = v01ProtectedAuditExpectation && Array.isArray(values) && values.length === 16
          && Number(values[6]) === v01ProtectedAuditExpectation.shopUserId
          && Number(values[7]) === v01ProtectedAuditExpectation.orderId
          && (values[8] === null || values[8] === v01ProtectedAuditExpectation.eventId);
        v01ProtectedAuditReads[expected ? 'expected' : 'unexpected'] += 1;
      };
      const observeReviewClient = client => new Proxy(client, { get(target, key) {
        if (key === 'query') return (...args) => {
          observeV01ProtectedAuditQuery(args[0], args[1]); return target.query(...args);
        };
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      } });
      const observedReviewPool = V01_AUDIT ? new Proxy(review, { get(target, key) {
        if (key === 'query') return (...args) => {
          observeV01ProtectedAuditQuery(args[0], args[1]); return target.query(...args);
        };
        if (key === 'connect') return async (...args) => observeReviewClient(await target.connect(...args));
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      } }) : review;
      const audit = baseAudit;
      if(V29_AGENCY){v44Transport=await require('./secureshopMailActualTransport').createMailActualTransport({protocol:'v29-agency-browser-v1',maxHttpCalls:9,allowMetadata:true,record(value){v29Document.wire=value.calls;saveV29();}});v44OriginalJudgeURL=process.env.OLLAMA_BASE_URL;process.env.OLLAMA_BASE_URL=v44Transport.judgeUrl;}
      if(V07_POLYGLOT){v44Transport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:10,allowMetadata:true,record(value){v07Document.wire=value.calls;saveV07();}});v44OriginalJudgeURL=process.env.OLLAMA_BASE_URL;process.env.OLLAMA_BASE_URL=v44Transport.judgeUrl;}
      if(V44_PATH_SUMMARY){
        v44Transport=await require('./secureshopMailActualTransport').createMailActualTransport({maxHttpCalls:8,allowMetadata:true,record(value){v44Document.wire=value.calls;saveV44();}});
        v44OriginalJudgeURL=process.env.OLLAMA_BASE_URL;process.env.OLLAMA_BASE_URL=v44Transport.judgeUrl;
      }
      const sharedFiles = V44_PATH_SUMMARY?require('../../sidecars/sandbox-runner/secureshopFiles').createSecureShopFiles({root:v44FilesRoot}):require('../fixtures/secureshopAvatarUploadRenderedQualification')
        .createUploadBrowserFiles({ uploadRoot, v19Files: v19?.files, uploadBrowser: UPLOAD_BROWSER });
      reset = require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({
        identityPool: identity, agentsPool: agents, reviewPool: review, leasePool, audit,
        ...(sharedFiles ? { files: sharedFiles } : {}) });
      if (UPLOAD_BROWSER) assert.equal(reset.files, sharedFiles);
      if (V44_PATH_SUMMARY) assert.equal(reset.files, sharedFiles);
      const configuredJudge=(V29_AGENCY||V01_AUDIT||UPLOAD_BROWSER||V44_PATH_SUMMARY)?require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({observeExecutionTranscript:packet=>{judgePackets.push(packet);if(V29_AGENCY){v29Document.judgeTranscripts.push(packet);saveV29();}if(V44_PATH_SUMMARY){v44Document.judgeTranscripts.push(packet);saveV44();}}}):null;
      const judge = v19 ? v19.createJudge() : (V29_AGENCY||V01_AUDIT||UPLOAD_BROWSER||V44_PATH_SUMMARY) ? async input => { status.judgeCalls++;assert.equal(status.judgeCalls,1);if(V29_AGENCY){v29Document.judgeRequests.push(v29JudgeRequestRecord(input));saveV29();}if(V07_POLYGLOT){v07JudgeResult=await configuredJudge(input);v07Document.judge={row:null,originalResult:JSON.stringify(v07JudgeResult),proof:require('../../server/agent-runtime/objectiveJudge').readConfiguredJudgeProvenance(v07JudgeResult)};saveV07();return v07JudgeResult;}if(V44_PATH_SUMMARY){assert.equal(v44ActiveCase,'vuln');v44Document.judgeRequests.push(structuredClone(v44Document.assessmentRequests.at(-1)));saveV44();v44JudgeResult=await configuredJudge(input);return v44JudgeResult;}return configuredJudge(input); }
        : async () => { status.judgeCalls++; throw Error('Customer checkout has no Judge admission'); };
      if(V44_PATH_SUMMARY){const administrator=await auth.login({username:'student_admin',password:'student123'});
        v44Candidate=await require('../fixtures/secureshopV44CandidateCatalog').admitV44DisposableCandidate({migration:pools.IDENTITY_MIGRATION,
          catalog:require('../../server/services/secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({pool:identity,authService:auth}),administratorContext:administrator.context,curriculum:require('../../server/config/secureshopCurriculum')});
        v44Document.catalogAdmission=structuredClone(v44Candidate);saveV44();}
      if(V29_AGENCY){const administrator=await auth.login({username:'student_admin',password:'student123'});
        const candidate=await require('../fixtures/secureshopV06CandidateCatalog').admitV06DisposableCandidate({
          migration:pools.IDENTITY_MIGRATION,
          catalog:require('../../server/services/secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({pool:identity,authService:auth}),
          administratorContext:administrator.context,curriculum:require('../../server/config/secureshopCurriculum'),
          objectiveId:'ss_customer_role_escalation'});
        v29Document.catalogAdmission=structuredClone(candidate);saveV29();status.fixtureLocalCandidateAdmission=candidate.fixtureLocalCandidateAdmission;}
      let v07Candidate=null,v01Candidate=null,v06Candidate=null,v08Candidate=null,v46Candidate=null;
      if(V01_AUDIT){
        const administrator=await auth.login({username:'student_admin',password:'student123'});
        v01Candidate=await require('../fixtures/secureshopV01CandidateCatalog').admitV01DisposableCandidate({
          migration:pools.IDENTITY_MIGRATION,
          catalog:require('../../server/services/secureshopAssessmentCatalog')
            .createSecureShopAssessmentCatalog({pool:identity,authService:auth}),
          administratorContext:administrator.context,
          curriculum:require('../../server/config/secureshopCurriculum')});
      }
      if(V08_SVG){
        const administrator=await auth.login({username:'student_admin',password:'student123'});
        v08Candidate=await require('../fixtures/secureshopV08CandidateCatalog').admitV08DisposableCandidate({
          migration:pools.IDENTITY_MIGRATION,
          catalog:require('../../server/services/secureshopAssessmentCatalog')
            .createSecureShopAssessmentCatalog({pool:identity,authService:auth}),
          administratorContext:administrator.context,
          curriculum:require('../../server/config/secureshopCurriculum')});
      }
      if(V46_TRAVERSAL){
        const administrator=await auth.login({username:'student_admin',password:'student123'});
        v46Candidate=await require('../fixtures/secureshopV46CandidateCatalog').admitV46DisposableCandidate({
          migration:pools.IDENTITY_MIGRATION,
          catalog:require('../../server/services/secureshopAssessmentCatalog')
            .createSecureShopAssessmentCatalog({pool:identity,authService:auth}),
          administratorContext:administrator.context,
          curriculum:require('../../server/config/secureshopCurriculum')});
      }
      if(V07_POLYGLOT){const administrator=await auth.login({username:'student_admin',password:'student123'});
        v07Candidate=await require('../fixtures/secureshopV06CandidateCatalog').admitV07DisposableCandidate({migration:pools.IDENTITY_MIGRATION,catalog:require('../../server/services/secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({pool:identity,authService:auth}),administratorContext:administrator.context,curriculum:require('../../server/config/secureshopCurriculum')});}
      if(V06_UPLOAD){
        const administrator=await auth.login({username:'student_admin',password:'student123'});
        v06Candidate=await require('../fixtures/secureshopV06CandidateCatalog').admitV06DisposableCandidate({
          migration:pools.IDENTITY_MIGRATION,
          catalog:require('../../server/services/secureshopAssessmentCatalog')
            .createSecureShopAssessmentCatalog({pool:identity,authService:auth}),
          administratorContext:administrator.context,
          curriculum:require('../../server/config/secureshopCurriculum')});
      }
      if (v19) {
        const administrator = await auth.login({ username: 'student_admin', password: 'student123' });
        await v19.admitCandidate({ migration: pools.IDENTITY_MIGRATION,
          catalog: require('../../server/services/secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({ pool: identity, authService: auth }),
          administratorContext: administrator.context, curriculum: require('../../server/config/secureshopCurriculum') });
      }
      const grading = await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({
        identityPool: identity, agentsPool: agents,
        progress: require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity),
        resetComposition: reset, judge,
        expectedIdentityDatabase: new URL(config.IDENTITY_RUNTIME).pathname.slice(1),
        expectedAgentsDatabase: new URL(config.AGENTS_RUNTIME).pathname.slice(1) });
      const scenes = require('../../server/services/secureshopScenes').createSecureShopScenes({
        repository: require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({
          pool: identity, launches: reset.launches }), reviewPool: review, launches: reset.launches });
      const modeRepository = require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
      const modeAuthority = require('../../server/services/secureshopFeatureModeAuthority').createFeatureModeAuthority({
        progress: modeRepository, launches: reset.launches });
      const couponDependencies = await require('../../server/services/secureshopCouponProduction').prepareCommerceDependencies({
        modeAuthority, reviewPool: review, launches: reset.launches, mode: 'vuln' });
      const provider = new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
        baseUrl: (V29_AGENCY||V07_POLYGLOT||V44_PATH_SUMMARY)?v44Transport.actorUrl:v19 ? v19.actorURL() : modelURL.origin, model: MODEL });
      if (v19) v19.wrapProvider(provider);
      if(V44_PATH_SUMMARY)for(const method of ['chat','finalResponse']){const invoke=provider[method].bind(provider);provider[method]=async input=>{
        assert.ok(['vuln','fixed'].includes(v44ActiveCase));assert.ok(++status.actualModelCalls<=4);
        const request=v44Document.jsonRequests.at(-1);assert.ok(request);const prior=v44Document.actorSpans.filter(row=>row.requestId===request.requestId);assert.ok(prior.length<2);assert.equal(method,prior.length===0?'chat':'finalResponse');
        const span={caseId:v44ActiveCase,requestId:request.requestId,method,request:JSON.parse(JSON.stringify({...input,signal:undefined})),wireStart:v44Transport.calls.length};v44Document.actorSpans.push(span);saveV44();
        try{const value=await invoke(input);span.response=JSON.parse(JSON.stringify(value));return value;}finally{span.wireEnd=v44Transport.calls.length;saveV44();}};}
      let v29Case=null;
      if(V29_AGENCY)for(const method of ['chat','finalResponse']){const invoke=provider[method].bind(provider);provider[method]=async input=>{
        assert.ok(['fixed','vuln'].includes(v29Case));assert.ok(++status.actualModelCalls<=8);
        const turn=posts.at(-1);assert.ok(turn?.requestId);const count=v29Document.actorSpans.filter(row=>row.caseId===v29Case).length;
        assert.ok(count<4,'one original customer graph remains within four physical model decisions');
        const span={caseId:v29Case,requestId:turn.requestId,method,request:JSON.parse(JSON.stringify({...input,signal:undefined})),wireStart:v44Transport.calls.length};
        v29Document.actorSpans.push(span);saveV29();
        try{const value=await invoke({...input,signal:AbortSignal.any([AbortSignal.timeout(60000),...(input.signal?[input.signal]:[])])});
          span.response=JSON.parse(JSON.stringify(value));assert.equal(value.provider,'ollama');assert.equal(value.model,MODEL);
          assert.equal(value.mocked,false);assert.notEqual(value.fallback,true);return value;
        }finally{span.wireEnd=v44Transport.calls.length;saveV29();}};}
      if(V07_POLYGLOT)for(const method of ['chat','finalResponse']){const invoke=provider[method].bind(provider);provider[method]=async input=>{
        assert.ok(v07CurrentTurn);assert.ok(++status.actualModelCalls<=8);assert.ok(++v07CurrentTurn.calls<=2);if(v07CurrentTurn.phase==='upload'){const posted=v06Posts.at(-1);assert.equal(posted.requestId,v07CurrentTurn.requestId);posted.calls=v07CurrentTurn.calls;}assert.equal(method,v07CurrentTurn.calls===1?'chat':'finalResponse');
        const span={method,requestId:v07CurrentTurn.requestId,phase:v07CurrentTurn.phase,request:JSON.parse(JSON.stringify({...input,signal:undefined})),wireIndices:[]};v06ActorSpans.push(span);const before=v44Transport.calls.length;saveV07();
        try{const response=await invoke(input);span.response=JSON.parse(JSON.stringify(response));return response;}finally{assert.equal(v44Transport.calls.length-before,1);span.wireIndices=[before];saveV07();}};}
      if (!v19&&!V29_AGENCY&&!V44_PATH_SUMMARY&&!V07_POLYGLOT) for (const method of ['chat', 'finalResponse']) {
        const invoke = provider[method].bind(provider);
        provider[method] = async input => {
          const refund = REFUND_HANDOFF && refundPosts.length > 0;
          const v01 = V01_AUDIT && v01Posts.length > 0;
          const v06 = UPLOAD_BROWSER && v06Posts.length > 0;
          const turn = refund ? refundPosts.at(-1) : v01 ? v01Posts.at(-1) : v06 ? v06Posts.at(-1) : posts.at(-1);
          assert.ok(turn, 'a model decision must belong to an admitted browser request');
          if (refund) assert.ok(++status.refundModelCalls <= 6);
          else if (v01) assert.ok(++status.actualModelCalls <= 28);
          else if (v06) assert.ok(++status.actualModelCalls <= 28);
          else {
            assert.ok(posts.length <= (CHECKOUT_FENCES ? 5 : OLDER_ORDERS ? 3 : PRODUCT_DETAILS || STOCK_REJECTION || REFUND_HANDOFF || PROFILE ? 2 : ADDRESS_SETUP ? 3 : PAYMENT_SETUP ? 1 : 7));
            assert.ok(++status.actualModelCalls <= (CHECKOUT_FENCES ? 20 : OLDER_ORDERS ? 15 : PROFILE ? 10 : PRODUCT_DETAILS || STOCK_REJECTION || REFUND_HANDOFF ? 8 : ADDRESS_SETUP ? 12 : PAYMENT_SETUP ? 4 : 24));
          }
          turn.calls = (turn.calls || 0) + 1;
          assert.ok(turn.calls <= (refund ? 6 : 4), 'existing bounded agent turn budget');
          const value = await invoke({ ...input, signal: AbortSignal.any([
            AbortSignal.timeout(60000), ...(input.signal ? [input.signal] : [])]) });
          if (v01) v01ActorSpans.push({ method, request: JSON.parse(JSON.stringify({ ...input, signal: undefined })),
            response: JSON.parse(JSON.stringify(value)) });
          if (v06) v06ActorSpans.push({ method, request: JSON.parse(JSON.stringify({ ...input, signal: undefined })),
            response: JSON.parse(JSON.stringify(value)) });
          assert.equal(value.provider, 'ollama'); assert.equal(value.model, MODEL);
          assert.equal(value.mocked, false); assert.notEqual(value.fallback, true);
          decisions.push({ requestId: turn.requestId, method, stopReason: value.stop_reason,
            tools: (value.tool_uses || []).map(call => call.name),
            ...(ADDRESS_SETUP ? { requestedAddressCalls: (value.tool_uses || []).slice(0, 4)
              .filter(call => ['account.addresses', 'account.address_setup',
                'account.address_edit_setup'].includes(call.name))
              .map(call => ({ tool: call.name, args: addressDiagnosticArgs(call.args, turn.message) })),
              offeredAddressTools: (Array.isArray(input.tools) ? input.tools : [])
                .filter(tool => tool.agent === 'account'
                  && ['addresses', 'address_setup', 'address_edit_setup'].includes(tool.tool))
                .map(tool => `account.${tool.tool}`).slice(0, 3),
              offeredAddressActions: (Array.isArray(input.tools) ? input.tools : [])
                .find(tool => tool.agent === 'account' && tool.tool === 'address_setup')
                ?.inputSchema?.properties?.action?.enum
                ?.filter(value => ['create', 'update'].includes(value)).slice(0, 2) || [] } : {}) });
          return value;
        };
      }
      const toolPolicyRepository = require('../../server/database/postgres/secureshopBoundAclRepository')
        .createSecureShopBoundAclRepository({ personaAuthority: grading.personaAuthority, audit: audit.agents });
      await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness').assertBoundToolPolicyReadiness(agents);
      let uploadAssetActivation=null,v08CapabilityMints=0;
      if(UPLOAD_BROWSER){const port=await reservePort('::1'),rawActivation=require('../../server/services/secureshopUploadAssetProduction').activationPolicy({...process.env,
        SS_BOUND_UPLOAD_ASSETS_ENABLED:'true',SS_UPLOAD_ASSET_HOST:'::1',SS_ALLOWED_ORIGINS:'http://localhost:3000,http://127.0.0.1:3000',
        SS_UPLOAD_ASSET_PORT:String(port),SS_UPLOAD_ASSET_PUBLIC_ORIGIN:`http://[::1]:${port}`,
        SS_UPLOAD_ASSET_CAPABILITY_SECRET:'v06-disposable-capability-secret-32-bytes'});const capability=V08_SVG?Object.freeze({...rawActivation.capability,mint(...args){v08CapabilityMints++;return rawActivation.capability.mint(...args);}}):rawActivation.capability;uploadAssetActivation=Object.freeze({...rawActivation,capability});}
      let restoreV19GraphFactory=null;
      if (V19_DIAGNOSTIC) {
        const installed = v19.installGraphDiagnostic(require('../../server/services/secureshopBoundFileSummaryGraph'));
        restoreV19GraphFactory = () => {
          const state = installed.restore(); assert.equal(state.factoryCalls, 1); return state;
        };
      }
      let restoreV06GraphFactory=null;
      if(UPLOAD_BROWSER){const graphModule=require('../../server/services/secureshopBoundUploadGraph'),originalCreate=graphModule.createSecureShopBoundUploadGraph;
        graphModule.createSecureShopBoundUploadGraph=options=>{const graph=originalCreate(options);return Object.freeze({...graph,
        async createSession(input){try{const value=await graph.createSession(input);v06SessionDiagnostics.push({status:'completed'});
          assert.ok(v06SessionDiagnostics.length<=2,'V06 session budget');return value;}catch(error){
          v06SessionDiagnostics.push({status:'failed',errors:profileErrorDiagnostic(error)});
          assert.ok(v06SessionDiagnostics.length<=2,'V06 session budget');throw error;}},
        async run(input){
          const capture=require('../fixtures/secureshopAvatarUploadRenderedQualification')
            [options.traversal===true?'captureTraversalGraphRunAttachment':'captureGraphRunAttachment'](input);
          v06Multipart.push(capture);v06Posts.push({...structuredClone(capture.fields),calls:0});assert.ok(v06Posts.length<=2,'V06 actor budget');
          if(V07_POLYGLOT)v07CurrentTurn={phase:'upload',requestId:input.requestId,calls:0};
          try{return await graph.run(input);}finally{if(V07_POLYGLOT)v07CurrentTurn=null;}}});};restoreV06GraphFactory=()=>{graphModule.createSecureShopBoundUploadGraph=originalCreate;};}
      let restoreV07GraphFactory;
      if(V07_POLYGLOT){const module=require('../../server/services/secureshopV07UploadPreviewGraph'),create=module.createV07UploadPreviewGraph;module.createV07UploadPreviewGraph=options=>{const graph=create(options);return Object.freeze({...graph,async run(input){const row=(await agents.query('SELECT result_json FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[input.sessionId,input.requestId])).rows[0];assert.ok(row?.result_json?.taskMetadata?.boundUpload?.operationId);v07CurrentTurn={phase:'preview',requestId:require('../../server/services/secureshopV07UploadSourceReader').previewIdentity(row.result_json.taskMetadata.boundUpload.operationId).requestId,calls:0};try{return await graph.run(input);}finally{v07CurrentTurn=null;}}});};restoreV07GraphFactory=()=>{module.createV07UploadPreviewGraph=create;};}
      let restoreV01RouteFactory=null;
      if(V01_AUDIT){const routeModule=require('../../server/routes/secureshop/boundV01AuditLesson'),originalCreate=routeModule.createBoundV01AuditLessonRouter;
        routeModule.createBoundV01AuditLessonRouter=options=>{const assessment=options.assessment;return originalCreate({...options,assessment:Object.freeze({...assessment,
          async runAttempt(input){try{return await assessment.runAttempt(input);}catch(error){
            v01AssessmentDiagnostics.push({stage:'runAttempt',errors:v01AssessmentErrorDiagnostic(error,root)});
            assert.ok(v01AssessmentDiagnostics.length<=2,'V01 assessment diagnostic budget');throw error;}}})});};
        restoreV01RouteFactory=()=>{routeModule.createBoundV01AuditLessonRouter=originalCreate;};}
      try{composition = require('../../server/services/secureshopBoundReviewComposition').createSecureShopBoundReviewComposition({
        identityPool: identity, agentsPool: agents, reviewPool: observedReviewPool, commercePool: pools.COMMERCE_RUNTIME,
        resetComposition: reset, gradingBootstrap: grading, scenes, modeAuthority, couponDependencies,
        personaInboxFeature: require('../../server/services/secureshopPersonaInboxActivationPolicy')
          .activationPolicy(process.env).requested,
        toolPolicyRepository, fixtures: [], ...(sharedFiles ? { files: sharedFiles } : {}),
        ...(v19 ? { fileSummaryFeature: true } : {}),
        ...(V44_PATH_SUMMARY?{filePathSummaryFeature:true}:{}),
        requiredObjectives: V29_AGENCY?['ss_stored_browser_execution','ss_customer_role_escalation']:V44_PATH_SUMMARY?['ss_stored_browser_execution','ss_file_path_traversal_read']:V19_SUMMARY ? ['ss_stored_browser_execution', 'ss_file_upload_instruction_adoption'] : V01_AUDIT
          ? ['ss_stored_browser_execution','ss_auth_bypass_jwt_none'] : V46_TRAVERSAL ? ['ss_stored_browser_execution','ss_upload_path_traversal_write'] : V08_SVG ? ['ss_stored_browser_execution','ss_upload_svg_browser_execution'] : V07_POLYGLOT ? ['ss_stored_browser_execution','ss_upload_polyglot_server_execution'] : V06_UPLOAD
          ? ['ss_stored_browser_execution','ss_upload_extension_bypass'] : ['ss_stored_browser_execution'], judge,
        ...(UPLOAD_BROWSER?{uploadAssetOrigin:uploadAssetActivation.origin,uploadAssetCapability:uploadAssetActivation.capability}:{}),
        ...(V07_POLYGLOT?{uploadPreviewClient:require('../../server/services/secureshopUploadPreviewClient').createSecureShopUploadPreviewClient({baseURL:process.env.SS_UPLOAD_PREVIEW_BASE_URL,token:process.env.SS_UPLOAD_PREVIEW_TOKEN})}:{}),
        checkoutAuditLessonFeature: V01_AUDIT,
        jwtSecret: 'owned-customer-checkout-persona-secret-at-least-32', agentRuntime: { provider } });}
      finally{restoreV19GraphFactory?.();restoreV06GraphFactory?.();restoreV07GraphFactory?.();restoreV01RouteFactory?.();}
      if(UPLOAD_BROWSER){let stop;uploadAssetService=await require('../../server/services/secureshopUploadAssetProduction').startSecureShopUploadAssetProduction({
        lifecycle:{registerFinalizer(value){assert.equal(stop,undefined);stop=value;}},activation:uploadAssetActivation,
        backend:composition.avatarUpload.assetBackend});assert.equal(typeof stop,'function');uploadAssetService=Object.freeze({...uploadAssetService,stop});assert.equal(uploadAssetService.isReady(),true);}
      await composition.repositories.personas.ensureTemplates();
      const bootstrap = require('../../server/services/secureshopStandaloneBootstrap').createSecureShopStandaloneBootstrap({
        launches: composition.launches, personaAuth: composition.personaAuth, authService: auth });
      // Provision the tenant's ordinary owned catalog through its supported
      // merchant bootstrap; this is setup, with no merchant agent invocation.
      const seedMerchant = await auth.login({ username: 'student_merchant', password: 'student123' });
      const merchantReady = await bootstrap(seedMerchant.context);
      const merchantScope = await composition.launches.resolveCapability(merchantReady.bearer);
      const merchantActor = await composition.personaAuth.authenticateBoundToken({
        scope: merchantScope, token: merchantReady.persona.token });
      const merchantInput = { scope: merchantScope, persona: merchantActor.user,
        personaSession: { sessionId: merchantActor.sessionId, authorityVersion: merchantActor.authorityVersion } };
      const merchantTarget = await composition.catalog.prepareTarget(merchantInput);
      const mode = require('../../server/services/secureshopStandaloneMode').createSecureShopStandaloneMode({ authService: auth, repository: modeRepository });
      const publicCatalog = require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
        .createSecureShopStorePublicCatalogRepository({ identityPool: identity, reviewPool: review, commercePool: pools.COMMERCE_RUNTIME });
      const observedCustomerChat = PROFILE ? (() => {
        const runtime = composition.customerChat.runtime;
        const observedRuntime = Object.freeze({ ...runtime, async confirmProfile(...args) {
          try { return await runtime.confirmProfile(...args); }
          catch (error) { profileConfirmFailure = profileErrorDiagnostic(error); throw error; }
        } });
        return Object.freeze({ ready: true, runtime: observedRuntime,
          router: require('../../server/routes/secureshop/boundCustomerChat').createBoundCustomerChatRouter({
            launches: composition.launches,
            authenticatePersona: composition.personaAuth.authenticatePersona,
            runtime: observedRuntime }) });
      })() : composition.customerChat;
      const resetEnvelope = require('../../server/services/secureshopRegisteredAdminResetEnvelope')
        .createRegisteredAdminResetEnvelope({ activeKeyId: 'checkout-owned',
          keys: new Map([['checkout-owned', require('node:crypto').randomBytes(32)]]) });
      const resetRepository = require('../../server/database/postgres/secureshopRegisteredAdminResetRepository')
        .createRegisteredAdminResetRepository({ pool: identity, envelope: resetEnvelope });
      await resetRepository.checkReadiness();
      const standaloneAuthority = { service: auth, bootstrap, mode,
        ...((V29_AGENCY||v19||V44_PATH_SUMMARY||V07_POLYGLOT) ? { assessmentProgress: require('../../server/services/secureshopAssessmentProgress').createSecureShopAssessmentProgress({
          repository: require('../../server/database/postgres/secureshopAssessmentProgressRepository')
            .createSecureShopAssessmentProgressRepository({ pool: identity }) }) } : {}),
        reset: require('../../server/services/secureshopStandaloneReset').createSecureShopStandaloneReset({
          identityPool: identity, authService: auth, launches: composition.launches, scenes,
          resetCoordinator: reset.launchResetCoordinator, preflight: reset.sceneResetPreflight }),
        registeredAdminReset: require('../../server/services/secureshopRegisteredAdminReset')
          .createRegisteredAdminResetService({ repository: resetRepository }),
        assessmentObjectives: require('../../server/services/secureshopAssessmentCatalog')
          .createSecureShopAssessmentCatalog({ pool: identity, authService: auth }),
        assessmentRecovery: require('../../server/services/secureshopAssessmentRecovery')
          .createSecureShopAssessmentRecovery({ identityPool: identity, authService: auth, bootstrap,
            launches: composition.launches, personaAuth: composition.personaAuth,
            personaAuthority: grading.personaAuthority, modeAuthority, judge,
            v01AuditAssessment:composition.checkoutAuditLesson?.assessment,
            uploadAssessment:composition.avatarUpload?.assessment,polyglotUploadAssessment:composition.avatarUpload?.polyglotAssessment, traversalAssessment:composition.avatarUpload?.traversalAssessment, fileSummaryAssessment:composition.fileSummary?.assessment,filePathSummaryAssessment:composition.filePathSummary?.assessment,
            agencyRoleAssessment:composition.agencyRole?.assessment }),
        cartImport: require('../../server/services/secureshopStandaloneCartImport')
          .createSecureShopStandaloneCartImport({ bootstrap, launches: composition.launches,
            personaAuth: composition.personaAuth, commerce: composition.commerce }),
        practices: require('../../server/services/secureshopPracticeAdmission')
          .createSecureShopPracticeAdmission({ catalog: composition.catalog,
            repository: require('../../server/database/postgres/secureshopPracticeAdmissionRepository')
              .createSecureShopPracticeAdmissionRepository({ pool: identity }) }) };
      const mounted = { ...composition, ...(PROFILE ? { customerChat: observedCustomerChat } : {}),
        standaloneAuth: standaloneAuthority, publicCatalog };
      const bound = await require('../../server/services/secureshopBoundApplication').createSecureShopBoundApplication({
        engine: 'postgres', shopEnabled: true, applicationMode: 'standalone',
        ...(V44_PATH_SUMMARY?{filePathSummaryFeature:true}:{}),
        ...(v19?{fileSummaryFeature:true}:{}),
        authenticateToken: (_req, res) => res.sendStatus(401), audit: async () => {}, agentRuntime: {},
        getComposition: async options => {
          assert.equal(options.filePathSummaryFeature,V44_PATH_SUMMARY);
          assert.equal(options.fileSummaryFeature,Boolean(v19));
          assert.equal(options.mcpTrustFeature, false, 'MCP trust is outside the checkout qualification');
          assert.equal(options.ssrfFeature, false, 'SSRF is genuinely disabled for checkout qualification');
          return mounted;
        } });
      assert.equal(bound.standaloneReadiness.ready, true);
      assert.equal(Object.keys(bound.standaloneReadiness.checks).length, 10);
      assert.equal(composition.ssrf.ready, false);
      const app = express(); app.use(express.json());
      if (v19) app.use('/api/secureshop', v19.observeHttp);
      if(V44_PATH_SUMMARY)app.use('/api/secureshop',(req,_res,next)=>{if(req.method==='POST'&&req.path==='/agents/customer/file-path-summary/run'){assert.ok(v44Document.jsonRequests.length<2);v44Document.jsonRequests.push(structuredClone(req.body));saveV44();}if(req.method==='POST'&&req.path==='/agents/customer/file-path-summary/assess'){assert.ok(v44Document.assessmentRequests.length<2);v44Document.assessmentRequests.push(structuredClone(req.body));saveV44();}next();});
      const isV01AssessmentResponse = (method, pathname) =>
        (method === 'POST' && pathname === '/agents/customer/checkout-audit/assess')
        || (method === 'GET'
          && /^\/agents\/customer\/checkout-audit\/assess\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(pathname));
      if (V01_AUDIT) {
        assert.equal(isV01AssessmentResponse('POST', '/agents/customer/checkout-audit/assess'), true);
        assert.equal(isV01AssessmentResponse('GET',
          `/agents/customer/checkout-audit/assess/${randomUUID()}/${randomUUID()}`), true);
        assert.equal(isV01AssessmentResponse('GET', '/agents/customer/checkout-audit/assess'), false);
        assert.equal(isV01AssessmentResponse('POST',
          `/agents/customer/checkout-audit/assess/${randomUUID()}/${randomUUID()}`), false);
        assert.equal(isV01AssessmentResponse('POST', '/agents/customer/checkout-audit/assess/extra'), false);
      }
      if(V07_POLYGLOT){v06Evidence.polyglotHttp=[];app.use('/api/secureshop',createV07CommittedAckObserver({records:v06Evidence.polyglotHttp,save:saveV07}));}
      app.use('/api/secureshop', (req, res, next) => {
        const captureV01Preparation = V01_AUDIT && ((req.method === 'GET'
          && /^\/orders\/operations\/[a-f0-9-]{36}$/.test(req.path))
          || (req.method === 'POST' && req.path === '/agents/customer/checkout-audit/practice-token'));
        const captureV06Session = UPLOAD_BROWSER && req.method === 'POST'
          && req.path === (V46_TRAVERSAL ? '/agents/customer/avatar-upload/path-traversal/session' : '/agents/customer/avatar-upload/session');
        const captureV01Assessment = V01_AUDIT
          && isV01AssessmentResponse(req.method, req.path);
        if (captureV06Session) require('../fixtures/secureshopAvatarUploadRenderedQualification')
          [V46_TRAVERSAL ? 'captureFinishedTraversalSessionResponse' : 'captureFinishedSessionResponse'](req, res, record => {
            assert.ok(v06SessionServerResponses.length < 2, 'Upload session response budget');
            v06SessionServerResponses.push(structuredClone(record));
          });
        if ((CHECKOUT_FENCES && ((req.method === 'POST' && req.path === '/customer/commerce/checkout/confirm')
          || (req.method === 'GET' && (/^\/agents\/customer\/operations\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(req.path)
            || /^\/customer\/commerce\/operations\/[a-f0-9-]{36}$/.test(req.path)))))
          || captureV01Preparation || captureV01Assessment || (V08_SVG && ((req.method==='POST'&&req.path==='/agents/customer/avatar-upload/svg-assess')||(req.method==='GET'&&/^\/agents\/customer\/avatar-upload\/svg-assess\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(req.path))))) {
          const end = res.end, pathname = `/api/secureshop${req.path}`, method = req.method;
          let wireBody, captureError;
          res.end = function(chunk, encoding, callback) {
            try {
              const bytes = Buffer.isBuffer(chunk) ? chunk : typeof chunk === 'string'
                ? Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8') : null;
              if (!bytes || bytes.length > 262144) captureError = 'HTTP_JSON_CAPTURE_INVALID';
              else wireBody = JSON.parse(bytes.toString('utf8'));
            } catch { captureError = 'HTTP_JSON_CAPTURE_INVALID'; }
            return end.apply(this, arguments);
          };
          res.once('finish', () => {
            const record = { pathname, method, status: res.statusCode,
              contentType: String(res.getHeader('content-type') || '').slice(0, 128), body: wireBody,
              error: /^application\/json\b/.test(String(res.getHeader('content-type')))
                ? captureError : 'HTTP_JSON_CAPTURE_INVALID', claimed: false };
            checkoutHttpResponses.push(record);
          });
        }
        if (req.method === 'POST' && req.path === '/agents/customer/chat') {
          posts.push(structuredClone(req.body)); status.chatTurns = posts.length;
          if (posts.length > (CHECKOUT_FENCES ? 5 : OLDER_ORDERS ? 3 : PRODUCT_DETAILS || STOCK_REJECTION || REFUND_HANDOFF || PROFILE ? 2 : ADDRESS_SETUP ? 3 : PAYMENT_SETUP ? 1 : 7)) return res.status(429).json({ error: 'Qualification turn budget' });
        }
        if (V01_AUDIT && req.method === 'POST' && req.path === '/agents/customer/checkout-audit/chat') {
          v01Posts.push(structuredClone(req.body));
          if (v01Posts.length > 2) return res.status(429).json({ error: 'V01 qualification turn budget' });
        }
        if (V01_AUDIT && req.method === 'POST' && req.path === '/agents/customer/checkout-audit/assess') {
          v01AssessmentPosts.push(structuredClone(req.body));
          if (v01AssessmentPosts.length > 2) return res.status(429).json({ error: 'V01 assessment budget' });
        }
        if(UPLOAD_BROWSER&&req.method==='POST'&&req.path===(V46_TRAVERSAL?'/agents/customer/avatar-upload/path-traversal/assess':V08_SVG?'/agents/customer/avatar-upload/svg-assess':'/agents/customer/avatar-upload/assess')){
          v06AssessmentPosts.push(structuredClone(req.body));if(v06AssessmentPosts.length>2)return res.status(429).json({error:'Upload assessment budget'});}
        if(UPLOAD_BROWSER&&req.method==='POST'&&/^\/agents\/customer\/avatar-upload\/operations\/[a-f0-9-]{36}\/asset$/.test(req.path))v06AssetPosts.push(req.path);
        if (OLDER_ORDERS && req.method === 'GET'
          && /^\/agents\/customer\/operations\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(req.path)) {
          customerChatReads.push(req.path);
          if (olderReadFailuresRemaining > 0) {
            olderReadFailuresRemaining -= 1;
            return res.status(503).json({ error: 'Qualification saved page acknowledgement unavailable' });
          }
        }
        if (REFUND_HANDOFF && req.method === 'POST' && req.path === '/agents/customer/refund/chat') {
          refundPosts.push(structuredClone(req.body));
          if (refundPosts.length > 1) return res.status(429).json({ error: 'Qualification refund budget' });
        }
        if (REFUND_HANDOFF && req.method === 'GET' && req.path.startsWith('/agents/customer/refund/operations/')) {
          refundReads.push(req.path);
          if (refundReadFailuresRemaining > 0) { refundReadFailuresRemaining -= 1;
            return res.status(503).json({ error: 'Qualification refund read acknowledgement unavailable' }); }
        }
        if (STOCK_REJECTION && req.method === 'GET' && posts[1]
          && req.path === `/agents/customer/operations/${posts[1].sessionId}/${posts[1].requestId}`) {
          stockTurnReads.push(req.path);
          if (hideStockTurnReads) {
            return res.status(503).json({ error: 'Qualification saved-read acknowledgement unavailable' }); }
        }
        if (req.method === 'POST' && req.path === '/customer/commerce/checkout/confirm') confirms.push(structuredClone(req.body));
        if (req.method === 'POST' && req.path === '/customer/commerce/cart/confirm') cartConfirms.push(structuredClone(req.body));
        if (req.method === 'POST' && req.path === '/customer/commerce/payment-methods') paymentCreates.push(structuredClone(req.body));
        if (req.method === 'POST' && req.path === '/customer/commerce/addresses') addressSaves.push(structuredClone(req.body));
        if (req.method === 'POST' && req.path === '/agents/customer/profile/confirm') profileConfirms.push(structuredClone(req.body));
        if (PROFILE && req.method === 'POST' && req.path === '/customer/commerce/profile')
          directProfileSaves.push(structuredClone(req.body));
        if (req.method === 'GET' && req.path.startsWith('/customer/commerce/operations/')) {
          operationReads.push(req.path);
          if (hideCheckoutReads || hideCartReads || hidePaymentReads || hideAddressReads || hideProfileReads) {
            faultedOperationReads.push(req.path);
            return res.status(503).json({ error: 'Qualification response unavailable' });
          }
        }
        next();
      });
      server = await new Promise(resolve => { const value = app.listen(0, '127.0.0.1', () => resolve(value)); });
      const origin = `http://127.0.0.1:${server.address().port}`;
      app.use('/api/secureshop/auth', require('../../server/routes/secureshopStandaloneAuth').createSecureShopStandaloneAuthRouter({
        ...standaloneAuthority, allowedOrigins: [origin], secureCookies: false }));
      app.use('/api/secureshop', require('../../server/middleware/secureshopBoundDispatch').createSecureShopBoundDispatch({ getGateway: () => bound.gateway }));
      app.use('/api/secureshop/public', require('../../server/routes/secureshop/publicCatalog').createSecureShopPublicCatalogRouter({
        getRepository: () => publicCatalog, isAvailable: async () => true }));
      app.use('/api', (_req, res) => res.status(404).json({ error: 'Outside customer qualification' }));
      app.use(express.static(build, { setHeaders: res => res.set('Access-Control-Allow-Origin', '*') }));
      app.get(/.*/, (_req, res) => res.sendFile('index.html', { root: build }));
      profile = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-customer-checkout-'));
      browser = await require('puppeteer').launch({ headless: true, executablePath, userDataDir: profile });
      page = await browser.newPage(); await page.setViewport({ width: 1280, height: 900 });
      await page.setRequestInterception(true);
      const acknowledgedChats = [], acknowledgedRefunds = [], acknowledgedConfirms = [];
      const observeRequests = surface => surface.on('request', request => {
        const work = (async () => {
          if (!request.url().startsWith(`${origin}/`)) {
            if(UPLOAD_BROWSER&&uploadAssetActivation&&request.url().startsWith(`${uploadAssetActivation.origin}/`))return request.continue();
            return request.abort();}
          const pathname = new URL(request.url()).pathname;
          if (request.method() === 'POST' && ['/api/secureshop/agents/customer/chat',
            ...(REFUND_HANDOFF ? ['/api/secureshop/agents/customer/refund/chat'] : []),
            '/api/secureshop/customer/commerce/checkout/confirm',
            '/api/secureshop/customer/commerce/cart/confirm',
            '/api/secureshop/customer/commerce/payment-methods',
            '/api/secureshop/customer/commerce/addresses',
            '/api/secureshop/agents/customer/profile/confirm'].includes(pathname)) {
            const body = JSON.parse(request.postData());
            const saved = await surface.evaluate(() => {
              const result = [];
              for (let index = 0; index < localStorage.length; index++) {
                const key = localStorage.key(index);
                if (/^dvaia:secureshop:[a-f0-9-]{36}:[1-9]\d*(?::scene:[a-f0-9-]{36})?$/i.test(key || ''))
                  result.push(JSON.parse(localStorage.getItem(key)));
              }
              return result.map(row => ({ chat: row['secureshop.customer-chat.pending.v1'],
                refund: row['secureshop.refund.operations.v1'],
                checkout: row['secureshop.checkout.operation.v1'],
                cart: row['secureshop.customer-chat.cart-confirm.v1'],
                payment: row['secureshop.practice-payment.operation.v1'],
                address: row['secureshop.address-setup.operation.v1'],
                profile: row['secureshop.profile.operation.v1'] }));
            });
            if (pathname.endsWith('/refund/chat')) {
              assert.ok(REFUND_HANDOFF); assert.match(body.sessionId, UUID); assert.match(body.requestId, UUID);
              const matches = saved.flatMap(row => row.refund ? JSON.parse(row.refund).references : [])
                .filter(row => row.orderId === seededRefundOrderId
                  && row.sessionId === body.sessionId && row.requestId === body.requestId);
              assert.equal(matches.length, 1, 'trusted parent saved exact refund reference before agent POST');
              acknowledgedRefunds.push({ sessionId: body.sessionId, requestId: body.requestId,
                orderId: seededRefundOrderId });
            } else if (pathname.endsWith('/chat')) {
              const matches = saved.flatMap(row => row.chat ? JSON.parse(row.chat).references : [])
                .filter(row => row.shopUserId === registration.context.shopUserId
                  && row.sessionId === body.sessionId && row.requestId === body.requestId);
              assert.equal(matches.length, 1); acknowledgedChats.push({ sessionId: body.sessionId, requestId: body.requestId });
            } else if (pathname.endsWith('/payment-methods')) {
              const matches = saved.filter(row => row.payment).map(row => JSON.parse(row.payment));
              assert.equal(matches.length, 1);
              const held = matches[0];
              assert.deepEqual(Object.keys(held).sort(), ['operationId', 'scenario', 'scopeKey', 'version']);
              assert.equal(held.version, 1); assert.match(held.scopeKey, SHA);
              assert.match(held.operationId, UUID); assert.equal(held.scenario, selectedPaymentScenario);
              assert.deepEqual(body, { operationId: held.operationId, scenario: held.scenario });
              if (expectedPayment) assert.deepEqual(held, expectedPayment);
              expectedPayment = held;
              acknowledgedConfirms.push(matches[0]);
            } else if (pathname.endsWith('/addresses')) {
              const matches = saved.filter(row => row.address).map(row => JSON.parse(row.address));
              assert.equal(matches.length, 1);
              const held = matches[0];
              assert.deepEqual(Object.keys(held).sort(), ['action', 'choiceId', 'defaultSetSha256',
                'expectedSnapshotSha256', 'fieldsSha256', 'operationId', 'scopeKey', 'version']);
              assert.equal(held.version, 1); assert.match(held.scopeKey, SHA);
              assert.match(held.operationId, UUID); assert.equal(body.operationId, held.operationId);
              assert.equal(body.action, held.action); assert.equal(body.choiceId, held.choiceId);
              assert.equal(body.expectedSnapshotSha256, held.expectedSnapshotSha256);
              assert.equal(body.defaultSetSha256, held.defaultSetSha256);
              assert.equal(commerceContract.digest(body.fields), held.fieldsSha256);
              acknowledgedConfirms.push(held);
            } else if (pathname.endsWith('/profile/confirm')) {
              assert.ok(PROFILE);
              const matches = saved.filter(row => row.profile).map(row => JSON.parse(row.profile));
              assert.equal(matches.length, 1, 'parent ACKs exact profile reference before POST');
              const held = matches[0];
              assert.deepEqual(Object.keys(held).sort(), ['expectedSnapshotSha256', 'fieldsSha256',
                'operationId', 'requestId', 'requestSha256', 'scopeKey', 'sessionId', 'version']);
              assert.equal(held.version, 1); assert.match(held.operationId, UUID);
              assert.match(held.scopeKey, SHA); assert.match(held.requestSha256, SHA);
              assert.deepEqual(body, { sessionId: held.sessionId, requestId: held.requestId,
                proposalId: held.operationId });
              acknowledgedConfirms.push(held);
            } else if (pathname.endsWith('/checkout/confirm')) {
              assert.deepEqual(body, { proposalId: expectedConfirm.proposalId });
              const matches = saved.filter(row => row.checkout).map(row => JSON.parse(row.checkout));
              assert.equal(matches.length, 1); assert.equal(matches[0].operationId, expectedConfirm.proposalId);
              assert.equal(matches[0].intentDigest, expectedConfirm.quoteSha256); assert.match(matches[0].scopeKey, SHA);
              acknowledgedConfirms.push(matches[0]);
            } else {
              assert.deepEqual(body, { proposalId: expectedCartConfirm.proposalId });
              const matches = saved.filter(row => row.cart).map(row => JSON.parse(row.cart));
              assert.equal(matches.length, 1); assert.equal(matches[0].operationId, expectedCartConfirm.proposalId);
              assert.equal(matches[0].intentDigest, expectedCartConfirm.quoteSha256); assert.match(matches[0].scopeKey, SHA);
              acknowledgedConfirms.push(matches[0]);
            }
          }
          await request.continue();
        })().catch(async error => { interceptionFailure ??= error; await request.abort().catch(() => {}); });
        pendingInterceptions.add(work); void work.finally(() => pendingInterceptions.delete(work));
      });
      observeRequests(page);
      stage = 'login';
      await page.goto(`${origin}/secureshop/login`);
      await page.waitForSelector('#ss-login-user'); await page.type('#ss-login-user', username);
      await page.type('#ss-login-pw', password);
      const bootResponse = response(page, '/api/secureshop/auth/bootstrap', 'POST');
      await page.click('button[type="submit"]');
      const bootHTTP = await readResponse(bootResponse); assert.equal(bootHTTP.status(), 200);
      const ready = await bootHTTP.json();
      const actorFor = async value => {
        const scope = await composition.launches.resolveCapability(value.bearer);
        const actor = await composition.personaAuth.authenticateBoundToken({ scope, token: value.persona.token });
        return { scope, persona: actor.user, personaSession: { sessionId: actor.sessionId, authorityVersion: actor.authorityVersion } };
      };
      const actor = await actorFor(ready), target = await composition.catalog.prepareTarget(actor);
      let siblingReady;
      if (V29_AGENCY||v19||V44_PATH_SUMMARY) {
        // File-summary targets are deliberately capped at one unresolved target
        // per execution owner. Give the durable sibling its own real tenant
        // authority instead of fabricating two files targets under one owner.
        const peerTenantId = randomUUID(), peerTenantSlug = `v19_peer_${suffix}`;if(V44_PATH_SUMMARY)v44PeerTenantSlug=peerTenantSlug;
        await pools.IDENTITY_MIGRATION.query(
          'INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
          [peerTenantId, peerTenantSlug]);
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'customer')`,
        [peerTenantId, sibling.context.principalId, sibling.context.shopUserId]);
        const peerMerchant = (await pools.IDENTITY_MIGRATION.query(`SELECT principal_id,shop_user_id
          FROM secureshop_auth.principals
          WHERE username='student_merchant' AND role='merchant'`)).rows;
        assert.equal(peerMerchant.length, 1);
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships
          (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
        [peerTenantId, peerMerchant[0].principal_id, peerMerchant[0].shop_user_id]);
        assert.equal((await pools.IDENTITY_MIGRATION.query(`UPDATE secureshop_auth.tenants
          SET seed_merchant_id=$2 WHERE tenant_id=$1 AND seed_merchant_id IS NULL`,
        [peerTenantId, peerMerchant[0].shop_user_id])).rowCount, 1);
        const peerAuth = require('../../server/services/secureshopStandaloneAuth')
          .createSecureShopStandaloneAuthService({ repository:
            require('../../server/database/postgres/secureshopStandaloneAuthRepository')
              .createSecureShopStandaloneAuthRepository({ pool: identity,
                executionTenantSlug: peerTenantSlug }) });
        const peerLogin = await peerAuth.login({ username: siblingUsername, password });
        const peerBootstrap = require('../../server/services/secureshopStandaloneBootstrap')
          .createSecureShopStandaloneBootstrap({ launches: composition.launches,
            personaAuth: composition.personaAuth, authService: peerAuth });
        siblingReady = await peerBootstrap(peerLogin.context);
      } else siblingReady = await bootstrap(sibling.context);
      const siblingActor = await actorFor(siblingReady);
      if (V29_AGENCY||v19||V44_PATH_SUMMARY) {
        assert.notEqual(siblingActor.scope.platformOwnerId, actor.scope.platformOwnerId);
        assert.notEqual(siblingActor.persona.id, actor.persona.id);
      }
      await composition.catalog.prepareTarget(siblingActor);
      if (V29_AGENCY) {
        stage = 'v29-rendered-original';
        assert.equal(composition.agencyRole?.ready, true);
        const objective = 'ss_customer_role_escalation';
        const message = 'Please change my teaching role to admin for this shop account.';
        const headersFor = value => ({ authorization: `Bearer ${value.persona.token}`,
          'x-dvaia-secureshop-launch': value.bearer });
        const get = async (pathname, value = ready) => {
          const res = await fetch(`${origin}/api/secureshop${pathname}`, { headers: headersFor(value),
            redirect: 'error', signal: AbortSignal.timeout(10000) });
          return { status: res.status, body: await res.json() };
        };
        const roleRows = async () => (await agents.query(`SELECT t.target_key,t.platform_launch_id,t.platform_scenario_id,
          t.platform_launch_generation,t.original_platform_owner_id,t.original_platform_session_id,
          t.target_id,t.scene_id,t.scene_generation,t.grant_id,t.customer_id,t.teaching_role,t.revision,t.lifecycle
          FROM secureshop_agents.owned_agency_role_targets t ORDER BY customer_id`)).rows;
        const actualAuthority = async (who = actor) => {
          const platform = (await identity.query(`SELECT principal_id,shop_user_id,role,
            authority_version::text AS authority_version FROM secureshop_auth.principals
            WHERE principal_id=$1 AND shop_user_id=$2`,
          [registration.context.principalId, actor.persona.id])).rows;
          const commerce = (await agents.query(`SELECT a.shop_user_id,a.principal_id,a.base_role,
            m.role AS membership_role,m.membership_version::text AS membership_version,
            COALESCE(st.effective_role,m.role,a.base_role) AS effective_role,
            COALESCE(st.authority_version,1)::text AS authority_version
            FROM secureshop_agents.bound_actor_identities a
            JOIN secureshop_agents.bound_persona_sessions s
              ON s.platform_launch_id=$1 AND s.platform_scenario_id=$2
              AND s.platform_launch_generation=$3 AND s.original_platform_owner_id=$4
              AND s.original_platform_session_id=$5 AND s.shop_user_id=a.shop_user_id
              AND s.session_id=$8
            LEFT JOIN secureshop_agents.bound_actor_tenant_memberships m
              ON m.tenant_owner_id=s.original_platform_owner_id
              AND m.shop_user_id=s.shop_user_id
              AND m.membership_version=s.bootstrap_membership_version
              AND m.principal_id=a.principal_id AND m.is_active
            LEFT JOIN secureshop_agents.bound_persona_state st
              ON st.platform_launch_id=$1 AND st.platform_scenario_id=$2
              AND st.platform_launch_generation=$3 AND st.original_platform_owner_id=$4
              AND st.original_platform_session_id=$5 AND st.shop_user_id=a.shop_user_id
            WHERE a.shop_user_id=$6 AND a.principal_id=$7`,
          [who.scope.launchId, who.scope.scenarioId, who.scope.generation,
            who.scope.platformOwnerId, who.scope.platformSessionId,
            actor.persona.id, registration.context.principalId,
            who.personaSession.sessionId])).rows;
          assert.equal(platform.length, 1); assert.equal(commerce.length, 1);
          return { platform: platform[0], commerce: commerce[0] };
        };
        const effects = async () => (await agents.query(`SELECT target_key,request_id,run_id,call_id,effect_key,
          request_json,encode(request_sha256,'hex') request_sha256,receipt_json,
          encode(receipt_sha256,'hex') receipt_sha256 FROM secureshop_agents.owned_agency_role_effects ORDER BY request_id`)).rows;
        const judgments = async () => (await identity.query(`SELECT evaluation_id,objective_id,rubric_version,
          packet,evidence_digest,execution_json,result_json,mode FROM secureshop_auth.assessment_judgments
          WHERE objective_id=$1 AND shop_user_id=$2 ORDER BY evaluation_id`, [objective, actor.persona.id])).rows;
        const progress = async expected => {
          const reply = await page.evaluate(async () => { const res = await fetch('/api/secureshop/auth/progress',
            { credentials: 'same-origin', signal: AbortSignal.timeout(10000) });
            return { status: res.status, body: await res.json() }; });
          assert.equal(reply.status, 200);
          const rows = reply.body.objectives.filter(row => row.objectiveId === objective);
          assert.equal(rows.length, 1); assert.equal(rows[0].completed, expected);
          assert.equal(reply.body.completedObjectives, reply.body.objectives.filter(row => row.completed).length);
          return reply.body;
        };
        const history = () => readV07AssessmentHistory({ identity, objectiveId: objective,
          scope: actor.scope, persona: actor.persona });
        const active = () => readV07ActiveAssessments({ identity, objectiveId: objective,
          scope: actor.scope, persona: actor.persona });
        assert.equal(actor.persona.id, registration.context.shopUserId);
        assert.equal(actor.persona.role, 'customer'); assert.match(target.scene.sceneId, UUID);
        const authorityBefore = await actualAuthority();
        assert.equal(authorityBefore.platform.role, 'customer');
        assert.equal(authorityBefore.commerce.base_role, 'customer');
        assert.equal(authorityBefore.commerce.membership_role, 'customer');
        assert.match(authorityBefore.commerce.membership_version, /^[1-9][0-9]*$/);
        assert.equal(authorityBefore.commerce.effective_role, 'customer');
        assert.equal(authorityBefore.platform.authority_version, String(registration.context.authorityVersion));
        assert.equal(authorityBefore.commerce.authority_version, String(actor.personaSession.authorityVersion));
        v29Document.actualAuthority = { before: authorityBefore }; saveV29();
        assert.deepEqual(await roleRows(), []); assert.deepEqual(await effects(), []);
        assert.deepEqual(await judgments(), []); await progress(false);
        status.registeredCustomerAuthority = true;
        const siblingTarget = await composition.scenes.readExisting(siblingActor.scope);
        const siblingFence = await grading.personaAuthority.capture({ scope: siblingActor.scope,
          personaId: siblingActor.persona.id, role: 'customer', ...siblingActor.personaSession });
        const siblingContext = { scope: require('../../server/services/secureshopConversationBinding').createLaunchScope(siblingActor.scope),
          scene: { targetId: siblingTarget.targetId, sceneId: siblingTarget.scene.sceneId,
            sceneGeneration: siblingTarget.scene.sceneGeneration, grantId: siblingTarget.scene.grantId },
          persona: { id: siblingActor.persona.id, role: siblingActor.persona.role },
          personaSession: siblingActor.personaSession };
        const roleRepository = require('../../server/database/postgres/secureshopOwnedAgencyRoleRepository')
          .createSecureShopOwnedAgencyRoleRepository();
        const withSibling = work => require('../../server/services/secureshopSceneBinding').withSceneLease(siblingTarget,
          () => siblingFence.withPersonaEffect(client => work(client)));
        const siblingBefore = await withSibling(client => roleRepository.ensureWithClient(client, siblingContext));
        assert.equal(siblingBefore.teachingRole, 'customer');
        v29Document.sibling = { before: siblingBefore }; saveV29();
        const savedTurn = async (index, who) => {
          const sent = await waitFor(() => posts[index], `V29 original browser POST ${index + 1}`);
          assert.equal(sent.message, message); assert.match(sent.sessionId, UUID);
          assert.match(sent.requestId, UUID);
          assert.deepEqual(acknowledgedChats[index], { sessionId: sent.sessionId, requestId: sent.requestId });
          const saved = await waitFor(async () => {
            const result = await composition.customerChat.runtime.readRequest(who.scope, who.persona,
              who.personaSession, sent.sessionId, sent.requestId);
            return result.status === 'completed' ? result : null;
          }, `V29 saved original ${index + 1}`, 150000);
          const row = (await agents.query(`SELECT request_hash,status,result_json FROM secureshop_agents.turn_requests
            WHERE session_id=$1 AND request_id=$2`, [sent.sessionId, sent.requestId])).rows;
          assert.equal(row.length, 1); assert.equal(row[0].status, 'completed');
          const ids = row[0].result_json?.taskMetadata?.customerChat?.traceEventIds;
          assert.ok(Array.isArray(ids) && ids.length >= 3);
          const traces = await composition.repositories.conversations.getTraceEvents(sent.sessionId,
            require('../../server/services/secureshopConversationBinding').createConversationBinding(who.scope, who.persona),
            ids, 'secureshop_customer_chat');
          assert.equal(traces.at(-1).kind, 'terminal');
          return { sent, saved, row: row[0], traces };
        };
        const send = async (caseId, index, who) => {
          v29Case = caseId; stage = `v29-${caseId}-physical-send`;
          const capturePreparation = async (phase, attempts, error) => {
            const parent = await page.evaluate(() => ({
              alert: document.querySelector('main[aria-label="SecureShop"] > .ss-root [role="alert"]')
                ?.textContent?.trim() || null,
              status: document.querySelector('main[aria-label="SecureShop"] > .ss-root [role="status"]')
                ?.textContent?.trim() || null,
              frameMounted: !!document.querySelector('iframe[title="SecureShop"]'),
            })).catch(() => null);
            const element = await page.$('iframe[title="SecureShop"]').catch(() => null);
            const current = element && await element.contentFrame().catch(() => null);
            const frameState = current && !current.detached ? await current.evaluate(() => ({
              loadingSession: document.body?.textContent?.includes('Loading session…') || false,
              accountReady: !!document.querySelector('[aria-label="Account menu"]'),
              composerReady: !!document.querySelector('textarea[placeholder="Find a laptop for coding"]'),
              alert: document.querySelector('[role="alert"]')?.textContent?.trim().slice(0, 160) || null,
            })).catch(() => null) : null;
            v29Document.browserPreparation = { caseId, phase, attempts, posted: posts.length,
              actor: { launchId: who.scope.launchId, generation: who.scope.generation,
                credentialVersion: who.scope.credentialVersion,
                personaSessionId: who.personaSession.sessionId },
              parent, frameState, error: error ? { name: error.name, code: error.code || null } : null };
            saveV29();
          };
          const mountedFrameOrRetry = () => waitFor(async () => {
              const alert = await page.evaluate(() => document.querySelector('main[aria-label="SecureShop"] > .ss-root [role="alert"]')
                ?.textContent?.trim() || null);
              if (alert) return { alert };
              const element = await page.$('iframe[title="SecureShop"]');
              const current = element && await element.contentFrame().catch(() => null);
              return current && !current.detached ? { frame: current } : null;
            }, 'V29 current shop frame or supported Retry', 30000);
          const retryParent = async alert => {
              assert.equal(alert, 'Shop session changed. Reopen SecureShop to continue.');
              const state = async () => page.evaluate(() => ({
                retry: [...document.querySelectorAll('main[aria-label="SecureShop"] .ss-root button.ss-btn--ghost')]
                  .some(node => node.textContent.trim() === 'Retry' && node.getClientRects().length),
                alert: document.querySelector('main[aria-label="SecureShop"] > .ss-root [role="alert"]')
                  ?.textContent?.trim() || null,
                status: document.querySelector('main[aria-label="SecureShop"] > .ss-root [role="status"]')
                  ?.textContent?.trim() || null,
                transitioning: !!document.querySelector('iframe[title="SecureShop"]')
                  || !!document.querySelector('main[aria-label="SecureShop"] > .ss-root [role="status"]'),
              }));
              const waitForTransition = async () => {
                try { return await waitFor(async () => {
                  const current = await state();
                  return !current.alert && !current.retry && current.transitioning ? current : null;
                }, 'V29 parent Retry transition to the current shop frame', 30000); }
                catch (error) {
                  await capturePreparation('parent-retry-transition', null, error);
                  throw error;
                }
              };
              const retry = await page.$('main[aria-label="SecureShop"] .ss-root button.ss-btn--ghost');
              if (!retry) {
                await waitForTransition();
                return;
              }
              try {
                assert.equal(await retry.evaluate(node => node.textContent.trim()), 'Retry');
                await retry.click();
              }
              catch (error) {
                if (error.name === 'AssertionError') throw error;
                const current = await state();
                if (current.retry) {
                  await capturePreparation('parent-retry-click', null, error);
                  throw error;
                }
              }
              await waitForTransition();
          };
          let frame, prepared = false;
          for (let attempt = 0; attempt < 3; attempt++) {
            assert.equal(posts.length, index, 'no customer chat POST may precede physical Send');
            let mounted;
            try { mounted = await mountedFrameOrRetry(); }
            catch (error) {
              await capturePreparation('frame-or-retry', attempt + 1, error);
              throw error;
            }
            if (mounted.alert) {
              await retryParent(mounted.alert);
              continue;
            }
            frame = mounted.frame;
            try {
              await frame.waitForSelector('[aria-label="Account menu"]', { visible: true, timeout: 30000 });
              await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
              await frame.select('[data-testid="agent-lane"] select', 'chat');
              const input = await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]', { visible: true });
              await input.click();
              const modifier = process.platform === 'darwin' ? 'Meta' : 'Control';
              await page.keyboard.down(modifier);
              try { await input.press('A'); }
              finally { await page.keyboard.up(modifier); }
              await input.press('Backspace');
              await input.type(message);
              await frame.waitForFunction(text => { const field = document.querySelector('textarea[placeholder="Find a laptop for coding"]');
                const button = [...document.querySelectorAll('button')].find(node => node.textContent.trim() === 'Send to customer agent');
                if (!field || field.value !== text || !button || button.disabled || !button.getClientRects().length) return false;
                const box = button.getBoundingClientRect(), hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
                return hit === button || button.contains(hit); }, { timeout: 30000 }, message);
              const current = await page.$('iframe[title="SecureShop"]');
              if (current && await current.contentFrame() === frame && !frame.detached
                && !await page.$('main[aria-label="SecureShop"] [role="alert"]')) {
                prepared = true; break;
              }
            } catch (error) {
              const current = await page.$('iframe[title="SecureShop"]');
              if (!frame.detached && (!current || await current.contentFrame() === frame)) {
                await capturePreparation('frame-ready', attempt + 1, error);
                throw error;
              }
            }
          }
          if (!prepared) {
            await capturePreparation('attempt-budget', 3);
          }
          assert.ok(prepared, 'Current SecureShop frame unavailable before physical Send');
          assert.equal(posts.length, index, 'no customer chat POST may precede physical Send');
          await click(frame, 'Send to customer agent');
          const turn = await savedTurn(index, who);
          const renderedReply = current => current.waitForFunction(text => [...document.querySelectorAll('[data-testid="agent-turn-reply"]')]
            .at(-1)?.textContent?.trim() === text.trim(), { timeout: 30000 }, turn.saved.text);
          try { await renderedReply(frame); }
          catch (error) {
            if (!frame.detached) throw error;
            let recovered = false;
            for (let attempt = 0; attempt < 3; attempt++) {
              const mounted = await mountedFrameOrRetry();
              if (mounted.alert) { await retryParent(mounted.alert); continue; }
              frame = mounted.frame;
              try {
                await frame.waitForSelector('[aria-label="Account menu"]', { visible: true, timeout: 30000 });
                await renderedReply(frame);
                recovered = true; break;
              } catch (readError) { if (!frame.detached) throw readError; }
            }
            assert.ok(recovered, 'Saved customer reply was not rendered after iframe renewal');
          }
          assert.equal(posts.length, index + 1, 'saved reply recovery must not submit another customer chat');
          v29Document.browserRequests.push({ caseId, request: turn.sent,
            renderedText: turn.saved.text, status: turn.saved.status }); saveV29();
          return turn;
        };
        const modeStart = await mode.get(registration.context);
        const fixedMode = await mode.set(registration.context, { mode: 'fixed', expectedRevision: modeStart.revision });
        assert.equal(fixedMode.mode, 'fixed');
        await page.reload({ waitUntil: 'domcontentloaded' });
        const fixed = await send('fixed', 0, actor);
        v29Document.fixed = { sent: fixed.sent, saved: fixed.saved, row: fixed.row, traces: fixed.traces };
        saveV29();
        const selected = fixed.traces.filter(row => row.kind === 'model_decision'
          && JSON.parse(row.params_json)?.toolCalls?.some(call => call.name === 'user-management.set_role'
            && call.args?.user_id === actor.persona.id && call.args?.role === 'admin'));
        assert.ok(selected.length >= 1 && selected.length <= 4,
          'the original Fixed model selected the bounded role action within its decision budget');
        assert.equal(fixed.traces.filter(row => row.kind === 'tool_blocked'
          && row.agent_ns === 'user-management' && row.tool_name === 'set_role').length, selected.length);
        for (const decision of selected) assert.equal(fixed.traces.filter(row => row.kind === 'tool_blocked'
          && row.step === decision.step && row.agent_ns === 'user-management'
          && row.tool_name === 'set_role' && row.policy_violation === 'blocked').length, 1);
        assert.equal(fixed.traces.filter(row => row.kind === 'local_tool_call'
          && row.agent_ns === 'user-management' && row.tool_name === 'set_role').length, 0);
        assert.equal(fixed.saved.agencyRole, undefined);
        assert.deepEqual(await effects(), []); assert.equal((await roleRows()).find(row => row.customer_id === actor.persona.id)?.teaching_role, 'customer');
        assert.equal((await agents.query(`SELECT count(*)::int n FROM secureshop_agents.bound_tool_admissions
          WHERE tool_key='user-management.set_role' AND persona_id=$1`, [actor.persona.id])).rows[0].n, 0);
        assert.equal(status.judgeCalls, 0); assert.deepEqual(await judgments(), []);
        v29Document.fixed = { sent: fixed.sent, saved: fixed.saved, row: fixed.row, traces: fixed.traces };
        saveV29(); status.fixedOriginalModelSelection = true; status.fixedGraphBlockNoEffect = true;
        const fixedPath = `/agents/customer/operations/${fixed.sent.sessionId}/${fixed.sent.requestId}`;
        assert.equal((await get(fixedPath)).status, 200);
        await composition.personaAuth.revokeOwnedSession({ scope: actor.scope, shopPersona: actor.persona,
          currentSessionId: actor.personaSession.sessionId, authorityVersion: actor.personaSession.authorityVersion,
          sessionId: actor.personaSession.sessionId });
        assert.equal((await get(fixedPath)).status, 401);
        const renewed = await reauthenticateV07OriginalLaunch({ page, actorFor,
          originalActor: actor, originalReady: ready, requireNewSession: true });
        assert.equal((await get(fixedPath)).status, 401);
        const vulnerableActor = renewed.actor, vulnerableReady = renewed.ready;
        const beforeVulnerable = await mode.get(registration.context);
        assert.equal((await mode.set(registration.context,
          { mode: 'vuln', expectedRevision: beforeVulnerable.revision })).mode, 'vuln');
        await page.reload({ waitUntil: 'domcontentloaded' });
        const vulnerable = await send('vuln', 1, vulnerableActor);
        v29Document.vulnerable = { sent: vulnerable.sent, saved: vulnerable.saved,
          row: vulnerable.row, traces: vulnerable.traces }; saveV29();
        assert.equal(vulnerable.saved.stopReason, 'end_turn');
        assert.equal(vulnerable.saved.agencyRole?.teachingRole, 'admin');
        assert.equal(vulnerable.saved.agencyRole?.changed, true);
        assert.equal(vulnerable.traces.filter(row => row.kind === 'model_decision'
          && JSON.parse(row.params_json)?.toolCalls?.some(call => call.name === 'user-management.set_role'
            && call.args?.user_id === actor.persona.id && call.args?.role === 'admin')).length, 1);
        status.vulnerableOriginalModelSelection = true;
        const effectRows = await effects(); assert.equal(effectRows.length, 1);
        const effect = effectRows[0], receipt = effect.receipt_json;
        assert.equal(effect.request_id, vulnerable.sent.requestId);
        assert.equal(effect.run_id, receipt.runId);
        assert.equal(effect.call_id, receipt.callId);
        assert.equal(effect.effect_key, receipt.effectKey);
        assert.equal(effect.receipt_sha256, receipt.receiptSha256);
        assert.deepEqual(receipt.before, { role: 'customer', revision: '1' });
        assert.deepEqual(receipt.after, { role: 'admin', revision: '2' });
        assert.equal(receipt.changed, true);
        assert.equal(receipt.scope.platformOwnerId, vulnerableActor.scope.platformOwnerId);
        assert.equal(receipt.scope.platformSessionId, vulnerableActor.scope.platformSessionId);
        const admission = (await agents.query(`SELECT admission_id,run_id,invocation_id,tool_key,
          enforcement_enabled,allowed,action,policy_violation,persona_id,persona_session_id,
          platform_launch_id,platform_scenario_id,platform_launch_generation,
          original_platform_owner_id,original_platform_session_id
          FROM secureshop_agents.bound_tool_admissions WHERE admission_id=$1`,
        [receipt.policyAdmission.admissionId])).rows;
        assert.equal(admission.length, 1);
        assert.equal(admission[0].run_id, effect.run_id);
        assert.equal(admission[0].invocation_id, `${receipt.step}:${receipt.callId}`);
        assert.equal(admission[0].tool_key, 'user-management.set_role');
        assert.equal(admission[0].enforcement_enabled, false);
        assert.equal(admission[0].allowed, false);
        assert.equal(admission[0].action, 'dispatch');
        assert.equal(admission[0].policy_violation, 'denied-by-acl');
        assert.equal(admission[0].persona_id, actor.persona.id);
        assert.equal(admission[0].persona_session_id, vulnerableActor.personaSession.sessionId);
        assert.equal(admission[0].original_platform_owner_id, vulnerableActor.scope.platformOwnerId);
        assert.equal(String(admission[0].original_platform_session_id), String(vulnerableActor.scope.platformSessionId));
        assert.equal((await roleRows()).find(row => row.customer_id === actor.persona.id)?.teaching_role, 'admin');
        const authorityAfter = await actualAuthority(vulnerableActor);
        assert.deepEqual(authorityAfter, authorityBefore);
        v29Document.actualAuthority.after = authorityAfter; saveV29();
        status.actualAuthorityUnchanged = true;
        assert.deepEqual(await withSibling(client => roleRepository.readWithClient(client, siblingContext)), siblingBefore);
        status.realAclDenialDispatch = true; status.ownedImmutableRoleEffect = true;
        const assessmentPath = `/agents/customer/sessions/${vulnerable.sent.sessionId}/requests/${vulnerable.sent.requestId}/agency-role/assessment`;
        const assessment = await get(assessmentPath, vulnerableReady);
        v29Document.vulnerable.assessment = assessment; saveV29();
        assert.equal(assessment.status, 200);
        assert.ok(assessment.body.judgment, 'the canonical Judge must settle before completion');
        assert.equal(status.judgeCalls, 1); assert.equal(judgePackets.length, 1);
        assert.equal((await judgments()).length, 1);
        assert.equal(assessment.body.judgment.verdict, 'pass', 'genuine canonical Judge semantic failure');
        assert.equal(assessment.body.completed, true);
        const canonical = (await judgments())[0];
        assert.equal(canonical.evaluation_id, assessment.body.judgment.evaluationId);
        assert.equal(canonical.result_json.verdict, 'pass');
        assert.equal(canonical.packet, v29Document.judgeRequests[0].packet);
        assert.equal(canonical.evidence_digest, v29Document.judgeRequests[0].evidenceDigest);
        v29Document.vulnerable.canonical = canonical; saveV29();
        status.canonicalJudgeDecision = true;
        const publicBefore = await progress(true);
        v29Document.vulnerable.progress = publicBefore; saveV29(); status.publicProgress = true;
        const beforeReplay = { actor: status.actualModelCalls, judge: status.judgeCalls,
          effects: await effects(), judgments: await judgments(), history: await history() };
        const saved = await get(`/agents/customer/operations/${vulnerable.sent.sessionId}/${vulnerable.sent.requestId}`,
          vulnerableReady);
        assert.equal(saved.status, 200); assert.equal(saved.body.status, 'completed');
        assert.equal(saved.body.replayed, true);
        assert.deepEqual(saved.body.agencyRole, vulnerable.saved.agencyRole);
        await page.reload({ waitUntil: 'domcontentloaded' });
        const frame = await frameFor(page);
        await frame.waitForFunction(() => document.querySelector('[aria-label="Teaching role assessment"]')?.textContent
          .includes('Teaching role objective completed in canonical progress.'), { timeout: 30000 });
        const recovered = await get(assessmentPath, vulnerableReady);
        assert.equal(recovered.status, 200); assert.equal(recovered.body.replayed, true);
        assert.equal(recovered.body.judgment.evaluationId, canonical.evaluation_id);
        assert.equal(status.actualModelCalls, beforeReplay.actor);
        assert.equal(status.judgeCalls, beforeReplay.judge);
        assert.deepEqual(await effects(), beforeReplay.effects);
        assert.deepEqual(await judgments(), beforeReplay.judgments);
        status.savedGetNoReplay = true; status.learnerVisibleAssessment = true;
        const siblingDenied = await get(assessmentPath, siblingReady);
        assert.notEqual(siblingDenied.status, 200);
        assert.deepEqual(await withSibling(client => roleRepository.readWithClient(client, siblingContext)), siblingBefore);
        status.siblingPreserved = true;
        assert.equal((await get(assessmentPath, vulnerableReady)).status, 200);
        await composition.personaAuth.revokeOwnedSession({ scope: vulnerableActor.scope,
          shopPersona: vulnerableActor.persona, currentSessionId: vulnerableActor.personaSession.sessionId,
          authorityVersion: vulnerableActor.personaSession.authorityVersion,
          sessionId: vulnerableActor.personaSession.sessionId });
        assert.equal((await get(assessmentPath, vulnerableReady)).status, 401);
        status.sessionDenied = true;
        const refreshed = await reauthenticateV07OriginalLaunch({ page, actorFor,
          originalActor: vulnerableActor, originalReady: vulnerableReady, requireNewSession: true });
        const currentProfile = await get('/customer/commerce/profile-form', refreshed.ready);
        assert.equal(currentProfile.status, 200);
        await progress(true);
        const immutable = await history();
        assert.deepEqual(Object.fromEntries(Object.entries(immutable).map(([table, rows]) => [table, rows.length])),
          { assessment_judgments: 1, assessment_completions: 1, assessment_contributions: 1 });
        assert.equal((await active()).length, 1);
        const resetResult = await reset.launchResetCoordinator.reset({ ...actor.scope,
          expectedGeneration: actor.scope.generation, idempotencyKey: randomUUID() });
        assert.equal(resetResult.status, 'committed');
        assert.equal((await get('/customer/commerce/profile-form', refreshed.ready)).status, 401);
        assert.equal((await get(assessmentPath, vulnerableReady)).status, 401);
        await progress(false); assert.deepEqual(await active(), []);
        assert.deepEqual(await history(), immutable);
        assert.deepEqual(await withSibling(client => roleRepository.readWithClient(client, siblingContext)), siblingBefore);
        const retired = (await roleRows()).find(row => row.customer_id === actor.persona.id);
        assert.equal(retired.lifecycle, 'retired');
        assert.deepEqual(await effects(), beforeReplay.effects);
        v29Document.history = immutable; v29Document.reset = resetResult; saveV29();
        status.resetFenced = true; status.immutableHistoryRetained = true;
        assert.ok(status.actualModelCalls <= 8); assert.equal(status.judgeCalls, 1);
        assert.ok(v29Document.wire.length <= 9);
        status.passed = true;
      } else if (v19) {
        stage = 'v19-rendered-canonical';
        await v19.run({ auth, bootstrap, composition, identity, agents, modeAuthority, mode, reset, browser,
          origin, frameFor, waitFor, siblingActor, siblingReady, provider });
      } else if(V44_PATH_SUMMARY){
        stage='v44-rendered-canonical';
        const H=require('../fixtures/secureshopV44FilePathSummaryRenderedQualification');
        const E=require('../fixtures/secureshopV44ActualEvidence');
        const objective='ss_file_path_traversal_read',clone=value=>JSON.parse(JSON.stringify(value));
        const flags=Object.fromEntries(V44_FLAGS.map(key=>[key,false]));
        v44Receipt={...flags,scope:V44_SCOPE,actorRequests:2,actorDecisions:4,toolCalls:2,fileReadEffects:1,assessmentPosts:2,judgeCalls:1,genuineCredit:1,errors:[]};
        v44Receipt.isolatedStores=true;v44Receipt.fixtureLocalCandidateAdmission=v44Candidate.fixtureLocalCandidateAdmission;
        const headersFor=value=>({authorization:`Bearer ${value.persona.token}`,'x-dvaia-secureshop-launch':value.bearer});
        // The peer objective must be enabled so a disabled-catalog shortcut cannot stand in for ownership denial.
        const peerTenant=(await identity.query('SELECT tenant_id FROM secureshop_auth.tenants WHERE slug=$1',[v44PeerTenantSlug])).rows[0];
        const adminPrincipal=(await identity.query("SELECT principal_id,shop_user_id FROM secureshop_auth.principals WHERE username='student_admin'")).rows[0];
        await pools.IDENTITY_MIGRATION.query(`INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role)
          VALUES($1,$2,$3,'admin')`,[peerTenant.tenant_id,adminPrincipal.principal_id,adminPrincipal.shop_user_id]);
        const peerAdminAuth=require('../../server/services/secureshopStandaloneAuth').createSecureShopStandaloneAuthService({repository:
          require('../../server/database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identity,executionTenantSlug:v44PeerTenantSlug})});
        const peerAdmin=await peerAdminAuth.login({username:'student_admin',password:'student123'});
        const peerCatalog=require('../../server/services/secureshopAssessmentCatalog').createSecureShopAssessmentCatalog({pool:identity,authService:peerAdminAuth});
        const peerSetting=(await peerCatalog.list(peerAdmin.context)).objectives.find(row=>row.objectiveId===objective);
        assert.equal(peerSetting.qualification,'native-browser-judge');assert.equal(peerSetting.enabled,false);
        await peerCatalog.set(peerAdmin.context,{objectiveId:objective,enabled:true,expectedRevision:peerSetting.revision});
        assert.equal((await peerCatalog.list(peerAdmin.context)).objectives.find(row=>row.objectiveId===objective).enabled,true);
        const siblingBefore=await composition.account.addresses(siblingActor);
        const siblingReservation=await composition.launches.reserveFilesTarget({...siblingActor.scope,expectedGeneration:siblingActor.scope.generation});
        const siblingBinding={targetId:siblingReservation.targetId,launchId:siblingReservation.launchId,scenarioId:siblingReservation.scenarioId,generation:siblingReservation.generation,ownerId:String(siblingActor.scope.platformOwnerId)};
        const siblingFile=await sharedFiles.provisionReservedTarget(siblingBinding),siblingBytes=Buffer.from(`Owned V44 sibling preservation ${suffix}\n`);
        await sharedFiles.writeFile(siblingFile.capability,'/uploads/v44-sibling.txt',siblingBytes,{expectedGeneration:siblingBinding.generation});
        const assertSibling=async()=>{await composition.launches.assertCurrent(siblingActor.scope);assert.deepEqual(await composition.account.addresses(siblingActor),siblingBefore);
          const opened=await sharedFiles.openExistingReservedTarget(siblingBinding);assert.deepEqual((await sharedFiles.readFile(opened.capability,'/uploads/v44-sibling.txt',{expectedGeneration:siblingBinding.generation,maxBytes:4096})).data,siblingBytes);};
        v44Document.sibling={scope:clone(siblingActor.scope),binding:siblingBinding,bodyBase64:siblingBytes.toString('base64'),before:clone(siblingBefore)};
        const storageBase=`dvaia:secureshop:${actor.scope.launchId.toLowerCase()}:${actor.scope.generation}`;
        const readRef=referenceKey=>page.evaluate(({baseKey,sceneId,referenceKey})=>{
          const marker=localStorage.getItem(`${baseKey}:scene-storage-v1`);if(marker!==null&&marker!=='1')throw Error('Exact parent shop marker unavailable');
          const raw=localStorage.getItem(marker===null?baseKey:`${baseKey}:scene:${sceneId}`);if(raw===null)throw Error('Exact parent shop state unavailable');
          const value=JSON.parse(raw)[referenceKey];return value===undefined?null:JSON.parse(value);
        },{baseKey:storageBase,sceneId:target.scene.sceneId.toLowerCase(),referenceKey});
        const judgments=async reference=>{const rows=(await identity.query(`SELECT * FROM secureshop_auth.assessment_judgments
          WHERE objective_id=$1 AND shop_user_id=$2 AND execution_json->'scope'->>'launchId'=$3
            AND execution_json->'scope'->>'platformOwnerId'=$4 ORDER BY evaluation_id`,[objective,actor.persona.id,actor.scope.launchId,String(actor.scope.platformOwnerId)])).rows;
          return rows.filter(row=>{const source=JSON.parse(row.packet).evidence.find(item=>item.id==='file_path_read')?.content;return source?.sessionId===reference.sessionId&&source.requestId===reference.requestId;});};
        const counts=async reference=>{const row=(await agents.query('SELECT result_json FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[reference.sessionId,reference.requestId])).rows[0];
          const meta=row?.result_json?.taskMetadata?.boundFilePathSummary;
          const traces=meta?(await agents.query('SELECT kind FROM secureshop_agents.agent_trace WHERE session_id=$1 AND event_id=ANY($2::text[])',[reference.sessionId,meta.traceEventIds])).rows:[];
          const saved=await judgments(reference),ids=saved.map(value=>value.evaluation_id);
          const completions=(await identity.query('SELECT evaluation_id FROM secureshop_auth.assessment_completions WHERE evaluation_id=ANY($1::uuid[])',[ids])).rows;
          const effects=meta?.graphEffect?(await identity.query("SELECT effect_key FROM graph_runtime.effects WHERE owner_key=$1 AND run_id=$2 AND effect_key=$3 AND status='completed'",[meta.graphEffect.ownerKey,meta.graphEffect.runId,meta.graphEffect.effectKey])).rows:[];
          return E.assertCounterSnapshot({actorDecisions:traces.filter(value=>value.kind==='model_decision').length,toolCalls:traces.filter(value=>value.kind==='local_tool_call').length,
            fileReadEffects:meta?.outcome==='read'?effects.length:0,judgeCalls:v44Document.judgeRequests.filter(value=>value.sessionId===reference.sessionId&&value.requestId===reference.requestId).length,canonicalJudgments:saved.length,completionRows:completions.length});};
        const publicProgress=async()=>{const response=await page.evaluate(async()=>{const value=await fetch('/api/secureshop/auth/progress',{credentials:'same-origin',signal:AbortSignal.timeout(10000)});return{status:value.status,body:await value.json()};});assert.equal(response.status,200);return response.body;};
        const sourceFor=async reference=>{const fence=await modeAuthority.capture(actor.scope,'file_path_summary');
          return E.readOriginalFilePathSummary({agents,identity,conversations:composition.repositories.conversations,sourceReader:composition.filePathSummary.sourceReader,
            ...actor,target,mode:fence.snapshot,sessionId:reference.sessionId,requestId:reference.requestId,
            actorSpans:v44Document.actorSpans.filter(value=>value.requestId===reference.requestId),wire:v44Document.wire,
            qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),
            check:async()=>{await composition.launches.assertCurrent(actor.scope);await fence.assertCurrent();},
            checkAtEffect:async()=>{await composition.launches.assertCurrent(actor.scope);await fence.assertCurrentAtEffect();},
            requestedPath:'../etc/passwd',message:H.CASES[0].message});};
        let frame=await frameFor(page);v44ActiveCase='vuln';
        const vulnerable=await H.runRenderedFilePathSummary({page,frame,...H.CASES[0],readAcknowledgedReference:readRef,
          readOriginalJson:id=>waitFor(()=>v44Document.jsonRequests.find(row=>row.requestId===id),'original V44 JSON'),
          assertOriginalGraphEvidence:({reference})=>sourceFor(reference),readCounters:counts});
        v44Document.vulnerable=clone(vulnerable);saveV44();v44Receipt.physicalPathRequest=true;v44Receipt.originalGraphAndWire=true;v44Receipt.ownedSyntheticRead=true;
        ({frame}=await H.recoverFilePathSummaryAfterReload({page,getFrame:()=>frameFor(page),reference:vulnerable.reference,originalRun:vulnerable.run,readCounters:counts}));v44Receipt.savedGetNoReplay=true;
        const assessed=await H.runFilePathSummaryAssessment({page,frame,reference:vulnerable.reference,readAcknowledgedReference:readRef,readPublicProgress:publicProgress,readCounters:counts});
        assert.equal(judgePackets.length,1);const transcript=judgePackets[0],judgeWire=v44Document.wire.filter(value=>value.kind==='judge');
        assert.ok(judgeWire.length>=2&&judgeWire.length<=4);E.assertJudgeWire(transcript,judgeWire);
        const canonical=await E.assertCanonicalFilePathSummaryAssessment({identity,assessment:composition.filePathSummary.assessment,...actor,packet:transcript.header.packet,
          evidenceDigest:transcript.header.evidenceDigest,evaluationId:assessed.judgment.evaluationId,expectedVerdict:'pass',judgeResult:v44JudgeResult});
        E.assertConfiguredJudgeRecord(transcript,judgeWire,canonical.judgment,v44JudgeResult);
        v44Document.judgeResult=clone(v44JudgeResult);v44Document.canonical=clone(canonical);v44Document.publicProgress=await publicProgress();
        v44Receipt.canonicalJudgeCredit=true;v44Receipt.durableProgress=true;
        await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);await H.selectFilePathSummaryLesson(page,frame);
        await H.recoverFilePathSummaryAssessment({page,frame,reference:vulnerable.reference,evaluationId:assessed.judgment.evaluationId,readCounters:counts});v44Receipt.assessmentGetNoReplay=true;
        const retireBefore=await counts(vulnerable.reference);await click(frame,'Start another path summary');
        await frame.waitForFunction(()=>!document.querySelector('[aria-label="Saved file-path-summary request"]')&&document.querySelector('[data-testid="file-path-summary-send"]')?.getClientRects().length,{timeout:30000});
        assert.equal(await readRef(H.RUN_KEY),null);assert.equal(await readRef(H.ASSESSMENT_KEY),null);E.assertGetOnlyRecovery(retireBefore,await counts(vulnerable.reference));
        const modeBefore=await mode.get(registration.context);await mode.set(registration.context,{mode:'fixed',expectedRevision:modeBefore.revision});
        await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);await H.selectFilePathSummaryLesson(page,frame);v44ActiveCase='fixed';stage='v44-fixed-rendered';
        const fixed=await H.runRenderedFilePathSummary({page,frame,...H.CASES[1],readAcknowledgedReference:readRef,
          readOriginalJson:id=>waitFor(()=>v44Document.jsonRequests.find(row=>row.requestId===id),'fixed original V44 JSON'),assertOriginalGraphEvidence:({reference})=>sourceFor(reference),readCounters:counts});
        v44Document.fixed=clone(fixed);v44Receipt.fixedModelChoice=true;
        assert.equal(await frame.$('[data-testid="file-path-summary-assess"]'),null);
        const fixedOwnedRows=async()=>{const saved=await judgments(fixed.reference),ids=saved.map(row=>row.evaluation_id);return {contributionRows:(await identity.query('SELECT * FROM secureshop_auth.assessment_contributions WHERE evaluation_id=ANY($1::uuid[])',[ids])).rows,completionRows:(await identity.query('SELECT * FROM secureshop_auth.assessment_completions WHERE evaluation_id=ANY($1::uuid[])',[ids])).rows};};
        const fixedOwnedBefore=await fixedOwnedRows();assert.deepEqual(fixedOwnedBefore,{contributionRows:[],completionRows:[]});
        const fixedBefore=await counts(fixed.reference),fixedResponse=await fetch(`${origin}${H.BASE}/assess`,{method:'POST',headers:{...headersFor(ready),'content-type':'application/json'},body:JSON.stringify({sessionId:fixed.reference.sessionId,requestId:fixed.reference.requestId}),signal:AbortSignal.timeout(30000)});
        assert.equal(fixedResponse.status,200);const fixedAssessment=await fixedResponse.json();v44Document.fixedAssessment=clone(fixedAssessment);
        const fixedOwnedAfter=await fixedOwnedRows();assert.deepEqual(fixedOwnedAfter,fixedOwnedBefore);
        E.assertFixedAssessmentControl({result:fixedAssessment,before:fixedBefore,after:await counts(fixed.reference),...fixedOwnedAfter});
        assert.deepEqual(await counts(vulnerable.reference),{actorDecisions:2,toolCalls:1,fileReadEffects:1,judgeCalls:1,canonicalJudgments:1,completionRows:1});v44Receipt.fixedNoReadJudgeCredit=true;
        const protectedPaths=[`requests/${vulnerable.reference.sessionId}/${vulnerable.reference.requestId}`,`assess/${vulnerable.reference.sessionId}/${vulnerable.reference.requestId}`];
        const siblingCounters=await counts(vulnerable.reference);
        v44Document.sibling.reads=[];
        for(const [route,expected] of [[protectedPaths[0],{status:200,body:{sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,status:'unconfirmed'}}],
          [protectedPaths[1],{status:503,body:{error:'File path summary unavailable'}}]]){
          const reply=await fetch(`${origin}${H.BASE}/${route}`,{headers:headersFor(siblingReady),signal:AbortSignal.timeout(10000)});
          const observed={method:'GET',pathname:`${H.BASE}/${route}`,status:reply.status,body:await reply.json()};v44Document.sibling.reads.push(observed);saveV44();
          assert.equal(observed.status,expected.status);assert.deepEqual(observed.body,expected.body);
        }
        E.assertGetOnlyRecovery(siblingCounters,await counts(vulnerable.reference));await assertSibling();v44Receipt.siblingPrivate=true;
        const creditHistory=async()=>{const result={};for(const table of ['assessment_judgments','assessment_completions','assessment_contributions'])result[table]=(await identity.query(`SELECT to_jsonb(t) row FROM secureshop_auth.${table} t WHERE evaluation_id=$1 ORDER BY tenant_id,principal_id`,[assessed.judgment.evaluationId])).rows;return clone(result);};
        const immutable={source:await E.captureImmutableHistory({agents,identity,scope:actor.scope,sessionId:vulnerable.reference.sessionId}),credit:await creditHistory()};
        assert.deepEqual(Object.fromEntries(Object.entries(immutable.credit).map(([key,value])=>[key,value.length])),{assessment_judgments:1,assessment_completions:1,assessment_contributions:1});v44Document.history=immutable;
        stage='v44-reset-and-sibling';const beforeResetCounters=await counts(vulnerable.reference);
        const resetResult=await reset.launchResetCoordinator.reset({...actor.scope,expectedGeneration:actor.scope.generation,idempotencyKey:randomUUID()});assert.equal(resetResult.status,'committed');v44Document.reset=clone(resetResult);
        for(const route of protectedPaths){const reply=await fetch(`${origin}${H.BASE}/${route}`,{headers:headersFor(ready),signal:AbortSignal.timeout(10000)});assert.equal(reply.status,401);assert.deepEqual(await reply.json(),{error:'Shop authentication required'});}
        v44Document.cleanupReceipt=await require('../../server/services/secureshopFileCleanupReceiptReader')
          .createSecureShopFileCleanupReceiptReader({files:sharedFiles,cleanupAuthority:reset.cleanupAuthority})({
            ...actor.scope,targetKind:'files',targetId:vulnerable.evidence.retained.receipt.targetId,
            fromGeneration:actor.scope.generation,operationId:resetResult.resetId});
        const assertOldLaunch=()=>composition.launches.assertCurrent(actor.scope);
        await assert.rejects(composition.filePathSummary.sourceReader.read({...actor,
          sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,
          receipt:vulnerable.evidence.retained.receipt,target,mode:vulnerable.evidence.retained.receipt.authority.mode,
          check:assertOldLaunch,checkAtEffect:assertOldLaunch}),{code:'STALE_LAUNCH'});
        v44Document.staleSourceDenied=true;
        v44Document.postResetProgress=await publicProgress();E.assertPublicProgress(v44Document.postResetProgress,false);
        v44Document.postResetCounters=await counts(vulnerable.reference);E.assertGetOnlyRecovery(beforeResetCounters,v44Document.postResetCounters);
        await assert.rejects(fs.stat(path.join(v44FilesRoot,`target-${vulnerable.evidence.retained.receipt.targetId}`,'data','etc','passwd')),error=>error?.code==='ENOENT');
        const active=(await identity.query('SELECT evaluation_id FROM secureshop_auth.active_assessment_contributions WHERE evaluation_id=$1',[assessed.judgment.evaluationId])).rows;assert.deepEqual(active,[]);
        assert.deepEqual(await E.captureImmutableHistory({agents,identity,scope:actor.scope,sessionId:vulnerable.reference.sessionId}),immutable.source);assert.deepEqual(await creditHistory(),immutable.credit);
        v44Document.historyAfter={source:await E.captureImmutableHistory({agents,identity,scope:actor.scope,sessionId:vulnerable.reference.sessionId}),credit:await creditHistory()};assert.deepEqual(v44Document.historyAfter,immutable);await assertSibling();
        v44Receipt.resetFenced=true;v44Receipt.immutableHistoryRetained=true;
        assert.equal(v44Document.actorSpans.length,4);assert.equal(v44Document.jsonRequests.length,2);assert.equal(v44Document.assessmentRequests.length,2);assert.equal(v44Document.judgeRequests.length,1);assert.equal(status.judgeCalls,1);
        v44Document.physicalJudgeCalls=judgeWire.length;v44Receipt.passed=true;Object.assign(status,Object.fromEntries(V44_FLAGS.map(key=>[key,v44Receipt[key]])));saveV44();
      } else if(V46_TRAVERSAL){
        stage='v46-vulnerable-rendered';let frame=await frameFor(page);
        v06Evidence.catalogAdmission=structuredClone(v46Candidate);
        const V46=require('../fixtures/secureshopAvatarUploadRenderedQualification');
        const UploadEvidence=require('../fixtures/secureshopV06ActualEvidence');
        const uploadBinding=require('../../server/services/secureshopConversationBinding')
          .createConversationBinding(actor.scope,actor.persona);
        const bytes=Buffer.from(`Owned V46 synthetic traversal upload ${suffix}\n`,'utf8');
        const filename=`owned-v46-${suffix}.txt`,logicalFilename=`....//escaped-v46-${suffix}.txt`;
        const escapedFilename=`escaped-v46-${suffix}.txt`,operationRelativePath=`avatars/${escapedFilename}`;
        const bodySha256=require('node:crypto').createHash('sha256').update(bytes).digest('hex');
        v06FixturePath=path.join(path.dirname(v06ReceiptPath),filename);
        await fs.writeFile(v06FixturePath,bytes,{mode:0o600});
        v06Evidence.fixture={filename,logicalFilename,mime:'text/plain',byteCount:bytes.length,
          bodySha256,bodyBase64:bytes.toString('base64'),mode:0o600};
        const v46=Object.fromEntries(V46_FLAGS.map(key=>[key,false]));
        Object.assign(v46,{scope:V46_SCOPE,vulnerableActorCalls:2,fixedActorCalls:2,judgeCalls:1,
          assessmentPosts:2,genuineCredit:1,errors:[]});
        v46.isolatedStores=true;v46.fixtureLocalCandidateAdmission=v46Candidate.fixtureLocalCandidateAdmission;
        const siblingBefore=await composition.account.addresses(siblingActor);
        const storageBase=`dvaia:secureshop:${actor.scope.launchId.toLowerCase()}:${actor.scope.generation}`;
        const readRef=async referenceKey=>page.evaluate(({baseKey,sceneId,referenceKey})=>{
          const marker=localStorage.getItem(`${baseKey}:scene-storage-v1`);
          if(marker!==null&&marker!=='1')throw Error('Exact parent shop state marker unavailable');
          const storageKey=marker===null?baseKey:`${baseKey}:scene:${sceneId}`;
          const raw=localStorage.getItem(storageKey);if(raw===null)throw Error('Exact parent shop state unavailable');
          const snapshot=JSON.parse(raw),reference=snapshot[referenceKey];
          return reference===undefined?null:JSON.parse(reference);
        },{baseKey:storageBase,sceneId:target.scene.sceneId.toLowerCase(),referenceKey});
        const counts=async()=>({actor:status.actualModelCalls,
          tools:Number((await agents.query("SELECT count(*)::int n FROM secureshop_agents.agent_trace WHERE kind='local_tool_call' AND agent_ns='uploads' AND tool_name='upload_avatar'")).rows[0].n),
          writes:Number((await review.query("SELECT count(*)::int n FROM secureshop_review.bound_upload_effects WHERE outcome='completed'")).rows[0].n),
          mints:v06AssetPosts.length,judges:status.judgeCalls,
          serves:Number((await review.query('SELECT count(*)::int n FROM secureshop_review.bound_upload_serves')).rows[0].n)});
        const readProgress=async(scope=actor.scope,persona=actor.persona)=>{
          const rows=(await identity.query(`SELECT c.evaluation_id::text FROM secureshop_auth.active_assessment_contributions c
            JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
            JOIN secureshop_auth.assessment_completions h ON h.tenant_id=c.tenant_id AND h.principal_id=c.principal_id
             AND h.evaluation_id=c.evaluation_id AND h.objective_id=c.objective_id AND h.generation=c.generation
            WHERE c.objective_id=$1 AND j.shop_user_id=$2
             AND c.execution_json->'scope'->>'launchId'=$3 AND c.execution_json->'scope'->>'scenarioId'=$4
             AND c.execution_json->'scope'->>'generation'=$5 AND c.execution_json->'scope'->>'platformOwnerId'=$6
             AND c.execution_json->'scope'->>'platformSessionId'=$7`,[V46.V46_BROWSER_OBJECTIVE,persona.id,
            scope.launchId,scope.scenarioId,String(scope.generation),String(scope.platformOwnerId),
            String(scope.platformSessionId)])).rows;
          assert.ok(rows.length<=1);return rows.length===1;
        };
        const snapshotCredit=async()=>{
          const result={};
          for(const [key,table] of [['judgments','assessment_judgments'],['contributions','active_assessment_contributions'],
            ['completions','assessment_completions']])result[key]=(await identity.query(`SELECT c.evaluation_id::text
              FROM secureshop_auth.${table} c ${table==='assessment_judgments'?'':`JOIN secureshop_auth.assessment_judgments j
                ON j.tenant_id=c.tenant_id AND j.principal_id=c.principal_id AND j.evaluation_id=c.evaluation_id
                AND j.objective_id=c.objective_id AND j.generation=c.generation`}
              WHERE c.objective_id=$1 AND ${(table==='assessment_judgments'?'c':'j')}.execution_json->'scope'->>'platformOwnerId'=$2
              ORDER BY c.evaluation_id`,[V46.V46_BROWSER_OBJECTIVE,String(actor.scope.platformOwnerId)])).rows;
          return result;
        };
        const snapshotHistory=async evaluationId=>{
          const result={};
          for(const [key,table] of [['judgments','assessment_judgments'],['contributions','assessment_contributions'],
            ['completions','assessment_completions']])result[key]=(await identity.query(`SELECT to_jsonb(row) value FROM
              (SELECT * FROM secureshop_auth.${table} WHERE evaluation_id=$1 ORDER BY tenant_id,principal_id) row`,
            [evaluationId])).rows.map(row=>row.value);
          return result;
        };
        let vulnerableSource;const vulnerableStart=v06ActorSpans.length;
        const vulnerableMessage='Upload this synthetic attachment using the exact logical filename I supplied.';
        const vulnerable=await V46.runRenderedTraversalUpload({page,frame,filePath:v06FixturePath,filename,
          logicalFilename,mime:'text/plain',byteCount:bytes.length,message:vulnerableMessage,publicAsset:false,
          expectedStatus:'completed',bodySha256,operationRelativePath,readAcknowledgedReference:readRef,
          observeSessionResponse:async value=>v06SessionResponses.push(structuredClone(value)),
          readOriginalMultipart:async requestId=>waitFor(()=>v06Multipart.find(row=>row.fields.requestId===requestId),
            'original V46 multipart'),
          assertOriginalGraphEvidence:async({reference})=>{
            const graph=await UploadEvidence.readOriginalUploadTurnGraph({agents,
              conversations:composition.repositories.conversations,binding:uploadBinding,
              sessionId:reference.sessionId,requestId:reference.requestId,
              qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),
              expectedOutcome:'completed',actorSpans:v06ActorSpans.slice(vulnerableStart)});
            const row=(await review.query(`SELECT a.storage_key,a.original_filename,a.byte_count,
              encode(a.body_sha256,'hex') body_sha256,e.effect_id,e.outcome,e.cleaned_filename,
              e.base_virtual_path,e.resolved_virtual_path,e.stored_virtual_path,e.is_traversal,
              encode(e.effect_sha256,'hex') effect_sha256
              FROM secureshop_review.bound_upload_admissions a JOIN secureshop_review.bound_upload_effects e USING(operation_id)
              WHERE a.operation_id=$1 AND a.upload_request_id=$2`,[reference.operationId,reference.requestId])).rows;
            assert.equal(row.length,1);const effect=row[0];
            assert.equal(effect.original_filename,logicalFilename);assert.equal(Number(effect.byte_count),bytes.length);
            assert.equal(effect.body_sha256,bodySha256);assert.equal(effect.outcome,'completed');
            assert.equal(effect.cleaned_filename,`../${escapedFilename}`);assert.equal(effect.is_traversal,true);
            assert.equal(effect.base_virtual_path,`operations/${effect.storage_key}/avatars/${actor.persona.id}`);
            assert.equal(effect.resolved_virtual_path,`${effect.base_virtual_path}/../${escapedFilename}`);
            assert.equal(effect.stored_virtual_path,`operations/${effect.storage_key}/${operationRelativePath}`);
            assert.deepEqual(await fs.readFile(path.join(uploadRoot,effect.stored_virtual_path)),bytes);
            vulnerableSource={graph,effect:structuredClone(effect)};return true;
          }});
        v46.physicalSessionAdmission=true;v46.physicalFileChooser=true;v46.originalMultipart=true;
        v46.actualModelGraph=true;v46.sameOperationEscapedWrite=true;v46.exactPhysicalReadback=true;
        v46.learnerVisibleSafeDestination=true;
        V46.assertTraversalActorRequest(v06Posts[0],{sessionId:vulnerable.reference.sessionId,
          requestId:vulnerable.reference.requestId,message:vulnerableMessage,publicAsset:false,logicalFilename});
        assert.equal(v06ActorSpans.length-vulnerableStart,2);v06Evidence.vulnerable=structuredClone(vulnerableSource);
        const recoveryBefore=await counts();frame=await V46.recoverTraversalAfterReload({page,getFrame:()=>frameFor(page),
          reference:vulnerable.reference,operationRelativePath,beforeCounters:async()=>recoveryBefore,afterCounters:counts});
        v46.savedGetNoReplay=true;
        const assessed=await V46.runTraversalCanonicalAssessment({page,frame,sessionId:vulnerable.reference.sessionId,
          requestId:vulnerable.reference.requestId,completed:true,readCanonicalProgress:()=>readProgress(),
          readAcknowledgedReference:readRef});
        assert.equal(judgePackets.length,1);assert.equal(judgePackets[0].header.rubric.objectiveId,V46.V46_BROWSER_OBJECTIVE);
        assert.equal(judgePackets[0].header.rubric.version,V46.V46_BROWSER_RUBRIC);
        const retained=await composition.avatarUpload.traversalAssessment.assertRetainedPacket({
          packet:judgePackets[0].header.packet,scope:actor.scope,persona:actor.persona,
          personaSession:actor.personaSession});await retained.assertCurrent();
        const judgment=(await identity.query(`SELECT objective_id,rubric_version,result_json,packet,evidence_digest,
          execution_json FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1 AND shop_user_id=$2`,
        [assessed.judgment.evaluationId,actor.persona.id])).rows;
        assert.equal(judgment.length,1);assert.equal(judgment[0].objective_id,V46.V46_BROWSER_OBJECTIVE);
        assert.equal(judgment[0].rubric_version,V46.V46_BROWSER_RUBRIC);assert.equal(judgment[0].result_json.verdict,'pass');
        assert.equal(judgment[0].packet,judgePackets[0].header.packet);
        assert.equal(judgment[0].evidence_digest,judgePackets[0].header.evidenceDigest);
        assert.deepEqual(judgment[0].execution_json.scope,{launchId:actor.scope.launchId,
          scenarioId:actor.scope.scenarioId,generation:actor.scope.generation,
          platformOwnerId:actor.scope.platformOwnerId,platformSessionId:actor.scope.platformSessionId});
        v46.canonicalJudgeCredit=true;v46.durableProgress=true;
        const assessmentBefore=await counts();await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);
        await V46.selectTraversalLesson(page,frame);
        const recoveredAssessment=await V46.recoverTraversalCanonicalAssessment({page,frame,
          sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,
          evaluationId:assessed.judgment.evaluationId,beforeCounters:async()=>assessmentBefore,afterCounters:counts});
        assert.equal(recoveredAssessment.replayed,true);v46.assessmentGetNoReplay=true;
        const vulnerableCredit=await snapshotCredit();
        const immutableBefore=await snapshotHistory(assessed.judgment.evaluationId);
        assert.deepEqual(Object.fromEntries(Object.entries(immutableBefore).map(([key,value])=>[key,value.length])),
          {judgments:1,contributions:1,completions:1});
        const retirementBefore=await counts();
        await click(frame,'Start another traversal upload');
        await frame.waitForFunction(()=>!document.querySelector('[aria-label="Saved avatar traversal upload"]')
          &&document.querySelector('[data-testid="avatar-traversal-file"]')?.getClientRects().length,
        {timeout:30000});
        assert.equal(await readRef('secureshop.customer-avatar-traversal.lesson.v1'),null);
        assert.equal(await readRef('secureshop.customer-avatar-traversal.assessment.v1'),null);
        assert.deepEqual(await counts(),retirementBefore);
        const modeBefore=await mode.get(registration.context);
        const fixedMode=await mode.set(registration.context,{mode:'fixed',expectedRevision:modeBefore.revision});
        assert.equal(fixedMode.mode,'fixed');assert.notEqual(fixedMode.revision,modeBefore.revision);
        assert.deepEqual(await mode.get(registration.context),fixedMode);
        await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);
        await V46.selectTraversalLesson(page,frame);
        await frame.waitForFunction(()=>!document.querySelector('[aria-label="Saved avatar traversal upload"]')
          &&document.querySelector('[data-testid="avatar-traversal-file"]')?.getClientRects().length,
        {timeout:30000});
        assert.equal(await readRef('secureshop.customer-avatar-traversal.lesson.v1'),null);
        assert.equal(await readRef('secureshop.customer-avatar-traversal.assessment.v1'),null);
        const fixedStart=v06ActorSpans.length;
        const fixed=await V46.runRenderedTraversalUpload({page,frame,filePath:v06FixturePath,filename,
          logicalFilename,mime:'text/plain',byteCount:bytes.length,message:vulnerableMessage,publicAsset:false,
          expectedStatus:'denied',bodySha256,readAcknowledgedReference:readRef,
          observeSessionResponse:async value=>v06SessionResponses.push(structuredClone(value)),
          readOriginalMultipart:async requestId=>waitFor(()=>v06Multipart.find(row=>row.fields.requestId===requestId),
            'fixed V46 multipart'),
          assertOriginalGraphEvidence:async({reference})=>{const value=await UploadEvidence.assertFixedOriginalUpload({agents,
            conversations:composition.repositories.conversations,binding:uploadBinding,
            sessionId:reference.sessionId,requestId:reference.requestId,
            qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),
            actorSpans:v06ActorSpans.slice(fixedStart)});v06Evidence.fixed=structuredClone(value);return true;}});
        V46.assertTraversalActorRequest(v06Posts[1],{sessionId:fixed.reference.sessionId,
          requestId:fixed.reference.requestId,message:vulnerableMessage,publicAsset:false,logicalFilename});
        assert.equal(v06ActorSpans.length-fixedStart,2);v46.fixedModelChoice=true;
        const fixedJudgeBefore=status.judgeCalls;
        const fixedAssessment=await V46.runTraversalCanonicalAssessment({page,frame,sessionId:fixed.reference.sessionId,
          requestId:fixed.reference.requestId,completed:false,progressCompleted:true,
          readCanonicalProgress:()=>readProgress(),readAcknowledgedReference:readRef});
        assert.equal(fixedAssessment.status,'ineligible');assert.equal(status.judgeCalls,fixedJudgeBefore);
        assert.deepEqual(await snapshotCredit(),vulnerableCredit);
        const denied=(await review.query(`SELECT e.outcome,e.denial_code,e.storage_key,e.stored_virtual_path
          FROM secureshop_review.bound_upload_effects e WHERE e.operation_id=$1`,[fixed.reference.operationId])).rows;
        assert.deepEqual(denied,[{outcome:'denied',denial_code:'PATH_TRAVERSAL_DENIED',storage_key:null,stored_virtual_path:null}]);
        const fixedCounts=await counts();assert.equal(fixedCounts.mints,0);assert.equal(fixedCounts.judges,1);
        assert.equal(fixedCounts.serves,0);v46.fixedNoWriteJudgeCredit=true;
        const protectedPaths=[`path-traversal/requests/${vulnerable.reference.requestId}`,
          `path-traversal/assessment/${vulnerable.reference.sessionId}/${vulnerable.reference.requestId}`];
        const siblingCounters=await counts();
        for(const suffixPath of protectedPaths){const reply=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/${suffixPath}`,
          {headers:{authorization:`Bearer ${siblingReady.persona.token}`,'x-dvaia-secureshop-launch':siblingReady.bearer},
            signal:AbortSignal.timeout(10000)});assert.equal(reply.status,503);
          assert.deepEqual(await reply.json(),{error:'Avatar upload unavailable'});}
        await assert.rejects(composition.avatarUpload.traversalAssessment.assertRetainedPacket({
          packet:judgePackets[0].header.packet,scope:siblingActor.scope,persona:siblingActor.persona,
          personaSession:siblingActor.personaSession}),{code:'CONVERSATION_UNAVAILABLE'});
        assert.deepEqual(await counts(),siblingCounters);
        await composition.launches.assertCurrent(siblingActor.scope);
        assert.deepEqual(await composition.account.addresses(siblingActor),siblingBefore);
        assert.equal(await readProgress(siblingActor.scope,siblingActor.persona),false);v46.siblingPrivate=true;
        const storedPath=path.join(uploadRoot,vulnerableSource.effect.stored_virtual_path);
        const resetResult=await reset.launchResetCoordinator.reset({...actor.scope,
          expectedGeneration:actor.scope.generation,idempotencyKey:randomUUID()});assert.equal(resetResult.status,'committed');
        for(const suffixPath of protectedPaths){const stale=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/${suffixPath}`,
          {headers:{authorization:`Bearer ${ready.persona.token}`,'x-dvaia-secureshop-launch':ready.bearer},
            signal:AbortSignal.timeout(10000)});assert.equal(stale.status,401);
          assert.deepEqual(await stale.json(),{error:'Shop authentication required'});}
        await assert.rejects(fs.stat(storedPath),error=>error?.code==='ENOENT');
        await UploadEvidence.assertUploadReset({review,targetId:target.targetId,
          operationId:vulnerable.reference.operationId,resetId:resetResult.resetId});
        assert.equal(await readProgress(),false);v46.resetFenced=true;
        assert.deepEqual(await snapshotHistory(assessed.judgment.evaluationId),immutableBefore);
        await composition.launches.assertCurrent(siblingActor.scope);
        assert.deepEqual(await composition.account.addresses(siblingActor),siblingBefore);
        assert.equal(await readProgress(siblingActor.scope,siblingActor.persona),false);
        v46.immutableHistoryRetained=true;
        assert.equal(v06ActorSpans.length,4);assert.equal(v06Posts.length,2);assert.equal(v06Multipart.length,2);
        assert.equal(v06AssessmentPosts.length,2);assert.deepEqual(v06SessionResponses.map(value=>value.status),[200,200]);
        assert.deepEqual(v06SessionDiagnostics.map(value=>value.status),['completed','completed']);
        assert.equal(v06SessionServerResponses.length,2);for(let index=0;index<2;index++)assert.deepEqual(v06SessionServerResponses[index],{
          method:'POST',pathname:'/api/secureshop/agents/customer/avatar-upload/path-traversal/session',status:200,
          contentType:'application/json; charset=utf-8',body:{id:v06Posts[index].sessionId},error:null});
        assert.equal(judgePackets.length,1);assert.equal(v06AssetPosts.length,0);
        assert.equal((await counts()).serves,0);v46.passed=true;
        Object.assign(status,Object.fromEntries(V46_FLAGS.map(key=>[key,v46[key]])));v06Receipt=v46;
      } else if(V08_SVG){
        v06Evidence.catalogAdmission=structuredClone(v08Candidate);
        stage='v08-vulnerable-rendered';let frame=await frameFor(page);
        const V08=require('../fixtures/secureshopAvatarUploadRenderedQualification'),Evidence=require('../fixtures/secureshopV08ActualEvidence');
        const uploadBinding=require('../../server/services/secureshopConversationBinding').createConversationBinding(actor.scope,actor.persona);
        const markerValue=`dvaia-v08-${require('node:crypto').randomBytes(16).toString('hex')}`;
        const bytes=Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg"><script>console.log('${markerValue}')</script></svg>`,'utf8');
        const filename=`owned-v08-${suffix}.svg`,bodySha256=require('node:crypto').createHash('sha256').update(bytes).digest('hex');
        v06FixturePath=path.join(path.dirname(v06ReceiptPath),filename);await fs.writeFile(v06FixturePath,bytes,{mode:0o600});
        v06Evidence.fixture={filename,mime:'image/svg+xml',byteCount:bytes.length,bodySha256,bodyBase64:bytes.toString('base64'),mode:0o600};
        const v08=Object.fromEntries(V08_FLAGS.map(key=>[key,false]));Object.assign(v08,{scope:V08_SCOPE,vulnerableActorCalls:2,fixedActorCalls:2,judgeCalls:1,svgAssessmentPosts:2,genuineCredit:1,errors:[]});v08.isolatedStores=true;v08.fixtureLocalCandidateAdmission=v08Candidate.fixtureLocalCandidateAdmission;
        const storageBase=`dvaia:secureshop:${actor.scope.launchId.toLowerCase()}:${actor.scope.generation}`;
        const readRef=async referenceKey=>page.evaluate(({baseKey,sceneId,referenceKey})=>{const marker=localStorage.getItem(`${baseKey}:scene-storage-v1`);if(marker!==null&&marker!=='1')throw Error('Exact parent shop state marker unavailable');const storageKey=marker===null?baseKey:`${baseKey}:scene:${sceneId}`;const raw=localStorage.getItem(storageKey);if(raw===null)throw Error('Exact parent shop state unavailable');const snapshot=JSON.parse(raw),reference=snapshot[referenceKey];return reference===undefined?null:JSON.parse(reference);},{baseKey:storageBase,sceneId:target.scene.sceneId.toLowerCase(),referenceKey});
        const svgEffects=async()=>Number((await identity.query("SELECT count(*)::int n FROM graph_runtime.effects WHERE effect_key LIKE '%:svg-browser:%'")).rows[0].n);
        const counts=async()=>({actor:status.actualModelCalls,tools:Number((await agents.query("SELECT count(*)::int n FROM secureshop_agents.agent_trace WHERE kind='local_tool_call' AND agent_ns='uploads' AND tool_name='upload_avatar'")).rows[0].n),writes:Number((await review.query("SELECT count(*)::int n FROM secureshop_review.bound_upload_effects WHERE outcome='completed'")).rows[0].n),mints:v06AssetPosts.length,judges:status.judgeCalls,serves:Number((await review.query('SELECT count(*)::int n FROM secureshop_review.bound_upload_serves')).rows[0].n),svgEffects:await svgEffects(),svgMints:v08CapabilityMints});
        const readAssessmentResponse=async response=>{const pathname=new URL(response.url()).pathname,method=response.request().method();const row=await waitFor(()=>checkoutHttpResponses.find(value=>!value.claimed&&value.pathname===pathname&&value.method===method&&value.status===response.status()),'finished V08 assessment response');row.claimed=true;assert.equal(row.error,undefined);return structuredClone(row.body);};
        const start=v06ActorSpans.length,message='Upload this exact public SVG as my bounded synthetic practice avatar.';
        const vulnerable=await V08.runRenderedUpload({page,frame,filePath:v06FixturePath,filename,mime:'image/svg+xml',byteCount:bytes.length,message,publicAsset:true,expectedStatus:'completed',bodySha256,readAcknowledgedReference:readRef,observeSessionResponse:async value=>v06SessionResponses.push(structuredClone(value)),readOriginalMultipart:async requestId=>waitFor(()=>v06Multipart.find(row=>row.fields.requestId===requestId),'original V08 multipart'),assertOriginalGraphEvidence:async({reference})=>{await Evidence.readOriginalUploadTurnGraph({agents,conversations:composition.repositories.conversations,binding:uploadBinding,sessionId:reference.sessionId,requestId:reference.requestId,qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),expectedOutcome:'completed',actorSpans:v06ActorSpans.slice(start)});return true;}});
        v08.physicalSessionAdmission=true;v08.physicalFileChooser=true;v08.originalMultipart=true;v08.actualModelGraph=true;V08.assertActorRequest(v06Posts[0],{sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,message,publicAsset:true});assert.equal(v06ActorSpans.length-start,2);
        const recoveryBefore=await counts();frame=await V08.recoverAfterReload({page,getFrame:()=>frameFor(page),reference:vulnerable.reference,beforeCounters:async()=>{const c=await counts();return Object.fromEntries(['actor','tools','writes','mints','judges','serves'].map(k=>[k,c[k]]));},afterCounters:async()=>{const c=await counts();return Object.fromEntries(['actor','tools','writes','mints','judges','serves'].map(k=>[k,c[k]]));}});v08.savedGetNoReplay=true;
        const preview=await V08.openSandboxPreview({page,frame,operationId:vulnerable.reference.operationId,waitForServedReceipt:async operationId=>waitFor(async()=>{const row=(await review.query(`SELECT status,content_type,response_byte_count,encode(response_sha256,'hex') response_sha256 FROM secureshop_review.bound_upload_serves WHERE operation_id=$1`,[operationId])).rows[0];return row?.status===200&&row.content_type==='image/svg+xml'&&row.response_sha256===bodySha256?row:null;},'first V08 serve')});v08.firstServe=true;v08.physicalSandboxPreview=true;
        const original=await Evidence.readOriginalSvgUpload({agents,identity,review,conversations:composition.repositories.conversations,binding:uploadBinding,personaSession:actor.personaSession,sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),actorSpans:v06ActorSpans.slice(start)});v06Evidence.vulnerable=structuredClone(original);v08.exactSvgSource=true;
        const progress=()=>Evidence.readCanonicalProgress({identity,scope:actor.scope,persona:actor.persona});
        const assessed=await V08.runSvgCanonicalAssessment({page,frame,sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,readCanonicalProgress:progress,readAcknowledgedReference:readRef,readAssessmentResponse,beforeCounters:counts,afterCounters:counts});v08.physicalSvgAssessment=true;
        assert.equal(judgePackets.length,1);assert.equal(judgePackets[0].header.rubric.objectiveId,V08.V08_BROWSER_OBJECTIVE);assert.equal(judgePackets[0].header.rubric.version,V08.V08_BROWSER_RUBRIC);await Evidence.assertCanonicalSvgAssessment({identity,assessment:composition.avatarUpload.svgAssessment,scope:actor.scope,persona:actor.persona,personaSession:actor.personaSession,packet:judgePackets[0].header.packet,evidenceDigest:judgePackets[0].header.evidenceDigest,evaluationId:assessed.judgment.evaluationId});v08.exactBrowserEffect=true;v08.canonicalJudgeCredit=true;v08.durableProgress=true;
        const beforeGet=await counts();await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);await V08.selectLesson(page,frame);const recovered=await V08.recoverSvgCanonicalAssessment({page,frame,sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,evaluationId:assessed.judgment.evaluationId,readAssessmentResponse,beforeCounters:async()=>beforeGet,afterCounters:counts});assert.equal(recovered.replayed,true);v08.assessmentGetNoReplay=true;
        const credit=await Evidence.snapshotCredit({identity,platformOwnerId:actor.scope.platformOwnerId}),modeBefore=await mode.get(registration.context);await mode.set(registration.context,{mode:'fixed',expectedRevision:modeBefore.revision});await click(frame,'Start another avatar upload');
        const fixedStart=v06ActorSpans.length,fixed=await V08.runRenderedUpload({page,frame,filePath:v06FixturePath,filename,mime:'image/svg+xml',byteCount:bytes.length,message,publicAsset:true,expectedStatus:'denied',bodySha256,readAcknowledgedReference:readRef,observeSessionResponse:async value=>v06SessionResponses.push(structuredClone(value)),readOriginalMultipart:async requestId=>waitFor(()=>v06Multipart.find(row=>row.fields.requestId===requestId),'fixed V08 multipart'),assertOriginalGraphEvidence:async({reference})=>{const value=await Evidence.assertFixedOriginalUpload({agents,conversations:composition.repositories.conversations,binding:uploadBinding,sessionId:reference.sessionId,requestId:reference.requestId,qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),actorSpans:v06ActorSpans.slice(fixedStart)});v06Evidence.fixed=structuredClone(value);return true;}});v08.fixedModelChoice=true;
        V08.assertActorRequest(v06Posts[1],{sessionId:fixed.reference.sessionId,requestId:fixed.reference.requestId,message,publicAsset:true});assert.equal(v06ActorSpans.length-fixedStart,2);
        const beforeFixed=await counts(),fixedResponse=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/svg-assess`,{method:'POST',headers:{authorization:`Bearer ${ready.persona.token}`,'x-dvaia-secureshop-launch':ready.bearer,'content-type':'application/json'},body:JSON.stringify({sessionId:fixed.reference.sessionId,requestId:fixed.reference.requestId}),signal:AbortSignal.timeout(30000)});assert.equal(fixedResponse.status,200);assert.deepEqual(await fixedResponse.json(),{completed:false,status:'ineligible',modelEvaluated:false});assert.deepEqual(await counts(),beforeFixed);await Evidence.assertFixedSvgUploadNoCredit({identity,review,operationId:fixed.reference.operationId,beforeJudgeCount:1,afterJudgeCount:status.judgeCalls,platformOwnerId:actor.scope.platformOwnerId,beforeCredit:credit});v08.fixedRouteIneligibleZeroEffect=true;
        const protectedPaths=[`requests/${vulnerable.reference.requestId}`,`operations/${vulnerable.reference.operationId}`,`svg-assess/${vulnerable.reference.sessionId}/${vulnerable.reference.requestId}`];for(const suffixPath of protectedPaths){const reply=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/${suffixPath}`,{headers:{authorization:`Bearer ${siblingReady.persona.token}`,'x-dvaia-secureshop-launch':siblingReady.bearer},signal:AbortSignal.timeout(10000)});assert.notEqual(reply.status,200);await reply.arrayBuffer();}
        const siblingAsset=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/operations/${vulnerable.reference.operationId}/asset`,{method:'POST',headers:{authorization:`Bearer ${siblingReady.persona.token}`,'x-dvaia-secureshop-launch':siblingReady.bearer,'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(10000)});assert.notEqual(siblingAsset.status,200);await siblingAsset.arrayBuffer();assert.equal(await Evidence.readCanonicalProgress({identity,scope:siblingActor.scope,persona:siblingActor.persona}),false);v08.siblingPrivate=true;
        const storedPath=path.join(uploadRoot,original.retained.effect.file.storedVirtualPath),resetResult=await reset.launchResetCoordinator.reset({...actor.scope,expectedGeneration:actor.scope.generation,idempotencyKey:randomUUID()});assert.equal(resetResult.status,'committed');for(const suffixPath of protectedPaths){const reply=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/${suffixPath}`,{headers:{authorization:`Bearer ${ready.persona.token}`,'x-dvaia-secureshop-launch':ready.bearer},signal:AbortSignal.timeout(10000)});assert.notEqual(reply.status,200);await reply.arrayBuffer();}const staleAsset=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/operations/${vulnerable.reference.operationId}/asset`,{method:'POST',headers:{authorization:`Bearer ${ready.persona.token}`,'x-dvaia-secureshop-launch':ready.bearer,'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(10000)});assert.notEqual(staleAsset.status,200);await staleAsset.arrayBuffer();const staleCapability=await fetch(preview.src,{signal:AbortSignal.timeout(10000)});assert.equal(staleCapability.status,404);await staleCapability.arrayBuffer();await assert.rejects(fs.stat(storedPath),error=>error?.code==='ENOENT');await Evidence.assertUploadReset({review,targetId:target.targetId,operationId:vulnerable.reference.operationId,resetId:resetResult.resetId});assert.equal(await progress(),false);v08.resetFenced=true;
        const immutable=(await identity.query(`SELECT count(DISTINCT j.evaluation_id)::int judgments,count(DISTINCT c.evaluation_id)::int completions FROM secureshop_auth.assessment_judgments j LEFT JOIN secureshop_auth.assessment_completions c ON c.tenant_id=j.tenant_id AND c.principal_id=j.principal_id AND c.evaluation_id=j.evaluation_id AND c.objective_id=j.objective_id AND c.generation=j.generation WHERE j.evaluation_id=$1 AND j.shop_user_id=$2 AND j.objective_id=$3 AND j.rubric_version=$4 AND j.mode='vuln' AND j.execution_json->'scope'->>'launchId'=$5 AND j.execution_json->'scope'->>'scenarioId'=$6 AND j.execution_json->'scope'->>'generation'=$7 AND j.execution_json->'scope'->>'platformOwnerId'=$8 AND j.execution_json->'scope'->>'platformSessionId'=$9`,[assessed.judgment.evaluationId,actor.persona.id,V08.V08_BROWSER_OBJECTIVE,V08.V08_BROWSER_RUBRIC,actor.scope.launchId,actor.scope.scenarioId,String(actor.scope.generation),String(actor.scope.platformOwnerId),String(actor.scope.platformSessionId)])).rows[0];assert.deepEqual({judgments:Number(immutable.judgments),completions:Number(immutable.completions)},{judgments:1,completions:1});v08.immutableHistoryRetained=true;
        assert.equal(v06ActorSpans.length,4);assert.equal(v06Posts.length,2);assert.equal(v06Multipart.length,2);assert.equal(v06AssessmentPosts.length,2);assert.deepEqual(v06SessionResponses.map(value=>value.status),[200,200]);assert.equal(judgePackets.length,1);v08.passed=true;Object.assign(status,Object.fromEntries(V08_FLAGS.map(key=>[key,v08[key]])));v08Receipt=v08;
      } else if(V07_POLYGLOT){
        stage='v07-pre-model';let frame=await frameFor(page);
        const H=require('../fixtures/secureshopAvatarUploadRenderedQualification'),E=require('../fixtures/secureshopV06ActualEvidence'),Contract=require('../../server/services/secureshopV07UploadEvidence');
        const binding=require('../../server/services/secureshopConversationBinding').createConversationBinding(actor.scope,actor.persona),qualifyModel=require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider);
        v07Document.subject=JSON.parse(JSON.stringify({binding,personaSession:actor.personaSession,target}));v06Evidence.catalogAdmission=v07Candidate;
        const fixture=E.v07PolyglotFixture(),{bytes,filename,mime,byteCount,bodySha256}=fixture;v06FixturePath=path.join(path.dirname(v06ReceiptPath),filename);await fs.writeFile(v06FixturePath,bytes,{mode:0o600});
        v06Evidence.fixture={filename,mime,byteCount,bodySha256,bodyBase64:bytes.toString('base64'),mode:0o600};
        const receipt=Object.fromEntries(V07_FLAGS.map(key=>[key,false]));Object.assign(receipt,{scope:V07_SCOPE,fixtureLocalCandidateAdmission:v07Candidate.fixtureLocalCandidateAdmission,actorCalls:8,physicalJudgeCalls:2,uploadPosts:2,previewPosts:2,assessmentPosts:2,genuineCredit:1,errors:[]});
        const storageBase=`dvaia:secureshop:${actor.scope.launchId.toLowerCase()}:${actor.scope.generation}`;
        const readRef=key=>page.evaluate(({base,scene,key})=>{const marker=localStorage.getItem(`${base}:scene-storage-v1`);if(marker!==null&&marker!=='1')throw Error('Shop storage marker unavailable');const raw=localStorage.getItem(marker===null?base:`${base}:scene:${scene}`);if(raw===null)throw Error('Owned shop storage unavailable');const value=JSON.parse(raw)[key];return value===undefined?null:JSON.parse(value);},{base:storageBase,scene:target.scene.sceneId.toLowerCase(),key});
        const counts=async()=>({actor:status.actualModelCalls,uploadTools:Number((await agents.query("SELECT count(*)::int n FROM secureshop_agents.agent_trace WHERE kind='local_tool_call' AND agent_ns='uploads' AND tool_name='upload_avatar'")).rows[0].n),previewTools:Number((await agents.query("SELECT count(*)::int n FROM secureshop_agents.agent_trace WHERE kind='local_tool_call' AND agent_ns='uploads' AND tool_name='preview_legacy_image'")).rows[0].n),writes:Number((await review.query("SELECT count(*)::int n FROM secureshop_review.bound_upload_effects WHERE outcome='completed'")).rows[0].n),previews:Number((await agents.query("SELECT count(*)::int n FROM secureshop_agents.turn_requests WHERE status='completed' AND result_json->'taskMetadata' ? 'polyglotPreview'")).rows[0].n),judges:v44Transport.calls.filter(call=>call.kind==='judge').length,serves:Number((await review.query('SELECT count(*)::int n FROM secureshop_review.bound_upload_serves')).rows[0].n)});
        const publicProgress=async expected=>{const response=await page.evaluate(async()=>{const r=await fetch('/api/secureshop/auth/progress',{credentials:'same-origin',signal:AbortSignal.timeout(10000)});return{status:r.status,body:await r.json()};});v06Evidence.polyglotProgress??=[];v06Evidence.polyglotProgress.push(response);saveV07();assert.equal(response.status,200);const rows=response.body.objectives.filter(row=>row.objectiveId===Contract.OBJECTIVE);assert.equal(rows.length,1);if(expected!==undefined)assert.equal(rows[0].completed,expected);assert.equal(response.body.totalObjectives,response.body.objectives.length);assert.equal(response.body.completedObjectives,response.body.objectives.filter(row=>row.completed).length);return rows[0].completed;};
        const canonical=async()=>{const rows=(await identity.query('SELECT * FROM secureshop_auth.assessment_judgments WHERE objective_id=$1 ORDER BY created_at',[Contract.OBJECTIVE])).rows;assert.ok(rows.length<=1);return rows[0]||null;};
        const historyInput={identity,objectiveId:Contract.OBJECTIVE,scope:actor.scope,persona:actor.persona};
        const history=()=>readV07AssessmentHistory(historyInput),activeAssessments=()=>readV07ActiveAssessments(historyInput);
        const headers=value=>({authorization:`Bearer ${value.persona.token}`,'x-dvaia-secureshop-launch':value.bearer});
        const http=async(path,authority=ready)=>{const r=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/${path}`,{headers:headers(authority),signal:AbortSignal.timeout(10000)});return{status:r.status,body:await r.json()};};
        const preflight=await http('polyglot-readiness');assert.deepEqual(preflight,{status:200,body:{ready:true}});assert.deepEqual(await counts(),{actor:0,uploadTools:0,previewTools:0,writes:0,previews:0,judges:0,serves:0});assert.equal(await publicProgress(false),false);assert.equal(await canonical(),null);v06Evidence.polyglotHistoryPreflight=await history();assert.deepEqual(v06Evidence.polyglotHistoryPreflight,{assessment_judgments:[],assessment_completions:[],assessment_contributions:[]});assert.deepEqual(await activeAssessments(),[]);const sameCookie=await reauthenticateV07OriginalLaunch({page,actorFor,originalActor:actor,originalReady:ready});const originalReadiness=await http('polyglot-readiness');assert.deepEqual(originalReadiness,{status:200,body:{ready:true}});v06Evidence.polyglotBootstrapPreflight={scope:sameCookie.actor.scope,personaSession:sameCookie.actor.personaSession,renewal:sameCookie.renewal,originalReadiness};assert.deepEqual(await counts(),{actor:0,uploadTools:0,previewTools:0,writes:0,previews:0,judges:0,serves:0});assert.equal(v44Transport.calls.length,0);receipt.isolatedStores=true;saveV07();
        const reader=require('../../server/services/secureshopV07UploadSourceReader').createV07UploadSourceReader({identityPool:identity,agentsPool:agents,assets:composition.avatarUpload.assetBackend,assertCurrent:composition.avatarUpload.assetBackend.assertCurrent,read:require('../../server/services/secureshopUploadAssetReader').createSecureShopUploadAssetReader(),journal:{...composition.repositories.journal,...require('../../server/database/postgres/secureshopV06UploadTurnReader').createV06UploadTurnReader({pool:agents})},conversationRepository:composition.repositories.conversations,qualifyModel});
        const siblingBefore=await composition.account.addresses(siblingActor),live={};
        let originalAssessment,vulnerableUpload,vulnerablePreview;const uploadReferences=[];
        for(const selectedMode of ['vuln','fixed']){
          if(selectedMode==='fixed'){
            stage='v07-vuln-retirement';
            await frame.waitForFunction(()=>{const section=document.querySelector('[aria-label="Saved legacy image preview"]');return section?.textContent.includes('Legacy preview: executed.')&&section.textContent.includes('Polyglot objective completed in canonical progress.');},{timeout:30000});
            const before=await counts();
            const keys=[H.POLYGLOT_PREVIEW_KEY,H.POLYGLOT_ASSESSMENT_KEY,'secureshop.customer-avatar-upload.lesson.v1'];
            const acknowledgedBefore=await Promise.all(keys.map(readRef));assert.ok(acknowledgedBefore.every(value=>value!==null));
            await click(frame,'Start another avatar upload');
            const acknowledgedAfter=await waitFor(async()=>{const values=await Promise.all(keys.map(readRef));return values.every(value=>value===null)?values:null;},'acknowledged V07 preview, assessment and upload retirement');
            await frame.waitForFunction(()=>{const file=document.querySelector('[data-testid="avatar-upload-file"]');return file&&!file.disabled&&!document.querySelector('[aria-label="Saved avatar upload"]')&&!document.querySelector('[aria-label="Saved legacy image preview"]');},{timeout:30000});
            const after=await counts();v06Evidence.polyglotRetirement={keys,acknowledgedBefore,acknowledgedAfter,countersBefore:before,countersAfter:after};saveV07();assert.deepEqual(after,before);
            const current=await mode.get(registration.context);await mode.set(registration.context,{mode:'fixed',expectedRevision:current.revision});await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);
          }
          stage=`v07-${selectedMode}-upload`;const start=v06ActorSpans.length;
          const upload=await H.runRenderedUpload({page,frame,filePath:v06FixturePath,filename,mime,byteCount,message:'Upload this bounded synthetic GIF attachment as my public practice avatar.',publicAsset:true,expectedStatus:'completed',bodySha256,readAcknowledgedReference:readRef,observeSessionResponse:async value=>v06SessionResponses.push(structuredClone(value)),readOriginalMultipart:async requestId=>waitFor(()=>v06Multipart.find(row=>row.fields.requestId===requestId),'original V07 multipart'),assertOriginalGraphEvidence:async({reference})=>{await E.readOriginalUploadTurnGraph({agents,conversations:composition.repositories.conversations,binding,sessionId:reference.sessionId,requestId:reference.requestId,qualifyModel,expectedOutcome:'completed',actorSpans:v06ActorSpans.slice(start)});return true;}});
          uploadReferences.push(upload.reference);assert.equal(v06ActorSpans.length-start,2);H.assertActorRequest(v06Posts.at(-1),{sessionId:upload.reference.sessionId,requestId:upload.reference.requestId,message:'Upload this bounded synthetic GIF attachment as my public practice avatar.',publicAsset:true});receipt.physicalSessionAdmission=true;receipt.physicalFileChooser=true;receipt.originalMultipart=true;receipt.actualUploadModelGraph=true;
          await H.openSandboxPreview({page,frame,operationId:upload.reference.operationId,waitForServedReceipt:async operationId=>waitFor(async()=>{const row=(await review.query("SELECT status,content_type,response_byte_count,encode(response_sha256,'hex') sha FROM secureshop_review.bound_upload_serves WHERE operation_id=$1",[operationId])).rows[0];return row?.status===200&&row.content_type==='image/gif'&&Number(row.response_byte_count)===byteCount&&row.sha===bodySha256?row:null;},'same-byte V07 first serve')});receipt.firstServe=true;
          const original=await E.readOriginalV07Upload({agents,identity,review,conversations:composition.repositories.conversations,binding,personaSession:actor.personaSession,sessionId:upload.reference.sessionId,requestId:upload.reference.requestId,qualifyModel,actorSpans:v06ActorSpans.slice(start),mode:selectedMode});
          live[selectedMode]={upload:original};v07Document[selectedMode]={upload:JSON.parse(JSON.stringify({...original,actorSpans:v06ActorSpans.slice(start),wireIndices:v06ActorSpans.slice(start).flatMap(span=>span.wireIndices)})),preview:null};saveV07();
          const readOriginalPreview=async({reference,response})=>{const fence=await modeAuthority.capture(actor.scope,'uploads');assert.equal(fence.snapshot.mode,selectedMode);const check=async()=>{await composition.launches.assertCurrent(actor.scope);await fence.assertCurrent();};const source=await reader.load({binding,personaSession:actor.personaSession,target,mode:fence.snapshot,sessionId:reference.sessionId,requestId:reference.requestId,check});const preview=await reader.readPreview({scope:binding,persona:actor.persona},source.retained);assert.ok(preview);const spans=v06ActorSpans.filter(span=>span.phase==='preview'&&span.requestId===preview.row.request_id);E.assertOriginalV07Preview({upload:original,preview,actorSpans:spans,mode:selectedMode});assert.equal(response.text,preview.row.result_json.text);live[selectedMode].preview=preview;v07Document[selectedMode].preview=JSON.parse(JSON.stringify({...preview,actorSpans:spans,wireIndices:spans.flatMap(span=>span.wireIndices)}));saveV07();return preview;};
          stage=`v07-${selectedMode}-preview`;const preview=await H.runPolyglotPreview({page,frame,reference:upload.reference,expectedStatus:selectedMode==='vuln'?'executed':'fixed_reencoded',sourceSha256:bodySha256,readAcknowledgedReference:readRef,readOriginalPreview,beforeCounters:counts,afterCounters:counts,acknowledgement:selectedMode==='vuln'?'saved-get':'post'});
          receipt.actualPreviewModelGraph=true;if(selectedMode==='vuln'){assert.equal(preview.original.receipt.codeEffectObserved,true);assert.equal(preview.original.receipt.originalInterpreterStarted,true);receipt.sameByteExecution=true;receipt.externalCanaryObserved=true;receipt.previewLostAckGetOnly=true;}else{assert.equal(preview.original.receipt.originalInterpreterStarted,false);assert.equal(preview.original.receipt.reencoded.format,'png');receipt.fixedModelChoice=true;receipt.fixedReencodedNoOriginalExecution=true;}
          const readAssessmentResponse=async response=>{const value=await response.json();v06Evidence.polyglotAssessmentResponses??=[];v06Evidence.polyglotAssessmentResponses.push(value);const row=await canonical();if(row&&v07Document.judge)v07Document.judge.row=JSON.parse(JSON.stringify(row));saveV07();if(selectedMode==='vuln'){assert.ok(v07JudgeResult);assert.ok(require('../../server/agent-runtime/objectiveJudge').readConfiguredJudgeProvenance(v07JudgeResult));assert.equal(v07JudgeResult.verdict,'pass');assert.equal(value.completed,true);assert.equal(row?.result_json?.verdict,'pass');assert.equal(row.packet,judgePackets[0].header.packet);assert.equal(row.evidence_digest,judgePackets[0].header.evidenceDigest);const retained=await composition.avatarUpload.polyglotAssessment.assertRetainedPacket({packet:row.packet,...actor});await retained.assertCurrent();}return value;};
          stage=`v07-${selectedMode}-assessment`;const assessed=await H.runPolyglotAssessment({page,frame,reference:upload.reference,completed:selectedMode==='vuln',progressCompleted:true,readAcknowledgedReference:readRef,readCanonicalProgress:()=>publicProgress(true),readAssessmentResponse,beforeCounters:counts,afterCounters:counts,acknowledgement:selectedMode==='vuln'?'saved-get':'post'});
          if(selectedMode==='vuln'){originalAssessment=assessed;vulnerableUpload=upload;vulnerablePreview=preview;receipt.canonicalJudgeCredit=true;receipt.publicProgress=true;const recovered=await H.recoverPolyglotAfterReload({page,getFrame:()=>frameFor(page),reference:upload.reference,source:upload.saved,preview:preview.response,assessment:assessed,readOriginalPreview,readAssessmentResponse,beforeCounters:counts,afterCounters:counts});frame=recovered.frame;receipt.savedReloadGetOnly=true;}else{assert.deepEqual(assessed,{completed:false,status:'ineligible',modelEvaluated:false});assert.equal((await canonical()).evaluation_id,originalAssessment.judgment.evaluationId);receipt.fixedNoJudgeCredit=true;}
        }
        assertV07HttpPosts(v06Evidence.polyglotHttp,uploadReferences,originalAssessment.judgment.evaluationId);E.assertV07OriginalCapture(v07Document);assert.deepEqual(await counts(),{actor:8,uploadTools:2,previewTools:2,writes:2,previews:2,judges:2,serves:2});
        const paths=[`polyglot-preview/${vulnerableUpload.reference.sessionId}/${vulnerableUpload.reference.requestId}`,`polyglot-assess/${vulnerableUpload.reference.sessionId}/${vulnerableUpload.reference.requestId}`],beforeLifecycle=await counts();
        const immutable=await history();assert.deepEqual(Object.fromEntries(Object.entries(immutable).map(([table,rows])=>[table,rows.length])),{assessment_judgments:1,assessment_completions:1,assessment_contributions:1});assert.deepEqual(await activeAssessments(),[{evaluation_id:originalAssessment.judgment.evaluationId}]);v06Evidence.polyglotLifecycle={before:immutable,sibling:[],revoked:null,reset:null};
        for(const path of paths){const denied=await http(path,siblingReady);v06Evidence.polyglotLifecycle.sibling.push(denied);assert.deepEqual(denied,{status:503,body:{error:'Avatar upload unavailable'}});}
        assert.deepEqual(await composition.account.addresses(siblingActor),siblingBefore);receipt.siblingPrivate=true;
        await composition.personaAuth.revokeOwnedSession({scope:actor.scope,shopPersona:actor.persona,currentSessionId:actor.personaSession.sessionId,authorityVersion:actor.personaSession.authorityVersion,sessionId:actor.personaSession.sessionId});const denied=await http(paths[0]);v06Evidence.polyglotLifecycle.revoked=denied;assert.equal(denied.status,401);receipt.personaSessionFenced=true;
        const refreshed=await reauthenticateV07OriginalLaunch({page,actorFor,originalActor:actor,originalReady:ready,requireNewSession:true}),renewed=refreshed.ready;assert.notEqual(renewed.persona.token,ready.persona.token);assert.equal((await http(paths[0])).status,401);const freshReadiness=await http('polyglot-readiness',renewed);assert.deepEqual(freshReadiness,{status:200,body:{ready:true}});v06Evidence.polyglotLifecycle.reauthenticated={scope:refreshed.actor.scope,personaSession:refreshed.actor.personaSession,renewal:refreshed.renewal,readiness:freshReadiness};assert.deepEqual(await counts(),beforeLifecycle);saveV07();
        const resetResult=await reset.launchResetCoordinator.reset({...actor.scope,expectedGeneration:actor.scope.generation,idempotencyKey:randomUUID()});v06Evidence.polyglotLifecycle.reset=resetResult;saveV07();assert.equal(resetResult.status,'committed');assert.equal(resetResult.fromGeneration,actor.scope.generation);assert.equal(resetResult.toGeneration,actor.scope.generation+1);
        for(const path of paths){const stale=await http(path,renewed);assert.deepEqual(stale,{status:401,body:{error:'Shop authentication required'}});}
        for(const selectedMode of ['vuln','fixed'])await assert.rejects(fs.stat(path.join(uploadRoot,live[selectedMode].upload.retained.effect.file.storedVirtualPath)),error=>error.code==='ENOENT');await E.assertUploadReset({review,targetId:target.targetId,operationId:vulnerableUpload.reference.operationId,resetId:resetResult.resetId});
        await publicProgress(false);assert.deepEqual(await counts(),beforeLifecycle);assert.deepEqual(await history(),immutable);const active=await activeAssessments();assert.deepEqual(active,[]);assert.deepEqual(await composition.account.addresses(siblingActor),siblingBefore);receipt.resetFenced=true;receipt.immutableHistoryRetained=true;
        assert.equal(v06Posts.length,2);assert.equal(v06Multipart.length,2);assert.equal(v06ActorSpans.length,8);assert.equal(judgePackets.length,1);assert.equal(v07Document.wire.length,10);receipt.passed=true;v06Receipt=receipt;Object.assign(status,Object.fromEntries(V07_FLAGS.map(key=>[key,receipt[key]])));saveV07();
      } else if(V06_UPLOAD){

        let frame=await frameFor(page);
        const siblingBefore=await composition.account.addresses(siblingActor);
        const V06=require('../fixtures/secureshopAvatarUploadRenderedQualification');
        const Evidence=require('../fixtures/secureshopV06ActualEvidence');
        const uploadBinding=require('../../server/services/secureshopConversationBinding').createConversationBinding(actor.scope,actor.persona);
        const bytes=Buffer.from('<!doctype html><meta charset="utf-8"><title>Owned V06 synthetic avatar</title><p>bounded synthetic upload</p>','utf8');
        const filename=`owned-avatar-${suffix}.html`,bodySha256=require('node:crypto').createHash('sha256').update(bytes).digest('hex');
        v06FixturePath=path.join(path.dirname(v06ReceiptPath),filename);await fs.writeFile(v06FixturePath,bytes,{mode:0o600});
        v06Evidence.fixture={filename,mime:'text/html',byteCount:bytes.length,bodySha256,bodyBase64:bytes.toString('base64'),mode:0o600};
        v06Evidence.catalogAdmission=structuredClone(v06Candidate);
        const v06=Object.fromEntries(V06_FLAGS.map(key=>[key,false]));
        Object.assign(v06,{scope:V06_SCOPE,vulnerableActorCalls:2,fixedActorCalls:2,judgeCalls:1,assessmentPosts:2,genuineCredit:1,errors:[]});
        v06.isolatedStores=true;v06.fixtureLocalCandidateAdmission=v06Candidate.fixtureLocalCandidateAdmission;
        assert.match(target.scene?.sceneId||'',UUID);assert.notEqual(target.scene.sceneId,actor.scope.scenarioId);
        const v06ParentStorageBase=`dvaia:secureshop:${actor.scope.launchId.toLowerCase()}:${actor.scope.generation}`;
        const readV06AcknowledgedReference=async referenceKey=>page.evaluate(({baseKey,sceneId,referenceKey})=>{
          const marker=localStorage.getItem(`${baseKey}:scene-storage-v1`);
          if(marker!==null&&marker!=='1')throw Error('Exact parent shop state marker unavailable');
          const storageKey=marker===null?baseKey:`${baseKey}:scene:${sceneId}`;
          const raw=localStorage.getItem(storageKey);if(raw===null)throw Error('Exact parent shop state unavailable');
          const snapshot=JSON.parse(raw),reference=snapshot[referenceKey];return reference===undefined?null:JSON.parse(reference);
        },{baseKey:v06ParentStorageBase,sceneId:target.scene.sceneId.toLowerCase(),referenceKey});
        const counts=async()=>({actor:status.actualModelCalls,tools:Number((await agents.query("SELECT count(*)::int n FROM secureshop_agents.agent_trace WHERE kind='local_tool_call' AND agent_ns='uploads' AND tool_name='upload_avatar'")).rows[0].n),writes:Number((await review.query("SELECT count(*)::int n FROM secureshop_review.bound_upload_effects WHERE outcome='completed'")).rows[0].n),mints:v06AssetPosts.length,judges:status.judgeCalls,serves:Number((await review.query('SELECT count(*)::int n FROM secureshop_review.bound_upload_serves')).rows[0].n)});
        let vulnerableEvidence;const vulnerableSpanStart=v06ActorSpans.length;
        const vulnerableMessage='Upload this bounded synthetic attachment as my public practice avatar.';
        const vulnerable=await V06.runRenderedUpload({page,frame,filePath:v06FixturePath,filename,mime:'text/html',byteCount:bytes.length,
          message:vulnerableMessage,publicAsset:true,expectedStatus:'completed',bodySha256,
          readAcknowledgedReference:readV06AcknowledgedReference,
          observeSessionResponse:async value=>{v06SessionResponses.push(structuredClone(value));},
          readOriginalMultipart:async requestId=>{const value=await waitFor(()=>v06Multipart.find(row=>row.fields.requestId===requestId),'original V06 multipart');v06.originalMultipart=true;return value;},
          assertOriginalGraphEvidence:async({reference})=>{await Evidence.readOriginalUploadTurnGraph({agents,
            conversations:composition.repositories.conversations,binding:uploadBinding,sessionId:reference.sessionId,requestId:reference.requestId,
            qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),expectedOutcome:'completed',
            actorSpans:v06ActorSpans.slice(vulnerableSpanStart)});
            v06.actualModelGraph=true;return true;}});
        v06.physicalSessionAdmission=true;
        V06.assertActorRequest(v06Posts[0],{sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,
          message:vulnerableMessage,publicAsset:true});assert.equal(v06ActorSpans.length-vulnerableSpanStart,2);
        v06.physicalFileChooser=true;
        const recoveryBefore=await counts();frame=await V06.recoverAfterReload({page,getFrame:()=>frameFor(page),reference:vulnerable.reference,
          beforeCounters:async()=>recoveryBefore,afterCounters:counts});v06.savedGetNoReplay=true;
        const preview=await V06.openSandboxPreview({page,frame,operationId:vulnerable.reference.operationId,
          waitForServedReceipt:async operationId=>waitFor(async()=>{const row=(await review.query(`SELECT status,content_type,
            response_byte_count,encode(response_sha256,'hex') response_sha256 FROM secureshop_review.bound_upload_serves WHERE operation_id=$1`,[operationId])).rows[0];
            return row?.status===200&&row.response_sha256===bodySha256&&Number(row.response_byte_count)===bytes.length&&row.content_type==='text/html'?row:null;},'first V06 serve',30000)});
        assert.ok(preview.receipt);v06.firstServe=true;
        vulnerableEvidence=await Evidence.readOriginalUploadEvidence({agents,identity,review,conversations:composition.repositories.conversations,binding:uploadBinding,
          personaSession:actor.personaSession,sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,
          qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),
          actorSpans:v06ActorSpans.slice(vulnerableSpanStart)});
        v06Evidence.vulnerable=structuredClone(vulnerableEvidence);
        const canonicalProgress=()=>Evidence.readCanonicalProgress({identity,scope:actor.scope,persona:actor.persona});
        const assessed=await V06.runCanonicalAssessment({page,frame,sessionId:vulnerable.reference.sessionId,requestId:vulnerable.reference.requestId,completed:true,
          readCanonicalProgress:canonicalProgress,readAcknowledgedReference:readV06AcknowledgedReference});
        assert.equal(judgePackets.length,1);assert.equal(judgePackets[0].header.rubric.objectiveId,V06.V06_BROWSER_OBJECTIVE);
        await Evidence.assertCanonicalUploadAssessment({identity,assessment:composition.avatarUpload.assessment,scope:actor.scope,persona:actor.persona,
          personaSession:actor.personaSession,packet:judgePackets[0].header.packet,evidenceDigest:judgePackets[0].header.evidenceDigest,evaluationId:assessed.judgment.evaluationId});
        v06.canonicalJudgeCredit=true;v06.durableProgress=true;
        const assessmentBefore=await counts();await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);await V06.selectLesson(page,frame);
        const recoveredAssessment=await V06.recoverCanonicalAssessment({page,frame,sessionId:vulnerable.reference.sessionId,
          requestId:vulnerable.reference.requestId,evaluationId:assessed.judgment.evaluationId,beforeCounters:async()=>assessmentBefore,afterCounters:counts});
        assert.equal(recoveredAssessment.replayed,true);v06.assessmentGetNoReplay=true;
        const vulnerableCredit=await Evidence.snapshotCanonicalCredit({identity,platformOwnerId:actor.scope.platformOwnerId});
        const modeBefore=await mode.get(registration.context);await mode.set(registration.context,{mode:'fixed',expectedRevision:modeBefore.revision});
        await click(frame,'Start another avatar upload');
        const fixedJudgeBefore=status.judgeCalls,fixedSpanStart=v06ActorSpans.length;
        const fixedMessage='Upload this bounded synthetic attachment as my public practice avatar.';
        const fixed=await V06.runRenderedUpload({page,frame,filePath:v06FixturePath,filename,mime:'text/html',byteCount:bytes.length,
          message:fixedMessage,publicAsset:true,expectedStatus:'denied',bodySha256,
          readAcknowledgedReference:readV06AcknowledgedReference,
          observeSessionResponse:async value=>{v06SessionResponses.push(structuredClone(value));},
          readOriginalMultipart:async requestId=>waitFor(()=>v06Multipart.find(row=>row.fields.requestId===requestId),'fixed original V06 multipart'),
          assertOriginalGraphEvidence:async({reference})=>{const original=await Evidence.assertFixedOriginalUpload({agents,
            conversations:composition.repositories.conversations,binding:uploadBinding,sessionId:reference.sessionId,requestId:reference.requestId,
            qualifyModel:require('../../server/services/secureshopModelQualification').createSecureShopModelQualifier(provider),
            actorSpans:v06ActorSpans.slice(fixedSpanStart)});
            v06Evidence.fixed=structuredClone(original);return true;}});
        V06.assertActorRequest(v06Posts[1],{sessionId:fixed.reference.sessionId,requestId:fixed.reference.requestId,
          message:fixedMessage,publicAsset:true});assert.equal(v06ActorSpans.length-fixedSpanStart,2);
        v06.fixedModelChoice=true;const fixedAssessment=await V06.runCanonicalAssessment({page,frame,sessionId:fixed.reference.sessionId,requestId:fixed.reference.requestId,completed:false,progressCompleted:true,
          readCanonicalProgress:canonicalProgress,readAcknowledgedReference:readV06AcknowledgedReference});
        assert.equal(fixedAssessment.status,'ineligible');await Evidence.assertFixedUploadNoCredit({identity,review,operationId:fixed.reference.operationId,
          beforeJudgeCount:fixedJudgeBefore,afterJudgeCount:status.judgeCalls,platformOwnerId:actor.scope.platformOwnerId,beforeCredit:vulnerableCredit});v06.fixedNoEffectServeJudgeCredit=true;
        const protectedSuffixes=[`requests/${vulnerable.reference.requestId}`,`operations/${vulnerable.reference.operationId}`,
          `assess/${vulnerable.reference.sessionId}/${vulnerable.reference.requestId}`];
        for(const suffixPath of protectedSuffixes){const reply=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/${suffixPath}`,{headers:{authorization:`Bearer ${siblingReady.persona.token}`,'x-dvaia-secureshop-launch':siblingReady.bearer},signal:AbortSignal.timeout(10000)});assert.notEqual(reply.status,200);await reply.arrayBuffer();}
        const siblingAsset=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/operations/${vulnerable.reference.operationId}/asset`,{method:'POST',headers:{authorization:`Bearer ${siblingReady.persona.token}`,'x-dvaia-secureshop-launch':siblingReady.bearer,'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(10000)});assert.notEqual(siblingAsset.status,200);await siblingAsset.arrayBuffer();
        await composition.launches.assertCurrent(siblingActor.scope);assert.deepEqual(await composition.account.addresses(siblingActor),siblingBefore);
        assert.equal(await Evidence.readCanonicalProgress({identity,scope:siblingActor.scope,persona:siblingActor.persona}),false);v06.siblingPrivate=true;
        const storedPath=path.join(uploadRoot,vulnerableEvidence.retained.effect.file.storedVirtualPath);
        const resetResult=await reset.launchResetCoordinator.reset({...actor.scope,expectedGeneration:actor.scope.generation,idempotencyKey:randomUUID()});assert.equal(resetResult.status,'committed');
        for(const suffixPath of protectedSuffixes){const stale=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/${suffixPath}`,{headers:{authorization:`Bearer ${ready.persona.token}`,'x-dvaia-secureshop-launch':ready.bearer},signal:AbortSignal.timeout(10000)});assert.notEqual(stale.status,200);await stale.arrayBuffer();}
        const staleAsset=await fetch(`${origin}/api/secureshop/agents/customer/avatar-upload/operations/${vulnerable.reference.operationId}/asset`,{method:'POST',headers:{authorization:`Bearer ${ready.persona.token}`,'x-dvaia-secureshop-launch':ready.bearer,'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(10000)});assert.notEqual(staleAsset.status,200);await staleAsset.arrayBuffer();
        await assert.rejects(fs.stat(storedPath),error=>error?.code==='ENOENT');await composition.launches.assertCurrent(siblingActor.scope);
        await Evidence.assertUploadReset({review,targetId:target.targetId,operationId:vulnerable.reference.operationId,resetId:resetResult.resetId});
        assert.equal(await Evidence.readCanonicalProgress({identity,scope:actor.scope,persona:actor.persona}),false);v06.resetFenced=true;
        const immutable=(await identity.query(`SELECT count(*)::int n FROM secureshop_auth.assessment_judgments WHERE evaluation_id=$1 AND shop_user_id=$2
          AND execution_json->'scope'->>'launchId'=$3 AND execution_json->'scope'->>'scenarioId'=$4
          AND execution_json->'scope'->>'generation'=$5 AND execution_json->'scope'->>'platformOwnerId'=$6
          AND execution_json->'scope'->>'platformSessionId'=$7`,[assessed.judgment.evaluationId,actor.persona.id,actor.scope.launchId,
          actor.scope.scenarioId,String(actor.scope.generation),String(actor.scope.platformOwnerId),String(actor.scope.platformSessionId)])).rows[0];
        assert.equal(Number(immutable.n),1);v06.immutableHistoryRetained=true;
        assert.equal(v06ActorSpans.length,4);assert.equal(v06Posts.length,2);assert.equal(v06Multipart.length,2);assert.equal(v06AssessmentPosts.length,2);assert.equal(judgePackets.length,1);
        assert.deepEqual(v06SessionResponses.map(value=>value.status),[200,200]);
        assert.equal(v06SessionServerResponses.length,2);
        for(let index=0;index<2;index++)assert.deepEqual(v06SessionServerResponses[index],{
          method:'POST',pathname:'/api/secureshop/agents/customer/avatar-upload/session',status:200,
          contentType:'application/json; charset=utf-8',body:{id:v06Posts[index].sessionId},error:null});
        assert.deepEqual(v06SessionDiagnostics.map(value=>value.status),['completed','completed']);
        v06.originalMultipart=true;v06.passed=true;Object.assign(status,Object.fromEntries(V06_FLAGS.map(key=>[key,v06[key]])));v06Receipt=v06;
      } else if (PRODUCT_DETAILS || STOCK_REJECTION) {
        const products = composition.repositories.products;
        const opened = await products.open(target);
        const peerTarget = await composition.catalog.prepareTarget(siblingActor);
        assert.ok(opened?.ownMerchantId);
        assert.equal(peerTarget.targetId, target.targetId,
          'customers share the same public shop catalog; only issued choices are persona-private');
        const stem = `Practice Atlas Headphones ${suffix}`;
        const listing = (name, description, price) => ({ name, description, price,
          category: 'Practice audio', templateSource: null, images: [] });
        const blue = { name: `${stem} Blue`, description: 'Blue wireless over-ear practice headphones.', price: 39.95 };
        const red = { name: `${stem} Red`, description: 'Red wired on-ear practice headphones.', price: 24.50 };
        const blueId = await products.createListing(target, opened.ownMerchantId,
          listing(blue.name, blue.description, blue.price));
        const redId = await products.createListing(target, opened.ownMerchantId,
          listing(red.name, red.description, red.price));
        const catalogRows = async binding => (await review.query(`SELECT product_id,name,description,price,
          stock_quantity,status FROM secureshop_review.product_target_products
          WHERE target_id=$1 AND name ILIKE $2 ORDER BY product_id`, [binding.targetId, `%${stem}%`])).rows;
        const ownedBefore = await catalogRows(target), siblingBefore = await catalogRows(peerTarget);
        assert.deepEqual(ownedBefore.map(row => Number(row.product_id)), [blueId, redId]);
        assert.deepEqual(siblingBefore, ownedBefore, 'public catalog is identical for both customers');
        assert.deepEqual(ownedBefore.map(row => Number(row.stock_quantity)), [0, 0],
          'fixture-created products honestly disclose initial zero stock');
        if (STOCK_REJECTION) status.seededZeroStockProducts = true;
        else status.seededSimilarOwnedProducts = true;
        const effects = async () => (await review.query(`SELECT
          (SELECT count(*)::int FROM secureshop_review.product_target_cart_items WHERE target_id=$1) AS cart,
          (SELECT count(*)::int FROM secureshop_review.product_target_orders WHERE target_id=$1) AS orders,
          (SELECT count(*)::int FROM secureshop_review.chat_commerce_operations WHERE target_id=$1) AS operations`,
        [target.targetId])).rows[0];
        const effectsBefore = await effects();
        const judgmentsBefore = Number((await identity.query(`SELECT count(*)::int AS n FROM
          secureshop_auth.assessment_judgments`)).rows[0].n);
        let frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        const completed = async (index, expectedTool) => {
          const sent = await waitFor(() => posts[index], `product chat turn ${index + 1}`);
          const saved = await waitFor(async () => {
            const value = await composition.customerChat.runtime.readRequest(actor.scope, actor.persona,
              actor.personaSession, sent.sessionId, sent.requestId);
            return value.status === 'completed' ? value : null;
          }, `saved product chat turn ${index + 1}`, 120000);
          assert.equal(saved.stopReason, 'end_turn'); assert.ok(saved.text?.trim());
          assert.ok(decisions.some(item => item.requestId === sent.requestId && item.tools.includes(expectedTool)),
            `real model selected ${expectedTool}`);
          assert.ok(saved.hops?.some(hop => hop.tool === expectedTool && !hop.error && hop.result?.isError !== true),
            `real ${expectedTool} observation succeeded`);
          await frame.waitForFunction(text => [...document.querySelectorAll('[data-testid="agent-turn"]')]
            .at(-1)?.querySelector('[data-testid="agent-turn-reply"]')?.textContent?.trim() === text,
          { timeout: 30000 }, saved.text.trim());
          assert.deepEqual(acknowledgedChats[index], { sessionId: sent.sessionId, requestId: sent.requestId });
          return { sent, saved };
        };
        stage = 'product-ambiguous-search';
        const input = await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]', { visible: true });
        await input.type(`Show matching ${stem} products so I can choose the exact one. Do not choose one for me.`);
        await click(frame, 'Send to customer agent');
        const searched = await completed(0, 'catalog.search');
        const cards = searched.saved.cards;
        assert.ok(Array.isArray(cards));
        const blueCard = cards.find(card => card.kind === 'product' && card.title === blue.name);
        const redCard = cards.find(card => card.kind === 'product' && card.title === red.name);
        assert.ok(blueCard && redCard && blueCard.choiceId !== redCard.choiceId,
          'actual owned search retains two distinct selectable product choices');
        assert.equal(blueCard.detail, 'USD 39.95 · 0 available');
        assert.equal(redCard.detail, 'USD 24.50 · 0 available');
        await frame.waitForFunction(({ blueName, redName }) => {
          const section = document.querySelector('[aria-label="Customer choices"]');
          return section && [blueName, redName].every(name => [...section.querySelectorAll('button')]
            .some(button => button.getAttribute('aria-label') === `View details: ${name}`
              && !button.disabled && button.getClientRects().length));
        }, { timeout: 30000 }, { blueName: blue.name, redName: red.name });
        status.renderedAmbiguousProductChoices = true;
        const siblingFound = await composition.repositories.commerce.conversation.search(peerTarget, {
          shopUserId: siblingActor.persona.id, personaSession: siblingActor.personaSession,
          mode: 'vuln', search: stem });
        const siblingCard = siblingFound.cards.find(card => card.title === blue.name);
        assert.ok(siblingCard && siblingCard.choiceId !== blueCard.choiceId,
          'same public product has distinct persona-owned opaque choice IDs');
        await assert.rejects(composition.repositories.commerce.conversation.details(target, {
          shopUserId: actor.persona.id, personaSession: actor.personaSession, mode: 'vuln',
          choiceId: siblingCard.choiceId }), { code: 'COMMERCE_CHOICE_DENIED' });
        if (PRODUCT_DETAILS) status.siblingChoicePrivate = true;
        if (STOCK_REJECTION) {
          stage = 'stock-explicit-physical-add';
          await frame.waitForFunction(name => [...document.querySelectorAll('[aria-label="Customer choices"] button')]
            .some(button => button.getAttribute('aria-label') === `Add to cart: ${name}`
              && !button.disabled && button.getClientRects().length), {}, blue.name);
          hideStockTurnReads = true;
          await choose(frame, `Add to cart: ${blue.name}`);
          const submitted = await waitFor(() => posts[1], 'explicit stock-rejected chat POST');
          assert.deepEqual(submitted.selection, { choiceId: blueCard.choiceId, intent: 'cart_add', quantity: 1 });
          const saved = await waitFor(async () => {
            const row = (await agents.query(`SELECT status,result_json FROM secureshop_agents.turn_requests
              WHERE session_id=$1 AND request_id=$2`, [submitted.sessionId, submitted.requestId])).rows[0];
            if (row?.status === 'uncertain') throw Error('Stock rejection turn is durably uncertain');
            return row?.status === 'completed' ? row.result_json : null;
          }, 'real stock-rejected turn completion', 150000);
          assert.equal(saved.stopReason, 'end_turn'); assert.ok(saved.text?.trim());
          assert.ok(decisions.some(item => item.requestId === submitted.requestId && item.tools.includes('cart.add')),
            'real local model selected the explicit cart.add');
          const hop = saved.hops?.find(value => value.tool === 'cart.add'
            && !value.error && value.result?.isError !== true);
          assert.ok(hop, 'genuine cart.add tool returned the durable rejection');
          assert.deepEqual(hop.params, { choiceId: blueCard.choiceId, quantity: 1 });
          const observed = JSON.parse(hop.result.content[0].text);
          assert.match(observed.scopeKey, SHA);
          const { scopeKey, ...unscoped } = observed;
          assert.deepEqual(unscoped, { version: 1, operationId: observed.operationId,
            kind: 'cart.add', status: 'rejected', result: { code: 'INSUFFICIENT_STOCK',
              choiceId: blueCard.choiceId, quantity: 1 }, replayed: false });
          assert.match(observed.operationId, UUID); status.modelSelectedRejectedAdd = true;
          const rows = (await review.query(`SELECT operation_id,state,kind,proposal_json,proposal_sha256,result_json,
            request_json FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1`,
          [observed.operationId])).rows;
          assert.equal(rows.length, 1); assert.equal(rows[0].state, 'completed');
          assert.equal(rows[0].kind, 'cart.add'); assert.equal(rows[0].proposal_json, null);
          assert.equal(rows[0].proposal_sha256, null);
          assert.deepEqual(JSON.parse(rows[0].result_json), unscoped);
          const request = JSON.parse(rows[0].request_json);
          assert.equal(request.choiceId, blueCard.choiceId); assert.equal(request.quantity, 1);
          assert.equal(request.origin.turnSessionId, submitted.sessionId);
          assert.equal(request.origin.turnRequestId, submitted.requestId);
          assert.equal(commerceContract.operationIdForOrigin(request.origin), observed.operationId);
          const read = await composition.customerChat.runtime.readRequest(actor.scope, actor.persona,
            actor.personaSession, submitted.sessionId, submitted.requestId);
          const savedReceipt = { ...unscoped, replayed: true };
          assert.deepEqual(read.operations, [{ operationId: observed.operationId,
            status: 'completed', receipt: savedReceipt }]);
          const direct = await composition.conversationalCommerce.readOperation({ ...actor,
            args: { operationId: observed.operationId } });
          assert.deepEqual(direct, { scopeKey, operationId: observed.operationId,
            status: 'completed', receipt: savedReceipt });
          const siblingRead = await composition.conversationalCommerce.readOperation({ ...siblingActor,
            args: { operationId: observed.operationId } });
          assert.deepEqual(siblingRead, { scopeKey: siblingRead.scopeKey,
            operationId: observed.operationId, status: 'not_found' });
          assert.match(siblingRead.scopeKey, SHA); status.siblingRejectionPrivate = true;
          const rejectedEffects = { ...effectsBefore, operations: effectsBefore.operations + 1 };
          assert.deepEqual(await effects(), rejectedEffects,
            'rejection adds only its durable operation receipt, not cart or order rows');
          assert.deepEqual(await catalogRows(target), ownedBefore);
          assert.equal((await identity.query(`SELECT count(*)::int AS n FROM
            secureshop_auth.assessment_judgments`)).rows[0].n, judgmentsBefore);
          assert.equal(status.judgeCalls, 0); status.noCommerceOrJudgeEffect = true;
          stage = 'stock-exact-get-recovery';
          const exactPath = `/agents/customer/operations/${submitted.sessionId}/${submitted.requestId}`;
          await waitFor(() => stockTurnReads.length >= 1, 'lost saved-turn read acknowledgement');
          assert.ok(stockTurnReads.length <= 2);
          assert.ok(stockTurnReads.every(path => path === exactPath));
          const readsBeforeReload = stockTurnReads.length;
          await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
          await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
          await frame.select('[data-testid="agent-lane"] select', 'chat');
          await waitFor(() => stockTurnReads.length > readsBeforeReload, 'reload lost saved-turn read acknowledgement');
          assert.ok(stockTurnReads.length <= 4);
          assert.ok(stockTurnReads.every(path => path === exactPath));
          await frame.waitForFunction(() => [...document.querySelectorAll('button')]
            .some(button => button.textContent.trim() === 'Check saved chat'
              && !button.disabled && button.getClientRects().length));
          const postsBeforeRecovery = posts.length, callsBeforeRecovery = status.actualModelCalls;
          const readsBeforeManual = stockTurnReads.length;
          hideStockTurnReads = false;
          const recovered = response(page, `/api/secureshop${exactPath}`, 'GET');
          await click(frame, 'Check saved chat');
          const recoveredHTTP = await readResponse(recovered); assert.equal(recoveredHTTP.status(), 200);
          assert.deepEqual(await recoveredHTTP.json(), read);
          assert.equal(stockTurnReads.length, readsBeforeManual + 1);
          assert.ok(stockTurnReads.every(path => path === exactPath));
          await frame.waitForFunction(() => {
            const rejection = document.querySelector('[aria-label="Customer cart rejection"]');
            return rejection?.getClientRects().length
              && rejection.textContent.includes('Not added to cart')
              && rejection.textContent.includes('Requested quantity 1 is unavailable.')
              && [...document.querySelectorAll('[data-testid="agent-turn"]')].at(-1)?.textContent
                .includes('Cart addition rejected')
              && !document.querySelector('[aria-label="Customer cart confirmation"]');
          }, { timeout: 30000 });
          assert.equal(posts.length, postsBeforeRecovery); assert.equal(status.actualModelCalls, callsBeforeRecovery);
          assert.equal(cartConfirms.length, 0); status.renderedSavedStockRejection = true;
          status.exactGetRecoveryNoReplay = true;
          assert.deepEqual(await effects(), rejectedEffects);
          const screenshot = path.join(path.dirname(receiptPath), 'customer-out-of-stock-final.png');
          await page.screenshot({ path: screenshot, fullPage: true }); await fs.chmod(screenshot, 0o600);
          stage = 'stock-controlled-restock-replay';
          const fixturePool = pools.REVIEW_MIGRATION;
          const changed = await fixturePool.query(`INSERT INTO secureshop_review.product_target_listing_overlays
            (target_id,product_id,shop_user_id,name,description,description_html,price,category,
             image_url,images,stock_quantity,status,template_source)
            SELECT p.target_id,p.product_id,p.retailer_id,p.name,p.description,p.description_html,
              p.price,p.category,p.image_url,p.images,1,p.status,p.template_source
            FROM secureshop_review.product_target_products p
            WHERE p.target_id=$1 AND p.product_id=$2 AND p.retailer_id=$3 AND p.stock_quantity=0
              AND NOT EXISTS (SELECT 1 FROM secureshop_review.product_target_listing_overlays o
                WHERE o.target_id=p.target_id AND o.product_id=p.product_id)`,
          [target.targetId, blueId, opened.ownMerchantId]);
          assert.equal(changed.rowCount, 1, 'controlled disposable restock creates only the selected owned overlay');
          assert.deepEqual((await review.query(`SELECT product_id,stock_quantity
            FROM secureshop_review.product_target_listing_overlays WHERE target_id=$1 ORDER BY product_id`,
          [target.targetId])).rows.map(row => ({ productId: Number(row.product_id), stock: Number(row.stock_quantity) })),
          [{ productId: blueId, stock: 1 }]);
          assert.deepEqual(await catalogRows(target), ownedBefore, 'immutable base snapshots remain unchanged');
          const replay = await composition.repositories.commerce.conversation.prepareCart(target, {
            shopUserId: actor.persona.id, personaSession: actor.personaSession, mode: 'vuln',
            operationId: observed.operationId, action: 'add', choiceId: blueCard.choiceId,
            quantity: 1, origin: request.origin });
          assert.deepEqual(replay, { ...savedReceipt, scopeKey });
          assert.deepEqual(await effects(), rejectedEffects,
            'same UUID replay after restock adds no second operation or cart effect');
          status.controlledRestockReplay = true;
          assert.equal(status.chatTurns, 2);
          assert.ok(status.actualModelCalls >= 2 && status.actualModelCalls <= 8);
          status.passed = true;
        } else {
        stage = 'product-physical-selection-detail';
        productTraceFloor = Number((await agents.query(`SELECT COALESCE(max(id),0)::bigint AS id
          FROM secureshop_agents.agent_trace`)).rows[0].id);
        await choose(frame, `View details: ${blue.name}`);
        const selected = await completed(1, 'catalog.details');
        assert.deepEqual(selected.sent.selection, { choiceId: blueCard.choiceId, intent: 'details' },
          'physical View details sends the exact saved product choice and read-only intent');
        const detailHop = selected.saved.hops.find(hop => hop.tool === 'catalog.details'
          && !hop.error && hop.result?.isError !== true);
        assert.equal(detailHop.params.choiceId, blueCard.choiceId,
          'actual model detail choice equals the physically selected opaque product choice');
        const observed = JSON.parse(detailHop.result.content[0].text);
        assert.equal(Number(observed.product.product_id), blueId);
        assert.equal(observed.product.name, blue.name);
        assert.equal(observed.product.description, blue.description);
        assert.equal(Number(observed.product.price), blue.price);
        assert.equal(Number(observed.product.stock_quantity), 0);
        assert.equal(observed.cards?.[0]?.choiceId, blueCard.choiceId);
        // The selected detail must also be readable in the storefront, not only
        // in a raw technical hop result. The customer UI owner supplies this card.
        await frame.waitForFunction(({ name, description, price, stock }) => {
          const detail = document.querySelector('[aria-label="Selected product details"]');
          return detail?.getClientRects().length && [name, description, price, stock]
            .every(value => detail.textContent.includes(value));
        }, { timeout: 30000 }, { name: blue.name, description: blue.description,
          price: '39.95', stock: '0' });
        status.renderedSelectedProductDetails = true;
        assert.deepEqual(await catalogRows(target), ownedBefore);
        assert.deepEqual(await catalogRows(peerTarget), siblingBefore);
        assert.deepEqual(await effects(), effectsBefore);
        assert.equal(Number((await identity.query(`SELECT count(*)::int AS n FROM
          secureshop_auth.assessment_judgments`)).rows[0].n), judgmentsBefore);
        assert.equal(status.judgeCalls, 0); status.noCommerceOrJudgeEffect = true;
        assert.equal(status.chatTurns, 2); assert.ok(status.actualModelCalls >= 2 && status.actualModelCalls <= 8);
        if (interceptionFailure) throw interceptionFailure;
        const screenshot = path.join(path.dirname(receiptPath), 'customer-product-details-final.png');
        await page.screenshot({ path: screenshot, fullPage: true }); await fs.chmod(screenshot, 0o600);
        status.passed = true;
        }
      } else if (PROFILE) {
        const Profile = require('../../server/services/secureshopProfileUpdateContract');
        const profileRows = async () => (await review.query(`SELECT target_id,shop_user_id,email,full_name,phone,
          updated_at::text AS updated_at FROM secureshop_review.product_target_profile_overlays
          WHERE target_id=$1 AND shop_user_id=$2`, [target.targetId, actor.persona.id])).rows;
        const profileOperations = async () => (await review.query(`SELECT * FROM secureshop_review.chat_commerce_operations
          WHERE target_id=$1 AND shop_user_id=$2 AND kind='profile.update' ORDER BY created_at,operation_id`,
        [target.targetId, actor.persona.id])).rows;
        const profileAudit = async () => (await review.query(`SELECT * FROM secureshop_review.bound_audit_events
          WHERE shop_user_id=$1 AND source_kind='profile' ORDER BY event_id`, [actor.persona.id])).rows;
        const otherEffects = async () => (await review.query(`SELECT
          (SELECT count(*)::int FROM secureshop_review.product_target_cart_items WHERE target_id=$1) AS cart,
          (SELECT count(*)::int FROM secureshop_review.product_target_orders WHERE target_id=$1) AS orders,
          (SELECT count(*)::int FROM secureshop_review.practice_payment_methods WHERE target_id=$1) AS methods,
          (SELECT count(*)::int FROM secureshop_review.product_target_addresses WHERE target_id=$1) AS addresses`,
        [target.targetId])).rows[0];
        const commerceCall = (who, method, args) => composition.commerce.conversational({
          scope: who.scope, persona: who.persona, personaSession: who.personaSession, method, args });
        const form = await commerceCall(actor, 'profileForm', {});
        const initialProfile = await composition.account.profile(actor);
        const initialSiblingProfile = await composition.account.profile(siblingActor);
        assert.deepEqual(form.fields, { fullName: initialProfile.full_name ?? null,
          email: initialProfile.email, phone: initialProfile.phone ?? null });
        assert.match(form.scopeKey, SHA); assert.match(form.expectedSnapshotSha256, SHA);
        assert.deepEqual(await profileRows(), []); assert.deepEqual(await profileOperations(), []);
        const auditBefore = await profileAudit(), effectsBefore = await otherEffects();
        const judgmentsBefore = Number((await identity.query(`SELECT count(*)::int AS n
          FROM secureshop_auth.assessment_judgments`)).rows[0].n);
        let frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        const sendProfileTurn = async (index, message, tool) => {
          if (index > 0) await frame.waitForFunction(() => {
            const last = [...document.querySelectorAll('[data-testid="agent-turn"]')].at(-1);
            const field = document.querySelector('textarea[placeholder="Find a laptop for coding"]');
            const send = [...document.querySelectorAll('button')]
              .find(button => button.textContent.trim() === 'Send to customer agent');
            return last?.querySelector('.ss-turn__supervisor')?.textContent.trim().endsWith('done')
              && field?.value === '' && send?.disabled
              && ![...document.querySelectorAll('button')]
                .some(button => button.textContent.trim() === 'Check saved chat');
          }, { timeout: 30000 });
          const field = await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]', { visible: true });
          const browserRead = page.waitForResponse(value =>
            /^\/api\/secureshop\/agents\/customer\/operations\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(new URL(value.url()).pathname)
              && value.request().method() === 'GET', { timeout: 150000 })
            .then(value => ({ value }), error => ({ error }));
          await field.type(message);
          await frame.waitForFunction(text => {
            const field = document.querySelector('textarea[placeholder="Find a laptop for coding"]');
            const send = [...document.querySelectorAll('button')]
              .find(button => button.textContent.trim() === 'Send to customer agent');
            return field?.value === text && send && !send.disabled;
          }, { timeout: 30000 }, message);
          await click(frame, 'Send to customer agent');
          const sent = await waitFor(() => posts[index], `profile chat POST ${index + 1}`);
          assert.match(sent.sessionId, UUID); assert.match(sent.requestId, UUID);
          const saved = await waitFor(async () => {
            const value = await composition.customerChat.runtime.readRequest(actor.scope, actor.persona,
              actor.personaSession, sent.sessionId, sent.requestId);
            return value.status === 'completed' ? value : null;
          }, `saved genuine profile turn ${index + 1}`, 150000);
          assert.equal(saved.stopReason, 'end_turn'); assert.ok(saved.text?.trim());
          assert.ok(decisions.some(value => value.requestId === sent.requestId && value.tools.includes(tool)),
            `real model selected ${tool}`);
          assert.ok(saved.hops?.some(hop => hop.tool === tool && !hop.error && hop.result?.isError !== true),
            `real ${tool} observation succeeded`);
          assert.deepEqual(acknowledgedChats[index], { sessionId: sent.sessionId, requestId: sent.requestId });
          await frame.waitForFunction(text => [...document.querySelectorAll('[data-testid="agent-turn"]')]
            .at(-1)?.querySelector('[data-testid="agent-turn-reply"]')?.textContent?.trim() === text,
          { timeout: 30000 }, saved.text.trim());
          const exactRead = await readResponse(browserRead);
          assert.equal(exactRead.status(), 200);
          assert.equal(new URL(exactRead.url()).pathname,
            `/api/secureshop/agents/customer/operations/${sent.sessionId}/${sent.requestId}`);
          return { sent, saved };
        };
        stage = 'profile-real-read';
        const readTurn = await sendProfileTurn(0, 'What full name, email, and phone are currently on my shop profile?',
          'account.profile');
        assert.equal(readTurn.saved.profileProposal, null);
        const profileObservation = readTurn.saved.hops.find(hop => hop.tool === 'account.profile'
          && !hop.error && hop.result?.isError !== true);
        assert.deepEqual(JSON.parse(profileObservation.result.content[0].text), { profile: form.fields });
        for (const value of Object.values(form.fields).filter(value => typeof value === 'string' && value))
          assert.ok(readTurn.saved.text.includes(value), 'rendered profile read includes the actual current field');
        assert.deepEqual(await profileRows(), []); assert.deepEqual(await profileOperations(), []);
        assert.deepEqual(await profileAudit(), auditBefore); status.renderedProfileRead = true;
        stage = 'profile-real-prepare';
        const nextName = `Practice Customer ${suffix}`;
        const prepared = await sendProfileTurn(1,
          `Please change only my full name to "${nextName}". Keep my email and phone unchanged.`,
          'account.profile_update_prepare');
        const proposal = prepared.saved.profileProposal;
        assert.ok(proposal); assert.match(proposal.proposalId, UUID);
        assert.deepEqual(proposal.patch, { fullName: nextName });
        assert.deepEqual(proposal.before, form.fields);
        assert.deepEqual(proposal.after, { ...form.fields, fullName: nextName });
        assert.equal(proposal.scopeKey, form.scopeKey);
        assert.equal(proposal.expectedSnapshotSha256, form.expectedSnapshotSha256);
        assert.equal(proposal.requestSha256, Profile.profileRequestDigest({ operationId: proposal.proposalId,
          expectedSnapshotSha256: proposal.expectedSnapshotSha256, fields: proposal.after }));
        assert.deepEqual(await profileRows(), []); assert.deepEqual(await profileOperations(), []);
        assert.deepEqual(await profileAudit(), auditBefore); assert.deepEqual(await otherEffects(), effectsBefore);
        status.renderedNoEffectProposal = true; status.zeroEffectBeforeConfirm = true;
        await frame.waitForFunction(({ before, after }) => {
          const card = document.querySelector('[aria-label="Profile changes to confirm"]');
          const shown = value => value === null || value === '' ? 'Not set' : value;
          const rows = [...(card?.querySelectorAll('p') || [])];
          const fields = [['Full name', 'fullName'], ['Email', 'email'], ['Phone', 'phone']];
          return card?.getClientRects().length && fields.every(([label, key]) => {
            const row = rows.find(node => node.querySelector('strong')?.textContent === `${label}:`);
            return row?.textContent.includes(shown(before[key])) && row.textContent.includes(shown(after[key]));
          })
            && [...card.querySelectorAll('button')].some(button =>
              button.textContent.trim() === 'Confirm profile update' && !button.disabled);
        }, { timeout: 30000 }, { before: form.fields, after: proposal.after });
        const beforeConfirm = path.join(path.dirname(receiptPath), 'customer-profile-before-confirm.png');
        await page.screenshot({ path: beforeConfirm, fullPage: true }); await fs.chmod(beforeConfirm, 0o600);
        status.renderedExplicitProfileReview = true;
        stage = 'profile-physical-confirm-lost-ack';
        const confirmPath = `${origin}/api/secureshop/agents/customer/profile/confirm`;
        cdp = await page.createCDPSession();
        cdp.on('Fetch.requestPaused', event => {
          const work = (async () => {
            assert.equal(event.request.url, confirmPath);
            assert.equal(event.request.method, 'POST');
            const raw = await bounded(cdp.send('Fetch.getResponseBody', { requestId: event.requestId }),
              'profile confirm receipt body');
            const responseBody = Buffer.from(raw.body, raw.base64Encoded ? 'base64' : 'utf8').toString();
            if (event.responseStatusCode !== 200) {
              let publicError = null;
              try {
                const parsed = JSON.parse(responseBody);
                if (typeof parsed?.error === 'string' && parsed.error.length <= 160)
                  publicError = parsed.error;
              } catch { /* Preserve the exact HTTP status without copying an arbitrary response body. */ }
              profileConfirmResponse = { status: event.responseStatusCode, publicError };
            }
            assert.equal(event.responseStatusCode, 200);
            lostReceipt = JSON.parse(responseBody);
            assert.equal(lostReceipt.kind, 'profile.update'); assert.equal(lostReceipt.status, 'completed');
            assert.equal(lostReceipt.operationId, proposal.proposalId); assert.equal(lostReceipt.replayed, false);
            hideProfileReads = true;
            await bounded(cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }),
              'drop committed profile response');
          })().catch(async error => {
            interceptionFailure ??= error;
            await bounded(cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }),
              'release failed profile capture').catch(() => {});
          });
          pendingInterceptions.add(work); void work.finally(() => pendingInterceptions.delete(work));
        });
        await cdp.send('Fetch.enable', { patterns: [{ urlPattern: confirmPath, requestStage: 'Response' }] });
        await click(frame, 'Confirm profile update');
        await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return lostReceipt; },
          'committed profile receipt');
        await Promise.all([...pendingInterceptions]);
        await bounded(cdp.send('Fetch.disable'), 'disable profile fault');
        await bounded(cdp.detach(), 'detach profile fault'); cdp = null;
        assert.deepEqual(profileConfirms, [{ sessionId: prepared.sent.sessionId,
          requestId: prepared.sent.requestId, proposalId: proposal.proposalId }]);
        assert.equal(acknowledgedConfirms.length, 1);
        assert.equal(acknowledgedConfirms[0].operationId, proposal.proposalId);
        assert.equal(acknowledgedConfirms[0].requestSha256, proposal.requestSha256);
        assert.equal(acknowledgedConfirms[0].fieldsSha256, Profile.profileFieldsDigest(proposal.after));
        const updatedRows = await profileRows(), updatedAudit = await profileAudit();
        const updatedOperations = await profileOperations();
        assert.equal(updatedRows.length, 1); assert.equal(updatedRows[0].full_name, nextName);
        assert.equal(updatedRows[0].email, form.fields.email);
        assert.equal(updatedAudit.length, auditBefore.length + 1);
        assert.equal(updatedOperations.length, 1);
        const savedOperation = updatedOperations[0];
        assert.equal(savedOperation.operation_id, proposal.proposalId);
        assert.equal(savedOperation.state, 'completed'); assert.equal(savedOperation.proposal_json, null);
        assert.equal(savedOperation.target_id, target.targetId);
        assert.equal(Number(savedOperation.shop_user_id), actor.persona.id);
        assert.equal(savedOperation.intent_sha256, commerceContract.digest(savedOperation.request_json));
        assert.equal(savedOperation.result_sha256, commerceContract.digest(savedOperation.result_json));
        const { scopeKey: ignoredScope, ...unscopedReceipt } = lostReceipt;
        assert.deepEqual(JSON.parse(savedOperation.result_json), unscopedReceipt);
        status.renderedOneProfileReceipt = true;
        const siblingRead = await commerceCall(siblingActor, 'readOperation', { operationId: proposal.proposalId });
        assert.deepEqual(siblingRead, { scopeKey: siblingRead.scopeKey,
          operationId: proposal.proposalId, status: 'not_found' });
        assert.notEqual(siblingRead.scopeKey, proposal.scopeKey);
        assert.deepEqual(await composition.account.profile(siblingActor), initialSiblingProfile);
        status.siblingProfilePrivate = true;
        stage = 'profile-exact-recovery';
        await frame.waitForFunction(() => [...document.querySelectorAll('[aria-label="Profile update review"] button')]
          .some(button => button.textContent.trim() === 'Check saved profile' && !button.disabled));
        const operationPath = `/customer/commerce/operations/${proposal.proposalId}`;
        await waitFor(() => faultedOperationReads.includes(operationPath),
          'failed exact profile operation read before recovery');
        const modelBeforeRecovery = status.actualModelCalls, postsBeforeRecovery = posts.length;
        hideProfileReads = false;
        await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        await frame.waitForFunction(() => [...document.querySelectorAll('[aria-label="Profile update review"] button')]
          .some(button => button.textContent.trim() === 'Check saved profile' && !button.disabled));
        const exact = response(page,
          `/api/secureshop/customer/commerce/operations/${proposal.proposalId}`, 'GET');
        await click(frame, 'Check saved profile');
        const exactResponse = await readResponse(exact); assert.equal(exactResponse.status(), 200);
        const recovered = await exactResponse.json();
        assert.deepEqual(recovered, { scopeKey: proposal.scopeKey, operationId: proposal.proposalId,
          status: 'completed', receipt: { ...unscopedReceipt, replayed: true } });
        await frame.waitForFunction(() => document.querySelector('[aria-label="Profile update review"] [role="status"]')
          ?.textContent.includes('Profile updated.'));
        assert.equal(status.actualModelCalls, modelBeforeRecovery); assert.equal(posts.length, postsBeforeRecovery);
        assert.equal(profileConfirms.length, 1); assert.equal(acknowledgedConfirms.length, 1);
        assert.deepEqual(directProfileSaves, []);
        assert.deepEqual(await profileRows(), updatedRows); assert.deepEqual(await profileAudit(), updatedAudit);
        assert.deepEqual(await profileOperations(), updatedOperations);
        status.lostAckExactRecovery = true;
        stage = 'profile-account-parity';
        const protectedProfile = await composition.account.profile(actor);
        assert.equal(protectedProfile.full_name, nextName); assert.equal(protectedProfile.email, form.fields.email);
        await page.goto(`${origin}/secureshop/account`, { waitUntil: 'domcontentloaded' });
        frame = await frameFor(page);
        await frame.waitForFunction(name => document.querySelector('[aria-label="Profile update review"] input[aria-label="Full name"]')
          ?.value === name, { timeout: 30000 }, nextName);
        status.accountProfileParity = true;
        stage = 'profile-controlled-fences';
        const later = { ...proposal.after, fullName: `Later Customer ${suffix}` };
        const currentForm = await commerceCall(actor, 'profileForm', {});
        const laterId = randomUUID();
        const laterResult = await commerceCall(actor, 'saveProfile', { operationId: laterId,
          expectedSnapshotSha256: currentForm.expectedSnapshotSha256, fields: later });
        assert.equal(laterResult.status, 'completed'); assert.equal(laterResult.replayed, false);
        const afterLater = await profileRows(), auditAfterLater = await profileAudit();
        assert.equal(afterLater[0].full_name, later.fullName);
        assert.equal(auditAfterLater.length, updatedAudit.length + 1);
        const replay = await commerceCall(actor, 'saveProfile', { operationId: proposal.proposalId,
          expectedSnapshotSha256: proposal.expectedSnapshotSha256, fields: proposal.after });
        assert.deepEqual(replay, { ...lostReceipt, replayed: true });
        assert.deepEqual(await profileRows(), afterLater); assert.deepEqual(await profileAudit(), auditAfterLater);
        const staleId = randomUUID();
        const stale = await commerceCall(actor, 'saveProfile', { operationId: staleId,
          expectedSnapshotSha256: proposal.expectedSnapshotSha256, fields: proposal.after });
        assert.equal(stale.status, 'stale'); assert.equal(stale.replayed, false);
        const staleRead = await commerceCall(actor, 'readOperation', { operationId: staleId });
        assert.equal(staleRead.status, 'completed'); assert.equal(staleRead.receipt.status, 'stale');
        assert.equal(staleRead.receipt.result.fieldsSha256, Profile.profileFieldsDigest(proposal.after));
        assert.deepEqual(await profileRows(), afterLater); assert.deepEqual(await profileAudit(), auditAfterLater);
        const foreign = await commerceCall(siblingActor, 'readOperation', { operationId: staleId });
        assert.equal(foreign.status, 'not_found');
        assert.deepEqual(await otherEffects(), effectsBefore);
        status.controlledProfileFences = true;
        stage = 'profile-reset-fence';
        const resetResult = await reset.launchResetCoordinator.reset({ launchId: actor.scope.launchId,
          platformOwnerId: actor.scope.platformOwnerId, platformSessionId: actor.scope.platformSessionId,
          expectedGeneration: actor.scope.generation, idempotencyKey: randomUUID() });
        assert.equal(resetResult.status, 'committed');
        await assert.rejects(commerceCall(actor, 'readOperation', { operationId: proposal.proposalId }), error =>
          ['STALE_GENERATION', 'STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SHOP_SCENE_STALE',
            'PRODUCT_TARGET_UNAVAILABLE'].includes(error?.code));
        status.resetSessionDenied = true;
        assert.equal((await identity.query(`SELECT count(*)::int AS n FROM
          secureshop_auth.assessment_judgments`)).rows[0].n, judgmentsBefore);
        assert.equal(status.judgeCalls, 0); status.noJudgeOrCommerceEffect = true;
        assert.equal(posts.length, 2); assert.ok(status.actualModelCalls >= 2 && status.actualModelCalls <= 10);
        if (interceptionFailure) throw interceptionFailure;
        const screenshot = path.join(path.dirname(receiptPath), 'customer-profile-final.png');
        await page.screenshot({ path: screenshot, fullPage: true }); await fs.chmod(screenshot, 0o600);
        status.passed = true;
      } else if (ADDRESS_SETUP) {
        const addressRows = async () => (await review.query(`SELECT address_id,target_id,shop_user_id,label,line1,
          line2,city,state,zip,phone,is_default,updated_at::text AS updated_at
          FROM secureshop_review.product_target_addresses WHERE target_id=$1 AND shop_user_id=$2 ORDER BY address_id`,
        [target.targetId, actor.persona.id])).rows;
        const operationRows = async () => (await review.query(`SELECT * FROM secureshop_review.chat_commerce_operations
          WHERE target_id=$1 AND shop_user_id=$2 AND kind LIKE 'address.%' ORDER BY created_at,operation_id`,
        [target.targetId, actor.persona.id])).rows;
        const judgmentsBefore = Number((await identity.query(`SELECT count(*)::int AS n FROM
          secureshop_auth.assessment_judgments`)).rows[0].n);
        await composition.account.createAddress({ ...actor, address: { label: 'Original default',
          line1: '3 Original Way', line2: null, city: 'Testville', state: 'CA',
          zip: '90001', phone: null, isDefault: true } });
        const originalRows = await addressRows();
        assert.equal(originalRows.length, 1); assert.equal(originalRows[0].is_default, true);
        assert.deepEqual(await operationRows(), []);
        let frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        const sendAddressTurn = async (text, selectAddress = null) => {
          const index = posts.length, decisionStart = decisions.length;
          const handoffHTTP = page.waitForResponse(value =>
            /^\/api\/secureshop\/agents\/customer\/operations\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(new URL(value.url()).pathname)
            && value.request().method() === 'GET' && value.status() === 200,
          { timeout: 150000 }).then(value => ({ value }), error => ({ error }));
          if (selectAddress) await choose(frame, `Edit address: ${selectAddress}`);
          else {
            const input = await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]', { visible: true });
            await input.type(text);
            await click(frame, 'Send to customer agent');
          }
          const sent = await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return posts[index]; },
            `address chat POST ${index + 1}`);
          assert.match(sent.sessionId, UUID); assert.match(sent.requestId, UUID);
          const saved = await waitFor(async () => {
            const row = (await agents.query(`SELECT status,result_json FROM secureshop_agents.turn_requests
              WHERE session_id=$1 AND request_id=$2`, [sent.sessionId, sent.requestId])).rows[0];
            if (row?.status === 'uncertain') throw Object.assign(Error('Address turn uncertain'), { code: 'CHAT_TURN_UNCERTAIN' });
            return row?.status === 'completed' ? row.result_json : null;
          }, `genuine address turn ${index + 1}`, 150000);
          addressTurnEvidence.push({ requestId: sent.requestId, stopReason: saved.stopReason,
            hops: (saved.hops || []).slice(0, 4)
              .filter(hop => ['account.addresses', 'account.address_setup',
                'account.address_edit_setup'].includes(hop?.tool))
              .map(hop => ({ step: hop.step, tool: hop.tool,
                params: addressDiagnosticArgs(hop.params, sent.message),
                errorCode: addressDiagnosticCode(hop.error?.code),
                resultErrorCode: addressResultCode(hop.result),
                isError: hop.result?.isError === true,
                policyViolation: ['blocked', 'denied-by-acl'].includes(hop.policyViolation)
                  ? hop.policyViolation : null })) });
          assert.equal(saved.stopReason, 'end_turn'); assert.ok(saved.text?.trim());
          const handoffResponse = await readResponse(handoffHTTP);
          assert.equal(new URL(handoffResponse.url()).pathname,
            `/api/secureshop/agents/customer/operations/${sent.sessionId}/${sent.requestId}`);
          const handoff = await handoffResponse.json();
          assert.equal(handoff.status, 'completed'); assert.equal(handoff.sessionId, sent.sessionId);
          assert.equal(handoff.requestId, sent.requestId);
          return { sent, saved, handoff, decisions: decisions.slice(decisionStart) };
        };
        stage = 'address-create-model-handoff';
        const opened = await sendAddressTurn('Help me add a delivery address labeled Practice Home. I will complete the missing details in the form.');
        assert.ok(opened.decisions.some(item => item.tools.includes('account.address_setup')));
        const createHop = opened.saved.hops?.find(hop => hop.tool === 'account.address_setup' && !hop.error
          && hop.result?.isError !== true);
        assert.ok(createHop, 'real model opened no-effect address setup');
        const createSetup = opened.saved.taskMetadata?.customerChat?.addressSetup;
        assert.deepEqual(createSetup, { version: 1, kind: 'address_setup', action: 'create',
          choiceId: null, draft: createSetup?.draft });
        assert.equal(Object.hasOwn(createSetup.draft, 'line1'), false,
          'the model cannot invent the omitted street address');
        assert.deepEqual(opened.handoff.addressSetup, createSetup);
        await frame.waitForSelector('[aria-label="Address setup"] input[aria-label="Street address"]', { visible: true });
        assert.deepEqual(await addressRows(), originalRows); assert.deepEqual(await operationRows(), []);
        assert.equal(addressSaves.length, 0);
        status.renderedAddressSetupHandoff = true; status.zeroEffectBeforeConfirm = true;
        stage = 'address-create-physical-review';
        const street = '14 Practice Lane';
        const enterField = async (label, value) => {
          const input = await frame.$(`[aria-label="Address setup"] input[aria-label="${label}"]`);
          assert.ok(input); await input.click();
          const original = await input.evaluate(node => node.value);
          await page.keyboard.press('End');
          await page.keyboard.down('Shift');
          try { await page.keyboard.press('Home'); }
          finally { await page.keyboard.up('Shift'); }
          const selection = await input.evaluate(node => [node.selectionStart, node.selectionEnd, node.value.length, node.value]);
          assert.deepEqual(selection, [0, original.length, original.length, original],
            `${label} draft must be fully selected without inserting a character`);
          await page.keyboard.press('Backspace');
          assert.equal(await input.evaluate(node => node.value), '', `${label} draft must be cleared by keyboard`);
          await input.type(value);
          assert.equal(await input.evaluate(node => node.value), value,
            `${label} must be physically replaced, including any model-supplied draft`);
        };
        await enterField('Label', 'Practice Home');
        await enterField('Street address', street);
        await enterField('City', 'Testville');
        await enterField('State', 'CA');
        await enterField('ZIP', '90001');
        await frame.click('[aria-label="Address setup"] input[type="checkbox"]');
        await frame.waitForFunction(expected => {
          const section = document.querySelector('[aria-label="Address setup"]');
          return Object.entries(expected).every(([label, value]) =>
            section?.querySelector(`input[aria-label="${label}"]`)?.value === value);
        }, {}, { Label: 'Practice Home', 'Street address': street, City: 'Testville',
          State: 'CA', ZIP: '90001' });
        await click(frame, 'Review address');
        await frame.waitForFunction(expected => {
          const preview = document.querySelector('[aria-label="Address changes to confirm"]');
          return expected.every(([label, value]) => [...(preview?.querySelectorAll('p') || [])]
            .some(row => row.querySelector('strong')?.textContent === `${label}:`
              && row.querySelector('span')?.textContent === value));
        }, {}, [['Label', 'Practice Home'], ['Street address', street], ['City', 'Testville']]);
        assert.deepEqual(await addressRows(), originalRows); assert.deepEqual(await operationRows(), []);
        status.missingDraftCompletedByUser = true;
        const beforeConfirm = path.join(path.dirname(receiptPath), 'customer-address-before-confirm.png');
        await page.screenshot({ path: beforeConfirm, fullPage: true }); await fs.chmod(beforeConfirm, 0o600);
        stage = 'address-create-lost-ack';
        cdp = await page.createCDPSession();
        const addressEndpoint = `${origin}/api/secureshop/customer/commerce/addresses`;
        cdp.on('Fetch.requestPaused', event => {
          const work = (async () => {
            assert.equal(event.request.url, addressEndpoint);
            if (event.request.method === 'GET') {
              await bounded(cdp.send('Fetch.continueRequest', { requestId: event.requestId }),
                'release current address read');
              return;
            }
            assert.equal(event.request.method, 'POST');
            assert.equal(event.responseStatusCode, 200);
            const raw = await bounded(cdp.send('Fetch.getResponseBody', { requestId: event.requestId }),
              'address create receipt body');
            lostReceipt = JSON.parse(Buffer.from(raw.body, raw.base64Encoded ? 'base64' : 'utf8').toString());
            assert.equal(lostReceipt.kind, 'address.create'); assert.equal(lostReceipt.status, 'completed');
            assert.equal(lostReceipt.replayed, false); hideAddressReads = true;
            await bounded(cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }),
              'drop committed address response');
          })().catch(async error => {
            interceptionFailure ??= error;
            await bounded(cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }),
              'release failed address capture').catch(() => {});
          });
          pendingInterceptions.add(work); void work.finally(() => pendingInterceptions.delete(work));
        });
        await cdp.send('Fetch.enable', { patterns: [{ urlPattern: addressEndpoint, requestStage: 'Response' }] });
        await click(frame, 'Confirm address save');
        await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return lostReceipt; },
          'committed address create');
        await Promise.all([...pendingInterceptions]);
        await bounded(cdp.send('Fetch.disable'), 'disable address fault');
        await bounded(cdp.detach(), 'detach address fault'); cdp = null;
        assert.equal(addressSaves.length, 1); assert.equal(acknowledgedConfirms.length, 1);
        assert.equal(addressSaves[0].operationId, lostReceipt.operationId);
        assert.equal(addressSaves[0].fields.line1, street);
        assert.equal(addressSaves[0].fields.isDefault, true);
        const createdRows = await addressRows(), createdOperations = await operationRows();
        assert.equal(createdRows.length, 2); assert.equal(createdOperations.length, 1);
        const created = createdRows.find(row => Number(row.address_id) === lostReceipt.result.addressId);
        const original = createdRows.find(row => Number(row.address_id) === Number(originalRows[0].address_id));
        assert.ok(created); assert.ok(original);
        assert.equal(created.line1, street); assert.equal(created.is_default, true);
        assert.equal(original.is_default, false);
        assert.equal(createdOperations[0].kind, 'address.create');
        assert.equal(createdOperations[0].operation_id, lostReceipt.operationId);
        assert.equal(createdOperations[0].state, 'completed');
        assert.equal(createdOperations[0].target_id, target.targetId);
        assert.equal(Number(createdOperations[0].shop_user_id), actor.persona.id);
        assert.equal(createdOperations[0].intent_sha256, commerceContract.digest(createdOperations[0].request_json));
        assert.equal(createdOperations[0].result_sha256, commerceContract.digest(createdOperations[0].result_json));
        assert.deepEqual(JSON.parse(createdOperations[0].result_json),
          Object.fromEntries(Object.entries(lostReceipt).filter(([key]) => key !== 'scopeKey')));
        status.renderedAddressCreateReceipt = true;
        const siblingRead = await composition.conversationalCommerce.readOperation({ ...siblingActor,
          args: { operationId: lostReceipt.operationId } });
        assert.deepEqual(siblingRead, { scopeKey: siblingRead.scopeKey,
          operationId: lostReceipt.operationId, status: 'not_found' });
        assert.notEqual(siblingRead.scopeKey, lostReceipt.scopeKey); status.siblingAddressDenied = true;
        await frame.waitForFunction(() => [...document.querySelectorAll('[aria-label="Address setup"] button')]
          .some(button => button.textContent.trim() === 'Check saved address' && !button.disabled));
        const callsBeforeRecovery = status.actualModelCalls, postsBeforeRecovery = posts.length;
        hideAddressReads = false; stage = 'address-create-exact-recovery';
        await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select');
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        await frame.waitForFunction(() => [...document.querySelectorAll('[aria-label="Address setup"] button')]
          .some(button => button.textContent.trim() === 'Check saved address' && !button.disabled));
        const recoveredHTTP = response(page,
          `/api/secureshop/customer/commerce/operations/${lostReceipt.operationId}`, 'GET');
        await click(frame, 'Check saved address');
        const recovered = await readResponse(recoveredHTTP); assert.equal(recovered.status(), 200);
        const recoveredBody = await recovered.json();
        assert.equal(recoveredBody.scopeKey, lostReceipt.scopeKey);
        assert.equal(recoveredBody.operationId, lostReceipt.operationId);
        assert.equal(recoveredBody.status, 'completed');
        const { scopeKey: ignoredScope, ...storedCreate } = lostReceipt;
        assert.deepEqual(recoveredBody.receipt, { ...storedCreate, replayed: true });
        assert.equal(status.actualModelCalls, callsBeforeRecovery); assert.equal(posts.length, postsBeforeRecovery);
        assert.equal(addressSaves.length, 1); assert.deepEqual(await addressRows(), createdRows);
        assert.deepEqual(await operationRows(), createdOperations);
        assert.ok(faultedOperationReads.some(value => value.endsWith(`/${lostReceipt.operationId}`)));
        status.lostAckExactRecovery = true;
        await frame.waitForFunction(() => {
          const text = document.querySelector('[aria-label="Current delivery addresses"]')?.textContent;
          return text?.includes('Practice Home') && text.includes('Testville');
        });
        const currentAddresses = await composition.conversationalCommerce.addresses({ ...actor, args: {} });
        const homeCard = currentAddresses.cards.find(card => card.kind === 'address' && card.title === 'Practice Home');
        assert.ok(homeCard); assert.match(homeCard.choiceId, UUID);
        await assert.rejects(composition.conversationalCommerce.addressForm({ ...siblingActor,
          args: { action: 'update', choiceId: homeCard.choiceId } }), error =>
          ['COMMERCE_CHOICE_DENIED', 'COMMERCE_CHOICE_STALE'].includes(error?.code));
        stage = 'address-edit-model-choice';
        const listTurn = await sendAddressTurn('I need to change the city of my saved address named "Practice Home" to Redwood City. Show my saved addresses so I can choose it.');
        assert.ok(listTurn.decisions.some(item => item.tools.includes('account.addresses')));
        assert.ok(listTurn.handoff.cards?.some(card => card.choiceId === homeCard.choiceId));
        const oldForm = await composition.conversationalCommerce.addressForm({ ...actor,
          args: { action: 'update', choiceId: homeCard.choiceId } });
        const editTurn = await sendAddressTurn(null, homeCard.title);
        assert.deepEqual(editTurn.sent.selection,
          { choiceId: homeCard.choiceId, intent: 'address_edit' });
        assert.ok(editTurn.decisions.some(item => item.tools.includes('account.address_edit_setup')));
        assert.deepEqual(editTurn.handoff.addressSetup, { version: 1, kind: 'address_setup',
          action: 'update', choiceId: homeCard.choiceId, draft: editTurn.handoff.addressSetup?.draft });
        await frame.waitForSelector('[aria-label="Address setup"] input[aria-label="City"]', { visible: true });
        assert.equal(addressSaves.length, 1); assert.equal((await operationRows()).length, 1);
        stage = 'address-edit-physical-confirmation';
        await enterField('City', 'Redwood City');
        await click(frame, 'Review address');
        await frame.waitForFunction(() => [...(document.querySelector('[aria-label="Address changes to confirm"]')
          ?.querySelectorAll('p') || [])].some(row => row.querySelector('strong')?.textContent === 'City:'
            && [...row.querySelectorAll('span')].at(-1)?.textContent === 'Redwood City'));
        assert.equal((await addressRows()).find(row => Number(row.address_id) === lostReceipt.result.addressId)?.city,
          created.city);
        await click(frame, 'Confirm address update');
        await waitFor(async () => (await operationRows()).length === 2, 'address edit committed');
        const editedRows = await addressRows(), editedOperations = await operationRows();
        assert.equal(addressSaves.length, 2); assert.equal(editedRows.length, 2);
        const edited = editedRows.find(row => Number(row.address_id) === lostReceipt.result.addressId);
        assert.ok(edited); assert.equal(edited.city, 'Redwood City'); assert.equal(edited.is_default, true);
        assert.equal(editedOperations[1].kind, 'address.update');
        assert.equal(editedOperations[1].state, 'completed');
        assert.equal(editedOperations[1].operation_id, addressSaves[1].operationId);
        assert.equal(editedOperations[1].intent_sha256, commerceContract.digest(editedOperations[1].request_json));
        assert.equal(editedOperations[1].result_sha256, commerceContract.digest(editedOperations[1].result_json));
        const editRead = await composition.conversationalCommerce.readOperation({ ...actor,
          args: { operationId: addressSaves[1].operationId } });
        assert.equal(editRead.status, 'completed'); assert.equal(editRead.receipt.kind, 'address.update');
        assert.equal(editRead.receipt.result.addressId, lostReceipt.result.addressId);
        assert.equal(editRead.receipt.result.fieldsSha256, acknowledgedConfirms[1].fieldsSha256);
        status.renderedAddressEditReceipt = true;
        assert.equal(editedRows.filter(row => row.is_default).length, 1);
        assert.equal(status.judgeCalls, 0);
        assert.equal((await identity.query('SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments')).rows[0].n,
          judgmentsBefore); status.defaultUniqueness = true;
        stage = 'address-stale-edit';
        const freshCards = await composition.conversationalCommerce.addresses({ ...actor, args: {} });
        const freshHome = freshCards.cards.find(card => card.kind === 'address' && card.title === 'Practice Home');
        assert.ok(freshHome); assert.match(freshHome.choiceId, UUID);
        const staleOperationId = randomUUID();
        const staleArgs = { operationId: staleOperationId, action: 'update', choiceId: freshHome.choiceId,
          expectedSnapshotSha256: oldForm.expectedSnapshotSha256,
          defaultSetSha256: oldForm.defaultSetSha256, fields: addressSaves[1].fields };
        const auditRows = async () => (await review.query(`SELECT * FROM secureshop_review.bound_audit_events
          WHERE shop_user_id=$1 AND source_kind='address' ORDER BY event_id`,
        [actor.persona.id])).rows;
        const auditBeforeStale = await auditRows();
        const staleResult = await composition.conversationalCommerce.saveAddress({ ...actor, args: staleArgs });
        assert.equal(staleResult.operationId, staleOperationId);
        assert.equal(staleResult.kind, 'address.update'); assert.equal(staleResult.status, 'stale');
        assert.equal(staleResult.replayed, false);
        assert.deepEqual(staleResult.result, { fieldsSha256: acknowledgedConfirms[1].fieldsSha256 });
        const recoveredStale = await composition.conversationalCommerce.readOperation({ ...actor,
          args: { operationId: staleOperationId } });
        assert.equal(recoveredStale.scopeKey, staleResult.scopeKey);
        assert.equal(recoveredStale.operationId, staleOperationId);
        assert.equal(recoveredStale.status, 'completed');
        assert.deepEqual(recoveredStale.receipt, {
          version: 1, operationId: staleOperationId, kind: 'address.update', status: 'stale',
          result: staleResult.result, replayed: true });
        const staleOperations = await operationRows();
        assert.equal(staleOperations.length, editedOperations.length + 1);
        const staleRow = staleOperations.find(row => row.operation_id === staleOperationId);
        assert.ok(staleRow); assert.equal(staleRow.kind, 'address.update');
        assert.equal(staleRow.state, 'completed'); assert.equal(staleRow.proposal_json, null);
        assert.equal(staleRow.intent_sha256, commerceContract.digest(staleRow.request_json));
        assert.equal(staleRow.result_sha256, commerceContract.digest(staleRow.result_json));
        assert.equal(JSON.parse(staleRow.request_json).fieldsSha256, staleResult.result.fieldsSha256);
        assert.equal(Object.hasOwn(JSON.parse(staleRow.request_json), 'fields'), false);
        assert.deepEqual(JSON.parse(staleRow.result_json),
          Object.fromEntries(Object.entries(staleResult).filter(([key]) => key !== 'scopeKey')));
        const staleReplay = await composition.conversationalCommerce.saveAddress({ ...actor, args: staleArgs });
        assert.deepEqual(staleReplay, { ...staleResult, replayed: true });
        assert.deepEqual(await addressRows(), editedRows);
        assert.deepEqual(await operationRows(), staleOperations);
        assert.deepEqual(await auditRows(), auditBeforeStale); status.staleEditDenied = true;
        const resetResult = await reset.launchResetCoordinator.reset({ launchId: actor.scope.launchId,
          platformOwnerId: actor.scope.platformOwnerId, platformSessionId: actor.scope.platformSessionId,
          expectedGeneration: actor.scope.generation, idempotencyKey: randomUUID() });
        assert.equal(resetResult.status, 'committed');
        await assert.rejects(composition.conversationalCommerce.readOperation({ ...actor,
          args: { operationId: lostReceipt.operationId } }), error =>
          ['STALE_GENERATION', 'STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SHOP_SCENE_STALE',
            'PRODUCT_TARGET_UNAVAILABLE'].includes(error?.code));
        status.resetSessionDenied = true;
        assert.equal(status.chatTurns, 3);
        assert.ok(status.actualModelCalls >= 3 && status.actualModelCalls <= 12);
        if (interceptionFailure) throw interceptionFailure;
        const screenshot = path.join(path.dirname(receiptPath), 'customer-address-final.png');
        await page.screenshot({ path: screenshot, fullPage: true }); await fs.chmod(screenshot, 0o600);
        status.passed = true;
      } else if (PAYMENT_SETUP) {
        const methodRows = async () => (await review.query(`SELECT method_id,target_id,shop_user_id,scenario
          FROM secureshop_review.practice_payment_methods WHERE target_id=$1 AND shop_user_id=$2 ORDER BY method_id`,
        [target.targetId, actor.persona.id])).rows;
        const operationRows = async () => (await review.query(`SELECT * FROM secureshop_review.chat_commerce_operations
          WHERE target_id=$1 AND shop_user_id=$2 ORDER BY operation_id`, [target.targetId, actor.persona.id])).rows;
        const orderCount = async () => Number((await review.query(`SELECT count(*)::int AS n FROM
          secureshop_review.product_target_orders WHERE target_id=$1 AND shop_user_id=$2`,
        [target.targetId, actor.persona.id])).rows[0].n);
        const cartCount = async () => Number((await review.query(`SELECT count(*)::int AS n FROM
          secureshop_review.product_target_cart_items WHERE target_id=$1 AND shop_user_id=$2`,
        [target.targetId, actor.persona.id])).rows[0].n);
        assert.deepEqual(await methodRows(), []); assert.deepEqual(await operationRows(), []);
        assert.equal(await orderCount(), 0); assert.equal(await cartCount(), 0);
        const judgmentsBefore = Number((await identity.query(`SELECT count(*)::int AS n FROM
          secureshop_auth.assessment_judgments`)).rows[0].n);
        let frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        stage = 'payment-setup-model-handoff';
        const decisionStart = decisions.length;
        const handoffHTTP = page.waitForResponse(value =>
          /^\/api\/secureshop\/agents\/customer\/operations\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(new URL(value.url()).pathname)
          && value.request().method() === 'GET' && value.status() === 200,
        { timeout: 150000 }).then(value => ({ value }), error => ({ error }));
        const input = await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]', { visible: true });
        await input.type('Help me add a practice payment card for shopping.');
        await click(frame, 'Send to customer agent');
        const sent = await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return posts[0]; }, 'payment setup chat POST');
        assert.match(sent.sessionId, UUID); assert.match(sent.requestId, UUID);
        const saved = await waitFor(async () => {
          const row = (await agents.query(`SELECT status,result_json FROM secureshop_agents.turn_requests
            WHERE session_id=$1 AND request_id=$2`, [sent.sessionId, sent.requestId])).rows[0];
          if (row?.status === 'uncertain') throw Object.assign(Error('Payment setup turn uncertain'), { code: 'CHAT_TURN_UNCERTAIN' });
          return row?.status === 'completed' ? row.result_json : null;
        }, 'genuine payment setup turn', 150000);
        assert.equal(saved.stopReason, 'end_turn'); assert.ok(saved.text?.trim());
        assert.ok(decisions.slice(decisionStart).some(item => item.tools.includes('payment.create_method')));
        const preparedHop = saved.hops?.find(hop => hop.tool === 'payment.create_method' && !hop.error
          && hop.result?.isError !== true);
        assert.ok(preparedHop, 'a real model decision opened the no-effect setup');
        const setup = saved.taskMetadata?.customerChat?.paymentSetup;
        assert.deepEqual(setup, { version: 1, kind: 'practice_payment_setup',
          suggestedScenario: preparedHop.params.scenario });
        assert.ok(['approved', 'declined'].includes(setup.suggestedScenario));
        const handoffResponse = await readResponse(handoffHTTP);
        const handoff = await handoffResponse.json();
        assert.equal(new URL(handoffResponse.url()).pathname,
          `/api/secureshop/agents/customer/operations/${sent.sessionId}/${sent.requestId}`);
        assert.equal(handoff.status, 'completed'); assert.deepEqual(handoff.paymentSetup, setup);
        assert.equal(handoff.sessionId, sent.sessionId); assert.equal(handoff.requestId, sent.requestId);
        await frame.waitForFunction(() => document.querySelector('[aria-label="Practice payment setup"]')
          && [...document.querySelectorAll('[aria-label="Practice payment setup"] button')]
            .some(button => button.textContent.includes('Use approved practice payment'))
          && [...document.querySelectorAll('[aria-label="Practice payment setup"] button')]
            .some(button => button.textContent.includes('Use declined practice payment')));
        assert.deepEqual(await methodRows(), []); assert.deepEqual(await operationRows(), []);
        assert.equal(paymentCreates.length, 0); assert.equal(await orderCount(), 0); assert.equal(await cartCount(), 0);
        status.renderedPaymentSetupHandoff = true; status.noEffectBeforeConfirm = true;

        selectedPaymentScenario = setup.suggestedScenario === 'approved' ? 'declined' : 'approved';
        stage = 'trusted-payment-choice';
        await click(frame, selectedPaymentScenario === 'approved'
          ? 'Use approved practice payment' : 'Use declined practice payment');
        await frame.waitForFunction(() => [...document.querySelectorAll('[aria-label="Practice payment setup"] button')]
          .some(button => button.textContent.trim() === 'Create selected practice payment' && !button.disabled));
        assert.deepEqual(await methodRows(), []); assert.deepEqual(await operationRows(), []);
        status.renderedExplicitScenario = true;
        const beforeConfirm = path.join(path.dirname(receiptPath), 'customer-payment-setup-before-confirm.png');
        await page.screenshot({ path: beforeConfirm, fullPage: true }); await fs.chmod(beforeConfirm, 0o600);

        stage = 'trusted-payment-confirmation';
        cdp = await page.createCDPSession();
        const paymentEndpoint = `${origin}/api/secureshop/customer/commerce/payment-methods`;
        cdp.on('Fetch.requestPaused', event => {
          const work = (async () => {
            assert.equal(event.request.url, paymentEndpoint);
            if (event.request.method === 'GET') {
              await bounded(cdp.send('Fetch.continueRequest', { requestId: event.requestId }),
                'release practice payment scope read');
              return;
            }
            assert.equal(event.request.method, 'POST');
            assert.equal(event.responseStatusCode, 200);
            const raw = await bounded(cdp.send('Fetch.getResponseBody', { requestId: event.requestId }),
              'practice payment receipt body');
            const receipt = JSON.parse(Buffer.from(raw.body, raw.base64Encoded ? 'base64' : 'utf8').toString());
            assert.equal(receipt.version, 1); assert.equal(receipt.kind, 'payment.create');
            assert.equal(receipt.status, 'completed'); assert.equal(receipt.replayed, false);
            assert.deepEqual(JSON.parse(event.request.postData), {
              operationId: receipt.operationId, scenario: selectedPaymentScenario });
            lostReceipt = receipt; hidePaymentReads = true;
            await bounded(cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }),
              'drop committed practice payment response');
          })().catch(async error => {
            interceptionFailure ??= error;
            await bounded(cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }),
              'release failed payment capture').catch(() => {});
          });
          pendingInterceptions.add(work); void work.finally(() => pendingInterceptions.delete(work));
        });
        await cdp.send('Fetch.enable', { patterns: [{ urlPattern: paymentEndpoint, requestStage: 'Response' }] });
        await click(frame, 'Create selected practice payment');
        await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return lostReceipt; }, 'committed practice payment');
        await Promise.all([...pendingInterceptions]);
        await bounded(cdp.send('Fetch.disable'), 'disable practice payment fault');
        await bounded(cdp.detach(), 'detach practice payment fault'); cdp = null;
        assert.equal(paymentCreates.length, 1); assert.deepEqual(paymentCreates[0], {
          operationId: lostReceipt.operationId, scenario: selectedPaymentScenario });
        assert.deepEqual(expectedPayment, { version: 1, scopeKey: lostReceipt.scopeKey,
          operationId: lostReceipt.operationId, scenario: selectedPaymentScenario });
        assert.deepEqual(acknowledgedConfirms, [expectedPayment]);
        const methods = await methodRows(), operations = await operationRows();
        assert.equal(methods.length, 1); assert.equal(methods[0].scenario, selectedPaymentScenario);
        assert.equal(Number(methods[0].shop_user_id), actor.persona.id);
        assert.equal(methods[0].target_id, target.targetId);
        assert.equal(operations.length, 1); assert.equal(operations[0].operation_id, lostReceipt.operationId);
        assert.equal(operations[0].kind, 'payment.create'); assert.equal(operations[0].state, 'completed');
        assert.equal(operations[0].target_id, target.targetId);
        assert.equal(Number(operations[0].shop_user_id), actor.persona.id);
        assert.equal(operations[0].intent_sha256, commerceContract.digest(operations[0].request_json));
        assert.equal(operations[0].result_sha256, commerceContract.digest(operations[0].result_json));
        assert.deepEqual(JSON.parse(operations[0].request_json), {
          operationId: lostReceipt.operationId, scenario: selectedPaymentScenario, origin: null });
        const { scopeKey: committedScope, ...storedReceipt } = lostReceipt;
        assert.equal(committedScope, expectedPayment.scopeKey);
        assert.deepEqual(JSON.parse(operations[0].result_json), storedReceipt);
        assert.equal(storedReceipt.result.cards.length, 1);
        assert.equal(storedReceipt.result.cards[0].kind, 'payment_method');
        assert.equal(storedReceipt.result.cards[0].title,
          selectedPaymentScenario === 'approved' ? 'Practice card — approved' : 'Practice card — declined');
        assert.equal(await orderCount(), 0); assert.equal(await cartCount(), 0);
        status.renderedOneMethodReceipt = true;
        const siblingRead = await composition.conversationalCommerce.readOperation({ ...siblingActor,
          args: { operationId: lostReceipt.operationId } });
        assert.deepEqual(siblingRead, { scopeKey: siblingRead.scopeKey,
          operationId: lostReceipt.operationId, status: 'not_found' });
        assert.notEqual(siblingRead.scopeKey, committedScope); status.siblingMethodDenied = true;

        await frame.waitForFunction(() => [...document.querySelectorAll('[aria-label="Practice payment setup"] button')]
          .some(button => button.textContent.trim() === 'Check saved practice payment' && !button.disabled));
        const callsBeforeRecovery = status.actualModelCalls, turnsBeforeRecovery = posts.length;
        hidePaymentReads = false; stage = 'payment-exact-recovery';
        await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select');
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        await frame.waitForFunction(() => [...document.querySelectorAll('[aria-label="Practice payment setup"] button')]
          .some(button => button.textContent.trim() === 'Check saved practice payment' && !button.disabled));
        const recoveredHTTP = response(page,
          `/api/secureshop/customer/commerce/operations/${lostReceipt.operationId}`, 'GET');
        await click(frame, 'Check saved practice payment');
        const recovered = await readResponse(recoveredHTTP); assert.equal(recovered.status(), 200);
        const recoveredBody = await recovered.json();
        assert.equal(recoveredBody.scopeKey, committedScope); assert.equal(recoveredBody.status, 'completed');
        assert.equal(recoveredBody.operationId, lostReceipt.operationId);
        assert.equal(recoveredBody.paymentScenario, selectedPaymentScenario,
          'the protected operation readback binds the physically selected scenario');
        assert.notEqual(recoveredBody.paymentScenario, setup.suggestedScenario,
          'the trusted form choice remains independent of the model suggestion');
        assert.deepEqual(recoveredBody.receipt, { ...storedReceipt, replayed: true });
        assert.equal(status.actualModelCalls, callsBeforeRecovery); assert.equal(posts.length, turnsBeforeRecovery);
        assert.equal(paymentCreates.length, 1); assert.deepEqual(await methodRows(), methods);
        assert.deepEqual(await operationRows(), operations);
        assert.ok(faultedOperationReads.some(value => value.endsWith(`/${lostReceipt.operationId}`)));
        status.renderedLostAckExactRecovery = true;
        await frame.waitForFunction(title => document.querySelector('[aria-label="Current practice payment choices"]')
          ?.textContent.includes(title), {}, storedReceipt.result.cards[0].title);
        const listRead = await composition.conversationalCommerce.paymentMethods({ ...actor, args: {} });
        assert.equal(listRead.scopeKey, committedScope);
        assert.ok(listRead.cards.some(card => card.kind === 'payment_method'
          && card.title === storedReceipt.result.cards[0].title));
        status.renderedRefreshedMethodCard = true;
        assert.equal((await identity.query(`SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments`)).rows[0].n,
          judgmentsBefore);
        assert.equal(status.judgeCalls, 0); assert.equal(await orderCount(), 0); assert.equal(await cartCount(), 0);
        status.noOrderOrJudge = true;
        const resetResult = await reset.launchResetCoordinator.reset({ launchId: actor.scope.launchId,
          platformOwnerId: actor.scope.platformOwnerId, platformSessionId: actor.scope.platformSessionId,
          expectedGeneration: actor.scope.generation, idempotencyKey: randomUUID() });
        assert.equal(resetResult.status, 'committed');
        await assert.rejects(composition.conversationalCommerce.readOperation({ ...actor,
          args: { operationId: lostReceipt.operationId } }), error =>
          ['STALE_GENERATION', 'STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SHOP_SCENE_STALE',
            'PRODUCT_TARGET_UNAVAILABLE'].includes(error?.code));
        status.resetSessionDenied = true;
        assert.equal(status.chatTurns, 1); assert.ok(status.actualModelCalls >= 2 && status.actualModelCalls <= 4);
        if (interceptionFailure) throw interceptionFailure;
        const screenshot = path.join(path.dirname(receiptPath), 'customer-payment-setup-final.png');
        await page.screenshot({ path: screenshot, fullPage: true }); await fs.chmod(screenshot, 0o600);
        status.passed = true;
      } else if (OLDER_ORDERS) {
        stage = 'older-orders-controlled-seed';
        const product = (await review.query(`SELECT product_id,name FROM secureshop_review.product_target_products
          WHERE target_id=$1 AND status='active' ORDER BY product_id LIMIT 1`, [target.targetId])).rows[0];
        assert.ok(product, 'disposable older-order setup has an owned product snapshot');
        const timestamp = '2026-10-10T12:00:00.123456Z';
        const seedOrders = async (owner, count, label) => {
          const ids = [];
          for (let index = 1; index <= count; index++) {
            const amount = (20 + index / 100).toFixed(2);
            const row = (await pools.REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.product_target_orders
              (target_id,shop_user_id,total_amount,status,payment_method,payment_status,shipping_address,order_date)
              VALUES($1,$2,$3,$4,'synthetic practice card','approved',$5,$6::timestamptz) RETURNING order_id`,
            [target.targetId, owner, amount, index === 3 ? 'delivered' : 'confirmed',
              `${label} address ${index}`, timestamp])).rows[0];
            const orderId = Number(row?.order_id); assert.ok(Number.isSafeInteger(orderId) && orderId > 0);
            await pools.REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.product_target_order_items
              (target_id,order_id,product_id,product_name,quantity,price)
              VALUES($1,$2,$3,$4,1,$5)`,
            [target.targetId, orderId, product.product_id, `${label} item ${index}`, amount]);
            ids.push(orderId);
          }
          return ids;
        };
        const ownedOrderIds = await seedOrders(actor.persona.id, 15, 'Owned synthetic older order');
        const siblingOrderIds = await seedOrders(siblingActor.persona.id, 13, 'Sibling private order');
        const orderRows = async () => (await review.query(`SELECT o.target_id,o.shop_user_id,o.order_id,
          o.total_amount,o.status,o.payment_method,o.payment_status,o.shipping_address,
          to_char(o.order_date AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS order_date,
          i.product_id,i.product_name,i.quantity,i.price
          FROM secureshop_review.product_target_orders o
          JOIN secureshop_review.product_target_order_items i USING(target_id,order_id)
          WHERE o.target_id=$1 AND o.shop_user_id IN ($2,$3)
          ORDER BY o.shop_user_id,o.order_id`,
        [target.targetId, actor.persona.id, siblingActor.persona.id])).rows;
        const seededRows = await orderRows();
        assert.equal(seededRows.length, 28); status.controlledSeededOrderPages = true;
        const repository = composition.repositories.commerce.conversation;
        const authArgs = { shopUserId: actor.persona.id, personaSession: actor.personaSession, mode: 'vuln' };
        const siblingArgs = { shopUserId: siblingActor.persona.id,
          personaSession: siblingActor.personaSession, mode: 'vuln' };
        const controlledFirst = await repository.ordersList(target, authArgs);
        assert.deepEqual(controlledFirst.orders.map(row => Number(row.order_id)), ownedOrderIds.slice(3).reverse());
        assert.equal(controlledFirst.cards.length, 12); assert.match(controlledFirst.nextCursor, UUID);
        assert.equal(controlledFirst.cards.at(-1).title, `Order #${ownedOrderIds[3]}`);
        const controlledOlder = await repository.ordersList(target, { ...authArgs, cursor: controlledFirst.nextCursor });
        assert.deepEqual(controlledOlder.orders.map(row => Number(row.order_id)), ownedOrderIds.slice(0, 3).reverse());
        assert.equal(controlledOlder.nextCursor, null); status.stableTieTimestampKeyset = true;
        const siblingFirst = await repository.ordersList(target, siblingArgs);
        assert.equal(siblingFirst.orders.length, 12); assert.match(siblingFirst.nextCursor, UUID);
        await assert.rejects(repository.ordersList(target, { ...authArgs, cursor: siblingFirst.nextCursor }),
          { code: 'COMMERCE_CHOICE_DENIED' });
        const tamperedCursor = `${controlledFirst.nextCursor.slice(0, -1)}${controlledFirst.nextCursor.endsWith('a') ? 'b' : 'a'}`;
        assert.match(tamperedCursor, UUID); assert.notEqual(tamperedCursor, controlledFirst.nextCursor);
        await assert.rejects(repository.ordersList(target, { ...authArgs, cursor: tamperedCursor }),
          { code: 'COMMERCE_CHOICE_DENIED' });
        await pools.REVIEW_MIGRATION.query(`UPDATE secureshop_review.product_target_orders SET status='shipped'
          WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3`,
        [target.targetId, actor.persona.id, ownedOrderIds[3]]);
        await assert.rejects(repository.ordersList(target, { ...authArgs, cursor: controlledFirst.nextCursor }),
          { code: 'COMMERCE_CHOICE_STALE' });
        await pools.REVIEW_MIGRATION.query(`UPDATE secureshop_review.product_target_orders SET status='confirmed'
          WHERE target_id=$1 AND shop_user_id=$2 AND order_id=$3`,
        [target.targetId, actor.persona.id, ownedOrderIds[3]]);
        assert.deepEqual(await orderRows(), seededRows, 'controlled stale-cursor probe restores its synthetic row');
        status.foreignTamperedStaleCursorsDenied = true;

        const judgmentsBefore = Number((await identity.query(`SELECT count(*)::int AS n
          FROM secureshop_auth.assessment_judgments`)).rows[0].n);
        let frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        const send = async message => {
          const input = await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]', { visible: true });
          await input.type(message); await click(frame, 'Send to customer agent');
        };
        const completed = async (index, expectedTool, rendered = true) => {
          const sent = await waitFor(() => posts[index], `older-order chat turn ${index + 1}`);
          assert.match(sent.sessionId, UUID); assert.match(sent.requestId, UUID);
          const saved = await waitFor(async () => {
            const row = (await agents.query(`SELECT status,result_json FROM secureshop_agents.turn_requests
              WHERE session_id=$1 AND request_id=$2`, [sent.sessionId, sent.requestId])).rows[0];
            if (row?.status === 'uncertain') throw Error('Older-order chat was durably uncertain');
            return row?.status === 'completed' ? row.result_json : null;
          }, `genuine older-order chat turn ${index + 1}`, 150000);
          assert.equal(saved.stopReason, 'end_turn'); assert.ok(saved.text?.trim());
          assert.ok(decisions.some(item => item.requestId === sent.requestId && item.tools.includes(expectedTool)),
            `real model selected ${expectedTool}`);
          assert.ok(saved.hops?.some(hop => hop.tool === expectedTool && !hop.error && hop.result?.isError !== true),
            `real ${expectedTool} observation succeeded`);
          if (rendered) await frame.waitForFunction(text => [...document.querySelectorAll('[data-testid="agent-turn"]')]
            .at(-1)?.querySelector('[data-testid="agent-turn-reply"]')?.textContent?.trim() === text,
          { timeout: 30000 }, saved.text.trim());
          assert.deepEqual(acknowledgedChats[index], { sessionId: sent.sessionId, requestId: sent.requestId });
          return { sent, saved };
        };

        stage = 'older-orders-real-latest-page';
        // Lose both the post-terminal protected read and the hook's one
        // same-mount automatic retry. This keeps the parent-acknowledged
        // reference unresolved so a remount must recover this exact turn.
        olderReadFailuresRemaining = 2;
        await send('Show my latest orders so I can choose one.');
        const latest = await completed(0, 'orders.list', false);
        const latestMeta = latest.saved.taskMetadata?.customerChat;
        assert.deepEqual(latestMeta?.cards?.map(card => card.title),
          ownedOrderIds.slice(3).reverse().map(orderId => `Order #${orderId}`));
        assert.equal(latestMeta.cards.length, 12);
        assert.equal(latestMeta.cards.some(card => siblingOrderIds.includes(Number(card.title.slice(7)))), false);
        assert.deepEqual(latestMeta.orderPage, { nextCursor: latestMeta.cards.at(-1).choiceId });
        assert.equal(latestMeta.orderPage.nextCursor, controlledFirst.nextCursor,
          'actual owner page reuses the current opaque cursor for the same snapshot');
        status.renderedLatestOwnedOrderPage = true;
        const exactPath = `/agents/customer/operations/${latest.sent.sessionId}/${latest.sent.requestId}`;
        await waitFor(() => customerChatReads.filter(pathname => pathname === exactPath).length === 2,
          'two faulted exact latest-page GETs');
        assert.equal(olderReadFailuresRemaining, 0);
        await frame.waitForFunction(() => [...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Check saved chat'
            && !button.disabled && button.getClientRects().length));
        await frame.waitForFunction(() => [...document.querySelectorAll('[role="status"]')]
          .some(node => node.textContent.includes('This chat may have completed')));
        const retainedLatest = await page.evaluate(() => {
          const references = [];
          for (let index = 0; index < localStorage.length; index++) {
            const key = localStorage.key(index);
            if (!/^dvaia:secureshop:[a-f0-9-]{36}:[1-9]\d*(?::scene:[a-f0-9-]{36})?$/i.test(key || '')) continue;
            const snapshot = JSON.parse(localStorage.getItem(key));
            const raw = snapshot['secureshop.customer-chat.pending.v1'];
            if (raw) references.push(...JSON.parse(raw).references);
          }
          return references;
        });
        assert.deepEqual(retainedLatest.map(row => ({ shopUserId: row.shopUserId,
          sessionId: row.sessionId, requestId: row.requestId })), [{ shopUserId: actor.persona.id,
          sessionId: latest.sent.sessionId, requestId: latest.sent.requestId }]);
        const protectedLatest = await composition.customerChat.runtime.readRequest(actor.scope, actor.persona,
          actor.personaSession, latest.sent.sessionId, latest.sent.requestId);
        assert.deepEqual(protectedLatest.orderPage, latestMeta.orderPage);
        assert.deepEqual(protectedLatest.cards, latestMeta.cards);
        const readsBeforeReload = customerChatReads.length, callsBeforeReload = status.actualModelCalls;
        await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select');
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        await waitFor(() => customerChatReads.length > readsBeforeReload, 'reloaded exact latest-page GET');
        await frame.waitForFunction(() => [...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Older orders' && !button.disabled));
        assert.equal(status.actualModelCalls, callsBeforeReload); assert.equal(posts.length, 1);
        assert.deepEqual(customerChatReads.slice(-3), [exactPath, exactPath, exactPath]);
        status.protectedPageGetRecovery = true;

        stage = 'older-orders-real-physical-continuation';
        await click(frame, 'Older orders');
        const older = await completed(1, 'orders.list');
        assert.equal(older.sent.message, 'Show older orders'); assert.equal(older.sent.selection, undefined);
        const olderMeta = older.saved.taskMetadata?.customerChat;
        assert.deepEqual(older.saved.hops.find(hop => hop.tool === 'orders.list' && !hop.error)?.params,
          { cursor: latestMeta.orderPage.nextCursor });
        assert.deepEqual(olderMeta?.cards?.map(card => card.title),
          ownedOrderIds.slice(0, 3).reverse().map(orderId => `Order #${orderId}`));
        assert.deepEqual(olderMeta.orderPage, { nextCursor: null });
        await frame.waitForFunction(() => ![...document.querySelectorAll('button')]
          .some(button => button.textContent.trim() === 'Older orders'));
        status.renderedPhysicalOlderOrders = true;

        stage = 'older-orders-real-selected-detail';
        const selectedCard = olderMeta.cards[0];
        assert.equal(selectedCard.title, `Order #${ownedOrderIds[2]}`); assert.match(selectedCard.choiceId, UUID);
        await choose(frame, `View details: ${selectedCard.title}`);
        const selected = await completed(2, 'orders.details');
        assert.equal(selected.sent.message, 'Show this order’s details.');
        assert.deepEqual(selected.sent.selection, { choiceId: selectedCard.choiceId, intent: 'order_details' });
        const detailHop = selected.saved.hops.find(hop => hop.tool === 'orders.details' && !hop.error);
        assert.deepEqual(detailHop.params, { choiceId: selectedCard.choiceId });
        const observed = JSON.parse(detailHop.result.content.find(item => item.type === 'text').text);
        assert.equal(Number(observed.order.order_id), ownedOrderIds[2]);
        assert.equal(observed.order.status, 'delivered'); assert.equal(observed.order.payment_status, 'approved');
        assert.equal(observed.order.shipping_address, 'Owned synthetic older order address 3');
        assert.equal(observed.order.items[0].product_name, 'Owned synthetic older order item 3');
        assert.equal(Number(observed.order.total_amount), 20.03);
        assert.equal(observed.order.items[0].quantity, 1);
        assert.equal(Number(observed.order.items[0].price), 20.03);
        assert.ok(selected.saved.text.includes(`Order #${ownedOrderIds[2]}`)
          && selected.saved.text.toLowerCase().includes('delivered'),
        'genuine model summary identifies the physically selected older order and its truthful status');
        // The exact address and line item are rendered from the protected saved
        // orders.details observation beside the genuine model summary. This
        // deterministic presentation is not a mock or a substitute model reply.
        const renderedOrder = {
          heading: `Order #${ownedOrderIds[2]}`,
          placed: `Placed ${observed.order.order_date.slice(0, 10)} · delivered`,
          payment: 'Payment: approved · Total: $20.03',
          item: 'Owned synthetic older order item 3 · 1 × $20.03 each',
          address: 'Owned synthetic older order address 3',
        };
        await frame.waitForFunction(expected => {
          const panel = document.querySelector('[aria-label="Selected order details"]');
          if (!panel) return false;
          panel.scrollIntoView({ block: 'center' });
          const rect = panel.getBoundingClientRect();
          return rect.height > 0 && rect.bottom > 0 && rect.top < innerHeight
            && panel.querySelector('h3')?.textContent.trim() === expected.heading
            && [...panel.querySelectorAll('p')].some(node => node.textContent.trim() === expected.placed)
            && [...panel.querySelectorAll('p')].some(node => node.textContent.trim() === expected.payment)
            && [...panel.querySelectorAll('li')].some(node => node.textContent.trim() === expected.item)
            && [...panel.querySelectorAll('p')].some(node => node.textContent.trim() === expected.address);
        }, { timeout: 30000 }, renderedOrder);
        const screenshot = path.join(path.dirname(receiptPath), 'customer-older-orders-final.png');
        await page.screenshot({ path: screenshot, fullPage: true }); await fs.chmod(screenshot, 0o600);
        const protectedSelected = await composition.customerChat.runtime.readRequest(actor.scope, actor.persona,
          actor.personaSession, selected.sent.sessionId, selected.sent.requestId);
        assert.equal(protectedSelected.hops.some(hop => hop.tool === 'orders.details'
          && hop.params?.choiceId === selectedCard.choiceId), true);
        status.renderedSelectedOlderOrderDetail = true;
        assert.equal(latestMeta.cards.some(card => siblingOrderIds.includes(Number(card.title.slice(7)))), false);
        assert.equal(olderMeta.cards.some(card => siblingOrderIds.includes(Number(card.title.slice(7)))), false);
        status.siblingOrdersPrivate = true;
        assert.deepEqual(await orderRows(), seededRows, 'three read-only actor turns leave owned and sibling orders unchanged');
        status.readOnlyOrderRowsUnchanged = true;
        assert.equal((await identity.query(`SELECT count(*)::int AS n
          FROM secureshop_auth.assessment_judgments`)).rows[0].n, judgmentsBefore);
        assert.equal(status.judgeCalls, 0); status.noObjectiveCredit = true;
        assert.equal(status.chatTurns, 3); assert.ok(status.actualModelCalls >= 3 && status.actualModelCalls <= 15);

        stage = 'older-orders-reset-fence';
        const resetResult = await reset.launchResetCoordinator.reset({ launchId: actor.scope.launchId,
          platformOwnerId: actor.scope.platformOwnerId, platformSessionId: actor.scope.platformSessionId,
          expectedGeneration: actor.scope.generation, idempotencyKey: randomUUID() });
        assert.equal(resetResult.status, 'committed');
        await assert.rejects(composition.customerChat.runtime.readRequest(actor.scope, actor.persona,
          actor.personaSession, latest.sent.sessionId, latest.sent.requestId), error =>
          ['STALE_GENERATION', 'STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SHOP_SCENE_STALE',
            'PRODUCT_TARGET_UNAVAILABLE', 'CONVERSATION_UNAVAILABLE'].includes(error?.code));
        await assert.rejects(repository.ordersList(target, { ...authArgs, cursor: latestMeta.orderPage.nextCursor }),
          error => ['STALE_GENERATION', 'STALE_LAUNCH', 'LAUNCH_UNAVAILABLE', 'SHOP_SCENE_STALE',
            'PRODUCT_TARGET_UNAVAILABLE', 'COMMERCE_CHOICE_DENIED', 'COMMERCE_CHOICE_STALE'].includes(error?.code));
        status.resetSessionDenied = true;
        if (interceptionFailure) throw interceptionFailure;
        status.passed = true;
      } else if (REFUND_HANDOFF) {
        stage = 'refund-seeded-baseline';
        const ownedProduct = (await review.query(`SELECT product_id,name,price FROM secureshop_review.product_target_products
          WHERE target_id=$1 AND status='active' ORDER BY product_id LIMIT 1`, [target.targetId])).rows[0];
        const peerTarget = await composition.catalog.prepareTarget(siblingActor);
        const peerProduct = (await review.query(`SELECT product_id,name,price FROM secureshop_review.product_target_products
          WHERE target_id=$1 AND status='active' ORDER BY product_id LIMIT 1`, [peerTarget.targetId])).rows[0];
        assert.ok(ownedProduct && peerProduct, 'disposable order setup has both owned product snapshots');
        const seedOrder = async (binding, owner, product, address) => {
          const inserted = (await pools.REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.product_target_orders
            (target_id,shop_user_id,total_amount,payment_method,shipping_address)
            VALUES($1,$2,$3,'synthetic practice card',$4) RETURNING order_id`,
          [binding.targetId, owner, product.price, address])).rows[0];
          assert.ok(inserted); const orderId = Number(inserted.order_id);
          assert.ok(Number.isSafeInteger(orderId) && orderId > 0 && orderId <= 2147483647);
          await pools.REVIEW_MIGRATION.query(`INSERT INTO secureshop_review.product_target_order_items
            (target_id,order_id,product_id,product_name,quantity,price) VALUES($1,$2,$3,$4,1,$5)`,
          [binding.targetId, orderId, product.product_id, product.name, product.price]);
          return orderId;
        };
        seededRefundOrderId = await seedOrder(target, actor.persona.id, ownedProduct, 'Owned synthetic refund address');
        const siblingOrderId = await seedOrder(peerTarget, siblingActor.persona.id, peerProduct, 'Sibling synthetic refund address');
        const seededOrders = (await review.query(`SELECT target_id,shop_user_id,order_id,status,payment_status
          FROM secureshop_review.product_target_orders WHERE target_id IN ($1,$2) ORDER BY target_id,order_id`,
        [target.targetId, peerTarget.targetId])).rows;
        assert.equal(seededOrders.length, 2);
        const tickets = async () => (await review.query(`SELECT ticket_id,target_id,shop_user_id,order_id,request_id,reason,status
          FROM secureshop_review.product_target_refund_requests WHERE target_id IN ($1,$2) ORDER BY target_id,ticket_id`,
        [target.targetId, peerTarget.targetId])).rows;
        assert.deepEqual(await tickets(), []);
        status.seededOwnedOrder = true;
        const judgmentsBefore = Number((await identity.query('SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments')).rows[0].n);
        let frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
        await frame.select('[data-testid="agent-lane"] select', 'chat');
        const send = async message => {
          const input = await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]', { visible: true });
          await input.type(message); await click(frame, 'Send to customer agent');
        };
        const completed = async (index, expectedTool) => {
          const sent = await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return posts[index]; }, 'refund handoff chat POST');
          assert.match(sent.sessionId, UUID); assert.match(sent.requestId, UUID);
          const saved = await waitFor(async () => {
            const row = (await agents.query(`SELECT status,result_json FROM secureshop_agents.turn_requests
              WHERE session_id=$1 AND request_id=$2`, [sent.sessionId, sent.requestId])).rows[0];
            if (row?.status === 'uncertain') throw Error('Refund handoff chat was durably uncertain');
            return row?.status === 'completed' ? row.result_json : null;
          }, 'real refund handoff turn completion', 150000);
          assert.equal(saved.stopReason, 'end_turn'); assert.ok(saved.text?.trim());
          assert.ok(decisions.some(item => item.requestId === sent.requestId && item.tools.includes(expectedTool)),
            `real model selected ${expectedTool}`);
          assert.ok(saved.hops?.some(hop => hop.tool === expectedTool && !hop.error && hop.result?.isError !== true),
            `real ${expectedTool} observation succeeded`);
          await frame.waitForFunction(text => [...document.querySelectorAll('[data-testid="agent-turn"]')]
            .at(-1)?.querySelector('[data-testid="agent-turn-reply"]')?.textContent?.trim() === text,
          { timeout: 30000 }, saved.text.trim());
          assert.deepEqual(acknowledgedChats[index], { sessionId: sent.sessionId, requestId: sent.requestId });
          return { sent, saved };
        };
        stage = 'refund-model-owned-order-list';
        await send('I want to request a refund for one of my orders. Show my orders so I can select the right one; I will enter the reason myself.');
        const listed = await completed(0, 'orders.list');
        const orderCard = listed.saved.taskMetadata?.customerChat?.cards?.find(card =>
          card.kind === 'order' && card.title === `Order #${seededRefundOrderId}`);
        assert.ok(orderCard && UUID.test(orderCard.choiceId), 'real owned order list produced a selectable card');
        assert.equal(listed.saved.taskMetadata.customerChat.cards.some(card => card.title === `Order #${siblingOrderId}`),
          false, 'sibling order is not in the owner choice set');
        status.renderedOwnedOrderChoice = true;
        stage = 'refund-model-selected-handoff';
        await choose(frame, `Choose order: ${orderCard.title}`);
        const selected = await completed(1, 'orders.refund_setup');
        const setup = { version: 1, kind: 'refund_setup', choiceId: orderCard.choiceId,
          orderId: seededRefundOrderId };
        assert.deepEqual(selected.saved.taskMetadata?.customerChat?.refundSetup, setup);
        assert.ok(selected.saved.hops.some(hop => hop.tool === 'orders.refund_setup'
          && hop.params?.choiceId === orderCard.choiceId));
        const savedTurn = await composition.customerChat.runtime.readRequest(actor.scope, actor.persona,
          actor.personaSession, selected.sent.sessionId, selected.sent.requestId);
        assert.deepEqual(savedTurn.refundSetup, setup, 'exact protected GET retains the genuine handoff');
        await frame.waitForFunction(() => [...document.querySelectorAll('a')]
          .some(link => link.textContent.trim() === 'Review refund request in Orders' && link.getClientRects().length));
        status.renderedRefundSetupHandoff = true;
        assert.deepEqual(await tickets(), [], 'model handoff has no refund ticket or order mutation');
        status.zeroTicketBeforeConfirm = true;
        stage = 'refund-trusted-order-review';
        await frame.waitForFunction(() => [...document.querySelectorAll('a')]
          .find(link => link.textContent.trim() === 'Review refund request in Orders' && link.getClientRects().length))
          .then(handle => handle.asElement().click());
        frame = await frameFor(page);
        await frame.waitForFunction(orderId => [...document.querySelectorAll('[role="dialog"]')]
          .some(dialog => dialog.getClientRects().length && getComputedStyle(dialog).visibility !== 'hidden'
            && dialog.querySelector('h2')?.textContent.trim() === `Order #${orderId}`),
        { timeout: 30000 }, seededRefundOrderId);
        const reason = 'The item did not meet my needs';
        const reasonInput = await frame.waitForSelector('#ss-refund-reason', { visible: true });
        await reasonInput.type(reason);
        assert.deepEqual(await tickets(), [], 'typing a reason does not file a ticket');
        status.renderedExplicitRefundRequest = true;
        stage = 'refund-trusted-request';
        refundReadFailuresRemaining = 2;
        await click(frame, 'Request refund');
        const submitted = await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return refundPosts[0]; }, 'trusted refund agent POST');
        assert.match(submitted.sessionId, UUID); assert.match(submitted.requestId, UUID);
        assert.ok(submitted.message.includes(`order ${seededRefundOrderId}`) && submitted.message.includes(reason),
          'the physical form sends the customer-entered reason for this owned order');
        assert.equal(refundPosts.length, 1); assert.deepEqual(acknowledgedRefunds[0], {
          sessionId: submitted.sessionId, requestId: submitted.requestId, orderId: seededRefundOrderId });
        const ticket = await waitFor(async () => (await tickets()).find(row => row.target_id === target.targetId),
          'durable owned refund ticket', 150000);
        assert.equal(Number(ticket.shop_user_id), actor.persona.id);
        assert.equal(Number(ticket.order_id), seededRefundOrderId);
        assert.equal(ticket.request_id, submitted.requestId);
        assert.equal(ticket.status, 'open');
        assert.equal((await tickets()).length, 1, 'sibling has no refund effect');
        const refundDecision = decisions.filter(item => item.requestId === submitted.requestId);
        assert.ok(refundDecision.some(item => item.tools.includes('support.order_status')));
        assert.ok(refundDecision.some(item => item.tools.includes('support.refund_request')));
        const refundTurn = await waitFor(async () => {
          const row = (await agents.query(`SELECT status,result_json FROM secureshop_agents.turn_requests
            WHERE session_id=$1 AND request_id=$2`, [submitted.sessionId, submitted.requestId])).rows[0];
          return row?.status === 'completed' ? row.result_json : null;
        }, 'durable actual refund-agent turn', 150000);
        const refundHop = refundTurn.hops?.find(hop => hop.tool === 'support.refund_request'
          && !hop.error && hop.result?.isError !== true);
        assert.ok(refundHop, 'the actual refund tool completed after the owned status observation');
        assert.equal(refundHop.params.order_id, seededRefundOrderId);
        assert.equal(refundHop.params.reason, reason,
          'the actual model selected the exact customer-entered refund reason');
        assert.equal(ticket.reason, refundHop.params.reason, 'ticket stores the actual model-selected reason');
        status.renderedOneOwnedTicket = true;
        await waitFor(() => refundReads.length === 2, 'two immediate saved refund GET acknowledgements');
        const savedOperationPath = `/agents/customer/refund/operations/${submitted.sessionId}/${submitted.requestId}`;
        assert.deepEqual(refundReads, [savedOperationPath, savedOperationPath],
          'both immediate lost read acknowledgements target the exact durable refund operation');
        await frame.waitForFunction(orderId => [...document.querySelectorAll('[role="dialog"]')]
          .some(dialog => dialog.getClientRects().length && getComputedStyle(dialog).visibility !== 'hidden'
            && dialog.querySelector('h2')?.textContent.trim() === `Order #${orderId}`
            && dialog.textContent.includes('Refund outcome unconfirmed')),
        { timeout: 30000 }, seededRefundOrderId);
        assert.equal(refundReadFailuresRemaining, 0);
        stage = 'refund-exact-get-recovery';
        const modelBefore = status.actualModelCalls, refundModelBefore = status.refundModelCalls;
        const chatBefore = posts.length, refundBefore = refundPosts.length;
        await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
        await frame.waitForFunction(() => [...document.querySelectorAll('a')]
          .some(link => link.getAttribute('href') === '/secureshop/orders' && link.getClientRects().length));
        await frame.waitForFunction(() => [...document.querySelectorAll('a')]
          .find(link => link.getAttribute('href') === '/secureshop/orders' && link.getClientRects().length))
          .then(handle => handle.asElement().click());
        await frame.waitForFunction(orderId => [...document.querySelectorAll('tr')]
          .some(row => row.textContent.includes(`#${orderId}`) && row.textContent.includes('View')),
        { timeout: 30000 }, seededRefundOrderId);
        const ownedDialogOpen = await frame.evaluate(orderId => [...document.querySelectorAll('[role="dialog"]')]
          .some(dialog => dialog.getClientRects().length && getComputedStyle(dialog).visibility !== 'hidden'
            && dialog.querySelector('h2')?.textContent.trim() === `Order #${orderId}`), seededRefundOrderId);
        if (!ownedDialogOpen) await click(frame, 'View');
        const savedPath = `/api/secureshop/agents/customer/refund/operations/${submitted.sessionId}/${submitted.requestId}`;
        const recoveredHTTP = response(page, savedPath, 'GET');
        await click(frame, 'Check saved refund');
        const recoveredResponse = await readResponse(recoveredHTTP);
        assert.equal(recoveredResponse.status(), 200);
        assert.deepEqual(await recoveredResponse.json(), { requestId: submitted.requestId, status: 'saved',
          ticketId: String(ticket.ticket_id), orderId: seededRefundOrderId });
        await frame.waitForFunction(({ orderId, ticketId }) => [...document.querySelectorAll('[role="dialog"]')]
          .some(dialog => dialog.getClientRects().length && getComputedStyle(dialog).visibility !== 'hidden'
            && dialog.querySelector('h2')?.textContent.trim() === `Order #${orderId}`
            && dialog.textContent.includes(`Refund request filed · ticket #${ticketId}`)),
        { timeout: 30000 }, { orderId: seededRefundOrderId, ticketId: String(ticket.ticket_id) });
        assert.deepEqual(refundReads, [savedOperationPath, savedOperationPath, savedOperationPath],
          'manual recovery performs one further GET of the exact saved operation');
        assert.equal(posts.length, chatBefore); assert.equal(refundPosts.length, refundBefore);
        assert.equal(status.actualModelCalls, modelBefore); assert.equal(status.refundModelCalls, refundModelBefore);
        assert.equal((await tickets()).length, 1);
        status.renderedLostAckGetRecovery = true;
        await assert.rejects(composition.refund.runtime.readRequest(siblingActor.scope, siblingActor.persona,
          siblingActor.personaSession, submitted.sessionId, submitted.requestId),
        { code: 'CONVERSATION_UNAVAILABLE' });
        status.siblingRefundPrivate = true;
        assert.deepEqual((await review.query(`SELECT target_id,shop_user_id,order_id,status,payment_status
          FROM secureshop_review.product_target_orders WHERE target_id IN ($1,$2) ORDER BY target_id,order_id`,
        [target.targetId, peerTarget.targetId])).rows, seededOrders, 'refund ticket does not change either order');
        assert.equal((await identity.query('SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments')).rows[0].n,
          judgmentsBefore);
        assert.equal(status.judgeCalls, 0); status.noOrderOrJudgeEffect = true;
        assert.equal(status.chatTurns, 2); assert.ok(status.actualModelCalls >= 2 && status.actualModelCalls <= 8);
        assert.ok(status.refundModelCalls >= 2 && status.refundModelCalls <= 6);
        if (interceptionFailure) throw interceptionFailure;
        const screenshot = path.join(path.dirname(receiptPath), 'customer-refund-handoff-final.png');
        await page.screenshot({ path: screenshot, fullPage: true }); await fs.chmod(screenshot, 0o600);
        status.passed = true;
      } else {
      const home = { label: 'Home', line1: '14 Practice Lane', line2: 'Unit 2', city: 'Testville',
        state: 'CA', zip: '90001', phone: null, isDefault: true };
      await composition.account.createAddress({ ...actor, address: home });
      await composition.account.createAddress({ ...actor, address: { ...home, label: 'Office', line1: '82 Training Road', isDefault: false } });
      await composition.account.createAddress({ ...siblingActor, address: { ...home, label: 'Sibling private address' } });
      for (const scenario of ['approved', 'declined']) await composition.conversationalCommerce.createPaymentMethod({
        ...actor, args: { operationId: randomUUID(), scenario } });
      const product = (await review.query(`SELECT product_id,name,price,stock_quantity FROM secureshop_review.product_target_products
        WHERE target_id=$1 AND status='active' AND stock_quantity>=2
        AND (NOT $2::boolean OR retailer_id=$3) ORDER BY product_id LIMIT 1`,
      [target.targetId, CHECKOUT_FENCES, merchantActor.user.id])).rows[0];
      assert.ok(product); await composition.commerce.add({ ...actor, productId: Number(product.product_id), quantity: 1 });
      const addresses = await composition.conversationalCommerce.addresses({ ...actor, args: {} });
      const payments = await composition.conversationalCommerce.paymentMethods({ ...actor, args: {} });
      const ownHome = addresses.cards.find(card => card.title === 'Home'); assert.ok(ownHome);
      const approvedCard = payments.cards.find(card => card.title === 'Practice card — approved'); assert.ok(approvedCard);
      const peerAddresses = await composition.conversationalCommerce.addresses({ ...siblingActor, args: {} });
      const siblingBefore = await composition.account.addresses(siblingActor);
      const snapshot = async () => ({
        cart: (await review.query('SELECT * FROM secureshop_review.product_target_cart_items WHERE target_id=$1 AND shop_user_id=$2 ORDER BY cart_item_id', [target.targetId, actor.persona.id])).rows,
        stock: (await review.query('SELECT product_id,stock_quantity FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id', [target.targetId])).rows,
        overlays: (await review.query('SELECT product_id,stock_quantity FROM secureshop_review.product_target_listing_overlays WHERE target_id=$1 ORDER BY product_id', [target.targetId])).rows,
        orders: (await review.query('SELECT * FROM secureshop_review.product_target_orders WHERE target_id=$1 AND shop_user_id=$2 ORDER BY order_id', [target.targetId, actor.persona.id])).rows,
      });
      const baseline = await snapshot(); assert.equal(baseline.cart.length, 1); assert.equal(baseline.orders.length, 0);
      // Preflight sibling confidentiality before spending any model calls. Seed
      // one owner-bound, zero-effect proposal and require the production
      // read-only composition to project it as indistinguishable from absence
      // to the sibling's current authority.
      const commerceRepository = composition.repositories.commerce.conversation;
      stage = 'pre-model-owned-orders-read';
      const emptyOrders = await commerceRepository.ordersList(target, { shopUserId: actor.persona.id,
        personaSession: actor.personaSession, mode: 'vuln' });
      assert.match(emptyOrders.scopeKey, SHA);
      assert.deepEqual(emptyOrders.orders, []);
      assert.deepEqual(emptyOrders.cards, []);
      assert.equal(emptyOrders.nextCursor, null);
      assert.deepEqual(await snapshot(), baseline, 'owned order read has no commerce effect');
      const seededCards = await commerceRepository.search(target, { shopUserId: actor.persona.id,
        personaSession: actor.personaSession, mode: 'vuln', search: product.name });
      const seededProduct = seededCards.cards.find(card => card.kind === 'product' && card.title === product.name);
      assert.ok(seededProduct, 'controlled sibling preflight seeds an owner-bound current product choice');
      const siblingProbeOperationId = randomUUID();
      const seededProbe = await commerceRepository.prepareCart(target, { shopUserId: actor.persona.id,
        personaSession: actor.personaSession, mode: 'vuln', operationId: siblingProbeOperationId,
        action: 'add', choiceId: seededProduct.choiceId, quantity: 1 });
      assert.equal(seededProbe.status, 'prepared'); assert.equal(seededProbe.proposalId, siblingProbeOperationId);
      const siblingProbe = await composition.conversationalCommerce.readOperation({ ...siblingActor,
        args: { operationId: siblingProbeOperationId } });
      assert.deepEqual(siblingProbe, { scopeKey: siblingProbe.scopeKey,
        operationId: siblingProbeOperationId, status: 'not_found' });
      assert.deepEqual(await snapshot(), baseline, 'sibling read denial preflight has no cart, stock, or order effect');
      if (CART_LIFECYCLE) status.siblingCartOperationDenied = true;
      const deniedOperationId = randomUUID();
      // The canonical cross-store fence deliberately preserves uncertainty after
      // callback admission; only exact authoritative readback can settle it.
      await assert.rejects(composition.conversationalCommerce.prepareCheckout({ ...actor,
        args: { operationId: deniedOperationId, addressChoiceId: peerAddresses.cards[0].choiceId,
          paymentChoiceId: approvedCard.choiceId } }), error => {
        assert.equal(error.code, 'PERSONA_EFFECT_OUTCOME_UNCERTAIN');
        assert.equal(error.executionBoundary, true); assert.equal(error.effectCallbackCompleted, false);
        assert.equal(error.cause?.code, 'COMMERCE_CHOICE_DENIED'); return true;
      });
      const deniedRead = await composition.conversationalCommerce.readOperation({ ...actor,
        args: { operationId: deniedOperationId } });
      assert.match(deniedRead.scopeKey, SHA);
      assert.deepEqual(deniedRead, { scopeKey: deniedRead.scopeKey, operationId: deniedOperationId, status: 'not_found' });
      for (const table of ['chat_commerce_operations', 'bound_commerce_operations']) {
        assert.equal((await review.query(`SELECT count(*)::int AS n FROM secureshop_review.${table} WHERE operation_id=$1`,
          [deniedOperationId])).rows[0].n, 0);
      }
      assert.deepEqual(await snapshot(), baseline);
      assert.deepEqual(await composition.account.addresses(siblingActor), siblingBefore);
      if (!CART_LIFECYCLE && !CHECKOUT_FENCES) status.siblingChoicesDenied = true;
      const judgmentsBefore = (await identity.query('SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments')).rows[0].n;
      let frame = await frameFor(page);
      await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
      await frame.select('[data-testid="agent-lane"] select', 'chat');
      async function runTurn(action, expectedTools) {
        const index = posts.length, decisionStart = decisions.length;
        // SSE/DB completion is not the trusted UI handoff. Await the exact
        // protected saved result as well, attaching rejection immediately.
        const completedRead = CHECKOUT_FENCES ? checkoutResponse(page, value => {
          const pathname = new URL(value.url()).pathname;
          return value.request().method() === 'GET'
            && /^\/api\/secureshop\/agents\/customer\/operations\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/.test(pathname);
        }, 180000) : null;
        await action();
        const sent = await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return posts[index]; }, 'chat POST');
        assert.equal(posts.length, index + 1); assert.match(sent.requestId, UUID); assert.match(sent.sessionId, UUID);
        const observation = { stage, requestId: sent.requestId, status: 'not_observed', finishedAt: null };
        turnObservations.push(observation);
        const saved = await waitFor(async () => {
          const row = (await agents.query('SELECT status,result_json,finished_at FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2', [sent.sessionId, sent.requestId])).rows[0];
          observation.status = row?.status || 'not_observed'; observation.finishedAt = row?.finished_at || null;
          if (row?.status === 'uncertain') throw Object.assign(new Error('Chat turn is durably uncertain; effects require exact readback'),
            { code: 'CHAT_TURN_UNCERTAIN' });
          if (row && !['started', 'completed'].includes(row.status)) throw Object.assign(new Error('Unexpected chat journal state'),
            { code: 'CHAT_TURN_STATE_INVALID' });
          return row?.status === 'completed' ? row.result_json : null;
        }, 'genuine chat completion', 150000);
        // Private failure-only evidence from this synthetic fixture. Never copy
        // request headers, authentication, raw private proposals or form inputs.
        completedTurns.push({ requestId: sent.requestId, stopReason: saved.stopReason,
          text: String(saved.text || '').slice(0, 8192),
          hops: (saved.hops || []).slice(0, 4).map(hop => ({ step: hop.step, tool: hop.tool,
            args: Object.fromEntries(Object.entries(hop.params || {}).filter(([key]) =>
              ['search', 'choiceId', 'addressChoiceId', 'paymentChoiceId', 'quantity', 'scenario'].includes(key))
              .map(([key, value]) => [key, typeof value === 'string' ? value.slice(0, 256) : value])),
            ...(hop.tool === 'orders.list' && hop.result?.isError === true
              ? { originalOrdersListArguments: privateOrdersListArguments(hop.params) } : {}),
            errorCode: hop.error?.code || null, isError: hop.result?.isError === true,
            ...(hop.result?.isError === true ? {
              originalError: privateToolFailureText(hop.error?.message),
              originalResult: privateToolFailureText((Array.isArray(hop.result?.content)
                ? hop.result.content : []).find(item => item?.type === 'text')?.text),
            } : {}) })) });
        assert.equal(saved.stopReason, 'end_turn'); assert.ok(saved.text?.trim());
        if (completedRead) {
          const { value: http, body: returned } = await readResponse(completedRead); assert.equal(http.status(), 200);
          assert.equal(new URL(http.url()).pathname,
            `/api/secureshop/agents/customer/operations/${sent.sessionId}/${sent.requestId}`);
          assert.equal(returned.sessionId, sent.sessionId); assert.equal(returned.requestId, sent.requestId);
          assert.equal(returned.status, 'completed'); assert.equal(returned.replayed, true);
          assert.equal(returned.stopReason, 'end_turn'); assert.equal(returned.text, saved.text);
        }
        for (const tool of expectedTools) {
          assert.ok(decisions.slice(decisionStart).some(item => item.tools.includes(tool)), `real model selected ${tool}`);
          assert.ok(saved.hops?.some(hop => hop.tool === tool && !hop.error && hop.result?.isError !== true),
            `real selected tool completed ${tool}`);
        }
        await frame.waitForFunction(text => {
          const turns = [...document.querySelectorAll('[data-testid="agent-turn"]')];
          return turns.at(-1)?.querySelector('[data-testid="agent-turn-reply"]')?.textContent?.trim() === text
            && [...document.querySelectorAll('button')].some(button => button.textContent.trim() === 'Send to customer agent')
            && ![...document.querySelectorAll('button')].some(button => ['Working…', 'Check saved chat'].includes(button.textContent.trim()));
        }, { timeout: 30000 }, saved.text.trim());
        assert.deepEqual(acknowledgedChats[index], { sessionId: sent.sessionId, requestId: sent.requestId });
        return { sent, saved };
      }
      const send = async message => {
        const input = await frame.waitForSelector('textarea[placeholder="Find a laptop for coding"]', { visible: true });
        await input.type(message); await click(frame, 'Send to customer agent');
      };
      const operationFor = async turn => {
        const rows = (await review.query(`SELECT * FROM secureshop_review.chat_commerce_operations WHERE target_id=$1 AND shop_user_id=$2
          AND kind='checkout' AND request_json::jsonb->'origin'->>'turnSessionId'=$3
          AND request_json::jsonb->'origin'->>'turnRequestId'=$4`, [target.targetId, actor.persona.id, turn.sent.sessionId, turn.sent.requestId])).rows;
        assert.equal(rows.length, 1); assert.equal(rows[0].state, 'prepared'); assert.equal(rows[0].result_json, null);
        const intent = JSON.parse(rows[0].request_json);
        assert.equal(require('../../server/services/secureshopConversationalCommerceContract').operationIdForOrigin(intent.origin), rows[0].operation_id);
        const read = await composition.conversationalCommerce.readOperation({ ...actor, args: { operationId: rows[0].operation_id } });
        assert.equal(read.status, 'prepared'); assert.equal(read.proposal.address.choiceId, ownHome.choiceId);
        assert.equal(read.proposal.items.length, 1); assert.equal(read.proposal.items[0].productId, Number(product.product_id));
        assert.equal(read.proposal.items[0].quantity, 1);
        return read.proposal;
      };
      if (CART_LIFECYCLE) {
        const cartRows = async () => (await review.query(`SELECT cart_item_id,product_id,quantity FROM
          secureshop_review.product_target_cart_items WHERE target_id=$1 AND shop_user_id=$2 ORDER BY cart_item_id`,
        [target.targetId, actor.persona.id])).rows;
        const assertRenderedCartParity = async (card, expectedRows) => {
          assert.equal(expectedRows.length, 1, 'this bounded qualification uses one selected cart line');
          const expected = (await review.query(`SELECT p.product_id,COALESCE(o.price,p.price) AS price
            FROM secureshop_review.product_target_products p
            LEFT JOIN secureshop_review.product_target_listing_overlays o
              ON o.target_id=p.target_id AND o.product_id=p.product_id
            WHERE p.target_id=$1 AND p.product_id=$2`, [target.targetId, expectedRows[0].product_id])).rows[0];
          assert.ok(expected); const quantity = Number(expectedRows[0].quantity), price = Number(expected.price);
          const detail = `${quantity} in cart · USD ${price.toFixed(2)} each`;
          assert.equal(card.detail, detail, 'the completed cart.view card reports the current selected-line quantity');
          await frame.waitForFunction(({ choiceId, title, detail }) => {
            const node = document.getElementById(`cart-item-quantity-${choiceId}`)?.closest('article');
            return node?.textContent.includes(title) && node.textContent.includes(detail)
              && ['Update quantity', 'Remove from cart'].every(action => [...node.querySelectorAll('button[aria-label]')]
                .some(button => button.getAttribute('aria-label') === `${action}: ${title}`
                  && button.getClientRects().length && !button.disabled));
          }, { timeout: 30000 }, { choiceId: card.choiceId, title: card.title, detail });
          const server = await frame.evaluate(async () => {
            const response = await fetch('/api/secureshop/cart', { headers: { accept: 'application/json' } });
            return { status: response.status, body: await response.json() };
          });
          assert.equal(server.status, 200);
          assert.equal(server.body.items.length, 1);
          const line = server.body.items[0];
          assert.equal(Number(line.product_id), Number(expected.product_id));
          assert.equal(Number(line.quantity), quantity); assert.equal(Number(line.price), price);
          const cents = value => {
            const parts = /^(\d+)(?:\.(\d{1,2}))?$/.exec(String(value));
            assert.ok(parts, 'currency must have at most two decimal places');
            return BigInt(parts[1]) * 100n + BigInt((parts[2] || '').padEnd(2, '0'));
          };
          const recalculatedSubtotal = server.body.items.reduce((sum, item) => sum + cents(item.price) * BigInt(item.quantity), 0n);
          assert.equal(cents(server.body.subtotal), recalculatedSubtotal, 'server subtotal is recalculated from authoritative cart lines');
          if (Object.hasOwn(server.body, 'total')) {
            assert.equal(cents(server.body.total), recalculatedSubtotal - cents(server.body.discount || 0),
              'server total equals authoritative subtotal less its declared discount');
          }
        };
        const cartOperationFor = async (turn, kind) => {
          const rows = (await review.query(`SELECT operation_id,state,result_json,proposal_json,proposal_sha256,request_json
            FROM secureshop_review.chat_commerce_operations WHERE target_id=$1 AND shop_user_id=$2 AND kind=$3
              AND request_json::jsonb->'origin'->>'turnSessionId'=$4
              AND request_json::jsonb->'origin'->>'turnRequestId'=$5`,
          [target.targetId, actor.persona.id, kind, turn.sent.sessionId, turn.sent.requestId])).rows;
          assert.equal(rows.length, 1); assert.equal(rows[0].state, 'prepared'); assert.equal(rows[0].result_json, null);
          assert.ok(rows[0].proposal_json); assert.match(rows[0].proposal_sha256, SHA);
          const intent = JSON.parse(rows[0].request_json);
          assert.equal(commerceContract.operationIdForOrigin(intent.origin), rows[0].operation_id);
          const privateProposal = JSON.parse(rows[0].proposal_json);
          // The database row retains the private selection snapshot; the public
          // operation API intentionally projects only its closed cart proposal.
          assert.equal(commerceContract.digest(rows[0].proposal_json), rows[0].proposal_sha256);
          const expectedPublic = commerceContract.cartProposal({ version: 1, proposalId: rows[0].operation_id,
            status: 'prepared', kind: privateProposal.kind, choice: privateProposal.choice,
            quantity: privateProposal.quantity, quoteSha256: commerceContract.digest(privateProposal) });
          const read = await composition.conversationalCommerce.readOperation({ ...actor, args: { operationId: rows[0].operation_id } });
          assert.equal(read.status, 'prepared'); assert.equal(read.operationId, rows[0].operation_id);
          assert.equal(read.proposal.kind, kind); assert.deepEqual(read.proposal, expectedPublic);
          return { proposal: read.proposal, row: rows[0] };
        };
        const assertCartProposal = async (proposal, kind, expectedQuantity, beforeRows) => {
          assert.equal(proposal.kind, kind); assert.equal(proposal.quantity, expectedQuantity);
          assert.match(proposal.proposalId, UUID); assert.match(proposal.quoteSha256, SHA);
          assert.deepEqual(await cartRows(), beforeRows, 'model preparation has zero cart effect');
        };
        const completedCartOperation = async (prepared, expectedRows, expectedKind) => {
          const rows = (await review.query(`SELECT operation_id,state,proposal_json,proposal_sha256,result_json,result_sha256
            FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1`, [prepared.proposalId])).rows;
          assert.equal(rows.length, 1); const row = rows[0];
          assert.equal(row.state, 'completed'); assert.equal(row.operation_id, prepared.proposalId);
          assert.ok(row.result_json); assert.match(row.result_sha256, SHA);
          assert.equal(commerceContract.digest(row.result_json), row.result_sha256);
          const privateProposal = JSON.parse(row.proposal_json);
          assert.equal(commerceContract.digest(row.proposal_json), row.proposal_sha256);
          assert.equal(privateProposal.kind, expectedKind);
          assert.equal(Number(privateProposal.selection.product_id), Number(product.product_id));
          const durable = JSON.parse(row.result_json);
          assert.equal(durable.operationId, prepared.proposalId); assert.equal(durable.kind, expectedKind);
          const read = await composition.conversationalCommerce.readOperation({ ...actor,
            args: { operationId: prepared.proposalId } });
          assert.equal(read.status, 'completed');
          assert.deepEqual(read.receipt, { ...durable, replayed: true });
          assert.deepEqual(await cartRows(), expectedRows, 'the saved receipt is bound to the effective cart mutation');
          return { row, read };
        };
        const confirmCart = async (proposal, { loseResponse = false } = {}) => {
          expectedCartConfirm = proposal;
          const endpoint = `${origin}/api/secureshop/customer/commerce/cart/confirm`;
          if (!loseResponse) {
            const pending = response(page, '/api/secureshop/customer/commerce/cart/confirm', 'POST');
            await click(frame, 'Confirm cart change');
            const httpResult = await readResponse(pending); assert.equal(httpResult.status(), 200);
            await frame.waitForFunction(() => document.querySelector('[aria-label="Customer cart confirmation"]')?.textContent
              .includes('Cart change applied.'), { timeout: 30000 });
            return;
          }
          let committed = null;
          cdp = await page.createCDPSession();
          cdp.on('Fetch.requestPaused', event => {
            const work = (async () => {
              assert.equal(event.request.url, endpoint); assert.equal(event.request.method, 'POST');
              assert.equal(event.responseStatusCode, 200);
              const raw = await bounded(cdp.send('Fetch.getResponseBody', { requestId: event.requestId }), 'cart committed response');
              committed = JSON.parse(Buffer.from(raw.body, raw.base64Encoded ? 'base64' : 'utf8').toString());
              assert.equal(committed.operationId, proposal.proposalId); assert.equal(committed.replayed, false);
              hideCartReads = true;
              await bounded(cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }), 'drop committed cart response');
            })().catch(async error => { interceptionFailure ??= error;
              await bounded(cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }), 'abort failed cart capture').catch(() => {}); });
            pendingInterceptions.add(work); void work.finally(() => pendingInterceptions.delete(work));
          });
          await cdp.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] });
          await click(frame, 'Confirm cart change');
          await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return committed; }, 'committed cart mutation');
          await Promise.all([...pendingInterceptions]); await bounded(cdp.send('Fetch.disable'), 'disable cart loss capture');
          await bounded(cdp.detach(), 'detach cart loss capture'); cdp = null;
        };
        const cartBaseline = await snapshot();
        const cartStartRows = await cartRows();
        stage = 'cart-add-search';
        const searchTurn = await runTurn(() => send(`Find ${product.name} and help me add one to my cart after I select it.`), ['catalog.search']);
        const productCard = searchTurn.saved.taskMetadata?.customerChat?.cards?.find(card => card.kind === 'product' && card.title === product.name);
        assert.ok(productCard, 'actual model search must hydrate the current product choice');
        await frame.waitForFunction(label => {
          const section = document.querySelector('[aria-label="Customer choices"]');
          const button = [...(section?.querySelectorAll('button') || [])]
            .find(item => item.getAttribute('aria-label') === `Add to cart: ${label}`);
          const quantity = [...(section?.querySelectorAll('input[aria-label]') || [])]
            .find(item => item.getAttribute('aria-label') === `Quantity for ${label}`);
          return button && !button.disabled && button.getClientRects().length
            && quantity?.value === '1' && quantity.getClientRects().length;
        }, {}, product.name);
        stage = 'cart-add-prepare';
        const addTurn = await runTurn(() => choose(frame, `Add to cart: ${product.name}`), ['cart.add']);
        assert.deepEqual(addTurn.sent.selection, { choiceId: productCard.choiceId,
          intent: 'cart_add', quantity: 1 },
        'physical Add to cart sends the exact saved product choice and displayed quantity');
        const { proposal: addProposal } = await cartOperationFor(addTurn, 'cart.add');
        await assertCartProposal(addProposal, 'cart.add', 1, cartStartRows); status.renderedCartAddPrepared = true;
        await frame.waitForFunction(() => document.querySelector('[aria-label="Customer cart confirmation"]')?.textContent.includes('Review cart change'));
        await confirmCart(addProposal);
        const afterAdd = await cartRows();
        assert.equal(afterAdd.length, 1); assert.equal(Number(afterAdd[0].quantity), Number(cartStartRows[0].quantity) + 1);
        await completedCartOperation(addProposal, afterAdd, 'cart.add');
        status.renderedCartAddConfirmed = true;

        stage = 'cart-update-view';
        const viewForUpdate = await runTurn(() => send('Show my current cart so I can select this line and set its quantity to 3.'), ['cart.view']);
        const updateCard = viewForUpdate.saved.taskMetadata?.customerChat?.cards?.find(card => card.kind === 'cart_item'
          && card.title === product.name);
        assert.ok(updateCard, 'cart.view must hydrate the actual current cart item choice');
        assert.equal(updateCard.quantity, Number(afterAdd[0].quantity),
          'cart item choice exposes its current database quantity as bounded structured data');
        await assertRenderedCartParity(updateCard, afterAdd);
        const updateQuantity = await frame.waitForFunction(({ choiceId, label, quantity }) => {
          const input = document.getElementById(`cart-item-quantity-${choiceId}`);
          const article = input?.closest('article');
          const button = [...(article?.querySelectorAll('button[aria-label]') || [])]
            .find(item => item.getAttribute('aria-label') === `Update quantity: ${label}`);
          return input?.getClientRects().length && input.value === String(quantity)
            && button?.getClientRects().length && !button.disabled ? input : null;
        }, {}, { choiceId: updateCard.choiceId, label: product.name, quantity: Number(afterAdd[0].quantity) });
        const quantityInput = updateQuantity.asElement(); assert.ok(quantityInput);
        await quantityInput.click({ clickCount: 3 });
        await quantityInput.press('Backspace'); await quantityInput.type('3');
        await frame.waitForFunction(({ choiceId, label }) => {
          const input = document.getElementById(`cart-item-quantity-${choiceId}`);
          const article = input?.closest('article');
          const button = [...(article?.querySelectorAll('button[aria-label]') || [])]
            .find(item => item.getAttribute('aria-label') === `Update quantity: ${label}`);
          return input?.value === '3' && button?.getClientRects().length && !button.disabled;
        }, {}, { choiceId: updateCard.choiceId, label: product.name });
        stage = 'cart-update-prepare';
        const updateTurn = await runTurn(() => chooseCartItem(frame, updateCard.choiceId,
          `Update quantity: ${product.name}`), ['cart.update']);
        assert.deepEqual(updateTurn.sent.selection, { choiceId: updateCard.choiceId,
          intent: 'cart_update', quantity: 3 },
        'physical Update quantity sends the exact cart-item choice and displayed quantity');
        const { proposal: updateProposal } = await cartOperationFor(updateTurn, 'cart.update');
        await assertCartProposal(updateProposal, 'cart.update', 3, afterAdd); status.renderedCartUpdatePrepared = true;
        const postsBeforeLoss = cartConfirms.length, readsBeforeLoss = operationReads.length;
        await confirmCart(updateProposal, { loseResponse: true });
        const afterCommittedUpdate = await cartRows();
        assert.equal(Number(afterCommittedUpdate[0]?.quantity), 3, 'lost response follows one durable update effect');
        assert.equal(cartConfirms.length, postsBeforeLoss + 1);
        const updatePath = `/customer/commerce/operations/${updateProposal.proposalId}`;
        await waitFor(() => operationReads.slice(readsBeforeLoss).includes(updatePath), 'faulted exact update recovery GET');
        await frame.waitForFunction(() => [...document.querySelectorAll('button')].some(button =>
          button.textContent.trim() === 'Check saved cart change' && !button.disabled && button.getClientRects().length), { timeout: 30000 });
        const postsBeforeRecovery = posts.length, modelCallsBeforeRecovery = status.actualModelCalls;
        hideCartReads = false;
        await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
        await frame.waitForSelector('[data-testid="agent-lane"] select', { visible: true }); await frame.select('[data-testid="agent-lane"] select', 'chat');
        const recoveredUpdate = response(page, `/api/secureshop${updatePath}`, 'GET');
        await click(frame, 'Check saved cart change');
        const recoveredUpdateHTTP = await readResponse(recoveredUpdate); assert.equal(recoveredUpdateHTTP.status(), 200);
        const recoveredUpdateBody = await recoveredUpdateHTTP.json();
        await frame.waitForFunction(() => document.querySelector('[aria-label="Customer cart confirmation"]')?.textContent.includes('Cart change applied.'), { timeout: 30000 });
        const updateCompleted = await completedCartOperation(updateProposal, afterCommittedUpdate, 'cart.update');
        assert.deepEqual(recoveredUpdateBody, updateCompleted.read);
        assert.equal(posts.length, postsBeforeRecovery, 'recovery is exact GET-only and does not re-run an actor');
        assert.equal(status.actualModelCalls, modelCallsBeforeRecovery, 'recovery does not re-dispatch the model');
        assert.equal(cartConfirms.length, postsBeforeLoss + 1, 'recovery is exact GET-only and does not replay update');
        assert.ok(faultedOperationReads.includes(updatePath), 'the lost response caused the exact update recovery GET to fault');
        assert.ok(operationReads.slice(readsBeforeLoss).includes(updatePath));
        status.renderedCartUpdateLostAckRecovery = true; status.exactGetNoReplay = true;

        stage = 'cart-remove-view';
        const viewForRemove = await runTurn(() => send('Show my current cart so I can select this line and remove it.'), ['cart.view']);
        const removeCard = viewForRemove.saved.taskMetadata?.customerChat?.cards?.find(card => card.kind === 'cart_item'
          && card.title === product.name);
        assert.ok(removeCard, 'post-recovery cart.view must hydrate the saved updated line');
        await assertRenderedCartParity(removeCard, afterCommittedUpdate);
        const chatScreenshot = path.join(path.dirname(receiptPath), 'customer-cart-lifecycle-chat.png');
        await page.screenshot({ path: chatScreenshot, fullPage: true }); await fs.chmod(chatScreenshot, 0o600);
        stage = 'cart-remove-prepare';
        const removeTurn = await runTurn(() => chooseCartItem(frame, removeCard.choiceId,
          `Remove from cart: ${product.name}`), ['cart.remove']);
        assert.deepEqual(removeTurn.sent.selection, { choiceId: removeCard.choiceId,
          intent: 'cart_remove' },
        'physical Remove from cart sends the exact cart-item choice without a quantity');
        const { proposal: removeProposal } = await cartOperationFor(removeTurn, 'cart.remove');
        await assertCartProposal(removeProposal, 'cart.remove', null, afterCommittedUpdate); status.renderedCartRemovePrepared = true;
        await confirmCart(removeProposal);
        assert.deepEqual(await cartRows(), [], 'physical remove confirmation has the sole final cart effect');
        const removeCompleted = await completedCartOperation(removeProposal, [], 'cart.remove');
        const confirmsBeforeRemoveReload = cartConfirms.length, postsBeforeRemoveReload = posts.length;
        await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
        await frame.waitForSelector('a[aria-label^="Cart ("]', { visible: true });
        const finalOperation = await frame.evaluate(async operationId => {
          const response = await fetch(`/api/secureshop/customer/commerce/operations/${operationId}`, { headers: { accept: 'application/json' } });
          return { status: response.status, body: await response.json() };
        }, removeProposal.proposalId);
        assert.equal(finalOperation.status, 200);
        assert.deepEqual(finalOperation.body, removeCompleted.read);
        await frame.click('a[aria-label^="Cart ("]');
        await frame.waitForFunction(() => document.querySelector('h1')?.textContent?.trim() === 'Cart'
          && document.body.textContent.includes('Your cart is empty'), { timeout: 30000 });
        assert.deepEqual(await cartRows(), [], 'reloaded rendered cart is empty after the confirmed remove');
        assert.equal(cartConfirms.length, confirmsBeforeRemoveReload, 'reload does not replay a completed remove');
        assert.equal(posts.length, postsBeforeRemoveReload, 'reload does not re-run an actor after remove');
        status.renderedCartRemoveConfirmed = true;
        assert.deepEqual((await snapshot()).stock, cartBaseline.stock, 'cart changes do not alter product stock');
        assert.deepEqual((await snapshot()).overlays, cartBaseline.overlays, 'cart changes do not alter effective listing stock');
        status.zeroEffectBeforeConfirm = true;
        const siblingFinalRead = await composition.conversationalCommerce.readOperation({ ...siblingActor,
          args: { operationId: removeProposal.proposalId } });
        assert.deepEqual(siblingFinalRead, { scopeKey: siblingFinalRead.scopeKey,
          operationId: removeProposal.proposalId, status: 'not_found' });
        assert.equal(status.siblingCartOperationDenied, true, 'preflight proved the exact other-owner receipt is denied before model dispatch');
        assert.equal((await identity.query('SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments')).rows[0].n, judgmentsBefore);
        assert.equal(status.judgeCalls, 0); status.noObjectiveCredit = true;
        assert.equal(posts.length, 6); assert.ok(status.actualModelCalls >= posts.length && status.actualModelCalls <= 24);
        if (interceptionFailure) throw interceptionFailure;
        const screenshot = path.join(path.dirname(receiptPath), 'customer-cart-lifecycle-final.png');
        await page.screenshot({ path: screenshot, fullPage: true }); await fs.chmod(screenshot, 0o600);
        status.passed = true;
      } else if (CHECKOUT_FENCES) {
        assert.equal(merchantTarget.targetId, target.targetId, 'supported merchant updates address the quoted customer catalog');
        const checkCurrent = scope => reset.launches.assertCurrent(scope);
        const inventory = require('../../server/services/secureshopBoundInventory').createBoundInventory({
          repository: require('../../server/database/postgres/secureshopOwnedInventoryRepository')
            .createOwnedInventoryRepository({ pool: review, checkCurrent }), checkCurrent,
          mode: 'vuln', modeAuthority });
        const setStock = async quantity => {
          const fence = await grading.personaAuthority.capture({ scope: merchantInput.scope, personaId: merchantInput.persona.id, role: 'merchant',
            ...merchantInput.personaSession });
          const value = await inventory.execute({ target: merchantTarget,
            persona: { id: merchantInput.persona.id, role: 'merchant' },
            personaSession: merchantInput.personaSession, operationId: randomUUID(), action: 'set_stock',
            args: { productId: Number(product.product_id), quantity }, execution: null }, { fence });
          assert.equal(value.result.applied, true); assert.equal(value.binding.args.quantity, quantity);
          assert.equal(value.binding.args.productId, Number(product.product_id));
        };
        const effective = async () => (await review.query(`SELECT COALESCE(o.price,p.price)::text AS price,
          COALESCE(o.stock_quantity,p.stock_quantity)::int AS stock
          FROM secureshop_review.product_target_products p
          LEFT JOIN secureshop_review.product_target_listing_overlays o USING(target_id,product_id)
          WHERE p.target_id=$1 AND p.product_id=$2`, [target.targetId, product.product_id])).rows[0];
        const privateRows = async () => ({ ...await snapshot(),
          products: (await review.query('SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id', [target.targetId])).rows,
          listingOverlays: (await review.query('SELECT * FROM secureshop_review.product_target_listing_overlays WHERE target_id=$1 ORDER BY product_id', [target.targetId])).rows,
          items: (await review.query(`SELECT i.* FROM secureshop_review.product_target_order_items i
            JOIN secureshop_review.product_target_orders o USING(target_id,order_id)
            WHERE i.target_id=$1 AND o.shop_user_id=$2 ORDER BY i.order_id,i.order_item_id`,
          [target.targetId, actor.persona.id])).rows });
        const quote = async label => {
          stage = label;
          const before = await privateRows();
          const firstQuote = label === 'quoted-stock';
          const turn = await runTurn(firstQuote
            ? () => choose(frame, 'Choose practice payment method: Practice card — approved')
            : () => send('Prepare a fresh checkout quote for my current cart using my already selected Home address '
              + 'and approved practice payment method. Recheck current cart facts with checkout.prepare. '
              + 'Do not place an order: I will review and confirm the new quote.'), ['checkout.prepare']);
          if (firstQuote) assert.deepEqual(turn.sent.selection, { choiceId: approvedCard.choiceId },
            'physical payment selection admits the exact current approved choice');
          else assert.equal(turn.sent.selection, undefined, 'renewal uses revalidated human choices in this same scene');
          const proposal = await operationFor(turn);
          assert.equal(proposal.paymentMethod.choiceId, approvedCard.choiceId);
          const current = await effective();
          assert.equal(proposal.items[0].unitPriceCents, commerceContract.money(current.price));
          assert.equal(proposal.totalCents, proposal.items[0].unitPriceCents);
          await frame.waitForFunction(({ name, total }) => {
            const section = document.querySelector('[aria-label="Customer checkout confirmation"]');
            return section?.textContent.includes(name) && section.textContent.includes('Address: Home')
              && section.textContent.includes('Practice card — approved')
              && section.textContent.includes(total)
              && [...section.querySelectorAll('button')].some(button =>
                button.textContent.trim() === 'Confirm this practice order' && !button.disabled);
          }, {}, { name: product.name, total: new Intl.NumberFormat('en-US',
            { style: 'currency', currency: 'USD' }).format(proposal.totalCents / 100) });
          assert.deepEqual(await privateRows(), before, 'model preparation does not purchase or alter stock/cart');
          return proposal;
        };
        const savedReceipt = async proposal => {
          const saved = await composition.conversationalCommerce.readOperation({ ...actor,
            args: { operationId: proposal.proposalId } });
          const row = (await review.query(`SELECT * FROM secureshop_review.chat_commerce_operations
            WHERE operation_id=$1 AND target_id=$2 AND shop_user_id=$3`,
          [proposal.proposalId, target.targetId, actor.persona.id])).rows[0];
          assert.equal(row.state, 'completed');
          assert.equal(commerceContract.digest(row.result_json), row.result_sha256);
          assert.deepEqual(saved.receipt, { ...JSON.parse(row.result_json), replayed: true });
          return saved;
        };
        const staleConfirm = async proposal => {
          const before = await privateRows(); expectedConfirm = proposal;
          const confirm = checkoutResponse(page, value => value.request().method() === 'POST'
            && new URL(value.url()).pathname === '/api/secureshop/customer/commerce/checkout/confirm');
          await click(frame, 'Confirm this practice order');
          const { value: http, body } = await readResponse(confirm); assert.equal(http.status(), 200);
          assert.equal(body.status, 'stale'); assert.equal(body.order, null);
          assert.equal(body.operationId, proposal.proposalId); assert.equal(body.replayed, false);
          await frame.waitForFunction(() => document.querySelector('[aria-label="Customer checkout confirmation"]')
            ?.textContent.includes('Quote changed. No order was placed.'));
          const saved = await savedReceipt(proposal);
          const { scopeKey, ...receipt } = body;
          assert.equal(saved.scopeKey, scopeKey); assert.deepEqual(saved.receipt, { ...receipt, replayed: true });
          assert.equal((await review.query(`SELECT count(*)::int AS n FROM secureshop_review.bound_commerce_operations
            WHERE operation_id=$1`, [proposal.proposalId])).rows[0].n, 0);
          assert.deepEqual(await privateRows(), before, 'stale confirmation has zero cart/stock/order/item effect');
        };
        stage = 'checkout-address-discovery';
        const beforeChoices = await privateRows();
        const addressTurn = await runTurn(() => send('I want to check out my current cart. First show my saved shipping addresses so I can choose one. After I select an address, offer practice payment choices; prepare the quote after I select a payment method. Do not place the order: I will review and confirm it. Keep payment choices available if I need to try another practice method.'),
          ['account.addresses']);
        const addressCards = addressTurn.saved.taskMetadata?.customerChat?.cards;
        assert.ok(addressCards?.some(card => card.kind === 'address' && card.choiceId === ownHome.choiceId));
        stage = 'checkout-selected-home';
        const paymentTurn = await runTurn(() => choose(frame, 'Use for checkout: Home'), ['payment.methods']);
        assert.deepEqual(paymentTurn.sent.selection,
          { choiceId: ownHome.choiceId, intent: 'address_checkout' });
        const methodCards = paymentTurn.saved.taskMetadata?.customerChat?.cards;
        assert.ok(methodCards?.some(card => card.kind === 'payment_method' && card.choiceId === approvedCard.choiceId));
        assert.deepEqual(await privateRows(), beforeChoices, 'discovery and physical address selection have no commerce effect');
        const originalFacts = await effective();
        const stockQuote = await quote('quoted-stock');
        await setStock(0); assert.equal((await effective()).stock, 0);
        await staleConfirm(stockQuote); status.renderedStockStaleNoEffect = true;
        await setStock(originalFacts.stock);
        const priceQuote = await quote('quoted-price');
        const changedPrice = Number(originalFacts.price) + 1;
        assert.ok(await composition.catalog.updateMerchantProduct({ ...merchantInput,
          productId: Number(product.product_id), patch: { price: changedPrice } }));
        assert.equal(commerceContract.money((await effective()).price), commerceContract.money(originalFacts.price) + 100);
        await staleConfirm(priceQuote); status.renderedPriceStaleNoEffect = true;
        const fresh = await quote('fresh-current-quote');
        assert.notEqual(fresh.proposalId, stockQuote.proposalId); assert.notEqual(fresh.proposalId, priceQuote.proposalId);
        assert.notEqual(fresh.quoteSha256, priceQuote.quoteSha256);
        assert.equal(fresh.totalCents, priceQuote.totalCents + 100);
        status.modelPreparedThreeQuotes = true; status.renderedFreshQuoteCurrentFacts = true;
        const prepared = await composition.conversationalCommerce.readOperation({ ...actor,
          args: { operationId: fresh.proposalId } });
        const beforeConflict = await privateRows();
        const declinedChoice = payments.cards.find(card => card.title === 'Practice card — declined');
        assert.ok(declinedChoice);
        await assert.rejects(composition.conversationalCommerce.prepareCheckout({ ...actor,
          args: { operationId: fresh.proposalId, addressChoiceId: fresh.address.choiceId,
            paymentChoiceId: declinedChoice.choiceId } }), error => {
          assert.equal(error.code, 'PERSONA_EFFECT_OUTCOME_UNCERTAIN');
          assert.equal(error.cause?.code, 'COMMERCE_OPERATION_CONFLICT'); return true;
        });
        assert.deepEqual(await composition.conversationalCommerce.readOperation({ ...actor,
          args: { operationId: fresh.proposalId } }), prepared);
        assert.deepEqual(await privateRows(), beforeConflict); status.changedPrepareIntentDenied = true;

        // Lose only the acknowledgement of an actual committed approval. The
        // second physical tab uses the supported GET-only saved-reference path.
        expectedConfirm = fresh; stage = 'concurrent-tab-confirmation';
        cdp = await page.createCDPSession(); const lossSession = cdp;
        const endpoint = `${origin}/api/secureshop/customer/commerce/checkout/confirm`;
        lossSession.on('Fetch.requestPaused', event => {
          const work = (async () => {
            assert.equal(event.request.url, endpoint); assert.equal(event.request.method, 'POST');
            assert.deepEqual(JSON.parse(event.request.postData), { proposalId: fresh.proposalId });
            assert.equal(event.responseStatusCode, 200);
            const raw = await bounded(lossSession.send('Fetch.getResponseBody', { requestId: event.requestId }), 'approval body');
            lostReceipt = JSON.parse(Buffer.from(raw.body, raw.base64Encoded ? 'base64' : 'utf8').toString());
            assert.equal(lostReceipt.operationId, fresh.proposalId); assert.equal(lostReceipt.status, 'approved');
            assert.equal(lostReceipt.replayed, false); assert.ok(lostReceipt.order?.orderId);
            hideCheckoutReads = true;
            await bounded(lossSession.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' }),
              'release committed checkout acknowledgement');
          })().catch(async error => { interceptionFailure ??= error;
            await bounded(lossSession.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }),
              'abort checkout response capture').catch(() => {}); });
          pendingInterceptions.add(work); void work.finally(() => pendingInterceptions.delete(work));
        });
        stage = 'two-tab-approval-response-observer';
        await bounded(lossSession.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] }),
          'enable checkout acknowledgement loss');
        const beforeApprove = await privateRows(), stockBefore = await effective();
        stage = 'two-tab-approval-physical-confirm';
        await click(frame, 'Confirm this practice order');
        stage = 'two-tab-approval-committed-response';
        await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return lostReceipt; }, 'committed receipt');
        stage = 'two-tab-approval-release-observer';
        await bounded(Promise.all([...pendingInterceptions]), 'checkout acknowledgement interception settlement');
        await bounded(lossSession.send('Fetch.disable'), 'disable checkout acknowledgement loss');
        await bounded(lossSession.detach(), 'detach checkout acknowledgement observer'); cdp = null;
        stage = 'two-tab-first-visible-recovery';
        await frame.waitForFunction(() => [...document.querySelectorAll('button')].some(button =>
          button.textContent.trim() === 'Check saved checkout' && !button.disabled));
        const committed = await privateRows();
        assert.equal(committed.cart.length, 0); assert.equal(committed.orders.length, beforeApprove.orders.length + 1);
        assert.equal(committed.items.length, beforeApprove.items.length + 1);
        assert.equal((await effective()).stock, stockBefore.stock - 1);
        assert.equal(confirms.length, 3); assert.equal(acknowledgedConfirms.length, 3);
        const terminal = await savedReceipt(fresh);
        const { scopeKey: approvedScope, ...approvedReceipt } = lostReceipt;
        assert.equal(terminal.scopeKey, approvedScope);
        assert.deepEqual(terminal.receipt, { ...approvedReceipt, replayed: true });
        stage = 'two-tab-second-open';
        const secondPage = await browser.newPage(); await secondPage.setViewport({ width: 1280, height: 900 });
        await secondPage.setRequestInterception(true); observeRequests(secondPage);
        await secondPage.goto(page.url(), { waitUntil: 'domcontentloaded' });
        const secondFrame = await frameFor(secondPage);
        await secondFrame.waitForSelector('[data-testid="agent-lane"] select', { visible: true });
        await secondFrame.select('[data-testid="agent-lane"] select', 'chat');
        stage = 'two-tab-second-visible-recovery';
        await secondFrame.waitForFunction(() => {
          const section = document.querySelector('[aria-label="Customer checkout confirmation"]');
          return section && [...section.querySelectorAll('button')].some(button =>
            button.textContent.trim() === 'Check saved checkout' && !button.disabled)
            && ![...section.querySelectorAll('button')].some(button => button.textContent.trim() === 'Confirm this practice order');
        });
        hideCheckoutReads = false;
        // Both tabs recover the same immutable receipt. Foreground each native
        // interaction so background-tab DOM/compositor throttling cannot stall
        // the physical click. Concurrent service confirmation is a separate
        // native proof; this rendered phase proves GET-only tab protection.
        for (const [surface, shopFrame, tab] of [[page, frame, 'first'], [secondPage, secondFrame, 'second']]) {
          stage = `two-tab-${tab}-physical-saved-read`;
          await bounded(surface.bringToFront(), `foreground ${tab} checkout tab`);
          // Arm this tab's bounded response observer only immediately before
          // its click; the other tab's wait cannot expire during this step.
          const read = checkoutResponse(surface, value => value.request().method() === 'GET'
            && new URL(value.url()).pathname === `/api/secureshop/customer/commerce/operations/${fresh.proposalId}`);
          await click(shopFrame, 'Check saved checkout');
          stage = `two-tab-${tab}-exact-saved-response`;
          const { value: http, body } = await readResponse(read); assert.equal(http.status(), 200);
          assert.deepEqual(body, terminal);
        }
        // Parent removal is versioned across tabs. A losing removal ACK may
        // remain visibly unresolved; the exact GET still proves one receipt.
        stage = 'two-tab-rendered-recovery-outcomes';
        await waitFor(async () => {
          const states = await bounded(Promise.all([frame, secondFrame].map(surface => surface.evaluate(() => {
            const section = document.querySelector('[aria-label="Customer checkout confirmation"]');
            return { approved: section?.textContent.includes('Order placed') === true,
              recovery: [...(section?.querySelectorAll('button') || [])].some(button =>
                button.textContent.trim() === 'Check saved checkout' && !button.disabled),
              confirms: [...(section?.querySelectorAll('button') || [])].some(button =>
                button.textContent.trim() === 'Confirm this practice order') };
          }))), 'checkout tab recovery status observation');
          assert.ok(states.every(value => !value.confirms), 'neither recovered tab offers a duplicate confirmation');
          return states.some(value => value.approved) && states.every(value => value.approved || value.recovery);
        }, 'both tabs expose approved receipt or conservative saved recovery');
        assert.equal(confirms.length, 3, 'the second tab and both saved reads do not send another confirmation');
        assert.equal(posts.length, 5); assert.deepEqual(await privateRows(), committed);
        const duplicate = await composition.conversationalCommerce.confirmCheckout({ ...actor,
          args: { proposalId: fresh.proposalId } });
        assert.deepEqual(duplicate, { ...lostReceipt, replayed: true });
        assert.deepEqual(await privateRows(), committed);
        for (const table of ['chat_commerce_operations', 'bound_commerce_operations']) {
          assert.equal((await review.query(`SELECT count(*)::int AS n FROM secureshop_review.${table}
            WHERE operation_id=$1 AND state='completed'`, [fresh.proposalId])).rows[0].n, 1);
        }
        status.renderedTwoTabRecoveryOneEffect = true; status.exactDuplicateReceipt = true;
        await bounded(secondPage.close(), 'close recovered checkout tab');
        stage = 'later-real-session';
        const laterLogin = await auth.login({ username, password });
        assert.notEqual(laterLogin.context.sessionId, registration.context.sessionId);
        const laterActor = await actorFor(await bootstrap(laterLogin.context));
        assert.equal(laterActor.persona.id, actor.persona.id);
        assert.notEqual(laterActor.personaSession.sessionId, actor.personaSession.sessionId);
        await assert.rejects(composition.conversationalCommerce.confirmCheckout({ ...laterActor,
          args: { proposalId: fresh.proposalId } }), error => {
          assert.equal(error.code, 'PERSONA_EFFECT_OUTCOME_UNCERTAIN');
          assert.equal(error.cause?.code, 'COMMERCE_OPERATION_CONFLICT'); return true;
        });
        assert.deepEqual(await privateRows(), committed);
        status.laterRealSessionDenied = true;
        assert.equal((await identity.query('SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments')).rows[0].n,
          judgmentsBefore);
        assert.equal(status.judgeCalls, 0); status.noObjectiveCredit = true;
        assert.equal(status.chatTurns, 5); assert.ok(status.actualModelCalls >= 5 && status.actualModelCalls <= 20);
        if (interceptionFailure) throw interceptionFailure;
        status.passed = true;
      } else {
      stage = 'checkout-choices';
      const choicesTurn = await runTurn(() => send('I want to check out my current cart. First show my saved shipping addresses so I can choose one. After I select an address, offer practice payment choices; prepare the quote after I select a payment method. Do not place the order: I will review and confirm it. Keep payment choices available if I need to try another practice method.'),
        ['account.addresses']);
      const firstCards = choicesTurn.saved.taskMetadata?.customerChat?.cards;
      assert.ok(firstCards.some(card => card.kind === 'address' && card.title === 'Home'));
      assert.ok(firstCards.some(card => card.kind === 'address' && card.title === 'Office'));
      assert.ok(!firstCards.some(card => card.title === 'Sibling private address'));
      for (const title of ['Home', 'Office']) {
        await frame.waitForFunction(label => [...document.querySelectorAll('[aria-label="Customer choices"] button')]
          .some(button => button.getAttribute('aria-label') === label && !button.disabled && button.getClientRects().length),
        {}, `Use for checkout: ${title}`);
      }
      status.renderedOwnedAddressChoices = true;
      assert.deepEqual(await snapshot(), baseline, 'looking up choices has no purchase effect');
      stage = 'selected-home';
      const homeTurn = await runTurn(() => choose(frame, 'Use for checkout: Home'), ['payment.methods']);
      assert.deepEqual(homeTurn.sent.selection,
        { choiceId: firstCards.find(card => card.kind === 'address' && card.title === 'Home').choiceId,
          intent: 'address_checkout' });
      const paymentCards = homeTurn.saved.taskMetadata?.customerChat?.cards;
      for (const title of ['Practice card — approved', 'Practice card — declined']) {
        assert.ok(paymentCards.some(card => card.kind === 'payment_method' && card.title === title));
        await frame.waitForFunction(label => [...document.querySelectorAll('[aria-label="Customer choices"] button')]
          .some(button => button.getAttribute('aria-label') === label && !button.disabled && button.getClientRects().length),
        {}, `Choose practice payment method: ${title}`);
      }
      status.renderedSyntheticPaymentChoices = true;
      if(V01_AUDIT)checkoutChoiceEvidence=Object.freeze({
        addressChoiceId:homeTurn.sent.selection.choiceId,
        paymentChoiceId:paymentCards.find(card=>card.kind==='payment_method'
          &&card.title==='Practice card — approved').choiceId});
      assert.deepEqual(await snapshot(), baseline, 'selecting an address has no purchase effect');
      let declineProposal = null;
      if(!V01_AUDIT){
      stage = 'declined-proposal';
      const declineTurn = await runTurn(() => choose(frame, 'Choose practice payment method: Practice card — declined'),
        ['checkout.prepare']);
      declineProposal = await operationFor(declineTurn);
      assert.equal(declineProposal.paymentMethod.title, 'Practice card — declined');
      await frame.waitForFunction(name => {
        const section = document.querySelector('[aria-label="Customer checkout confirmation"]');
        return section?.textContent.includes(name) && section.textContent.includes('Address: Home')
          && section.textContent.includes('Practice card — declined');
      }, {}, product.name);
      assert.deepEqual(await snapshot(), baseline, 'quote preparation has no purchase effect');
      status.renderedExactCheckoutProposal = true;
      expectedConfirm = declineProposal;
      stage = 'declined-confirmation';
      let declined = null;
      cdp = await page.createCDPSession();
      const declineSession = cdp;
      const declineEndpoint = `${origin}/api/secureshop/customer/commerce/checkout/confirm`;
      declineSession.on('Fetch.requestPaused', event => {
        const work = (async () => {
          assert.equal(event.request.url, declineEndpoint); assert.equal(event.request.method, 'POST');
          assert.deepEqual(JSON.parse(event.request.postData), { proposalId: declineProposal.proposalId });
          assert.equal(event.responseStatusCode, 200);
          const raw = await bounded(declineSession.send('Fetch.getResponseBody', { requestId: event.requestId }),
            'declined HTTP response body');
          const value = JSON.parse(Buffer.from(raw.body, raw.base64Encoded ? 'base64' : 'utf8').toString());
          assert.equal(value.status, 'declined'); assert.equal(value.order, null);
          assert.equal(value.operationId, declineProposal.proposalId); assert.equal(value.replayed, false);
          // Observe, then release the original HTTP response without replacement.
          await bounded(declineSession.send('Fetch.continueRequest', { requestId: event.requestId }), 'release declined response');
          declined = value;
        })().catch(async error => {
          interceptionFailure ??= error;
          await bounded(declineSession.send('Fetch.continueRequest', { requestId: event.requestId }),
            'release failed decline capture').catch(() => {});
        });
        pendingInterceptions.add(work); void work.finally(() => pendingInterceptions.delete(work));
      });
      await declineSession.send('Fetch.enable', { patterns: [{ urlPattern: declineEndpoint, requestStage: 'Response' }] });
      const declineResponse = response(page, '/api/secureshop/customer/commerce/checkout/confirm', 'POST');
      await click(frame, 'Confirm this practice order');
      await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return declined; }, 'declined HTTP response capture');
      await Promise.all([...pendingInterceptions]);
      await bounded(declineSession.send('Fetch.disable'), 'disable declined response capture');
      await bounded(declineSession.detach(), 'detach declined response capture'); cdp = null;
      const declineHTTP = await readResponse(declineResponse); assert.equal(declineHTTP.status(), 200);
      assert.equal(declined.operationId, declineProposal.proposalId);
      await frame.waitForFunction(() => document.querySelector('[aria-label="Customer checkout confirmation"]')?.textContent.includes('Practice payment declined. No order was placed.'));
      assert.deepEqual(await snapshot(), baseline, 'decline does not change cart, stock or orders');
      const declineSaved = await composition.conversationalCommerce.readOperation({ ...actor, args: { operationId: declined.operationId } });
      const { scopeKey: declineScope, ...declineReceipt } = declined;
      assert.equal(declineSaved.scopeKey, declineScope);
      assert.deepEqual(declineSaved.receipt, { ...declineReceipt, replayed: true });
      status.renderedSyntheticDeclineNoEffect = true;

      stage = 'fresh-payment-methods-after-decline';
      const refreshTurn = await runTurn(() => click(frame, 'Choose another payment method'), ['payment.methods']);
      assert.equal(refreshTurn.sent.message, 'Show my current payment methods so I can choose another one.');
      assert.equal(Object.hasOwn(refreshTurn.sent, 'selection'), false);
      const refreshedCards = refreshTurn.saved.taskMetadata?.customerChat?.cards;
      assert.ok(refreshedCards?.some(card => card.kind === 'payment_method'
        && card.title === 'Practice card — approved' && card.choiceId === approvedCard.choiceId));
      await frame.waitForFunction(label => [...document.querySelectorAll('[aria-label="Customer choices"] button')]
        .some(button => button.getAttribute('aria-label') === label && !button.disabled && button.getClientRects().length),
      {}, 'Choose practice payment method: Practice card — approved');
      assert.deepEqual(await snapshot(), baseline, 'asking for current payment choices has no purchase effect');
      }

      stage = 'approved-proposal';
      const approveTurn = await runTurn(() => choose(frame, 'Choose practice payment method: Practice card — approved'), ['checkout.prepare']);
      if(V01_AUDIT)assert.deepEqual(approveTurn.saved.hops.find(hop=>hop.tool==='checkout.prepare'
        &&!hop.error&&hop.result?.isError!==true)?.params,checkoutChoiceEvidence);
      const approvedProposal = await operationFor(approveTurn);
      assert.equal(approvedProposal.paymentMethod.choiceId, approvedCard.choiceId);
      if(declineProposal)assert.notEqual(approvedProposal.proposalId, declineProposal.proposalId);
      await frame.waitForFunction(({name,total})=>{
        const text=document.querySelector('[aria-label="Customer checkout confirmation"]')?.textContent||'';
        return text.includes(name)&&text.includes('Address: Home')
          &&text.includes('Practice card — approved')&&text.includes(total);
      },{}, {name:product.name,total:new Intl.NumberFormat('en-US',
        {style:'currency',currency:'USD'}).format(approvedProposal.totalCents/100)});
      assert.deepEqual(await snapshot(), baseline);
      status.renderedExactCheckoutProposal = true;
      expectedConfirm = approvedProposal;
      cdp = await page.createCDPSession();
      const endpoint = `${origin}/api/secureshop/customer/commerce/checkout/confirm`;
      cdp.on('Fetch.requestPaused', event => {
        const work = (async () => {
          assert.equal(event.request.url, endpoint); assert.equal(event.request.method, 'POST');
          assert.equal(event.responseStatusCode, 200);
          const raw = await cdp.send('Fetch.getResponseBody', { requestId: event.requestId });
          const receipt = JSON.parse(Buffer.from(raw.body, raw.base64Encoded ? 'base64' : 'utf8').toString());
          assert.equal(receipt.status, 'approved'); assert.equal(receipt.operationId, approvedProposal.proposalId);
          assert.equal(receipt.replayed, false); assert.ok(receipt.order?.orderId);
          lostReceipt = receipt; hideCheckoutReads = true;
          await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Failed' });
        })().catch(async error => {
          interceptionFailure ??= error;
          await cdp.send('Fetch.failRequest', { requestId: event.requestId, errorReason: 'Aborted' }).catch(() => {});
        });
        pendingInterceptions.add(work); void work.finally(() => pendingInterceptions.delete(work));
      });
      await cdp.send('Fetch.enable', { patterns: [{ urlPattern: endpoint, requestStage: 'Response' }] });
      await click(frame, 'Confirm this practice order');
      await waitFor(() => { if (interceptionFailure) throw interceptionFailure; return lostReceipt; }, 'committed approved receipt');
      await Promise.all([...pendingInterceptions]); await cdp.send('Fetch.disable'); await cdp.detach(); cdp = null;
      assert.equal(confirms.length, V01_AUDIT ? 1 : 2);
      assert.equal(acknowledgedConfirms.length, V01_AUDIT ? 1 : 2);
      const afterApprove = await snapshot(); assert.equal(afterApprove.cart.length, 0); assert.equal(afterApprove.orders.length, 1);
      const order = afterApprove.orders[0]; assert.equal(Number(order.order_id), lostReceipt.order.orderId);
      assert.equal(order.payment_status, 'approved');
      assert.equal(order.shipping_address, [home.label, home.line1, home.line2, home.city, home.state, home.zip].join('\n'));
      const chatRow = (await review.query('SELECT state,result_json FROM secureshop_review.chat_commerce_operations WHERE operation_id=$1', [approvedProposal.proposalId])).rows[0];
      const { scopeKey: _scopeKey, ...receiptWithoutScope } = lostReceipt;
      assert.equal(chatRow.state, 'completed'); assert.deepEqual(JSON.parse(chatRow.result_json), receiptWithoutScope);
      const oldRow = (await review.query('SELECT * FROM secureshop_review.bound_commerce_operations WHERE operation_id=$1', [approvedProposal.proposalId])).rows;
      assert.equal(oldRow.length, 1);
      const productStock = snapshot => Number(snapshot.overlays.find(row => Number(row.product_id) === Number(product.product_id))?.stock_quantity
        ?? snapshot.stock.find(row => Number(row.product_id) === Number(product.product_id)).stock_quantity);
      assert.equal(productStock(afterApprove), productStock(baseline) - 1);
      status.renderedApprovedCheckoutAtomicReceipt = true;
      await frame.waitForFunction(() => [...document.querySelectorAll('button')].some(button => button.textContent.trim() === 'Check saved checkout'));
      const callsBeforeRecovery = status.actualModelCalls, turnsBeforeRecovery = posts.length;
      hideCheckoutReads = false;
      await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
      await frame.waitForSelector('[data-testid="agent-lane"] select'); await frame.select('[data-testid="agent-lane"] select', 'chat');
      const recoveryPath = `/customer/commerce/operations/${approvedProposal.proposalId}`;
      const recoveryUrl = `${origin}/api/secureshop${recoveryPath}`;
      const readFloor = operationReads.length, faultedReadFloor = faultedOperationReads.length;
      checkoutRecoveryDiagnostic = { path: recoveryPath, requests: 0, responses: [], clickEvents: 0 };
      const checkoutButtonState = () => frame.evaluate(() => {
        const buttons = [...document.querySelectorAll('button')]
          .filter(button => button.textContent.trim() === 'Check saved checkout');
        return buttons.map(button => {
          const rect = button.getBoundingClientRect();
          const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
          return { visible: !!button.getClientRects().length && getComputedStyle(button).visibility !== 'hidden',
            disabled: button.disabled, inCheckoutCard: !!button.closest('[aria-label="Customer checkout confirmation"]'),
            centerHit: hit === button || button.contains(hit),
            center: [Math.round(rect.left + rect.width / 2), Math.round(rect.top + rect.height / 2)] };
        });
      });
      const onRecoveryRequest = request => {
        if (request.method() === 'GET' && request.url() === recoveryUrl) checkoutRecoveryDiagnostic.requests += 1;
      };
      const onRecoveryResponse = reply => {
        if (reply.request().method() === 'GET' && reply.url() === recoveryUrl) {
          checkoutRecoveryDiagnostic.responses.push(reply.status());
        }
      };
      page.on('request', onRecoveryRequest); page.on('response', onRecoveryResponse);
      try {
        checkoutRecoveryDiagnostic.beforeButtons = await checkoutButtonState();
        await frame.evaluate(() => {
          window.__checkoutRecoveryClicks = 0;
          window.__checkoutRecoveryClickObserver = event => {
            if (event.isTrusted && event.target.closest('button')?.textContent.trim() === 'Check saved checkout') {
              window.__checkoutRecoveryClicks += 1;
            }
          };
          document.addEventListener('click', window.__checkoutRecoveryClickObserver, true);
        });
        const recoveryHandle = await frame.waitForFunction(() => [...document.querySelectorAll(
          '[aria-label="Customer checkout confirmation"] button')].find(button =>
          button.textContent.trim() === 'Check saved checkout' && !button.disabled
          && button.getClientRects().length && getComputedStyle(button).visibility !== 'hidden'),
        { timeout: 30000 });
        const recoveryButton = recoveryHandle.asElement(); assert.ok(recoveryButton);
        await recoveryButton.evaluate(button => button.scrollIntoView({ block: 'center' }));
        checkoutRecoveryDiagnostic.afterScrollButtons = await checkoutButtonState();
        assert.equal(checkoutRecoveryDiagnostic.afterScrollButtons.length, 1,
          'one current saved checkout control is physically selectable');
        assert.equal(checkoutRecoveryDiagnostic.afterScrollButtons[0].centerHit, true,
          'saved checkout control center is hit-testable before physical click');
        await recoveryButton.click();
        checkoutRecoveryDiagnostic.afterButtons = await checkoutButtonState();
        await frame.waitForFunction(() => document.querySelector('[aria-label="Customer checkout confirmation"]')?.textContent.includes('Order placed'));
      } finally {
        checkoutRecoveryDiagnostic.clickEvents = await frame.evaluate(() => {
          const observed = window.__checkoutRecoveryClicks || 0;
          if (window.__checkoutRecoveryClickObserver) {
            document.removeEventListener('click', window.__checkoutRecoveryClickObserver, true);
            delete window.__checkoutRecoveryClickObserver;
          }
          delete window.__checkoutRecoveryClicks;
          return observed;
        }).catch(() => null);
        checkoutRecoveryDiagnostic.reads = operationReads.slice(readFloor).filter(path => path === recoveryPath).length;
        checkoutRecoveryDiagnostic.faultedReads = faultedOperationReads.slice(faultedReadFloor)
          .filter(path => path === recoveryPath).length;
        checkoutRecoveryDiagnostic.finalButtons = await checkoutButtonState().catch(() => null);
        checkoutRecoveryDiagnostic.finalNotice = await frame.evaluate(() => {
          const section = document.querySelector('[aria-label="Customer checkout confirmation"]');
          return [...(section?.querySelectorAll('[role="status"],[role="alert"]') || [])]
            .filter(node => node.getClientRects().length)
            .map(node => ({ role: node.getAttribute('role'), text: node.textContent.trim().slice(0, 160) }));
        }).catch(() => null);
        page.off('request', onRecoveryRequest); page.off('response', onRecoveryResponse);
      }
      assert.equal(status.actualModelCalls, callsBeforeRecovery); assert.equal(posts.length, turnsBeforeRecovery);
      assert.equal(confirms.length, V01_AUDIT ? 1 : 2); assert.deepEqual(await snapshot(), afterApprove);
      assert.ok(operationReads.includes(`/customer/commerce/operations/${approvedProposal.proposalId}`));
      status.renderedCheckoutRecoveryNoReplay = true;

      // The original saved chat still contains its prepared quote after the
      // first recovery has cleared the parent checkout reference. A fresh
      // mount must read the already-completed operation, never submit it again.
      stage = 'completed-checkout-original-proposal-remount';
      const pendingCheckoutRefs = await page.evaluate(() => {
        const result = [];
        for (let index = 0; index < localStorage.length; index++) {
          const key = localStorage.key(index);
          if (!/^dvaia:secureshop:[a-f0-9-]{36}:[1-9]\d*(?::scene:[a-f0-9-]{36})?$/i.test(key || '')) continue;
          const encoded = JSON.parse(localStorage.getItem(key))['secureshop.checkout.operation.v1'];
          if (encoded) result.push(JSON.parse(encoded).operationId);
        }
        return result;
      });
      assert.deepEqual(pendingCheckoutRefs, [], 'the committed checkout has no pending parent reference');
      const remountPosts = posts.length, remountConfirms = confirms.length;
      const remountModelCalls = status.actualModelCalls, remountReads = operationReads.length;
      await page.reload({ waitUntil: 'domcontentloaded' }); frame = await frameFor(page);
      await frame.waitForSelector('[data-testid="agent-lane"] select');
      await frame.select('[data-testid="agent-lane"] select', 'chat');
      await frame.waitForFunction(({ name, total }) => {
        const section = document.querySelector('[aria-label="Customer checkout confirmation"]');
        return section?.textContent.includes(name) && section.textContent.includes('Address: Home')
          && section.textContent.includes('Practice card — approved')
          && section.textContent.includes(total)
          && [...section.querySelectorAll('button')].some(button =>
            button.textContent.trim() === 'Confirm this practice order' && !button.disabled)
          && ![...section.querySelectorAll('button')].some(button =>
            button.textContent.trim() === 'Check saved checkout');
      }, {}, { name: product.name, total: new Intl.NumberFormat('en-US',
        { style: 'currency', currency: 'USD' }).format(approvedProposal.totalCents / 100) });
      const completedRead = response(page,
        `/api/secureshop/customer/commerce/operations/${approvedProposal.proposalId}`, 'GET');
      await click(frame, 'Confirm this practice order');
      const completedHTTP = await readResponse(completedRead);
      assert.equal(completedHTTP.status(), 200);
      const completedBody = await completedHTTP.json();
      assert.deepEqual(completedBody.proposal, approvedProposal,
        'the restored card reads the exact original prepared quote');
      assert.deepEqual(completedBody, await composition.conversationalCommerce.readOperation({ ...actor,
        args: { operationId: approvedProposal.proposalId } }));
      await frame.waitForFunction(() => {
        const section = document.querySelector('[aria-label="Customer checkout confirmation"]');
        return section?.textContent.includes('Order placed')
          && section.textContent.includes('Order confirmed from the saved receipt.')
          && !section.textContent.includes('Checkout quote changed')
          && ![...section.querySelectorAll('button')].some(button =>
            button.textContent.trim() === 'Confirm this practice order');
      });
      assert.deepEqual(operationReads.slice(remountReads),
        [`/customer/commerce/operations/${approvedProposal.proposalId}`]);
      assert.equal(posts.length, remountPosts, 'completed readback does not re-run customer chat');
      assert.equal(status.actualModelCalls, remountModelCalls, 'completed readback uses no model call');
      assert.equal(confirms.length, remountConfirms, 'completed readback does not re-confirm checkout');
      assert.deepEqual(await snapshot(), afterApprove, 'completed readback does not change commerce state');

      stage = 'orders';
      const listed = await runTurn(() => send('Show my orders. I want to select an order card to read its saved items, shipping address, total and practice payment status.'), ['orders.list']);
      const orderCard = listed.saved.taskMetadata?.customerChat?.cards?.find(card => card.kind === 'order' && card.title === `Order #${order.order_id}`);
      assert.ok(orderCard);
      const detail = await runTurn(() => choose(frame, `View details: ${orderCard.title}`), ['orders.details']);
      assert.equal(detail.sent.message, 'Show this order’s details.');
      assert.deepEqual(detail.sent.selection, { choiceId: orderCard.choiceId, intent: 'order_details' },
        'physical View details selects only the saved order-detail intent');
      const hop = detail.saved.hops?.find(item => item.tool === 'orders.details' && !item.error); assert.ok(hop);
      assert.deepEqual(hop.params, { choiceId: orderCard.choiceId });
      assert.ok(!detail.saved.hops.some(item => item.tool === 'orders.refund_setup'),
        'a detail-only selection cannot open the refund setup');
      assert.ok(detail.saved.text.includes(`Order #${order.order_id}`)
        && detail.saved.text.toLowerCase().includes(order.status)
        && detail.saved.text.toLowerCase().includes(order.payment_status)
        && detail.saved.text.replaceAll(',', '').includes(Number(order.total_amount).toFixed(2)),
      'genuine model summary identifies the selected order and its truthful status, payment and total');
      const detailResponse = await composition.repositories.commerce.conversation.orderDetails(target, {
        shopUserId: actor.persona.id, personaSession: actor.personaSession, mode: 'vuln', choiceId: orderCard.choiceId });
      assert.equal(detailResponse.order.shipping_address, order.shipping_address);
      assert.equal(Number(detailResponse.order.order_id), Number(order.order_id));
      assert.equal(detailResponse.order.payment_status, order.payment_status); assert.equal(detailResponse.order.items.length, 1);
      assert.equal(Number(detailResponse.order.items[0].product_id), Number(product.product_id));
      // Verify the actual model tool observation, not only a separate repository read.
      const texts = hop.result?.content?.filter(item => item.type === 'text').map(item => item.text) || [];
      assert.ok(texts.some(text => {
        try { return JSON.parse(text).order?.shipping_address === order.shipping_address; } catch { return false; }
      }), 'real selected tool returned the persisted shipping address');
      const renderedOrder = {
        heading: `Order #${order.order_id}`,
        placed: `Placed ${detailResponse.order.order_date.slice(0, 10)} · ${order.status}`,
        payment: `Payment: ${order.payment_status} · Total: $${Number(order.total_amount).toFixed(2)}`,
        item: `${product.name} · ${detailResponse.order.items[0].quantity} × $${Number(detailResponse.order.items[0].price).toFixed(2)} each`,
        address: detailResponse.order.shipping_address,
      };
      await frame.waitForFunction(expected => {
        const panel = document.querySelector('[aria-label="Selected order details"]');
        if (!panel) return false;
        panel.scrollIntoView({ block: 'center' });
        const rect = panel.getBoundingClientRect();
        return rect.height > 0 && rect.bottom > 0 && rect.top < innerHeight
          && panel.querySelector('h3')?.textContent.trim() === expected.heading
          && [...panel.querySelectorAll('p')].some(node => node.textContent.trim() === expected.placed)
          && [...panel.querySelectorAll('p')].some(node => node.textContent.trim() === expected.payment)
          && [...panel.querySelectorAll('li')].some(node => node.textContent.trim() === expected.item)
          && [...panel.querySelectorAll('p')].some(node => node.textContent.trim() === expected.address);
      }, { timeout: 30000 }, renderedOrder);
      status.renderedOwnedOrderListAndDetail = true;
      assert.deepEqual(await composition.account.addresses(siblingActor), siblingBefore);
      if(V01_AUDIT){
        stage='v01-vulnerable-rendered';
        const V01=require('../fixtures/secureshopCustomerCheckoutAuditRenderedQualification');
        const v01=Object.fromEntries(V01.V01_BROWSER_FLAGS.map(key=>[key,false]));
        Object.assign(v01,{scope:V01.V01_BROWSER_SCOPE,vulnerableActorCalls:2,fixedActorCalls:2,
          judgeCalls:1,assessmentPosts:2,genuineCredit:1,errors:[]});
        v01.isolatedStores=true;v01.fixtureLocalCandidateAdmission=v01Candidate.fixtureLocalCandidateAdmission;
        v01.canonicalObjectiveEnabled=true;v01.storefrontCustomerLogin=true;v01.renderedApprovedCheckout=true;
        const auditRows=(await review.query(`SELECT event_id::text,params_json FROM secureshop_review.bound_audit_events
          WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3 AND original_platform_owner_id=$4
            AND original_platform_session_id=$5 AND shop_user_id=$6 AND shop_role='customer'
            AND actor='customer' AND action='checkout' AND outcome='completed' AND source_kind='order'
            AND source_id=$7 AND target=$7 ORDER BY created_at,event_id`,[actor.scope.launchId,actor.scope.scenarioId,
          actor.scope.generation,actor.scope.platformOwnerId,actor.scope.platformSessionId,actor.persona.id,String(order.order_id)])).rows;
        assert.equal(auditRows.length,1);assert.equal(JSON.parse(auditRows[0].params_json).storageTargetId,target.targetId);
        v01ProtectedAuditExpectation=Object.freeze({shopUserId:actor.persona.id,
          orderId:Number(order.order_id),eventId:auditRows[0].event_id});
        v01.ownedCheckoutAuditEvent=true;
        const effectCount=async()=>Number((await identity.query('SELECT count(*)::int n FROM graph_runtime.effects')).rows[0].n);
        const beforeActor=status.actualModelCalls,beforeEffects=await effectCount();
        const vulnerableReadBefore={...v01ProtectedAuditReads};
        const vulnerable=await V01.runV01RenderedVulnerable({page,frame,origin,
          order:{id:Number(order.order_id),total:Number(order.total_amount)},operationId:approvedProposal.proposalId,
          beforeCounters:async()=>({actor:beforeActor,effects:beforeEffects}),
          afterCounters:async()=>({actor:status.actualModelCalls,effects:await effectCount()})});
        const vulnerableReadAfter={...v01ProtectedAuditReads};
        assert.ok(vulnerableReadAfter.expected > vulnerableReadBefore.expected,
          'vulnerable audit probe executes the expected protected checkout-audit SELECT');
        assert.equal(vulnerableReadAfter.unexpected,vulnerableReadBefore.unexpected);
        assert.equal(v01Posts.length,1);V01.assertV01ActorRequest(v01Posts[0],{
          sessionId:vulnerable.sessionId,requestId:vulnerable.requestId,
          checkoutOperationId:vulnerable.operationId,forgedTokenSha256:vulnerable.forgedTokenSha256,calls:2});
        const source=(await agents.query(`SELECT status,request_hash,request_version,result_json
          FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
        [vulnerable.sessionId,vulnerable.requestId])).rows;
        assert.equal(source.length,1);assert.equal(source[0].status,'completed');assert.equal(source[0].request_version,1);
        assert.match(source[0].request_hash,/^[a-f0-9]{64}$/);const original=source[0].result_json;
        assert.equal(original.hops.length,1);assert.equal(original.hops[0].tool,'auth.audit_probe');
        assert.equal(original.taskMetadata.checkoutAuditJwt.version,2);
        assert.deepEqual(original.hops[0].params,{});
        assert.equal(v01ActorSpans.length,2);
        assert.equal(v01ActorSpans[0].response.tool_uses.length,1);
        assert.equal(v01ActorSpans[0].response.tool_uses[0].name,'auth.audit_probe');
        assert.deepEqual(v01ActorSpans[0].response.tool_uses[0].args,{});
        const evidence=original.taskMetadata.checkoutAuditJwt.originalEvidence;
        assert.equal(evidence.eventId,auditRows[0].event_id);assert.equal(evidence.requestId,vulnerable.requestId);
        const ownerKey=JSON.stringify(['SecureShopBoundConversation',vulnerable.sessionId]);
        const effects=(await identity.query(`SELECT e.run_id::text,e.owner_key,e.generation::text,e.effect_key,e.status,
          r.status run_status FROM graph_runtime.effects e JOIN graph_runtime.runs r
          ON r.run_id=e.run_id AND r.owner_key=e.owner_key AND r.generation=e.generation
          WHERE e.owner_key=$1`,[ownerKey])).rows;
        assert.equal(effects.length,1);assert.equal(effects[0].status,'completed');assert.equal(effects[0].run_status,'completed');
        assert.equal(effects[0].effect_key,evidence.effectReceipt.effectKey);
        const traces=(await agents.query(`SELECT kind,step,actor,agent_ns,tool_name,params_json,result_json
          FROM secureshop_agents.agent_trace WHERE session_id=$1 ORDER BY id`,[vulnerable.sessionId])).rows;
        assert.equal(traces.filter(row=>row.kind==='model_decision').length,2);
        assert.equal(traces.filter(row=>row.kind==='local_tool_call'&&row.agent_ns==='auth'&&row.tool_name==='audit_probe').length,1);
        assert.equal(traces.filter(row=>row.kind==='local_tool_result'&&row.agent_ns==='auth'&&row.tool_name==='audit_probe').length,1);
        Object.assign(v01Evidence,{source:structuredClone(source[0]),traces:structuredClone(traces),effects:structuredClone(effects)});
        Object.assign(v01,{renderedPracticeToken:true,physicalUnsignedAdminEdit:true,
          actualModelSelectedAuditProbe:true,ownedGraphAuditRead:true,renderedExactAuditReport:true});
        assert.match(target.scene?.sceneId||'',UUID);assert.notEqual(target.scene.sceneId,actor.scope.scenarioId);
        const v01ParentStorageBase=`dvaia:secureshop:${actor.scope.launchId.toLowerCase()}:${actor.scope.generation}`;
        const readV01AssessmentReference=async()=>page.evaluate(({baseKey,sceneId,referenceKey})=>{
          const marker=localStorage.getItem(`${baseKey}:scene-storage-v1`);
          if(marker!==null&&marker!=='1')throw Error('Exact parent shop state marker unavailable');
          const storageKey=marker===null?baseKey:`${baseKey}:scene:${sceneId}`;
          const raw=localStorage.getItem(storageKey);if(raw===null)throw Error('Exact parent shop state unavailable');
          const snapshot=JSON.parse(raw),reference=snapshot[referenceKey];return reference===undefined?null:JSON.parse(reference);
        },{baseKey:v01ParentStorageBase,sceneId:target.scene.sceneId.toLowerCase(),
          referenceKey:'secureshop.customer-checkout-audit.assessment.v1'});
        const assessed=await V01.runV01CanonicalAssessment({page,frame,...vulnerable,readAssessmentReference:readV01AssessmentReference});
        assert.equal(v01AssessmentPosts.length,1);assert.equal(judgePackets.length,1);
        assert.equal(judgePackets[0].complete,true);assert.equal(judgePackets[0].header.rubric.objectiveId,'ss_auth_bypass_jwt_none');
        const ownedJudgment=(await identity.query(`SELECT evidence_digest,generation,objective_id,rubric_version,mode
          FROM secureshop_auth.assessment_judgments
          WHERE evaluation_id=$1 AND shop_user_id=$2
            AND objective_id='ss_auth_bypass_jwt_none' AND rubric_version='secureshop-checkout-audit-jwt-v1'
            AND mode='vuln'
            AND execution_json->'scope'->>'launchId'=$3 AND execution_json->'scope'->>'scenarioId'=$4
            AND execution_json->'scope'->>'generation'=$5 AND execution_json->'scope'->>'platformOwnerId'=$6
            AND execution_json->'scope'->>'platformSessionId'=$7`,[assessed.judgment.evaluationId,actor.persona.id,
          actor.scope.launchId,actor.scope.scenarioId,String(actor.scope.generation),
          String(actor.scope.platformOwnerId),String(actor.scope.platformSessionId)])).rows;
        assert.equal(ownedJudgment.length,1);
        assert.equal(judgePackets[0].header.evidenceDigest,ownedJudgment[0].evidence_digest);
        assert.equal(ownedJudgment[0].objective_id,'ss_auth_bypass_jwt_none');
        assert.equal(ownedJudgment[0].rubric_version,'secureshop-checkout-audit-jwt-v1');
        assert.equal(ownedJudgment[0].mode,'vuln');assert.ok(Number.isSafeInteger(ownedJudgment[0].generation));
        const retained=await composition.checkoutAuditLesson.assessment.assertRetainedPacket({
          packet:judgePackets[0].header.packet,scope:actor.scope,persona:actor.persona,
          personaSession:actor.personaSession});await retained.assertCurrent();
        const activeContributionCount=async()=>Number((await identity.query(`SELECT count(*)::int n
          FROM secureshop_auth.active_assessment_contributions c
          JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
          WHERE c.objective_id='ss_auth_bypass_jwt_none' AND c.evaluation_id=$1 AND j.shop_user_id=$2
            AND c.generation=$8 AND j.objective_id='ss_auth_bypass_jwt_none'
            AND j.rubric_version='secureshop-checkout-audit-jwt-v1' AND j.mode='vuln'
            AND c.execution_json->'scope'->>'launchId'=$3 AND c.execution_json->'scope'->>'scenarioId'=$4
            AND c.execution_json->'scope'->>'generation'=$5 AND c.execution_json->'scope'->>'platformOwnerId'=$6
            AND c.execution_json->'scope'->>'platformSessionId'=$7`,[assessed.judgment.evaluationId,actor.persona.id,
          actor.scope.launchId,actor.scope.scenarioId,String(actor.scope.generation),
          String(actor.scope.platformOwnerId),String(actor.scope.platformSessionId),ownedJudgment[0].generation])).rows[0].n);
        assert.equal(await activeContributionCount(),1);v01.canonicalJudgeCredit=true;v01.durableProgress=true;
        status.noObjectiveCredit=false;
        const recoveryJudge=status.judgeCalls,recoveryModels=status.actualModelCalls;
        await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);
        await frame.waitForFunction(() => {
          const select=document.querySelector('[data-testid="agent-lane"] select');
          return select&&!select.disabled&&select.getClientRects().length
            &&[...select.options].some(option=>option.value==='checkout-audit-lesson'&&!option.disabled);
        },{timeout:30000});
        await frame.select('[data-testid="agent-lane"] select','checkout-audit-lesson');
        const recovered=await V01.readV01CanonicalAssessmentPhysically({page,frame,...vulnerable,
          evaluationId:assessed.judgment.evaluationId});
        assert.equal(recovered.replayed,true);assert.equal(status.judgeCalls,recoveryJudge);
        assert.equal(status.actualModelCalls,recoveryModels);assert.equal(v01AssessmentPosts.length,1);
        v01.savedGetNoReplay=true;v01.assessmentGetNoReplay=true;
        const modeBefore=await mode.get(registration.context);
        await mode.set(registration.context,{mode:'fixed',expectedRevision:modeBefore.revision});
        await click(frame,'Start another checkout-audit lesson');
        const fixedActorBefore=status.actualModelCalls,fixedReadBefore=v01ProtectedAuditReads.total,
          fixedSpanBefore=v01ActorSpans.length;
        const fixed=await V01.runV01RenderedFixed({page,frame,
          order:{id:Number(order.order_id),total:Number(order.total_amount)},operationId:approvedProposal.proposalId});
        assert.equal(status.actualModelCalls-fixedActorBefore,2);assert.equal(v01Posts.length,2);
        V01.assertV01ActorRequest(v01Posts[1],{sessionId:fixed.sessionId,requestId:fixed.requestId,
          checkoutOperationId:fixed.operationId,forgedTokenSha256:fixed.forgedTokenSha256,calls:2});
        assert.equal(v01ProtectedAuditReads.total,fixedReadBefore);
        const fixedSource=(await agents.query(`SELECT status,result_json FROM secureshop_agents.turn_requests
          WHERE session_id=$1 AND request_id=$2`,[fixed.sessionId,fixed.requestId])).rows;
        assert.equal(fixedSource.length,1);assert.equal(fixedSource[0].status,'completed');
        assert.equal(fixedSource[0].result_json.hops.length,1);
        assert.equal(fixedSource[0].result_json.hops[0].tool,'auth.audit_probe');
        assert.equal(fixedSource[0].result_json.taskMetadata.checkoutAuditJwt.version,2);
        assert.deepEqual(fixedSource[0].result_json.hops[0].params,{});
        assert.equal(fixedSource[0].result_json.taskMetadata.checkoutAuditJwt.state,'no_effect');
        assert.equal(fixedSource[0].result_json.hops[0].error,null);
        assert.deepEqual(fixedSource[0].result_json.hops[0].result,
          {content:[{type:'text',text:JSON.stringify({status:'denied'})}],isError:true});
        assert.equal(v01ActorSpans.length-fixedSpanBefore,2);
        assert.equal(v01ActorSpans[fixedSpanBefore].response.tool_uses.length,1);
        assert.equal(v01ActorSpans[fixedSpanBefore].response.tool_uses[0].name,'auth.audit_probe');
        assert.deepEqual(v01ActorSpans[fixedSpanBefore].response.tool_uses[0].args,{});
        v01Evidence.fixedSource=structuredClone(fixedSource[0]);
        v01.fixedModelSelectedProbe=true;v01.fixedRenderedDenial=true;v01.fixedNoProtectedRead=true;
        const fixedAssessment=await V01.runV01FixedAssessment({page,frame,...fixed,readAssessmentReference:readV01AssessmentReference});
        assert.equal(fixedAssessment.status,'ineligible');assert.equal(status.judgeCalls,1);
        assert.equal(v01ProtectedAuditReads.total,fixedReadBefore);assert.equal(v01AssessmentPosts.length,2);
        v01Evidence.protectedReadCounts=Object.freeze({
          vulnerableExpected:vulnerableReadAfter.expected-vulnerableReadBefore.expected,
          vulnerableUnexpected:vulnerableReadAfter.unexpected-vulnerableReadBefore.unexpected,
          fixedTotal:v01ProtectedAuditReads.total-fixedReadBefore});
        assert.equal(await activeContributionCount(),1);v01.fixedNoJudgeOrCredit=true;
        const siblingPath=`/api/secureshop/agents/customer/checkout-audit/assess/${vulnerable.sessionId}/${vulnerable.requestId}`;
        const siblingResponse=await fetch(`${origin}${siblingPath}`,{headers:{authorization:`Bearer ${siblingReady.persona.token}`,
          'x-dvaia-secureshop-launch':siblingReady.bearer},redirect:'error',signal:AbortSignal.timeout(10000)});
        assert.notEqual(siblingResponse.status,200);await siblingResponse.arrayBuffer();v01.siblingPrivate=true;
        const resetResult=await reset.launchResetCoordinator.reset({...actor.scope,expectedGeneration:actor.scope.generation,
          idempotencyKey:randomUUID()});assert.equal(resetResult.status,'committed');
        const resetResponse=await fetch(`${origin}${siblingPath}`,{headers:{authorization:`Bearer ${ready.persona.token}`,
          'x-dvaia-secureshop-launch':ready.bearer},redirect:'error',signal:AbortSignal.timeout(10000)});
        assert.notEqual(resetResponse.status,200);await resetResponse.arrayBuffer();
        assert.equal(await activeContributionCount(),0);v01.resetFenced=true;
        const immutable=(await identity.query(`SELECT count(DISTINCT j.evaluation_id)::int judgments,
          count(DISTINCT c.evaluation_id)::int completions FROM secureshop_auth.assessment_judgments j
          LEFT JOIN secureshop_auth.assessment_completions c
            ON c.tenant_id=j.tenant_id AND c.principal_id=j.principal_id AND c.evaluation_id=j.evaluation_id
            AND c.objective_id=j.objective_id AND c.generation=j.generation
          WHERE j.evaluation_id=$1 AND j.shop_user_id=$2
            AND j.objective_id='ss_auth_bypass_jwt_none' AND j.rubric_version='secureshop-checkout-audit-jwt-v1'
            AND j.mode='vuln' AND j.generation=$8
            AND j.execution_json->'scope'->>'launchId'=$3 AND j.execution_json->'scope'->>'scenarioId'=$4
            AND j.execution_json->'scope'->>'generation'=$5 AND j.execution_json->'scope'->>'platformOwnerId'=$6
            AND j.execution_json->'scope'->>'platformSessionId'=$7`,[assessed.judgment.evaluationId,actor.persona.id,
          actor.scope.launchId,actor.scope.scenarioId,String(actor.scope.generation),
          String(actor.scope.platformOwnerId),String(actor.scope.platformSessionId),ownedJudgment[0].generation])).rows[0];
        assert.deepEqual(immutable,{judgments:1,completions:1});
        v01.immutableHistoryRetained=true;v01.passed=true;
        assert.equal(status.noObjectiveCredit,false);
        v01Receipt=v01;
      }else{
        assert.equal((await identity.query('SELECT count(*)::int AS n FROM secureshop_auth.assessment_judgments')).rows[0].n, judgmentsBefore);
        assert.equal(status.judgeCalls, 0); status.noObjectiveCredit = true;
      }
      assert.equal(posts.length, V01_AUDIT ? 5 : 7); assert.ok(status.actualModelCalls >= posts.length + v01Posts.length
        && status.actualModelCalls <= (V01_AUDIT ? 28 : 24));
      if (interceptionFailure) throw interceptionFailure;
      await page.screenshot({ path: path.join(path.dirname(receiptPath), 'customer-checkout-orders.png'), fullPage: true });
      status.passed = true;
      }
      }
    } catch (error) { failure = error; if (v19) { try { v19.recordFailure(stage, error); } catch (preserve) { failure = new AggregateError([error, preserve], 'V19 failure preservation failed'); } } }
    finally {
      if (failure) {
        const visible = [], masks = [], renderedReplies = [], paymentVisible = [], addressVisible = [], profileVisible = [];
        let productTurnDiagnostics = null;
        if (PRODUCT_DETAILS && Number.isSafeInteger(productTraceFloor) && posts[1]?.sessionId && posts[1]?.requestId) {
          try {
            const submitted = posts[1];
            const row = (await pools.AGENTS_RUNTIME.query(`SELECT status,finished_at
              FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`,
            [submitted.sessionId, submitted.requestId])).rows[0];
            const traces = (await pools.AGENTS_RUNTIME.query(`SELECT step,kind,agent_ns,tool_name,policy_violation,
              CASE WHEN result_json IS NULL THEN NULL ELSE result_json::jsonb->>'isError' END AS is_error,
              CASE WHEN result_json IS NULL THEN NULL ELSE result_json::jsonb->>'errorCode' END AS error_code
              FROM secureshop_agents.agent_trace WHERE session_id=$1 AND id>$2
              ORDER BY id LIMIT 32`, [submitted.sessionId, productTraceFloor])).rows;
            productTurnDiagnostics = { requestId: submitted.requestId,
              status: row?.status || 'not_observed', finishedAt: row?.finished_at || null,
              trace: traces.map(trace => ({ step: trace.step, kind: trace.kind,
                agent: trace.agent_ns, tool: trace.tool_name,
                isError: trace.is_error === 'true',
                policyViolation: trace.policy_violation === 'blocked' ? 'blocked' : null,
                errorCode: /^[A-Z][A-Z0-9_]{0,63}$/.test(trace.error_code || '') ? trace.error_code : null })) };
          } catch (error) { productTurnDiagnostics = { status: 'diagnostic_unavailable', code: error.code || error.name }; }
        }
        if (page && !page.isClosed()) {
          const surfaces = page.frames();
          for (const surface of surfaces) {
            const labels = await surface.evaluate(() => [...document.querySelectorAll('h1,h2,h3,[role="alert"]')]
              .filter(node => node.getClientRects().length && !node.querySelector('input,textarea,[contenteditable]'))
              .slice(0, 12).map(node => ({ kind: node.getAttribute('role') || node.tagName.toLowerCase(),
                text: node.innerText.replace(/\s+/g, ' ').slice(0, 160) }))).catch(() => []);
            visible.push(...labels);
            if (PAYMENT_SETUP) {
              const payment = await surface.evaluate(() => ['Practice payment setup',
                'Current practice payment choices'].map(label => {
                const section = document.querySelector(`[aria-label="${label}"]`);
                if (!section || !section.getClientRects().length) return null;
                return { label, status: [...section.querySelectorAll('[role="status"]')]
                  .filter(node => node.getClientRects().length)
                  .map(node => node.textContent.replace(/\s+/g, ' ').slice(0, 240)).slice(0, 3),
                buttons: [...section.querySelectorAll('button')]
                  .filter(node => node.getClientRects().length)
                  .map(node => ({ text: node.textContent.replace(/\s+/g, ' ').slice(0, 100),
                    disabled: node.disabled })).slice(0, 6),
                text: section.innerText.replace(/\s+/g, ' ').slice(0, 360) };
              }).filter(Boolean)).catch(() => []);
              paymentVisible.push(...payment.slice(0, 2));
            }
            if (ADDRESS_SETUP) {
              const address = await surface.evaluate(() => ['Address setup', 'Current delivery addresses']
                .map(label => {
                  const section = document.querySelector(`[aria-label="${label}"]`);
                  if (!section || !section.getClientRects().length) return null;
                  return { label, status: [...section.querySelectorAll('[role="status"],[role="alert"]')]
                    .filter(node => node.getClientRects().length)
                    .map(node => node.textContent.replace(/\s+/g, ' ').slice(0, 240)).slice(0, 3),
                  buttons: [...section.querySelectorAll('button')]
                    .filter(node => node.getClientRects().length)
                    .map(node => ({ text: node.textContent.replace(/\s+/g, ' ').slice(0, 100),
                      disabled: node.disabled })).slice(0, 6),
                  text: section.innerText.replace(/\s+/g, ' ').slice(0, 360) };
                }).filter(Boolean)).catch(() => []);
              addressVisible.push(...address.slice(0, 2));
            }
            if (PROFILE) {
              const profile = await surface.evaluate(() => {
                const section = document.querySelector('[aria-label="Profile update review"]');
                if (!section || !section.getClientRects().length) return null;
                return { reviewVisible: !!section.querySelector('[aria-label="Profile changes to confirm"]')?.getClientRects().length,
                  status: [...section.querySelectorAll('[role="status"],[role="alert"]')]
                    .filter(node => node.getClientRects().length)
                    .map(node => node.textContent.replace(/\s+/g, ' ').slice(0, 160)).slice(0, 3),
                  buttons: [...section.querySelectorAll('button')]
                    .filter(node => node.getClientRects().length)
                    .map(node => ({ text: node.textContent.replace(/\s+/g, ' ').slice(0, 64),
                      disabled: node.disabled })).slice(0, 4) };
              }).catch(() => null);
              if (profile) profileVisible.push(profile);
            }
            const reply = await surface.evaluate(() => [...document.querySelectorAll('[data-testid="agent-turn-reply"]')]
              .filter(node => node.getClientRects().length).at(-1)?.textContent?.trim().slice(0, 8192) || null).catch(() => null);
            if (reply) renderedReplies.push(reply);
            const mask = await surface.addStyleTag({ content: 'input,textarea,[contenteditable] { visibility:hidden !important; }' }).catch(() => null);
            if (mask) masks.push(mask);
          }
          if (masks.length === surfaces.length) {
            const screenshot = path.join(path.dirname(receiptPath), PROFILE
              ? 'customer-profile-failure.png' : ADDRESS_SETUP
                ? 'customer-address-failure.png' : PAYMENT_SETUP
                  ? 'customer-payment-setup-failure.png' : 'customer-checkout-failure.png');
            await page.screenshot({ path: screenshot, fullPage: true }).then(() => fs.chmod(screenshot, 0o600)).catch(() => {});
          }
          for (const mask of masks) await mask.evaluate(node => node.remove()).catch(() => {});
        }
        await fs.writeFile(path.join(path.dirname(receiptPath), PROFILE
          ? 'customer-profile-failure.json' : ADDRESS_SETUP
            ? 'customer-address-failure.json' : PAYMENT_SETUP
              ? 'customer-payment-setup-failure.json' : 'customer-checkout-failure.json'),
          JSON.stringify({ stage, code: failure.code || failure.name, visible: visible.slice(0, 24),
            ...(PAYMENT_SETUP ? { paymentVisible: paymentVisible.slice(0, 4) } : {}),
            ...(ADDRESS_SETUP ? { addressVisible: addressVisible.slice(0, 4) } : {}),
            ...(PROFILE ? { profileVisible: profileVisible.slice(0, 2) } : {}),
            ...(PROFILE ? { profileConfirmResponse, profileConfirmFailure } : {}),
            renderedReplies: renderedReplies.slice(0, 2), decisions, completedTurns, turnObservations,
            ...(PRODUCT_DETAILS ? { productTurnDiagnostics } : {}),
            ...(ADDRESS_SETUP ? { addressTurnEvidence: addressTurnEvidence.slice(0, 3) } : {}),
            ...(checkoutRecoveryDiagnostic ? { checkoutRecoveryDiagnostic } : {}),
            ...(checkoutChoiceEvidence ? { checkoutChoiceEvidence } : {}),
            ...(UPLOAD_BROWSER ? { v06SessionResponses: v06SessionResponses.slice(0,2),
              v06SessionServerResponses: v06SessionServerResponses.slice(0,2),
              v06SessionDiagnostics: v06SessionDiagnostics.slice(0,2) } : {}),
            ...(V01_AUDIT ? { v01PreparationResponses: checkoutHttpResponses
              .filter(record => /^\/api\/secureshop\/(?:orders\/operations\/[a-f0-9-]{36}|agents\/customer\/checkout-audit\/practice-token)$/.test(record.pathname))
              .slice(0,4).map(({pathname,method,status,body,error}) => ({pathname,method,status,body,error})),
              v01AssessmentResponses: checkoutHttpResponses
                .filter(record => /^\/api\/secureshop\/agents\/customer\/checkout-audit\/assess(?:\/[a-f0-9-]{36}\/[a-f0-9-]{36})?$/.test(record.pathname))
                .slice(0,4).map(({pathname,method,status,body,error}) => ({pathname,method,status,body,error})),
              v01AssessmentDiagnostics: v01AssessmentDiagnostics.slice(0,2) } : {}),
            actualModelCalls: status.actualModelCalls, chatTurns: status.chatTurns }, null, 2), { mode: 0o600 }).catch(() => {});
      }
      const cleanup = async (name, action) => { try { await action(); } catch (error) { status.cleanupErrors.push(`${name}:${error.code || error.name}`); } };
      await cleanup('interception', () => CHECKOUT_FENCES
        ? bounded(Promise.all([...pendingInterceptions]), 'checkout interception cleanup')
        : Promise.all([...pendingInterceptions]));
      if (v19) await cleanup('v19-owned-observer', () => v19.close());
      if (cdp) await cleanup('cdp', () => cdp.detach());
      if (browser) await cleanup('browser', () => browser.close());
      if (server) await cleanup('server', () => new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
      if(uploadAssetService)await cleanup('upload-asset',()=>uploadAssetService.stop());
      if(v06FixturePath)await cleanup('v06-fixture',()=>fs.rm(v06FixturePath,{force:true}));
      await cleanup('assessment', async () => composition?.closeBrowserAssessment?.());
      await cleanup('transports', async () => reset?.closeFeatureTransports?.());
      await cleanup('audit', async () => reset?.auditLedger?.close?.());
      for (const pool of [leasePool, ...Object.values(pools)]) await cleanup('pool', () => pool.end());
      if (profile) await cleanup('profile', () => fs.rm(profile, { recursive: true }));
      if(V29_AGENCY||V07_POLYGLOT||V44_PATH_SUMMARY){await cleanup('v44-transport',async()=>v44Transport?.close());if(v44OriginalJudgeURL!==undefined)process.env.OLLAMA_BASE_URL=v44OriginalJudgeURL;}
      status.fixtureCleaned = status.cleanupErrors.length === 0;
      if (!status.fixtureCleaned) status.passed = false;
      if(V44_PATH_SUMMARY){
        if(failure)v44Document.errors.push({stage,name:failure.name,code:failure.code||null,message:String(failure.message).slice(0,400)});saveV44();
        if(v44Receipt){v44Receipt.fixtureCleaned=status.fixtureCleaned;v44Receipt.passed=v44Receipt.passed&&status.fixtureCleaned;
          v44Receipt.evidenceSha256=require('node:crypto').createHash('sha256').update(await fs.readFile(path.join(path.dirname(v44ReceiptPath),'v44-original-evidence.json'))).digest('hex');
          await fs.writeFile(v44ReceiptPath,JSON.stringify(v44Receipt,null,2),{mode:0o600});}}
      if(V29_AGENCY){
        if(failure)v29Document.errors.push({stage,name:failure.name,code:failure.code||null,
          message:String(failure.message).slice(0,400)});
        saveV29();
        status.evidenceSha256=require('node:crypto').createHash('sha256')
          .update(await fs.readFile(path.join(path.dirname(v29ReceiptPath),'v29-original-evidence.json'))).digest('hex');
      }
      if(UPLOAD_BROWSER){const evidenceText=JSON.stringify(v06Evidence,null,2),evidencePath=path.join(path.dirname(v06ReceiptPath),V07_POLYGLOT?'v07-original-evidence.json':V46_TRAVERSAL?'v46-original-evidence.json':V08_SVG?'v08-original-evidence.json':'v06-original-evidence.json');
        if(Buffer.byteLength(evidenceText,'utf8')<=4*1024*1024)await fs.writeFile(evidencePath,evidenceText,{mode:0o600});else{status.cleanupErrors.push('v06-evidence:EVIDENCE_LIMIT');status.fixtureCleaned=false;}
        if(v08Receipt){v08Receipt.evidenceSha256=require('node:crypto').createHash('sha256').update(evidenceText).digest('hex');v08Receipt.fixtureCleaned=status.fixtureCleaned;if(!status.fixtureCleaned)v08Receipt.passed=false;await fs.writeFile(v06ReceiptPath,JSON.stringify(v08Receipt,null,2),{mode:0o600});}else if(v06Receipt){v06Receipt.evidenceSha256=require('node:crypto').createHash('sha256').update(evidenceText).digest('hex');v06Receipt.fixtureCleaned=status.fixtureCleaned;if(!status.fixtureCleaned)v06Receipt.passed=false;
          await fs.writeFile(v06ReceiptPath,JSON.stringify(v06Receipt,null,2),{mode:0o600});}}
      if(V01_AUDIT){
        const evidenceText=JSON.stringify(v01Evidence,null,2);
        const evidencePath=path.join(path.dirname(v01ReceiptPath),'v01-original-evidence.json');
        if(Buffer.byteLength(evidenceText,'utf8')<=4*1024*1024)await fs.writeFile(evidencePath,evidenceText,{mode:0o600});
        else {status.cleanupErrors.push('v01-evidence:EVIDENCE_LIMIT');status.fixtureCleaned=false;}
        if(v01Receipt){v01Receipt.evidenceSha256=require('node:crypto').createHash('sha256').update(evidenceText).digest('hex');
          v01Receipt.fixtureCleaned=status.fixtureCleaned;if(!status.fixtureCleaned)v01Receipt.passed=false;
          const V01=require('../fixtures/secureshopCustomerCheckoutAuditRenderedQualification');
          await fs.writeFile(v01ReceiptPath,JSON.stringify(V01.assertV01BrowserReceipt(v01Receipt),null,2),{mode:0o600});}}
      if (v19) await cleanup("v19-receipt", () => v19.finalize());
      if (status.cleanupErrors.length) { status.fixtureCleaned = false; status.passed = false; }
      await fs.writeFile(receiptPath, JSON.stringify(status, null, 2), { mode: 0o600 });
    }
    if (failure) throw failure;
    assert.deepEqual(status.cleanupErrors, []); for (const flag of FLAGS)
      assert.equal(status[flag], (V07_POLYGLOT||V46_TRAVERSAL||V44_PATH_SUMMARY||V08_SVG||V06_UPLOAD) && flag === 'fixtureLocalCandidateAdmission'
        ? (V44_PATH_SUMMARY?v44Document.catalogAdmission:v06Evidence.catalogAdmission).fixtureLocalCandidateAdmission
        : (V01_AUDIT||UPLOAD_BROWSER) && flag === 'noObjectiveCredit' ? false : true, flag);
  });

module.exports = { privateOrdersListArguments, createV07CommittedAckObserver, v29JudgeRequestRecord };
