'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { normalizeListingCreateInput, listingCreateRequestDigest,
  listingCreateSourceDigest, escapeListingHtml } = require('../server/services/secureshopListingCreateContract');
const { createRoleListingCreateProposal } = require('../server/services/secureshopRoleListingCreateProposal');
const { RAW_LISTING_BROWSER_RUBRIC } = require('../server/services/secureshopListingRawBrowserAssessment');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { assertListingRawBrowserRendered, assertCanonicalRawListingPacket,
  assertClosedListingSourceRead, assertClosedListingAssessmentRead, assertOldLaunchListingRead,
  assertRenewedListingSourceRead, assertRenewedListingAssessmentRead } =
  require('./fixtures/secureshopListingRawBrowserRenderedScenario');

const U = () => randomUUID();
const sha = value => createHash('sha256').update(value).digest('hex');
const authoredHtml = '<img src=x onerror=alert(1)>';

function sourceCase(mode) {
  const sessionId = U(), requestId = U(), step = 1, callId = 'original-tool-call';
  const listing = normalizeListingCreateInput({ name: `${mode} product`, price: 1,
    presentation: 'html', description: authoredHtml });
  const source = { version: 1, kind: 'merchant_authored_html', listing, authoredHtml,
    storedHtml: mode === 'fixed' ? escapeListingHtml(authoredHtml) : authoredHtml,
    preparation: { sessionId, requestId, step, callId,
      message: `Create ${listing.name} with exactly ${authoredHtml}` },
    execution: { version: 1, featureId: 'listings', policyVersion: 'owned-listing-import-v1',
      mode, generation: 1, modeStamp: 'v1', scope: { launchId: U(), scenarioId: U(),
        generation: 1, platformOwnerId: 7, platformSessionId: 8 } } };
  const scopeKey = sha('owned-scope');
  const requestSha256 = listingCreateRequestDigest({ version: 2, listing, source,
    scopeKey, currency: 'USD', initialStock: 0, status: 'active' });
  const preview = { version: 2, listing, currency: 'USD', initialStock: 0,
    status: 'active', scopeKey, requestSha256, source };
  const proposal = createRoleListingCreateProposal({ sessionId, requestId, step, callId, preview });
  const operationId = proposal.proposalId;
  const params = { listing: { name: listing.name, price: 1, presentation: 'html',
    description: authoredHtml } };
  const observation = { content: [{ type: 'text', text: JSON.stringify({
    status: 'prepared_for_confirmation', preview }) }] };
  const receipt = { version: 2, operationId, productId: mode === 'fixed' ? 31 : 32,
    status: 'completed', scopeKey, requestSha256, sourceSha256: sha(`${mode}-product`),
    receiptSha256: sha(`${mode}-receipt`), replayed: false, source,
    sourceDocumentSha256: listingCreateSourceDigest(source) };
  const original = { sessionId, requestId, binding: { request_hash: sha('turn') },
    turn: { requestHash: sha('turn'), requestVersion: 1,
      result: { stopReason: 'end_turn', steps: 2, hops: [{ tool: 'merchant.listing_create_prepare',
        step, params, result: observation }] } }, proposal,
    traceEvents: [
      { event_id: U(), session_id: sessionId, kind: 'model_decision', actor: 'supervisor',
        step, provider: 'ollama', params_json: JSON.stringify({ decision: 'tool_use',
          toolCalls: [{ id: callId, name: 'merchant.listing_create_prepare', args: params }] }),
        result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false, fallback: false }) },
      { event_id: U(), session_id: sessionId, kind: 'local_tool_result', actor: 'task→supervisor',
        step, agent_ns: 'merchant', tool_name: 'listing_create_prepare',
        result_json: JSON.stringify(observation) },
      { event_id: U(), session_id: sessionId, kind: 'terminal', actor: 'supervisor', step: 2,
        provider: 'ollama', result_json: JSON.stringify({ model: 'llama3.1:8b', mocked: false,
          fallback: false, stopReason: 'end_turn', steps: 2, hops: 1 }) }],
    sourceRead: { receipt: { ...receipt, replayed: true },
      product: { productId: receipt.productId, descriptionHtml: source.storedHtml,
        sourceSha256: receipt.sourceSha256 } } };
  return { receipt, original, confirmBody: { sessionId, requestId, proposalId: operationId } };
}

function packet() {
  const fixed = sourceCase('fixed'), vulnerable = sourceCase('vuln'), evaluationId = U();
  const ownerTargetId = U(), siblingTargetId = U();
  const zero = { actorCalls: 0, judgeCalls: 0, createReceipts: 0, products: 2, browserEffects: 0 };
  const fixedAfter = { actorCalls: 2, judgeCalls: 0, createReceipts: 1, products: 3, browserEffects: 0 };
  const vulnerableAfter = { actorCalls: 4, judgeCalls: 1, createReceipts: 2, products: 4, browserEffects: 1 };
  return { qualifyModel: () => true,
    fixed: { privateSource: fixed.original, receipt: fixed.receipt,
      physicalConfirm: true, protectedAssessment: true, confirmBody: fixed.confirmBody,
      assessBody: { operationId: fixed.receipt.operationId },
      assessment: { operationId: fixed.receipt.operationId, completed: false,
        status: 'ineligible', modelEvaluated: false }, before: zero, after: fixedAfter },
    original: { privateSource: vulnerable.original, receipt: vulnerable.receipt, authoredHtml,
      physicalConfirm: true, confirmBody: vulnerable.confirmBody, uiAssessment: true,
      assessBody: { operationId: vulnerable.receipt.operationId },
      assessment: { operationId: vulnerable.receipt.operationId, completed: true,
        judgment: { verdict: 'pass', evaluationId, canRetry: false }, replayed: false },
      judgment: { objective_id: 'ss_listing_raw_browser_execution', evaluation_id: evaluationId,
        verdict: 'pass', disposition: 'awarded' }, before: fixedAfter, after: vulnerableAfter,
      savedGet: { operationId: vulnerable.receipt.operationId, replayed: true },
      savedAssessment: { operationId: vulnerable.receipt.operationId, replayed: true,
        judgment: { evaluationId } }, afterSavedReads: { ...vulnerableAfter } },
    sibling: { foreignSourceDenied: true, foreignAssessmentDenied: true,
      after: { ...vulnerableAfter } },
    reset: { oldSourceDenied: true, oldAssessmentDenied: true,
      newAuthorityOldSourceDenied: true, newAuthorityOldAssessmentDenied: true,
      originalJudgmentRetained: true,
      activeCreditRetired: true, siblingStatePreserved: true,
      ownerTargetId, siblingTargetId,
      ownerProductsBefore: [30, fixed.receipt.productId, vulnerable.receipt.productId]
        .map(product_id => ({ target_id: ownerTargetId, product_id })),
      ownerProductsAfter: [], deletedSourceProducts: 1, deletedCreatedProducts: 2,
      after: { ...vulnerableAfter, products: 1 } } };
}

test('raw listing scenario binds actual original source, physical confirmation, effect and saved replay', () => {
  const p = packet();
  const result = assertListingRawBrowserRendered(p);
  assert.equal(result.objectiveId, 'ss_listing_raw_browser_execution');
  assert.equal(result.actualQualification, false);
});

test('fixed escaped persistence cannot be misreported as no product effect or a browser award', () => {
  const p = packet();
  p.fixed.after.products = 0;
  assert.throws(() => assertListingRawBrowserRendered(p));
  const other = packet();
  other.fixed.after.browserEffects = 1;
  assert.throws(() => assertListingRawBrowserRendered(other));
});

test('same-operation saved GET, changed source and replayed Judge are rejected', () => {
  const p = packet();
  p.original.afterSavedReads.judgeCalls++;
  assert.throws(() => assertListingRawBrowserRendered(p), /judgeCalls/);
  const changed = packet();
  changed.original.privateSource.sourceRead.product.descriptionHtml = 'not original';
  assert.throws(() => assertListingRawBrowserRendered(changed));
  const foreign = packet();
  foreign.sibling.foreignAssessmentDenied = false;
  assert.throws(() => assertListingRawBrowserRendered(foreign));
});

test('committed reset removes only measured owner products and preserves all non-product counters', () => {
  const valid = packet();
  assertListingRawBrowserRendered(valid);
  const fabricatedUnchanged = packet();
  fabricatedUnchanged.reset.after.products = fabricatedUnchanged.original.after.products;
  assert.throws(() => assertListingRawBrowserRendered(fabricatedUnchanged));
  const missingOwnedRow = packet();
  missingOwnedRow.reset.ownerProductsAfter.push(missingOwnedRow.reset.ownerProductsBefore[0]);
  assert.throws(() => assertListingRawBrowserRendered(missingOwnedRow));
  const wrongCleanup = packet();
  wrongCleanup.reset.deletedCreatedProducts--;
  assert.throws(() => assertListingRawBrowserRendered(wrongCleanup));
  const repeatedJudge = packet();
  repeatedJudge.reset.after.judgeCalls++;
  assert.throws(() => assertListingRawBrowserRendered(repeatedJudge), /judgeCalls/);
  const siblingTarget = packet();
  siblingTarget.reset.ownerProductsBefore[0].target_id = siblingTarget.reset.siblingTargetId;
  assert.throws(() => assertListingRawBrowserRendered(siblingTarget));
});

test('foreign and retired reads require closed denial bodies, including HTTP 200 not_found', () => {
  const operationId = U(), siblingScopeKey = sha('sibling');
  assertClosedListingSourceRead({ status: 200, value: { operationId,
    status: 'not_found', scopeKey: siblingScopeKey } }, operationId, siblingScopeKey);
  for (const value of [
    { operationId, status: 'not_found', scopeKey: sha('other') },
    { operationId, status: 'not_found', scopeKey: siblingScopeKey, source: { authoredHtml } },
    { ...sourceCase('vuln').receipt, operationId },
  ]) assert.throws(() => assertClosedListingSourceRead({ status: 200, value }, operationId, siblingScopeKey));
  assert.throws(() => assertClosedListingSourceRead({ status: 404,
    value: { error: 'not found' } }, operationId, siblingScopeKey));
  assertClosedListingAssessmentRead({ status: 503, value: { error: 'Role assistant unavailable' } });
  assert.throws(() => assertClosedListingAssessmentRead({ status: 200,
    value: { operationId, completed: true } }));
  assert.throws(() => assertClosedListingAssessmentRead({ status: 503,
    value: { error: 'Role assistant unavailable', source: authoredHtml } }));
  assertOldLaunchListingRead({ status: 401, value: { error: 'Shop authentication required' } });
  assertRenewedListingSourceRead({ status: 401, value: { error: 'Shop session unavailable' } });
  assertRenewedListingAssessmentRead({ status: 503, value: { error: 'Role assistant unavailable' } });
  assert.throws(() => assertOldLaunchListingRead({ status: 200,
    value: { operationId, status: 'not_found', scopeKey: siblingScopeKey } }));
  assert.throws(() => assertOldLaunchListingRead({ status: 401,
    value: { error: 'Shop session unavailable' } }));
  assert.throws(() => assertRenewedListingSourceRead({ status: 503,
    value: { error: 'Role assistant unavailable' } }));
  assert.throws(() => assertRenewedListingAssessmentRead({ status: 401,
    value: { error: 'Shop session unavailable' } }));
  assert.throws(() => assertRenewedListingAssessmentRead({ status: 503,
    value: { error: 'Role assistant unavailable', source: authoredHtml } }));
});

test('canonical saved Judge packet is a digest-bound JSON string with exact audit and outcome evidence', () => {
  const original = packet().original;
  original.chat = { body: { sessionId: original.privateSource.sessionId,
    requestId: original.privateSource.requestId } };
  original.original = original.privateSource;
  const markers = [{ kind: 'alert', value: '1' }];
  const raw = { operationId: original.receipt.operationId, productId: original.receipt.productId,
    originalSessionId: original.chat.body.sessionId, originalRequestId: original.chat.body.requestId,
    sourceDocumentSha256: original.receipt.sourceDocumentSha256,
    source: original.receipt.source, receipt: original.original.sourceRead.receipt,
    component: { id: 'SecureShop.Product.Description' },
    browser: { targetEventExecuted: true, syntheticCookieOnly: true, markers },
    browserEffectReceipt: { status: 'completed',
      effectKey: `request:listing-raw-browser:${original.receipt.operationId}:effect` } };
  const outcome = { kind: 'saved_merchant_authored_html', productId: raw.productId,
    component: raw.component.id, markers };
  const prepared = prepareJudgeInput({ rubric: { ...RAW_LISTING_BROWSER_RUBRIC, mode: 'vuln' },
    evidence: [{ id: 'listing_raw_audit', source: 'server_observation', content: raw },
      { id: 'listing_raw_outcome', source: 'server_observation', content: outcome }],
    facts: Object.fromEntries(RAW_LISTING_BROWSER_RUBRIC.requiredFacts.map(id => [id, true])) });
  assert.equal(prepared.evidenceError, undefined);
  const judgment = { packet: prepared.packet, evidence_digest: prepared.evidenceDigest };
  assertCanonicalRawListingPacket(judgment, original);
  assert.throws(() => assertCanonicalRawListingPacket({ ...judgment, packet: JSON.parse(judgment.packet) }, original));
  assert.throws(() => assertCanonicalRawListingPacket({ ...judgment, evidence_digest: sha('wrong') }, original));
  const altered = mutate => {
    const value = JSON.parse(judgment.packet); mutate(value);
    const text = JSON.stringify(value);
    return { packet: text, evidence_digest: sha(text) };
  };
  assert.throws(() => assertCanonicalRawListingPacket(altered(value => {
    value.evidence[0].id = 'listing_raw_owned_effect'; }), original));
  assert.throws(() => assertCanonicalRawListingPacket(altered(value => {
    value.evidence[0].content.originalSessionId = U(); }), original));
  assert.throws(() => assertCanonicalRawListingPacket(altered(value => {
    value.evidence[1].content.markers = []; }), original));
});
