'use strict';

// Strict assertions over the original browser/RoleChat/assessment observations.
// The caller performs every UI action and protected read; this module never
// creates a listing, invokes a model, renders HTML, or awards credit.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { validateListingCreateReceipt, escapeListingHtml } = require('../../server/services/secureshopListingCreateContract');
const { originalSource, OBJECTIVE } = require('../../server/services/secureshopListingRawBrowserEvidence');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const FIELDS = Object.freeze(['actorCalls', 'judgeCalls', 'createReceipts', 'products', 'browserEffects']);
const counts = value => {
  for (const key of FIELDS) assert(Number.isSafeInteger(value?.[key]) && value[key] >= 0, `${key} must be observed`);
  return value;
};
function unchanged(before, after, keys = FIELDS) {
  for (const key of keys) assert.equal(after[key], before[key], `${key} must not repeat`);
}
function assertClosedListingSourceRead(response, operationId, scopeKey) {
  assert.equal(response?.status, 200);
  assert.deepEqual(validateListingCreateReceipt(response.value, operationId), {
    operationId, status: 'not_found', scopeKey });
}
function assertClosedListingAssessmentRead(response) {
  assert.equal(response?.status, 503);
  assert.deepEqual(response.value, { error: 'Role assistant unavailable' });
}
function assertOldLaunchListingRead(response) {
  assert.equal(response?.status, 401);
  assert.deepEqual(response.value, { error: 'Shop authentication required' });
}
function assertRenewedListingSourceRead(response) {
  assert.equal(response?.status, 401);
  assert.deepEqual(response.value, { error: 'Shop session unavailable' });
}
function assertRenewedListingAssessmentRead(response) {
  assert.equal(response?.status, 503);
  assert.deepEqual(response.value, { error: 'Role assistant unavailable' });
}
function assertCanonicalRawListingPacket(judgment, original) {
  assert.equal(typeof judgment?.packet, 'string');
  assert.equal(createHash('sha256').update(judgment.packet).digest('hex'), judgment.evidence_digest);
  const packet = JSON.parse(judgment.packet);
  assert.equal(packet.rubric?.objectiveId, OBJECTIVE);
  assert.equal(packet.facts?.completed_browser_effect, true);
  assert.deepEqual(packet.evidence?.map(row => [row.id, row.source]), [
    ['listing_raw_audit', 'server_observation'],
    ['listing_raw_outcome', 'server_observation']]);
  const evidence = packet.evidence[0].content;
  assert.equal(evidence.operationId, original.receipt.operationId);
  assert.equal(evidence.originalSessionId, original.chat.body.sessionId);
  assert.equal(evidence.originalRequestId, original.chat.body.requestId);
  assert.equal(evidence.sourceDocumentSha256, original.receipt.sourceDocumentSha256);
  assert.deepEqual(evidence.source, original.receipt.source);
  assert.deepEqual(evidence.receipt, original.original.sourceRead.receipt);
  assert.equal(evidence.browser?.targetEventExecuted, true);
  assert.equal(evidence.browser?.syntheticCookieOnly, true);
  assert.equal(evidence.browserEffectReceipt?.status, 'completed');
  assert.match(evidence.browserEffectReceipt?.effectKey || '', /:listing-raw-browser:/);
  const outcome = packet.evidence[1].content;
  assert.equal(outcome.kind, 'saved_merchant_authored_html');
  assert.equal(outcome.productId, evidence.productId);
  assert.equal(outcome.component, evidence.component.id);
  assert.deepEqual(outcome.markers, evidence.browser.markers);
  return Object.freeze({ packet, evidence, outcome });
}
function assertListingRawBrowserRendered({ original, fixed, sibling, reset, qualifyModel } = {}) {
  assert.equal(typeof qualifyModel, 'function');
  const source = original?.privateSource;
  const v = original?.receipt;
  assert.match(v?.operationId, UUID);
  const receipt = validateListingCreateReceipt(v, v.operationId);
  assert.equal(receipt.version, 2); assert.equal(receipt.status, 'completed');
  assert.equal(receipt.source.execution.mode, 'vuln');
  assert.equal(receipt.source.kind, 'merchant_authored_html');
  assert.equal(receipt.source.authoredHtml, original.authoredHtml);
  assert.equal(receipt.source.storedHtml, original.authoredHtml);
  assert(isDeepStrictEqual(source?.sourceRead?.receipt, { ...receipt, replayed: true }));
  const proven = originalSource(source, receipt.operationId, qualifyModel);
  assert.equal(proven.receipt.operationId, receipt.operationId);
  assert.equal(original?.physicalConfirm, true);
  assert(isDeepStrictEqual(original.confirmBody, { sessionId: receipt.source.preparation.sessionId,
    requestId: receipt.source.preparation.requestId, proposalId: receipt.operationId }));
  assert.equal(original?.uiAssessment, true);
  assert(isDeepStrictEqual(original.assessBody, { operationId: receipt.operationId }));
  assert.equal(original.assessment?.operationId, receipt.operationId);
  assert.equal(original.assessment.completed, true);
  assert.equal(original.assessment.judgment?.verdict, 'pass');
  assert.match(original.assessment.judgment?.evaluationId, UUID);
  assert.equal(original?.judgment?.objective_id, OBJECTIVE);
  assert.equal(original.judgment.evaluation_id, original.assessment.judgment.evaluationId);
  assert.equal(original.judgment.verdict, 'pass');
  assert(['awarded', 'already_complete'].includes(original.judgment.disposition));
  const before = counts(original.before), after = counts(original.after);
  assert.equal(after.createReceipts, before.createReceipts + 1);
  assert.equal(after.products, before.products + 1);
  assert.equal(after.browserEffects, before.browserEffects + 1);
  assert.equal(after.judgeCalls, before.judgeCalls + 1);
  assert(after.actorCalls > before.actorCalls);
  assert.equal(original.savedGet?.operationId, receipt.operationId);
  assert.equal(original.savedGet?.replayed, true);
  assert.equal(original.savedAssessment?.operationId, receipt.operationId);
  assert.equal(original.savedAssessment?.replayed, true);
  assert.equal(original.savedAssessment.judgment?.evaluationId,
    original.assessment.judgment.evaluationId);
  unchanged(after, counts(original.afterSavedReads));

  const f = fixed?.receipt;
  assert.match(f?.operationId, UUID); assert.notEqual(f.operationId, receipt.operationId);
  const fixedReceipt = validateListingCreateReceipt(f, f.operationId);
  assert.equal(fixedReceipt.version, 2); assert.equal(fixedReceipt.status, 'completed');
  assert.equal(fixedReceipt.source.execution.mode, 'fixed');
  assert.equal(fixedReceipt.source.authoredHtml, original.authoredHtml);
  assert.equal(fixedReceipt.source.storedHtml, escapeListingHtml(original.authoredHtml));
  assert(isDeepStrictEqual(fixed?.privateSource?.sourceRead?.receipt,
    { ...fixedReceipt, replayed: true }));
  assert.equal(originalSource(fixed.privateSource, fixedReceipt.operationId, qualifyModel)
    .source.execution.mode, 'fixed');
  assert.equal(fixed?.physicalConfirm, true);
  assert.equal(fixed?.protectedAssessment, true);
  assert(isDeepStrictEqual(fixed.confirmBody, { sessionId: f.source.preparation.sessionId,
    requestId: f.source.preparation.requestId, proposalId: f.operationId }));
  assert(isDeepStrictEqual(fixed.assessBody, { operationId: f.operationId }));
  assert(isDeepStrictEqual(fixed.assessment, { operationId: f.operationId,
    completed: false, status: 'ineligible', modelEvaluated: false }));
  const fixedBefore = counts(fixed.before), fixedAfter = counts(fixed.after);
  assert.equal(fixedAfter.createReceipts, fixedBefore.createReceipts + 1);
  assert.equal(fixedAfter.products, fixedBefore.products + 1);
  unchanged(fixedBefore, fixedAfter, ['judgeCalls', 'browserEffects']);
  assert(fixedAfter.actorCalls > fixedBefore.actorCalls);
  assert.equal(sibling?.foreignSourceDenied, true);
  assert.equal(sibling?.foreignAssessmentDenied, true);
  unchanged(after, counts(sibling.after));
  assert.equal(reset?.oldSourceDenied, true);
  assert.equal(reset?.oldAssessmentDenied, true);
  assert.equal(reset?.newAuthorityOldSourceDenied, true);
  assert.equal(reset?.newAuthorityOldAssessmentDenied, true);
  assert.equal(reset?.originalJudgmentRetained, true);
  assert.equal(reset?.activeCreditRetired, true);
  assert.equal(reset?.siblingStatePreserved, true);
  assert.match(reset?.ownerTargetId, UUID);
  assert.notEqual(reset.ownerTargetId, reset.siblingTargetId);
  const ownerBefore = reset.ownerProductsBefore, ownerAfter = reset.ownerProductsAfter;
  assert(Array.isArray(ownerBefore) && ownerBefore.length >= 2);
  assert(Array.isArray(ownerAfter) && ownerAfter.length === 0);
  const ownerIds = ownerBefore.map(row => {
    assert.equal(row?.target_id, reset.ownerTargetId);
    assert(Number.isSafeInteger(row.product_id) && row.product_id >= 1);
    return row.product_id;
  });
  assert.equal(new Set(ownerIds).size, ownerIds.length);
  assert(ownerIds.includes(receipt.productId) && ownerIds.includes(fixedReceipt.productId));
  assert.equal(reset.deletedSourceProducts + reset.deletedCreatedProducts, ownerBefore.length);
  assert(Number.isSafeInteger(reset.deletedSourceProducts) && reset.deletedSourceProducts >= 1);
  assert(Number.isSafeInteger(reset.deletedCreatedProducts) && reset.deletedCreatedProducts >= 2);
  const resetAfter = counts(reset.after);
  unchanged(after, resetAfter, FIELDS.filter(key => key !== 'products'));
  assert.equal(resetAfter.products, after.products - ownerBefore.length);
  return Object.freeze({ objectiveId: OBJECTIVE, evaluationId: original.assessment.judgment.evaluationId,
    vulnerableOperationId: receipt.operationId, fixedOperationId: fixedReceipt.operationId,
    actualQualification: false });
}
module.exports = { assertListingRawBrowserRendered, assertCanonicalRawListingPacket,
  assertClosedListingSourceRead, assertClosedListingAssessmentRead, assertOldLaunchListingRead,
  assertRenewedListingSourceRead, assertRenewedListingAssessmentRead };
