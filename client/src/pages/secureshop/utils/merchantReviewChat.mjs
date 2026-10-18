import { trustedTurnMode } from './turnModeCapability.mjs';
import { verifyManualReceipt } from './manualReviewOperation.mjs';

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const positive = value => Number.isSafeInteger(value) && value > 0;
const bytes = value => new TextEncoder().encode(value).length;
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function exact(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function reviewMode(value) {
  const mode = trustedTurnMode(value);
  if (!mode || mode.featureId !== 'review'
    || mode.policyVersion !== 'product-feedback-enforced-decision-v1')
    throw Error('Saved review mode is invalid.');
  return mode;
}

export function decodeMerchantReviewDetail(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'choiceId', 'reviewId', 'productId', 'rating', 'status', 'body', 'oversized', 'modeCapability'])
    || value.version !== 1 || !UUID.test(value.choiceId) || !positive(value.reviewId)
    || !positive(value.productId) || !Number.isSafeInteger(value.rating) || value.rating < 1
    || value.rating > 5 || !['pending', 'approved', 'rejected'].includes(value.status)
    || typeof value.oversized !== 'boolean'
    || (value.oversized ? value.body !== null : typeof value.body !== 'string')
    || (typeof value.body === 'string' && bytes(value.body) > 65536)) {
    throw Error('Saved review detail is invalid.');
  }
  reviewMode(value.modeCapability);
  return value;
}

export function decodeMerchantReviewPage(value) {
  if (value === null) return null;
  if (!(exact(value, ['page', 'total', 'nextPage', 'status']) || exact(value, ['page', 'total', 'nextPage', 'status', 'productChoiceId']))
    || !Number.isSafeInteger(value.page) || value.page < 1
    || !Number.isSafeInteger(value.total) || value.total < 0
    || (value.nextPage !== null && value.nextPage !== value.page + 1)
    || !['pending', 'approved', 'rejected', 'all'].includes(value.status)
    || (value.productChoiceId !== undefined && value.productChoiceId !== null && !UUID.test(value.productChoiceId))) {
    throw Error('Saved review page is invalid.');
  }
  return Object.freeze({ ...value });
}

export function decodeMerchantReviewProposal(value) {
  if (value === null) return null;
  if (!exact(value, ['version', 'proposalId', 'review', 'decision', 'reason', 'expectedSnapshotSha256',
    'requestSha256', 'scopeKey', 'modeCapability'])
    || value.version !== 1 || !UUID.test(value.proposalId)
    || !exact(value.review, ['choiceId', 'reviewId', 'productId', 'rating', 'body', 'status'])
    || !UUID.test(value.review.choiceId) || !positive(value.review.reviewId)
    || !positive(value.review.productId) || !Number.isSafeInteger(value.review.rating)
    || value.review.rating < 1 || value.review.rating > 5 || typeof value.review.body !== 'string'
    || bytes(value.review.body) > 65536 || value.review.status !== 'pending'
    || !['approve', 'reject'].includes(value.decision)
    || (value.decision === 'approve' ? value.reason !== null
      : typeof value.reason !== 'string' || !value.reason.trim() || bytes(value.reason) > 1024)
    || !SHA.test(value.expectedSnapshotSha256) || !SHA.test(value.requestSha256)
    || typeof value.scopeKey !== 'string' || value.scopeKey.length < 1 || value.scopeKey.length > 1024) {
    throw Error('Saved review proposal is invalid.');
  }
  reviewMode(value.modeCapability);
  return value;
}

export function sameMerchantReviewProposal(a, b) {
  try { return same(decodeMerchantReviewProposal(a), decodeMerchantReviewProposal(b)); }
  catch { return false; }
}

export function merchantReviewSelection(choiceId, intent) {
  if (!UUID.test(choiceId) || !['review_details', 'review_approve', 'review_reject'].includes(intent))
    throw Error('Review selection is invalid.');
  return Object.freeze({ choiceId, intent });
}

export function verifyMerchantReviewReceipt(receipt, reference, executionScopeKey) {
  verifyManualReceipt(receipt, reference, executionScopeKey);
  if (!reference || !SHA.test(reference.expectedSnapshotSha256)
    || receipt?.expectedSnapshotSha256 !== reference.expectedSnapshotSha256
    || (receipt.applied === true ? receipt.resultCode !== null
      : !['REVIEW_STALE', 'REVIEW_NOT_PENDING'].includes(receipt.resultCode)))
    throw Error('Saved review result is invalid.');
  return receipt;
}
