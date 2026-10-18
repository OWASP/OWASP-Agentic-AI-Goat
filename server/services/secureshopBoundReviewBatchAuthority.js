'use strict';

const CONTRACT = 'bound-review-batch-v1';
const authorities = new WeakSet();

function createBoundReviewBatchAuthority({ requested, batchLimit } = {}) {
  if (!Number.isInteger(requested) || requested < 1 || requested > 100
      || !Number.isInteger(batchLimit) || batchLimit < 1 || batchLimit > requested) {
    throw new TypeError('Bound review batch configuration required');
  }
  let issued = false;
  let hasMore = false;
  let considered = 0;
  const issuedIds = new Set();
  const unresolved = new Map();
  const authority = Object.freeze({
    requested,
    batchLimit,
    issue(rows, more) {
      if (issued || !Array.isArray(rows) || rows.length > batchLimit || typeof more !== 'boolean') {
        throw new TypeError('Invalid bound review batch snapshot');
      }
      const ids = rows.map(row => row?.id);
      if (ids.some(id => !Number.isSafeInteger(id) || id < 1)
          || new Set(ids).size !== ids.length) {
        throw new TypeError('Invalid bound review batch row');
      }
      issued = true;
      hasMore = more;
      for (const row of rows) {
        issuedIds.add(row.id);
        unresolved.set(row.id, row);
      }
    },
    isIssued() { return issued; },
    isUnresolved(reviewId) { return issued && unresolved.has(reviewId); },
    unresolvedRows() { return Object.freeze([...unresolved.values()]); },
    consider(reviewId) {
      if (!issued || !issuedIds.has(reviewId)) throw new TypeError('Review is outside the bound batch');
      if (!unresolved.delete(reviewId)) return false;
      considered += 1;
      return true;
    },
    shouldEnterFinalResponse() { return issued && unresolved.size === 0; },
    metadata() {
      const complete = issued && unresolved.size === 0;
      return Object.freeze({ contract: CONTRACT, requested, considered, complete,
        continuationRequired: complete && hasMore && considered < requested });
    },
  });
  authorities.add(authority);
  return authority;
}

function assertBoundReviewBatchAuthority(value) {
  if (!authorities.has(value)) throw new TypeError('Trusted bound review batch authority required');
  return value;
}

module.exports = { CONTRACT, createBoundReviewBatchAuthority, assertBoundReviewBatchAuthority };
