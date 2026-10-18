'use strict';

const { createHash } = require('node:crypto');
const {
  createV06UploadAssessment
} = require('./secureshopV06UploadAssessment');
const {
  TRAVERSAL_OBJECTIVE,
  TRAVERSAL_PURPOSE,
  TRAVERSAL_RUBRIC,
  buildTraversalCandidate
} = require('./secureshopV46TraversalEvidence');

const hash = value => createHash('sha256').update(value).digest('hex');
const sourceFingerprint = source => hash(JSON.stringify([
  source.retained.admission.bindingSha256,
  source.retained.effect.effectSha256,
  source.retained.readback.bodySha256
]));

const TRAVERSAL_EVIDENCE_CONTRACT = Object.freeze({
  objectiveId: TRAVERSAL_OBJECTIVE,
  rubric: TRAVERSAL_RUBRIC,
  sourcePurpose: TRAVERSAL_PURPOSE,
  buildCandidate: buildTraversalCandidate,
  sourceFingerprint
});

function createSecureShopV46TraversalAssessment(options = {}) {
  return createV06UploadAssessment({
    ...options,
    evidenceContract: TRAVERSAL_EVIDENCE_CONTRACT
  });
}

module.exports = {
  TRAVERSAL_EVIDENCE_CONTRACT,
  createSecureShopV46TraversalAssessment
};
