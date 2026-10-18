'use strict';

const issued = new WeakMap();
const BROWSER_OBJECTIVES = Object.freeze(['csrf_g2', 'csrf_g3', 'csrf_p1', 'csrf_p2', 'csrf_p3']);
const ATTACKER_ORIGIN = 'http://attacker.csrf.invalid';
const VICTIM_ORIGIN = 'http://victim.csrf.invalid';

// Internal capability: only the trusted workflow issues this after Chrome has
// observed the response. JSON submitted by a learner cannot recreate it.
function issueCsrfBrowserReceipt({ binding, observation, responseStatus, execution, activity }) {
  const receipt = Object.freeze({ type: 'browser_observed', runId: binding.runId,
    ownerKey: binding.ownerKey, generation: binding.generation,
    objectiveId: binding.objectiveId, tab: binding.tab, payloadDigest: binding.payloadDigest,
    method: observation.method, frameOrigin: observation.frameOrigin,
    resourceType: observation.resourceType, cookiePresent: observation.cookiePresent,
    responseStatus, responseObserved: true });
  issued.set(receipt, { execution, activity });
  return receipt;
}

function hasCsrfBrowserReceipt({ receipt, execution, activity, userId, objectiveId }) {
  const scope = receipt && issued.get(receipt);
  return !!scope && scope.execution === execution && scope.activity === activity
    && receipt.runId === execution.runId && receipt.generation === execution.generation
    && receipt.ownerKey === execution.ownerKey
    && receipt.ownerKey === JSON.stringify(['CSRF', String(userId)])
    && receipt.objectiveId === objectiveId && BROWSER_OBJECTIVES.includes(objectiveId);
}

module.exports = { BROWSER_OBJECTIVES, ATTACKER_ORIGIN, VICTIM_ORIGIN,
  issueCsrfBrowserReceipt, hasCsrfBrowserReceipt };
