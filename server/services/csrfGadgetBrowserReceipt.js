'use strict';

const { GADGET_OBJECTIVES } = require('./csrfGadgetBrowserAttempt');
const issued = new WeakMap();

function issueCsrfGadgetBrowserReceipt({ binding, observation, responseStatus, execution, activity }) {
  const selected = GADGET_OBJECTIVES[binding?.objectiveId];
  if (!selected || selected.tab !== binding.tab || selected.vector !== binding.expectedVector) {
    throw new TypeError('Invalid gadget browser binding');
  }
  const receipt = Object.freeze({ type: 'gadget_browser_observed', runId: binding.runId,
    ownerKey: binding.ownerKey, generation: binding.generation,
    objectiveId: binding.objectiveId, tab: binding.tab, payloadDigest: binding.payloadDigest,
    expectedVector: binding.expectedVector, observedVector: activity?.result?.vector,
    method: observation.method, frameOrigin: observation.frameOrigin,
    resourceType: observation.resourceType, cookiePresent: observation.cookiePresent,
    responseStatus, responseObserved: true });
  issued.set(receipt, { execution, activity });
  return receipt;
}

function hasCsrfGadgetBrowserReceipt({ receipt, execution, activity, userId, objectiveId }) {
  const scope = receipt && issued.get(receipt);
  const selected = GADGET_OBJECTIVES[objectiveId];
  const result = activity?.result;
  return !!scope && !!selected && scope.execution === execution && scope.activity === activity
    && receipt.runId === execution.runId && receipt.generation === execution.generation
    && receipt.ownerKey === execution.ownerKey
    && receipt.ownerKey === JSON.stringify(['CSRF', String(userId)])
    && receipt.objectiveId === objectiveId && receipt.tab === selected.tab
    && receipt.expectedVector === selected.vector && receipt.observedVector === selected.vector
    && receipt.method === 'POST' && receipt.resourceType === 'fetch'
    && receipt.cookiePresent === true && receipt.responseObserved === true && receipt.responseStatus === 200
    && activity.userKey === String(userId) && activity.tabId === selected.tab && result?.kind === 'attack'
    && result.executed === true && result.blocked === false && !result.error
    && result.vector === selected.vector;
}

module.exports = { issueCsrfGadgetBrowserReceipt, hasCsrfGadgetBrowserReceipt };
