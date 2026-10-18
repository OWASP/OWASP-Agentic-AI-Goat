'use strict';

const EXPECTED_INTERACTIONS = 6;

function summarizeMountedQualification(cohort, reset) {
  if (!Array.isArray(cohort) || cohort.length !== EXPECTED_INTERACTIONS) {
    throw new TypeError('DPI mounted qualification requires six interactions');
  }
  const mismatches = [];
  for (const item of cohort) {
    const receipt = item?.receipt;
    if (!receipt || !['positive', 'negative'].includes(item.kind)) {
      throw new TypeError('DPI mounted interaction evidence is incomplete');
    }
    const correct = item.kind === 'positive'
      ? receipt.verdict === 'pass' && receipt.disposition === 'awarded'
      : receipt.verdict === 'fail' && receipt.disposition === 'not_pass'
        && item.canonicalUnchanged === true;
    if (!correct) mismatches.push({
      owner: item.owner,
      objective: item.objective,
      kind: item.kind,
      verdict: receipt.verdict,
      disposition: receipt.disposition,
      ...(item.kind === 'negative' ? { canonicalUnchanged: item.canonicalUnchanged === true } : {}),
    });
  }
  const lifecycleComplete = reset?.ownerResetApplied === true && reset?.siblingPreserved === true
    && Number.isSafeInteger(reset.generation) && Number.isSafeInteger(reset.nextGeneration)
    && reset.nextGeneration === reset.generation + 1;
  return Object.freeze({
    lifecycle: Object.freeze({ completed: lifecycleComplete, interactions: cohort.length,
      receipts: cohort.filter(item => item.receipt).length, reset: lifecycleComplete }),
    modelAccuracy: Object.freeze({ expected: EXPECTED_INTERACTIONS,
      matched: EXPECTED_INTERACTIONS - mismatches.length, mismatches: Object.freeze(mismatches) }),
  });
}

module.exports = { EXPECTED_INTERACTIONS, summarizeMountedQualification };
