'use strict';
const { inspectXssProfileOrigin } = require('./xssProfileOriginValidation');
const FIELDS = ['name', 'bio', 'website'];

// Only server-owned repository and canonical completion dependencies belong here.
function createXssStoredOriginEvidence({ readCurrent, hasPrerequisite } = {}) {
  if (typeof readCurrent !== 'function' || typeof hasPrerequisite !== 'function') {
    throw new TypeError('Explicit private origin and canonical prerequisite readers are required');
  }
  return async function qualify({ objectiveId, userKey, platformUserId, grading, execution, attempt }) {
    if (!['xss_g2', 'xss_g3'].includes(objectiveId)) throw new TypeError('Stored-model objective required');
    if (typeof execution?.check !== 'function') throw new TypeError('Current owner execution required');
    await execution.check();
    const fields = objectiveId === 'xss_g2' ? [grading?.toolResult?.field].filter(field => FIELDS.includes(field)) : FIELDS;
    const qualified = [];
    const checks = [];
    for (const field of fields) {
      const snapshot = await readCurrent({ userKey, field, platformUserId });
      await execution.check();
      const proof = inspectXssProfileOrigin({ snapshot, userKey, platformUserId, field,
        workshopGeneration: attempt?.generation, execution, requireWriterRun: objectiveId === 'xss_g2' });
      const observedValue = objectiveId === 'xss_g2' ? grading?.toolResult?.value : grading?.toolResult?.profile?.[field];
      checks.push(Object.freeze({ field, reason: proof.valid ? (proof.eventSource === observedValue ? null : 'observed_value_mismatch') : proof.reason }));
      if (proof.valid && proof.eventSource === observedValue) qualified.push({ field, value: proof.eventSource, origin: Object.freeze({ field, revision: snapshot.origin.revision, valueSha256: snapshot.origin.valueSha256, writerRunId: snapshot.origin.runId, provider: snapshot.origin.provider, model: snapshot.origin.model, rawDecisionSha256: snapshot.origin.rawDecisionSha256, observationIndex: snapshot.origin.observationIndex }) });
    }
    let prerequisite = false;
    if (objectiveId === 'xss_g3' && qualified.length) {
      prerequisite = await hasPrerequisite({ userId: platformUserId, workshopKey: 'xss_workshop',
        objectiveId: 'xss_g2', execution, attempt });
      await execution.check();
    }
    return Object.freeze({ checks: Object.freeze(checks.length ? checks : [{ field: null, reason: 'observed_field_missing' }]), modelProfileOriginCurrent: qualified.length > 0,
      canonicalModelSaveCompleted: prerequisite === true,
      origins: Object.freeze(qualified.map(item => item.origin)),
      eventSources: Object.freeze(qualified.map(item => item.value)) });
  };
}
module.exports = { createXssStoredOriginEvidence };
