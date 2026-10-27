'use strict';

// Source-only candidate protocol, not an execution/credit authority. A future
// admitted launcher must wire physicalCall at the actual provider POST boundary
// and separately prove the rebuilt worker, complete catalog, original wire,
// canonical Judge, Fixed mode and owner/session/reset/sibling isolation.
const { SOURCE_TASK, V39_FINAL_PREFIX, REGISTRATIONS } = require('./secureshopMcpDescriptionRenderedQualification');
const { V39_ATOMIC_V1 } = require('../../sidecars/sandbox-runner/owned-mcp-registry/worker');
const { RUBRIC } = require('../../server/services/secureshopMcpDescriptionEvidence');
const VERSION = 'v39-atomic-prefix-pair-v1';
const LIMITS = Object.freeze({ actorPerArm: 13, judgePerArm: 4, physicalPerArm: 14, physicalPair: 28 });
const RUN_ID = /^[a-f0-9]{32}$/;
const error = code => Object.assign(new Error(code), { code });
function armDefinition(arm) {
  if (!Object.hasOwn(V39_ATOMIC_V1, arm)) throw error('V39_PAIR_ARM');
  const variant = V39_ATOMIC_V1[arm];
  return Object.freeze({ version: VERSION, arm, originalTask: SOURCE_TASK,
    prefix: V39_FINAL_PREFIX, description: variant.description,
    registrations: Object.freeze([REGISTRATIONS[0], Object.freeze({ ...REGISTRATIONS[1],
      url: `http://attacker.training:8080${variant.endpoint}` })]),
    rubricVersion: RUBRIC.version, objectiveId: RUBRIC.objectiveId,
    candidateOnly: true, liveAdmitted: false, qualification: false, limits: LIMITS,
    controlCanEarnCredit: false });
}
function createPairBudget(binding) {
  if (!binding || Object.keys(binding).sort().join(',') !== 'controlRunId,treatmentRunId'
      || !RUN_ID.test(binding.controlRunId) || !RUN_ID.test(binding.treatmentRunId)
      || binding.controlRunId === binding.treatmentRunId) throw error('V39_PAIR_BINDING');
  const runs = { control: binding.controlRunId, treatment: binding.treatmentRunId };
  const counts = { control: { actor: 0, judge: 0, physical: 0 }, treatment: { actor: 0, judge: 0, physical: 0 } };
  const states = { control: 'waiting', treatment: 'waiting' };
  let active = null, pending = false, total = 0, failed = false;
  function reject(code) { failed = true; if (active) states[active] = 'failed'; throw error(code); }
  function snapshot() {
    return Object.freeze({ version: VERSION, candidateOnly: true, qualification: false,
      controlCredit: 0, physicalBoundaryWiringRequired: true, failed, pendingCalls: Number(pending),
      totalPhysical: total, limits: LIMITS,
      arms: Object.freeze(Object.fromEntries(Object.keys(runs).map(arm => [arm,
        Object.freeze({ runId: runs[arm], state: states[arm], ...counts[arm] })]))) });
  }
  return Object.freeze({ snapshot, beginArm(arm, runId) {
    if (failed || active || !Object.hasOwn(runs, arm) || runId !== runs[arm]
        || states[arm] !== 'waiting' || (arm === 'treatment' && states.control !== 'finished'))
      return reject('V39_PAIR_SEQUENCE');
    active = arm; states[arm] = 'running';
    return Object.freeze({ definition: armDefinition(arm), runId,
      async physicalCall(role, dispatch) {
        if (failed || active !== arm || states[arm] !== 'running' || pending)
          return reject('V39_PAIR_CLOSED_OR_PENDING');
        if (!['actor', 'judge'].includes(role) || typeof dispatch !== 'function') return reject('V39_PAIR_DISPATCH');
        const row = counts[arm];
        if (row[role] >= LIMITS[`${role}PerArm`] || row.physical >= LIMITS.physicalPerArm
            || total >= LIMITS.physicalPair) return reject('V39_PAIR_CALL_LIMIT');
        // Charge before dispatch, including failed/lost-response attempts.
        row[role]++; row.physical++; total++; pending = true;
        try { return await dispatch(); }
        catch (cause) { failed = true; states[arm] = 'failed'; throw cause; }
        finally { pending = false; }
      },
      finish() {
        if (failed || active !== arm || states[arm] !== 'running' || pending)
          return reject('V39_PAIR_CLOSED_OR_PENDING');
        states[arm] = 'finished'; active = null; return snapshot();
      },
    });
  } });
}
module.exports = { VERSION, LIMITS, armDefinition, createPairBudget };
