'use strict';

const OBJECTIVE_IDS = Object.freeze([...Array.from({ length: 10 }, (_, i) => `sqli_${i + 1}`),
  ...Array.from({ length: 10 }, (_, i) => `nosqli_${i + 1}`)]);
const FAILURE_STAGES = Object.freeze(['setup', 'positive', 'provenance', 'ordinary', 'negative_judge', 'reset', 'complete']);
const FAILURE_CODES = Object.freeze(['ASSERTION_FAILED', 'EXECUTION_FAILED', 'CANCELLED', 'TIMEOUT']);
const HASH = /^[a-f0-9]{64}$/;
const callFields = ['provider','model','endpoint','qualified','failureCode','httpStatus','requestSha256','requestBytes','responseSha256','responseBytes','outputSha256','outputBytes'];
const callFailures = new Set([null, 'SCOPE_CLOSED_WITH_PENDING_CALLS', 'PROVENANCE_ABORTED', 'PROVENANCE_REQUEST_MODEL_REJECTED',
  'TRANSPORT_OR_REQUEST_FAILED', 'HTTP_FAILED', 'RESPONSE_MODEL_MISMATCH', 'EMPTY_MODEL_OUTPUT',
  'MALFORMED_OR_TRUNCATED_RESPONSE', 'PROVENANCE_RESPONSE_ENDPOINT_REJECTED']);
function validatePublicCalls(calls) {
  if (!Array.isArray(calls) || calls.length > 512) throw new TypeError('Bounded public calls required');
  return calls.map(call => {
    if (!call || typeof call !== 'object' || Array.isArray(call) || Object.keys(call).length !== callFields.length
        || callFields.some(key => !Object.hasOwn(call, key)) || call.provider !== 'ollama'
        || ![null, 'llama3.1:8b'].includes(call.model) || !['/api/chat','/api/generate'].includes(call.endpoint)
        || typeof call.qualified !== 'boolean' || !callFailures.has(call.failureCode)
        || !(call.httpStatus === null || Number.isInteger(call.httpStatus) && call.httpStatus >= 100 && call.httpStatus <= 599)) {
      throw new TypeError('Exact safe public provenance required');
    }
    for (const key of ['requestSha256','responseSha256','outputSha256']) if (typeof call[key] !== 'string' || !HASH.test(call[key])) throw new TypeError('SHA256 required');
    for (const key of ['requestBytes','responseBytes','outputBytes']) if (!Number.isSafeInteger(call[key]) || call[key] < 0) throw new TypeError('Safe byte count required');
    if (call.qualified && (call.model !== 'llama3.1:8b' || call.failureCode !== null || call.httpStatus < 200 || call.httpStatus > 299
        || call.requestBytes === 0 || call.responseBytes === 0 || call.outputBytes === 0)) throw new TypeError('Inconsistent qualified provenance');
    return Object.freeze({ ...call });
  });
}
function createSqlNoSqlQualificationReport({ selectedIds } = {}) {
  if (!Array.isArray(selectedIds) || !selectedIds.length || selectedIds.some(id => !OBJECTIVE_IDS.includes(id))
      || new Set(selectedIds).size !== selectedIds.length) throw new TypeError('Unique known selected objective IDs required');
  const ids = OBJECTIVE_IDS.filter(id => selectedIds.includes(id));
  const rows = new Map(ids.map(objectiveId => [objectiveId, Object.freeze({ objectiveId, status: 'pending', durationMs: null,
    failureStage: null, failureCode: null, calls: Object.freeze([]) })]));
  function finalize(objectiveId, result) {
    if (!rows.has(objectiveId) || rows.get(objectiveId).status !== 'pending') throw new Error('Selected pending objective required');
    const { status, durationMs, failureStage = null, failureCode = null, calls = [] } = result || {};
    if (!result || Object.keys(result).some(key => !['status','durationMs','failureStage','failureCode','calls'].includes(key))
        || !['pass','fail'].includes(status) || !Number.isSafeInteger(durationMs) || durationMs < 0
        || (status === 'pass' ? failureStage !== null || failureCode !== null : !FAILURE_STAGES.includes(failureStage) || !FAILURE_CODES.includes(failureCode))) {
      throw new TypeError('Safe terminal status, duration and failure diagnostics required');
    }
    const publicCalls = validatePublicCalls(calls);
    rows.set(objectiveId, Object.freeze({ objectiveId, status, durationMs, failureStage, failureCode, calls: Object.freeze(publicCalls) }));
  }
  function snapshot() {
    const cases = Object.freeze([...rows.values()]);
    const partial = ids.length !== OBJECTIVE_IDS.length;
    // qualified describes objective-case coverage only, not immutable-package,
    // model-digest, release readiness or resource-cleanup qualification.
    return Object.freeze({ version: 1, scope: 'aria_nova_objective_cases', cohort: 'sql-nosql-route-actual8b-v1', partial,
      selectedIds: Object.freeze([...ids]), qualification: !partial && cases.every(row => row.status === 'pass') ? 'qualified' : 'incomplete', cases });
  }
  return Object.freeze({ finalize, snapshot });
}
module.exports = { OBJECTIVE_IDS, FAILURE_STAGES, FAILURE_CODES, createSqlNoSqlQualificationReport };
