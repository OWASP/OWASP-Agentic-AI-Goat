const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const VERDICTS = new Set(['pass', 'fail', 'inconclusive', 'unavailable']);
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const invalid = () => { throw Error('Saved listing assessment is invalid.'); };

export function decodeListingCreateAssessment(value, operationId) {
  if (!UUID.test(operationId || '') || !value || value.operationId !== operationId.toLowerCase()) invalid();
  if (exact(value, ['operationId', 'completed', 'status', 'modelEvaluated'])) {
    if (value.completed !== false || !['ineligible', 'unconfirmed'].includes(value.status) || value.modelEvaluated !== false) invalid();
    return Object.freeze({ operationId: value.operationId, completed: false, status: value.status, modelEvaluated: false });
  }
  if (!exact(value, ['operationId', 'completed', 'judgment', 'replayed']) || typeof value.completed !== 'boolean'
    || typeof value.replayed !== 'boolean' || !exact(value.judgment, ['evaluationId', 'verdict', 'canRetry'])
    || !VERDICTS.has(value.judgment.verdict) || !UUID.test(value.judgment.evaluationId || '')
    || value.judgment.evaluationId !== value.judgment.evaluationId.toLowerCase()
    || typeof value.judgment.canRetry !== 'boolean'
    || (value.completed === true && (value.judgment.verdict !== 'pass' || value.judgment.canRetry !== false))
    || (value.judgment.canRetry === true && value.judgment.verdict !== 'unavailable')) invalid();
  return Object.freeze({ operationId: value.operationId, completed: value.completed,
    judgment: Object.freeze({ evaluationId: value.judgment.evaluationId, verdict: value.judgment.verdict,
      canRetry: value.judgment.canRetry }), replayed: value.replayed });
}

async function decodeResponse(response, operationId) {
  if (!response.ok) throw Error(`Saved listing assessment lookup failed (${response.status}).`);
  return decodeListingCreateAssessment(await response.json(), operationId);
}
export async function readListingCreateAssessment(transport, operationId, signal) {
  return decodeResponse(await transport(`/api/secureshop/agents/merchant/assistant/listing-create/assessment/${operationId}`,
    { method: 'GET', headers: { accept: 'application/json' }, signal }), operationId);
}
export async function assessListingCreate(transport, operationId, signal) {
  return decodeResponse(await transport('/api/secureshop/agents/merchant/assistant/listing-create/assess', {
    method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify({ operationId }), signal,
  }), operationId);
}
