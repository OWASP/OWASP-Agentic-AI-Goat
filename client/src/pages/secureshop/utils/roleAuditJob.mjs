const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SHA = /^[a-f0-9]{64}$/;
const encoder = new TextEncoder();
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
const canonical = value => Array.isArray(value) ? value.map(canonical)
  : value && Object.getPrototypeOf(value) === Object.prototype
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const fail = () => { throw new Error('Saved audit job invalid'); };
const text = (value, limit) => typeof value === 'string' && encoder.encode(value).byteLength <= limit;
const modePolicy = Object.freeze({ agent: ['audit', 'raw-audit-query-disabled-v1'],
  summary: ['audit_summary', 'capped-audit-metadata-v1'] });

async function digest(value) {
  if (!globalThis.crypto?.subtle) fail();
  const bytes = await globalThis.crypto.subtle.digest('SHA-256', encoder.encode(value));
  return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
function mode(value, action) {
  const [featureId, policyVersion] = modePolicy[action] || [];
  if (!exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    || !exact(value.scope, ['kind', 'id']) || value.version !== 1
    || value.featureId !== featureId || value.policyVersion !== policyVersion
    || !['vuln', 'fixed'].includes(value.effectiveMode)
    || value.scope.kind !== 'launch_feature' || value.scope.id !== featureId) fail();
  return { version: 1, featureId, policyVersion, effectiveMode: value.effectiveMode,
    scope: { kind: 'launch_feature', id: featureId } };
}
function input(value, action, effectiveMode) {
  if (action === 'agent') {
    if (!exact(value, ['message']) || !text(value.message, 12000) || !value.message.trim()) fail();
    return { message: value.message };
  }
  if (!exact(value, ['requestedCount']) || !Number.isSafeInteger(value.requestedCount)
    || value.requestedCount < 1 || (effectiveMode === 'fixed' && value.requestedCount > 100)) fail();
  return { requestedCount: value.requestedCount };
}
export function sameAuditJobMode(left, right, action) {
  try { return JSON.stringify(mode(left, action)) === JSON.stringify(mode(right, action)); }
  catch { return false; }
}

export async function decodeRoleAuditJobProposal(value, sourceSessionId, sourceRequestId) {
  if (value == null) return null;
  if (!exact(value, ['version', 'kind', 'proposalId', 'scopeKey', 'action', 'sessionId',
    'requestId', 'input', 'modeCapability', 'source', 'requestSha256'])
    || value.version !== 1 || value.kind !== 'audit_job'
    || !['agent', 'summary'].includes(value.action) || !UUID.test(value.proposalId)
    || !UUID.test(value.sessionId) || value.requestId !== value.proposalId
    || !SHA.test(value.scopeKey) || !SHA.test(value.requestSha256)
    || !exact(value.source, ['sessionId', 'requestId'])
    || value.source.sessionId !== sourceSessionId || value.source.requestId !== sourceRequestId) fail();
  const normalizedMode = mode(value.modeCapability, value.action);
  const body = { version: 1, kind: 'audit_job', proposalId: value.proposalId,
    scopeKey: value.scopeKey, action: value.action, sessionId: value.sessionId,
    requestId: value.requestId, input: input(value.input, value.action, normalizedMode.effectiveMode),
    modeCapability: normalizedMode,
    source: { sessionId: value.source.sessionId, requestId: value.source.requestId } };
  if (await digest(JSON.stringify(canonical(body))) !== value.requestSha256) fail();
  return Object.freeze({ ...body, requestSha256: value.requestSha256 });
}

function evidence(value, action, result) {
  if (value === null && action === 'agent') return null;
  const hashes = action === 'agent'
    ? ['sourceSha256', 'payloadSha256', 'resultSha256', 'decisionSha256', 'responseSha256']
    : ['logSha256', 'sourcesSha256', 'summarySha256', 'observationSha256'];
  if (!exact(value, ['version', 'modelProvenance', ...hashes,
    action === 'agent' ? 'tool' : 'artifacts', 'trace']) || value.version !== 1
    || value.modelProvenance !== true || hashes.some(key => !SHA.test(value[key]))
    || !Array.isArray(value.trace) || value.trace.length !== 2) fail();
  for (const [index, phase] of value.trace.entries()) {
    if (!exact(phase, ['step', 'phase', 'provider', 'model', 'tool'])
      || !Number.isSafeInteger(phase.step) || phase.step < 1
      || phase.phase !== ['decision', 'final'][index]
      || typeof phase.provider !== 'string' || !phase.provider
      || typeof phase.model !== 'string' || !phase.model
      || phase.tool !== (index === 0 ? (action === 'agent'
        ? 'audit.search_by_user' : 'audit.summarize_anomalies') : null)) fail();
  }
  if (value.trace[1].step !== value.trace[0].step + 1
    || value.trace[1].provider !== result.provider
    || value.trace[1].model !== result.model) fail();
  if (action === 'agent') {
    if (!exact(value.tool, ['name', 'args']) || value.tool.name !== 'audit.search_by_user'
      || !exact(value.tool.args, ['username']) || !text(value.tool.args.username, 8192)) fail();
  } else {
    if (!exact(value.artifacts, ['log', 'sources', 'messages', 'traces', 'effects'])) fail();
    for (const ref of Object.values(value.artifacts)) {
      if (!exact(ref, ['bytes', 'sha256']) || !Number.isSafeInteger(ref.bytes)
        || ref.bytes < 0 || ref.bytes > 134217728 || !SHA.test(ref.sha256)) fail();
    }
    if (value.logSha256 !== value.artifacts.log.sha256
      || value.sourcesSha256 !== value.artifacts.sources.sha256) fail();
  }
  return value;
}

export async function decodeAuditJobOperation(proposal, value) {
  if (!proposal || !exact(value, ['version', 'kind', 'action', 'sessionId', 'requestId',
    'status', 'result']) || value.version !== 1 || value.kind !== 'audit_job'
    || value.action !== proposal.action || value.sessionId !== proposal.sessionId
    || value.requestId !== proposal.requestId
    || !['completed', 'not_found', 'unconfirmed'].includes(value.status)) fail();
  if (value.status !== 'completed') {
    if (value.result !== null) fail();
    return Object.freeze({ status: value.status, result: null });
  }
  const result = value.result;
  const keys = proposal.action === 'agent'
    ? ['text', 'query', 'provider', 'model', 'assessment', 'runId', 'modeCapability', 'evidence']
    : ['runId', 'summary', 'provider', 'model', 'requestedCount', 'rowCount',
      'objectiveCredit', 'modeCapability', 'assessment', 'evidence'];
  if (!exact(result, keys) || !UUID.test(result.runId) || typeof result.provider !== 'string'
    || !result.provider || typeof result.model !== 'string' || !result.model
    || !text(result[proposal.action === 'agent' ? 'text' : 'summary'], 65536)
    || !result[proposal.action === 'agent' ? 'text' : 'summary'].trim()
    || !sameAuditJobMode(result.modeCapability, proposal.modeCapability, proposal.action)
    || !result.assessment || Object.getPrototypeOf(result.assessment) !== Object.prototype) fail();
  if (proposal.action === 'summary' && (!Number.isSafeInteger(result.requestedCount)
    || result.requestedCount !== proposal.input.requestedCount
    || !Number.isSafeInteger(result.rowCount) || result.rowCount < 0
    || result.rowCount > result.requestedCount || typeof result.objectiveCredit !== 'boolean'
    || result.assessment.completed !== result.objectiveCredit
    || !['pass', 'fail', 'inconclusive', 'unavailable'].includes(result.assessment.judgment?.verdict)
    || (result.objectiveCredit && result.assessment.judgment.verdict !== 'pass'))) fail();
  const proof = evidence(result.evidence, proposal.action, result);
  if (proof && proposal.action === 'agent'
    && await digest(JSON.stringify(canonical(result.query))) !== proof.resultSha256) fail();
  if (proof && proposal.action === 'summary'
    && await digest(result.summary) !== proof.summarySha256) fail();
  if (encoder.encode(JSON.stringify(result)).byteLength > 256 * 1024) fail();
  return Object.freeze({ status: 'completed', result: Object.freeze(result) });
}
