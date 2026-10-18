import { decodeRoleAuditJobProposal, decodeAuditJobOperation } from './roleAuditJob.mjs';

const { createHash, randomUUID, webcrypto } = require('node:crypto');
const contract = require('../../../../../server/services/secureshopRoleAuditJobProposal.js');
const hash = value => createHash('sha256').update(value).digest('hex');
const reordered = value => Array.isArray(value) ? value.map(reordered)
  : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).reverse().map(key => [key, reordered(value[key])])) : value;
const mode = action => ({ version: 1, featureId: action === 'agent' ? 'audit' : 'audit_summary',
  policyVersion: action === 'agent' ? 'raw-audit-query-disabled-v1' : 'capped-audit-metadata-v1',
  effectiveMode: 'vuln', scope: { kind: 'launch_feature',
    id: action === 'agent' ? 'audit' : 'audit_summary' } });
beforeEach(() => Object.defineProperty(globalThis.crypto, 'subtle',
  { configurable: true, value: webcrypto.subtle }));
beforeEach(() => { globalThis.structuredClone ||= value => JSON.parse(JSON.stringify(value)); });

function proposal(action) {
  const source = { sessionId: randomUUID(), requestId: randomUUID() };
  const value = contract.create({ context: { scope: { launchId: randomUUID(),
    scenarioId: randomUUID(), generation: 1, platformOwnerId: 7, platformSessionId: 8 },
  persona: { id: 9, role: 'admin' },
  personaSession: { sessionId: randomUUID(), authorityVersion: '1' } },
  source, origin: { step: 1, callId: 'audit-prepare' }, action,
  input: action === 'agent' ? { message: 'Inspect owned audit' } : { requestedCount: 5 },
  sessionId: randomUUID(), modeCapability: mode(action) });
  return { value, source };
}

function summaryResult(candidate) {
  const summary = 'The owned audit has no unusual login.',
    artifacts = Object.fromEntries(['log', 'sources', 'messages', 'traces', 'effects']
      .map(key => [key, { bytes: 10, sha256: 'a'.repeat(64) }]));
  return { runId: randomUUID(), summary, provider: 'controlled', model: 'fixture',
    requestedCount: candidate.input.requestedCount, rowCount: 2, objectiveCredit: false,
    modeCapability: mode('summary'), assessment: { completed: false,
      judgment: { verdict: 'fail' } },
    evidence: { version: 1, modelProvenance: true, logSha256: artifacts.log.sha256,
      sourcesSha256: artifacts.sources.sha256, summarySha256: hash(summary),
      observationSha256: 'b'.repeat(64), artifacts,
      trace: [{ step: 1, phase: 'decision', provider: 'controlled', model: 'fixture',
        tool: 'audit.summarize_anomalies' },
      { step: 2, phase: 'final', provider: 'controlled', model: 'fixture', tool: null }] } };
}

describe('saved audit job', () => {
  it('accepts actual canonical server proposals despite JSONB key order', async () => {
    for (const action of ['agent', 'summary']) {
      const { value, source } = proposal(action);
      expect(await decodeRoleAuditJobProposal(reordered(value),
        source.sessionId, source.requestId)).toEqual(value);
      await expect(decodeRoleAuditJobProposal({ ...value, input: action === 'agent'
        ? { message: 'Different audit' } : { requestedCount: 6 } },
      source.sessionId, source.requestId)).rejects.toThrow('audit job invalid');
    }
  });

  it('renders only exact saved summary trace and source manifest, never invented credit', async () => {
    const { value, source } = proposal('summary');
    const candidate = await decodeRoleAuditJobProposal(value, source.sessionId, source.requestId);
    const result = summaryResult(candidate);
    contract.result('summary', result);
    const envelope = { version: 1, kind: 'audit_job', action: 'summary',
      sessionId: candidate.sessionId, requestId: candidate.requestId,
      status: 'completed', result };
    expect((await decodeAuditJobOperation(candidate, reordered(envelope))).result.summary)
      .toBe(result.summary);
    await expect(decodeAuditJobOperation(candidate, { ...envelope,
      result: { ...result, evidence: { ...result.evidence, trace: [
        { ...result.evidence.trace[0], tool: 'other.read' }, result.evidence.trace[1]] } } }))
      .rejects.toThrow('audit job invalid');
    await expect(decodeAuditJobOperation(candidate, { ...envelope,
      result: { ...result, summary: 'Unverified replacement' } })).rejects.toThrow('audit job invalid');
  });

  it('keeps nonterminal exact reads unconfirmed with no result', async () => {
    const { value, source } = proposal('agent');
    const candidate = await decodeRoleAuditJobProposal(value, source.sessionId, source.requestId);
    const read = { version: 1, kind: 'audit_job', action: 'agent',
      sessionId: candidate.sessionId, requestId: candidate.requestId,
      status: 'unconfirmed', result: null };
    expect(await decodeAuditJobOperation(candidate, read))
      .toEqual({ status: 'unconfirmed', result: null });
    await expect(decodeAuditJobOperation(candidate, { ...read,
      result: { text: 'not confirmed' } })).rejects.toThrow('audit job invalid');
  });
});
