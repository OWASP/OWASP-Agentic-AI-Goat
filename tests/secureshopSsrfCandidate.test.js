'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { Server } = require('../agent-host/shared/graphServer');
const { CallToolRequestSchema, ListToolsRequestSchema } = require('@modelcontextprotocol/sdk/types.js');
const { explainReturnPolicy } = require('../agent-host/agents/summarizer/tools/explain_return_policy');
const { createSecureShopSsrfOwnedTarget } = require('../server/services/secureshopSsrfOwnedTarget');
const { createSecureShopSsrfTargetPool } = require('../server/services/secureshopSsrfTargetPool');
const { createSecureShopSsrfExternalAdapter, SSRF_EGRESS_POLICY_SHA256 } = require('../server/services/secureshopSsrfExternalAdapter');
const { buildSecureShopSsrfEvidence } = require('../server/services/secureshopSsrfEvidence');
const { createSecureShopSsrfAssessment } = require('../server/services/secureshopSsrfAssessment');
const { createSecureShopSsrfResetAdapter } = require('../server/services/secureshopSsrfResetAdapter');
const { createSecureShopSsrfApplication } = require('../server/services/secureshopSsrfApplication');
const { createSecureShopSsrfComposition } = require('../server/services/secureshopSsrfComposition');
const { createSecureShopBoundSsrfRepository } = require('../server/database/postgres/secureshopBoundSsrfRepository');
const { createBoundAgentRunner } = require('../server/services/secureshopBoundAgentRunner');
const { createSecureShopSsrfExecutionConfig } = require('../server/services/secureshopSsrfExecutionConfig');
const { digestMcpValue } = require('../server/services/secureshopMcpTrustTools');
const { SECURESHOP_RESET_TARGET_KINDS } = require('../server/database/postgres/secureshopResetCleanupAuthorityRepository');
const { SECURESHOP_RECONCILIATION_TARGET_KINDS } = require('../server/database/postgres/secureshopTargetReconciliationRepository');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const { markSecureShopFailure, projectSecureShopFailure }
  = require('../server/services/secureshopFailureDiagnostic');

const uuid = () => crypto.randomUUID();
const scope = Object.freeze({ targetId: uuid(), launchId: uuid(), scenarioId: uuid(), generation: 1,
  platformOwnerId: 11, platformSessionId: 21 });
const sibling = Object.freeze({ ...scope, targetId: uuid(), launchId: uuid(), platformOwnerId: 12, platformSessionId: 22 });

async function protocol(t) {
  const [{ Client }, { InMemoryTransport }] = await Promise.all([
    import('@modelcontextprotocol/sdk/client/index.js'), import('@modelcontextprotocol/sdk/inMemory.js'),
  ]);
  const server = new Server({ name: 'secureshop-summarizer-ssrf-test', version: '1.0.0' },
    { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{
    name: 'explain_return_policy',
    description: 'Fetch a return-policy URL and return its body summarized.',
    inputSchema: { type: 'object', properties: { policy_url: { type: 'string' } }, required: ['policy_url'] },
  }] }));
  server.setRequestHandler(CallToolRequestSchema, async request => {
    if (request.params.name !== 'explain_return_policy') {
      return { content: [{ type: 'text', text: `unknown tool ${request.params.name}` }], isError: true };
    }
    const result = await explainReturnPolicy(request.params.arguments || {});
    return { content: [{ type: 'text', text: JSON.stringify(result) }] };
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: 'secureshop-ssrf-qualification', version: '1.0.0' });
  await server.connect(serverTransport); await client.connect(clientTransport);
  t.after(async () => Promise.allSettled([client.close(), clientTransport.close(), serverTransport.close(), server.close()]));
  let calls = 0;
  return { get calls() { return calls; }, async callTool(agent, tool, args, options) {
    calls += 1; assert.equal(agent, 'summarizer'); options?.signal?.throwIfAborted();
    return client.callTool({ name: tool, arguments: args }, undefined, { signal: options?.signal });
  } };
}

test('real summarizer MCP tool crosses the owned public/private HTTP boundary and seals an exact invocation', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ssrf-owned-')); t.after(() => fs.rm(root, { recursive: true, force: true }));
  const targetPool = createSecureShopSsrfTargetPool({ root }); t.after(() => targetPool.retire(scope)); const upstreamPool = await protocol(t);
  const publicRequestId = uuid(); const publicRequest = await targetPool.issue(scope, { requestId: publicRequestId, resourceKind: 'public-policy' });
  const publicResult = await upstreamPool.callTool('summarizer', 'explain_return_policy', { policy_url: publicRequest.url }, {});
  const publicReceipt = targetPool.consume(scope, { nonce: publicRequest.nonce, requestId: publicRequestId });
  const publicBody = JSON.parse(JSON.parse(publicResult.content[0].text).body);
  assert.equal(publicBody.classification, 'public'); assert.equal(publicReceipt.resourceKind, 'public-policy');

  const requestId = uuid(), runId = uuid(), sessionId = `session:${uuid()}`;
  const issued = Object.freeze({ ...scope, ...await targetPool.issue(scope, { requestId, resourceKind: 'private-policy' }),
    egressPolicySha256: SSRF_EGRESS_POLICY_SHA256, policyDecision: 'denied' });
  const records = []; const execution = Object.freeze({ runId, ownerKey: 'owner:11', durableGeneration: 1,
    signal: new AbortController().signal, async check() {} });
  const adapter = createSecureShopSsrfExternalAdapter({ resolveRequest: async () => issued, targetPool, upstreamPool,
    checkCurrent: async value => assert.deepEqual(Object.fromEntries(Object.keys(scope).map(key => [key, value[key]])), scope),
    recordInvocation: async (request, input) => { const value = Object.freeze({ ...request, ...input }); records.push(value); return value; } });
  const pool = await adapter.createToolPool(scope, { execution, requestId, sessionId });
  let argumentFailure;
  await assert.rejects(pool.callTool('summarizer', 'explain_return_policy', { policy_url: 'http://127.0.0.1/wrong' }, { callId: 'wrong' }),
    error => { argumentFailure = error; return error?.code === 'BOUND_SSRF_UNAVAILABLE'; });
  assert.equal(pool.projectRecoverableToolError(argumentFailure), 'INVALID_TOOL_ARGUMENTS');
  assert.equal(pool.projectRecoverableToolError(Object.assign(new Error('spoof'), { code: argumentFailure.code })), null);
  const otherRunPool = await adapter.createToolPool(scope, { execution, requestId, sessionId });
  assert.equal(otherRunPool.projectRecoverableToolError(argumentFailure), null,
    'the opaque classifier is scoped to the admitted tool pool');
  let callIdentityFailure;
  await assert.rejects(pool.callTool('summarizer', 'explain_return_policy', { policy_url: issued.url }, { callId: 'bad call id' }),
    error => { callIdentityFailure = error; return error?.code === 'BOUND_SSRF_UNAVAILABLE'; });
  assert.equal(pool.projectRecoverableToolError(callIdentityFailure), null,
    'provider call identity is an evidentiary requirement, not correctable model feedback');
  let selectionFailure;
  await assert.rejects(pool.callTool('catalog', 'search', {}, { callId: 'wrong-tool' }),
    error => { selectionFailure = error; return error?.code === 'BOUND_SSRF_UNAVAILABLE'; });
  assert.equal(pool.projectRecoverableToolError(selectionFailure), 'INVALID_TOOL_SELECTION');
  assert.equal(upstreamPool.calls, 1, 'off-authority URL is rejected before the real MCP transport');
  const args = { policy_url: issued.url }, callId = 'ssrf-call';
  const result = await pool.callTool('summarizer', 'explain_return_policy', args, { callId });
  assert.equal(upstreamPool.calls, 2); const parsed = JSON.parse(result.content[0].text); const privateBody = JSON.parse(parsed.body);
  assert.equal(targetPool.pendingReceipts(scope), 1, 'remote HTTP effect remains reconciliation debt until canonical observation commits');
  assert.equal(privateBody.recordId, `internal-policy:${scope.targetId}`); assert.equal(privateBody.classification, 'protected-training-record');
  const effectReceipt = Object.freeze({ version: 1, status: 'completed', runId, ownerKey: execution.ownerKey, generation: '1',
    effectKey: `${requestId}:${JSON.stringify([1, callId, 'summarizer.explain_return_policy'])}` });
  const observation = Object.freeze({ step: 1, callId, tool: 'summarizer.explain_return_policy', args, result, effectReceipt });
  for (const changed of [{ responseSha256: '0'.repeat(64) }, { responseStatus: 201 }, { requestPath: '/wrong' },
    { egressReceiptSha256: '0'.repeat(64) }]) {
    const tampered = { ...observation, result: { ...result, _meta: { ...result._meta, ...changed } } };
    await assert.rejects(adapter.observeExternalTool({ run: execution, binding: scope, sessionId, requestId,
      observation: tampered }), { code: 'BOUND_SSRF_UNAVAILABLE' });
    assert.equal(records.length, 0); assert.equal(targetPool.pendingReceipts(scope), 1);
  }
  const externalRecord = await adapter.observeExternalTool({ run: execution, binding: scope, sessionId, requestId, observation });
  assert.equal(records.length, 1); assert.equal(externalRecord.invocation.operationId, issued.operationId);
  assert.equal(targetPool.pendingReceipts(scope), 0);

  const modelResult = { model: 'llama3.1:8b', mocked: false };
  const traces = [
    { kind: 'model_decision', actor: 'supervisor', provider: 'ollama', step: 1,
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: callId, name: observation.tool, args }] }),
      result_json: JSON.stringify(modelResult) },
    { kind: 'mcp_result', actor: 'task→supervisor', step: 1, agent_ns: 'summarizer', tool_name: 'explain_return_policy',
      result_json: JSON.stringify(result) },
    { kind: 'terminal', actor: 'supervisor', provider: 'ollama', step: 2,
      result_json: JSON.stringify({ ...modelResult, stopReason: 'end_turn' }) },
  ];
  const packets = buildSecureShopSsrfEvidence({ binding: scope, execution, sessionId, requestId, traces, observation,
    externalRecord, result: { stopReason: 'end_turn' }, qualifyModel: identity => identity.provider === 'ollama' });
  assert.deepEqual(packets.map(packet => packet.objectiveId), ['ss_controlled_ssrf']);
  assert.deepEqual(packets[0].evidence.protectedObservation, { recordId: `internal-policy:${scope.targetId}`,
    classification: 'protected-training-record', contentSha256: externalRecord.invocation.responseSha256 });
  assert.equal('routingNote' in packets[0].evidence.protectedObservation, false, 'private fixture content is not grading evidence');
  assert.deepEqual(buildSecureShopSsrfEvidence({ binding: scope, execution, sessionId, requestId, traces, observation,
    externalRecord: { ...externalRecord, invocation: { ...externalRecord.invocation, policyDecision: 'allowed' } },
    result: { stopReason: 'end_turn' }, qualifyModel: () => true }), []);
  assert.deepEqual(buildSecureShopSsrfEvidence({ binding: sibling, execution, sessionId, requestId, traces, observation,
    externalRecord, result: { stopReason: 'end_turn' }, qualifyModel: () => true }), []);
  assert.deepEqual(buildSecureShopSsrfEvidence({ binding: scope, execution, sessionId, requestId, traces, observation,
    externalRecord: { ...externalRecord, invocation: { ...externalRecord.invocation, responseSha256: '0'.repeat(64) } },
    result: { stopReason: 'end_turn' }, qualifyModel: () => true }), []);
  const binding = Object.freeze({ ...scope, shopUserId: 13, role: 'admin' }), stored = [];
  const assessment = createSecureShopSsrfAssessment({ qualifyModel: identity => identity.provider === 'ollama',
    resolveTarget: async () => binding, readInvocation: async () => records[0],
    receipts: { async beginEvaluation(input) { stored.push(input); return { ...input, verdict: null, generation: 3 }; },
      async recordVerdict({ result: verdict }) { return { result: verdict, verdict: verdict.verdict, disposition: 'awarded', generation: 3 }; } },
    progress: { async getGeneration() { return 3; }, async getEvaluationScope() { return { generation: 3, mode: 'vuln', modeStamp: 'stamp' }; } },
    judge: async packet => ({ family: packet.rubric.family, scenario: packet.rubric.scenario,
      objectiveId: packet.rubric.objectiveId, rubricVersion: packet.rubric.version,
      evidenceDigest: prepareJudgeInput(packet).evidenceDigest, runId, mode: packet.rubric.mode, verdict: 'pass',
      criteria: [{ id: packet.rubric.criteria[0].id, satisfied: true, evidenceRefs: ['bound_ssrf_invocation_chain'] }],
      explanation: 'Controlled SSRF fixture evidence is complete.', provider: 'fixture', model: 'fixture', usage: null }) });
  const lifecycle = assessment.assessmentFactory({ binding, sessionId, requestId }), attempt = await lifecycle.begin(execution);
  await lifecycle.observe(execution, { attempt, binding, sessionId, requestId, observation, externalRecord });
  const graded = await lifecycle.finalize(execution, { attempt, binding, sessionId, requestId, traces,
    result: { stopReason: 'end_turn' } });
  assert.equal(graded.ss_controlled_ssrf.completed, true); assert.equal(stored.length, 1);
  const { targetId: _targetId, ...launchScope } = scope;
  assert.deepEqual(stored[0].instanceScope, launchScope);
  await targetPool.retire(scope);
});

test('stale target authority and upstream failures cannot borrow the private pre-dispatch classification', async () => {
  const requestId=uuid(),sessionId=`session:${uuid()}`;
  const issued=Object.freeze({...scope,operationId:uuid(),requestId,nonce:uuid(),resourceKind:'private-policy',
    url:'http://127.0.0.1:8181/policy/private',egressPolicySha256:SSRF_EGRESS_POLICY_SHA256,policyDecision:'denied'});
  const execution=Object.freeze({runId:uuid(),ownerKey:'owner:11',durableGeneration:1,
    signal:new AbortController().signal,async check(){}});
  const stale=Object.assign(new Error('target is no longer current'),{code:'BOUND_SSRF_UNAVAILABLE'});
  let freshnessChecks=0,upstreamCalls=0;
  const staleAdapter=createSecureShopSsrfExternalAdapter({resolveRequest:async()=>issued,
    targetPool:{consume(){},readReceipt(){}},upstreamPool:{async callTool(){upstreamCalls+=1;}},recordInvocation:async()=>{},
    checkCurrent:async()=>{freshnessChecks+=1;if(freshnessChecks===2)throw stale;}});
  const stalePool=await staleAdapter.createToolPool(scope,{execution,requestId,sessionId});
  let observed;
  await assert.rejects(stalePool.callTool('summarizer','explain_return_policy',{policy_url:'wrong'},{callId:'stale'}),
    error=>{observed=error;return error===stale;});
  assert.equal(stalePool.projectRecoverableToolError(observed),null);
  assert.equal(upstreamCalls,0);

  const upstreamFailure=Object.assign(new Error('remote copied a public code'),{code:'BOUND_SSRF_UNAVAILABLE'});
  const upstreamAdapter=createSecureShopSsrfExternalAdapter({resolveRequest:async()=>issued,
    targetPool:{consume(){},readReceipt(){}},upstreamPool:{async callTool(){throw upstreamFailure;}},
    recordInvocation:async()=>{},checkCurrent:async()=>{}});
  const upstreamPool=await upstreamAdapter.createToolPool(scope,{execution,requestId,sessionId});
  await assert.rejects(upstreamPool.callTool('summarizer','explain_return_policy',{policy_url:issued.url},{callId:'upstream'}),
    error=>{observed=error;return error===upstreamFailure;});
  assert.equal(upstreamPool.projectRecoverableToolError(observed),null,
    'a remote code or error identity is never part of the run-local private brand');
});

test('owned target cleanup drains concurrent reads, shares cleanup, and retries partial filesystem failure without reopening', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ssrf-cleanup-')); t.after(() => fs.rm(root, { recursive: true, force: true }));
  let releaseRead, startedRead; const started = new Promise(resolve => { startedRead = resolve; });
  const realRead = fs.readFile.bind(fs), realRm = fs.rm.bind(fs); let hold = true, rmCalls = 0, failAfterRemoval = true;
  const fsImpl = { ...fs,
    async readFile(file, options) { if (hold && file.endsWith('private-policy.json')) { startedRead(); await new Promise(resolve => { releaseRead = resolve; }); } return realRead(file, options); },
    async rm(file, options) { rmCalls += 1; await realRm(file, options); if (failAfterRemoval) { failAfterRemoval = false; throw new Error('injected post-removal failure'); } },
  };
  const target = await createSecureShopSsrfOwnedTarget({ root, targetId: scope.targetId, fsImpl });
  const requestId = uuid(), issued = target.issue({ requestId, resourceKind: 'private-policy' });
  const response = fetch(issued.url); await started; const first = target.cleanup(), second = target.cleanup();
  assert.throws(() => target.issue({ requestId: uuid(), resourceKind: 'public-policy' }), { code: 'BOUND_SSRF_UNAVAILABLE' });
  hold = false; releaseRead(); assert.equal((await response).status, 200);
  const settled = await Promise.allSettled([first, second]); assert.deepEqual(settled.map(value => value.status), ['rejected', 'rejected']);
  assert.equal(rmCalls, 1); assert.deepEqual(await target.cleanup(), { ok: true, replayed: false });
  assert.deepEqual(await target.cleanup(), { ok: true, replayed: true }); assert.equal(rmCalls, 1, 'confirmed ENOENT does not repeat removal');
});

test('cancellation after the real HTTP effect retains reconciliation debt and cannot create canonical evidence', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ssrf-cancel-')); t.after(() => fs.rm(root, { recursive: true, force: true }));
  const targetPool = createSecureShopSsrfTargetPool({ root }), actual = await protocol(t), controller = new AbortController();
  const requestId = uuid(), sessionId = `session:${uuid()}`;
  const issued = Object.freeze({ ...scope, ...await targetPool.issue(scope, { requestId, resourceKind: 'private-policy' }),
    egressPolicySha256: SSRF_EGRESS_POLICY_SHA256, policyDecision: 'denied' });
  let records = 0;
  const execution = Object.freeze({ runId: uuid(), ownerKey: 'owner:cancel', durableGeneration: 1, signal: controller.signal,
    async check() { controller.signal.throwIfAborted(); } });
  const adapter = createSecureShopSsrfExternalAdapter({ resolveRequest: async () => issued, targetPool,
    upstreamPool: { async callTool(...args) { const value = await actual.callTool(...args); controller.abort(new Error('reset')); return value; } },
    checkCurrent: async () => {}, recordInvocation: async () => { records += 1; } });
  const tools = await adapter.createToolPool(scope, { execution, requestId, sessionId });
  await assert.rejects(tools.callTool('summarizer', 'explain_return_policy', { policy_url: issued.url }, { callId: 'cancelled-call' }),
    error => error?.name === 'Error' && error.message === 'reset');
  assert.equal(records, 0); assert.equal(targetPool.pendingReceipts(scope), 1); assert.equal(targetPool.state(scope).active, true,
    'the unconsumed HTTP receipt remains owned cleanup debt, never a completed invocation');
  await targetPool.retire(scope); assert.equal(targetPool.state(scope), null);
});

test('target pool and reset adapter preserve sibling scope and retire durable state only after owned payload cleanup', async () => {
  const events = [], receipts = new Map();
  const pool = createSecureShopSsrfTargetPool({ root: '/owned', createTarget: async ({ targetId }) => ({
    issue: input => ({ targetId, ...input }), consume() {}, async cleanup() { events.push(`file:${targetId}`); },
  }) });
  await pool.issue(scope, { requestId: uuid(), resourceKind: 'private-policy' });
  await pool.issue(sibling, { requestId: uuid(), resourceKind: 'private-policy' });
  await assert.rejects(pool.issue({ ...scope, launchId: sibling.launchId }, { requestId: uuid(), resourceKind: 'private-policy' }), /scope mismatch/);
  const repository = { async retire(value, input) { events.push(`db:${value.targetId}`); receipts.set(value.targetId, { targetId: value.targetId,
      launchId: value.launchId, scenarioId: value.scenarioId, fromGeneration: value.generation,
      platformOwnerId: value.platformOwnerId, platformSessionId: value.platformSessionId,
      operationId: input.operationId, targetReceiptVersion: 1, targetReceiptSha256: input.receiptSha256,
      targetCompletedAt: '2026-09-14T12:00:00.000Z' }); },
    async readCleanupReceipt(value) { return receipts.get(value.targetId); } };
  const cleanupAuthority = { async checkTarget(value) { assert.equal(value.targetKind,'controlled_ssrf');return { status: 'fenced' }; } };
  const reset = createSecureShopSsrfResetAdapter({ repository, targetPool: pool, cleanupAuthority });
  const operationId = uuid(); const receipt = await reset.cleanup({ ...scope, fromGeneration: 1 }, { operationId });
  assert.deepEqual(events, [`file:${scope.targetId}`, `db:${scope.targetId}`]); assert.equal(receipt.operationId, operationId);
  assert.equal(receipt.kind,'controlled_ssrf','cleanup receipt identifies the canonical reconciliation target kind');
  assert.equal(pool.state(sibling).active, true); assert.equal(pool.state(scope), null);
  await assert.rejects(pool.issue(scope, { requestId: uuid(), resourceKind: 'public-policy' }), /retired/,
    'an in-memory tombstone prevents same-target payload and listener resurrection');
});

test('authorized reset recovers a durable target after process restart without recreating a listener or touching a sibling', async t => {
  const root=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-ssrf-recovery-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
  const targetDirectory=path.join(root,scope.targetId),siblingDirectory=path.join(root,sibling.targetId);
  await Promise.all([fs.mkdir(targetDirectory,{mode:0o700}),fs.mkdir(siblingDirectory,{mode:0o700})]);
  await Promise.all([fs.writeFile(path.join(targetDirectory,'private-policy.json'),'owned',{mode:0o600}),
    fs.writeFile(path.join(siblingDirectory,'private-policy.json'),'sibling',{mode:0o600})]);
  let creations=0;const pool=createSecureShopSsrfTargetPool({root,async createTarget(){creations++;throw new Error('must not recreate');}});
  const receipts=new Map(),repository={async retire(value,data){receipts.set(value.targetId,{targetId:value.targetId,launchId:value.launchId,
      scenarioId:value.scenarioId,fromGeneration:value.generation,platformOwnerId:value.platformOwnerId,
      platformSessionId:value.platformSessionId,operationId:data.operationId,targetReceiptVersion:1,
      targetReceiptSha256:data.receiptSha256,targetCompletedAt:'2026-09-14T12:00:00.000Z'});},
    async readCleanupReceipt(value){return receipts.get(value.targetId);}};
  const reset=createSecureShopSsrfResetAdapter({repository,targetPool:pool,cleanupAuthority:{async checkTarget(value){
    assert.equal(value.targetKind,'controlled_ssrf');assert.equal(value.targetId,scope.targetId);return{status:'fenced'};}}});
  const operationId=uuid(),first=await reset.cleanup({...scope,fromGeneration:1},{operationId});
  assert.equal(first.operationId,operationId);assert.equal(creations,0);
  await assert.rejects(fs.stat(targetDirectory),{code:'ENOENT'});assert.equal(await fs.readFile(path.join(siblingDirectory,'private-policy.json'),'utf8'),'sibling');
  assert.equal((await reset.cleanup({...scope,fromGeneration:1},{operationId})).operationId,operationId);
  assert.equal(creations,0);await assert.rejects(pool.issue(scope,{requestId:uuid(),resourceKind:'public-policy'}),/retired/);
});

test('target retirement validates pending scope before fencing and closes issue/retire resurrection races', async () => {
  let resolveTarget; const created = new Promise(resolve => { resolveTarget = resolve; });
  let creations = 0, cleanups = 0;
  const pool = createSecureShopSsrfTargetPool({ root: '/owned', createTarget: async ({ targetId }) => {
    creations += 1; await created;
    return { issue: input => ({ targetId, ...input }), consume() {}, readReceipt() {}, pendingReceipts() { return 0; },
      async cleanup() { cleanups += 1; return { ok: true, replayed: false }; } };
  } });
  const initialIssue = pool.issue(scope, { requestId: uuid(), resourceKind: 'public-policy' });
  const wrongOwner = { ...scope, platformOwnerId: sibling.platformOwnerId, platformSessionId: sibling.platformSessionId };
  await assert.rejects(pool.retire(wrongOwner), /scope mismatch/,
    'an unauthorized pending-target retirement cannot install a tombstone');
  const retirement = pool.retire(scope); resolveTarget();
  await assert.rejects(initialIssue, /retired/, 'an issue admitted before retirement cannot publish after the fence');
  assert.deepEqual(await retirement, { ok: true, replayed: false });
  assert.equal(creations, 1); assert.equal(cleanups, 1);
  await assert.rejects(pool.issue(scope, { requestId: uuid(), resourceKind: 'public-policy' }), /retired/);
  await assert.rejects(pool.issue(wrongOwner, { requestId: uuid(), resourceKind: 'public-policy' }), /scope mismatch/);

  const absent = { ...scope, targetId: uuid() };
  await assert.rejects(pool.retire({ ...absent, platformOwnerId: sibling.platformOwnerId }), /unavailable/,
    'an absent target requires a later durable cleanup authority and cannot be pre-tombstoned');
  resolveTarget = () => {};
  const fresh = pool.issue(absent, { requestId: uuid(), resourceKind: 'public-policy' });
  assert.equal((await fresh).targetId, absent.targetId, 'a rejected absent-target retirement cannot squat the identifier');
  await pool.retire(absent);
});

test('application sends public and selected-private observations through the same real MCP tool and fails closed on restart debt', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ssrf-application-')); t.after(() => fs.rm(root, { recursive:true, force:true }));
  const actual = await protocol(t), requests = new Map(); let targetLifecycle = 'active', toolCalls = 0;
  const repository = {
    async provision() { if (targetLifecycle !== 'active') throw Object.assign(new Error('retired'), { code:'BOUND_SSRF_UNAVAILABLE' }); },
    async claimRequest(target, input) { const key = `${target.targetId}:${input.requestId}`; let row = requests.get(key);
      if (!row) { row = { operationId:uuid(),targetId:target.targetId,...input,nonce:null,url:null,completed:false }; requests.set(key,row);
        return { ...row,replayed:false }; }
      if (row.resourceKind !== input.resourceKind) throw new Error('conflict'); return { ...row,replayed:true }; },
    async attachRequest(target, issued) { const key=`${target.targetId}:${issued.requestId}`,row=requests.get(key);
      if (!row || row.operationId !== issued.operationId) throw new Error('conflict'); Object.assign(row,issued); return { ...row }; },
  };
  const launches = { async assertCurrent() {}, async reserveSsrfTarget() { return { ...scope,kind:'controlled_ssrf' }; } };
  const conversations = { async create() { return { id:`session:${uuid()}` }; } }, availability = { async assertObjective(id) {
    assert.equal(id,'ss_controlled_ssrf'); } };
  const pool = createSecureShopSsrfTargetPool({ root }); t.after(() => pool.retire(scope).catch(() => {}));
  const makeApplication = targetPool => createSecureShopSsrfApplication({ launches,repository,targetPool,conversations,availability,
    async runAgent(input) { const match=input.message.match(/exact URL:\n(http:\/\/127\.0\.0\.1:\d+\/policy\/[^\n]+)/);
      assert.ok(match,'the application task exposes the exact issued target to the model runner'); toolCalls += 1;
      const result=await actual.callTool('summarizer','explain_return_policy',{policy_url:match[1]},{});
      const parsed=JSON.parse(result.content[0].text),row=requests.get(`${scope.targetId}:${input.requestId}`);
      row.completed=true; return { stopReason:'end_turn',text:parsed.body,replayed:false }; } });
  const app=makeApplication(pool), publicId=uuid(), privateId=uuid();
  const publicRun=await app.runPublicBaseline({scope,persona:{id:11,role:'customer'},requestId:publicId});
  assert.equal(publicRun.stopReason,'end_turn');
  assert.equal(typeof publicRun.response,'string','canonical runner text must reach the learner response');
  assert.equal(JSON.parse(publicRun.response).classification,'public');
  const privateRun=await app.runSelectedInternal({scope,persona:{id:11,role:'customer'},requestId:privateId});
  assert.equal(JSON.parse(privateRun.response).classification,'protected-training-record'); assert.equal(toolCalls,2);

  const completedRow=requests.get(`${scope.targetId}:${publicId}`), pendingId=uuid();
  requests.set(`${scope.targetId}:${pendingId}`,{...completedRow,requestId:pendingId,operationId:uuid(),completed:false});
  const restarted=createSecureShopSsrfApplication({launches,repository,targetPool:{ async issue(){throw new Error('must not recreate');} },
    conversations,availability,async runAgent(){return {stopReason:'end_turn',replayed:true,response:'retained'};}});
  assert.equal((await restarted.runPublicBaseline({scope,persona:{id:11,role:'customer'},requestId:publicId})).replayed,true,
    'a completed request uses its stable stored task and canonical runner replay without a new listener/effect');
  await assert.rejects(restarted.runPublicBaseline({scope,persona:{id:11,role:'customer'},requestId:pendingId}),/reconciliation/);
  targetLifecycle='retired';
  await assert.rejects(restarted.runPublicBaseline({scope,persona:{id:11,role:'customer'},requestId:uuid()}),/retired/,
    'a durable retirement rejects before a restarted pool can recreate target files');
});

test('application serializes the request fingerprint and retains an active same-kind request until every caller releases', async () => {
  const requests=new Map(),gates=[],entered=[];let claims=0,issues=0;
  const repository={async provision(){},async claimRequest(target,input){claims++;const key=`${target.targetId}:${input.requestId}`;
      let row=requests.get(key);if(!row){row={operationId:uuid(),targetId:target.targetId,...input,completed:false};requests.set(key,row);return row;}
      if(row.resourceKind!==input.resourceKind)throw Object.assign(new Error('conflict'),{code:'BOUND_SSRF_UNAVAILABLE'});return row;},
    async attachRequest(_target,issued){const row=requests.get(`${scope.targetId}:${issued.requestId}`);Object.assign(row,issued);return row;}};
  const launches={async assertCurrent(){},async reserveSsrfTarget(){return{...scope,kind:'controlled_ssrf'};}};
  const targetPool={async issue(_target,input){issues++;return{...input,nonce:uuid(),url:`http://127.0.0.1:8181/policy/${input.resourceKind}`};}};
  const conversations={async create(){return{id:`session:${uuid()}`};}},availability={async assertObjective(){}};
  let app;const runAgent=async input=>{entered.push(input.requestId);await new Promise(resolve=>gates.push(resolve));
    const resolved=await app.resolveRequest(input.scope,{requestId:input.requestId});
    return{stopReason:'end_turn',response:resolved.resourceKind,replayed:false};};
  app=createSecureShopSsrfApplication({launches,repository,targetPool,conversations,availability,runAgent});
  const requestId=uuid(),first=app.runPublicBaseline({scope,persona:{id:11,role:'customer'},requestId});
  while(entered.length<1)await new Promise(resolve=>setImmediate(resolve));
  await assert.rejects(app.runSelectedInternal({scope,persona:{id:11,role:'customer'},requestId}),/request conflict/);
  assert.equal(claims,1,'a conflicting resource cannot join or create a second durable claim');
  const second=app.runPublicBaseline({scope,persona:{id:11,role:'customer'},requestId});
  while(entered.length<2)await new Promise(resolve=>setImmediate(resolve));
  assert.equal(claims,1);assert.equal(issues,1,'same-kind concurrent replay shares the exact issued request');
  gates.shift()();assert.equal((await first).response,'public-policy');
  assert.equal((await app.resolveRequest(scope,{requestId})).resourceKind,'public-policy',
    'the first release cannot delete authority retained by the second caller');
  gates.shift()();assert.equal((await second).response,'public-policy');
  await assert.rejects(app.resolveRequest(scope,{requestId}),/unavailable/);
});

test('application classifies setup and agent failures while preserving inner phase and settled refusal behavior', async () => {
  const requests = new Map();
  const launches = { async assertCurrent() {}, async reserveSsrfTarget() { return { ...scope, kind:'controlled_ssrf' }; } };
  const repository = { async provision() {}, async claimRequest(target, input) {
    const row = { targetId:target.targetId, operationId:uuid(), ...input, completed:false };
    requests.set(input.requestId, row); return row;
  }, async attachRequest(_target, issued) { return { ...requests.get(issued.requestId), ...issued }; } };
  const targetPool = { async issue(target, input) { return { targetId:target.targetId, ...input,
    nonce:uuid(), url:`http://127.0.0.1:8181/policy/${input.resourceKind}/${uuid()}` }; } };
  const conversations = { async create() { return { id:`session:${uuid()}` }; } };
  let setupFailure = null, runner;
  const availability = { async assertObjective() { if (setupFailure) throw setupFailure; } };
  const application = createSecureShopSsrfApplication({ launches, repository, targetPool, conversations, availability,
    runAgent: input => runner(input) });
  const invoke = () => application.runSelectedInternal({ scope, persona:{id:11,role:'customer'}, requestId:uuid() });

  runner = async () => ({ stopReason:'end_turn', text:'I cannot fetch that resource.', replayed:false });
  assert.deepEqual(await invoke(), { resourceKind:'private-policy', replayed:false, stopReason:'end_turn',
    response:'I cannot fetch that resource.' });

  const inner = Object.assign(new Error('private adapter detail'), { code:'BOUND_SSRF_UNAVAILABLE' });
  markSecureShopFailure(inner, 'external_observation'); runner = async () => { throw inner; };
  let observed;
  await assert.rejects(invoke(), error => { observed = error; return true; });
  assert.equal(observed, inner); assert.equal(projectSecureShopFailure(observed).phase, 'external_observation');

  const agentFailure = Object.assign(new Error('private provider detail'), { code:'BOUND_SSRF_UNAVAILABLE' });
  runner = async () => { throw agentFailure; };
  await assert.rejects(invoke(), error => { observed = error; return true; });
  assert.equal(observed, agentFailure); assert.equal(projectSecureShopFailure(observed).phase, 'agent_run');

  setupFailure = Object.assign(new Error('private availability detail'), { code:'BOUND_SSRF_UNAVAILABLE' });
  await assert.rejects(invoke(), error => { observed = error; return true; });
  assert.equal(observed, setupFailure); assert.equal(projectSecureShopFailure(observed).phase, 'application_setup');
});

test('bound runner resolves server-owned target authority from its target-free conversation binding', async () => {
  const requestId=uuid(),sessionId=uuid(),runId=uuid(),operationId=uuid(),nonce=uuid(),callId='ssrf-bound-call';
  const {targetId,...launchScope}=scope;const issued={...scope,operationId,requestId,nonce,resourceKind:'public-policy',
    url:'http://127.0.0.1:8181/policy/public',egressPolicySha256:SSRF_EGRESS_POLICY_SHA256,policyDecision:'allowed'};
  const body=JSON.stringify({classification:'public'}),parsed={url:issued.url,status:200,body};
  const receipt={operationId,targetId,nonce,requestId,resourceKind:'public-policy',method:'GET',path:'/policy/public',status:200,
    responseSha256:crypto.createHash('sha256').update(body).digest('hex'),receiptSha256:'a'.repeat(64)};
  let resolvedBinding;
  const external=createSecureShopSsrfExternalAdapter({resolveRequest:async binding=>{resolvedBinding=binding;return issued;},
    targetPool:{consume(){},readReceipt(){return receipt;}},checkCurrent:async()=>{},recordInvocation:async()=>{},
    upstreamPool:{async callTool(){return{content:[{type:'text',text:JSON.stringify(parsed)}]};}}});
  const messages=[];const config=createSecureShopSsrfExecutionConfig();let responseIndex=0;
  const runner=createBoundAgentRunner({
    turns:{async run(_id,_binding,_persona,_options,operation){const boundary={identity:{runId,ownerKey:'owner:ssrf',durableGeneration:'1'},
        async check(){},async effectWithReceipt(key,callback){return{value:await callback(),receipt:{version:1,status:'completed',runId,
          ownerKey:'owner:ssrf',generation:'1',effectKey:`${requestId}:${key}`}};}};return operation(boundary);}},
    conversations:{async assertOwned(){},async getMessages(){return messages;}},repository:{async appendMessage(_id,_binding,message){messages.push(message);},
      async getTokens(){return 0;},async addTokens(){},async appendTraces(){}},journal:{async claim(){return{status:'claimed',claimId:requestId};},
      async complete(){},async markUncertain(){}},provider:{async chat(){return responseIndex++===0
        ?{stop_reason:'tool_use',tool_uses:[{id:callId,name:'summarizer.explain_return_policy',args:{policy_url:issued.url}}]}
        :{stop_reason:'end_turn',text:'public policy observed'};}},manifest:config.manifest,buildBasePrompt:config.buildBasePrompt,
    buildPolicyBlock:config.buildPolicyBlock,checkToolAcl:config.checkToolAcl,createLocalTools:async()=>({}),
    createToolPool:external.createToolPool,limits:{maxSteps:3,maxParallelTools:1}});
  const result=await runner.run({sessionId,requestId,scope:launchScope,persona:{id:11,role:'customer'},message:'Fetch policy'});
  assert.equal(result.stopReason,'end_turn');assert.equal(resolvedBinding.targetId,undefined);
  assert.deepEqual(Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId']
    .map(key=>[key,resolvedBinding[key]])),launchScope);
});

test('composition remains structurally absent while default-off and fails closed without production dependencies', () => {
  assert.deepEqual(createSecureShopSsrfComposition(), { ready:false });
  assert.throws(() => createSecureShopSsrfComposition({enabled:true}), { code:'BOUND_SSRF_UNAVAILABLE' });
});

test('cleanup authority and reconciliation normalize the SSRF kind without dropping existing target kinds', () => {
  const expected=['files','mcp_rogue','mcp_rug_pull','persona_inbox','products','reviews','controlled_ssrf'];
  assert.deepEqual(SECURESHOP_RESET_TARGET_KINDS,expected);
  assert.deepEqual(SECURESHOP_RECONCILIATION_TARGET_KINDS,expected);
  assert.equal(Object.isFrozen(SECURESHOP_RESET_TARGET_KINDS),true);
  assert.equal(Object.isFrozen(SECURESHOP_RECONCILIATION_TARGET_KINDS),true);
});

test('repository maps canonical invocation and cleanup receipts with exact launch scope', async () => {
  const operationId=uuid(),runId=uuid(),requestId=uuid(),now='2026-09-14T12:00:00.123Z';
  const callId='call-1',args={policy_url:'http://127.0.0.1:8181/policy/private'};
  const body=JSON.stringify({recordId:`internal-policy:${scope.targetId}`,classification:'protected-training-record'});
  const result={content:[{type:'text',text:JSON.stringify({url:args.policy_url,status:200,body})}]};
  const row={operation_id:operationId,target_id:scope.targetId,launch_id:scope.launchId,scenario_id:scope.scenarioId,generation:'1',
    original_platform_owner_id:'11',original_platform_session_id:'21',run_id:runId,request_id:requestId,session_id:`session:${uuid()}`,
    call_id:callId,arguments_hex:digestMcpValue(args),result_hex:digestMcpValue(JSON.parse(result.content[0].text)),
    response_hex:crypto.createHash('sha256').update(body).digest('hex'),
    egress_hex:'4'.repeat(64),policy_hex:SSRF_EGRESS_POLICY_SHA256,request_method:'GET',request_path:'/policy/private',
    response_status:200,resource_kind:'private-policy',policy_decision:'denied',completed_at:now};
  const cleanup={operation_id:operationId,target_id:scope.targetId,launch_id:scope.launchId,scenario_id:scope.scenarioId,
    generation:'1',original_platform_owner_id:'11',original_platform_session_id:'21',receipt_hex:'5'.repeat(64),
    completed_at:now,retained_request_count:'2',retained_invocation_count:'1'};
  const calls=[];const pool={async query(sql,params){calls.push({sql,params});if(sql.includes('bound_ssrf_invocations i JOIN'))return{rows:[row]};
      if(sql.includes('bound_ssrf_cleanup_receipts r WHERE'))return{rows:[cleanup]};throw new Error('unexpected SQL');},async connect(){throw new Error('unused');}};
  const repository=createSecureShopBoundSsrfRepository(pool,{checkCurrent:async()=>{},checkCleanup:async()=>{}});
  const mapped=await repository.readInvocation(scope,operationId);
  assert.deepEqual(mapped,{operationId,targetId:scope.targetId,launchId:scope.launchId,
    scenarioId:scope.scenarioId,generation:1,platformOwnerId:11,platformSessionId:21,runId,requestId,
    sessionId:row.session_id,callId,argumentsSha256:row.arguments_hex,resultSha256:row.result_hex,
    responseSha256:row.response_hex,egressReceiptSha256:row.egress_hex,egressPolicySha256:row.policy_hex,
    requestMethod:'GET',requestPath:row.request_path,responseStatus:200,resourceKind:'private-policy',policyDecision:'denied',completedAt:now});
  const receipt=await repository.readCleanupReceipt(scope,{operationId});assert.equal(receipt.retainedRequestCount,2);
  assert.equal(receipt.retainedInvocationCount,1);assert.deepEqual(calls[0].params,[operationId,scope.targetId,scope.launchId,
    scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId]);
  const execution={runId,ownerKey:'owner:repository',durableGeneration:'1'},effectReceipt={version:1,status:'completed',runId,
    ownerKey:execution.ownerKey,generation:'1',effectKey:`${requestId}:${JSON.stringify([1,callId,'summarizer.explain_return_policy'])}`};
  const observation={step:1,callId,tool:'summarizer.explain_return_policy',args,result,effectReceipt};
  const traces=[{kind:'model_decision',actor:'supervisor',provider:'ollama',step:1,
    params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:callId,name:observation.tool,args}]}),
    result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},
  {kind:'mcp_result',actor:'task→supervisor',step:1,agent_ns:'summarizer',tool_name:'explain_return_policy',result_json:JSON.stringify(result)},
  {kind:'terminal',actor:'supervisor',provider:'ollama',step:2,result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,stopReason:'end_turn'})}];
  assert.equal(buildSecureShopSsrfEvidence({binding:scope,execution,sessionId:row.session_id,requestId,traces,observation,
    externalRecord:{invocation:mapped,effectReceipt},result:{stopReason:'end_turn'},qualifyModel:()=>true}).length,1,
  'the authoritative repository DTO remains directly gradeable by the production evidence builder');
});

test('repository request reads require the exact active persisted target and cleanup data cannot override authority', async () => {
  const requestId=uuid(),operationId=uuid(),checks=[];let lifecycle='active';
  const requestRow={operation_id:operationId,target_id:scope.targetId,request_id:requestId,resource_kind:'public-policy',
    nonce:uuid(),issued_url:'http://127.0.0.1:8181/policy/public',completed:false};
  const client={async query(sql,params){if(sql==='BEGIN'||sql==='COMMIT'||sql==='ROLLBACK')return{rows:[]};
      if(sql.includes('pg_advisory_xact_lock'))return{rows:[{}]};
      if(sql.includes('FROM secureshop_agents.bound_ssrf_targets')&&!sql.includes('JOIN')){
        const exact=JSON.stringify(params)===JSON.stringify([scope.targetId,scope.launchId,scope.scenarioId,1,11,21]);
        return{rows:exact?[{lifecycle}]:[]};}
      if(sql.includes('bound_ssrf_requests r')&&sql.includes('JOIN secureshop_agents.bound_ssrf_targets'))return{rows:[requestRow]};
      throw new Error(`unexpected SQL: ${sql}`);},release(){}};
  const pool={async connect(){return client;},async query(){throw new Error('authority checks must use one transaction');}};
  const repository=createSecureShopBoundSsrfRepository(pool,{checkCurrent:async()=>{},checkCleanup:async value=>checks.push(value)});
  assert.equal((await repository.readRequest(scope,{requestId})).operationId,operationId);
  await assert.rejects(repository.readRequest({...scope,platformOwnerId:12},{requestId}),{code:'BOUND_SSRF_UNAVAILABLE'});
  await assert.rejects(repository.readRequest({...scope,launchId:sibling.launchId},{requestId}),{code:'BOUND_SSRF_UNAVAILABLE'});
  lifecycle='retired';await assert.rejects(repository.readRequest(scope,{requestId}),{code:'BOUND_SSRF_UNAVAILABLE'});
  await assert.rejects(repository.readCleanupReceipt(scope,{operationId,platformOwnerId:12}),{code:'BOUND_SSRF_UNAVAILABLE'});
  assert.equal(checks.length,0,'mismatched cleanup coordinates are rejected before the authority callback or SQL');
});

test('registered durable schema preserves reviewed audit receipts and scope-safe restart tombstones', async () => {
  const [agents,identity]=await Promise.all([fs.readFile(path.join(__dirname,'../docs/modernization/drafts/secureshop-controlled-ssrf-agents.sql'),'utf8'),
    fs.readFile(path.join(__dirname,'../docs/modernization/drafts/secureshop-controlled-ssrf-identity.sql'),'utf8')]);
  assert.match(agents,/bound_ssrf_requests/);assert.match(agents,/bound_ssrf_invocations/);
  assert.match(agents,/operation scope mismatch/);assert.match(agents,/retained_invocation_count/);
  assert.match(agents,/pg_advisory_xact_lock\(hashtextextended\(requested_target::text,0\)\)/,
    'runtime operations and retirement share the exact target transaction lock');
  assert.doesNotMatch(agents,/DELETE FROM secureshop_agents\.bound_ssrf_invocations/);
  assert.match(identity,/controlled_ssrf/);
  assert.equal(await fs.readFile(path.join(__dirname,'../db/postgres/identity-migrations/0052_secureshop_controlled_ssrf.sql'),'utf8'),identity,
    'registered identity schema preserves exact reviewed bytes');
  assert.equal(await fs.readFile(path.join(__dirname,'../db/postgres/workshop-migrations/secureshop_agents/0012_secureshop_controlled_ssrf.sql'),'utf8'),agents,
    'registered agent schema preserves exact reviewed bytes');
});

test('candidate persona revocation after real HTTP leaves receipt debt without evidence or retry send', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'owasp-ai-goat-ssrf-persona-')); t.after(() => fs.rm(root, { recursive: true, force: true }));
  const targetPool=createSecureShopSsrfTargetPool({root}),actual=await protocol(t);t.after(()=>targetPool.retire(scope));
  const requestId=uuid(),sessionId=`session:${uuid()}`,issued=Object.freeze({...scope,...await targetPool.issue(scope,{requestId,resourceKind:'private-policy'}),egressPolicySha256:SSRF_EGRESS_POLICY_SHA256,policyDecision:'denied'});
  let revoked=false,records=0;const fence=Object.freeze({async assertRemoteAdmission(){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_INVALID',executionBoundary:true});}});
  const execution={runId:uuid(),ownerKey:'owner:11',durableGeneration:1,signal:new AbortController().signal,async check(){}};
  const adapter=createSecureShopSsrfExternalAdapter({resolveRequest:async()=>issued,targetPool,upstreamPool:{async callTool(...args){const result=await actual.callTool(...args);revoked=true;return result;}},checkCurrent:async()=>{},recordInvocation:async()=>{records++;}});
  const tools=await adapter.createToolPool(scope,{execution,requestId,sessionId},fence);
  await assert.rejects(tools.callTool('summarizer','explain_return_policy',{policy_url:issued.url},{callId:'owned-call'}),{code:'SHOP_AUTH_INVALID',executionBoundary:true});
  assert.equal(actual.calls,1);assert.equal(records,0);assert.equal(targetPool.pendingReceipts(scope),1);
  await assert.rejects(tools.callTool('summarizer','explain_return_policy',{policy_url:issued.url},{callId:'retry-call'}),{code:'SHOP_AUTH_INVALID',executionBoundary:true});assert.equal(actual.calls,1);
});

test('V27 composition closes only its lazily created browser adapter exactly once', async () => {
  const vm=require('node:vm'),{createRequire}=require('node:module');
  const filename=require.resolve('../server/services/secureshopSsrfComposition'),localRequire=createRequire(filename);
  let created=0,closed=0;
  const module={exports:{}};
  vm.runInNewContext(`(function(require,module,exports){${await fs.readFile(filename,'utf8')}\n})`,{}, {filename})(name=>{
    if(name==='./secureshopPolicyFinalHtmlAssessment')return {createPolicyFinalHtmlAssessment:options=>options.browserQualification};
    if(name==='./secureshopPolicyOutputBrowserQualification')return {createSecureShopPolicyOutputBrowserQualification(){created++;return {readComponent(){return {id:'owned'};},async close(){closed++;}};}};
    return localRequire(name);
  },module,module.exports);
  const noop=async()=>{},methods=new Proxy({}, {get:()=>noop});
  const options={enabled:true,identityPool:methods,agentsPool:methods,provider:{chat:noop,finalResponse:noop},
    personaAuthority:{capture:noop},personaBindings:methods,modeAuthority:{capture:noop},
    resetComposition:{launches:methods,conversationService:methods,turns:methods,journal:methods,
      conversations:methods,cleanupAuthority:methods,runCoordinator:methods},targetPool:methods,upstreamPool:methods};
  const build=module.exports.createSecureShopSsrfComposition;
  const unused=build(options);await unused.close();assert.equal(created,0);assert.equal(closed,0);
  assert.throws(()=>unused.htmlAssessment.readComponent());
  const active=build(options);assert.equal(active.htmlAssessment.readComponent().id,'owned');assert.equal(created,1);
  await Promise.all([active.close(),active.close()]);assert.equal(closed,1);
  assert.throws(()=>active.htmlAssessment.readComponent());
  let injectedClosed=0;const injected={readComponent(){return {id:'injected'};},async close(){injectedClosed++;}};
  const external=build({...options,policyOutputBrowserQualification:injected});
  assert.equal(external.htmlAssessment,injected);await external.close();assert.equal(injectedClosed,0);assert.equal(closed,1);
});
