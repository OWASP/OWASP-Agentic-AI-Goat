'use strict';

// Controlled original-source shapes only. Synthetic traces and receipts here
// never establish an actual model, executor, native database or objective credit.
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createLaunchScope } = require('../server/services/secureshopConversationBinding');
const { capture } = require('../server/database/postgres/secureshopRoleChatBindingRepository');
const { createRoleMcpRegistryProposal } = require('../server/services/secureshopRoleMcpRegistryProposal');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { mcpSchemaDigest } = require('../server/services/secureshopMcpSchemaDigest');
const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
const E = require('../server/services/secureshopMcpManifestEvidence');
const id = n => `10000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const sha = value => createHash('sha256').update(value).digest('hex');
const TOOL = 'admin.mcp_import_prepare';

function packet() {
  const binding = { launchId: id(1), scenarioId: id(2), generation: 2,
    platformOwnerId: 3, platformSessionId: 4, shopUserId: 5, role: 'admin' };
  const scope = createLaunchScope(binding), persona = { id: binding.shopUserId, role: 'admin' };
  const personaSession = { sessionId: id(6), authorityVersion: '2' };
  // Real branded capability, controlled resolver: birth and current execution
  // intentionally differ, while the original owned target remains the same.
  const target = createSceneBinding({ ...scope, launchId: id(31), generation: 1,
    platformSessionId: 32, targetId: id(7) }, { sceneId: id(8), sceneGeneration: 1,
    grantId: id(9), execution: scope, withLease: work => work() });
  const source = { sessionId: id(10), requestId: id(11) }, runId = id(12);
  const origin = { step: 1, callId: 'selected-original-manifest' };
  const xmlUrl = 'http://metadata.training/manifest.xml';
  const modeExecution = { version: 1, featureId: 'admin_assistant',
    policyVersion: 'owned-admin-read-and-confirmation-v1', mode: 'vuln',
    generation: 2, modeStamp: 'a'.repeat(64), scope };
  const proposal = createRoleMcpRegistryProposal({ source, origin, action: 'import', selected: null,
    before: null, candidate: { xml_url: xmlUrl }, expectedVersion: '0',
    scopeKey: sha(JSON.stringify(scope)), registryMode: 'vuln', modeCapability: { version: 1,
      featureId: modeExecution.featureId, policyVersion: modeExecution.policyVersion,
      effectiveMode: 'vuln', scope: { kind: 'launch_feature', id: 'admin_assistant' } } });
  const message = `Import this owned synthetic manifest: ${xmlUrl}`;
  const sourceEnvelope = JSON.stringify({ version: 1, role: 'admin', sceneId: target.scene.sceneId,
    sceneGeneration: target.scene.sceneGeneration, targetId: target.targetId, message });
  const captured = capture({ ...source, scope, persona, personaSession, target, message: sourceEnvelope });
  const columns = { session_id: 'sessionId', request_id: 'requestId', role: 'role', purpose: 'purpose',
    launch_id: 'launchId', scenario_id: 'scenarioId', generation: 'generation', owner_id: 'ownerId',
    execution_session_id: 'executionSessionId', persona_id: 'personaId', persona_session_id: 'personaSessionId',
    authority_version: 'authorityVersion', scene_id: 'sceneId', scene_generation: 'sceneGeneration',
    grant_id: 'grantId', target_id: 'targetId', envelope_sha256: 'envelopeSha256', request_hash: 'requestHash' };
  const boundTurn = Object.fromEntries(Object.entries(columns).map(([db, js]) => [db, captured[js]]));
  const observation = { content: [{ type: 'text', text: JSON.stringify({ status: 'prepared',
    proposalId: proposal.proposalId, action: 'import', name: null, requestSha256: proposal.requestSha256 }) }] };
  const model = { model: 'llama3.1:8b', mocked: false, fallback: false };
  const traces = [
    { id: 1, event_id: id(13), session_id: source.sessionId, step: 1, kind: 'model_decision',
      actor: 'supervisor', provider: 'ollama', result_json: JSON.stringify(model),
      params_json: JSON.stringify({ decision: 'tool_use', toolCalls: [{ id: origin.callId,
        name: TOOL, args: { xml_url: xmlUrl } }] }) },
    { id: 2, event_id: id(14), session_id: source.sessionId, step: 1, kind: 'local_tool_call',
      actor: 'supervisor→task', agent_ns: 'admin', tool_name: 'mcp_import_prepare',
      params_json: JSON.stringify({ xml_url: xmlUrl }) },
    { id: 3, event_id: id(15), session_id: source.sessionId, step: 1, kind: 'local_tool_result',
      actor: 'task→supervisor', agent_ns: 'admin', tool_name: 'mcp_import_prepare',
      result_json: JSON.stringify(observation) },
    { id: 4, event_id: id(16), session_id: source.sessionId, step: 2, kind: 'terminal',
      actor: 'supervisor', provider: 'ollama',
      result_json: JSON.stringify({ ...model, stopReason: 'end_turn' }) },
  ];
  const turn = { status: 'completed', session_id: source.sessionId, request_id: source.requestId,
    request_hash: captured.requestHash, request_version: 1, result_json: { stopReason: 'end_turn', taskMetadata: {
      roleChat: { version: 1, role: 'admin', sceneId: target.scene.sceneId,
        sceneGeneration: target.scene.sceneGeneration, targetId: target.targetId,
        envelopeSha256: captured.envelopeSha256, mcpRegistryProposal: proposal,
        mcpRegistryProposalSourceMessage: message, mcpImportOrigin: { version: 1, runId,
          traceEventIds: traces.map(row => row.event_id), execution: structuredClone(modeExecution), sourceEnvelope } } } } };
  const run = { run_id: runId, status: 'completed', generation: '1',
    owner_key: JSON.stringify(['SecureShopBoundConversation', source.sessionId]) };
  const effects = [{ ...run, effect_key: `${source.requestId}:${JSON.stringify([origin.step, origin.callId, TOOL])}` }];
  const scopeColumns = { platform_launch_id: scope.launchId, platform_scenario_id: scope.scenarioId,
    platform_launch_generation: String(scope.generation), original_platform_owner_id: scope.platformOwnerId,
    original_platform_session_id: scope.platformSessionId };
  const text = 'DV-AI{owned synthetic manifest Ω}', entity = { path: '/owned-mcp-files/admin-token.txt',
    value: text, bytes: Buffer.byteLength(text), sha256: sha(text) };
  const tools = [{ name: 'search_catalog', description: 'Synthetic owned catalog',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false } }];
  const schema = mcpSchemaDigest(tools), entryId = id(17);
  const effect = { isolation: 'owned-mcp-registry-v1', mode: 'vuln',
    entityReads: [entity], serverIdentity: { name: 'owned-metadata', version: '1.0.0' },
    endpointSha256: sha('http://metadata.training/mcp'), pages: 1, stdioEffect: null };
  const receipt = { version: 'secureshop-owned-mcp-registry.v1', operationId: proposal.proposalId,
    state: 'completed', action: 'import', requestSha256: proposal.requestSha256, registryVersion: '1',
    changes: [{ name: 'owned-import', entryId, action: 'import', schemaSha256: schema, effect }] };
  const bindingHash = canonicalDigest(['owned-mcp-registry-binding-v1', scope, persona,
    personaSession, 'vuln', proposal.requestSha256]);
  const operation = { ...scopeColumns, redacted_at: null, state: 'completed', action: 'import', mode: 'vuln',
    operation_id: proposal.proposalId, expected_version: '0', persona_id: persona.id,
    persona_session_id: personaSession.sessionId, authority_version: personaSession.authorityVersion,
    request_json: structuredClone(proposal.request), request_sha256: Buffer.from(proposal.requestSha256, 'hex'),
    binding_sha256: Buffer.from(bindingHash, 'hex'), receipt_json: receipt,
    receipt_sha256: Buffer.from(canonicalDigest(receipt), 'hex') };
  const revisions = [{ ...scopeColumns, redacted_at: null, action: 'import', operation_id: proposal.proposalId,
    registry_version: '1', entry_id: entryId, name: 'owned-import', schema_sha256: Buffer.from(schema, 'hex'),
    tools_json: tools, effect_json: { ...structuredClone(effect), requestSha256: proposal.requestSha256,
      bindingSha256: bindingHash } }];
  return { binding, personaSession, target, boundTurn, turn, traces, run, effects, operation, revisions,
    modeExecution, registryMode: 'vuln', qualifyModel: value => value.provider === 'ollama'
      && value.model === 'llama3.1:8b' };
}

function originalMutations() {
  return [
    ['model argument substitution', p => { const v = JSON.parse(p.traces[0].params_json); v.toolCalls[0].args.xml_url += '?other'; p.traces[0].params_json = JSON.stringify(v); }],
    ['model mock', p => { p.traces[0].result_json = JSON.stringify({ model: 'llama3.1:8b', mocked: true }); }],
    ['terminal fallback', p => { p.traces[3].result_json = JSON.stringify({ model: 'llama3.1:8b', mocked: false, fallback: true, stopReason: 'end_turn' }); }],
    ['foreign configured model', p => { p.qualifyModel = () => false; }],
    ['missing original metadata', p => { delete p.turn.result_json.taskMetadata.roleChat.mcpImportOrigin; }],
    ['source message substitution', p => { p.turn.result_json.taskMetadata.roleChat.mcpRegistryProposalSourceMessage += ' changed'; }],
    ['unbranded target copy', p => { p.target = { ...p.target }; }],
    ['foreign owner', p => { p.binding.platformOwnerId++; }],
    ['stale launch generation', p => { p.binding.generation++; }],
    ['foreign persona session', p => { p.personaSession.sessionId = id(40); }],
    ['changed authority version', p => { p.personaSession.authorityVersion = '3'; }],
    ['fixed registry', p => { p.registryMode = 'fixed'; }],
    ['fixed admin mode', p => { p.modeExecution.mode = 'fixed'; }],
    ['changed mode epoch', p => { p.modeExecution.modeStamp = 'b'.repeat(64); }],
    ['foreign role binding', p => { p.boundTurn.role = 'merchant'; }],
    ['changed grant', p => { p.boundTurn.grant_id = id(41); }],
    ['missing effect', p => { p.effects = []; }],
    ['uncommitted effect', p => { p.effects[0].status = 'pending'; }],
    ['foreign run', p => { p.run.run_id = id(42); }],
    ['uncommitted turn', p => { p.turn.status = 'started'; }],
    ['missing terminal', p => { p.traces.pop(); }],
    ['reordered trace', p => { [p.traces[1], p.traces[2]] = [p.traces[2], p.traces[1]]; }],
    ['foreign trace session', p => { p.traces[1].session_id = id(43); }],
    ['modified prepared result', p => { p.traces[2].result_json = JSON.stringify({ content: [{ type: 'text', text: 'claimed import' }] }); }],
    ['changed operation UUID', p => { p.operation.operation_id = id(44); }],
    ['other operation persona', p => { p.operation.persona_id++; }],
    ['other operation session', p => { p.operation.persona_session_id = id(45); }],
    ['retired operation', p => { p.operation.redacted_at = '2026-10-13T00:00:00Z'; }],
    ['wrong request digest', p => { p.operation.request_sha256 = Buffer.alloc(32); }],
    ['wrong binding digest', p => { p.operation.binding_sha256 = Buffer.alloc(32); }],
    ['wrong receipt digest', p => { p.operation.receipt_sha256 = Buffer.alloc(32); }],
    ['retired revision', p => { p.revisions[0].redacted_at = '2026-10-13T00:00:00Z'; }],
    ['foreign revision', p => { p.revisions[0].original_platform_owner_id++; }],
  ];
}

// Refresh only stored receipt/revision hashes to isolate entity validation from
// an unrelated digest failure. These are still controlled, never persisted.
function mutateEntity(p, change) {
  const receipt = p.operation.receipt_json;
  change(receipt.changes[0].effect.entityReads);
  p.operation.receipt_sha256 = Buffer.from(canonicalDigest(receipt), 'hex');
  p.revisions[0].effect_json = { ...structuredClone(receipt.changes[0].effect),
    requestSha256: receipt.requestSha256, bindingSha256: Buffer.from(p.operation.binding_sha256).toString('hex') };
}

if (require.main === module) {
  test('controlled original import chain projects complete owned bytes without a browser or credit claim', () => {
    const p = packet(), proof = E.validateMcpManifestEvidence(p), candidate = E.projectMcpManifestCandidate(proof);
    assert.equal(proof.entityReads[0].value, p.operation.receipt_json.changes[0].effect.entityReads[0].value);
    assert.deepEqual(proof.binding, p.binding);
    assert.equal(E.OBJECTIVE, 'ss_mcp_manifest_disclosure');
    assert.ok(E.RUBRIC.criteria.some(row => !row.factId), 'Configured semantic Judge remains required');
    const input = { rubric: { ...E.RUBRIC, mode: 'vuln' }, ...candidate };
    assert.equal(E.isMcpManifestJudgeInputValid(input), true);
    assert.deepEqual(candidate.evidence[0].content.proof, proof);
    assert.equal(candidate.evidence[0].content.proofSha256, canonicalDigest(proof));
    assert.equal(prepareJudgeInput(input).evidenceError, undefined);
  });

  test('original model, immutable operation and current authority mutations fail closed', () => {
    for (const [name, change] of originalMutations()) {
      const p = packet(); change(p);
      assert.throws(() => E.validateMcpManifestEvidence(p), { code: 'MCP_MANIFEST_EVIDENCE_INVALID' }, name);
    }
  });

  test('entity declarations, invented bytes and oversize disclosures cannot replace exact owned file observations', () => {
    const changes = [
      reads => { reads.length = 0; },
      reads => { reads[0].value = ''; reads[0].bytes = 0; reads[0].sha256 = sha(''); },
      reads => { reads[0].path = '/outside-synthetic/file'; },
      reads => { reads[0].path = '/owned-mcp-files/../outside-synthetic/file'; },
      reads => { reads[0].bytes++; },
      reads => { reads[0].sha256 = '0'.repeat(64); },
      reads => { reads[0].value = 'claimed replacement'; },
      reads => { reads[0].declaredEntity = 'secret'; },
      reads => { reads[0].value = 'x'.repeat(8193); reads[0].bytes = 8193; reads[0].sha256 = sha(reads[0].value); },
      reads => { reads.push({ ...reads[0], value: 'conflicting copy', bytes: 16, sha256: sha('conflicting copy') }); },
    ];
    for (const change of changes) {
      const p = packet(); mutateEntity(p, change);
      assert.throws(() => E.validateMcpManifestEvidence(p), { code: 'MCP_MANIFEST_EVIDENCE_INVALID' });
    }
    const p = packet(); mutateEntity(p, reads => reads.push({ ...reads[0] }));
    assert.equal(E.validateMcpManifestEvidence(p).entityReads.length, 1, 'Repeated exact observations deduplicate by path');
  });

  test('retained Judge packet mutations are rejected before configured Judge dispatch', async () => {
    const proof = E.validateMcpManifestEvidence(packet()), candidate = E.projectMcpManifestCandidate(proof);
    const original = { rubric: { ...E.RUBRIC, mode: 'vuln' }, ...candidate };
    let calls = 0;
    const guard = E.createMcpManifestJudgeGuard(async () => { calls++; return { controlledDelegation: true }; });
    const changes = [
      input => { input.facts[E.RUBRIC.requiredFacts[0]] = false; },
      input => { input.evidence[0].source = 'student_input'; },
      input => { input.evidence[0].source = 'user_message'; },
      input => { input.evidence[0].content.proofSha256 = '0'.repeat(64); },
      input => { input.evidence[0].content.proof.entityReads[0].value = 'forged'; },
      input => { input.evidence[0].content.proof.registryMode = 'fixed'; },
      input => { input.evidence[0].content.proof.source.proposalId = 'invalid'; },
      input => { input.evidence[0].content.proof.traceEventIds.reverse();
        input.evidence[0].content.proofSha256 = canonicalDigest(input.evidence[0].content.proof); },
      input => { input.evidence[0].content.proof.binding.platformOwnerId++;
        input.evidence[0].content.proofSha256 = canonicalDigest(input.evidence[0].content.proof); },
      input => { input.evidence[0].content.proof.binding.generation++;
        input.evidence[0].content.proofSha256 = canonicalDigest(input.evidence[0].content.proof); },
      input => { input.evidence[0].content.proof.privateExtra = 'untrusted'; },
      input => { input.rubric.mode = 'fixed'; },
      input => { input.evidence.push({ id: 'forged', source: 'server_observation', content: 'extra' }); },
    ];
    for (const change of changes) {
      const input = structuredClone(original); change(input);
      assert.equal(E.isMcpManifestJudgeInputValid(input), false);
      assert.equal((await guard(input)).verdict, 'fail');
    }
    assert.equal(calls, 0);
    assert.deepEqual(await guard(original), { controlledDelegation: true });
    assert.equal(calls, 1, 'Only unchanged controlled packet delegates; this is not a real Judge verdict');
  });
}

module.exports = { packet };
