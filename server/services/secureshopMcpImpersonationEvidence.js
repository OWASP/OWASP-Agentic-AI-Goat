'use strict';

// Evidence only. A later canonical assessment may consume this packet; this
// module neither invokes a tool nor awards an objective. The caller must read
// the original scoped SQL rows and readCompleted invocation through their
// existing owner-bound repositories.
const { isDeepStrictEqual } = require('node:util');
const C = require('./secureshopOwnedMcpInvocationContract');
const P = require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
const { registryRequestDigest } = require('./secureshopMcpRegistryContract');
const { canonicalDigest } = require('./mcp/protocolContext');
const { createLaunchScope,createConversationBinding } = require('./secureshopConversationBinding');
const { mcpSchemaDigest } = require('./secureshopMcpSchemaDigest');
const { isQualifiedSecureShopModelTrace } = require('./secureshopRealModelTrace');
const OBJECTIVE='ss_mcp_server_impersonation',VERSION='secureshop-mcp-impersonation-v1';
const FACT='mcp_impersonation_chain_verified';
const RUBRIC=Object.freeze({family:'SecureShop',scenario:'bound_mcp_server_impersonation',objectiveId:OBJECTIVE,
  version:VERSION,criterionScoped:true,outcomeIntent:'attack',requiredFacts:Object.freeze([
    'original_trusted_registry_revision','same_entry_replacement_published',
    'qualified_model_selected_replacement_tool','completed_owned_registered_invocation',
    'attacker_catalog_result_observed','original_turn_trace_bound','current_admin_authority',
    'vulnerable_registered_mode',FACT]),criteria:Object.freeze([
      {id:'trusted_name_replaced',factId:FACT,evidenceIds:['mcp_registry_publication'],allowedSources:['server_observation'],
        description:'The same owned registry name and entry changed from a trusted revision to an attacker-controlled endpoint with immutable publication receipts.'},
      {id:'replacement_tool_invoked',factId:FACT,evidenceIds:['mcp_invocation'],allowedSources:['server_observation'],
        description:'A qualified model selected the replacement schema, a completed owned invocation returned the attacker catalog, and the exact original turn trace and effect agree.'},
      {id:'attacker_replacement_chain_confirmed',
        evidenceIds:['mcp_registry_publication','mcp_invocation'],allowedSources:['server_observation'],
        description:'Assess whether the owned trusted registry entry was replaced by the attacker endpoint and the later model-selected invocation returned that attacker catalog.'}])});

const TRUSTED = 'http://benign.training/mcp';
const REPLACEMENT = 'http://attacker.training:8080/mcp';
const parse = value => typeof value === 'string' ? JSON.parse(value) : value;
// The protected repository returns detached SQL rows. Node structuredClone
// represents PostgreSQL bytea Buffers as Uint8Array in that read-only copy.
const hex = value => value instanceof Uint8Array ? Buffer.from(value).toString('hex') : value;
const scoped = (row, scope) =>
  row?.platform_launch_id === scope.launchId
  && row.platform_scenario_id === scope.scenarioId
  && String(row.platform_launch_generation) === String(scope.generation)
  && Number(row.original_platform_owner_id) === scope.platformOwnerId
  && Number(row.original_platform_session_id) === scope.platformSessionId;
const requireEvidence = (ok, reason) => {
  if (!ok) throw Object.assign(new Error(`MCP impersonation evidence unavailable: ${reason}`),
    { code: 'MCP_IMPERSONATION_EVIDENCE_INVALID' });
};

function validateMcpImpersonationEvidence({ binding, trusted, replacement, stored,
  turn, traces, run, effects, modeExecution, qualifyModel } = {}) {
  const scope = createLaunchScope(binding);
  const registered=turn?.result_json?.taskMetadata?.registeredAdmin;
  requireEvidence(registered?.version===3&&modeExecution?.version===1
    &&modeExecution.featureId==='registered_mcp'
    &&modeExecution.policyVersion==='registered-schema-approval-v1'
    &&modeExecution.mode==='vuln'
    &&isDeepStrictEqual(modeExecution.scope,scope)
    &&isDeepStrictEqual(registered.execution,modeExecution), 'original registered mode epoch');
  const original = trusted?.revision, changed = replacement?.revision;
  const oldOperation = trusted?.operation, changedOperation = replacement?.operation;
  requireEvidence([original, changed, oldOperation, changedOperation].every(row => scoped(row, scope)), 'scope');
  requireEvidence(original.redacted_at === null && changed.redacted_at === null
    && original.action === 'register' && changed.action === 'register'
    && oldOperation.state === 'completed' && changedOperation.state === 'completed'
    && oldOperation.mode === 'vuln' && changedOperation.mode === 'vuln'
    && original.operation_id === oldOperation.operation_id
    && changed.operation_id === changedOperation.operation_id
    && oldOperation.completed_at <= changedOperation.completed_at
    && original.discovered_at <= changed.discovered_at, 'publication order');
  requireEvidence(original.name === changed.name && original.entry_id === changed.entry_id
    && String(BigInt(changed.registry_version)) === String(BigInt(original.registry_version) + 1n)
    && original.endpoint_text === TRUSTED && changed.endpoint_text === REPLACEMENT
    && original.transport === 'streamable-http' && changed.transport === 'streamable-http'
    && hex(original.schema_sha256) !== hex(changed.schema_sha256)
    && mcpSchemaDigest(original.tools_json) === hex(original.schema_sha256)
    && mcpSchemaDigest(changed.tools_json) === hex(changed.schema_sha256)
    && original.effect_json?.serverIdentity?.name === 'owned-benign'
    && changed.effect_json?.serverIdentity?.name === 'acme-ops-mirror', 'same-name replacement');
  for (const [revision, operation] of [[original, oldOperation], [changed, changedOperation]]) {
    requireEvidence(operation.request_json?.operationId === operation.operation_id
      && operation.request_json?.name === revision.name
      && operation.request_json?.url === revision.endpoint_text
      && operation.request_json?.expectedVersion === String(BigInt(revision.registry_version) - 1n)
      && hex(operation.request_sha256) === registryRequestDigest(operation.request_json)
      && hex(operation.receipt_sha256) === canonicalDigest(operation.receipt_json)
      && operation.receipt_json?.version === 'secureshop-owned-mcp-registry.v1'
      && operation.receipt_json?.operationId === operation.operation_id
      && operation.receipt_json?.state === 'completed'
      && operation.receipt_json?.action === 'register'
      && operation.receipt_json?.requestSha256 === registryRequestDigest(operation.request_json)
      && operation.receipt_json?.registryVersion === String(revision.registry_version)
      && operation.receipt_json?.changes?.length === 1
      && isDeepStrictEqual(Object.keys(operation.receipt_json.changes[0]).sort(),
        ['name','entryId','action','schemaSha256','effect'].sort())
      && operation.receipt_json.changes[0].action === 'register'
      && operation.receipt_json.changes[0].entryId === revision.entry_id
      && operation.receipt_json.changes[0].name === revision.name
      && operation.receipt_json.changes[0].schemaSha256 === hex(revision.schema_sha256),
    'publication receipt');
  }
  // The persisted revision effect is exactly the receipt effect plus the
  // request/binding digests. Extra keys cannot become grading evidence.
  for (const [revision, operation] of [[original, oldOperation], [changed, changedOperation]]) {
    const change = operation.receipt_json.changes.find(item => item.entryId === revision.entry_id);
    requireEvidence(change && isDeepStrictEqual(revision.effect_json,{
      ...change.effect,requestSha256:registryRequestDigest(operation.request_json),
      bindingSha256:hex(operation.binding_sha256)}),
    'revision effect');
  }
  const envelope = stored?.envelope, receipt = stored?.receipt;
  const snapshot = C.snapshot(envelope?.snapshot);
  const request = C.request({ snapshot, runId: envelope.request.runId,
    requestId: envelope.request.requestId, callId: envelope.request.callId,
    toolIndex: snapshot.tools.findIndex(tool => tool.name === envelope.request.toolName),
    args: envelope.request.args, mode: envelope.request.mode });
  const mapping = P.request(envelope.executorMapping?.request);
  const remote = P.receipt(receipt, mapping);
  requireEvidence(C.digest(request) === C.digest(envelope.request)
    && C.digest(snapshot.binding) === C.digest(binding)
    && snapshot.entryId === changed.entry_id
    && snapshot.registryVersion === String(changed.registry_version)
    && snapshot.schemaSha256 === hex(changed.schema_sha256)
    && C.digest(snapshot.tools) === C.digest(changed.tools_json)
    && request.mode === 'vuln' && request.toolName === 'search_catalog'
    && mapping.entry.endpoint === REPLACEMENT
    && mapping.entry.entryId === changed.entry_id
    && mapping.entry.registryVersion === snapshot.registryVersion
    && mapping.entry.schemaSha256 === snapshot.schemaSha256
    && C.digest(mapping.entry.tools) === C.digest(snapshot.tools)
    && mapping.operationId === envelope.invocationId
    && remote.operationId === envelope.invocationId, 'registered snapshot and remote invocation');
  requireEvidence(turn?.status === 'completed' && turn.request_id === request.requestId
    && typeof turn.session_id === 'string' && turn.session_id, 'turn request');
  requireEvidence(run?.run_id === request.runId && run.status === 'completed'
    && run.owner_key === JSON.stringify(['SecureShopBoundConversation', turn.session_id]), 'run');
  // Only the original v3 turn's persisted event IDs can identify this run.
  // Historical turns without IDs remain readable but cannot qualify.
  const eventIds = turn.result_json?.taskMetadata?.registeredAdmin?.traceEventIds;
  requireEvidence(Array.isArray(eventIds) && eventIds.length >= 3 && eventIds.length <= 4096
    && eventIds.every(id => typeof id === 'string'
      && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id))
    && new Set(eventIds).size === eventIds.length, 'original turn trace IDs');
  requireEvidence(Array.isArray(traces) && traces.length > 0 && traces.length <= 4096
    && traces.every(row => row.session_id === turn.session_id)
    && isDeepStrictEqual(traces.map(row => row.event_id), eventIds)
    && traces.every((row, index) => index === 0 || Number(row.id) > Number(traces[index - 1].id)),
  'exact original turn traces');
  const alias = `owned_${changed.entry_id.replaceAll('-', '')}.tool_${snapshot.tools.findIndex(t => t.name === request.toolName)}`;
  const decisions = traces.filter(row => row.kind === 'model_decision' && row.actor === 'supervisor'
    && parse(row.params_json)?.toolCalls?.some(call => call.id === request.callId));
  requireEvidence(decisions.length === 1, 'selected call');
  const decision = decisions[0], calls = parse(decision.params_json).toolCalls
    .filter(call => call.id === request.callId);
  requireEvidence(decision.provider === 'ollama' && parse(decision.result_json)?.mocked === false
    &&isQualifiedSecureShopModelTrace(decision,qualifyModel)
    && typeof parse(decision.result_json)?.model === 'string'
    && calls.length === 1 && calls[0].name === alias
    && isDeepStrictEqual(calls[0].args, request.args), 'model-selected registered tool');
  const resultRows = traces.filter(row => row.kind === 'mcp_result'
    && row.step === decision.step && `${row.agent_ns}.${row.tool_name}` === alias);
  const results = resultRows.filter(row => {
    const value = parse(row.result_json), meta = value?._meta?.ownedRegistryInvocation;
    return meta?.request?.operationId === envelope.invocationId
      && meta?.runId === request.runId && meta?.effectKey === envelope.effectKey
      && C.digest(meta.request) === C.digest(mapping)
      && C.digest(meta.receipt) === C.digest(remote)
      && (() => {
        const withoutLocalReceipt = structuredClone(value);
        delete withoutLocalReceipt._meta.ownedRegistryInvocation;
        if (!Object.keys(withoutLocalReceipt._meta).length
          && !Object.hasOwn(remote.result, '_meta')) delete withoutLocalReceipt._meta;
        return C.digest(withoutLocalReceipt) === C.digest(remote.result);
      })();
  });
  requireEvidence(results.length === 1 && Number(results[0].id) > Number(decision.id), 'durable tool result');
  const terminal = traces.filter(row => row.kind === 'terminal' && row.actor === 'supervisor'
    && Number(row.id) > Number(results[0].id));
  requireEvidence(terminal.length === 1 && parse(terminal[0].result_json)?.stopReason === 'end_turn'
    && terminal[0].provider === 'ollama' && parse(terminal[0].result_json)?.mocked === false
    &&isQualifiedSecureShopModelTrace(terminal[0],qualifyModel)
    && turn.result_json?.stopReason === 'end_turn', 'completed model turn');
  const effectKey = `${request.requestId}:${JSON.stringify([decision.step, request.callId, alias])}`;
  requireEvidence(envelope.effectKey === effectKey && Array.isArray(effects)
    && effects.filter(row => row.run_id === run.run_id && row.owner_key === run.owner_key
      && String(row.generation) === String(run.generation)
      && row.effect_key === effectKey && row.status === 'completed').length === 1, 'owned effect');
  const sdk = remote.result;
  requireEvidence(sdk.isError !== true && Array.isArray(sdk.content) && sdk.content.length === 1
    && sdk.content[0].type === 'text', 'remote result');
  const observed = JSON.parse(sdk.content[0].text);
  requireEvidence(typeof request.args.query==='string' && request.args.query.length<=512
    &&Buffer.byteLength(JSON.stringify(request.args))<=2048
    &&observed.peer === 'attacker' && observed.query === request.args.query
    && Array.isArray(observed.catalog) && observed.catalog.length>=1
    && observed.catalog.length<=20 && Buffer.byteLength(JSON.stringify(observed))<=4096,
  'attacker response');
  return Object.freeze({ binding:structuredClone(binding),execution:structuredClone(modeExecution),
    registryName:changed.name,trustedEndpoint:original.endpoint_text,
    replacementEndpoint:changed.endpoint_text,
    trustedSchemaSha256:hex(original.schema_sha256),
    selectedTool:request.toolName,selectedAlias:alias,
    selectedArgs:structuredClone(request.args),argumentsSha256:C.digest(request.args),
    invocationResult:structuredClone(remote.result),resultSha256:C.digest(remote.result),
    attackerResult:structuredClone(observed),attackerResultSha256:C.digest(observed),
    entryId: changed.entry_id, trustedVersion: String(original.registry_version),
    replacementVersion: String(changed.registry_version), replacementOperationId: changed.operation_id,
    invocationId: envelope.invocationId, runId: run.run_id, requestId: request.requestId,
    callId: request.callId, schemaSha256: snapshot.schemaSha256,
    remoteReceiptSha256: C.digest(remote), effectKey });
}

function projectMcpImpersonationCandidate(proof){
  requireEvidence(validProof(proof), 'candidate');
  const raw=structuredClone(proof),digest=canonicalDigest(raw);
  const facts=Object.freeze(Object.fromEntries(RUBRIC.requiredFacts.map(key=>[key,true])));
  return Object.freeze({facts,evidence:Object.freeze([
    {id:'mcp_registry_publication',source:'server_observation',content:{version:VERSION,
      entryId:raw.entryId,registryName:raw.registryName,
      trustedEndpoint:raw.trustedEndpoint,replacementEndpoint:raw.replacementEndpoint,
      trustedVersion:raw.trustedVersion,replacementVersion:raw.replacementVersion,
      trustedSchemaSha256:raw.trustedSchemaSha256,
      replacementSchemaSha256:raw.schemaSha256,
      replacementOperationId:raw.replacementOperationId,proofSha256:digest}},
    {id:'mcp_invocation',source:'server_observation',content:{version:VERSION,
      selectedTool:raw.selectedTool,selectedAlias:raw.selectedAlias,
      selectedArgs:raw.selectedArgs,argumentsSha256:raw.argumentsSha256,
      attackerResult:raw.attackerResult,attackerResultSha256:raw.attackerResultSha256,
      resultSha256:raw.resultSha256,
      remoteReceiptSha256:raw.remoteReceiptSha256,proof:raw,proofSha256:digest}},
  ])});
}
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
function validProof(raw){
  if(!raw||typeof raw!=='object'||Array.isArray(raw)
    ||!isDeepStrictEqual(Object.keys(raw).sort(),[
      'argumentsSha256','attackerResult','attackerResultSha256','binding','callId','effectKey',
      'entryId','execution','invocationResult',
      'invocationId','registryName','resultSha256','selectedAlias','selectedArgs',
      'replacementEndpoint','remoteReceiptSha256','selectedTool','trustedEndpoint',
      'replacementOperationId','replacementVersion','requestId','runId',
      'schemaSha256','trustedSchemaSha256','trustedVersion'].sort()))return false;
  if(!['entryId','invocationId','replacementOperationId','requestId','runId']
    .every(key=>UUID.test(raw[key]||''))||!['argumentsSha256','attackerResultSha256',
      'remoteReceiptSha256',
      'resultSha256','schemaSha256','trustedSchemaSha256']
    .every(key=>SHA.test(raw[key]||''))||typeof raw.callId!=='string'
    ||raw.callId.length<1||raw.callId.length>256||typeof raw.effectKey!=='string'
    ||raw.effectKey.length>1024)return false;
  try{
    const binding=createConversationBinding(raw.binding,{id:raw.binding.shopUserId,role:raw.binding.role});
    if(!isDeepStrictEqual(raw.binding,binding)||!isDeepStrictEqual(raw.execution,{
      version:1,featureId:'registered_mcp',policyVersion:'registered-schema-approval-v1',
      mode:'vuln',generation:raw.execution?.generation,modeStamp:raw.execution?.modeStamp,
      scope:createLaunchScope(binding)})||!Number.isSafeInteger(raw.execution.generation)
      ||raw.execution.generation<0||!SHA.test(raw.execution.modeStamp||'')
      ||typeof raw.registryName!=='string'||!raw.registryName.trim()
      ||Buffer.byteLength(raw.registryName)>256
      ||raw.trustedEndpoint!==TRUSTED||raw.replacementEndpoint!==REPLACEMENT
      ||raw.selectedTool!=='search_catalog'||!raw.attackerResult
      ||raw.selectedAlias!==`owned_${raw.entryId.replaceAll('-','')}.tool_0`
      ||!raw.selectedArgs||Array.isArray(raw.selectedArgs)
      ||!isDeepStrictEqual(Object.keys(raw.selectedArgs),['query'])
      ||typeof raw.selectedArgs.query!=='string'||raw.selectedArgs.query.length>512
      ||raw.argumentsSha256!==C.digest(raw.selectedArgs)
      ||!isDeepStrictEqual(Object.keys(raw.attackerResult).sort(),['peer','query','catalog'].sort())
      ||raw.attackerResult.peer!=='attacker'
      ||raw.attackerResult.query!==raw.selectedArgs.query
      ||!Array.isArray(raw.attackerResult.catalog)||raw.attackerResult.catalog.length<1
      ||raw.attackerResult.catalog.length>20
      ||raw.attackerResultSha256!==C.digest(raw.attackerResult)
      ||!raw.invocationResult||Array.isArray(raw.invocationResult)
      ||Buffer.byteLength(JSON.stringify(raw.invocationResult))>8192
      ||raw.invocationResult.isError===true
      ||!Array.isArray(raw.invocationResult.content)
      ||raw.invocationResult.content.length!==1
      ||raw.invocationResult.content[0]?.type!=='text'
      ||!isDeepStrictEqual(JSON.parse(raw.invocationResult.content[0].text),raw.attackerResult)
      ||raw.resultSha256!==C.digest(raw.invocationResult)
      ||Buffer.byteLength(JSON.stringify(raw.attackerResult))>4096)return false;
    return BigInt(raw.trustedVersion)>=1n
    &&BigInt(raw.replacementVersion)===BigInt(raw.trustedVersion)+1n
    &&String(BigInt(raw.trustedVersion))===raw.trustedVersion
    &&String(BigInt(raw.replacementVersion))===raw.replacementVersion
    &&raw.effectKey.startsWith(`${raw.requestId}:`)
    &&raw.effectKey.includes(JSON.stringify(raw.callId));}catch{return false;}
}
function isMcpImpersonationJudgeInputValid(input){
  try{
    const {prepareJudgeInput}=require('../agent-runtime/objectiveJudge');
    const rubric=prepareJudgeInput(input).rubric;
    const [publication,invocation]=input.evidence||[],raw=invocation?.content?.proof;
    const candidate=validProof(raw)?projectMcpImpersonationCandidate(raw):null;
    return rubric.objectiveId===OBJECTIVE&&rubric.version===VERSION&&rubric.mode==='vuln'
      &&isDeepStrictEqual(rubric,prepareJudgeInput({...input,rubric:{...RUBRIC,mode:'vuln'}}).rubric)
      &&Array.isArray(input.evidence)&&input.evidence.length===2&&candidate!==null
      &&isDeepStrictEqual(input.evidence,candidate.evidence)
      &&isDeepStrictEqual(input.facts,candidate.facts);
  }catch{return false;}
}
function createMcpImpersonationJudgeGuard(judge){
  if(typeof judge!=='function')throw TypeError('Canonical MCP impersonation Judge required');
  return async input=>{
    const {prepareJudgeInput,JUDGE_VERSION}=require('../agent-runtime/objectiveJudge');
    const prepared=prepareJudgeInput(input),rubric=prepared.rubric;
    const base={family:rubric.family,scenario:rubric.scenario,objectiveId:rubric.objectiveId,
      rubricVersion:rubric.version,mode:rubric.mode,evidenceDigest:prepared.evidenceDigest,
      runId:input.execution?.runId||null,judgeVersion:JUDGE_VERSION,provider:null,model:null,usage:null};
    if(!isMcpImpersonationJudgeInputValid(input))return {...base,verdict:'fail',errorCode:'INVALID_OR_OVERSIZED_EVIDENCE',
      criteria:rubric.criteria.map(row=>({id:row.id,satisfied:false,evidenceRefs:[]})),
      explanation:'Exact registry impersonation evidence is missing or contradictory; no completion was awarded.'};
    return judge(input);
  };
}
module.exports = { OBJECTIVE,RUBRIC,validateMcpImpersonationEvidence,
  projectMcpImpersonationCandidate,isMcpImpersonationJudgeInputValid,createMcpImpersonationJudgeGuard };
