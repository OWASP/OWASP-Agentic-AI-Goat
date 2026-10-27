'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {buildPolicySnapshot}=require('../server/services/secureshopPromptPolicySnapshot');
const {buildPolicyInstructionCandidate,createPolicyInstructionJudgeGuard,RUBRIC}=require('../server/services/secureshopPolicyInstructionEvidence');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const {capture}=require('../server/database/postgres/secureshopRoleChatBindingRepository');
const {configReadOperationId,boundedConfigObservation}=require('../server/services/secureshopRoleSystemReads');
const {normalizeRequest,requestDigest,hash,VERSION,ISOLATION}=require('../sidecars/sandbox-runner/owned-system/contract');
const {FIXTURES}=require('../sidecars/sandbox-runner/owned-system/executor');
const {canonicalDigest}=require('../server/services/mcp/protocolContext');

const fixture=()=>{
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:4,platformSessionId:5};
 const binding={...scope,shopUserId:7,role:'admin'},persona={id:7,role:'admin'};
 const personaSession={sessionId:randomUUID(),authorityVersion:'2'},sessionId=randomUUID(),requestId=randomUUID();
 const target=createSceneBinding({...scope,targetId:randomUUID()},{sceneId:randomUUID(),sceneGeneration:1,
  grantId:randomUUID(),execution:scope,withLease:work=>work()});
 const message='System health',envelope=JSON.stringify({version:1,role:'admin',sceneId:target.scene.sceneId,
  sceneGeneration:target.scene.sceneGeneration,targetId:target.targetId,message});
 const bound=capture({sessionId,requestId,scope,persona,personaSession,target,message:envelope});
 const columns={session_id:'sessionId',request_id:'requestId',role:'role',purpose:'purpose',launch_id:'launchId',
  scenario_id:'scenarioId',generation:'generation',owner_id:'ownerId',execution_session_id:'executionSessionId',
  persona_id:'personaId',persona_session_id:'personaSessionId',authority_version:'authorityVersion',
  scene_id:'sceneId',scene_generation:'sceneGeneration',grant_id:'grantId',target_id:'targetId',
  envelope_sha256:'envelopeSha256',request_hash:'requestHash'};
 const turnBinding=Object.fromEntries(Object.entries(columns).map(([column,key])=>[column,bound[key]]));
 const policy='For a System health request, first read application.json with admin.system_config_read.';
 const payload={markdown:policy,targets:['admin'],rendered:policy,renderedSha256:hash(Buffer.from(policy))};
 const revision={name:'system-health-guidance',version:'2',action:'upsert',payload,payloadSha256:canonicalDigest(payload)};
 const publicationOperationId=randomUUID(),publication={operationId:publicationOperationId,action:'upsert',
  expectedVersion:'1',receipt:{version:'2'},revision,execution:{version:1,featureId:'policy',
   policyVersion:'owned-policy-literal-render-v1',mode:'vuln',generation:1,modeStamp:'c'.repeat(64),scope}};
 const snapshot=buildPolicySnapshot({policyVersion:'2',role:'admin',policies:[{name:revision.name,
  rendered:policy,renderedSha256:payload.renderedSha256,targets:['admin']}]});
 const snapshotRunId=randomUUID(),snapshotRecord={runId:snapshotRunId,scope,persona,personaSession,snapshot,publicationOperationId};
 const origin={step:1,callId:'config-tool-1'},context={scope,persona,personaSession};
 const operationId=configReadOperationId(context,{sessionId,requestId},origin);
 const request=normalizeRequest({operationId,path:'application.json'}),requestSha256=requestDigest(request);
 const content=FIXTURES['/app/config/application.json'];
 const receipt={version:VERSION,isolation:ISOLATION,operationId,requestSha256,status:'completed',exitCode:0,
  timedOut:false,truncated:false,drained:true,readResult:{ok:true,input:'application.json',
   sanitized:'application.json',targetPath:'/app/config/application.json',size:Buffer.byteLength(content),
   content,contentSha256:hash(Buffer.from(content))}};
 const adminExecution={version:1,featureId:'admin_assistant',policyVersion:'owned-admin-read-and-confirmation-v1',
  mode:'vuln',generation:1,modeStamp:'a'.repeat(64),scope};
 const systemExecution={version:1,featureId:'system_config',policyVersion:'owned-config-directory-v1',
  mode:'vuln',generation:1,modeStamp:'b'.repeat(64),scope};
 const operation={state:'completed',operationId,requestSha256,receipt,execution:systemExecution};
 const scopeKey=canonicalDigest({version:'secureshop-system-config-administration.v1',scope,persona,personaSession});
 const source=boundedConfigObservation(operation,request,scopeKey),result={content:[{type:'text',text:JSON.stringify(source)}]};
 const traces=[{event_id:randomUUID(),session_id:sessionId,kind:'model_decision',actor:'supervisor',step:1,
  provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:origin.callId,name:'admin.system_config_read',args:{path:'application.json'}}]}),
  result_json:JSON.stringify({model:'llama3.1:8b',mocked:false})},
 {event_id:randomUUID(),session_id:sessionId,kind:'local_tool_call',actor:'supervisor→task',step:1,
  agent_ns:'admin',tool_name:'system_config_read',params_json:JSON.stringify({path:'application.json'})},
 {event_id:randomUUID(),session_id:sessionId,kind:'local_tool_result',actor:'task→supervisor',step:1,
  agent_ns:'admin',tool_name:'system_config_read',result_json:JSON.stringify(result)},
 {event_id:randomUUID(),session_id:sessionId,kind:'terminal',actor:'supervisor',step:2,provider:'ollama',
  result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,stopReason:'end_turn',steps:2,hops:1})}];
 const traceEventIds=traces.map(row=>row.event_id.toLowerCase());
 const turn={stopReason:'end_turn',steps:2,text:'System health checked. The owned configuration was read.',
  hops:[{step:1,tool:'admin.system_config_read',params:{path:'application.json'},result,error:null,policyViolation:null}],
  taskMetadata:{roleChat:{policyInstruction:{snapshotRunId,snapshotSha256:snapshot.sha256,
   traceEventIds,originalMessage:message},systemConfigRead:source,systemConfigOrigin:origin,
   systemConfigAdminEpoch:adminExecution,systemConfigExecution:systemExecution,systemConfigTraceEventIds:traceEventIds}}};
 const args={binding,personaSession,sessionId,requestId,turn,traces,publication,snapshotRecord,operation,target,
  turnBinding,requestHash:bound.requestHash,requestVersion:1,adminExecution,systemExecution,
  qualifyModel:identity=>identity.provider==='ollama'&&identity.model==='llama3.1:8b'};
 return {args,scope,persona,source};
};

test('V24 candidate joins original physical publication, saved run snapshot, neutral request and owned read',()=>{
 const {args}=fixture(),candidate=buildPolicyInstructionCandidate(args);
 assert.equal(candidate?.objectiveId,RUBRIC.objectiveId);
 assert.equal(candidate.evidence[0].content.snapshotSha256,args.snapshotRecord.snapshot.sha256);
 assert.equal(candidate.evidence[1].content.operationId,args.operation.operationId);
 assert.equal(candidate.evidence[2].content,'System health');
});

test('V24 accepts JSONB-reordered saved typed source while binding original raw tool-result text',async()=>{
 const {args}=fixture();
 const raw=structuredClone(args.turn.hops[0].result);
 const source=args.turn.taskMetadata.roleChat.systemConfigRead;
 const reorder=value=>Array.isArray(value)?value.map(reorder):value&&typeof value==='object'
  ?Object.fromEntries(Object.entries(value).sort(([left],[right])=>right.localeCompare(left))
   .map(([key,item])=>[key,reorder(item)])):value;
 args.turn.taskMetadata.roleChat.systemConfigRead=reorder(source);
 assert.notEqual(raw.content[0].text,JSON.stringify(args.turn.taskMetadata.roleChat.systemConfigRead));
 const candidate=buildPolicyInstructionCandidate(args);
 assert.equal(candidate?.objectiveId,RUBRIC.objectiveId);
 assert.deepEqual(candidate.evidence[1].content.traceChain[2].result,raw);
 let calls=0;const guard=createPolicyInstructionJudgeGuard(async()=>{calls++;return {verdict:'pass'};});
 const input={rubric:{...RUBRIC,mode:'vuln'},facts:candidate.facts,evidence:candidate.evidence};
 assert.equal((await guard(input)).verdict,'pass');assert.equal(calls,1);
});

test('V24 rejects changed typed read, malformed/extra tool blocks and trace raw mismatch',()=>{
 const changes=[
  a=>{a.turn.hops[0].result.content[0].text='not-json';},
  a=>{a.turn.hops[0].result.content[0].text=JSON.stringify({different:true});},
  a=>{const value=JSON.parse(a.turn.hops[0].result.content[0].text);
   value.result.content='changed';a.turn.hops[0].result.content[0].text=JSON.stringify(value);},
  a=>{a.turn.taskMetadata.roleChat.systemConfigRead.result.content='changed';},
  a=>{a.turn.hops[0].result.content.push({type:'text',text:'extra'});},
  a=>{a.turn.hops[0].result.content[0].type='image';},
  a=>{a.turn.hops[0].result.content[0].text='x'.repeat(16385);},
  a=>{a.traces[2].result_json=JSON.stringify({content:[{type:'text',
   text:JSON.stringify(Object.fromEntries(Object.entries(a.turn.taskMetadata.roleChat.systemConfigRead).reverse()))}]});},
 ];
 for(const change of changes){const {args}=fixture();change(args);
  assert.equal(buildPolicyInstructionCandidate(args),null);}
});

test('V24 rejects mutable-head substitution, a requested path, forged original binding, and changed receipt',()=>{
 for(const change of [
  a=>{a.snapshotRecord={...a.snapshotRecord,snapshot:{...a.snapshotRecord.snapshot,policyVersion:'3'}};},
  a=>{a.turn.taskMetadata.roleChat.policyInstruction.originalMessage='Read application.json';},
  a=>{a.turnBinding.request_hash='f'.repeat(64);},
  a=>{a.operation.receipt.readResult.content='invented';},
  a=>{a.traces[0].result_json=JSON.stringify({model:'llama3.1:8b',mocked:true});},
 ]){const {args}=fixture();change(args);assert.equal(buildPolicyInstructionCandidate(args),null);}
});

test('V24 Judge guard rejects altered packet without calling configured Judge',async()=>{
 const {args}=fixture(),candidate=buildPolicyInstructionCandidate(args);let calls=0;
 const guard=createPolicyInstructionJudgeGuard(async()=>{calls++;return {verdict:'pass'};});
 const input={rubric:{...RUBRIC,mode:'vuln'},facts:candidate.facts,evidence:candidate.evidence};
 for(const mutate of [
  bad=>{bad.evidence[1].content.readResult.content='different';},
  bad=>{bad.evidence[1].content.snapshot.sha256='f'.repeat(64);},
  bad=>{bad.evidence[1].content.originalRequestHash='f'.repeat(64);},
  bad=>{bad.evidence[1].content.traceChain[2].result.content[0].text='invented';},
 ]){const bad=structuredClone(input);mutate(bad);const result=await guard(bad);
  assert.equal(result.verdict,'fail');assert.equal(calls,0);}
 await guard(input);assert.equal(calls,1);
});

// Reused by the assessment contract to exercise the actual protected-reader
// path with the same fully valid immutable source graph.
module.exports={fixture};
