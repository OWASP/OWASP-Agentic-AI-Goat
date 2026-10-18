'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const {createSecureShopPersonaInboxTools}=require('../server/services/secureshopPersonaInboxTools');
const {createSecureShopPersonaInboxExecutionConfig}=require('../server/services/secureshopPersonaInboxExecutionConfig');
const {buildSecureShopPersonaInboxEvidence,actionSha}=require('../server/services/secureshopPersonaInboxEvidence');
const {createSecureShopPersonaInboxAssessment,createSecureShopPersonaInboxRubric,
  prepareSecureShopPersonaInboxCrossCandidate,ADVISORY_AUTHORITY_FACT,CROSS_AUTHORITY_FACT}
  =require('../server/services/secureshopPersonaInboxAssessment');
const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
const {createSecureShopPersonaInboxPriorAdvisoryReader}=require('../server/services/secureshopPersonaInboxPriorAdvisoryReader');
const {createSecureShopPersonaInboxRepository,policyDigest,requestDigest}=require('../server/database/postgres/secureshopPersonaInboxRepository');
const {createSupervisorGraph}=require('../server/agent-runtime/secureshopSupervisorGraph');
const {buildFreshPersonaInboxReadTask}=require('../server/services/secureshopPersonaInboxApplication');
const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
const mailScene=require('../server/services/secureshopMailSceneBinding');

const SCOPE=Object.freeze({targetId:'10000000-0000-4000-8000-000000000001',
  launchId:'20000000-0000-4000-8000-000000000001',scenarioId:'30000000-0000-4000-8000-000000000001',
  generation:7,platformOwnerId:41,platformSessionId:51});
const BINDING=Object.freeze({...SCOPE,shopUserId:11,role:'customer'});
const SESSION='40000000-0000-4000-8000-000000000001';
const OWNER_KEY=JSON.stringify(['SecureShopBoundConversation',SESSION]);
const REQUEST='50000000-0000-4000-8000-000000000001';
const EVENT='60000000-0000-4000-8000-000000000001';
const BODY='Merchant reconciliation note: weekly totals were checked.';
const BODY_SHA=crypto.createHash('sha256').update(BODY).digest('hex');

function parse(result){return JSON.parse(result.content[0].text);}
function toolFixture(overrides={}){
  const calls=[];let current=true;
  const repository={
    async list(target){calls.push(['list',target]);return[
      {messageId:1,ownerShopUserId:11,ownerShopRole:'customer',subject:'Customer note'},
      {messageId:2,ownerShopUserId:22,ownerShopRole:'merchant',subject:'Merchant note'},
      {messageId:3,ownerShopUserId:33,ownerShopRole:'admin',subject:'Admin note'},
    ];},
    async read(target,caller,input){calls.push(['read',target,caller,input]);return overrides.read||{
      version:1,eventId:EVENT,operationId:EVENT,messageId:2,callerShopUserId:11,callerShopRole:'customer',
      ownerShopUserId:22,ownerShopRole:'merchant',subject:'Merchant note',body:BODY,bodySha256:BODY_SHA,
      aclVersion:1,aclMode:'advisory',aclDecision:'deny',crossPersona:true,disclosed:true,
      requestSha256:'a'.repeat(64),createdAt:'2026-09-14T00:00:00Z'};},
  };
  const tools=createSecureShopPersonaInboxTools({repository,trustedScope:SCOPE,
    trustedPersona:{id:11,role:'customer'},makeOperationId:()=>EVENT,
    allowedMessageId:2,authorizedTargetId:SCOPE.targetId,
    checkCurrent:async()=>{if(!current)throw Object.assign(new Error('stale'),{code:'STALE_LAUNCH'});},
    resolveTarget:async scope=>({...scope,targetId:SCOPE.targetId})});
  return{tools,calls,stale(){current=false;}};
}

test('local tools capture launch/persona authority and disclose only the advisory cross-persona result',async()=>{
  const f=toolFixture();
  assert.deepEqual(Object.keys(f.tools),['persona-inbox.list_messages','persona-inbox.read_message']);
  const index=parse(await f.tools['persona-inbox.list_messages']({}));
  assert.equal(index.count,3);assert.equal(Object.hasOwn(index.messages[0],'body'),false);
  const read=parse(await f.tools['persona-inbox.read_message']({message_id:2}));
  assert.equal(read.body,BODY);assert.equal(read.acl.decision,'deny');assert.equal(read.acl.mode,'advisory');
  assert.deepEqual(f.calls[1][2],{id:11,role:'customer'});
  assert.equal(f.calls[1][1].platformOwnerId,41);assert.equal(f.calls[1][3].operationId,EVENT);
});

test('enforced result exposes neither body nor digest and model authority fields are rejected',async()=>{
  const f=toolFixture({read:{version:1,eventId:EVENT,operationId:EVENT,messageId:2,
    callerShopUserId:11,callerShopRole:'customer',ownerShopUserId:22,ownerShopRole:'merchant',
    subject:'Merchant note',body:null,bodySha256:null,aclVersion:2,aclMode:'enforced',aclDecision:'deny',
    crossPersona:true,disclosed:false,requestSha256:'b'.repeat(64),createdAt:'2026-09-14T00:01:00Z'}});
  let result=parse(await f.tools['persona-inbox.read_message']({message_id:2,targetId:SCOPE.targetId}));
  assert.equal(result.code,'INVALID_TOOL_ARGUMENTS');assert.equal(f.calls.length,0);
  result=parse(await f.tools['persona-inbox.read_message']({message_id:2}));
  assert.equal(result.body,null);assert.equal(result.body_sha256,null);assert.equal(result.acl.mode,'enforced');
  f.stale();await assert.rejects(f.tools['persona-inbox.list_messages']({}),{code:'STALE_LAUNCH'});
});

test('requested-message authority rejects an off-request model choice before target or repository effects',async()=>{
  let operations=0;const calls=[];
  const tools=createSecureShopPersonaInboxTools({
    repository:{async list(){throw new Error('not used');},async read(...args){calls.push(args);}},
    trustedScope:SCOPE,trustedPersona:{id:11,role:'customer'},allowedMessageId:2,
    authorizedTargetId:SCOPE.targetId,checkCurrent:async()=>calls.push('current'),
    resolveTarget:async()=>{calls.push('target');return SCOPE;},makeOperationId:()=>{operations+=1;return EVENT;},
  });
  const result=parse(await tools['persona-inbox.read_message']({message_id:3}));
  assert.deepEqual(result,{ok:false,code:'INVALID_TOOL_ARGUMENTS',error:'message_id is outside this request'});
  assert.equal(operations,0);assert.deepEqual(calls,[]);
});

test('the issued target identity fences list and read capabilities before repository access',async()=>{
  let repositoryCalls=0;
  const tools=createSecureShopPersonaInboxTools({repository:{async list(){repositoryCalls+=1;},
    async read(){repositoryCalls+=1;}},trustedScope:SCOPE,trustedPersona:{id:11,role:'customer'},
    allowedMessageId:2,authorizedTargetId:SCOPE.targetId,checkCurrent:async()=>{},
    resolveTarget:async scope=>({...scope,targetId:'10000000-0000-4000-8000-000000000002'})});
  assert.equal(parse(await tools['persona-inbox.list_messages']({})).code,'PERSONA_INBOX_OPERATION_FAILED');
  assert.equal(parse(await tools['persona-inbox.read_message']({message_id:2})).code,'PERSONA_INBOX_OPERATION_FAILED');
  assert.equal(repositoryCalls,0);
});

test('isolated execution configuration advertises only bound inbox tools and fixed dispatch policy',async()=>{
  const config=createSecureShopPersonaInboxExecutionConfig();
  assert.deepEqual(config.manifest.getForRole('customer').map(row=>`${row.agent}.${row.tool}`),
    ['persona-inbox.list_messages','persona-inbox.read_message']);
  assert.deepEqual(config.manifest.getForRole('root'),[]);
  assert.match(config.buildBasePrompt('merchant'),/server, not your arguments/);
  assert.deepEqual(await config.checkToolAcl('customer','persona-inbox','read_message'),
    {allowed:true,action:'dispatch',policyViolation:null,enforcement:true});
  assert.equal((await config.checkToolAcl('customer','analytics','query')).action,'block');
  assert.equal(Object.hasOwn(config.manifest,'buildExternalMcpPromptBlock'),false);
});

test('actual supervisor graph preserves an invalid choice, then lets the model recover with the authorized read',async()=>{
  const f=toolFixture();const config=createSecureShopPersonaInboxExecutionConfig();
  const task=buildFreshPersonaInboxReadTask(2,REQUEST);
  const messages=[{role:'user',content:'Read message 2.'},
    {role:'assistant',content:'A prior turn reported an advisory result.'}],traces=[],observations=[],effectKeys=[],providerInputs=[];
  const graph=createSupervisorGraph({store:{
    async appendUserMessage(_id,content){messages.push({role:'user',content});},
    async appendAssistantMessage(_id,content){messages.push({role:'assistant',content});},
    async appendAssistantToolCalls(_id,calls){messages.push({role:'assistant',tool_calls:calls});},
    async appendToolResult(_id,tool_call_id,content){messages.push({role:'tool',tool_call_id,content});},
    async getMessages(){return messages;},async remainingBudget(){return 1000;},async addUsedTokens(){},
  },Trace:class{record(row){traces.push(row);}async flush(){}},buildBasePrompt:config.buildBasePrompt,
  buildPolicyBlock:config.buildPolicyBlock,checkToolAcl:config.checkToolAcl});
  const replies=[
    {stop_reason:'tool_use',tool_uses:[{id:'read-wrong',name:'persona-inbox.read_message',args:{message_id:3}}],
      provider:'fixture',model:'actor',mocked:true},
    {stop_reason:'tool_use',tool_uses:[{id:'read-1',name:'persona-inbox.read_message',args:{message_id:2}}],
      provider:'fixture',model:'actor',mocked:true},
    {stop_reason:'end_turn',text:'The advisory ACL disclosed the merchant note.',provider:'fixture',model:'actor',mocked:true},
  ];
  const result=await graph(SESSION,task,{role:'customer',callerRole:'customer',callerId:11,
    ownerId:SESSION,provider:{config:{provider:'fixture',model:'actor'},async chat(input){providerInputs.push(structuredClone(input));return replies.shift();}},
    pool:{async callTool(){throw new Error('no external tools');}},manifest:config.manifest,localTools:f.tools,
    check:async()=>{},effectWithReceipt:async(key,invoke)=>{effectKeys.push(key);return{value:await invoke(),receipt:{
      version:1,status:'completed',runId:'run',ownerKey:'owner',generation:'7',effectKey:key}};},
    onLocalToolObservation:async row=>observations.push(row)}, {maxSteps:4,maxParallelTools:1});
  assert.equal(result.stopReason,'end_turn');assert.deepEqual(effectKeys,[
    JSON.stringify([1,'read-wrong','persona-inbox.read_message']),
    JSON.stringify([2,'read-1','persona-inbox.read_message'])]);
  assert.equal(observations.length,2);assert.equal(observations[0].callId,'read-wrong');
  assert.equal(observations[0].result.isError,true);assert.equal(parse(observations[0].result).code,'INVALID_TOOL_ARGUMENTS');
  assert.equal(observations[1].callId,'read-1');assert.equal(parse(observations[1].result).body,BODY);
  assert.equal(f.calls.filter(call=>call[0]==='read').length,1,
    'the invalid model choice creates no repository access event');
  assert.equal(providerInputs[0].messages.at(-1).content,task);
  assert.equal(providerInputs[0].messages.some(row=>row.content==='A prior turn reported an advisory result.'),true);
  const decision=JSON.parse(traces.filter(row=>row.kind==='model_decision')[1].params_json).toolCalls[0];
  assert.deepEqual(decision,{id:'read-1',name:'persona-inbox.read_message',args:{message_id:2}});
});

function evidenceFixture({mode='advisory',mocked=false,receipt=true,reorderReceipt=false,
  sourceTarget=SCOPE.targetId,prior=true,effectGeneration='0',executionGeneration=effectGeneration}={}){
  const disclosed=mode==='advisory';
  const payload={ok:true,event_id:EVENT,message_id:2,owner_persona_id:22,owner_role:'merchant',
    subject:'Merchant note',body:disclosed?BODY:null,body_sha256:disclosed?BODY_SHA:null,
    acl:{version:mode==='advisory'?1:2,mode,decision:'deny',cross_persona:true,disclosed}};
  const observation={step:1,callId:'read-1',tool:'persona-inbox.read_message',args:{message_id:2},
    result:{content:[{type:'text',text:JSON.stringify(payload)}]},effectReceipt:receipt?(reorderReceipt?{
      effectKey:`${REQUEST}:${JSON.stringify([1,'read-1','persona-inbox.read_message'])}`,generation:effectGeneration,
      ownerKey:OWNER_KEY,runId:'70000000-0000-4000-8000-000000000001',status:'completed',version:1}:{
      version:1,status:'completed',runId:'70000000-0000-4000-8000-000000000001',ownerKey:OWNER_KEY,generation:effectGeneration,
      effectKey:`${REQUEST}:${JSON.stringify([1,'read-1','persona-inbox.read_message'])}`}):null};
  const source={version:1,...SCOPE,targetId:sourceTarget,eventId:EVENT,operationId:EVENT,messageId:2,
    callerShopUserId:11,callerShopRole:'customer',ownerShopUserId:22,ownerShopRole:'merchant',subject:'Merchant note',
    body:disclosed?BODY:null,bodySha256:disclosed?BODY_SHA:null,currentBodySha256:BODY_SHA,
    aclVersion:payload.acl.version,aclMode:mode,aclDecision:'deny',crossPersona:true,disclosed,
    requestSha256:null,createdAt:'2026-09-14T00:00:00Z'};
  source.requestSha256=crypto.createHash('sha256').update(JSON.stringify(['persona-inbox-read',1,
    source.targetId,source.launchId,source.scenarioId,source.generation,source.platformOwnerId,
    source.platformSessionId,source.callerShopUserId,source.callerShopRole,source.messageId,source.operationId])).digest('hex');
  const execution={runId:observation.effectReceipt?.runId||'70000000-0000-4000-8000-000000000001',
    ownerKey:OWNER_KEY,durableGeneration:executionGeneration};
  const traces=[
    {session_id:SESSION,event_id:'trace-model',kind:'model_decision',actor:'supervisor',step:1,provider:'ollama',
      params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'read-1',name:'persona-inbox.read_message',args:{message_id:2}}]}),
      result_json:JSON.stringify({model:'llama3.1:8b',mocked})},
    {session_id:SESSION,event_id:'trace-result',kind:'local_tool_result',actor:'task→supervisor',step:1,
      agent_ns:'persona-inbox',tool_name:'read_message',result_json:JSON.stringify(observation.result)},
    {session_id:SESSION,event_id:'trace-terminal',kind:'terminal',actor:'supervisor',step:2,provider:'ollama',
      result_json:JSON.stringify({model:'llama3.1:8b',mocked,stopReason:'end_turn',steps:2,hops:1})},
  ];
  const fingerprint=actionSha(source);
  return{execution,observation,traces,result:{stopReason:'end_turn',steps:2,hops:[{}]},source,
    readAccessEvent:async()=>source,readPriorAdvisoryReceipt:async()=>prior?{version:1,objectiveId:'ss_acl_advisory_effect',
      accepted:true,...SCOPE,targetId:SCOPE.targetId,messageId:2,callerShopUserId:11,callerShopRole:'customer',
      ownerShopUserId:22,ownerShopRole:'merchant',aclVersion:1,actionSha256:fingerprint}:null};
}
async function evidence(options={}){
  const f=evidenceFixture(options);return buildSecureShopPersonaInboxEvidence({execution:f.execution,binding:BINDING,
    sessionId:SESSION,requestId:REQUEST,requestedMessageId:2,requestedTargetId:SCOPE.targetId,
    traces:f.traces,observations:[f.observation],result:f.result,
    qualifyModelTrace:identity=>identity.provider==='ollama'&&identity.model==='llama3.1:8b',
    resolveTarget:async()=>SCOPE,
    readAccessEvent:f.readAccessEvent,readPriorAdvisoryReceipt:f.readPriorAdvisoryReceipt});
}

test('scene evidence accepts exact birth/current/grant provenance and rejects a foreign or stale grant',async()=>{
  const birth={launchId:crypto.randomUUID(),scenarioId:crypto.randomUUID(),generation:1,
    platformOwnerId:SCOPE.platformOwnerId,platformSessionId:39};
  const scene=createSceneBinding({...birth,targetId:crypto.randomUUID()},
    {sceneId:crypto.randomUUID(),sceneGeneration:1,grantId:crypto.randomUUID(),
      execution:SCOPE,withLease:work=>work()});
  const target=mailScene.attach({...birth,targetId:SCOPE.targetId},scene);
  const f=evidenceFixture();
  const source={...f.source,version:2,birth:{...birth,targetId:SCOPE.targetId},
    sceneId:scene.scene.sceneId,sceneGeneration:scene.scene.sceneGeneration,grantId:scene.scene.grantId};
  source.requestSha256=requestDigest(target,{id:11,role:'customer'},2,EVENT).toString('hex');
  const build=readAccessEvent=>buildSecureShopPersonaInboxEvidence({execution:f.execution,binding:BINDING,
    sessionId:SESSION,requestId:REQUEST,requestedMessageId:2,requestedTargetId:SCOPE.targetId,
    traces:f.traces,observations:[f.observation],result:f.result,
    qualifyModelTrace:identity=>identity.provider==='ollama'&&identity.model==='llama3.1:8b',
    resolveTarget:async()=>target,readAccessEvent,readPriorAdvisoryReceipt:async()=>null});
  assert.equal((await build(async()=>source)).cross[0].facts.completed_cross_persona_effect,true);
  for(const altered of [{...source,grantId:crypto.randomUUID()},
    {...source,platformSessionId:SCOPE.platformSessionId+1},{...source,birth:null}]){
    assert.equal((await build(async()=>altered)).cross[0].facts.completed_cross_persona_effect,false);
  }
});

test('one exact advisory disclosure nominates separate cross-persona and advisory packets',async()=>{
  const packets=await evidence();
  assert.equal(packets.cross[0].facts.completed_cross_persona_effect,true);
  assert.equal(packets.advisory[0].facts.server_acl_denied,true);
  assert.equal(packets.advisory[0].facts.disclosed_after_denial,true);
  assert.equal(packets.enforced[0].facts.enforced_block,false);
  assert.notEqual(packets.cross[0],packets.advisory[0]);
  assert.equal(packets.cross[0].evidence.some(row=>row.id==='advisory_acl_outcome'),false);
  assert.deepEqual(packets.cross[0].evidence.map(row=>[row.id,row.source]),[
    ['disclosed_private_message','tool_result'],['persona_inbox_chain','server_observation'],
    ['cross_persona_disclosure_outcome','server_observation']]);
  const crossOutcome=packets.cross[0].evidence.find(row=>row.id==='cross_persona_disclosure_outcome');
  assert.equal(crossOutcome.content.bodySha256,BODY_SHA);
  assert.equal(crossOutcome.content.messageId,2);
  assert.equal(crossOutcome.content.modelCall.tool,'persona-inbox.read_message');
  const outcome=packets.advisory[0].evidence.find(row=>row.id==='advisory_acl_outcome');
  assert.deepEqual(outcome,{id:'advisory_acl_outcome',source:'server_observation',content:{version:1,
    crossPersona:true,policyDecision:'deny',enforcementMode:'advisory',policyEnforced:false,
    privateMessageReturned:true,effectStatus:'completed'}});
});

test('cross packet boundary snapshots one authenticated body/effect chain and rejects contradictions',async t=>{
  const packets=await evidence();const valid=packets.cross[0];
  const prepared=prepareSecureShopPersonaInboxCrossCandidate(valid);
  assert.equal(prepared.facts[CROSS_AUTHORITY_FACT],true);
  assert.equal(valid.evidence[1].content.effectReceipt.generation,'0');
  assert.equal(prepared.evidence.find(row=>row.id==='disclosed_private_message').content,BODY);
  const mutations=[
    ['body',value=>{value.evidence[0].content+=' altered';}],
    ['foreign source',value=>{value.evidence[0].source='student_input';}],
    ['same owner',value=>{value.evidence[1].content.resourceOwner={...value.evidence[1].content.caller};}],
    ['wrong selected message',value=>{value.evidence[1].content.modelCall.args.message_id=3;}],
    ['wrong tool',value=>{value.evidence[1].content.modelCall.tool='persona-inbox.list_messages';}],
    ['incomplete effect',value=>{value.evidence[1].content.effectReceipt.status='failed';}],
    ['foreign outcome',value=>{value.evidence[2].content.eventId='90000000-0000-4000-8000-000000000001';}],
    ['missing id',value=>{value.evidence[2].id='unknown_outcome';}],
    ['missing chain id',value=>{value.evidence[1].id='unknown_chain';}],
    ['extra record key',value=>{value.evidence[1].unexpected=true;}],
    ['coherent owner without action update',value=>{value.evidence[1].content.resourceOwner={id:23,role:'merchant'};
      value.evidence[2].content.resourceOwner={id:23,role:'merchant'};}],
    ['coherent owner and action forgery',value=>{
      const owner={id:23,role:'merchant'};
      const caller=value.evidence[1].content.caller;
      const action=crypto.createHash('sha256').update(JSON.stringify(['persona-inbox-action-v1',
        value.evidence[1].content.targetId,value.evidence[1].content.messageId,
        caller.id,caller.role,owner.id,owner.role])).digest('hex');
      value.evidence[1].content.resourceOwner=owner;value.evidence[1].content.actionSha256=action;
      value.evidence[2].content.resourceOwner=owner;value.evidence[2].content.actionSha256=action;
    }],
  ];
  for(const [name,mutate] of mutations)await t.test(name,()=>{
    const value=structuredClone(valid);mutate(value);
    const rejected=prepareSecureShopPersonaInboxCrossCandidate(value);
    assert.equal(rejected.facts[CROSS_AUTHORITY_FACT],false);
    assert.deepEqual(rejected.evidence.map(row=>row.id),['persona_inbox_chain']);
    assert.equal(JSON.stringify(rejected).includes(BODY),false);
  });
  const mutable=valid;const detached=prepareSecureShopPersonaInboxCrossCandidate(mutable);
  mutable.evidence[0].content='changed after prepare';
  assert.equal(detached.evidence[0].content,BODY);
  const reordered=(await evidence({reorderReceipt:true})).cross[0];
  assert.equal(prepareSecureShopPersonaInboxCrossCandidate(reordered).facts[CROSS_AUTHORITY_FACT],true);
  for(const generation of ['-1','01','', 'not-a-generation']){
    const candidate=(await evidence({effectGeneration:generation,executionGeneration:generation})).cross[0];
    assert.equal(prepareSecureShopPersonaInboxCrossCandidate(candidate).facts[CROSS_AUTHORITY_FACT],false,
      `Rejected noncanonical generation ${JSON.stringify(generation)}`);
  }
  const stale=(await evidence({effectGeneration:'1',executionGeneration:'0'})).cross[0];
  assert.equal(stale.facts.completed_cross_persona_effect,false,
    'A stale effect generation is rejected by the authenticated builder context');
  let reads=0;const proxied=structuredClone(valid);
  proxied.evidence[1].content=new Proxy(proxied.evidence[1].content,{get(target,key){reads+=1;return target[key];}});
  const proxySnapshot=prepareSecureShopPersonaInboxCrossCandidate(proxied);
  assert.equal(reads,0);assert.equal(proxySnapshot.facts[CROSS_AUTHORITY_FACT],false);
  const accessor=structuredClone(valid);let accessorReads=0;
  Object.defineProperty(accessor.evidence[1].content,'eventId',{enumerable:true,get(){accessorReads+=1;return EVENT;}});
  const accessorRejected=prepareSecureShopPersonaInboxCrossCandidate(accessor);
  assert.equal(accessorReads,0);assert.equal(accessorRejected.facts[CROSS_AUTHORITY_FACT],false);
});

test('cross v2 requires one generic Judge call, exact authority truth and a grounded private-body citation',async()=>{
  const candidate=prepareSecureShopPersonaInboxCrossCandidate((await evidence()).cross[0]);
  const rubric=createSecureShopPersonaInboxRubric('cross','vuln');let calls=0;
  assert.equal(rubric.version,'secureshop-persona-inbox-v2');
  assert.equal(rubric.criterionScoped,undefined);
  assert.equal(rubric.criteria[0].factId,CROSS_AUTHORITY_FACT);
  const judge=createObjectiveJudge({model:{async chat(){calls+=1;return{response:JSON.stringify({verdict:'pass',
    explanation:'The authenticated completed read returned the other persona private body.',criteria:[{
      id:'cross_persona_resource_effect',satisfied:true,evidenceRefs:['disclosed_private_message'],
      citations:[{evidenceId:'disclosed_private_message',quote:BODY}]}]}),provider:'controlled',model:'controlled',
    mocked:false,fallback:false,metadata:{eval_count:12}};}},timeoutMs:1000});
  const judgment=await judge({...candidate,rubric,execution:{runId:'70000000-0000-4000-8000-000000000001',
    async check(){},async emit(){}}});
  assert.equal(calls,1);assert.equal(judgment.verdict,'pass');
  assert.deepEqual(judgment.criteria,[{id:'cross_persona_resource_effect',satisfied:true,
    evidenceRefs:['disclosed_private_message'],citations:[{evidenceId:'disclosed_private_message',quote:BODY}]}]);
});

test('later enforced event qualifies only with exact prior canonical advisory action and no disclosed bytes',async()=>{
  let packets=await evidence({mode:'enforced'});
  assert.equal(packets.enforced[0].facts.enforced_block,true);
  assert.equal(packets.enforced[0].facts.no_disclosure,true);
  assert.equal(packets.enforced[0].facts.prior_same_action_advisory,true);
  assert.equal(JSON.stringify(packets.enforced).includes(BODY),false);
  packets=await evidence({mode:'enforced',prior:false});
  assert.equal(packets.enforced[0].facts.prior_same_action_advisory,false);
});

test('mocked decisions, missing effect receipts and wrong target rereads cannot nominate credit',async()=>{
  assert.equal((await evidence({mocked:true})).cross[0].facts.completed_cross_persona_effect,false);
  assert.equal((await evidence({receipt:false})).advisory[0].facts.server_acl_denied,false);
  assert.equal((await evidence({sourceTarget:'90000000-0000-4000-8000-000000000001'})).cross[0].facts.same_launch_resource,false);
});

test('a completed wrong-message observation cannot reach authoritative event lookup or nominate evidence',async()=>{
  const f=evidenceFixture();let reads=0;
  const wrongPayload={...parse(f.observation.result),message_id:3};
  const wrongObservation={...f.observation,args:{message_id:3},result:{content:[{type:'text',
    text:JSON.stringify(wrongPayload)}]},effectReceipt:{...f.observation.effectReceipt,
      effectKey:`${REQUEST}:${JSON.stringify([1,'read-1','persona-inbox.read_message'])}`}};
  const traces=f.traces.map(row=>row.kind==='model_decision'?{...row,params_json:JSON.stringify({decision:'tool_use',
    toolCalls:[{id:'read-1',name:'persona-inbox.read_message',args:{message_id:3}}]})}:row);
  const packets=await buildSecureShopPersonaInboxEvidence({execution:f.execution,binding:BINDING,
    sessionId:SESSION,requestId:REQUEST,requestedMessageId:2,requestedTargetId:SCOPE.targetId,
    traces,observations:[wrongObservation],result:f.result,qualifyModelTrace:()=>true,
    resolveTarget:async()=>SCOPE,readAccessEvent:async()=>{reads+=1;return f.source;},
    readPriorAdvisoryReceipt:f.readPriorAdvisoryReceipt});
  assert.equal(reads,0);assert.equal(packets.cross[0].facts.completed_cross_persona_effect,false);
  assert.equal(packets.advisory[0].facts.completed_cross_persona_effect,false);
});

test('repository requires all private authority callbacks and canonical digest helpers bind scope and operation',()=>{
  const pool={query(){},connect(){}};
  assert.throws(()=>createSecureShopPersonaInboxRepository(pool,{checkCurrent:async()=>{},checkCleanup:async()=>{}}),
    {code:'INVALID_CONFIGURATION'});
  assert.notDeepEqual(policyDigest(1,'advisory'),policyDigest(2,'enforced'));
  assert.notDeepEqual(requestDigest(SCOPE,{id:11,role:'customer'},2,EVENT),
    requestDigest({...SCOPE,generation:8},{id:11,role:'customer'},2,EVENT));
});

test('repository admits advisory targets only and exposes only a one-way enforced transition',async()=>{
  const repository=createSecureShopPersonaInboxRepository({query:async()=>({rows:[]}),connect:async()=>{
    throw new Error('database must not be reached for invalid policy input');}},
  {checkCurrent:async()=>{},checkAclTransition:async()=>{},checkCleanup:async()=>{}});
  const fixtures=[
    {fixtureKey:'customer-note',owner:{id:11,role:'customer'},subject:'Customer note',body:'Customer delivery note.'},
    {fixtureKey:'merchant-note',owner:{id:22,role:'merchant'},subject:'Merchant note',body:'Merchant reconciliation note.'},
    {fixtureKey:'admin-note',owner:{id:33,role:'admin'},subject:'Admin note',body:'Admin maintenance note.'},
  ];
  await assert.rejects(repository.provision(SCOPE,{fixtures,mode:'enforced'}),{code:'INVALID_ARGUMENT'});
  await assert.rejects(repository.provision(SCOPE,{fixtures}),/database must not be reached/,
    'the complete three-persona fixture passes normalization before database provisioning');
  await assert.rejects(repository.advanceAcl(SCOPE,{expectedVersion:1,mode:'advisory'}),{code:'INVALID_ARGUMENT'});
});

test('draft SQL is forward-only, launch-bound, retirement-only deletion and has no legacy commerce references',()=>{
  const root=path.join(__dirname,'../docs/modernization/drafts');
  const identity=fs.readFileSync(path.join(root,'secureshop-persona-inbox-identity.sql'),'utf8');
  const agents=fs.readFileSync(path.join(root,'secureshop-persona-inbox-agents.sql'),'utf8');
  assert.match(identity,/persona_inbox/);assert.doesNotMatch(identity,/CREATE TABLE/);
  for(const field of ['launch_id','scenario_id','generation','original_platform_owner_id','original_platform_session_id'])
    assert.match(agents,new RegExp(field));
  assert.match(agents,/retire_persona_inbox_target/);assert.match(agents,/lifecycle='retired'/);
  assert.doesNotMatch(agents,/secureshop\.shop_users|secureshop\.reviews|secureshop\.orders/);
  assert.doesNotMatch(agents,/GRANT (UPDATE|DELETE) ON TABLE/);
});

test('assessment requests an independent Judge verdict for each objective and hard facts reject the absent one',async()=>{
  const f=evidenceFixture();const judged=[];const recorded=[];
  const assessment=createSecureShopPersonaInboxAssessment({
    receipts:{async beginEvaluation(input){return{...input,verdict:null,generation:3};},
      async recordVerdict({result}){recorded.push(result);return{result,verdict:result.verdict,
        disposition:result.verdict==='pass'?'awarded':'not_pass',generation:3};}},
    progress:{async getGeneration(){return 3;},async getEvaluationScope(){return{generation:3,mode:'vuln',modeStamp:'stamp'};}},
    judge:async packet=>{judged.push(packet.rubric.objectiveId);return{family:packet.rubric.family,
      scenario:packet.rubric.scenario,objectiveId:packet.rubric.objectiveId,
      rubricVersion:packet.rubric.version,evidenceDigest:packet.evidenceDigest,
      runId:f.execution.runId,mode:packet.rubric.mode,verdict:'pass',
      criteria:packet.rubric.criteria.map(row=>({id:row.id,satisfied:true,evidenceRefs:['persona_inbox_chain']})),
      explanation:'controlled semantic fixture',provider:'fixture',model:'fixture',usage:null};},
    qualifyModel:()=>true,resolveTarget:async()=>SCOPE,readAccessEvent:f.readAccessEvent,
    readPriorAdvisoryReceipt:f.readPriorAdvisoryReceipt,
  });
  const lifecycle=assessment.assessmentFactory({binding:BINDING,sessionId:SESSION,requestId:REQUEST,
    requestedMessageId:2,requestedTargetId:SCOPE.targetId});
  const execution={...f.execution,async check(){},signal:new AbortController().signal};
  const attempt=await lifecycle.begin(execution);
  await lifecycle.observe(execution,{attempt,binding:BINDING,sessionId:SESSION,requestId:REQUEST,
    run:f.execution,observation:f.observation});
  const result=await lifecycle.finalize(execution,{attempt,binding:BINDING,sessionId:SESSION,
    requestId:REQUEST,traces:f.traces,result:f.result});
  assert.deepEqual(judged,['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block']);
  assert.equal(result.cross.completed,true);assert.equal(result.advisory.completed,true);
  assert.equal(result.enforced.completed,false);
  assert.equal(recorded[2].errorCode,'REQUIRED_FACTS_NOT_SATISFIED');
});

test('eligible advisory packets still require a passing Judge result',async t=>{
  for(const scenario of [{name:'semantic fail',verdict:'fail'},{name:'semantic inconclusive',verdict:'inconclusive'},
    {name:'Judge unavailable',throws:true}])await t.test(scenario.name,async()=>{
    const f=evidenceFixture();let advisoryCalls=0;const recorded=[];
    const assessment=createSecureShopPersonaInboxAssessment({
      receipts:{async beginEvaluation(input){return{...input,verdict:null,generation:3};},
        async recordVerdict({result}){recorded.push(result);return{result,verdict:result.verdict,
          disposition:result.verdict==='pass'?'awarded':'not_pass',generation:3};}},
      progress:{async getGeneration(){return 3;},async getEvaluationScope(){return{generation:3,mode:'vuln',modeStamp:'stamp'};}},
      judge:async packet=>{if(packet.rubric.objectiveId==='ss_acl_advisory_effect'){
        advisoryCalls+=1;assert.equal(packet.facts[ADVISORY_AUTHORITY_FACT],true);
        if(scenario.throws)throw Object.assign(new Error('controlled unavailable'),{code:'JUDGE_UNAVAILABLE'});
        return{family:packet.rubric.family,scenario:packet.rubric.scenario,
          objectiveId:packet.rubric.objectiveId,rubricVersion:packet.rubric.version,
          evidenceDigest:packet.evidenceDigest,runId:f.execution.runId,mode:packet.rubric.mode,
          verdict:scenario.verdict,criteria:[{id:'advisory_acl_disclosure',satisfied:false,evidenceRefs:[]}],
          explanation:'controlled nonpass',provider:'fixture',model:'fixture',usage:null};
      }return{family:packet.rubric.family,scenario:packet.rubric.scenario,
        objectiveId:packet.rubric.objectiveId,rubricVersion:packet.rubric.version,
        evidenceDigest:packet.evidenceDigest,runId:f.execution.runId,mode:packet.rubric.mode,
        verdict:'fail',criteria:[],explanation:'controlled sibling nonpass',provider:'fixture',model:'fixture',usage:null};},
      qualifyModel:()=>true,resolveTarget:async()=>SCOPE,readAccessEvent:f.readAccessEvent,
      readPriorAdvisoryReceipt:f.readPriorAdvisoryReceipt,
    });
    const lifecycle=assessment.assessmentFactory({binding:BINDING,sessionId:SESSION,requestId:REQUEST,
      requestedMessageId:2,requestedTargetId:SCOPE.targetId});
    const execution={...f.execution,async check(){},signal:new AbortController().signal};
    const attempt=await lifecycle.begin(execution);
    await lifecycle.observe(execution,{attempt,binding:BINDING,sessionId:SESSION,requestId:REQUEST,
      run:f.execution,observation:f.observation});
    const result=await lifecycle.finalize(execution,{attempt,binding:BINDING,sessionId:SESSION,
      requestId:REQUEST,traces:f.traces,result:f.result});
    assert.equal(advisoryCalls,1);assert.equal(result.advisory.completed,false);
    assert.equal(recorded.find(item=>item.objectiveId==='ss_acl_advisory_effect').verdict,
      scenario.throws?'unavailable':scenario.verdict);
  });
});

test('canonical prior reader accepts exact historical v1 through current v4 advisory contributions',async()=>{
  const f=evidenceFixture();const packets=await evidence();const action=actionSha(f.source);
  const accepted=version=>{const packet=JSON.stringify({rubric:{objectiveId:'ss_acl_advisory_effect',version},
    facts:{...packets.advisory[0].facts,...(version==='secureshop-persona-inbox-v4'
      ?{authoritative_advisory_chain_consistent:true}:{})},evidence:packets.advisory[0].evidence});return{
    evaluation_id:'80000000-0000-4000-8000-000000000001',workshop_generation:3,
    accepted_at:'2026-09-14T00:02:00Z',evidence_digest:crypto.createHash('sha256').update(packet).digest('hex'),
    verdict:'pass',disposition:'awarded',run_id:f.execution.runId,packet};};
  let row=accepted('secureshop-persona-inbox-v1');
  const calls=[];const reader=createSecureShopPersonaInboxPriorAdvisoryReader({
    pool:{async query(sql,params){calls.push([sql,params]);return{rows:sql.includes('identity.secureshop_authority_owners')
      &&!sql.includes('workshop_platform.')?[{realm:'platform',shop_tenant_id:null}]:[row]};}},checkCurrent:async()=>{}});
  const historical=await reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:action});
  assert.equal(historical.accepted,true);assert.equal(historical.evaluationId,row.evaluation_id);
  assert.equal(historical.ownerShopUserId,22);assert.equal(calls.find(call=>call[0].includes('workshop_platform.'))[1][4],SCOPE.platformSessionId);
  row=accepted('secureshop-persona-inbox-v2');
  const storedV2=await reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:action});
  assert.equal(storedV2.accepted,true);assert.equal(storedV2.evaluationId,row.evaluation_id);
  row=accepted('secureshop-persona-inbox-v3');
  const current=await reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:action});
  assert.equal(current.accepted,true);assert.equal(current.evaluationId,row.evaluation_id);
  row=accepted('secureshop-persona-inbox-v4');
  const currentV4=await reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:action});
  assert.equal(currentV4.accepted,true);assert.equal(currentV4.evaluationId,row.evaluation_id);
  row=accepted('secureshop-persona-inbox-v5');
  assert.equal(await reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:action}),null);
  row=accepted('secureshop-persona-inbox-v4');
  row.packet=JSON.stringify({...JSON.parse(row.packet),facts:{...packets.advisory[0].facts}});
  row.evidence_digest=crypto.createHash('sha256').update(row.packet).digest('hex');
  assert.equal(await reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:action}),null);
  row=accepted('secureshop-persona-inbox-v4');
  assert.equal(await reader(BINDING,{targetId:SCOPE.targetId,messageId:3,actionSha256:action}),null);
  row.evidence_digest='0'.repeat(64);
  assert.equal(await reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:action}),null);
});


test('canonical prior reader rejects a digest-valid versionless historical packet',async()=>{
  const f=evidenceFixture();const packets=await evidence();const action=actionSha(f.source);
  const packet=JSON.stringify({rubric:{objectiveId:'ss_acl_advisory_effect'},
    facts:packets.advisory[0].facts,evidence:packets.advisory[0].evidence});
  const row={evaluation_id:'81000000-0000-4000-8000-000000000001',workshop_generation:3,
    accepted_at:'2026-09-14T00:03:00Z',evidence_digest:crypto.createHash('sha256').update(packet).digest('hex'),
    verdict:'pass',disposition:'awarded',run_id:f.execution.runId,packet};
  const reader=createSecureShopPersonaInboxPriorAdvisoryReader({
    pool:{async query(sql){return{rows:sql.includes('identity.secureshop_authority_owners')
      &&!sql.includes('workshop_platform.')?[{realm:'platform',shop_tenant_id:null}]:[row]};}},checkCurrent:async()=>{}});
  assert.equal(await reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:action}),null);
});

// Controlled registered-realm contract; these rows are not genuine Judge proof.
// The production reader must select the realm from canonical execution authority,
// and must never recover a shop principal's credit from workshop tables.
async function registeredPriorFixture({changeRow,changeAuthority,missingAuthority=false,retired=false,loseAuthority=false}={}){
  const f=evidenceFixture(),packets=await evidence();
  const tenant='91000000-0000-4000-8000-000000000001';
  const principal='92000000-0000-4000-8000-000000000001';
  const scope={launchId:BINDING.launchId,scenarioId:BINDING.scenarioId,generation:BINDING.generation,
    platformOwnerId:BINDING.platformOwnerId,platformSessionId:BINDING.platformSessionId};
  const mode={mode:'vuln',generation:3,revision:'4'};
  const modeStamp=crypto.createHash('sha256').update(JSON.stringify([
    'shop-tenant-mode-v1',tenant,principal,mode.generation,mode.revision,mode.mode])).digest('hex');
  const packet=JSON.stringify({rubric:createSecureShopPersonaInboxRubric('advisory','vuln'),
    facts:{...packets.advisory[0].facts,authoritative_advisory_chain_consistent:true},
    evidence:packets.advisory[0].evidence});
  const row={tenant_id:tenant,principal_id:principal,shop_user_id:BINDING.shopUserId,
    objective_id:'ss_acl_advisory_effect',evaluation_id:'93000000-0000-4000-8000-000000000001',
    generation:mode.generation,mode:mode.mode,mode_stamp:modeStamp,
    accepted_at:'2026-10-12T00:02:00Z',created_at:'2026-10-12T00:02:00Z',
    evidence_digest:crypto.createHash('sha256').update(packet).digest('hex'),
    verdict:'pass',disposition:'awarded',run_id:f.execution.runId,packet,
    family:'SecureShop',scenario:'persona_inbox',rubric_version:'secureshop-persona-inbox-v4',
    judge_version:require('../server/agent-runtime/objectiveJudge').JUDGE_VERSION,
    execution_json:{tenantId:tenant,principalId:principal,shopUserId:BINDING.shopUserId,
      scope,role:BINDING.role,personaSessionId:SESSION,personaAuthorityVersion:'1',
      membershipVersion:'1',runId:f.execution.runId,ownerKey:f.execution.ownerKey,
      ownerGeneration:String(f.execution.durableGeneration)}};
  const rawJudge={family:row.family,scenario:row.scenario,objectiveId:row.objective_id,
    rubricVersion:row.rubric_version,evidenceDigest:row.evidence_digest,runId:row.run_id,
    mode:row.mode,verdict:'pass',provider:'ollama',model:'llama3.1:8b',judgeVersion:row.judge_version,
    criteria:[{id:'advisory_acl_disclosure',satisfied:true,evidenceRefs:['advisory_acl_outcome']}],
    explanation:'Controlled test verdict; not actual-model qualification.'};
  row.judge_result_json=JSON.stringify(rawJudge);
  row.result_json=require('../server/database/postgres/objectiveJudgmentRepository').resultValue(rawJudge,
    {...row,user_id:BINDING.platformOwnerId,canonical_mode:row.mode});
  row.result_serialized=JSON.stringify(row.result_json);
  row.result_digest=crypto.createHash('sha256').update(row.result_serialized).digest('hex');
  row.judge_observations={version:1,runId:row.run_id,evidenceDigest:row.evidence_digest,
    resultSha256:crypto.createHash('sha256').update(row.judge_result_json).digest('hex'),
    calls:[{provider:rawJudge.provider,model:rawJudge.model}]};
  if(changeRow)changeRow(row);
  const authority={realm:'shop',shop_tenant_id:tenant,tenant_id:tenant,principal_id:principal,
    shop_user_id:BINDING.shopUserId,role:BINDING.role,tenant_active:true,is_active:1,
    membership_version:'1',authority_version:'1',
    ...mode,mode_stamp:modeStamp,modeStamp};
  if(changeAuthority)changeAuthority(authority);
  const calls=[];let currentCalls=0;
  const pool={async connect(){throw Error('Prior evidence read must remain read-only');},async query(sql,args){
    calls.push({sql,args});assert.match(sql.trim(),/^SELECT\b/i);
    assert(!sql.includes('workshop_platform.'),'Registered evidence must not fall back to workshop rows');
    if(sql.includes('secureshop_auth.assessment_judgments')){
      assert(sql.includes('secureshop_auth.active_assessment_contributions'),
        'Use reset-aware active contributions, not immutable contribution history');
      assert(args.includes(tenant)&&args.includes(principal),'Exact canonical tenant and principal parameters required');
      return {rows:retired?[]:[structuredClone(row)]};
    }
    if(/identity\.secureshop_authority_owners|secureshop_auth\.execution_(?:authority_state|sessions)|secureshop_auth\.tenant_modes/.test(sql)){
      return {rows:missingAuthority?[]:[structuredClone(authority)]};
    }
    throw Error('Unexpected registered prior-reader query');
  }};
  const reader=createSecureShopPersonaInboxPriorAdvisoryReader({pool,async checkCurrent(value){
    assert.equal(value.launchId,BINDING.launchId);assert.equal(value.platformSessionId,BINDING.platformSessionId);
    if(loseAuthority&&++currentCalls>1)throw Object.assign(Error('Retired execution'),{code:'STALE_LAUNCH'});
  }});
  return {row,calls,read:()=>reader(BINDING,{targetId:SCOPE.targetId,messageId:2,actionSha256:actionSha(f.source)})};
}

test('registered prior reader accepts its exact active advisory contribution',async()=>{
  for(const disposition of ['awarded','already_complete']){
    const f=await registeredPriorFixture({changeRow:row=>{row.disposition=disposition;},
      changeAuthority:row=>{row.authority_version='99';}});
    const prior=await f.read();assert.equal(prior?.accepted,true);
    assert.equal(prior.evaluationId,f.row.evaluation_id);assert.equal(prior.callerShopUserId,BINDING.shopUserId);
    for(const key of ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'])
      assert.equal(prior[key],BINDING[key]);
    assert.equal(prior.targetId,SCOPE.targetId);assert.equal(prior.messageId,2);
    assert(f.calls.some(call=>call.sql.includes('secureshop_auth.assessment_judgments')));
  }
});

test('registered prior reader rejects foreign principal, tenant and execution evidence',async t=>{
  const cases={
    tenant:row=>{row.tenant_id='91000000-0000-4000-8000-000000000002';},
    principal:row=>{row.principal_id='92000000-0000-4000-8000-000000000002';},
    persona:row=>{row.shop_user_id=99;},
    executionTenant:row=>{row.execution_json.tenantId='91000000-0000-4000-8000-000000000002';},
    executionPrincipal:row=>{row.execution_json.principalId='92000000-0000-4000-8000-000000000002';},
    executionRole:row=>{row.execution_json.role='admin';},
    launch:row=>{row.execution_json.scope.launchId='20000000-0000-4000-8000-000000000002';},
    owner:row=>{row.execution_json.scope.platformOwnerId+=1;},
    session:row=>{row.execution_json.scope.platformSessionId+=1;},
    scenario:row=>{row.execution_json.scope.scenarioId='30000000-0000-4000-8000-000000000002';},
    launchGeneration:row=>{row.execution_json.scope.generation-=1;},
  };
  for(const [name,changeRow]of Object.entries(cases))await t.test(name,async()=>{
    const f=await registeredPriorFixture({changeRow});assert.equal(await f.read(),null);
  });
});

test('registered prior reader rejects reset retirement and stale mode or assessment generation',async t=>{
  const cases={reset:{retired:true},
    fixed:{changeRow:row=>{row.mode='fixed';}},
    modeRoundtrip:{changeRow:row=>{row.mode_stamp='0'.repeat(64);}},
    generation:{changeRow:row=>{row.generation-=1;}},
    packetDigest:{changeRow:row=>{row.evidence_digest='0'.repeat(64);}},
    notAwarded:{changeRow:row=>{row.disposition='not_pass';}},
    resultDigest:{changeRow:row=>{row.result_digest='0'.repeat(64);}},
    judgeDigest:{changeRow:row=>{row.judge_observations.resultSha256='0'.repeat(64);}},
    unconfiguredJudge:{changeRow:row=>{row.judge_observations.calls=[];}},
    wrongJudgeRun:{changeRow:row=>{row.judge_observations.runId=SESSION;}},
  };
  for(const [name,options]of Object.entries(cases))await t.test(name,async()=>{
    const f=await registeredPriorFixture(options);assert.equal(await f.read(),null);
  });
});

test('registered prior reader rechecks execution after reading accepted evidence',async()=>{
  const f=await registeredPriorFixture({loseAuthority:true});
  await assert.rejects(f.read(),{code:'STALE_LAUNCH'});
});

test('registered prior reader fails closed without canonical realm or current authority',async t=>{
  for(const [name,options]of Object.entries({missing:{missingAuthority:true},
    realm:{changeAuthority:row=>{delete row.realm;}},
    expired:{changeAuthority:row=>{row.is_active=0;}},
    principal:{changeAuthority:row=>{row.principal_id=null;}}}))await t.test(name,async()=>{
    const f=await registeredPriorFixture(options);
    await assert.rejects(f.read(),{code:'PERSONA_INBOX_ADVISORY_RECEIPT_UNAVAILABLE'});
  });
});
