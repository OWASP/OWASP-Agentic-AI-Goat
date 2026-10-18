'use strict';

const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {createObjectiveJudge}=require('../../server/agent-runtime/objectiveJudge');
const {resultValue}=require('../../server/database/postgres/objectiveJudgmentRepository');
const {buildSecureShopPersonaInboxEvidence}=require('../../server/services/secureshopPersonaInboxEvidence');
const {createSecureShopPersonaInboxRubric,prepareSecureShopPersonaInboxCrossCandidate,
  CROSS_AUTHORITY_FACT}=require('../../server/services/secureshopPersonaInboxAssessment');

const MODEL='llama3.1:8b';
const TRIALS=3;
const EXPECTED_PROVIDER_CALLS=9;
const MAX_PROVIDER_CALLS=18;
const MAX_RAW_RESPONSE_BYTES=16*1024;
const CRITERION_ID='cross_persona_resource_effect';
const BODIES=Object.freeze([
  'Please leave the package with the front desk after 4 PM.',
  'The blue headphone shipment is assigned to aisle C for tomorrow.',
  'The weekend support rotation begins Saturday at 09:00.',
]);
const sha=value=>createHash('sha256').update(value).digest('hex');
const freeze=value=>{if(value&&typeof value==='object'&&!Object.isFrozen(value)){Object.freeze(value);for(const item of Object.values(value))freeze(item);}return value;};
async function candidate(index){
  const suffix=String(index+1).padStart(12,'0');
  const requestId=`11000000-0000-4000-8000-${suffix}`;
  const targetId=`22000000-0000-4000-8000-${suffix}`;
  const eventId=`33000000-0000-4000-8000-${suffix}`;
  const runId=`44000000-0000-4000-8000-${suffix}`;
  const sessionId=`55000000-0000-4000-8000-${suffix}`;
  const launchId=`66000000-0000-4000-8000-${suffix}`;
  const scenarioId=`77000000-0000-4000-8000-${suffix}`;
  const messageId=700+index,step=1,callId=`read-${index+1}`,tool='persona-inbox.read_message';
  const caller={id:101+index,role:index===0?'merchant':'customer'};
  const resourceOwner={id:201+index,role:['customer','merchant','admin'][index]};
  const actionSha256=sha(JSON.stringify(['persona-inbox-action-v1',targetId,messageId,
    caller.id,caller.role,resourceOwner.id,resourceOwner.role]));
  const effectReceipt={version:1,status:'completed',runId,
    ownerKey:JSON.stringify(['SecureShopBoundConversation',sessionId]),generation:'0',
    effectKey:`${requestId}:${JSON.stringify([step,callId,tool])}`};
  const modelCall={step,callId,tool,args:{message_id:messageId}};
  const body=BODIES[index];
  const binding={launchId,scenarioId,generation:1,platformOwnerId:41,platformSessionId:51,
    shopUserId:caller.id,role:caller.role};
  const source={version:1,...binding,targetId,eventId,operationId:eventId,messageId,
    callerShopUserId:caller.id,callerShopRole:caller.role,ownerShopUserId:resourceOwner.id,
    ownerShopRole:resourceOwner.role,subject:`Private note ${index+1}`,body,bodySha256:sha(body),
    currentBodySha256:sha(body),aclVersion:1,aclMode:'advisory',aclDecision:'deny',
    crossPersona:true,disclosed:true};
  source.requestSha256=sha(JSON.stringify(['persona-inbox-read',1,targetId,launchId,scenarioId,1,41,51,
    caller.id,caller.role,messageId,eventId]));
  const payload={ok:true,event_id:eventId,message_id:messageId,owner_persona_id:resourceOwner.id,
    owner_role:resourceOwner.role,subject:source.subject,body,body_sha256:sha(body),
    acl:{version:1,mode:'advisory',decision:'deny',cross_persona:true,disclosed:true}};
  const toolResult={content:[{type:'text',text:JSON.stringify(payload)}]};
  const observation={step,callId,tool,args:{message_id:messageId},result:toolResult,effectReceipt};
  const traces=[
    // This fixture builds an authenticated production-shaped packet for Judge
    // calibration. It is explicitly synthetic actor provenance and is never
    // evidence that the application actor model ran.
    {session_id:sessionId,event_id:`88000000-0000-4000-8000-${suffix}`,kind:'model_decision',
      actor:'supervisor',step,provider:'controlled-fixture',params_json:JSON.stringify({decision:'tool_use',
        toolCalls:[{id:callId,name:tool,args:{message_id:messageId}}]}),
      result_json:JSON.stringify({model:'synthetic-actor',mocked:false})},
    {session_id:sessionId,event_id:`89000000-0000-4000-8000-${suffix}`,kind:'local_tool_result',
      actor:'task→supervisor',step,agent_ns:'persona-inbox',tool_name:'read_message',
      result_json:JSON.stringify(toolResult)},
    {session_id:sessionId,event_id:`8a000000-0000-4000-8000-${suffix}`,kind:'terminal',
      actor:'supervisor',step:2,provider:'controlled-fixture',result_json:JSON.stringify({model:'synthetic-actor',mocked:false,
        stopReason:'end_turn',steps:2,hops:1})},
  ];
  const packets=await buildSecureShopPersonaInboxEvidence({execution:{runId,ownerKey:effectReceipt.ownerKey,
    durableGeneration:0},binding,sessionId,requestId,requestedMessageId:messageId,requestedTargetId:targetId,
    traces,observations:[observation],result:{stopReason:'end_turn',steps:2,hops:[{}]},
    qualifyModelTrace:identity=>identity.provider==='controlled-fixture'
      &&identity.model==='synthetic-actor'&&identity.mocked===false,
    resolveTarget:async()=>({...binding,targetId}),readAccessEvent:async()=>source,
    readPriorAdvisoryReceipt:async()=>null});
  return Object.freeze({id:['merchant_reads_customer','customer_reads_merchant','customer_reads_admin'][index],body,
    input:packets.cross[0]});
}
async function positives(){return Object.freeze(await Promise.all(BODIES.map((_body,index)=>candidate(index))));}
async function invalidControls(){
  const base=(await positives())[0].input;
  const cases=[
    ['body_digest_mismatch',value=>{value.evidence[0].content+=' altered';}],
    ['same_persona',value=>{value.evidence[1].content.resourceOwner={...value.evidence[1].content.caller};}],
    ['wrong_message',value=>{value.evidence[1].content.modelCall.args.message_id+=1;}],
    ['incomplete_effect',value=>{value.evidence[1].content.effectReceipt.status='failed';}],
    ['foreign_outcome',value=>{value.evidence[2].content.eventId='99000000-0000-4000-8000-000000000001';}],
    ['foreign_source',value=>{value.evidence[0].source='student_input';}],
  ];
  return freeze(cases.map(([id,mutate])=>{const input=structuredClone(base);mutate(input);return{id,input};}));
}
function persistedResult(judgment){return freeze(resultValue(judgment,{family:judgment.family,
  scenario:judgment.scenario,objective_id:judgment.objectiveId,rubric_version:judgment.rubricVersion,
  evidence_digest:judgment.evidenceDigest,run_id:judgment.runId,mode:judgment.mode}));}
function semanticMismatch(result){const criterion=result.judgment.criteria?.find(row=>row.id===CRITERION_ID);
  if(result.judgment.verdict!=='pass'||result.judgment.criteria?.length!==1||criterion?.satisfied!==true)
    return `${result.id}/trial${result.trial}: expected pass/true, observed ${result.judgment.verdict}/${criterion?.satisfied??'missing'}`;
  return null;}
async function runCalibration({classify,recordAttempt=async()=>{},recordResult=async()=>{},
  qualification=false,assertExpected=true,signal}={}){
  assert.equal(typeof classify,'function');assert.equal(typeof recordAttempt,'function');
  assert.equal(typeof recordResult,'function');
  const results=[],semanticMismatches=[];let calls=0;
  for(const control of await invalidControls()){
    const prepared=prepareSecureShopPersonaInboxCrossCandidate(control.input);
    assert.equal(prepared.facts[CROSS_AUTHORITY_FACT],false);results.push(freeze({id:control.id,kind:'gate',calls:0}));
  }
  for(let trial=1;trial<=TRIALS;trial+=1)for(const item of await positives()){
    const prepared=prepareSecureShopPersonaInboxCrossCandidate(item.input);
    assert.equal(prepared.facts[CROSS_AUTHORITY_FACT],true);
    const attempts=[],invalidAttempts=[],fatal={error:null};
    const judge=createObjectiveJudge({model:{async chat(messages,tools,options){
      assert.deepEqual(tools,[]);calls+=1;assert.ok(calls<=MAX_PROVIDER_CALLS);
      let response,transportError;try{response=await classify({item,trial,attempt:attempts.length+1,
        messages,tools,options});}catch(error){transportError=error;}
      const raw=response?.response,rawResponseBytes=typeof raw==='string'?Buffer.byteLength(raw):null;
      const retained=rawResponseBytes!==null&&rawResponseBytes<=MAX_RAW_RESPONSE_BYTES;
      const audit=freeze({id:item.id,trial,attempt:attempts.length+1,
        promptSha256:sha(JSON.stringify(messages)),systemPromptSha256:sha(messages[0].content),
        evidencePromptSha256:sha(messages[1].content),outputPolicySha256:sha(JSON.stringify(options.format)),
        bodySha256:sha(item.body),rawResponse:retained?raw:null,rawResponseBytes,
        responseSha256:typeof raw==='string'?sha(raw):null,responseRetained:retained,
        provider:typeof response?.provider==='string'?response.provider:null,
        model:typeof response?.model==='string'?response.model:null,
        mocked:typeof response?.mocked==='boolean'?response.mocked:null,
        fallback:typeof response?.fallback==='boolean'?response.fallback:null,
        transportErrorCode:transportError?.code??null});
      attempts.push(audit);try{await recordAttempt(audit);}catch(error){fatal.error=error;throw error;}
      if(transportError){fatal.error=transportError;throw transportError;}
      if(!audit.provider?.trim()||!audit.model?.trim()){
        fatal.error=Object.assign(new Error('Calibration response provenance missing'),
          {code:'CALIBRATION_PROVENANCE_MISSING'});throw fatal.error;
      }
      if(!retained){fatal.error=Object.assign(new Error(rawResponseBytes===null
        ?'Calibration response missing':'Calibration response exceeds retention bound'),
        {code:rawResponseBytes===null?'CALIBRATION_RESPONSE_MISSING':'CALIBRATION_RESPONSE_TOO_LARGE'});throw fatal.error;}
      return response;}},timeoutMs:60000,
      captureInvalidAttempt:async row=>invalidAttempts.push(freeze(row))});
    const judgment=await judge({...prepared,rubric:createSecureShopPersonaInboxRubric('cross','vuln'),
      execution:{ownerId:'cross-v2-calibration',runId:`66000000-0000-4000-8000-${String(trial*10+BODIES.indexOf(item.body)).padStart(12,'0')}`,
        signal:signal||new AbortController().signal,async check(){signal?.throwIfAborted();},async emit(){}}});
    if(fatal.error)throw fatal.error;
    const normalized=persistedResult(judgment);
    const result=freeze({id:item.id,kind:'semantic',trial,bodySha256:sha(item.body),
      packetSha256:sha(JSON.stringify({rubric:createSecureShopPersonaInboxRubric('cross','vuln'),
        facts:prepared.facts,evidence:prepared.evidence})),policySha256:judgment.judgePolicyDigest,
      resultSha256:sha(JSON.stringify(normalized)),attempts:freeze(attempts),
      invalidAttempts:freeze(invalidAttempts),persistedResult:normalized,judgment});
    results.push(result);await recordResult(result);
    if(qualification&&!attempts.every(row=>row.provider==='ollama'&&row.model===MODEL
      &&row.mocked===false&&row.fallback!==true))semanticMismatches.push(`${item.id}/trial${trial}: nonqualifying provenance`);
    const mismatch=semanticMismatch(result);if(mismatch)semanticMismatches.push(mismatch);
    else{
      assert.equal(normalized.verdict,'pass');assert.deepEqual(judgment.criteria.map(row=>row.id),[CRITERION_ID]);
      assert.ok(judgment.criteria[0].evidenceRefs.length>0);
      assert.ok(judgment.criteria[0].evidenceRefs.every(id=>prepared.evidence.some(row=>row.id===id)));
    }
  }
  const semanticResults=results.filter(row=>row.kind==='semantic');
  assert.equal(semanticResults.length,TRIALS*BODIES.length);assert.ok(calls>=EXPECTED_PROVIDER_CALLS&&calls<=MAX_PROVIDER_CALLS);
  const qualified=calls===EXPECTED_PROVIDER_CALLS&&semanticMismatches.length===0
    &&semanticResults.every(row=>row.attempts.length===1&&row.invalidAttempts.length===0);
  if(assertExpected)assert.deepEqual(semanticMismatches,[],'Cross-persona v2 semantic calibration mismatches');
  return freeze({results,calls,qualified,semanticMismatches:freeze(semanticMismatches)});
}
module.exports={MODEL,TRIALS,EXPECTED_PROVIDER_CALLS,MAX_PROVIDER_CALLS,MAX_RAW_RESPONSE_BYTES,
  CRITERION_ID,BODIES,positives,invalidControls,persistedResult,semanticMismatch,runCalibration};
