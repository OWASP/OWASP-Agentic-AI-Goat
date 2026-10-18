'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createMcpImpersonationAssessment,assessmentRequestId}=require('../server/services/secureshopMcpImpersonationAssessment');

const scope=()=>({launchId:randomUUID(),scenarioId:randomUUID(),generation:1,
  platformOwnerId:2,platformSessionId:3,shopUserId:4,role:'admin'});

test('assessment request identity includes both original session and request',()=>{
  const session=randomUUID(),request=randomUUID();
  assert.equal(assessmentRequestId(session,request),assessmentRequestId(session,request));
  assert.notEqual(assessmentRequestId(session,request),assessmentRequestId(randomUUID(),request));
  assert.notEqual(assessmentRequestId(session,request),assessmentRequestId(session,randomUUID()));
  assert.throws(()=>assessmentRequestId('foreign',request));
});

test('protected assessment readback uses exact persisted hash and never creates a session',async()=>{
  const binding=scope(),sessionId=randomUUID(),requestId=randomUUID(),assessmentSessionId=randomUUID();
  const personaSession={sessionId:randomUUID(),authorityVersion:'1'};
  const key=assessmentRequestId(sessionId,requestId);
  const modeSnapshot={generation:1,modeStamp:'a'.repeat(64),mode:'vuln'};
  const msg=JSON.stringify(['ss_mcp_server_impersonation',sessionId,requestId,
    personaSession.sessionId,personaSession.authorityVersion]);
  const expected=createTurnRequest({sessionId:assessmentSessionId,requestId:key,binding,message:msg});
  const persisted={session_id:assessmentSessionId,request_id:key,status:'completed',
    request_hash:expected.hash,request_version:expected.version,
    result_json:{completed:false,judgment:{verdict:'fail'}}};
  const observed=[];let writes=0,rows=[persisted];
  const unchanged=async()=>{};
  const service=createMcpImpersonationAssessment({
    identityPool:{query:async()=>({rows:[]})},
    agentsPool:{query:async(sql,params)=>{observed.push({sql,params});return {rows};}},
    launches:{assertCurrent:unchanged},
    conversationRepository:{getTraceEvents:async()=>[],acquireBoundSession:async()=>{writes++;},
      getBoundSession:async id=>({id,state:'active',purpose:'general',binding})},
    coordinator:{run:async()=>{writes++;}},
    turnJournal:{readRegisteredAdminRequest:async()=>({status:'completed',result_json:{taskMetadata:{
      registeredAdmin:{version:3,execution:structuredClone(modeSnapshot)}}}}),claim:async()=>{writes++;},
      complete:async()=>{writes++;},markUncertain:async()=>{writes++;}},
    registryRepository:{readAssessmentRevisions:async()=>null},
    invocationJournal:{readCompleted:async()=>null},
    personaAuthority:{capture:()=>({assertRemoteAdmission:unchanged})},
    personaBindings:{capture:async()=>({})},
    receipts:{beginEvaluation:async()=>{writes++;},recordVerdict:async()=>{writes++;}},
    progress:{getGeneration:async()=>1},judge:async()=>({}),
    qualifyModel:()=>false,
    modeAuthority:{capture:async()=>({snapshot:modeSnapshot,
      assertCurrent:unchanged}),assertToken:value=>value},
  });
  const input={scope:binding,persona:{id:binding.shopUserId,role:'admin'},personaSession,
    sessionId,requestId,verifyOriginal:async()=>({status:'completed'})};
  assert.deepEqual(await service.readOutcome(input),{...persisted.result_json,replayed:true});
  assert.equal(writes,0);assert.equal(observed.length,1);
  assert.deepEqual(observed[0].params,[key,binding.launchId,binding.scenarioId,binding.generation,
    binding.platformOwnerId,binding.platformSessionId,binding.shopUserId,'admin']);
  assert.match(observed[0].sql,/JOIN secureshop_agents\.agent_sessions/);
  rows=[{...persisted,request_hash:'0'.repeat(64)}];
  await assert.rejects(service.readOutcome(input),{code:'MCP_IMPERSONATION_EVIDENCE_UNAVAILABLE'});
  rows=[{...persisted,result_json:{completed:false,status:'ineligible',modelEvaluated:false}}];
  assert.deepEqual(await service.readOutcome(input),
    {completed:false,status:'ineligible',modelEvaluated:false});
  rows=[];assert.deepEqual(await service.readOutcome(input),
    {completed:false,status:'unconfirmed',modelEvaluated:false});
  assert.equal(writes,0);
});
