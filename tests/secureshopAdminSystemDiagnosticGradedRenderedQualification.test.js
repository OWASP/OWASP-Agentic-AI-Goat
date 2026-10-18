'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {assertPrivateReceipt,assertGradedEvidence,assertNativeTypedDiagnosticRequest,
 failedAssessmentCapture,boundedAssessmentError,observeAssessmentFactory,failedAssessmentSqlState,
 FLAGS,SCOPE,TEMPLATE,ARGS,PROPOSAL_PROMPT,OBJECTIVE,
 MODEL}=require('./postgres/secureshopAdminSystemDiagnosticGradedRendered.integration.test');
const {diagnosticRequestDigest}=require('../sidecars/sandbox-runner/owned-system/diagnostic-contract');

function goodReceipt(){return Object.fromEntries([...FLAGS.map(key=>[key,true]),
 ['scope',SCOPE],['actorCalls',4],['roleTurns',2],['judgeCalls',2],
 ['executorCalls',1],['errors',[]]]);}
test('graded diagnostic receipt requires one isolated effect, a real Judge and canonical credit',()=>{
 assert.doesNotThrow(()=>assertPrivateReceipt(goodReceipt()));
 for(const [key,value] of [['actorCalls',3],['actorCalls',15],['judgeCalls',0],
  ['judgeCalls',4],['judgeCalls',false],['roleTurns',1],['executorCalls',2],
  ['canonicalJudgePass',false],['genuineCredit',false],['savedAssessmentGetRecovery',false],
  ['immutableHistoryRetained',false]]){
  assert.throws(()=>assertPrivateReceipt({...goodReceipt(),[key]:value}),key);
 }
 assert.throws(()=>assertPrivateReceipt({...goodReceipt(),invented:true}));
});
function gradeProof(){
 const proposalId=randomUUID(),sessionId=randomUUID(),requestId=randomUUID(),evaluationId=randomUUID();
 const targetId=randomUUID(),requestSha256=diagnosticRequestDigest({operationId:proposalId,
  cmd_template:TEMPLATE,args:ARGS});
 const proposal={proposalId,cmd_template:TEMPLATE,args:ARGS,requestSha256};
 const operation={operation_id:proposalId,target_id:targetId,
  request_json:{operationId:proposalId,cmd_template:TEMPLATE,args:ARGS},
  request_sha256:Buffer.from(requestSha256,'hex')};
 const receipt={result:{operationId:proposalId,requestSha256,command:`${TEMPLATE} ${ARGS}`,
  executed:true,exitCode:0,stdout:Buffer.from(`diagnostic-baseline\nsystem-diag-${targetId.replaceAll('-','')}\n`).toString('base64')}};
 const judgment={evaluation_id:evaluationId,verdict:'pass',disposition:'awarded',objective_id:OBJECTIVE,
  evidence_digest:'a'.repeat(64),packet:JSON.stringify({test:'original-command-and-stdout'}),
  result_json:{provider:'ollama',model:MODEL,verdict:'pass'}};
 const body={completed:true,replayed:false,judgment:{verdict:'pass',evaluationId,canRetry:false}};
 const assessment={post:{status:200,requestBody:{sessionId,requestId,proposalId},body},
  saved:{status:200,body:{...body,replayed:true}},judgment,
  contribution:{evaluation_id:evaluationId},completion:{evaluation_id:evaluationId},
  judgeTranscript:{header:{evidenceDigest:'a'.repeat(64),packet:judgment.packet}}};
 return {proposal,turn:{sessionId,requestId},operation,receipt,assessment};
}
test('graded proof joins exact model proposal, post-confirm target output, original POST, saved GET and durable Judge',()=>{
 const proof=gradeProof();assert.doesNotThrow(()=>assertGradedEvidence(proof));
 const mutate=(field,value)=>{const copy=structuredClone(proof);copy.operation.request_sha256=Buffer.from(proof.operation.request_sha256);field(copy,value);assert.throws(()=>assertGradedEvidence(copy));};
 mutate((p)=>{p.proposal.args="'diagnostic-baseline\\n'";});
 mutate((p)=>{p.receipt.result.stdout=Buffer.from('diagnostic-baseline\n').toString('base64');});
 mutate((p)=>{p.assessment.post.requestBody.requestId=randomUUID();});
 mutate((p)=>{p.assessment.saved.body.replayed=false;});
 mutate((p)=>{p.assessment.judgment.evidence_digest='b'.repeat(64);});
 mutate((p)=>{p.assessment.judgment.disposition='rejected';});
});
test('physical learner message is the complete typed diagnostic literal with exact quoted args',()=>{
 const {currentExplicitSystemDiagnosticRequest,LITERAL_REQUEST_PREFIX}=
  require('../server/services/secureshopRoleSystemDiagnosticProposal');
 assert.equal(PROPOSAL_PROMPT,`${LITERAL_REQUEST_PREFIX}${JSON.stringify({cmd_template:TEMPLATE,args:ARGS})}`);
 assert.deepEqual(currentExplicitSystemDiagnosticRequest(PROPOSAL_PROMPT),{cmd_template:TEMPLATE,args:ARGS});
 assert.equal([...ARGS].filter(char=>char==="'").length,2);
 const native=()=>({messages:[{role:'user',content:JSON.stringify({message:PROPOSAL_PROMPT})}],
  format:{oneOf:[{properties:{reply:{type:'string'}}},
   {properties:{tool_calls:{items:{oneOf:[
    {properties:{tool:{enum:['users_search']}}},
    {properties:{tool:{enum:['system_diagnostic_prepare']},args:{properties:{
     cmd_template:{enum:[TEMPLATE]},args:{enum:[ARGS]}}}}}]}}}}]}});
 const check=value=>assertNativeTypedDiagnosticRequest(PROPOSAL_PROMPT,JSON.stringify(value));
 assert.doesNotThrow(()=>check(native()));
 const mutate=change=>{const value=native();change(value);assert.throws(()=>check(value));};
 mutate(value=>{value.format.oneOf[1].properties.tool_calls.items.oneOf[1]
  .properties.args.properties.args.enum=[ARGS.replaceAll("'",'')];});
 mutate(value=>{value.format.oneOf.shift();});
 mutate(value=>{value.format.oneOf[1].properties.tool_calls.items.oneOf.shift();});
 mutate(value=>{value.messages[0].content=JSON.stringify({message:'different'});});
});
test('failed assessment capture retains bounded original HTTP responses and public error codes',()=>{
 const source=[
  {method:'GET',path:'/agents/admin/assistant/system/diagnostic/assess/original',status:200,
   body:{completed:false,status:'unconfirmed',modelEvaluated:false},requestBody:null},
  {method:'POST',path:'/agents/admin/assistant/system/diagnostic/assess',status:503,
   body:{error:'System diagnostic assessment unavailable',code:'SYSTEM_DIAGNOSTIC_ASSESSMENT_UNAVAILABLE'},
   requestBody:{sessionId:randomUUID(),requestId:randomUUID(),proposalId:randomUUID()}},
 ];
 const captured=failedAssessmentCapture(source);
 assert.deepEqual(captured,{responseCount:2,httpResponses:source,responsesTruncated:false});
 source[1].body.code='CHANGED';
 assert.equal(captured.httpResponses[1].body.code,'SYSTEM_DIAGNOSTIC_ASSESSMENT_UNAVAILABLE');
 const oversized=failedAssessmentCapture([...source,
  {...source[1],body:{error:'x'.repeat(20000)}}]);
 assert.equal(oversized.responseCount,3);
 assert.equal(oversized.httpResponses[2].responseTruncated,true);
 assert.match(oversized.httpResponses[2].responseSha256,/^[a-f0-9]{64}$/);
 assert.equal(oversized.httpResponses[2].body,undefined);
});
test('assessment observer rethrows the original error and snapshots only scoped SELECT state',async()=>{
 const error=Object.assign(new Error('original assessment failure'),{code:'ASSESSMENT_ORIGINAL'});
 const errors=[],input={source:'same'};
 const result={completed:false,status:'unconfirmed'};
 const factory=observeAssessmentFactory(received=>{
  assert.strictEqual(received,input);
  return {runAttempt:async received=>{assert.strictEqual(received,input);throw error;},
   readOutcome:async received=>{assert.strictEqual(received,input);return result;}};
 },errors);
 const observed=factory(input);
 assert.strictEqual(await observed.readOutcome(input),result);
 await assert.rejects(observed.runAttempt(input),caught=>caught===error);
 assert.equal(errors.length,1);
 assert.deepEqual(Object.keys(errors[0]),['phase','name','code','message','stack']);
 assert.equal(errors[0].phase,'runAttempt');
 assert.equal(errors[0].code,'ASSESSMENT_ORIGINAL');
 assert.equal(boundedAssessmentError('test',{message:'x'.repeat(2000)}).message.length,512);
 const sessionId=randomUUID(),requestId=randomUUID(),proposalId=randomUUID();
 const assessmentRequestId=require('../server/services/secureshopSystemDiagnosticAssessment')
  .assessmentRequestId(sessionId,requestId,proposalId);
 const originalRunId=randomUUID(),assessmentRunId=randomUUID(),assessmentSession=randomUUID(),calls=[];
 const agents={async query(sql,args){
  calls.push({store:'agents',sql,args});
  return {rows:[{session_id:sessionId,request_id:requestId,source_run_id:originalRunId},
   {session_id:assessmentSession,request_id:assessmentRequestId,source_run_id:null}]};
 }};
 let identityReads=0;
 const identity={async query(sql,args){
  calls.push({store:'identity',sql,args});identityReads++;
  if(identityReads===1)return {rows:[]};
  if(identityReads===2)return {rows:[
   {run_id:originalRunId,owner_key:JSON.stringify(['SecureShopBoundConversation',sessionId])},
   {run_id:assessmentRunId,owner_key:JSON.stringify(['SecureShopBoundConversation',assessmentSession])}]};
  return {rows:[]};
 }};
 const snapshot=await failedAssessmentSqlState(identity,agents,[{method:'POST',
  path:'/agents/admin/assistant/system/diagnostic/assess',
  requestBody:{sessionId,requestId,proposalId}}]);
 assert.equal(snapshot.assessmentRequestId,assessmentRequestId);
 assert.deepEqual(snapshot.runs.map(row=>row.run_id),[originalRunId,assessmentRunId]);
 assert.deepEqual(calls.map(call=>call.store),['agents','identity','identity','identity']);
 assert.ok(calls.every(call=>/^SELECT\b/.test(call.sql.trim())));
 assert.ok(calls[2].args[1].includes(JSON.stringify(['SecureShopBoundConversation',assessmentSession])));
 assert.deepEqual(calls[3].args[0],[originalRunId,assessmentRunId]);
});
