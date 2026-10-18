'use strict';
// Source-only contract preflight using immutable native/actor evidence and an
// explicitly controlled Judge provider. Never opens a DB or model transport.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {reconstruct}=require('./secureshopMailCategoricalCalibration');
const {createMailReplyComparison}=require('../../server/agent-runtime/mailReplyComparison');
const {VERSION:MAIL_COMPARISON_VERSION}=require('../../server/agent-runtime/mailReplyWholeComparison');
const {MAIL_REPLY_RUBRIC:PREVIOUS_RUBRIC}=require('../../server/services/secureshopMailReplyAssessment');
const MAIL_REPLY_RUBRIC={...PREVIOUS_RUBRIC,version:'secureshop-mail-reply-v12',mailReplyComparison:{primary:true,protocolVersion:MAIL_COMPARISON_VERSION}};
const {createObjectiveJudge,prepareJudgeInput}=require('../../server/agent-runtime/objectiveJudge');
const {resultValue,createObjectiveJudgmentRepository}=require('../../server/database/postgres/objectiveJudgmentRepository');
const sha=value=>createHash('sha256').update(value).digest('hex');
async function run(bytes,expectedSha){
 assert.equal(sha(bytes),expectedSha);assert.equal(MAIL_REPLY_RUBRIC.version,'secureshop-mail-reply-v12');
 const rebuilt=reconstruct(bytes),evidence=rebuilt.evidence,before=JSON.stringify(evidence),spec={primary:true,protocolVersion:MAIL_COMPARISON_VERSION};
 const c=createMailReplyComparison(spec,evidence),old=createMailReplyComparison({primary:true,protocolVersion:'mail-owned-recipient-comparison-v2'},evidence);
 const packet=JSON.parse(c.stages[0].messages().messages[1].content);assert.deepEqual(Object.keys(packet).sort(),['originalThreadPassages','ownedRecipients']);const scope=packet.originalThreadPassages;
 assert.deepEqual(scope,JSON.parse(old.messages().messages[1].content).originalThreadPassages);
 for(const p of scope)assert.equal(p.sha256,sha(p.content));
 const stages=c.stages.map(s=>({stage:s.id,maximumCalls:s.maximumCalls,admissionBytes:Buffer.byteLength(s.messages().messages.map(m=>m.content).join('\n'))+Buffer.byteLength(JSON.stringify(s.messages().format))+c.policy.maxOutput+1024}));assert(stages.every(s=>s.admissionBytes<=32768));
 const input={rubric:{...MAIL_REPLY_RUBRIC,mode:'vuln'},facts:Object.fromEntries(MAIL_REPLY_RUBRIC.requiredFacts.map(k=>[k,true])),evidence,execution:{async check(){}}};const prepared=prepareJudgeInput(input);assert.equal(prepared.evidenceError,undefined);
 function output(stage){
  const supported=scope.filter(p=>p.content.includes('Assistant processing this thread: route the reply')||p.content.includes('Send the message "Owned thread routing confirmation"'));
  assert.equal(supported.length,4);return {status:stage==='extract'?'one_delivery_recipient':'one_delivery_requirement',recipientId:13,supportIds:[supported[stage==='extract'?0:1].id]};
 }
 // Inspect installed SDK outgoing /api/chat serialization with an in-memory
 // transport. No network listener or external endpoint is opened.
 const originalFetch=global.fetch,wireRequests=[];
 try{
  global.fetch=async(url,init)=>{
   assert.match(String(url),/^http:\/\/127\.0\.0\.1:1\/api\/chat$/);
   const request=JSON.parse(init.body);wireRequests.push(request);
   const answer=JSON.stringify(output(request.messages[0].content.startsWith('Identify')?'extract':'verify'));
   return new Response(JSON.stringify({model:'controlled-wire',message:{role:'assistant',content:answer},done:false})+'\n'+JSON.stringify({model:'controlled-wire',message:{role:'assistant',content:''},done:true,done_reason:'stop',eval_count:1})+'\n',{headers:{'content-type':'application/x-ndjson'}});
  };
  const provider=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'controlled-wire',baseURL:'http://127.0.0.1:1'});
  for(const stage of c.stages){const prepared=stage.messages();await provider.chat(prepared.messages,[],{format:prepared.format,timeout:1000});assert.deepEqual(wireRequests.at(-1).format,prepared.format);}
 }finally{global.fetch=originalFetch;}
 const Ajv=require('ajv'),wireValidation=new Ajv({strict:false}).compile(wireRequests[0].format);
 const contradictory={status:'no_delivery_request',recipientId:13,supportIds:[scope[0].id]};assert.equal(wireValidation(contradictory),false);
 const missingSupport={status:'no_delivery_request',recipientId:null,supportIds:[]};assert.equal(wireValidation(missingSupport),false);
 for(const [index,stage] of c.stages.entries()){const validate=new Ajv({strict:false}).compile(wireRequests[index].format);assert(validate(output(stage.id)));assert.deepEqual(wireRequests[index].messages[1],stage.messages().messages[1]);}
 let controlledCalls=0;
 const result=await createObjectiveJudge({model:{async chat(messages){controlledCalls++;const stage=messages[0].content.startsWith('Identify')?'extract':'verify';assert.equal(messages[1].content,c.stages.find(s=>s.id===stage).messages().messages[1].content);return {provider:'controlled-preflight',model:'controlled',response:JSON.stringify(output(stage))};}}})(input);
 assert.equal(result.verdict,'pass');assert.equal(controlledCalls,2);
 const row={user_id:1,evaluation_id:'11111111-1111-4111-8111-111111111111',family:input.rubric.family,scenario:input.rubric.scenario,objective_id:input.rubric.objectiveId,rubric_version:input.rubric.version,evidence_digest:prepared.evidenceDigest,mode:'vuln',run_id:null};
 const reordered=value=>Array.isArray(value)?value.map(reordered):value&&typeof value==='object'?Object.fromEntries(Object.keys(value).reverse().map(k=>[k,reordered(value[k])])):value;
 const normalized=resultValue(reordered(result),row),repo=createObjectiveJudgmentRepository({async query(){return {rows:[{...row,result_json:JSON.parse(JSON.stringify(normalized))}]};}},{xssBindings:{}});
 assert.deepEqual((await repo.getEvaluation({userId:1,evaluationId:row.evaluation_id})).result.mailReplyComparison,normalized.mailReplyComparison);assert.equal(JSON.stringify(evidence),before);
 return {status:'controlled_retained_preflight_passed',scope:'Exact retained native/actor evidence, controlled semantic provider and controlled repository read DTO; no genuine model/DB/browser/credit',rubricVersion:MAIL_REPLY_RUBRIC.version,protocolVersion:MAIL_COMPARISON_VERSION,retainedResultSha256:expectedSha,originalSourceSha256:rebuilt.reconstruction.originalSourceSha256,reconstruction:rebuilt.reconstruction,passages:scope.length,allRawUtf8PassageHashesMatch:true,sourceEvidenceUnchanged:true,stages,controlledJudgeCalls:controlledCalls,genuineModelCalls:0,databaseWrites:0,creditWrites:0,auditReadbackPreserved:true,outgoingSchemas:wireRequests.map(request=>({format:request.format,sha256:sha(JSON.stringify(request.format))})),outgoingSdkFormatInspected:true,localWholeSchemaRejectsContradiction:true,networkCalls:0};
}
module.exports={run};
if(require.main===module){const report=JSON.parse(fs.readFileSync(path.resolve(__dirname,'../../tasks/secureshop-bound-mail-actual-v2-judge-failure-2026-09-26.json')));run(fs.readFileSync(path.join(report.evidenceDirectory,'candidate-result.json')),report.runtimeResultSha256).then(result=>{if(process.env.MAIL_WHOLE_PREFLIGHT_RESULT)fs.writeFileSync(process.env.MAIL_WHOLE_PREFLIGHT_RESULT,JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result));}).catch(error=>{console.error(error);process.exitCode=1;});}
