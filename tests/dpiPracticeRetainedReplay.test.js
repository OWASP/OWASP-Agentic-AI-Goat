'use strict';
if(process.env.OWASP_AI_GOAT_RETAINED_EVIDENCE_TESTS!=='1')throw Error('Retained-evidence qualification requires OWASP_AI_GOAT_RETAINED_EVIDENCE_TESTS=1 and its original local artifacts; this is not a portable unit suite.');
// Controlled replay of retained real-model bytes. No new model, app DB, or actor credit proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const ROOT=path.resolve(__dirname,'../backups/private-recovery/dpi-browser/run-orq3gf9w');
const hashes=['b4198b7b0f63221840f0c01dfa27dc60c74ff09290f0081e85bee90049a80bbf','917022070a96692825d18e082fc5c6d71d166af3a60160d919df60130ecb8c53','2d0f905b93ae2ba85afab33ca7da0363cc409ba234f1e54fae74632445604ff6'];
const WIRE='fe66aa3604b64ff3b84784395b40c1accbc9d6e2550c7f68c2326fc990a4cb5c';
const sha=b=>createHash('sha256').update(b).digest('hex');
function load(file,expected){const bytes=fs.readFileSync(file);assert.equal(sha(bytes),expected);return JSON.parse(bytes);}
function finalMessage(call){const frames=call.response.split('\n').filter(Boolean).map(JSON.parse);assert.equal(frames.at(-1).done,true);assert.equal(frames.at(-1).done_reason,'stop');return frames.map(f=>f.message?.content||'').join('');}
test('retained practice turns retain exact current Judge input and fail → threshold → award',async()=>{
 const service=require('../server/services/promptInjectionWorkshop'),judge=require('../server/agent-runtime/objectiveJudge'),proofs=require('../server/agent-runtime/dpiActorProof'),policy=require('../server/agent-runtime/dpiPolicyContract');
 const repo=require('../server/database/postgres/objectiveJudgmentRepository');
 const wire=load(path.join(ROOT,'dpi-actual-model-wire.json'),WIRE),calls=wire.calls.slice(0,6);assert.equal(calls.length,6);
 let count=0,completion=false;
 for(let i=0;i<3;i++){
  const retained=load(path.join(ROOT,`dpi-baseline-language-turn-${String(i+1).padStart(2,'0')}-raw.json`),hashes[i]);
  const old=retained.receipt.result_json,actorRequest=JSON.parse(calls[2*i].request),oldJudgeRequest=JSON.parse(calls[2*i+1].request);
  assert.equal(calls[2*i].status,200);assert.equal(calls[2*i+1].status,200);
  const oldEvidence=JSON.parse(oldJudgeRequest.messages[1].content);
  const request=oldEvidence.find(x=>x.id==='request').content,response=oldEvidence.find(x=>x.id==='response').content;
  assert.equal(actorRequest.messages.at(-1).content,request);assert.equal(retained.receipt.run_id,old.runId);
  assert.equal(finalMessage(calls[2*i]),response);
  const historicalActor=oldEvidence.find(x=>x.id==='owned_actor').content;
  assert.equal(historicalActor.generation,'0');
  const execution={runId:old.runId,ownerKey:historicalActor.ownerKey,durableGeneration:historicalActor.generation,async check(){}};
  const attempt={runId:old.runId,mode:'vuln',objectiveId:'interact'};
  const actorProof=proofs.createActorProof({request,response,execution,attempt,objective:'interact',messages:actorRequest.messages,selectedPolicy:policy.selectPolicy({objectiveId:'interact',mode:'vuln'}),result:{response,provider:'ollama',model:'llama3.1:8b'}});
  let packet;await service.evaluateDpiObjective(request,response,'interact',{execution,attempt,actorProof,judge:async p=>{packet=p;return{verdict:'inconclusive'};}});
  assert.equal(packet.rubric.version,'dpi-practice-v4');assert.deepEqual(packet.rubric.requiredFacts,['known_objective','response_present','request_present']);assert.deepEqual(packet.rubric.authoritativeVerdictFacts,[]);
  assert.deepEqual(packet.evidence,oldEvidence);
  const prepared=judge.prepareJudgeInput(packet);assert.equal(prepared.evidenceDigest,old.evidenceDigest);
  let seen=0,capturedMessages,capturedFormat;const model={async chat(messages,tools,options){seen++;assert.deepEqual(tools,[]);capturedMessages=messages;capturedFormat=options.format;return{response:finalMessage(calls[2*i+1]),provider:'ollama',model:'llama3.1:8b'};}};
  const replay=await judge.createObjectiveJudge({model})(packet);assert.equal(seen,1);assert.deepEqual(capturedMessages,oldJudgeRequest.messages);assert.deepEqual(capturedFormat,oldJudgeRequest.format);assert.equal(replay.verdict,old.verdict);assert.equal(replay.judgePolicyDigest,old.judgePolicyDigest);assert.deepEqual(replay.criteria,old.criteria);
  const row={user_id:1,evaluation_id:retained.receipt.evaluation_id,run_id:old.runId,workshop_key:'direct_prompt_injection',family:'DPI',scenario:'aws_assistant',objective_id:'interact',rubric_version:'dpi-practice-v4',evidence_digest:old.evidenceDigest,generation:0,mode:'vuln',canonical_mode:'vuln',mode_stamp:'default',verdict:null,disposition:'pending'};
  const queries=[];const query=async(sql,args=[])=>{queries.push(sql);
   if(sql.includes('RETURNING revision'))return{rows:[{revision:1}]};
   if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{generation:0,mode:'vuln',modeStamp:'default',is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true,workshop_key:row.workshop_key}]};
   if(sql.includes('SELECT generation FROM'))return{rows:[{generation:0}]};
   if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[{mode:'vuln',stamp:'default'}]};
   if(sql.includes('SELECT * FROM workshop_platform.objective_judgments'))return{rows:args[0]===1?[row]:[]};
   if(sql.includes('RETURNING activity_count'))return{rows:[{activity_count:++count}]};
   if(sql.startsWith('INSERT INTO workshop_platform.completions')){assert.equal(completion,false);completion=true;return{rows:[],rowCount:1};}
   if(sql.startsWith('UPDATE workshop_platform.objective_judgments')){Object.assign(row,{verdict:args[2],result_json:JSON.parse(args[3]),result_digest:args[4],disposition:args[5]});return{rows:[row]};}
   return{rows:[],rowCount:1};};
  const store=repo.createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});
  const receipt=await store.recordVerdict({userId:1,evaluationId:row.evaluation_id,result:replay});
  assert.equal(receipt.disposition,retained.receipt.disposition);
  assert.equal(receipt.result.verdict,old.verdict);
  assert.equal(count,i===0?0:i);
  assert.equal(queries.some(sql=>sql.startsWith('INSERT INTO workshop_platform.completions')),i===2);
 }
 assert.equal(completion,true);
});
