'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createCtfAdmittedAttemptRepository}=require('../server/database/postgres/ctfAdmittedAttemptRepository');
const {inputDocument}=require('../server/services/ctfPredefenseContract');
const {hashPayload}=require('../server/services/promptInjectionCTF');
const {stageDigest}=require('../server/agent-runtime/ctfStageJudge');
const {buildCtfLifecycleCommand,canonicalCtfJson}=require('../server/services/ctfLifecycleCommands');
const {buildCtfProjectionResult}=require('../server/services/ctfProjectionResults');
const id='00000000-0000-0000-0000-000000000002',runId='00000000-0000-0000-0000-000000000001';
const session={actorId:'7',sessionId:'8',rawToken:'synthetic'};
function harness(){
 const stage={id:1,stage_number:1,system_prompt:'guard',success_criteria:'secret'},scope={ownerId:'7',ownerGeneration:'1',globalRevision:'2',stageRevision:'3',participantId:'9',progressId:'10',stageId:'1'};
 const binding={...scope,ownerRevision:'4',sessionId:'8',runId,stageDigest:stageDigest(stage)},payload='input',p=hashPayload(payload);
 const input=inputDocument({version:1,binding,payload,normalizedPayload:p.normalized,payloadHash:p.hash,techniqueTag:'other',techniqueConfidence:0},JSON.stringify(Object.keys(stage).sort().map(k=>[k,stage[k]])));
 const command=buildCtfLifecycleCommand('admit_attempt',{failed:false},{actorId:'7',operationId:id,occurredAt:'2026-09-27T00:00:00.000Z',scope});
 const {commandHash,...content}=command,result=buildCtfProjectionResult(command,'1',{progressId:'10',attemptNumber:1,failedAttempts:0});
 const row={claim:{owner_id:7,session_id:8,admission_operation_id:id,run_id:runId,canonical_input:input.canonicalDocument,input_hash:input.documentHash,stage_snapshot:input.stageSnapshot},consumption:{final_disposition:'continue',failed:false,matched_payload_hash:null},admission:{ownerId:'7',ownerGeneration:'1',participantId:'9',progressId:'10',stageId:'1',attemptNumber:1,failed:false,sequence:'1'},canonical_command:canonicalCtfJson(content),command_hash:commandHash,canonical_result:result.canonicalResult,result_hash:result.resultHash,sequence:'1',state:'applied',kind:'admit_attempt',actor_id:'7',session_id:'8'};
 const calls=[];let authenticated=true;const pool={async connect(){return{async query(sql,args){calls.push({sql,args});if(sql.includes('SELECT u.id'))return{rows:authenticated?[{id:7}]:[]};if(sql.includes('row_to_json(c)'))return{rows:[row]};return{rows:[]};},release(){calls.push({sql:'release'});}};}};
 return{row,calls,deny(){authenticated=false;},load:(s=session)=>createCtfAdmittedAttemptRepository(pool).loadAdmittedAttempt(id,s)};
}
test('loads immutable applied continue evidence; closed decision binding and canonical auth first',async()=>{const h=harness(),r=await h.load();assert.equal(r.payload,'input');assert.equal(r.binding.admissionId,id);assert.equal(r.binding.ownerRevision,undefined);assert.equal(r.binding.stageNumber,1);assert(Object.isFrozen(r.stage));assert(h.calls.findIndex(x=>x.sql.includes('SELECT u.id'))<h.calls.findIndex(x=>x.sql.includes('row_to_json(c)')));assert.equal(h.calls.at(-2).sql,'COMMIT');assert(!JSON.stringify(r).includes('synthetic'));});
test('revoked session denies before private admission read and rolls back',async()=>{const h=harness();h.deny();await assert.rejects(h.load(),{code:'SESSION_REVOKED'});assert(!h.calls.some(x=>x.sql.includes('row_to_json(c)')));assert(h.calls.some(x=>x.sql==='ROLLBACK'));});
test('pending, blocked, failed or matched admissions never reach guardian input',async()=>{for(const mutate of [r=>r.state='pending',r=>r.consumption.final_disposition='payload',r=>r.consumption.failed=true,r=>r.consumption.matched_payload_hash='a'.repeat(64),r=>r.admission.failed=true]){const h=harness();mutate(h.row);await assert.rejects(h.load());}});
test('same owner different session, foreign owner and generation mismatch denied',async()=>{for(const mutate of [r=>r.claim.session_id=9,r=>r.session_id='9',r=>r.claim.owner_id=9,r=>r.admission.ownerGeneration='2',r=>r.admission.progressId='11']){const h=harness();mutate(h.row);await assert.rejects(h.load());}});
test('stored input, stage, command and receipt corruption or unrelated sequence denied',async()=>{for(const mutate of [r=>r.claim.input_hash='0'.repeat(64),r=>r.claim.stage_snapshot='[]',r=>r.command_hash='0'.repeat(64),r=>r.result_hash='0'.repeat(64),r=>r.sequence='2',r=>r.admission.attemptNumber=2]){const h=harness();mutate(h.row);await assert.rejects(h.load());}});
