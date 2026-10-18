'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createObjectiveJudgmentRepository,resultValue}=require('../server/database/postgres/objectiveJudgmentRepository');
const {prepareJudgeInput,JUDGE_VERSION}=require('../server/agent-runtime/objectiveJudge');
const {auditInstructionRubric}=require('../server/services/secureshopAuditJudgePacket');
const {createSourceComparison}=require('../server/agent-runtime/sourceComparisonVerifier');
const checkpoint=require('../server/agent-runtime/auditJudgeStageCheckpoint');
const parentId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',childId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',runId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
function fixture({expired=false}={}){
 const rubric=auditInstructionRubric(),evidence=[{id:'audit_log',source:'tool_result',content:'Routine inventory record.'},{id:'audit_summary',source:'assistant_response',content:'Routine inventory record.'}];
 const prepared=prepareJudgeInput({rubric,evidence,facts:Object.fromEntries(rubric.requiredFacts.map(id=>[id,true]))});
 const v=createSourceComparison(rubric.sourceComparison,evidence),sourceResult=v.validateSource(JSON.stringify({passages:[{sourceQuoteId:'q0',classification:'ordinary_content',obligation:null}],explanation:'Ordinary record.'}));
 const saved=checkpoint.checkpoint({stage:'source',runId,evidenceDigest:prepared.evidenceDigest,packetSha256:checkpoint.sha(prepared.packet),judgeVersion:JUDGE_VERSION,comparisonVersion:'source-only-obligation-verified-v6',policyDigest:'a'.repeat(64),canonicalInputSha256:'b'.repeat(64),actualRequestSha256:'c'.repeat(64),sourceCheckpointSha256:null,provider:'ollama',model:'llama3.3:70b',rawResponse:'{"passages":[{"sourceQuoteId":"q0","classification":"ordinary_content","obligation":null}],"explanation":"Ordinary record."}'});
 const row={user_id:7,evaluation_id:childId,run_id:runId,workshop_key:'secureshop_agent_security',family:'SecureShop',scenario:'bound_audit_summary',objective_id:'ss_audit_instruction_followed',rubric_version:rubric.version,evidence_digest:prepared.evidenceDigest,generation:0,mode:'vuln',canonical_mode:'vuln',mode_stamp:'default',verdict:null,disposition:null,platform_launch_id:null};
 const parent={...row,evaluation_id:parentId,packet:prepared.packet,judge_version:JUDGE_VERSION};
 const raw={family:row.family,scenario:row.scenario,objectiveId:row.objective_id,rubricVersion:row.rubric_version,evidenceDigest:row.evidence_digest,runId,mode:row.mode,verdict:'fail',criteria:[{id:'redirected_output',satisfied:false,evidenceRefs:[]}],explanation:'Ordinary content.',provider:'ollama',model:'llama3.3:70b',judgeVersion:JUDGE_VERSION,judgePolicyDigest:saved.policyDigest,comparisonVersion:'source-only-obligation-verified-v6',comparisonStages:[{stage:'source',attempts:0,completed:true,provider:saved.provider,model:saved.model}],attempts:0,semanticObservation:v.sourceOnlyResult(sourceResult).observation,auditContinuation:{version:'audit-stage-checkpoint-v1',checkpoints:[{stage:'source',checkpointSha256:saved.checkpointSha256}]}};
 const queries=[];
 const query=async(sql,args=[])=>{queries.push(sql);
  if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:row.workshop_key,is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true}]};
  if(sql.includes('SELECT generation FROM workshop_platform.user_state'))return{rows:[{generation:0}]};
  if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[{mode:'vuln',stamp:'default'}]};
  if(sql.includes('FROM workshop_platform.objective_judgments WHERE user_id')&&sql.includes('FOR UPDATE'))return{rows:[row]};
  if(sql.includes('FROM workshop_platform.objective_judgments WHERE user_id'))return{rows:[row]};
  if(sql.includes('p.child_evaluation_id=$2')){assert.match(sql,/p\.expires_at>clock_timestamp\(\)/);assert.match(sql,/FOR UPDATE OF p/);return{rows:expired?[]:[parent]};}
  if(sql.includes('FROM workshop_platform.audit_judge_stage_checkpoints'))return{rows:[{version:saved.version,stage:saved.stage,run_id:saved.runId,evidence_digest:saved.evidenceDigest,packet_sha256:saved.packetSha256,judge_version:saved.judgeVersion,comparison_version:saved.comparisonVersion,policy_digest:saved.policyDigest,canonical_input_sha256:saved.canonicalInputSha256,actual_request_sha256:saved.actualRequestSha256,source_checkpoint_sha256:null,provider:saved.provider,model:saved.model,raw_response:saved.rawResponse,response_sha256:saved.responseSha256,checkpoint_sha256:saved.checkpointSha256}]};
  if(sql.startsWith('UPDATE workshop_platform.objective_judgments')){row.verdict=args[2];row.result_json=JSON.parse(args[3]);row.result_digest=args[4];row.disposition=args[5];return{rows:[row]};}
  return{rows:[],rowCount:1};};
 const repo=createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});
 return {repo,row,raw,saved,queries};
}
test('canonical child commit requires exact stored parent checkpoint reference, not a well-formed forged digest',async()=>{
 const f=fixture();assert.equal(resultValue(f.raw,f.row).attempts,0);
 const forged={...f.raw,auditContinuation:{...f.raw.auditContinuation,checkpoints:[{stage:'source',checkpointSha256:'f'.repeat(64)}]}};
 assert.equal(resultValue(forged,f.row).auditContinuation.checkpoints[0].checkpointSha256,'f'.repeat(64));
 await assert.rejects(f.repo.recordVerdict({userId:7,evaluationId:childId,result:forged}),{code:'AUDIT_CHECKPOINT_INVALID'});
 assert.equal(f.row.verdict,null);assert.equal(f.queries.some(sql=>sql.startsWith('UPDATE workshop_platform.objective_judgments')),false);
 const committed=await f.repo.recordVerdict({userId:7,evaluationId:childId,result:f.raw});
 assert.equal(committed.verdict,'fail');assert.equal(f.row.result_json.auditContinuation.checkpoints[0].checkpointSha256,f.saved.checkpointSha256);
});
test('expired parent cannot commit a resumed child even when checkpoint bytes remain',async()=>{
 const f=fixture({expired:true});
 await assert.rejects(f.repo.recordVerdict({userId:7,evaluationId:childId,result:f.raw}),{code:'AUDIT_CHECKPOINT_INVALID'});
 assert.equal(f.row.verdict,null);assert.equal(f.queries.some(sql=>sql.startsWith('UPDATE workshop_platform.objective_judgments')),false);
});
