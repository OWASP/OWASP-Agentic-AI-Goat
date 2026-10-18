'use strict';

// SELECT-only canonical replay. Source-specific callers reconstruct the packet;
// this reader owns the shared current principal and immutable result joins.
const {createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope}=require('./secureshopConversationBinding');
const {projectJudgment}=require('../agent-runtime/dpiSemanticCreditPolicy');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[0-9a-f]{64}$/;
const hash=value=>createHash('sha256').update(value).digest('hex');
const fail=()=>Object.assign(Error('Saved assessment unavailable'),{code:'SAVED_ASSESSMENT_UNAVAILABLE'});
function project(row){
 if(!UUID.test(row?.evaluation_id||'')||!SHA.test(row.result_digest||'')
  ||!row.result_json||!['pass','fail','inconclusive','unavailable'].includes(row.verdict)
  ||row.result_json.verdict!==row.verdict
  ||!['awarded','already_complete','not_pass','grading_unqualified'].includes(row.disposition)
  ||['awarded','already_complete'].includes(row.disposition)&&row.verdict!=='pass')throw fail();
 const serialized=row.result_serialized??JSON.stringify(row.result_json);
 if(typeof serialized!=='string'||hash(serialized)!==row.result_digest
  ||!equal(JSON.parse(serialized),row.result_json))throw fail();
 return {completed:['awarded','already_complete'].includes(row.disposition),
  judgment:{...projectJudgment({disposition:row.disposition,result:row.result_json}),
   evaluationId:row.evaluation_id,canRetry:false}};
}
function createSavedAssessmentOutcomeReader({identityPool,objectiveId,rubric,role}={}){
 if(typeof identityPool?.query!=='function'||typeof objectiveId!=='string'
  ||rubric?.objectiveId!==objectiveId||!['customer','merchant','admin'].includes(role))throw TypeError('Saved assessment dependencies required');
 return Object.freeze({async read({binding,personaSession,publication,assessmentOwnerKey,
  turnResult,prepareRetainedPacket,check}){
  if(typeof check!=='function'||typeof prepareRetainedPacket!=='function'||binding?.role!==role
   ||!turnResult||Object.keys(turnResult).sort().join(',')!=='completed,judgment'
   ||typeof turnResult.completed!=='boolean'||!UUID.test(turnResult.judgment?.evaluationId||''))throw fail();
  await check();
  const rows=(await identityPool.query(`SELECT j.*,r.child_id,to_jsonb(child) AS child_row,to_jsonb(invocation) AS child_invocation,
   e.tenant_id AS current_tenant_id,e.principal_id AS current_principal_id,
   s.membership_version::text AS current_membership_version,g.generation::text AS live_owner_generation
   FROM secureshop_auth.execution_authority_state e
   JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
   JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
   JOIN secureshop_auth.assessment_judgments j ON j.tenant_id=e.tenant_id AND j.principal_id=e.principal_id
   LEFT JOIN secureshop_auth.assessment_retries r ON r.tenant_id=j.tenant_id AND r.principal_id=j.principal_id AND r.parent_id=j.evaluation_id
   LEFT JOIN secureshop_auth.assessment_judgments child ON child.tenant_id=r.tenant_id AND child.principal_id=r.principal_id AND child.evaluation_id=r.child_id
   LEFT JOIN secureshop_auth.assessment_retry_invocations invocation ON invocation.tenant_id=j.tenant_id
    AND invocation.principal_id=j.principal_id AND invocation.parent_id=j.evaluation_id
    AND invocation.run_id::text=child.execution_json->>'runId'
   LEFT JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
   WHERE e.session_id=$1 AND e.owner_id=$2 AND e.is_active=1 AND e.expires_at>clock_timestamp()
    AND p.shop_user_id=$3 AND j.evaluation_id=$4 AND j.objective_id=$5 LIMIT 2`,
  [binding.platformSessionId,binding.platformOwnerId,binding.shopUserId,turnResult.judgment.evaluationId,objectiveId])).rows;
  await check();if(rows.length!==1)throw fail();
  const row=rows[0],execution=row.execution_json;
  if(row.evaluation_id!==turnResult.judgment.evaluationId||row.workshop_key!=='secureshop_agent_security'
   ||row.objective_id!==objectiveId||Number(row.shop_user_id)!==binding.shopUserId
   ||row.family!==rubric.family||row.scenario!==rubric.scenario||row.rubric_version!==rubric.version
   ||row.mode!=='vuln'||row.mode!==publication.mode||Number(row.generation)!==publication.generation
   ||row.mode_stamp!==publication.modeStamp||row.owner_key!==assessmentOwnerKey
   ||String(row.owner_generation)!==String(row.live_owner_generation)
   ||execution?.tenantId!==row.current_tenant_id||execution.principalId!==row.current_principal_id
   ||execution.membershipVersion!==row.current_membership_version||!equal(execution.scope,createLaunchScope(binding))
   ||execution.personaSessionId!==personaSession.sessionId||execution.personaAuthorityVersion!==personaSession.authorityVersion
   ||execution.role!==role||execution.runId!==row.run_id)throw fail();
  const prepared=await prepareRetainedPacket(row.packet,Object.freeze({runId:row.run_id,ownerKey:row.owner_key,generation:String(row.owner_generation)}));await check();
  if(prepared?.evidenceError||typeof prepared?.packet!=='string'||!SHA.test(prepared.evidenceDigest||'')
   ||hash(prepared.packet)!==prepared.evidenceDigest||prepared.packet!==row.packet
   ||prepared.evidenceDigest!==row.evidence_digest)throw fail();
  const parent=project(row);
  if(turnResult.completed!==parent.completed||!equal({...turnResult.judgment,canRetry:false},parent.judgment))throw fail();
  if(!row.child_id)return Object.freeze({...parent,replayed:true});
  const child=row.child_row;
  if(!child||child.evaluation_id!==row.child_id||child.tenant_id!==row.tenant_id||child.principal_id!==row.principal_id
   ||child.objective_id!==objectiveId||child.workshop_key!==row.workshop_key||child.run_id!==row.run_id
   ||child.family!==row.family||child.scenario!==row.scenario||child.rubric_version!==row.rubric_version
   ||child.packet!==row.packet||child.evidence_digest!==row.evidence_digest||child.generation!==row.generation
   ||child.mode!==row.mode||child.mode_stamp!==row.mode_stamp||child.owner_key!==row.owner_key
   ||String(child.owner_generation)!==String(row.owner_generation)
   ||!equal({...child.execution_json,runId:null},{...execution,runId:null}))throw fail();
  const invocation=row.child_invocation;
  if(!invocation||invocation.tenant_id!==row.tenant_id||invocation.principal_id!==row.principal_id
   ||invocation.parent_id!==row.evaluation_id||invocation.run_id!==child.execution_json?.runId
   ||!UUID.test(invocation.run_id||'')||!Number.isInteger(invocation.attempt)||invocation.attempt<1||invocation.attempt>3
   ||!equal(invocation.execution_json,child.execution_json))throw fail();
  await check();return Object.freeze({...(child.verdict?project(child):parent),replayed:true});
 }});
}
module.exports={createSavedAssessmentOutcomeReader};
