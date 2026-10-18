'use strict';
const {inventoryGradingProjection}=require('./secureshopInventoryGradingProjection');
const {OBJECTIVE}=require('./secureshopInventoryEvidence');
const {fail}=require('./secureshopInventoryContract');
const {UUID}=require('./secureshopCouponContract');
const {createHash}=require('node:crypto');
const {isDeepStrictEqual:equal}=require('node:util');
const {createLaunchScope,createConversationBinding}=require('./secureshopConversationBinding');
const {validateRecoveryPacket,resultValue}=require('../database/postgres/objectiveJudgmentRepository');
const {JUDGE_VERSION}=require('../agent-runtime/objectiveJudge');
const unavailable=()=>fail('INVENTORY_EVIDENCE_UNAVAILABLE');
const digest=value=>createHash('sha256').update(value).digest('hex');
function sameExecution(row,expected){
 const binding=row?.execution_json;
 return binding&&Object.keys(expected).every(key=>equal(binding[key],expected[key]));
}
function validResult(row,platformOwnerId){
 if(!row?.verdict||!row.result_json||!(/^[a-f0-9]{64}$/).test(row.result_digest||'')
   ||typeof row.result_serialized!=='string'||digest(row.result_serialized)!==row.result_digest
   ||!equal(JSON.parse(row.result_serialized),row.result_json)
   ||row.result_json.verdict!==row.verdict
   ||(row.disposition==='awarded'||row.disposition==='already_complete')&&row.verdict!=='pass'
   ||(row.verdict==='pass'&&!row.judge_result_json))throw unavailable();
 if(row.judge_result_json){
  const proof=row.judge_observations;
  if(proof?.version!==1||proof.runId!==row.run_id||proof.evidenceDigest!==row.evidence_digest
    ||proof.resultSha256!==digest(row.judge_result_json)
    ||!equal(resultValue(JSON.parse(row.judge_result_json),{...row,user_id:platformOwnerId,canonical_mode:row.mode}),row.result_json))throw unavailable();
  if(row.verdict==='pass'&&['awarded','already_complete'].includes(row.disposition)
    &&(row.result_json.judgeVersion!==JUDGE_VERSION||row.judge_version!==JUDGE_VERSION
      ||!Array.isArray(proof.calls)||!proof.calls.some(call=>call.provider===row.result_json.provider
        &&call.model===row.result_json.model)))throw unavailable();
 }
}
async function readShopInventoryGrading({outcome,input,identityPool,tenantId,check}){
 const scope=createLaunchScope(input.scope),metadata=outcome.taskMetadata.inventory;
 const effects=metadata.effects,evaluationId=metadata.grading?.judgment?.evaluationId;
 if(!UUID.test(evaluationId||'')||!Array.isArray(effects)||!effects.length
   ||!Array.isArray(metadata.receipts)||!metadata.receipts.length)throw unavailable();
 await check();
 const authority=(await identityPool.query(`SELECT e.tenant_id,e.principal_id,p.shop_user_id,
  s.membership_version::text AS membership_version,m.role
  FROM secureshop_auth.execution_authority_state e
  JOIN secureshop_auth.execution_sessions s ON s.session_id=e.session_id
  JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
  JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=e.tenant_id AND m.principal_id=e.principal_id
  WHERE e.session_id=$1 AND e.owner_id=$2 AND e.tenant_id=$3 AND e.is_active=1
   AND e.expires_at>clock_timestamp() AND p.shop_user_id=$4 AND m.role='merchant'
   AND m.is_active AND m.membership_version=s.membership_version`,
 [scope.platformSessionId,scope.platformOwnerId,tenantId,input.persona.id])).rows;
 await check();
 if(authority.length!==1||authority[0].role!==input.persona.role)throw unavailable();
 const actor=authority[0],expected={tenantId:actor.tenant_id,principalId:actor.principal_id,
  shopUserId:Number(actor.shop_user_id),membershipVersion:actor.membership_version,scope,
  personaSessionId:input.personaSession.sessionId,personaAuthorityVersion:input.personaSession.authorityVersion,
  role:'merchant'};
 const rows=(await identityPool.query(`SELECT j.*,r.child_id AS child_evaluation_id,
  m.mode AS live_mode,m.generation AS live_generation,m.revision::text AS live_revision,
  g.generation::text AS live_owner_generation
  FROM secureshop_auth.assessment_judgments j
  LEFT JOIN secureshop_auth.assessment_retries r ON r.tenant_id=j.tenant_id
   AND r.principal_id=j.principal_id AND r.parent_id=j.evaluation_id
  JOIN secureshop_auth.tenant_modes m ON m.tenant_id=j.tenant_id AND m.principal_id=j.principal_id
  LEFT JOIN graph_runtime.owners g ON g.owner_key=j.owner_key
  WHERE j.tenant_id=$1 AND j.principal_id=$2 AND j.evaluation_id=$3`,
 [actor.tenant_id,actor.principal_id,evaluationId])).rows;
 await check();
 if(rows.length!==1)throw unavailable();
 const parent=rows[0],effect=effects.find(item=>item?.runId===parent.run_id
  &&item.ownerKey===parent.owner_key&&String(item.generation)===String(parent.owner_generation));
 const modeStamp=digest(JSON.stringify(['shop-tenant-mode-v1',actor.tenant_id,
  actor.principal_id,parent.live_generation,parent.live_revision,parent.live_mode]));
 if(!effect||parent.workshop_key!=='secureshop_agent_security'||parent.objective_id!==OBJECTIVE
  ||parent.evaluation_id!==evaluationId||parent.run_id!==effect.runId
  ||parent.owner_key!==effect.ownerKey||String(parent.owner_generation)!==String(effect.generation)
  ||String(parent.owner_generation)!==parent.live_owner_generation
  ||parent.generation!==parent.live_generation||parent.mode!==parent.live_mode
  ||parent.mode_stamp!==modeStamp||!sameExecution(parent,{...expected,
    runId:effect.runId,ownerKey:effect.ownerKey,ownerGeneration:String(effect.generation)})
  ||parent.verdict!=='unavailable'||parent.disposition!=='not_pass')throw unavailable();
 try{validResult(parent,scope.platformOwnerId)}catch{throw unavailable()}
 try{validateRecoveryPacket(parent.packet,parent.evidence_digest);}catch{throw unavailable();}
 let packet;try{packet=JSON.parse(parent.packet)}catch{throw unavailable()}
 const raw=packet?.evidence?.find(item=>item.id==='inventory_stock'&&item.source==='server_observation')?.content?.raw;
 if(packet?.rubric?.objectiveId!==OBJECTIVE||raw?.context?.requestId!==input.requestId
  ||raw?.execution?.runId!==effect.runId||raw?.execution?.ownerKey!==effect.ownerKey
  ||String(raw?.execution?.durableGeneration)!==String(effect.generation)
  ||!equal(raw?.context?.binding,createConversationBinding(scope,input.persona))
  ||!metadata.receipts.some(entry=>equal(entry,raw.entry)))throw unavailable();
 if(!parent.child_evaluation_id)return{status:'evaluated',completed:false,
  judgment:{evaluationId,verdict:'unavailable',canRetry:false}};
 if(!UUID.test(parent.child_evaluation_id))throw unavailable();
 const children=(await identityPool.query(`SELECT * FROM secureshop_auth.assessment_judgments
  WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3`,
 [actor.tenant_id,actor.principal_id,parent.child_evaluation_id])).rows;
 await check();
 if(children.length!==1)throw unavailable();
 const child=children[0];
 if(!sameExecution(child,{...expected,ownerKey:effect.ownerKey,ownerGeneration:String(effect.generation)})
  ||child.evaluation_id!==parent.child_evaluation_id
  ||child.shop_user_id!==parent.shop_user_id||child.packet!==parent.packet
  ||['workshop_key','objective_id','family','scenario','rubric_version','evidence_digest',
    'run_id','generation','mode','mode_stamp','owner_key','owner_generation','judge_version']
    .some(key=>child[key]!==parent[key]))throw unavailable();
 const invocations=(await identityPool.query(`SELECT 1 FROM secureshop_auth.assessment_retry_invocations
  WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3 AND run_id=$4 AND execution_json=$5::jsonb`,
 [actor.tenant_id,actor.principal_id,evaluationId,child.execution_json?.runId,
  JSON.stringify(child.execution_json)])).rows;
 await check();if(invocations.length!==1)throw unavailable();
 if(child.verdict){try{validResult(child,scope.platformOwnerId)}catch{throw unavailable()}}
 await check();
 return child.verdict?inventoryGradingProjection({completed:['awarded','already_complete'].includes(child.disposition),
  judgment:{evaluationId:child.evaluation_id,verdict:child.verdict,canRetry:false}})
  :{status:'evaluated',completed:false,judgment:{evaluationId,verdict:'unavailable',canRetry:false}};
}
// Resolve only a canonical child of this persisted stock turn. Reads never retry.
async function readInventoryGrading({outcome,input,receipts,isEnabled,check,identityPool}){
 await check();if(!await isEnabled(input.scope)){await check();return{status:'disabled',completed:false};}
 let result=inventoryGradingProjection(outcome?.taskMetadata?.inventory?.grading);
 if(result.judgment?.verdict==='unavailable'){
  if(identityPool){
   const owner=(await identityPool.query(`SELECT realm,shop_tenant_id FROM identity.secureshop_authority_owners
     WHERE id=$1 AND is_active=1`,[input.scope.platformOwnerId])).rows[0];await check();
   if(owner?.realm==='shop'&&owner.shop_tenant_id){
    result=await readShopInventoryGrading({outcome,input,identityPool,tenantId:owner.shop_tenant_id,check});
    await check();if(!await isEnabled(input.scope)){await check();return{status:'disabled',completed:false}}
    await check();return result;
   }
   if(owner?.realm!=='platform'||owner.shop_tenant_id!==null)throw unavailable();
  }
  const metadata=outcome.taskMetadata.inventory,evaluationId=result.judgment.evaluationId,scope=input.scope;
  const parent=await receipts.getRecovery({userId:scope.platformOwnerId,evaluationId});await check();
  // Use the canonical eligibility projection (expiry, version, budget, mode,
  // catalog and persona), never the immutable initial canRetry snapshot.
  const eligible=parent?await receipts.listRecoverable({userId:scope.platformOwnerId,evaluationId,judgeVersion:require('../agent-runtime/objectiveJudge').JUDGE_VERSION}):[];await check();
  result={...result,judgment:{...result.judgment,canRetry:eligible.find(row=>row.evaluationId===evaluationId)?.canRetry===true}};
  if(parent?.child_evaluation_id){
   const effect=metadata.effects?.[0];
   if(!UUID.test(parent.child_evaluation_id)||parent.workshop_key!=='secureshop_agent_security'||parent.objective_id!==OBJECTIVE||parent.platform_launch_id!==scope.launchId||parent.platform_scenario_id!==scope.scenarioId||Number(parent.platform_launch_generation)!==scope.generation
    ||parent.run_id!==effect?.runId||parent.owner_key!==effect?.ownerKey||String(parent.owner_generation)!==String(effect?.generation))throw fail('INVENTORY_EVIDENCE_UNAVAILABLE');
   await receipts.assertRecoveryAuthority({userId:scope.platformOwnerId,evaluationId});await check();
   const child=await receipts.getRecovery({userId:scope.platformOwnerId,evaluationId:parent.child_evaluation_id});await check();
   if(!child||child.evaluation_id!==parent.child_evaluation_id||['workshop_key','objective_id','evidence_digest','run_id','generation','mode','canonical_mode','mode_stamp','platform_launch_id','platform_scenario_id','platform_launch_generation','owner_key','owner_generation'].some(key=>child[key]!==parent[key]))throw fail('INVENTORY_EVIDENCE_UNAVAILABLE');
   await receipts.assertRecoveryAuthority({userId:scope.platformOwnerId,evaluationId:child.evaluation_id});await check();
   if(child.verdict)result=inventoryGradingProjection({completed:['awarded','already_complete'].includes(child.disposition),judgment:{evaluationId:child.evaluation_id,verdict:child.verdict,canRetry:false}});
  }
 }
 await check();if(!await isEnabled(input.scope)){await check();return{status:'disabled',completed:false};}await check();return result;
}
module.exports={readInventoryGrading};
