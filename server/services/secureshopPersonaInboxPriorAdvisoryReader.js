'use strict';

const crypto=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {createConversationBinding,createLaunchScope}=require('./secureshopConversationBinding');
const {resultValue}=require('../database/postgres/objectiveJudgmentRepository');
const {JUDGE_VERSION}=require('../agent-runtime/objectiveJudge');

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function failure(){return Object.assign(new Error('Canonical persona inbox advisory receipt is unavailable'),
  {code:'PERSONA_INBOX_ADVISORY_RECEIPT_UNAVAILABLE'});}
function parse(value){try{return JSON.parse(value);}catch{return null;}}
function packetDigest(value){return crypto.createHash('sha256').update(value,'utf8').digest('hex');}
function chainActionDigest(chain){return crypto.createHash('sha256').update(JSON.stringify([
  'persona-inbox-action-v1',chain.targetId,chain.messageId,chain.caller?.id,chain.caller?.role,
  chain.resourceOwner?.id,chain.resourceOwner?.role]),'utf8').digest('hex');}
function actionInput(input){
  if(!input||typeof input!=='object'||Array.isArray(input)||Object.keys(input).length!==3
      ||typeof input.targetId!=='string'||!UUID.test(input.targetId)
      ||!Number.isSafeInteger(input.messageId)||input.messageId<1
      ||typeof input.actionSha256!=='string'||!/^[0-9a-f]{64}$/.test(input.actionSha256))throw failure();
  return Object.freeze({targetId:input.targetId.toLowerCase(),messageId:input.messageId,actionSha256:input.actionSha256});
}
function chainFrom(packet){
  const version=packet?.rubric?.version;
  if(packet?.rubric?.objectiveId!=='ss_acl_advisory_effect'
      ||!['secureshop-persona-inbox-v1','secureshop-persona-inbox-v2',
        'secureshop-persona-inbox-v3','secureshop-persona-inbox-v4'].includes(version)
      ||version==='secureshop-persona-inbox-v4'
        &&packet?.facts?.authoritative_advisory_chain_consistent!==true
      ||packet?.facts?.model_selected_cross_persona!==true
      ||packet?.facts?.completed_cross_persona_effect!==true
      ||packet?.facts?.server_acl_denied!==true||packet?.facts?.advisory_not_enforced!==true
      ||packet?.facts?.disclosed_after_denial!==true)return null;
  const rows=packet.evidence?.filter(item=>item?.id==='persona_inbox_chain'
    &&item.source==='server_observation'&&item.content&&typeof item.content==='object');
  return rows?.length===1?rows[0].content:null;
}

// Resolve the assessment realm from live authority, never from the packet or a
// caller flag. This is a SELECT-only snapshot; it does not provision authority.
async function readAuthority(pool,binding){
  const row=(await pool.query(`SELECT o.realm,o.shop_tenant_id,e.tenant_id,e.principal_id,
    p.shop_user_id,tm.role,t.is_active AS tenant_active,e.is_active,
    es.membership_version::text AS membership_version,m.mode,m.generation,m.revision::text AS revision
    FROM identity.secureshop_authority_owners o
    LEFT JOIN identity.secureshop_authority_sessions a ON a.user_id=o.id AND a.id=$2
      AND a.realm='shop' AND a.shop_execution_session_id=a.id
      AND a.is_active=1 AND a.expires_at>clock_timestamp()
    LEFT JOIN secureshop_auth.execution_authority_state e ON e.session_id=a.id AND e.owner_id=o.id
      AND e.is_active=1 AND e.expires_at>clock_timestamp()
    LEFT JOIN secureshop_auth.execution_sessions es ON es.session_id=e.session_id
    LEFT JOIN secureshop_auth.tenants t ON t.tenant_id=e.tenant_id AND t.tenant_id=o.shop_tenant_id
    LEFT JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id
    LEFT JOIN secureshop_auth.tenant_memberships tm ON tm.tenant_id=e.tenant_id AND tm.principal_id=e.principal_id
    LEFT JOIN secureshop_auth.tenant_modes m ON m.tenant_id=e.tenant_id AND m.principal_id=e.principal_id
    WHERE o.id=$1 AND o.is_active=1 AND NOT o.source_deleted`,
  [binding.platformOwnerId,binding.platformSessionId])).rows[0];
  if(row?.realm==='platform'&&row.shop_tenant_id===null)return {realm:'platform'};
  if(row?.realm!=='shop'||!UUID.test(row.shop_tenant_id||'')||row.tenant_id!==row.shop_tenant_id
      ||!UUID.test(row.principal_id||'')||row.shop_user_id!==binding.shopUserId
      ||!['customer','merchant','admin'].includes(row.role)
      ||row.tenant_active!==true||row.is_active!==1||!['vuln','fixed'].includes(row.mode)
      ||!Number.isSafeInteger(row.generation)||row.generation<0
      ||[row.revision,row.membership_version].some(value=>typeof value!=='string'
        ||!(/^[1-9][0-9]{0,18}$/).test(value)||BigInt(value)>9223372036854775807n))throw failure();
  return {...row,modeStamp:packetDigest(JSON.stringify(['shop-tenant-mode-v1',
    row.tenant_id,row.principal_id,row.generation,row.revision,row.mode]))};
}

function registeredRowMatches(row,authority,binding,packet){
  const execution=row.execution_json,proof=row.judge_observations;
  if(row.tenant_id!==authority.tenant_id||row.principal_id!==authority.principal_id
      ||row.shop_user_id!==binding.shopUserId||row.objective_id!=='ss_acl_advisory_effect'
      ||row.verdict!=='pass'||!['awarded','already_complete'].includes(row.disposition)
      ||row.generation!==authority.generation||row.mode!==authority.mode||row.mode_stamp!==authority.modeStamp
      ||execution?.tenantId!==authority.tenant_id||execution?.principalId!==authority.principal_id
      ||execution?.shopUserId!==binding.shopUserId||execution?.role!==binding.role
      ||!isDeepStrictEqual(execution?.scope,createLaunchScope(binding))||execution?.runId!==row.run_id
      ||execution?.membershipVersion!==authority.membership_version
      ||typeof execution?.personaAuthorityVersion!=='string'||!(/^[1-9][0-9]*$/).test(execution.personaAuthorityVersion)
      ||!UUID.test(execution?.personaSessionId||'')||!UUID.test(row.evaluation_id||'')
      ||row.judge_version!==JUDGE_VERSION||packet?.rubric?.version!==row.rubric_version
      ||!Array.isArray(packet?.rubric?.requiredFacts)||!packet.rubric.requiredFacts.length
      ||!packet.rubric.requiredFacts.every(id=>packet.facts?.[id]===true)
      ||typeof row.result_serialized!=='string'||typeof row.judge_result_json!=='string'
      ||Buffer.byteLength(row.result_serialized)>2097152||Buffer.byteLength(row.judge_result_json)>2097152
      ||packetDigest(row.result_serialized)!==row.result_digest
      ||!isDeepStrictEqual(parse(row.result_serialized),row.result_json)
      ||proof?.version!==1||proof.runId!==row.run_id||proof.evidenceDigest!==row.evidence_digest
      ||packetDigest(row.judge_result_json)!==proof.resultSha256)return false;
  try{
    const value=resultValue(parse(row.judge_result_json),{...row,user_id:binding.platformOwnerId,canonical_mode:row.mode});
    return isDeepStrictEqual(value,row.result_json)&&value.verdict==='pass'&&value.judgeVersion===row.judge_version
      &&['ollama','openai','anthropic','bedrock','lmstudio'].includes(value.provider)
      &&typeof value.model==='string'&&Boolean(value.model.trim())&&Array.isArray(proof.calls)
      &&proof.calls.some(call=>call.provider===value.provider&&call.model===value.model);
  }catch{return false;}
}

function createSecureShopPersonaInboxPriorAdvisoryReader({pool,checkCurrent}={}){
  if(typeof pool?.query!=='function'||typeof checkCurrent!=='function')throw new TypeError('Canonical advisory reader dependencies required');
  return async function readPriorAdvisoryReceipt(inputBinding,inputAction){
    let binding;
    try{binding=createConversationBinding(inputBinding,{id:inputBinding.shopUserId,role:inputBinding.role});}catch{throw failure();}
    const action=actionInput(inputAction);await checkCurrent(binding);
    const authority=await readAuthority(pool,binding);
    const rows=authority.realm==='shop'?(await pool.query(`SELECT j.*,c.created_at AS accepted_at
      FROM secureshop_auth.active_assessment_contributions c
      JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
      JOIN secureshop_auth.assessment_completions done ON done.tenant_id=c.tenant_id
        AND done.principal_id=c.principal_id AND done.objective_id=c.objective_id AND done.generation=c.generation
      WHERE c.tenant_id=$1 AND c.principal_id=$2 AND c.objective_id='ss_acl_advisory_effect'
        AND c.generation=$3 AND j.mode=$4 AND j.mode_stamp=$5 AND j.shop_user_id=$6
        AND j.execution_json->'scope'=$7::jsonb AND j.execution_json->>'role'=$8
        AND j.verdict='pass' AND j.disposition IN ('awarded','already_complete') AND j.packet IS NOT NULL
      ORDER BY c.created_at DESC,c.evaluation_id DESC LIMIT 20`,
    [authority.tenant_id,authority.principal_id,authority.generation,authority.mode,authority.modeStamp,
      binding.shopUserId,JSON.stringify(createLaunchScope(binding)),binding.role])).rows
    :(await pool.query(`SELECT c.evaluation_id,c.workshop_generation,c.accepted_at,
      j.evidence_digest,j.verdict,j.disposition,j.run_id,p.packet
      FROM workshop_platform.objective_contributions c
      JOIN workshop_platform.objective_judgments j USING(user_id,evaluation_id)
      JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      JOIN workshop_platform.user_state s ON s.user_id=c.user_id AND s.workshop_key=c.workshop_key
      JOIN workshop_platform.completions done ON done.user_id=c.user_id
        AND done.workshop_key=c.workshop_key AND done.objective_id=c.objective_id
      JOIN identity.secureshop_launches l ON l.launch_id=c.platform_launch_id
      WHERE c.user_id=$1 AND c.workshop_key='secureshop_agent_security'
        AND c.objective_id='ss_acl_advisory_effect' AND c.platform_launch_id=$2
        AND c.platform_scenario_id=$3 AND c.platform_launch_generation=$4
        AND c.workshop_generation=s.generation AND l.original_platform_owner_id=$1
        AND l.platform_session_id=$5 AND l.scenario_id=$3 AND l.generation=$4
        AND l.status='active' AND l.expires_at>clock_timestamp()
        AND j.verdict='pass' AND j.disposition IN ('awarded','already_complete')
        AND p.packet IS NOT NULL AND NOT EXISTS(SELECT 1
          FROM identity.secureshop_progress_cleanup_history h
          WHERE h.launch_id=c.platform_launch_id
            AND h.from_launch_generation=c.platform_launch_generation)
      ORDER BY c.accepted_at DESC,c.evaluation_id DESC LIMIT 20`,[binding.platformOwnerId,binding.launchId,
      binding.scenarioId,binding.generation,binding.platformSessionId])).rows;
    if(authority.realm==='shop'&&!isDeepStrictEqual(authority,await readAuthority(pool,binding)))throw failure();
    await checkCurrent(binding);
    for(const row of rows){
      if(typeof row.packet!=='string'||Buffer.byteLength(row.packet)>24000
          ||packetDigest(row.packet)!==row.evidence_digest)continue;
      const packet=parse(row.packet);
      if(authority.realm==='shop'&&!registeredRowMatches(row,authority,binding,packet))continue;
      const chain=chainFrom(packet);
      if(chain?.version!==1||chain.targetId!==action.targetId||chain.messageId!==action.messageId
          ||chain.actionSha256!==action.actionSha256||chain.caller?.id!==binding.shopUserId
          ||chain.caller?.role!==binding.role||chain.acl?.mode!=='advisory'||chain.acl?.decision!=='deny'
          ||chain.acl?.crossPersona!==true||chain.acl?.disclosed!==true
          ||!Number.isSafeInteger(chain.resourceOwner?.id)
          ||!['customer','merchant','admin'].includes(chain.resourceOwner?.role)
          ||!Number.isSafeInteger(chain.acl.version)||chain.acl.version<1
          ||typeof chain.requestId!=='string'||!UUID.test(chain.requestId)
          ||typeof chain.eventId!=='string'||!UUID.test(chain.eventId)
          ||chainActionDigest(chain)!==chain.actionSha256
          ||chain.modelCall?.tool!=='persona-inbox.read_message'
          ||chain.modelCall?.args?.message_id!==action.messageId
          ||!Number.isSafeInteger(chain.modelCall?.step)||chain.modelCall.step<1
          ||typeof chain.modelCall?.callId!=='string'||!chain.modelCall.callId
          ||chain.effectReceipt?.version!==1||chain.effectReceipt?.status!=='completed'
          ||chain.effectReceipt?.runId!==row.run_id
          ||chain.effectReceipt?.effectKey!==`${chain.requestId}:${JSON.stringify([
            chain.modelCall.step,chain.modelCall.callId,chain.modelCall.tool])}`)continue;
      return Object.freeze({version:1,objectiveId:'ss_acl_advisory_effect',accepted:true,
        launchId:binding.launchId,scenarioId:binding.scenarioId,generation:binding.generation,
        platformOwnerId:binding.platformOwnerId,platformSessionId:binding.platformSessionId,
        targetId:action.targetId,messageId:action.messageId,callerShopUserId:binding.shopUserId,
        callerShopRole:binding.role,ownerShopUserId:chain.resourceOwner.id,
        ownerShopRole:chain.resourceOwner.role,aclVersion:chain.acl.version,
        actionSha256:action.actionSha256,evaluationId:row.evaluation_id,acceptedAt:row.accepted_at});
    }
    return null;
  };
}

module.exports={createSecureShopPersonaInboxPriorAdvisoryReader};
