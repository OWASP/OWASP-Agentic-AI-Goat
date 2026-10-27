'use strict';
const {resolveAssessmentReleaseAdmission}=require('../../services/secureshopAssessmentReleaseAdmission');
const {createHash,randomUUID}=require('node:crypto');
const {canRetryJudgeError}=require('../../agent-runtime/judgeErrors');
const {isDeepStrictEqual}=require('node:util');
const {withTransaction}=require('./index');
const {subjectState}=require('../../services/secureshopAssessmentSubject');
const {createSecureShopModeRepository}=require('./secureshopModeRepository');
const {resultValue,validateRecoveryPacket}=require('./objectiveJudgmentRepository');
const {JUDGE_VERSION}=require('../../agent-runtime/objectiveJudge');
const WORKSHOP='secureshop_agent_security';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fail=(code='SHOP_ASSESSMENT_STALE')=>Object.assign(new Error('Shop assessment unavailable'),{code});
const digest=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
function createSecureShopAssessmentStore({pool,subject,assessmentReleaseAdmission}) {
  const state=subjectState(subject),b=state.binding,modeRepository=createSecureShopModeRepository(pool);
  const release=resolveAssessmentReleaseAdmission(assessmentReleaseAdmission,{identityPool:pool});
  const args=[b.tenantId,b.principalId],judgeObservations=new Map(),allowedJudgeRuns=new Set([b.runId]);
  async function observeJudge(input,judge){
    await state.check();
    const catalog=await guarded(client=>objective(client,input.rubric.objectiveId));
    if(!catalog.catalog_active||!catalog.effective_enabled||!['native-model','native-browser-judge'].includes(catalog.qualification)){
      const prepared=require('../../agent-runtime/objectiveJudge').prepareJudgeInput(input);
      return {family:input.rubric.family,scenario:input.rubric.scenario,objectiveId:input.rubric.objectiveId,
        rubricVersion:input.rubric.version,mode:input.rubric.mode,evidenceDigest:prepared.evidenceDigest,runId:b.runId,
        verdict:'inconclusive',criteria:[],explanation:'This objective is not enabled for assessment.',
        provider:null,model:null,usage:null};
    }
    const result=await judge(input);
    await state.check();
    const proof=require('../../agent-runtime/objectiveJudge').readConfiguredJudgeProvenance(result);
    if(proof&&allowedJudgeRuns.has(proof.runId))judgeObservations.set(proof.evidenceDigest,proof);
    return result;
  }
  function checkUser(userId,key=WORKSHOP){if(userId!==b.scope.platformOwnerId||key!==WORKSHOP)throw fail();}
  function evaluation(value){if(typeof value!=='string'||!UUID.test(value))throw fail('BAD_REQUEST');return value.toLowerCase();}
  async function mode(){return modeRepository.getEvaluationScope(b.scope.platformOwnerId,WORKSHOP,b.scope);}
  async function guarded(work){
    await state.check();
    await release.assertScope(b.scope);
    const result=await state.fence.withCrossStoreEffect(()=>withTransaction(pool,async client=>{
      // Every shop credential/membership/tenant change synchronously updates this
      // registry row (0139). Its shared lock fences revocation through commit.
      const registry=(await client.query(`SELECT s.id FROM identity.secureshop_authority_sessions s
        JOIN identity.secureshop_authority_owners o ON o.id=s.user_id
        WHERE s.id=$1 AND s.user_id=$2 AND s.realm='shop' AND o.realm='shop'
        AND s.shop_execution_session_id=s.id AND o.shop_tenant_id=$3
        AND s.is_active=1 AND o.is_active=1 AND s.expires_at>clock_timestamp()
        FOR SHARE OF s,o`,[b.scope.platformSessionId,b.scope.platformOwnerId,b.tenantId])).rows[0];
      if(!registry)throw fail();
      const live=(await client.query(`SELECT l.launch_id FROM identity.secureshop_launches l
        JOIN secureshop_auth.execution_authority_state e ON e.session_id=l.platform_session_id
        WHERE l.launch_id=$1 AND l.scenario_id=$2 AND l.generation=$3 AND l.status='active'
          AND l.original_platform_owner_id=$4 AND l.platform_session_id=$5
          AND l.expires_at>clock_timestamp() AND e.is_active=1 AND e.expires_at>clock_timestamp()
          AND e.tenant_id=$6 AND e.principal_id=$7 FOR SHARE OF l`,
      [b.scope.launchId,b.scope.scenarioId,b.scope.generation,b.scope.platformOwnerId,b.scope.platformSessionId,...args])).rows[0];
      if(!live)throw fail();
      const current=(await client.query('SELECT * FROM secureshop_auth.lock_assessment_mode($1,$2,$3)',
        [b.scope.platformSessionId,...args])).rows[0];
      if(!current)throw fail();
      current.modeStamp=createHash('sha256').update(JSON.stringify(['shop-tenant-mode-v1',
        ...args,current.generation,current.revision,current.mode])).digest('hex');
      const result=await work(client,current);
      // Do not reacquire agents authority while its transaction is held. The
      // enclosing persona fence and identity launch lock fence the commit.
      return result;
    }));
    await state.check();return result;
  }
  const read=(client,id,lock='')=>client.query(`SELECT * FROM secureshop_auth.assessment_judgments
    WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3 ${lock}`,[...args,evaluation(id)]).then(r=>r.rows[0]);
  function dto(row){if(!row)return null;
    if(row.verdict){
      if(!row.result_json||!/^[a-f0-9]{64}$/.test(row.result_digest||''))throw fail('JUDGMENT_INTEGRITY');
      if(row.result_serialized&&(createHash('sha256').update(row.result_serialized).digest('hex')!==row.result_digest
        ||!isDeepStrictEqual(JSON.parse(row.result_serialized),row.result_json)))throw fail('JUDGMENT_INTEGRITY');
    }
    if(row.judge_result_json){
      const proof=row.judge_observations;
      if(!proof||proof.version!==1||proof.runId!==row.run_id||proof.evidenceDigest!==row.evidence_digest
        ||createHash('sha256').update(row.judge_result_json).digest('hex')!==proof.resultSha256
        ||!isDeepStrictEqual(resultValue(JSON.parse(row.judge_result_json),{...row,user_id:b.scope.platformOwnerId,canonical_mode:row.mode}),row.result_json))throw fail('JUDGMENT_INTEGRITY');
    }
    return Object.freeze({userId:b.scope.platformOwnerId,
    evaluationId:row.evaluation_id,workshopKey:WORKSHOP,objectiveId:row.objective_id,
    family:row.family,scenario:row.scenario,rubricVersion:row.rubric_version,evidenceDigest:row.evidence_digest,
    runId:row.run_id,generation:row.generation,mode:row.mode,canonicalMode:row.mode,modeGuard:'canonical',
    verdict:row.verdict,disposition:row.disposition,result:row.result_json,createdAt:row.created_at,evaluatedAt:row.evaluated_at,
    instanceScope:{launchId:row.execution_json.scope.launchId,scenarioId:row.execution_json.scope.scenarioId,generation:row.execution_json.scope.generation}});}
  async function objective(client,id){
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`shop-objective:${b.tenantId}:${id}`]);
    const row=(await client.query(`SELECT o.*,COALESCE(c.is_enabled,o.is_enabled) AS effective_enabled
      FROM secureshop_auth.assessment_objectives o LEFT JOIN secureshop_auth.assessment_configuration c
      ON c.objective_id=o.objective_id AND c.tenant_id=$2 WHERE o.objective_id=$1`,[id,b.tenantId])).rows[0];
    if(!row)throw fail('OBJECTIVE_UNAVAILABLE');
    return release.isAllowed(id)?row:{...row,qualification:'pending'};
  }
  function sameAuthority(other){return other&&isDeepStrictEqual({...other,runId:null},{...b,runId:null});}
  function eligible(row,current,catalog){return Boolean(sameAuthority(row.execution_json)&&row.owner_key===b.ownerKey
    &&String(row.owner_generation)===b.ownerGeneration&&row.verdict==='unavailable'&&row.disposition==='not_pass'
    &&canRetryJudgeError(row.result_json?.errorCode)&&row.packet&&row.judge_version===JUDGE_VERSION
    &&new Date(row.created_at).getTime()+86400000>Date.now()&&row.generation===current.generation
    &&row.mode===current.mode&&row.mode_stamp===current.modeStamp&&catalog.catalog_active&&catalog.effective_enabled
    &&['native-model','native-browser-judge'].includes(catalog.qualification));}
  const progress=Object.freeze({
    async getEvaluationScope(uid,key){checkUser(uid,key);await state.check();return mode();},
    async getGeneration(uid,key){checkUser(uid,key);await state.check();return (await mode()).generation;},
    async getObjectiveCompletionState(uid,key,id,{expectedGeneration}){
      checkUser(uid,key);return guarded(async(client,current)=>{
        await objective(client,id);if(expectedGeneration!==current.generation)throw fail('STALE_GENERATION');
        const found=await client.query(`SELECT 1 FROM secureshop_auth.active_assessment_contributions
          WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 AND generation=$4`,[...args,id,current.generation]);
        return {generation:current.generation,completed:release.isAllowed(id)&&found.rowCount>0};
      });
    },
    async getCanonicalWorkshopCompletions(uid,key,{expectedGeneration}){
      checkUser(uid,key);return guarded(async(client,current)=>{
        if(expectedGeneration!==current.generation)throw fail('STALE_GENERATION');
        const rows=(await client.query(`SELECT DISTINCT objective_id FROM secureshop_auth.active_assessment_contributions
          WHERE tenant_id=$1 AND principal_id=$2 AND generation=$3 ORDER BY objective_id`,[...args,current.generation])).rows;
        return {generation:current.generation,objectiveIds:rows.map(row=>row.objective_id).filter(release.isAllowed)};
      });
    },
  });
  const receipts=Object.freeze({
    async beginEvaluation(input,token){
      checkUser(input.userId,input.workshopKey);if(token!==subject)throw fail();
      const id=evaluation(input.evaluationId);
      if(input.runId!==b.runId||!isDeepStrictEqual(input.instanceScope,b.scope)
        ||input.family!=='SecureShop'||typeof input.objectiveId!=='string'
        ||typeof input.scenario!=='string'||typeof input.rubricVersion!=='string'
        ||!/^([a-f0-9]{64})$/.test(input.evidenceDigest)||!['vuln','fixed'].includes(input.mode))throw fail('JUDGMENT_SCOPE_MISMATCH');
      const recovery=input.recovery;
      if(recovery?.ownerKey!==b.ownerKey||String(recovery?.ownerGeneration)!==b.ownerGeneration
        ||recovery?.judgeVersion!==JUDGE_VERSION)throw fail();
      if(recovery.packet!==null)validateRecoveryPacket(recovery.packet,input.evidenceDigest);
      return guarded(async(client,current)=>{
        await objective(client,input.objectiveId);
        if(input.expectedGeneration!==current.generation)throw fail('STALE_GENERATION');
        if(input.mode!==current.mode||input.expectedMode!==current.mode||input.expectedModeStamp!==current.modeStamp)throw fail('MODE_CHANGED');
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`shop-grade:${b.tenantId}:${b.principalId}:${id}`]);
        const previous=await read(client,id);
        if(previous){
          if(previous.run_id!==b.runId||previous.evidence_digest!==input.evidenceDigest
            ||previous.objective_id!==input.objectiveId||previous.rubric_version!==input.rubricVersion
            ||!isDeepStrictEqual(previous.execution_json,b))throw fail('IDEMPOTENCY_CONFLICT');
          return dto(previous);
        }
        const row=(await client.query(`INSERT INTO secureshop_auth.assessment_judgments
          (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,
           rubric_version,evidence_digest,run_id,generation,mode,mode_stamp,packet,judge_version,owner_key,owner_generation)
          VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) RETURNING *`,
        [...args,id,b.shopUserId,JSON.stringify(b),input.objectiveId,input.family,input.scenario,input.rubricVersion,
          input.evidenceDigest,b.runId,current.generation,current.mode,current.modeStamp,recovery.packet,
          recovery.judgeVersion,b.ownerKey,b.ownerGeneration])).rows[0];
        return dto(row);
      });
    },
    async recordVerdict({userId,evaluationId,result}){
      checkUser(userId);return guarded(async(client,current)=>{
        let row=await read(client,evaluationId);if(!row)throw fail();
        await objective(client,row.objective_id);row=await read(client,evaluationId,'FOR UPDATE');
        if(!isDeepStrictEqual(row.execution_json,b)){
          if(!sameAuthority(row.execution_json))throw fail();
          const admitted=(await client.query(`SELECT 1 FROM secureshop_auth.assessment_retries r
            JOIN secureshop_auth.assessment_retry_invocations i USING(tenant_id,principal_id,parent_id)
            WHERE r.tenant_id=$1 AND r.principal_id=$2 AND r.child_id=$3 AND i.run_id=$4 AND i.execution_json=$5::jsonb`,
            [...args,row.evaluation_id,b.runId,JSON.stringify(b)])).rowCount;
          if(admitted!==1)throw fail();
        }
        const value=isDeepStrictEqual(result,row.result_json)?row.result_json:resultValue(result,{...row,user_id:b.scope.platformOwnerId,canonical_mode:row.mode});
        if(row.verdict){if(!isDeepStrictEqual(value,row.result_json))throw fail('IDEMPOTENCY_CONFLICT');return dto(row);}
        const proof=require('../../agent-runtime/objectiveJudge').readConfiguredJudgeProvenance(result);
        const observations=proof&&proof===judgeObservations.get(row.evidence_digest)?proof:null;
        const catalog=await objective(client,row.objective_id);
        let disposition='not_pass';
        if(current.generation!==row.generation)disposition='stale_generation';
        else if(current.mode!==row.mode||current.modeStamp!==row.mode_stamp)disposition='mode_changed';
        else if(!catalog.catalog_active||!catalog.effective_enabled)disposition='hidden';
        else if(!['native-model','native-browser-judge'].includes(catalog.qualification))disposition='grading_unqualified';
        else if(value.verdict==='pass'){
          const packet=row.packet?JSON.parse(row.packet):null;
          const qualified=packet&&packet.rubric?.requiredFacts?.length>0
            &&packet.rubric.requiredFacts.every(id=>packet.facts?.[id]===true)
            &&['ollama','openai','anthropic','bedrock','lmstudio'].includes(value.provider)
            &&typeof value.model==='string'&&value.model.trim()&&value.judgeVersion===JUDGE_VERSION
            &&observations?.runId===row.run_id&&observations.evidenceDigest===row.evidence_digest
            &&observations.calls.some(call=>call.provider===value.provider&&call.model===value.model);
          if(!qualified)disposition='grading_unqualified';
          else {
            // The first-completion row is immutable historical evidence. Reset
            // retires only its exact execution contributions; a later genuine
            // result can award again without replacing that original row.
            const active=await client.query(`SELECT 1 FROM secureshop_auth.active_assessment_contributions
              WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 AND generation=$4 LIMIT 1`,
            [...args,row.objective_id,row.generation]);
            await client.query(`INSERT INTO secureshop_auth.assessment_completions
              (tenant_id,principal_id,objective_id,generation,evaluation_id) VALUES($1,$2,$3,$4,$5)
              ON CONFLICT DO NOTHING`,[...args,row.objective_id,row.generation,row.evaluation_id]);
            await client.query(`INSERT INTO secureshop_auth.assessment_contributions
              (tenant_id,principal_id,evaluation_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`,[...args,row.evaluation_id]);
            disposition=active.rowCount?'already_complete':'awarded';
          }
        }
        return dto((await client.query(`UPDATE secureshop_auth.assessment_judgments
          SET verdict=$4,disposition=$5,result_json=$6::jsonb,result_digest=$7,judge_observations=$8::jsonb,judge_result_json=$9,result_serialized=$10,evaluated_at=clock_timestamp()
          WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3 RETURNING *`,
        [...args,row.evaluation_id,value.verdict,disposition,JSON.stringify(value),digest(value),JSON.stringify(observations),observations?JSON.stringify(result):null,JSON.stringify(value)])).rows[0]);
      });
    },
    async getEvaluation({userId,evaluationId}){checkUser(userId);return guarded(async client=>dto(await read(client,evaluationId)));},
    async getRecovery({userId,evaluationId}){
      checkUser(userId);return guarded(async(client,current)=>{
        const row=await read(client,evaluationId);if(!row)return null;
        const catalog=await objective(client,row.objective_id);
        const link=(await client.query('SELECT child_id FROM secureshop_auth.assessment_retries WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3',[...args,row.evaluation_id])).rows[0];
        return {...row,expires_at:new Date(new Date(row.created_at).getTime()+86400000).toISOString(),
          child_evaluation_id:link?.child_id||null,shop_binding_current:eligible(row,current,catalog)};
      });
    },
    async beginRetry({userId,evaluationId,judgeVersion,ownerGeneration}){
      checkUser(userId);return guarded(async(client,current)=>{
        const id=evaluation(evaluationId);
        let row=await read(client,id);if(!row)throw fail('SHOP_ASSESSMENT_NOT_FOUND');
        const catalog=await objective(client,row.objective_id);
        await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`shop-grade:${b.tenantId}:${b.principalId}:${id}`]);
        row=await read(client,id,'FOR UPDATE');
        if(!sameAuthority(row.execution_json)||row.owner_key!==b.ownerKey||String(row.owner_generation)!==b.ownerGeneration
          ||String(ownerGeneration)!==b.ownerGeneration)throw fail('SHOP_ASSESSMENT_STALE');
        if(current.generation!==row.generation)throw fail('STALE_GENERATION');
        if(current.mode!==row.mode||current.modeStamp!==row.mode_stamp)throw fail('MODE_CHANGED');
        if(!catalog.catalog_active||!catalog.effective_enabled)throw fail('OBJECTIVE_DISABLED');
        if(!['native-model','native-browser-judge'].includes(catalog.qualification)||row.verdict!=='unavailable'
          ||row.disposition!=='not_pass'||!canRetryJudgeError(row.result_json?.errorCode)||!row.packet)throw fail('RETRY_NOT_ALLOWED');
        if(new Date(row.created_at).getTime()+86400000<=Date.now())throw fail('EVIDENCE_EXPIRED');
        validateRecoveryPacket(row.packet,row.evidence_digest);
        const nested=(await client.query('SELECT 1 FROM secureshop_auth.assessment_retries WHERE tenant_id=$1 AND principal_id=$2 AND child_id=$3',[...args,id])).rowCount;
        if(nested)throw fail('RETRY_NOT_ALLOWED');
        let link=(await client.query('SELECT child_id FROM secureshop_auth.assessment_retries WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3',[...args,id])).rows[0];
        let child=link?await read(client,link.child_id):null;
        if(link&&!child)throw fail();
        if(child?.verdict)return {receipt:dto(child),packet:row.packet};
        if(row.judge_version!==judgeVersion||judgeVersion!==JUDGE_VERSION)throw fail('JUDGE_VERSION_CHANGED');
        if(!child){
          child=(await client.query(`INSERT INTO secureshop_auth.assessment_judgments
            (tenant_id,principal_id,evaluation_id,shop_user_id,execution_json,objective_id,family,scenario,rubric_version,
             evidence_digest,run_id,generation,mode,mode_stamp,packet,judge_version,owner_key,owner_generation)
            SELECT tenant_id,principal_id,$4,shop_user_id,$5::jsonb,objective_id,family,scenario,rubric_version,
              evidence_digest,run_id,generation,mode,mode_stamp,packet,judge_version,owner_key,owner_generation
            FROM secureshop_auth.assessment_judgments WHERE tenant_id=$1 AND principal_id=$2 AND evaluation_id=$3 RETURNING *`,
            [...args,id,randomUUID(),JSON.stringify(b)])).rows[0];
          await client.query('INSERT INTO secureshop_auth.assessment_retries(tenant_id,principal_id,parent_id,child_id) VALUES($1,$2,$3,$4)',[...args,id,child.evaluation_id]);
        }
        const invocations=(await client.query('SELECT attempt,run_id FROM secureshop_auth.assessment_retry_invocations WHERE tenant_id=$1 AND principal_id=$2 AND parent_id=$3 ORDER BY attempt',[...args,id])).rows;
        if(!invocations.some(value=>value.run_id===b.runId)){
          if(invocations.length>=3)throw fail('RETRY_EXHAUSTED');
          await client.query(`INSERT INTO secureshop_auth.assessment_retry_invocations
            (tenant_id,principal_id,parent_id,attempt,run_id,execution_json) VALUES($1,$2,$3,$4,$5,$6::jsonb)`,
            [...args,id,invocations.length+1,b.runId,JSON.stringify(b)]);
        }
        allowedJudgeRuns.add(row.run_id);
        return {receipt:dto(child),packet:row.packet};
      });
    },
  });
  return Object.freeze({subject,progress,receipts,observeJudge});
}
module.exports={createSecureShopAssessmentStore};
