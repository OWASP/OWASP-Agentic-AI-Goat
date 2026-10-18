'use strict';
const {createRunCoordinator}=require('../agent-runtime/runCoordinator');
const {configuredRunLedger}=require('../agent-runtime/postgresRunLedger');
const {error}=require('../database/postgres/workshopPlatformSupport');
function createObjectiveRegradeService({receipts,completion,coordinatorFactory=family=>createRunCoordinator({family,ledger:configuredRunLedger()})}) {
  const coordinators=new Map();
  return async ({userId,evaluationId})=>{
    const original=await receipts.getRecovery({userId,evaluationId});
    if(!original)throw error('NOT_FOUND','Recovery evidence not found');
    // Missing columns belong to pre-persona schemas; persisted required scope
    // must never become unbound when its optional resolver is unavailable.
    const marker=original.persona_authority_required;
    if(marker!==undefined && marker!==false && marker!==true)throw error('PERSONA_EVALUATION_UNAVAILABLE','Original grading authority is unavailable');
    let authority=null;
    if(marker===true){
      if(typeof receipts.assertRecoveryAuthority!=='function')throw error('PERSONA_EVALUATION_UNAVAILABLE','Original grading authority is unavailable');
      authority=await receipts.assertRecoveryAuthority({userId,evaluationId});
      if(typeof authority?.check!=='function')throw error('PERSONA_EVALUATION_UNAVAILABLE','Original grading authority is unavailable');
      await authority.check();
    }
    let scope;
    try {scope=JSON.parse(original.owner_key);}catch{throw error('RETRY_NOT_ALLOWED','Original execution is not recoverable');}
    if(!Array.isArray(scope)||scope.length!==2||scope.some(v=>typeof v!=='string'))throw error('RETRY_NOT_ALLOWED','Invalid execution scope');
    if(!coordinators.has(scope[0]))coordinators.set(scope[0],coordinatorFactory(scope[0]));
    const audit=original.workshop_key==='secureshop_agent_security'&&original.family==='SecureShop'
      &&original.scenario==='bound_audit_summary'&&original.objective_id==='ss_audit_instruction_followed';
    const mcpTiming=require('./mcp/timing');
    const recon=scope[0]==='MCP'&&mcpTiming.isMcpReconScope({workshopKey:original.workshop_key,
      family:original.family,scenario:original.scenario,objectiveId:original.objective_id});
    const timing=audit?require('./secureshopAuditTiming').createSecureShopAuditTiming()
      :recon?mcpTiming.createMcpReconTiming():null;
    const auditDeadline=audit?timing.deadline():undefined;
    const retryJudge=audit?require('./secureshopAuditTiming').createSecureShopAuditJudge(timing):undefined;
    return coordinators.get(scope[0]).run(scope[1],audit||recon?{timeoutMs:timing.runTimeoutMs}:{},async execution=>{
      const bounded=audit?Object.freeze({...execution,auditDeadline}):execution;
      if(!authority)return completion.retry({userId,evaluationId,execution:bounded,...(retryJudge?{retryJudge}:{})});
      const guarded=Object.freeze({...bounded,async check(){
        await bounded.check();
        await authority.check();
        await bounded.check();
      }});
      await guarded.check();
      return completion.retry({userId,evaluationId,execution:guarded,...(retryJudge?{retryJudge}:{})});
    });
  };
}
let singleton;
function getObjectiveRegradeService(){
  if(process.env.PLATFORM_DATABASE_ENGINE!=='postgres')throw error('GRADE_STORE_NOT_READY','PostgreSQL grade recovery required');
  if(!singleton){
    const {pool}=require('./postgresPlatformStores').getPostgresPlatformStores();
    singleton=createObjectiveRegradeService({receipts:require('../database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository(pool),completion:require('./objectiveCompletionService').getObjectiveCompletionService()});
  }
  return singleton;
}
module.exports={createObjectiveRegradeService,getObjectiveRegradeService};
