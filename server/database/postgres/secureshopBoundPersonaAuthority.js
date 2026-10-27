'use strict';
// Shared launch/persona authority; startup verifies the promoted store and grants.
const {createLaunchScope}=require('../../services/secureshopConversationBinding');

function authorityUnavailable(){return Object.assign(new Error('Persona authority store is unavailable'),{code:'PERSONA_AUTHORITY_NOT_READY'});}
async function assertAuthorityReady({pool,expectedDatabase}={}){
 if(typeof pool?.query!=='function'||typeof expectedDatabase!=='string'||!expectedDatabase)throw new TypeError('Authority readiness dependencies required');
 // Required grants are separate: a comma-separated PostgreSQL privilege list
 // accepts any listed grant. The forbidden DELETE/TRUNCATE check needs that OR.
 const {rows}=await pool.query(`SELECT current_database() AS database,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_persona_templates'),'SELECT'),false) AS templates,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_actor_identities'),'SELECT'),false) AS actors_read,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_actor_identities'),'INSERT'),false) AS actors_insert,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_actor_tenant_memberships'),'SELECT'),false) AS memberships_read,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_actor_tenant_memberships'),'INSERT'),false) AS memberships_insert,
  COALESCE(has_function_privilege(current_user,to_regprocedure('secureshop_agents.bound_actor_in_owner(integer,integer,bigint)'),'EXECUTE'),false) AS actor_owner_check,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_persona_state'),'SELECT'),false) AS state_read,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_persona_state'),'INSERT'),false) AS state_insert,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_persona_state'),'UPDATE'),false) AS state_update,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_persona_state'),'DELETE,TRUNCATE'),false) AS state_broad_write,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_persona_sessions'),'SELECT'),false) AS sessions,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_persona_credentials'),'SELECT'),false) AS credentials,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.conversation_generation_retirements'),'SELECT'),false) AS retirements,
  COALESCE(has_table_privilege(current_user,to_regclass('secureshop_agents.bound_audit_owner_deletion_receipts'),'SELECT'),false) AS deletions,
  COALESCE(has_function_privilege(current_user,to_regprocedure('secureshop_agents.guard_bound_persona_admin_state()'),'EXECUTE'),false) AS state_guard,
  COALESCE(has_function_privilege(current_user,to_regprocedure('secureshop_agents.guard_bound_persona_admin_insert()'),'EXECUTE'),false) AS insert_guard,
  COALESCE(has_function_privilege(current_user,to_regprocedure('secureshop_agents.guard_bound_persona_effective_session()'),'EXECUTE'),false) AS session_guard`);
 const row=rows[0];
 if(row?.database!==expectedDatabase||!row.templates||!row.actors_read||!row.actors_insert
   ||!row.memberships_read||!row.memberships_insert||!row.actor_owner_check
   ||!row.state_read||!row.state_insert||!row.state_update||row.state_broad_write
   ||!row.sessions||!row.credentials||!row.retirements||!row.deletions
   ||row.state_guard||row.insert_guard||row.session_guard)throw authorityUnavailable();
 return Object.freeze({ready:true,database:row.database});
}
function createSecureShopBoundPersonaAuthority({pool,checkCurrent}={}){
 if(typeof pool?.connect!=='function')throw new TypeError('Authority pool required');
 const invalid=()=>Object.assign(new Error('Shop authentication required'),{code:'SHOP_AUTH_INVALID'});
 async function resolve(client,scope,id,{role,version}={}){
  const s=createLaunchScope(scope);if(!Number.isSafeInteger(id)||id<1)throw invalid();
  const row=(await client.query(`SELECT a.shop_user_id AS id,a.username,
   COALESCE(st.effective_role,m.role,a.base_role) AS role,
   COALESCE(st.authority_version,1)::text AS authority_version,st.banned_at
   FROM secureshop_agents.bound_actor_identities a LEFT JOIN secureshop_agents.bound_persona_state st
   ON st.platform_launch_id=$1 AND st.platform_scenario_id=$2 AND st.platform_launch_generation=$3
   AND st.original_platform_owner_id=$4 AND st.original_platform_session_id=$5 AND st.shop_user_id=a.shop_user_id
   LEFT JOIN LATERAL (SELECT role FROM secureshop_agents.bound_actor_tenant_memberships
     WHERE tenant_owner_id=$4 AND shop_user_id=a.shop_user_id
     ORDER BY membership_version DESC LIMIT 1) m ON true
   WHERE a.shop_user_id=$6 AND secureshop_agents.bound_actor_in_owner(a.shop_user_id,$4)
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=$1 AND from_generation=$3)
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=$4)`,[s.launchId,s.scenarioId,s.generation,s.platformOwnerId,s.platformSessionId,id])).rows[0];
  if(!row||row.banned_at||!['customer','merchant','admin'].includes(row.role)
   ||(role!==undefined&&row.role!==role)||(version!==undefined&&row.authority_version!==version))throw invalid();
  return Object.freeze(row);
 }
 function capture({scope,personaId,sessionId,role,authorityVersion}={}) {
  const trusted=createLaunchScope(scope);
  if(typeof checkCurrent!=='function'||!Number.isSafeInteger(personaId)||personaId<1
   ||typeof sessionId!=='string'||!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(sessionId)
   ||!['customer','merchant','admin'].includes(role)||typeof authorityVersion!=='string'||!/^[1-9]\d*$/.test(authorityVersion))throw invalid();
  const binding=Object.freeze({...trusted,personaId,sessionId:sessionId.toLowerCase(),role,authorityVersion});
  async function current(c){
   await resolve(c,trusted,personaId,{role,version:authorityVersion});
   const live=(await c.query(`SELECT 1 FROM secureshop_agents.bound_persona_sessions s
    WHERE s.platform_launch_id=$1 AND s.platform_scenario_id=$2 AND s.platform_launch_generation=$3
    AND s.original_platform_owner_id=$4 AND s.original_platform_session_id=$5 AND s.shop_user_id=$6
    AND s.session_id=$7 AND s.role=$8 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
    AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,$4,s.bootstrap_membership_version)
    AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
     WHERE c.platform_launch_id=$1 AND c.platform_scenario_id=$2 AND c.platform_launch_generation=$3
     AND c.original_platform_owner_id=$4 AND c.original_platform_session_id=$5 AND c.shop_user_id=$6),1)`,
    [trusted.launchId,trusted.scenarioId,trusted.generation,trusted.platformOwnerId,trusted.platformSessionId,personaId,binding.sessionId,role])).rowCount;
   if(live!==1)throw invalid();
  }
  async function transaction(work,{externalDeadline}={}){
   await checkCurrent(trusted);const c=await pool.connect();
   try{await c.query('BEGIN');
    if(externalDeadline!==undefined){
     if(!Number.isFinite(externalDeadline)||externalDeadline<=Date.now()||externalDeadline>Date.now()+20000)throw invalid();
     await c.query("SET LOCAL statement_timeout='3000ms'");
     await c.query("SET LOCAL lock_timeout='3000ms'");
     await c.query("SET LOCAL idle_in_transaction_session_timeout='25000ms'");
    }
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-bound-audit-owner:${trusted.platformOwnerId}`]);
    await c.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`secureshop-conversation-admission:${trusted.launchId}`]);
    await current(c);const result=await work(c,binding);await current(c);await c.query('COMMIT');return result;
   }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}finally{c.release();}
  }
  return Object.freeze({binding,
   // Trusted caller must restrict callback to a short local effect+audit using c.
   withPersonaEffect(work){if(typeof work!=='function')throw invalid();return transaction(work);},
   // Separate-store transaction: no agents client crosses this boundary. The
   // callback must enforce its own SQL deadline and retain its local receipt.
   // An error after admission cannot assert rollback of that separate store.
   async withCrossStoreEffect(work){
    if(typeof work!=='function')throw invalid();let admitted=false,completed=false;
    try{return await transaction(async()=>{admitted=true;const value=await work(binding);completed=true;return value;});}
    catch(cause){if(!admitted || (['REVIEW_OPERATION_CONFLICT','COMMERCE_OPERATION_CONFLICT'].includes(cause?.code)
      && cause.effectNotApplied===true))throw cause;const error=Object.assign(new Error('Separate-store effect outcome requires authoritative readback'),{code:'PERSONA_EFFECT_OUTCOME_UNCERTAIN',executionBoundary:true,effectCallbackCompleted:completed});Object.defineProperty(error,'cause',{value:cause});throw error;}
   },
   // Purpose-closed external test-mail lease. No SQL client is handed to SMTP;
   // the caller must close its transport at this absolute deadline. A remote
   // effect is never described as rolled back by this transaction.
   withExternalMailDispatch(work,{deadlineAt}={}){
    if(typeof work!=='function'||!Number.isFinite(deadlineAt)
      ||deadlineAt<=Date.now()||deadlineAt>Date.now()+20000)throw invalid();
    return transaction(async()=>{
     if(Date.now()>=deadlineAt)throw invalid();
     return work(binding);
    },{externalDeadline:deadlineAt});
   },
   // Point-in-time admission only: returns after releasing SQL locks. This does
   // not authorize a later remote action or imply rollback of a remote effect.
   assertRemoteAdmission(){return transaction(async()=>Object.freeze({binding,pointInTimeOnly:true}));}
  });
 }
 return Object.freeze({resolve,capture,async read(scope,id,expected){const c=await pool.connect();try{return await resolve(c,scope,id,expected);}finally{c.release();}}});
}
module.exports={createSecureShopBoundPersonaAuthority,assertAuthorityReady};
