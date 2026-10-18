'use strict';
// Explicit candidate-only composition. Caller must qualify the full affected
// effect matrix before supplying this to the production gateway.
function createUserAdministrationCandidateComposition({agentsPool,commercePool,launches,jwtSecret,auditStore,account}={}){
 if(typeof launches?.assertCurrent!=='function'||!auditStore||!account)throw new TypeError('Candidate authority dependencies required');
 const authority=require('../database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agentsPool,checkCurrent:s=>launches.assertCurrent(s)});
 const personas=require('../database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool,agentsPool,auditStore,personaAuthority:authority});
 const auth=require('./secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret});
 const operations=require('../database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:agentsPool,auditStore,checkCurrent:s=>launches.assertCurrent(s)});
 const users=require('./secureshopBoundUserAdministration').createSecureShopBoundUserAdministration({repository:operations,personas,account,personaAuthority:authority});
 return Object.freeze({authority,personas,auth,operations,users,
  async assertStorageReady(){
   for(const table of ['bound_persona_state','bound_persona_admin_operations','bound_persona_admin_cleanup_receipts']){
    const found=(await agentsPool.query('SELECT to_regclass($1) AS relation',['secureshop_agents.'+table])).rows[0];if(!found?.relation)throw Error('Candidate persona storage unavailable');
   }
   const trigger=(await agentsPool.query("SELECT count(*)::int AS n FROM pg_trigger WHERE NOT tgisinternal AND tgenabled='O' AND tgname IN ('cleanup_bound_persona_admin_retirement','cleanup_bound_persona_admin_owner','bound_persona_effective_session_guard','bound_persona_admin_insert_guard','bound_persona_admin_state_fence')")).rows[0];
   if(trigger?.n!==5)throw Error('Candidate persona lifecycle unavailable');
   return Object.freeze({storageReady:true,productionReady:false});
  }
 });
}
module.exports={createUserAdministrationCandidateComposition};
