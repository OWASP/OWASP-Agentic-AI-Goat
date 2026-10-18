'use strict';
const WORKSHOP='secureshop_agent_security';
const OBJECTIVES=Object.freeze({rogue_registration:'ss_rogue_tool_selected',rug_pull:'ss_rug_pull_invoked'});
function unavailable(){return Object.assign(new Error('SecureShop MCP trust exercise unavailable'),{code:'BOUND_MCP_UNAVAILABLE'});}
function createSecureShopMcpTrustAvailability(pool){if(typeof pool?.query!=='function')throw unavailable();
  async function read(){const rows=(await pool.query(`SELECT e.catalog_active AS exercise_active,e.is_visible,
      o.objective_id,o.catalog_active,o.is_enabled FROM workshop_platform.exercises e
      JOIN workshop_platform.objectives o USING(workshop_key) WHERE e.workshop_key=$1 AND o.objective_id=ANY($2::text[])
      ORDER BY o.objective_id`,[WORKSHOP,Object.values(OBJECTIVES)])).rows;
    const registered=rows.length===2&&rows.every(row=>row.exercise_active===true&&row.catalog_active===true);
    return Object.freeze({registered,visible:registered&&rows.every(row=>row.is_visible===true),
      enabled:Object.freeze(Object.fromEntries(Object.entries(OBJECTIVES).map(([scenario,id])=>[scenario,
        rows.some(row=>row.objective_id===id&&row.is_enabled===true)])))});}
  async function assertScenario(scenario){if(!Object.hasOwn(OBJECTIVES,scenario))throw unavailable();const state=await read();
    if(!state.visible||state.enabled[scenario]!==true)throw unavailable();return state;}
  return Object.freeze({read,assertScenario});}
module.exports={MCP_TRUST_OBJECTIVES:OBJECTIVES,createSecureShopMcpTrustAvailability};
