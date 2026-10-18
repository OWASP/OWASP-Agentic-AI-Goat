'use strict';
const WORKSHOP='secureshop_agent_security',OBJECTIVE='ss_controlled_ssrf';
function unavailable(){return Object.assign(new Error('Controlled SSRF exercise unavailable'),{code:'BOUND_SSRF_UNAVAILABLE'});}
function createSecureShopSsrfAvailability(pool){if(typeof pool?.query!=='function')throw unavailable();
  async function read(id=OBJECTIVE){if(![OBJECTIVE,'ss_policy_final_html_execution'].includes(id))throw unavailable();const row=(await pool.query(`SELECT e.catalog_active AS exercise_active,e.is_visible,
      o.catalog_active AS objective_active,o.is_enabled FROM workshop_platform.exercises e
      JOIN workshop_platform.objectives o USING(workshop_key) WHERE e.workshop_key=$1 AND o.objective_id=$2`,
    [WORKSHOP,id])).rows[0];return Object.freeze({registered:row?.exercise_active===true&&row?.objective_active===true,
      visible:row?.exercise_active===true&&row?.objective_active===true&&row?.is_visible===true,
      enabled:row?.is_enabled===true});}
  async function assertObjective(id){const state=await read(id);
    if(!state.visible||!state.enabled)throw unavailable();return state;}
  return Object.freeze({read,assertObjective});}
module.exports={createSecureShopSsrfAvailability,SECURESHOP_SSRF_OBJECTIVE_ID:OBJECTIVE};
