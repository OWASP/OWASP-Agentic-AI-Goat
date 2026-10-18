'use strict';

const { OBJECTIVES } = require('./secureshopPersonaInboxAssessment');
const {readSecureShopAssessmentEligibility}=require('./secureshopAssessmentEligibility');
const WORKSHOP_KEY = 'secureshop_agent_security';
const IDS = Object.freeze(Object.values(OBJECTIVES));

function unavailable() {
  return Object.assign(new Error('Persona inbox exercise unavailable'), {
    code: 'PERSONA_INBOX_EXERCISE_UNAVAILABLE',
  });
}

function createSecureShopPersonaInboxAvailability(pool) {
  if (typeof pool?.query !== 'function') throw new TypeError('Persona inbox catalog pool required');
  async function read(scope) {
    if(scope!==undefined){
      const enabled=new Set(await readSecureShopAssessmentEligibility(pool,scope,IDS));
      return Object.freeze({registered:enabled.size>0,visible:enabled.size>0,enabled});
    }
    const rows = (await pool.query(`SELECT e.catalog_active AS exercise_active,e.is_visible,
        o.objective_id,o.catalog_active,o.is_enabled
      FROM workshop_platform.exercises e
      JOIN workshop_platform.objectives o USING(workshop_key)
      WHERE e.workshop_key=$1 AND o.objective_id=ANY($2::text[])
      ORDER BY o.objective_id`, [WORKSHOP_KEY, IDS])).rows;
    const registered = rows.length === IDS.length && IDS.every(id => rows.some(row =>
      row.objective_id === id && row.exercise_active === true && row.catalog_active === true));
    const visible = registered && rows.every(row => row.is_visible === true);
    const enabled = new Set(rows.filter(row => row.is_enabled === true).map(row => row.objective_id));
    return Object.freeze({ registered, visible, enabled });
  }
  async function assertObjectives(required,scope) {
    if (!Array.isArray(required) || !required.length || required.some(id => !IDS.includes(id))) throw unavailable();
    const state = await read(scope);
    if (!state.visible || required.some(id => !state.enabled.has(id))) throw unavailable();
    return state;
  }
  return Object.freeze({ read, assertObjectives });
}

module.exports = { createSecureShopPersonaInboxAvailability, PERSONA_INBOX_OBJECTIVE_IDS: IDS };
