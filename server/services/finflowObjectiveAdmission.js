'use strict';

const WORKSHOP_KEY = 'sensitive_info_disclosure';
const QUERY = `SELECT w.is_visible,w.catalog_active AS exercise_active,
  o.catalog_active AS objective_active,o.is_enabled
  FROM workshop_platform.exercises w
  LEFT JOIN workshop_platform.objectives o ON o.workshop_key=w.workshop_key AND o.objective_id=$2
  WHERE w.workshop_key=$1`;

function unavailable(code, statusCode, message) {
  return Object.assign(new Error(message), { code, statusCode });
}

// General chat and selected objectives share the same exercise availability gate.
function createWorkshopObjectiveAdmission({ pool } = {}) {
  if (typeof pool?.query !== 'function') throw new TypeError('PostgreSQL pool required');
  return Object.freeze({
    async admit(objectiveId) {
      const generalChat = objectiveId === undefined || objectiveId === null || objectiveId === '';
      if (generalChat) objectiveId = null;
      if (!generalChat && (typeof objectiveId !== 'string' || !/^[a-z0-9][a-z0-9_-]{0,99}$/.test(objectiveId))) {
        throw unavailable('BAD_REQUEST', 400, 'Invalid objective ID');
      }
      let row;
      try { row = (await pool.query(QUERY, [WORKSHOP_KEY, objectiveId])).rows[0]; }
      catch { throw unavailable('EXERCISE_AVAILABILITY_UNAVAILABLE', 503, 'Exercise availability is temporarily unavailable'); }
      if (!row) {
        throw unavailable('NOT_FOUND', 404, 'Unknown objective');
      }
      if (row.exercise_active !== true || row.is_visible !== true) {
        throw unavailable('EXERCISE_UNAVAILABLE', 403, 'Exercise unavailable');
      }
      if (!generalChat && row.objective_active !== true) {
        throw unavailable('NOT_FOUND', 404, 'Unknown objective');
      }
      if (!generalChat && row.is_enabled !== true) {
        throw unavailable('OBJECTIVE_DISABLED', 409, 'Objective unavailable');
      }
      return Object.freeze(generalChat ? { generalChat: true } : { generalChat: false, objectiveId });
    },
  });
}

module.exports = { createWorkshopObjectiveAdmission };
