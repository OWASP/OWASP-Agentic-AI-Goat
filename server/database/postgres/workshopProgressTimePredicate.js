'use strict';

const { WORKSHOP_KEY: SECURESHOP_WORKSHOP_KEY } = require('../../config/secureshopCurriculum');

function liveWorkshopTimeCondition(alias = 't') {
  if (!/^[a-z][a-z0-9_]*$/i.test(alias)) throw new TypeError('SQL alias must be an identifier');
  return `(${alias}.workshop_key<>'${SECURESHOP_WORKSHOP_KEY}' OR
    (${alias}.platform_launch_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM identity.secureshop_progress_cleanup_history h
      WHERE h.launch_id=${alias}.platform_launch_id
        AND h.from_launch_generation=${alias}.platform_launch_generation)))`;
}

module.exports = { liveWorkshopTimeCondition };
