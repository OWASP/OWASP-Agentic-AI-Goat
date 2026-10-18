'use strict';

const crypto = require('node:crypto');

const SOURCE_SHA256 = '6c26c5333633891593fb56597751fc0a9e877d6086fdf88171cb3c78b35e66db';
const IDS = Object.freeze([
  'ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block',
]);
const BEFORE = `VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7) ON CONFLICT(workshop_key,objective_id) DO UPDATE SET label=EXCLUDED.label,ordinal=EXCLUDED.ordinal,catalog_active=true
     WHERE workshop_platform.objectives.label IS DISTINCT FROM EXCLUDED.label OR workshop_platform.objectives.ordinal<>EXCLUDED.ordinal OR workshop_platform.objectives.catalog_active=false`;
const PERSONA = `workshop_platform.objectives.workshop_key='secureshop_agent_security'
       AND workshop_platform.objectives.objective_id=ANY(ARRAY[${IDS.map(id => `'${id}'`).join(',')}]::text[])`;
const AFTER = `VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7) ON CONFLICT(workshop_key,objective_id) DO UPDATE SET
       label=CASE WHEN ${PERSONA} THEN workshop_platform.objectives.label ELSE EXCLUDED.label END,
       ordinal=EXCLUDED.ordinal,catalog_active=true
     WHERE (NOT(${PERSONA}) AND workshop_platform.objectives.label IS DISTINCT FROM EXCLUDED.label)
       OR workshop_platform.objectives.ordinal<>EXCLUDED.ordinal
       OR workshop_platform.objectives.catalog_active=false`;

function buildCandidate(source) {
  if (typeof source !== 'string'
      || crypto.createHash('sha256').update(source).digest('hex') !== SOURCE_SHA256) {
    throw new Error('workshop platform seed source is not the reviewed frozen version');
  }
  if (source.split(BEFORE).length !== 2) throw new Error('workshop objective upsert seam changed');
  return source.replace(BEFORE, AFTER);
}

module.exports = { SOURCE_SHA256, IDS, buildCandidate };
