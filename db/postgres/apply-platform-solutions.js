'use strict';

const { mapPlatformSolutions, FAMILIES } = require('./map-platform-solutions');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');
const { bump } = require('../../server/database/postgres/workshopPlatformSupport');

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

/** Caller owns BEGIN/COMMIT. Only the six explicitly mapped families are applied. */
async function applyPlatformSolutions(client, raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).some(key => !['sources', 'archiveDigest', 'resolutions'].includes(key))) {
    reject('INVALID_SOLUTION_APPLY_INPUT');
  }
  const { snapshot, report } = mapPlatformSolutions(raw);
  if (report.requiresReview) reject('SOLUTION_IMPORT_REQUIRES_REVIEW');
  const expected = Object.values(FAMILIES).reduce((sum, family) => sum + family.objectiveIds.length, 0);
  if (snapshot.solutions.length !== expected || snapshot.solutionVisibility.length !== expected) {
    reject('INCOMPLETE_SOLUTION_MAPPING');
  }
  await client.query('SAVEPOINT platform_solutions_guard');
  const config = await client.query('SELECT id FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
  if (config.rowCount !== 1) reject('SOLUTION_IMPORT_CONFIG_MISSING');
  // Lock every target before the first update so missing/stale catalogs cannot partially apply.
  for (const row of snapshot.solutions) {
    if (!WORKSHOP_OBJECTIVES[row.workshopKey]?.some(objective => objective.id === row.objectiveId)) {
      reject('SOLUTION_IMPORT_UNKNOWN_TARGET');
    }
    const target = await client.query(`SELECT objective_id FROM workshop_platform.objectives
      WHERE workshop_key=$1 AND objective_id=$2 AND catalog_active=true FOR UPDATE`,
    [row.workshopKey, row.objectiveId]);
    if (target.rowCount !== 1) reject('SOLUTION_IMPORT_TARGET_MISSING');
  }
  for (const row of snapshot.solutions) {
    await client.query(`UPDATE workshop_platform.objectives SET solution_content=$3::jsonb,
      updated_at=clock_timestamp() WHERE workshop_key=$1 AND objective_id=$2`,
    [row.workshopKey, row.objectiveId, JSON.stringify(row.content)]);
  }
  for (const row of snapshot.solutionVisibility) {
    await client.query(`UPDATE workshop_platform.objectives SET solution_enabled=$3,
      updated_at=clock_timestamp() WHERE workshop_key=$1 AND objective_id=$2`,
    [row.workshopKey, row.objectiveId, row.enabled]);
  }
  await client.query('UPDATE workshop_platform.config_revision SET revision=revision+1,updated_at=clock_timestamp() WHERE id=1');
  await bump(client, { scopeType: 'global', scopeKey: '*', category: 'workshop_config' });
  await client.query('RELEASE SAVEPOINT platform_solutions_guard');
  return {
    applied: true, archiveDigest: raw.archiveDigest, counts: report.counts,
    chosenOrigins: [...snapshot.solutions.map(row => ({ workshopKey: row.workshopKey, objectiveId: row.objectiveId, field: 'content', provenance: row.provenance })),
      ...snapshot.solutionVisibility.map(row => ({ workshopKey: row.workshopKey, objectiveId: row.objectiveId, field: 'visibility', provenance: row.provenance }))],
    decisions: report.resolvedConflicts,
    unmappedFamilies: Object.keys(WORKSHOP_OBJECTIVES).filter(key => !Object.hasOwn(FAMILIES, key)),
    legitimateCatalogGaps: report.legitimateCatalogGaps,
  };
}

module.exports = { applyPlatformSolutions };
