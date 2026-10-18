'use strict';

const { mapAdditionalPlatformSolutions } = require('./map-platform-additional-solutions');
const { WORKSHOP_OBJECTIVES } = require('../../server/config/workshopCatalog');
const { bump } = require('../../server/database/postgres/workshopPlatformSupport');

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

/** Apply validated archive rows inside the caller's transaction; never seeds or awards progress. */
async function applyAdditionalPlatformSolutions(client, raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)
      || Object.keys(raw).some(key => !['sources', 'archiveDigest', 'resolutions', 'identityMap', 'naiveTimestamps'].includes(key))) {
    reject('INVALID_ADDITIONAL_SOLUTION_APPLY_INPUT');
  }
  const { snapshot, report } = mapAdditionalPlatformSolutions(raw);
  if (report.requiresReview) reject('SOLUTION_IMPORT_REQUIRES_REVIEW');
  if (snapshot.solutions.length !== 48 || snapshot.solutionVisibility.length !== 48) reject('INCOMPLETE_SOLUTION_MAPPING');
  await client.query('SAVEPOINT additional_solutions_guard');
  const config = await client.query('SELECT id FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
  if (config.rowCount !== 1) reject('SOLUTION_IMPORT_CONFIG_MISSING');
  for (const table of ['xss_legacy_solutions', 'xss_legacy_solution_visibility']) {
    await client.query(`LOCK TABLE workshop_platform.${table} IN ACCESS EXCLUSIVE MODE`);
    if ((await client.query(`SELECT EXISTS(SELECT 1 FROM workshop_platform.${table}) AS populated`)).rows[0].populated) {
      reject('LEGACY_SOLUTION_IMPORT_REQUIRES_EMPTY_TARGET');
    }
  }
  for (const row of snapshot.solutions) {
    if (!WORKSHOP_OBJECTIVES[row.workshopKey]?.some(objective => objective.id === row.objectiveId)) reject('SOLUTION_IMPORT_UNKNOWN_TARGET');
    const target = await client.query(`SELECT objective_id FROM workshop_platform.objectives
      WHERE workshop_key=$1 AND objective_id=$2 AND catalog_active=true FOR UPDATE`, [row.workshopKey, row.objectiveId]);
    if (target.rowCount !== 1) reject('SOLUTION_IMPORT_TARGET_MISSING');
  }
  for (const actor of new Set(snapshot.legacySolutionVisibility.map(row => row.enabledBy).filter(id => id !== null))) {
    if ((await client.query('SELECT id FROM identity.users WHERE id=$1 FOR KEY SHARE', [actor])).rowCount !== 1) reject('TARGET_IDENTITY_MISSING');
  }
  for (const row of snapshot.solutions) {
    await client.query(`UPDATE workshop_platform.objectives SET solution_content=$3::jsonb,
      updated_at=clock_timestamp() WHERE workshop_key=$1 AND objective_id=$2`, [row.workshopKey, row.objectiveId, JSON.stringify(row.content)]);
  }
  for (const row of snapshot.solutionVisibility) {
    await client.query(`UPDATE workshop_platform.objectives SET solution_enabled=$3,
      updated_at=clock_timestamp() WHERE workshop_key=$1 AND objective_id=$2`, [row.workshopKey, row.objectiveId, row.enabled]);
  }
  for (const row of snapshot.legacySolutions) {
    await client.query(`INSERT INTO workshop_platform.xss_legacy_solutions
      (challenge_id,title,difficulty,hints,examples,approach,tips,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [row.challengeId, row.title, row.difficulty, row.hints, row.examples, row.approach, row.tips, row.updatedAt]);
  }
  for (const row of snapshot.legacySolutionVisibility) {
    await client.query(`INSERT INTO workshop_platform.xss_legacy_solution_visibility
      (challenge_id,solutions_enabled,enabled_by,enabled_at,updated_at) VALUES($1,$2,$3,$4,$5)`,
    [row.challengeId, row.enabled, row.enabledBy, row.enabledAt, row.updatedAt]);
  }
  await client.query('UPDATE workshop_platform.config_revision SET revision=revision+1,updated_at=clock_timestamp() WHERE id=1');
  await bump(client, { scopeType: 'global', scopeKey: '*', category: 'workshop_config' });
  await client.query('RELEASE SAVEPOINT additional_solutions_guard');
  return { applied: true, archiveDigest: raw.archiveDigest, counts: report.counts,
    chosenOrigins: ['solutions', 'solutionVisibility', 'legacySolutions', 'legacySolutionVisibility'].flatMap(field =>
      snapshot[field].map(row => ({ field, workshopKey: row.workshopKey || 'xss_workshop', objectiveId: row.objectiveId || null,
        challengeId: row.challengeId || null, provenance: row.provenance }))),
    decisions: report.resolvedConflicts, unmappedTables: report.unmappedTables,
    scope: ['xss_workshop', 'csrf_workshop', 'sensitive_info_disclosure', 'supply_chain_rce'] };
}

module.exports = { applyAdditionalPlatformSolutions };
