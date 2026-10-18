'use strict';
const { mapPlatformSnapshot } = require('./map-platform-snapshot');

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}
/** Decisions are bound to this exact archive and revalidated against the mapper report. */
function preparePlatformImport(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) reject('INVALID_PLATFORM_IMPORT_INPUT');
  const allowed = new Set(['tables', 'identityMap', 'archiveDigest', 'naiveTimestamps', 'review']);
  if (Object.keys(input).some(key => !allowed.has(key))) reject('UNKNOWN_PLATFORM_IMPORT_INPUT');
  const mapped = mapPlatformSnapshot(input);
  if (mapped.snapshot.timeTracking.some(row => row.id === 2147483647)) reject('TIME_TRACKING_SEQUENCE_EXHAUSTED');
  const review = input.review;
  if (!review || review.archiveDigest !== input.archiveDigest) reject('ARCHIVE_BOUND_REVIEW_REQUIRED');
  if (Object.keys(review).some(key => !['archiveDigest', 'missingDefaults', 'retainedTables'].includes(key))) reject('UNKNOWN_IMPORT_REVIEW_DECISION');
  const neededDefaults = Object.entries(mapped.report.missingCatalogRows).filter(([, rows]) => rows.length).map(([key]) => key).sort();
  const missingDefaults = review.missingDefaults;
  if (!missingDefaults || typeof missingDefaults !== 'object' || Array.isArray(missingDefaults)) reject('EXPLICIT_DEFAULT_POLICY_REQUIRED');
  if (JSON.stringify(Object.keys(missingDefaults).sort()) !== JSON.stringify(neededDefaults)) reject('DEFAULT_POLICY_SCOPE_MISMATCH');
  for (const decision of Object.values(missingDefaults)) {
    if (decision !== 'catalog_visibility_defaults_without_content') reject('UNSUPPORTED_DEFAULT_POLICY');
  }
  const neededTables = mapped.report.unmappedTables.map(row => row.table).sort();
  if (!Array.isArray(review.retainedTables) || review.retainedTables.some(table => typeof table !== 'string') || new Set(review.retainedTables).size !== review.retainedTables.length || JSON.stringify([...review.retainedTables].sort()) !== JSON.stringify(neededTables)) reject('UNMAPPED_TABLE_RESOLUTION_REQUIRED');
  return {
    snapshot: mapped.snapshot,
    report: mapped.report,
    archiveDigest: input.archiveDigest,
    review: {
      archiveDigest: review.archiveDigest,
      missingDefaults: { ...missingDefaults },
      retainedTables: [...review.retainedTables],
    },
  };
}
module.exports = { preparePlatformImport };

/** Caller owns BEGIN/COMMIT/ROLLBACK; SAVEPOINT deliberately rejects autocommit use. */
async function applyPlatformSnapshot(client, rawInput) {
  const plan = preparePlatformImport(rawInput);
  const { snapshot } = plan;
  if (snapshot.exercises.some(row => [row.description, row.category, row.difficulty, row.route].some(value => value === null))) reject('NULL_EXERCISE_METADATA_REQUIRES_RESOLUTION');
  await client.query('SAVEPOINT platform_import_guard');
  const config = await client.query('SELECT id,revision FROM workshop_platform.config_revision WHERE id=1 FOR UPDATE');
  if (config.rowCount !== 1 || config.rows[0].id !== 1 || config.rows[0].revision !== 0) reject('PLATFORM_IMPORT_REQUIRES_FRESH_REVISION');
  const tables = ['activity_counters', 'completions', 'exercises', 'grade_packets', 'objective_evidence', 'objective_judgments', 'objectives', 'revisions', 'time_tracking', 'user_modes', 'user_state', 'xss_legacy_solutions', 'xss_legacy_solution_visibility'];
  const businessTables = [...tables.map(name => `workshop_platform.${name}`), 'identity.historical_import_provenance', 'identity.import_batches', ...['owners', 'runs', 'effects', 'events'].map(name => `graph_runtime.${name}`)];
  await client.query(`LOCK TABLE ${businessTables.join(',')} IN ACCESS EXCLUSIVE MODE`);
  for (const table of businessTables) {
    if ((await client.query(`SELECT EXISTS(SELECT 1 FROM ${table}) AS populated`)).rows[0].populated) reject('PLATFORM_IMPORT_REQUIRES_EMPTY_TARGET');
  }
  const owners = [...new Set(Object.values(rawInput.identityMap))];
  const existing = (await client.query('SELECT id FROM identity.users WHERE id=ANY($1::integer[]) FOR KEY SHARE', [owners])).rows;
  if (existing.length !== owners.length) reject('TARGET_IDENTITY_MISSING');
  const { WORKSHOP_OBJECTIVES, toChallengeKey } = require('../../server/config/workshopCatalog');
  const challenges = require('./workshopChallengeFixtures');
  let ordinal = 0;
  for (const [workshopKey, objectives] of Object.entries(WORKSHOP_OBJECTIVES)) {
    // Approved structural defaults retain curriculum readiness. Newly introduced
    // disabled exercises must not become visible/gradable through an old import.
    const metadata = challenges.find(item => item.key === toChallengeKey(workshopKey));
    await client.query('INSERT INTO workshop_platform.exercises(workshop_key,challenge_key,challenge_name,ordinal,is_visible) VALUES($1,$2,$3,$4,$5)', [workshopKey, toChallengeKey(workshopKey), workshopKey, ordinal++, metadata?.defaultVisible !== false]);
    for (const [index, objective] of objectives.entries()) await client.query('INSERT INTO workshop_platform.objectives(workshop_key,objective_id,label,ordinal,is_enabled) VALUES($1,$2,$3,$4,$5)', [workshopKey, objective.id, objective.text, index, objective.defaultEnabled !== false]);
  }
  for (const row of snapshot.exercises) await client.query('UPDATE workshop_platform.exercises SET challenge_name=$2,challenge_description=$3,category=$4,difficulty=$5,route=$6,is_visible=$7,show_hints=$8,show_solutions=$9,updated_by=$10,updated_at=$11 WHERE workshop_key=$1', [row.workshopKey, row.name, row.description ?? '', row.category ?? 'ai', row.difficulty ?? 'intermediate', row.route ?? '', row.visible, row.showHints, row.showSolutions, row.updatedBy, row.updatedAt]);
  for (const [collection, column] of [[snapshot.objectiveVisibility, 'is_enabled'], [snapshot.hintVisibility, 'hint_enabled']]) {
    for (const row of collection) await client.query(`UPDATE workshop_platform.objectives SET ${column}=$3,updated_by=$4,updated_at=$5 WHERE workshop_key=$1 AND objective_id=$2`, [row.workshopKey, row.objectiveId, row.enabled, row.updatedBy, row.updatedAt]);
  }
  for (const row of snapshot.hints) await client.query('UPDATE workshop_platform.objectives SET hint_content=$3::jsonb WHERE workshop_key=$1 AND objective_id=$2', [row.workshopKey, row.objectiveId, JSON.stringify({ title: row.title, hints: row.hints })]);
  const activity = async (row, startedAt) => client.query('INSERT INTO workshop_platform.user_state(user_id,workshop_key,started_at) VALUES($1,$2,$3) ON CONFLICT(user_id,workshop_key) DO UPDATE SET started_at=LEAST(workshop_platform.user_state.started_at,EXCLUDED.started_at)', [row.userId, row.workshopKey, startedAt]);
  for (const row of snapshot.historicalCompletions) {
    await activity(row, row.sourceCreatedAt);
    await client.query('INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id,completed_at,updated_at) VALUES($1,$2,$3,$4,$5)', [row.userId, row.workshopKey, row.objectiveId, row.completedAt, row.updatedAt]);
    const sourceKey = JSON.stringify(['platform-import-v1', row.provenance.source, row.provenance.table, ['id', row.provenance.rowId]]);
    const sourceHash = require('node:crypto').createHash('sha256').update(sourceKey).digest('hex');
    await client.query('INSERT INTO identity.historical_import_provenance(archive_sha256,import_version,source_file,source_table,source_row_sha256,historical_user_id,workshop_key,objective_id,source_created_at,source_updated_at,source_completed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)', [plan.archiveDigest, 'platform-import-v1', row.provenance.source, row.provenance.table, sourceHash, row.userId, row.workshopKey, row.objectiveId, row.sourceCreatedAt, row.updatedAt, row.completedAt]);
  }
  for (const row of snapshot.timeTracking) {
    await activity(row, row.sessionStart);
    await client.query('INSERT INTO workshop_platform.time_tracking(id,user_id,workshop_key,session_start,last_heartbeat,duration_seconds) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4,$5,$6)', [row.id, row.userId, row.workshopKey, row.sessionStart, row.lastHeartbeat, row.durationSeconds]);
  }
  for (const row of snapshot.modes) {
    await activity(row, row.createdAt);
    await client.query('INSERT INTO workshop_platform.user_modes(user_id,workshop_key,mode,created_at,updated_at) VALUES($1,$2,$3,$4,$5)', [row.userId, row.workshopKey, row.mode, row.createdAt, row.updatedAt]);
  }
  const nextId = snapshot.timeTracking.reduce((highest, row) => Math.max(highest, row.id), 0) + 1;
  await client.query(`ALTER TABLE workshop_platform.time_tracking ALTER COLUMN id RESTART WITH ${nextId}`);
  await client.query('UPDATE workshop_platform.config_revision SET revision=revision+1,updated_at=clock_timestamp() WHERE id=1');
  await require('../../server/database/postgres/workshopPlatformSupport').bump(client, { scopeType: 'global', scopeKey: '*', category: 'workshop_config' });
  await client.query('RELEASE SAVEPOINT platform_import_guard');
  return { applied: true, archiveDigest: plan.archiveDigest, counts: plan.report.counts, retainedNotImported: plan.review.retainedTables, defaults: plan.review.missingDefaults, provenanceKind: 'historical_completion' };
}
module.exports.applyPlatformSnapshot = applyPlatformSnapshot;
