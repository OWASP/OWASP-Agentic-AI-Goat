'use strict';

const { readVerifiedLegacyArchive } = require('./read-platform-archive');
const { COLUMNS, SEQUENCED_TABLES, mapCtfArchive } = require('./map-ctf-archive');
const { normalizeArchiveOwnerBinding, assertVerifiedArchiveOwnerBinding } = require('./archive-owner-binding');

function reject(code) { const error = new Error(code); error.code = code; throw error; }

async function readCtfArchive({ archive, identityMap, naiveTimestamps = 'reject', resolutions = {} }) {
  const verified = await readVerifiedLegacyArchive({ archive });
  if (!verified.sources['ctf.db']) reject('CTF_ARCHIVE_SOURCE_MISSING');
  const input = { tables: verified.sources['ctf.db'].tables, archiveDigest: verified.archiveDigest,
    identityMap: structuredClone(identityMap), naiveTimestamps, resolutions: structuredClone(resolutions) };
  return { input, ...mapCtfArchive(input) };
}

/** Caller owns BEGIN/COMMIT/ROLLBACK. A dry run rolls back only this helper's savepoint. */
async function applyCtfArchive(client, raw, { dryRun = true, ownerProof } = {}) {
  if (typeof dryRun !== 'boolean') reject('INVALID_CTF_DRY_RUN');
  // Capture every private input before the first await. A caller cannot mutate
  // owner mappings, source rows, or provenance while locks are being acquired.
  const input = structuredClone(raw);
  const binding = normalizeArchiveOwnerBinding({ archiveDigest: input.archiveDigest, identityMap: input.identityMap });
  assertVerifiedArchiveOwnerBinding(ownerProof, binding);
  const plan = mapCtfArchive(input);
  if (!plan.report.readyToApply) reject('CTF_IMPORT_REQUIRES_REVIEW');
  await client.query('SAVEPOINT ctf_import_guard');
  const targetTables = [...Object.keys(COLUMNS), 'import_provenance'];
  await client.query(`LOCK TABLE ${targetTables.map(table=>`ctf.${table}`).join(',')} IN ACCESS EXCLUSIVE MODE`);
  for (const table of targetTables) if ((await client.query(`SELECT EXISTS(SELECT 1 FROM ctf.${table}) AS populated`)).rows[0].populated) reject('CTF_IMPORT_REQUIRES_EMPTY_TARGET');

  const insertOrder = ['ctf_config','ctf_participants','ctf_stages','ctf_progress','ctf_attempts','ctf_leaderboard','ctf_events','ctf_sessions','ctf_technique_blocklist','ctf_payload_blocklist','ctf_bans','ctf_judgments'];
  for (const table of insertOrder) {
    const columns = COLUMNS[table].split(' '), identity = SEQUENCED_TABLES.includes(table);
    for (const row of plan.tables[table]) await client.query(`INSERT INTO ctf.${table}(${columns.join(',')})${identity?' OVERRIDING SYSTEM VALUE':''}
      VALUES(${columns.map((_,index)=>'$'+(index+1)).join(',')})`, columns.map(column=>row[column]));
  }
  for (const table of SEQUENCED_TABLES) {
    const next = plan.tables[table].reduce((max,row)=>Math.max(max,row.id),0)+1;
    await client.query(`ALTER TABLE ctf.${table} ALTER COLUMN id RESTART WITH ${next}`);
  }
  await client.query(`INSERT INTO ctf.import_provenance(archive_sha256,importer_version,source_file,table_counts,identity_map_sha256)
    VALUES($1,'ctf-import-v1','ctf.db',$2::jsonb,$3)`,[input.archiveDigest,JSON.stringify(plan.report.counts),binding.identityMapSha256]);
  if (dryRun) await client.query('ROLLBACK TO SAVEPOINT ctf_import_guard');
  await client.query('RELEASE SAVEPOINT ctf_import_guard');
  return { applied: !dryRun, dryRun, archiveDigest: input.archiveDigest, counts: plan.report.counts,
    identityMapSha256: binding.identityMapSha256, existingJudgmentsImported: plan.tables.ctf_judgments.length };
}

module.exports = { readCtfArchive, applyCtfArchive };
