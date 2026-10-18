'use strict';
const crypto = require('node:crypto');
const { Pool } = require('pg');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
const { WORKSHOP_OBJECTIVES, toChallengeKey } = require('../server/config/workshopCatalog');
const hints = require('../server/data/workshopHints');
const { solutionFixtures, seedWorkshopPlatform } = require('../server/database/postgres/workshopPlatformSeed');
const { resolveObjectiveContent } = require('../server/database/postgres/workshopPlatformSeedCore');
const challenges = require('../db/postgres/workshopChallengeFixtures');

const keyOf = row => [row.entity_kind,row.workshop_key,row.objective_id,row.field_name].join('\u001f');
function jsonValue(value) {
  if (value instanceof Date) return value.toISOString();
  if (Array.isArray(value)) return value.map(jsonValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, jsonValue(item)]));
  }
  return value;
}
const canonical = value => JSON.stringify(provenance.stable(jsonValue(value)));
const digest = value => crypto.createHash('sha256').update(canonical(value)).digest('hex');
function expectedCatalogSources() {
  const result = new Map(), solutions = solutionFixtures();
  for (const [workshopKey, objectives] of Object.entries(WORKSHOP_OBJECTIVES)) {
    const meta=challenges.find(value=>value.key===toChallengeKey(workshopKey)) || {};
    const exercise={challenge_name:meta.name||workshopKey,challenge_description:meta.description||'',
      category:meta.category||'ai',difficulty:meta.difficulty||'intermediate',route:meta.route||''};
    for (const [field,value] of Object.entries(exercise))
      result.set(['exercise',workshopKey,'',field].join('\u001f'),provenance.document(value));
    for (const objective of objectives) {
      const content=resolveObjectiveContent({workshopKey,objectiveId:objective.id,hints,solutions});
      const values={label:objective.text,category:objective.category||'',hint_content:content.hint,
        solution_content:content.solution};
      for (const [field,value] of Object.entries(values)) {
        const present=!['hint_content','solution_content'].includes(field)
          || (field==='hint_content'?content.hintPresent:content.solutionPresent);
        result.set(['objective',workshopKey,objective.id,field].join('\u001f'),
          present?provenance.document(value):provenance.document(undefined,false));
      }
    }
  }
  return result;
}
function validateTransition(beforeRows, afterRows, { expectedSources = expectedCatalogSources() } = {}) {
  if (!Array.isArray(beforeRows) || !Array.isArray(afterRows) || beforeRows.length !== afterRows.length)
    throw Object.assign(new Error('provenance row count changed'), { code:'PROVENANCE_TRANSITION_INVALID' });
  if (beforeRows.length > 5000) throw Object.assign(new Error('provenance transition exceeds diagnostic bound'),
    { code:'PROVENANCE_TRANSITION_INVALID' });
  const before = new Map(beforeRows.map(row => [keyOf(row),row]));
  const after = new Map(afterRows.map(row => [keyOf(row),row]));
  const beforeKeys=[...before.keys()].sort(),afterKeys=[...after.keys()].sort();
  if (before.size !== beforeRows.length || after.size !== afterRows.length
      || canonical(beforeKeys) !== canonical(afterKeys))
    throw Object.assign(new Error('provenance keys changed'), { code:'PROVENANCE_TRANSITION_INVALID',
      diagnostic:{ duplicateBefore:beforeRows.length-before.size,duplicateAfter:afterRows.length-after.size,
        removedKeys:beforeKeys.filter(key=>!after.has(key)),addedKeys:afterKeys.filter(key=>!before.has(key)) } });
  const expectedChanged = new Set([...expectedSources].filter(([key,document]) => {
    const row=before.get(key),hash=provenance.hashDocument(document);
    return row && (canonical(row.source_document)!==canonical(document) || row.source_hash!==hash);
  }).map(([key])=>key));
  const changed=[], transitions=[];
  for (const [key,left] of before) {
    const right=after.get(key); const columns=new Set([...Object.keys(left),...Object.keys(right)]
      .filter(column => canonical(left[column])!==canonical(right[column])));
    if (!columns.size) continue;
    const columnNames=[...columns].sort();
    const expectedDocument=expectedSources.get(key), expectedHash=expectedDocument&&provenance.hashDocument(expectedDocument);
    transitions.push({ key,columns:columnNames,expectedSourceTransition:expectedChanged.has(key),
      sourceDocumentMatches:expectedDocument!==undefined&&canonical(right.source_document)===canonical(expectedDocument),
      sourceHashMatches:expectedHash!==undefined&&right.source_hash===expectedHash });
    changed.push(key);
  }
  const invalid=transitions.filter(item => !item.expectedSourceTransition
    || item.columns.some(column => !['source_hash','source_document','updated_at'].includes(column))
    || !item.sourceDocumentMatches || !item.sourceHashMatches);
  const missingExpected=[...expectedChanged].filter(key=>!changed.includes(key)).sort();
  if (invalid.length || missingExpected.length)
    throw Object.assign(new Error('expected provenance source retirement was not exact'),
      { code:'PROVENANCE_TRANSITION_INVALID', diagnostic:{ transitions,invalid,missingExpected } });
  return Object.freeze({ rows:beforeRows.length, changed:changed.length,
    beforeSha256:digest(beforeRows), afterSha256:digest(afterRows) });
}
async function audit(connectionString) {
  const pool=new Pool({ connectionString });
  try {
    const read=async()=> (await pool.query(`SELECT * FROM workshop_platform.catalog_field_defaults
      ORDER BY entity_kind,workshop_key,objective_id,field_name`)).rows;
    const before=await read(); const seed=await seedWorkshopPlatform(pool); const after=await read();
    if (seed?.changed !== false) throw Object.assign(new Error('startup seed changed teaching data'),
      { code:'STARTUP_SEED_CHANGED' });
    return Object.freeze({ seedChanged:false, ...validateTransition(before,after) });
  } finally { await pool.end(); }
}
if (require.main===module) audit(process.argv[2]).then(result => {
  process.stdout.write(`MCP_SEED_TRANSITION=${JSON.stringify(result)}\n`);
}).catch(error => {
  const diagnostic = { code:error?.code || 'SEED_TRANSITION_FAILED', name:error?.name || 'Error',
    message:typeof error?.message === 'string' ? error.message.slice(0,1000) : 'seed transition failed',
    transition:error?.diagnostic || null };
  process.stderr.write(`MCP_SEED_TRANSITION_ERROR=${JSON.stringify(diagnostic)}\n`);process.exitCode=1;
});
module.exports={ keyOf, expectedCatalogSources, validateTransition, audit };
