'use strict';
// Explicit data, derived in memory from root-bound archived modules. No archived
// source tree is loaded at runtime; the fixture records each input checksum.
const fixture = require('../fixtures/workshopCatalogRelease116.json');
const { withTransaction } = require('../../server/database/postgres');
const { bump } = require('../../server/database/postgres/workshopPlatformSupport');
const fs = require('node:fs');
const { createHash } = require('node:crypto');
const { Module, createRequire } = require('node:module');
const hash = source => createHash('sha256').update(source).digest('hex');
const corePath = require.resolve('../../server/database/postgres/workshopPlatformSeedCore');
if (hash(fs.readFileSync(corePath)) !==
    'bf9ea4a6eb8beff236e8eb86188058aef886b797aa4c37ae418f20cee8ff48dd')
  throw new Error('historical catalog seed core source changed');
// A source view restores only the three later metadata no-op guards. The
// reconstructed module must match the exact archived release checksum.
const provenancePath = require.resolve('../../server/database/postgres/catalogDefaultProvenance');
let historicalSource = fs.readFileSync(provenancePath, 'utf8');
const guards = [
  "\n        AND (source_version IS DISTINCT FROM $5 OR source_hash IS DISTINCT FROM $6\n          OR source_document IS DISTINCT FROM $7::jsonb OR observed_document IS DISTINCT FROM $8::jsonb)",
  "\n      AND (source_version IS DISTINCT FROM $5 OR source_hash IS DISTINCT FROM $6\n        OR source_document IS DISTINCT FROM $7::jsonb OR observed_document IS DISTINCT FROM $8::jsonb)",
  "\n    AND (provenance_state IS DISTINCT FROM 'managed' OR source_version IS DISTINCT FROM $5\n      OR source_hash IS DISTINCT FROM $6 OR source_document IS DISTINCT FROM $7::jsonb\n      OR applied_default_version IS DISTINCT FROM $5 OR applied_default_hash IS DISTINCT FROM $6\n      OR applied_default_document IS DISTINCT FROM $7::jsonb OR observed_document IS DISTINCT FROM $7::jsonb)",
];
for (const guard of guards) historicalSource = historicalSource.replace(guard, '');
if (hash(historicalSource) !== 'd141c235826cf0a379fc202f970654fdf970f080a3ee816cee06934294b3aa31')
  throw new Error('historical catalog provenance source view changed');
const historicalModule = new Module(provenancePath, module);
historicalModule.filename = provenancePath;
historicalModule.require = createRequire(provenancePath);
historicalModule._compile(historicalSource, provenancePath);
const provenance = historicalModule.exports;
const { createWorkshopPlatformSeed } = require('../../server/database/postgres/workshopPlatformSeedCore');
const challengeKeys = Object.fromEntries(Object.entries(fixture.challengeKeys)
  .map(([challenge, workshop]) => [workshop, challenge]));
const historicalSeed = createWorkshopPlatformSeed({ withTransaction, bump, provenance,
  toChallengeKey: workshop => challengeKeys[workshop] || workshop,
  legacyXssSolutions: fixture.legacyXssSolutions });
function defaults(curriculum = fixture.newCurriculum) {
  return { catalog: { ...fixture.catalog, secureshop_agent_security: curriculum.OBJECTIVES },
    hints: { ...fixture.hints, secureshop_agent_security: curriculum.HINTS },
    solutions: { ...fixture.solutions, secureshop_agent_security: curriculum.SOLUTIONS },
    challenges: fixture.challenges.map(row => row.key === curriculum.CHALLENGE.key
      ? curriculum.CHALLENGE : row), catalogVersion: 'historical-catalog-release-116' };
}
async function seedRelease116(pool, curriculum) {
  return historicalSeed(pool, defaults(curriculum));
}
// Before field-provenance schema exists, arrange the original default rows
// explicitly. This is test data insertion, not a second runtime seeder.
async function arrangePrior116(pool) {
  const { catalog, hints, solutions, challenges } = defaults(fixture.oldCurriculum);
  return withTransaction(pool, async client => {
    let ordinal = 0;
    for (const [workshop, objectives] of Object.entries(catalog)) {
      const challenge = challengeKeys[workshop] || workshop;
      const meta = challenges.find(row => row.key === challenge) || {};
      await client.query(`INSERT INTO workshop_platform.exercises
        (workshop_key,challenge_key,challenge_name,challenge_description,category,difficulty,route,ordinal,is_visible)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [workshop,challenge,meta.name || workshop,
        meta.description || '',meta.category || 'ai',meta.difficulty || 'intermediate',
        meta.route || '',ordinal++,meta.defaultVisible !== false]);
      for (const [index, objective] of objectives.entries()) {
        const solution = solutions[workshop]?.[objective.id];
        const hint = hints[workshop]?.[objective.id] ||
          (['sql_injection_workshop','nosql_injection_workshop'].includes(workshop) && solution
            ? { title: solution.title, hints: solution.hints || [] } : null);
        await client.query(`INSERT INTO workshop_platform.objectives
          (workshop_key,objective_id,label,ordinal,hint_content,solution_content,is_enabled)
          VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7)`, [workshop,objective.id,objective.text,
          index,hint ? JSON.stringify(hint) : null,solution ? JSON.stringify(solution) : null,
          objective.defaultEnabled !== false]);
      }
    }
    await client.query('UPDATE workshop_platform.config_revision SET revision=revision+1 WHERE id=1');
    await bump(client, { scopeType: 'global', scopeKey: '*', category: 'workshop_config' });
  });
}
module.exports = { fixture, seedRelease116, arrangePrior116 };
