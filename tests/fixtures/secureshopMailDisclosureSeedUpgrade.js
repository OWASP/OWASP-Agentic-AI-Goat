'use strict';
const assert = require('node:assert/strict');
const key = 'secureshop_agent_security', id = 'ss_mail_cross_persona_read';

async function qualifyDisclosureNullPreservation({ migration, curriculum }) {
 const client = await migration.connect();
 const snapshot = async () => ({
  objectives: (await client.query('SELECT * FROM workshop_platform.objectives ORDER BY workshop_key,objective_id')).rows,
  defaults: (await client.query('SELECT * FROM workshop_platform.catalog_field_defaults ORDER BY entity_kind,workshop_key,objective_id,field_name')).rows,
  revision: (await client.query('SELECT * FROM workshop_platform.config_revision ORDER BY id')).rows,
 });
 let discard;
 try {
  const before = await snapshot();
  await client.query('BEGIN');
  try {
   for (const field of ['hint_content', 'solution_content']) {
    await client.query(`UPDATE workshop_platform.objectives SET ${field}=NULL WHERE workshop_key=$1 AND objective_id=$2`, [key, id]);
    const spec = { entityKind:'objective', workshopKey:key, objectiveId:id, fieldName:field,
     sourceValue:field==='hint_content'?curriculum.HINTS[id]:curriculum.SOLUTIONS[id], sourceVersion:'disclosure-null-fixture' };
    for (let attempt=0;attempt<2;attempt++) {
     const result=await require('../../server/database/postgres/catalogDefaultProvenance').reconcileField(client,spec);
     assert.equal(result.changed,false);
     const row=(await client.query(`SELECT ${field} AS value FROM workshop_platform.objectives WHERE workshop_key=$1 AND objective_id=$2`,[key,id])).rows[0];
     assert.equal(row.value,null);
    }
   }
  } finally {
   try { await client.query('ROLLBACK'); } catch(error) { discard=error; throw error; }
  }
  assert.deepEqual(await snapshot(),before,'Rollback must restore exact catalog, provenance and revision rows');
 } finally { client.release(discard); }
 return true;
}

async function qualifyDisclosureSeedUpgrade({ identity, migration, config }) {
 assert.equal(process.env.PG_TEST_DISPOSABLE, 'yes');
 const seed = require('../../server/database/postgres/workshopPlatformSeed');
 const curriculum = require('../../server/config/secureshopCurriculum');
 const prior = require('./secureshopMailDisclosurePriorDefaults.json');
 assert.equal(curriculum.isQualifiedObjective(id), true, 'Owned candidate must be staged before import');
 const read = async () => (await identity.query('SELECT objective_id,label,hint_content,solution_content,is_enabled,catalog_active FROM workshop_platform.objectives WHERE workshop_key=$1 ORDER BY objective_id', [key])).rows;
 const before = await read(), target = before.find(row => row.objective_id === id);
 assert(target);
 assert.deepEqual(target.hint_content, curriculum.HINTS[id]);
 assert.deepEqual(target.solution_content, curriculum.SOLUTIONS[id]);
 const hints = require('../../server/data/workshopHints'), solutions = seed.solutionFixtures();
 await seed.seedWorkshopPlatform(migration, {
  hints: { ...hints, [key]: { ...hints[key], [id]: prior.hint } },
  solutions: { ...solutions, [key]: { ...solutions[key], [id]: prior.solution } },
 });
 const pending = (await read()).find(row => row.objective_id === id);
 assert.deepEqual(pending.hint_content, prior.hint);
 assert.deepEqual(pending.solution_content, prior.solution);
 await seed.seedWorkshopPlatform(migration);
 assert.deepEqual(await read(), before);
 const revision = await config.getRevision();
 await seed.seedWorkshopPlatform(migration);
 assert.deepEqual(await read(), before);
 assert.equal(await config.getRevision(), revision);
 await qualifyDisclosureNullPreservation({ migration, curriculum });
 const customHint = { ...target.hint_content, title: 'Owned instructor disclosure hint' };
 const customSolution = { ...target.solution_content, title: 'Owned instructor disclosure solution' };
 await config.updateHintContent(key, id, customHint);
 await config.updateSolutionContent(key, id, customSolution);
 const customized = await read();
 await seed.seedWorkshopPlatform(migration);
 await seed.seedWorkshopPlatform(migration);
 assert.deepEqual(await read(), customized);
 await config.updateHintContent(key, id, target.hint_content);
 await config.updateSolutionContent(key, id, target.solution_content);
 assert.deepEqual(await read(), before);
 return { managedPriorDefaultsAdvance: true, unchangedHintsPreserved: true,
  secondRunContentAndRevisionNoop: true, instructorHintAndSolutionPreserved: true,
  siblingCatalogRowsAndEnablementPreserved: true,
  scope: 'Representative populated pending content staged via canonical seed overrides; not historical installation import',
  explicitStoredNullPreservedAndRolledBack: true,
  nullScope: 'Representative out-of-band stored SQL null reconciled on one transaction client; not a supported UI mutation. Full catalog/provenance/revision restored by rollback' };
}
module.exports = { qualifyDisclosureSeedUpgrade, qualifyDisclosureNullPreservation };
