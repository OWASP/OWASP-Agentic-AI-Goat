'use strict';

const path = require('node:path');
const { isPlatformDataLifecycleRequested } = require('./platformDataLifecycleActivation');
const { readMigrations } = require('../../db/postgres/migrate');
const { createPool } = require('../database/postgres');
const { createEmailArtifactRepository } = require('../database/postgres/emailArtifactRepository');
const { createStudentDeletionComposition } = require('./studentDeletionComposition');

const STORES = Object.freeze({
  identity: Object.freeze({ runtimeEnv: 'IDENTITY_DATABASE_URL', migrationEnv: 'IDENTITY_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_identity_runtime', migrationRole: 'dvaia_identity_migration',
    directory: path.join(__dirname, '../../db/postgres/identity-migrations'),
    capabilities: Object.freeze(['identity.finalize_student_deletion(uuid,uuid,integer)',
      'legacy_ai_private.cleanup_history_for_student_deletion(uuid,uuid,integer)',
      'identity.list_legacy_upload_cleanup(integer)','identity.retire_legacy_uploads(integer)',
      'identity.assert_legacy_platform_mutation(integer,bigint)']) }),
  xss: Object.freeze({ runtimeEnv: 'XSS_WORKSHOP_DATABASE_URL', migrationEnv: 'XSS_WORKSHOP_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_xss_runtime', migrationRole: 'dvaia_xss_migration',
    directory: path.join(__dirname, '../../db/postgres/workshop-migrations/xss'),
    capabilities: Object.freeze(['xss.destroy_student_owner(bigint)']) }),
  finflow: Object.freeze({ runtimeEnv: 'FINFLOW_WORKSHOP_DATABASE_URL', migrationEnv: 'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_finflow_runtime', migrationRole: 'dvaia_finflow_migration',
    directory: path.join(__dirname, '../../db/postgres/workshop-migrations/finflow'),
    capabilities: Object.freeze(['finflow.destroy_student_owner(bigint,uuid)',
      'finflow.begin_owner_resource_deletion(uuid,bigint)',
      'finflow.complete_owner_resource_deletion(uuid,bigint,uuid[])']) }),
  legacyChallenge: Object.freeze({ runtimeEnv: 'LEGACY_CHALLENGE_DATABASE_URL', migrationEnv: 'LEGACY_CHALLENGE_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_legacy_challenge_runtime', migrationRole: 'dvaia_legacy_challenge_migration',
    directory: path.join(__dirname, '../../db/postgres/workshop-migrations/legacy_challenge'),
    capabilities: Object.freeze(['legacy_challenge.destroy_student_owner(integer,uuid[])']) }),
  sensitiveLookup: Object.freeze({ runtimeEnv: 'SENSITIVE_LOOKUP_DATABASE_URL', migrationEnv: 'SENSITIVE_LOOKUP_MIGRATION_DATABASE_URL',
    runtimeRole: 'dvaia_sensitive_lookup_runtime', migrationRole: 'dvaia_sensitive_lookup_migration',
    directory: path.join(__dirname, '../../db/postgres/workshop-migrations/sensitive_lookup'),
    capabilities: Object.freeze(['sensitive_lookup.destroy_student_owner(text)']) }),
});
function unavailable(message = 'Student deletion cleanup is unavailable') {
  return Object.assign(new Error(message), { code: 'DELETION_UNAVAILABLE', statusCode: 503 });
}
async function assertLedger(pool, directory) {
  const expected = await readMigrations(directory);
  const actual = (await pool.query('SELECT name,checksum FROM dvaia_migrations.ledger ORDER BY name')).rows;
  if (actual.length !== expected.length || actual.some((row,index) => row.name !== expected[index].name
      || row.checksum !== expected[index].checksum)) throw unavailable('Student deletion migration history is not ready');
}
async function assertStudentDeletionStoreReadiness(name, runtimePool, migrationPool) {
  const config=STORES[name];
  if (!config || typeof runtimePool?.query !== 'function' || typeof migrationPool?.query !== 'function') throw unavailable();
  const runtime=(await runtimePool.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  const migration=(await migrationPool.query('SELECT current_user AS role,current_database() AS database')).rows[0];
  if(runtime?.role!==config.runtimeRole||migration?.role!==config.migrationRole||!runtime.database
      ||runtime.database!==migration.database)throw unavailable('Student deletion store identity is not ready');
  await assertLedger(migrationPool,config.directory);
  for(const signature of config.capabilities){
    const capability=(await runtimePool.query(`WITH object AS (SELECT to_regprocedure($1) AS oid)
      SELECT oid IS NOT NULL AS present,
      CASE WHEN oid IS NULL THEN false ELSE has_function_privilege(current_user,oid,'EXECUTE') END AS executable,
      NOT EXISTS(SELECT 1 FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) privilege
        WHERE p.oid=object.oid AND privilege.grantee=0
          AND privilege.privilege_type='EXECUTE') AS public_revoked FROM object`,[signature])).rows[0];
    if(capability?.present!==true||capability.executable!==true||capability.public_revoked!==true) {
      throw unavailable('Student deletion finalizer capability is not ready');
    }
  }
  if(name==='identity')await createEmailArtifactRepository(runtimePool).assertReady();
  return runtime.database;
}
async function assertStudentDeletionReadiness({ runtimePools, migrationPools } = {}) {
  if (!runtimePools || !migrationPools) throw unavailable();
  const probes = await Promise.allSettled(Object.keys(STORES).map(name =>
    assertStudentDeletionStoreReadiness(name,runtimePools[name],migrationPools[name])));
  const failed=probes.find(result=>result.status==='rejected');
  if(failed)throw failed.reason;
  if(new Set(probes.map(result=>result.value)).size!==probes.length)throw unavailable('Student deletion stores are not isolated');
  return true;
}
async function assertOwnedStudentDeletionReadiness({ runtimePools, createMigrationPool = (env,key) => createPool(env,key), env=process.env } = {}) {
  if(!runtimePools||typeof createMigrationPool!=='function')throw unavailable();
  const databases=[];
  for(const [name,store] of Object.entries(STORES)){
    const migrationPool=createMigrationPool(env,store.migrationEnv);
    if(typeof migrationPool?.end!=='function')throw unavailable();
    try{databases.push(await assertStudentDeletionStoreReadiness(name,runtimePools[name],migrationPool));}
    finally{await migrationPool.end();}
  }
  if(new Set(databases).size!==databases.length)throw unavailable('Student deletion stores are not isolated');
  return true;
}

async function createFinflowDeletionTraversal({ pool, root, fsImpl } = {}) {
  const repository = require('../database/postgres/finflowTraversalTargetRepository')
    .createFinflowTraversalTargetRepository({ pool });
  await repository.assertReady();
  const manager = require('./finflowTraversalArtifacts').createFinflowTraversalManager({
    repository, ...(root === undefined ? {} : { root }), ...(fsImpl === undefined ? {} : { fsImpl }),
  });
  return Object.freeze({ repository, manager,
    retireOwner: owner => manager.retireOwner(owner) });
}

let retained; let pending; let closing;
async function getProductionStudentDeletionComposition() {
  if(closing)throw unavailable('Student deletion cleanup is closing');
  if(retained)return retained.value;
  if(pending)return pending;
  if(!isPlatformDataLifecycleRequested()
      ||Object.values(STORES).some(store=>!process.env[store.runtimeEnv]||!process.env[store.migrationEnv])) {
    throw unavailable('Student deletion store configuration is incomplete');
  }
  pending=(async()=>{
    const ctfRuntime=require('./ctfAuthorityProduction').getProductionCtfAuthority().runtime;
    if(typeof ctfRuntime?.deleteStudent!=='function')throw unavailable('CTF deletion authority unavailable');
    const runtimePools={identity:require('./postgresIdentityAdapter').getPostgresIdentityAdapter().pool};
    try{
      runtimePools.xss=createPool(process.env,STORES.xss.runtimeEnv);
      runtimePools.finflow=createPool(process.env,STORES.finflow.runtimeEnv);
      runtimePools.legacyChallenge=createPool(process.env,STORES.legacyChallenge.runtimeEnv);
      runtimePools.sensitiveLookup=createPool(process.env,STORES.sensitiveLookup.runtimeEnv);
      await assertOwnedStudentDeletionReadiness({runtimePools});
      const resourceLifecycle=await require('./finflowDurableResourceComposition')
        .createFinflowDurableResourceLifecycle({pool:runtimePools.finflow});
      const finflowTraversal=await createFinflowDeletionTraversal({pool:runtimePools.finflow,
        root:resourceLifecycle.roots.traversalRoot});
      const secureShop=await require('./secureshopCleanupComposition').getSecureShopCleanupComposition();
      const value=createStudentDeletionComposition({identityPool:runtimePools.identity,ctfRuntime,
        xssPool:runtimePools.xss,finflowPool:runtimePools.finflow,
        createSecureShopCleanup:secureShop.createStudentDeletionCleanup,
        sceneResetPreflight:secureShop.sceneResetPreflight,
        retireFinflowTraversalOwner:finflowTraversal.retireOwner,
        cleanupFinflowBackups:resourceLifecycle.cleanupOwner});
      if(closing)throw unavailable('Student deletion cleanup is closing');
      retained={value,ownedPools:[runtimePools.xss,runtimePools.finflow,
        runtimePools.legacyChallenge,runtimePools.sensitiveLookup]};return value;
    }catch(error){await Promise.allSettled([runtimePools.xss?.end(),runtimePools.finflow?.end(),
      runtimePools.legacyChallenge?.end(),runtimePools.sensitiveLookup?.end()]
      .filter(Boolean));throw error;}
  })();
  try{return await pending;}finally{pending=undefined;}
}
async function closeProductionStudentDeletionComposition(){
  if(closing)return closing;
  closing=(async()=>{if(pending){try{await pending;}catch{}}const owned=retained;retained=undefined;
    const results=await Promise.allSettled([...(owned?.ownedPools||[]).map(pool=>pool.end()),
      require('./secureshopCleanupComposition').closeSecureShopCleanupComposition()]);
    const errors=results.filter(result=>result.status==='rejected').map(result=>result.reason);
    require('./studentDeletionApplication').clearStudentDeletionApplication();
    if(errors.length)throw new AggregateError(errors,'Student deletion cleanup shutdown failed');})();
  try{await closing;}finally{closing=undefined;}
}
module.exports={STORES,assertStudentDeletionReadiness,assertOwnedStudentDeletionReadiness,createFinflowDeletionTraversal,getProductionStudentDeletionComposition,
  closeProductionStudentDeletionComposition};
