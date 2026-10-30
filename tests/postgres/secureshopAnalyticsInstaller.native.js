'use strict';
// Invoked only by an owned, deadline-bound parent in a frozen disposable copy.
const assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {execFile}=require('node:child_process'),{promisify}=require('node:util');
const exec=promisify(execFile),installer=require('../../scripts/install/analytics-target');
const {getOwnedAnalyticsProduction}=require('../../server/services/secureshopOwnedAnalyticsProduction');
const {readManagedAnalyticsConfiguration}=require('../../server/services/secureshopAnalyticsManagedConfiguration');
const {Pool}=require('pg');
async function main(){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const root=path.resolve(__dirname,'../..'),homeDirectory=process.env.ANALYTICS_INSTALL_TEST_HOME;
 assert.ok(homeDirectory&&path.isAbsolute(homeDirectory));assert.equal(root,process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
 const options={root,homeDirectory},p=installer.plan(options),checks=[];
 await fs.mkdir(p.directory,{recursive:true,mode:0o700});
 const legacy=process.env.ANALYTICS_LEGACY_UPGRADE==='yes';const initialInstaller=legacy?require('../../scripts/install/analytics-target-legacy-fixture'):installer;
 const first=await initialInstaller.provision(options);assert.equal(first.created,true);assert.equal(first.enabled,false);
 const original=await fs.readFile(p.managedFile),record=await readManagedAnalyticsConfiguration(options);
 assert.equal((await fs.stat(p.managedFile)).mode&0o777,0o600);checks.push('fresh-private-install');
 let legacyTarget,legacyScope,legacyPool;
 if(legacy){
  const config=record.config;legacyPool=new Pool({host:'127.0.0.1',port:config.port,user:'analytics_service_admin',password:config.password,database:config.identity.controlDatabase,max:2});
  const connection={host:'127.0.0.1',port:config.port,user:'analytics_service_admin',password:config.password};
  const service=require('../../sidecars/analytics-sql-target/service').createOwnedAnalyticsService({controlPool:legacyPool,identity:config.identity,createPool:o=>new Pool(o),connection});
  const old={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:1};await service.provision(old);
  const disabled=await getOwnedAnalyticsProduction(options);try{await disabled.assertReady();assert.equal(disabled.fixedCapabilities,false);assert.equal((await disabled.service.retire(old)).retired,true);}finally{await disabled.close();}
  legacyScope={...old,launchId:randomUUID()};legacyTarget=await service.provision(legacyScope);checks.push('current-disabled-legacy1-cleanup');
 }
 const repeat=await installer.provision(options);assert.equal(repeat.created,false);assert.equal(repeat.containerId,first.containerId);
 assert.deepEqual(await fs.readFile(p.managedFile),original);checks.push('repeat-preserves-private-identity');
 if(legacy){const ready=await require('../../sidecars/analytics-sql-target/bootstrap').assertControlReady({pool:legacyPool,identity:record.config.identity,requiredVersion:2});assert.equal(ready.appliedVersion,2);assert.equal((await legacyPool.query('SELECT count(*)::integer AS n FROM owned_analytics_targets WHERE target_id=$1',[legacyTarget.targetId])).rows[0].n,1);const cleanup=await getOwnedAnalyticsProduction(options);try{await cleanup.assertReady();assert.equal(cleanup.fixedCapabilities,true);await cleanup.service.retire(legacyScope);}finally{await cleanup.close();await legacyPool.end();}checks.push('current-installer-populated1-to2-preserves-target-and-private-bytes');}
 await exec('docker',['--host',process.env.DOCKER_HOST,'stop','--time','5',first.containerId],{timeout:15000});
 const resumed=await installer.provision(options);assert.equal(resumed.containerId,first.containerId);assert.deepEqual(await fs.readFile(p.managedFile),original);checks.push('exact-stopped-container-resume');
 let runtime=await getOwnedAnalyticsProduction(options);
 try{assert.equal(runtime.admissions,false);assert.equal(await getOwnedAnalyticsProduction(options),runtime);await runtime.assertReady();
  await assert.rejects(runtime.service.provision({}),{code:'ANALYTICS_ADMISSIONS_DISABLED'});
 }finally{await runtime.close();}
 checks.push('disabled-shared-runtime-readiness');
 await fs.writeFile(p.managedFile,JSON.stringify({...record.config,enabled:true})+'\n',{mode:0o600});
 runtime=await getOwnedAnalyticsProduction(options);
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:1};
 let target;
 try{await runtime.assertReady();assert.equal(runtime.fixedCapabilities,true);target=await runtime.service.provision(scope);await runtime.service.prepareFixed(scope);
  const request={target,operationId:randomUUID(),runId:randomUUID(),requestId:randomUUID(),sessionId:randomUUID(),callId:'installer-native',sql:'SELECT COUNT(*) AS count FROM products'};
  request.mode={version:1,mode:'fixed',generation:0,modeStamp:'installer-native'};const result=await runtime.service.execute(request);assert.equal(Number(result.result.rows[0].count),256);assert.deepEqual(await runtime.service.execute(request),result);assert.equal(result.version,3);const denied=await runtime.service.execute({...request,operationId:randomUUID(),requestId:randomUUID(),sql:'SELECT api_key FROM shop_users'});assert.equal(denied.version,4);assert.equal(denied.denial.code,'42501');assert.equal(denied.denial.backendAbsent,true);
 }finally{await runtime.close();}
 checks.push('real-isolated-sql-and-replay');
 await fs.writeFile(p.managedFile,original,{mode:0o600});runtime=await getOwnedAnalyticsProduction(options);
 try{assert.equal(runtime.admissions,false);assert.equal((await runtime.service.retire(scope)).retired,true);}finally{await runtime.close();}
 const config=record.config,pool=new Pool({host:'127.0.0.1',port:config.port,user:'analytics_service_admin',password:config.password,database:config.identity.controlDatabase,max:1});
 try{const name='analytics_'+target.targetId.replaceAll('-','');assert.equal((await pool.query('SELECT 1 FROM pg_database WHERE datname=$1',[name])).rowCount,0);assert.equal((await pool.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[name])).rowCount,0);assert.equal((await pool.query('SELECT 1 FROM pg_roles WHERE rolname=$1',[name+'_metrics'])).rowCount,0);}finally{await pool.end();}
 checks.push('disabled-retirement-removes-exact-target');
 // Real setup helper against a separately owned application-state cluster.
 const migrationUrl=new URL(process.env.ANALYTICS_SETUP_MIGRATION_URL),runtimeUrl=new URL(process.env.ANALYTICS_SETUP_RUNTIME_URL);
 assert.equal(migrationUrl.hostname,'127.0.0.1');assert.equal(runtimeUrl.hostname,'127.0.0.1');assert.equal(migrationUrl.pathname,'/owasp_ai_goat_test_setup_'+p.workspaceId);assert.equal(runtimeUrl.pathname,migrationUrl.pathname);assert.notEqual(Number(runtimeUrl.port),config.port);
 const migration=new Pool({connectionString:migrationUrl.href,max:1});
 try{
  const {migrate}=require('../../db/postgres/migrate'),canonical=path.join(root,'db/postgres/workshop-migrations/secureshop_agents'),folder=path.join(homeDirectory,'staged-agents');await fs.cp(canonical,folder,{recursive:true});assert.ok((await fs.readdir(folder)).includes('0034_analytics_mode_admission.sql'));await migrate(migration,folder);assert.deepEqual(await migrate(migration,folder),[]);
  const {setupOwnedAnalytics}=require('../../scripts/install/analytics-setup'),applicationEnvironment={SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SECURESHOP_AGENTS_DATABASE_URL:runtimeUrl.href};
  const setupOptions={...options,requested:true,applicationEnvironment};
  assert.equal((await setupOwnedAnalytics(setupOptions)).activationEnabled,false);assert.deepEqual(await fs.readFile(p.managedFile),original);
  await migration.query('ALTER TABLE secureshop_agents.analytics_request_admissions DISABLE TRIGGER analytics_mode_admission_guard');
  try{await assert.rejects(setupOwnedAnalytics({...setupOptions,explicitActivation:true}),{code:'ANALYTICS_NOT_READY'});assert.deepEqual(await fs.readFile(p.managedFile),original);}
  finally{await migration.query('ALTER TABLE secureshop_agents.analytics_request_admissions ENABLE TRIGGER analytics_mode_admission_guard');}
  assert.deepEqual(await setupOwnedAnalytics({...setupOptions,explicitActivation:true}),{requested:true,activationEnabled:true,changed:true});
  const activated=await fs.readFile(p.managedFile);assert.deepEqual(JSON.parse(activated),{...config,enabled:true});
  assert.deepEqual(await setupOwnedAnalytics(setupOptions),{requested:true,activationEnabled:true,changed:false});assert.deepEqual(await fs.readFile(p.managedFile),activated);
  checks.push('real-setup-request-schema-drift-preserves-disabled-config','explicit-staged-activation-and-noop-preserve-private-identity');
 }finally{await migration.end();}
 await fs.writeFile(process.env.ANALYTICS_INSTALL_TEST_RESULT,JSON.stringify({passed:true,checks,containerId:first.containerId,workspaceId:p.workspaceId,managedSha256:createHash('sha256').update(original).digest('hex'),modelCalls:0})+'\n',{mode:0o600});
}
main().catch(error=>{console.error(error.code||error.name);console.error(String(error.stack||'').split('\n').filter(line=>/^\s+at /.test(line)).join('\n'));process.exitCode=1;});
