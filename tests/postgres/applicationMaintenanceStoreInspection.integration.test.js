'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const {Client}=require('pg');
const {provisionApplication,provisioningPlan}=require('../../db/postgres/provision-application');
const {provisionCtfDelivery}=require('../../db/postgres/provision-ctf-delivery');
const {acquireApplicationMaintenanceLease:acquire}=require('../../server/services/applicationMaintenanceLease');
const {createApplicationMaintenanceStoreInspection:createInspector}=require('../../server/database/postgres/applicationMaintenanceStoreInspection');
const {getPoolBudgetSnapshot}=require('../../server/database/postgres');
const enabled=process.env.SETUP_DATABASE_PHASE_ISOLATED==='1'&&process.env.SETUP_PHASE_SCENARIO==='store-inspection';
async function bounded(work,ms=5000){let timer;try{return await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned inspector fixture timeout')),ms);})]);}finally{clearTimeout(timer);}}
test('real canonical16 inspection authenticates roles, rejects each foreign backend and preserves lease ownership',{skip:!enabled,timeout:240000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 const root=await fs.realpath(process.cwd()),evidence=await fs.realpath(process.env.SETUP_PHASE_EVIDENCE_ROOT);
 assert.equal(root,await fs.realpath(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));assert.equal(path.dirname(root),evidence);assert.match(path.basename(evidence),/^dvaia-setup-phase-/);
 assert.match(process.env.SETUP_PHASE_OWNER,/^[a-f0-9]{32}$/);
 const adminUrl=new URL(process.env.PG_ADMIN_DATABASE_URL);assert.equal(adminUrl.hostname,'127.0.0.1');assert.equal(adminUrl.pathname,'/postgres');assert.match(adminUrl.port,/^[0-9]+$/);
 await assert.rejects(fs.lstat(path.join(root,'.env')),{code:'ENOENT'});
 const directory=path.join(evidence,'inspection-private');await fs.mkdir(directory,{mode:0o700});
 const manifestPath=path.join(directory,'provisioning.json'),deliveryManifestPath=path.join(directory,'delivery.json');
 const environment={PG_TLS:'disable',PG_POOL_BUDGET:'78',PG_ADMIN_DATABASE_URL:adminUrl.href};
 const clients=new Set();let lease,shared;const result={status:'running',realStores:[],idleBlocks:[],deliveryBlock:false,roleWideExemptionDenied:false,cleanup:{},scope:'Actual single owned PostgreSQL cluster observation only; no setup/recovery authorization or TLS proof'};
 const save=()=>fs.writeFile(path.join(evidence,'store-inspection-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
 async function connect(url){const c=new Client({connectionString:url,ssl:false,connectionTimeoutMillis:3000,query_timeout:3000,statement_timeout:3000});clients.add(c);c.on('error',()=>{});await bounded(()=>c.connect());return c;}
 async function close(c){await bounded(()=>c.end());clients.delete(c);}
 try{
  // Empty fresh owned cluster is a prerequisite, not permission to adopt databases.
  const admin=await connect(adminUrl.href);assert.equal((await admin.query("SELECT count(*)::int AS n FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')")).rows[0].n,0);
  await close(admin);
  const provisioned=await provisionApplication({adminUrl:adminUrl.href,manifestPath,env:environment});assert.equal(provisioned.status,'created');
  const delivery=await provisionCtfDelivery({adminUrl:adminUrl.href,manifestPath,outputPath:deliveryManifestPath,env:environment});
  const env={...environment,...provisioned.configuration,...delivery.configuration},manifest=JSON.parse(await fs.readFile(manifestPath,'utf8'));
  assert.equal(manifest.status,'complete');assert.equal(manifest.plan.length,16);
  const originalManifest=await fs.readFile(manifestPath),originalDelivery=await fs.readFile(deliveryManifestPath);
  const observer=await connect(adminUrl.href),expected=(await observer.query('SELECT oid::text,datname FROM pg_database WHERE datname=ANY($1::text[])',[provisioningPlan().map(p=>p.database)])).rows;
  assert.equal(expected.length,16);await close(observer);
  lease=await acquire({mode:'maintenance',env});
  const api=createInspector({environment:env,manifestPath,deliveryManifestPath,lease});
  const first=await api.inspect();assert.equal(first.recoveryAuthorized,false);assert.equal(first.recordedBackendsAbsent,true);
  assert.equal(first.stores.length,16);assert.equal(new Set(first.stores.map(s=>s.databaseOid)).size,16);
  for(const store of first.stores){assert.equal(String(store.databaseOid),expected.find(x=>x.datname===store.databaseName).oid);assert.equal(store.clusterIdentifier,manifest.cluster);result.realStores.push({key:store.storeKey,oid:store.databaseOid});}
  const budget=getPoolBudgetSnapshot(),activity=await connect(adminUrl.href);
  for(const store of provisioningPlan()){
   const c=await connect(env[store.runtimeVariable]);const row=(await c.query('SELECT pg_backend_pid() AS pid,session_user AS role,current_database() AS database')).rows[0];assert.equal(row.role,store.runtimeRole);assert.equal(row.database,store.database);
   // No transaction/query is active: idle sessions must still prevent drain proof.
   assert.equal((await activity.query('SELECT state FROM pg_stat_activity WHERE pid=$1',[row.pid])).rows[0].state,'idle');
   await assert.rejects(api.inspect(),{code:'MAINTENANCE_INSPECTION_OTHER_BACKEND'});result.idleBlocks.push(store.schema);await close(c);
  }
  const d=await connect(env.CTF_DELIVERY_DATABASE_URL);await assert.rejects(api.inspect(),{code:'MAINTENANCE_INSPECTION_OTHER_BACKEND'});result.deliveryBlock=true;await close(d);
  const sameRole=await connect(env.IDENTITY_MIGRATION_DATABASE_URL);await sameRole.query("SET application_name='dvaia-maintenance-lease'");await assert.rejects(api.inspect(),{code:'MAINTENANCE_INSPECTION_OTHER_BACKEND'});result.roleWideExemptionDenied=true;await close(sameRole);
  await assert.rejects(createInspector({environment:env,manifestPath,deliveryManifestPath,lease:{signal:new AbortController().signal,assertHeld(){},status(){return{state:'held',mode:'maintenance'};}}}).inspect(),{code:'MAINTENANCE_INSPECTION_UNAVAILABLE'});
  const wrong=path.join(directory,'wrong-cluster.json');await fs.writeFile(wrong,JSON.stringify({...manifest,cluster:'1'}),{mode:0o600});await assert.rejects(createInspector({environment:env,manifestPath:wrong,deliveryManifestPath,lease}).inspect(),{code:'MAINTENANCE_INSPECTION_UNAVAILABLE'});
  const hidden={...env,PG_ADMIN_DATABASE_URL:env.IDENTITY_MIGRATION_DATABASE_URL};await assert.rejects(createInspector({environment:hidden,manifestPath,deliveryManifestPath,lease}).inspect(),{code:'MAINTENANCE_INSPECTION_VISIBILITY_REQUIRED'});
  await assert.rejects(createInspector({environment:{...env,IDENTITY_DATABASE_URL:env.ARIA_DATABASE_URL},manifestPath,deliveryManifestPath,lease}).inspect(),{code:'MAINTENANCE_INSPECTION_CONFIGURATION_MISMATCH'});
  await close(activity);assert.equal((await api.inspect()).recordedBackendsAbsent,true);assert.deepEqual(getPoolBudgetSnapshot(),budget);
  assert.deepEqual(await fs.readFile(manifestPath),originalManifest);assert.deepEqual(await fs.readFile(deliveryManifestPath),originalDelivery);
  lease.assertHeld();await lease.close();lease=null;
  shared=await acquire({mode:'application',env});await assert.rejects(createInspector({environment:env,manifestPath,deliveryManifestPath,lease:shared}).inspect(),{code:'MAINTENANCE_INSPECTION_UNAVAILABLE'});await shared.close();shared=null;
  result.status='passed';await save();
 }finally{
  const errors=[];for(const c of clients)try{await close(c);}catch{errors.push('CLIENT_CLOSE_UNCONFIRMED');}
  for(const l of [shared,lease])if(l)try{await l.close();}catch{errors.push('LEASE_CLOSE_UNCONFIRMED');}
  result.cleanup={clientsClosed:clients.size===0,errors};await save();assert.deepEqual(errors,[]);
 }
});
