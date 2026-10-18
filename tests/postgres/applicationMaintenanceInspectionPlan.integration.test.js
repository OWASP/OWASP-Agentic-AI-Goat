'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path'),{createHash}=require('node:crypto'),{spawn}=require('node:child_process'),{Client}=require('pg');
function identityAdminUrl(value){const url=new URL(value);url.pathname='/dvaia_identity';return url.href;}
test('identity diagnostic URL changes database only, preserving admin role and credential',()=>{
 for(const value of ['postgresql://postgres:owned%2Fpostgres@127.0.0.1:49123/postgres','postgresql://postgres@127.0.0.1:49123/postgres?application_name=postgres']){
  const before=new URL(value),after=new URL(identityAdminUrl(value));assert.equal(after.pathname,'/dvaia_identity');for(const key of ['username','password','host','search','protocol'])assert.equal(after[key],before[key]);
 }
});
function ownedStoreUrl(environment,store){
 const row=require('../../db/postgres/provision-application').provisioningPlan().find(row=>row.schema===store);
 assert(row,'Unknown owned store');const value=environment[row.runtimeVariable];assert.equal(typeof value,'string','Owned store URL required');return value;
}
function ownedEndpoint(value,admin){const target=new URL(value);assert.equal(target.hostname,admin.hostname);assert.equal(target.port,admin.port);return target.href;}
test('owned runtime probes use canonical variable and reject implicit/default endpoints',()=>{
 const admin=new URL('postgresql://postgres@127.0.0.1:49123/postgres');
 const expected='postgresql://dvaia_aria_runtime@127.0.0.1:49123/dvaia_aria';
 assert.equal(ownedEndpoint(ownedStoreUrl({SQL_WORKSHOP_DATABASE_URL:expected},'aria'),admin),expected);
 assert.throws(()=>ownedStoreUrl({ARIA_DATABASE_URL:expected},'aria'));
 for(const bad of [undefined,'postgresql://postgres@127.0.0.1:5432/postgres','postgresql://postgres@localhost:49123/postgres'])assert.throws(()=>ownedEndpoint(bad,admin));
});
const enabled=process.env.SETUP_DATABASE_PHASE_ISOLATED==='1'&&process.env.SETUP_PHASE_SCENARIO==='inspection-plan';
test('actual recovery CLI observes canonical stores without granting recovery or altering private state',{skip:!enabled,timeout:240000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');const root=await fs.realpath(process.cwd()),evidence=await fs.realpath(process.env.SETUP_PHASE_EVIDENCE_ROOT);assert.equal(root,await fs.realpath(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));assert.equal(path.dirname(root),evidence);assert.match(path.basename(evidence),/^dvaia-setup-phase-/);assert.match(process.env.SETUP_PHASE_OWNER,/^[a-f0-9]{32}$/);
 const adminUrl=new URL(process.env.PG_ADMIN_DATABASE_URL);assert.equal(adminUrl.hostname,'127.0.0.1');assert.equal(adminUrl.pathname,'/postgres');
 const home=path.join(evidence,'plan-home');await fs.mkdir(home,{mode:0o700});const id=createHash('sha256').update(root).digest('hex').slice(0,12),directory=path.join(home,'.dvaia',id);await fs.mkdir(directory,{recursive:true,mode:0o700});
 const manifestPath=path.join(directory,'provisioning.json'),envPath=path.join(root,'.env'),deliveryPath=path.join(directory,'ctf-delivery.json');await assert.rejects(fs.lstat(envPath),{code:'ENOENT'});
 const clients=new Set(),children=new Set();let lease;const result={status:'running',cases:[],recoveryAuthorized:false,scope:'Real CLI observations only; no recovery execution, TLS or password-rejection proof'};
 const save=()=>fs.writeFile(path.join(evidence,'inspection-plan-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});
 async function connect(url){url=ownedEndpoint(url,adminUrl);const c=new Client({connectionString:url,connectionTimeoutMillis:3000,query_timeout:3000,statement_timeout:3000});clients.add(c);c.on('error',()=>{});await c.connect();return c;}
 async function bounded(work,ms){let timer;try{return await Promise.race([Promise.resolve().then(work),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned cleanup unconfirmed')),ms);})]);}finally{clearTimeout(timer);}}
 async function close(c){await bounded(()=>c.end(),3000);clients.delete(c);}
 async function privateSnapshot(){const map=new Map();for(const p of [manifestPath,envPath,deliveryPath,path.join(directory,'local-postgres.json')])try{map.set(p,await fs.readFile(p));}catch(e){if(e.code!=='ENOENT')throw e;}return map;}
 const extraSecrets=[];
 async function sql(query){const c=await connect(identityAdminUrl(adminUrl.href));try{return(await c.query(query)).rows;}finally{await close(c);}}
 async function run(name,explicit=true){
  const beforePrivate=await privateSnapshot();
  const env={PATH:path.dirname(process.execPath)+':/usr/bin:/bin',HOME:home,NODE_ENV:'test',...(explicit?{PG_ADMIN_DATABASE_URL:adminUrl.href}:{})};const child=spawn(process.execPath,['scripts/application-maintenance-recovery.js','--plan'],{cwd:root,env,stdio:['ignore','pipe','pipe']});children.add(child);let stdout='',stderr='',expired=false;
  child.stdout.on('data',b=>{stdout+=b;if(stdout.length>65536)child.kill('SIGKILL');});child.stderr.on('data',b=>{stderr+=b;if(stderr.length>65536)child.kill('SIGKILL');});
  const ended=new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',code=>{children.delete(child);resolve(code);});});
  let code;try{code=await bounded(()=>ended,90000);}catch{expired=true;child.kill('SIGKILL');await bounded(()=>ended,3000);}assert.equal(expired,false,'CLI deadline exceeded');
  const afterPrivate=await privateSnapshot();assert.equal(afterPrivate.size,beforePrivate.size,'CLI changed private file set');for(const [p,bytes]of beforePrivate)assert.equal(afterPrivate.get(p)?.equals(bytes),true,'CLI changed private bytes');
  for(const secret of [...Object.values(environment),...extraSecrets].filter(x=>x.startsWith('postgres'))){assert.equal((stdout+stderr).includes(secret),false,'CLI exposed private URL');const password=new URL(secret).password;if(password)assert.equal((stdout+stderr).includes(password),false,'CLI exposed credential');}
  assert.equal((stdout+stderr).includes('a'.repeat(64)),false,'CLI exposed local secret');let value;try{value=JSON.parse(stdout);}catch{}if(value){assert.equal(value.recoveryExecutable,false);assert.equal(value.recoveryAuthorized,false);}
  result.cases.push({name,exitCode:code,status:value?.storeInspection?.status||'unavailable',code:value?.storeInspection?.code||null});await save();return{code,value};
 }
 let environment;
 try{
  const a=await connect(adminUrl.href);assert.equal((await a.query("SELECT count(*)::int AS n FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')")).rows[0].n,0);await close(a);
  const p=await require('../../db/postgres/provision-application').provisionApplication({adminUrl:adminUrl.href,manifestPath,env:{PG_TLS:'disable'}});environment={...p.configuration,PG_TLS:'disable'};
  const encode=()=>Object.entries(environment).map(([k,v])=>`${k}=${JSON.stringify(v)}`).join('\n')+'\n';await fs.writeFile(envPath,encode(),{mode:0o600});
  assert.equal((await run('fresh-uninitialized')).code,1);assert.equal((await sql("SELECT to_regnamespace('dvaia_maintenance') IS NULL AS absent"))[0].absent,true);
  const acquire=()=>require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'maintenance',env:environment});lease=await acquire();const token=await lease.beginMaintenance();await lease.finishMaintenance(token);await lease.close();lease=null;
  const snapshot=()=>sql('SELECT row_to_json(c)::text AS value FROM dvaia_maintenance.control c UNION ALL SELECT row_to_json(e)::text FROM dvaia_maintenance.epochs e UNION ALL SELECT row_to_json(l)::text FROM dvaia_maintenance.ledger l ORDER BY value');const before=await snapshot();
  for(const name of ['clean','noop']){const x=await run(name);assert.equal(x.code,0);assert.equal(x.value.storeInspection.storeCount,16);assert.equal(x.value.storeInspection.deliveryPresent,false);}
  await fs.writeFile(path.join(directory,'local-postgres.json'),JSON.stringify({version:1,id,name:`dvaia-postgres-${id}`,port:Number(adminUrl.port),password:'a'.repeat(64)}),{mode:0o600});assert.equal((await run('local-state',false)).code,0);
  const idle=await connect(ownedStoreUrl(environment,'aria'));const blocked=await run('idle-runtime');assert.equal(blocked.code,1);assert.equal(blocked.value.storeInspection.code,'MAINTENANCE_INSPECTION_OTHER_BACKEND');await close(idle);
  lease=await require('../../server/services/applicationMaintenanceLease').acquireApplicationMaintenanceLease({mode:'application',env:environment});assert.equal((await run('shared-lease')).code,1);await lease.close();lease=null;
  const original=await fs.readFile(envPath);await fs.appendFile(envPath,'IDENTITY_DATABASE_URL: '+environment.IDENTITY_DATABASE_URL+'\n');assert.equal((await run('colon-duplicate')).code,1);await fs.writeFile(envPath,original);await fs.chmod(envPath,0o644);assert.equal((await run('public-mode')).code,1);await fs.chmod(envPath,0o600);
  const d=await require('../../db/postgres/provision-ctf-delivery').provisionCtfDelivery({adminUrl:adminUrl.href,manifestPath,outputPath:deliveryPath,env:environment});extraSecrets.push(...Object.values(d.configuration));assert.equal((await run('partial-delivery')).code,1);Object.assign(environment,d.configuration);await fs.writeFile(envPath,encode());const privatePaths=[manifestPath,envPath,deliveryPath,path.join(directory,'local-postgres.json')],privateBytes=await Promise.all(privatePaths.map(p=>fs.readFile(p)));const complete=await run('delivery');assert.equal(complete.code,0);assert.equal(complete.value.storeInspection.deliveryPresent,true);
  assert.equal(JSON.stringify(await snapshot())===JSON.stringify(before),true,'Diagnostic changed maintenance history');
  lease=await acquire();await lease.beginMaintenance();await lease.close();lease=null;const dirty=await snapshot();const observed=await run('legacy-dirty');assert.equal(observed.code,0);assert.equal(observed.value.state,'dirty');assert.equal(JSON.stringify(await snapshot())===JSON.stringify(dirty),true,'Dirty epoch changed');
  for(let i=0;i<privatePaths.length;i++)assert.equal((await fs.readFile(privatePaths[i])).equals(privateBytes[i]),true,'Private bytes changed');result.status='passed';
 }finally{const errors=[];for(const child of children){try{const ended=new Promise(resolve=>child.once('close',resolve));child.kill('SIGKILL');await bounded(()=>ended,3000);children.delete(child);}catch{errors.push('CHILD_CLOSE_UNCONFIRMED');}}for(const c of clients)try{await close(c);}catch{errors.push('CLIENT_CLOSE_FAILED');}if(lease)try{await lease.close();}catch{errors.push('LEASE_CLOSE_FAILED');}result.cleanup={errors,clientsRemaining:clients.size,childrenRemaining:children.size};await save();assert.equal(errors.length,0,'Owned cleanup failed');}
});
