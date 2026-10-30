'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {provisionApplication,provisioningPlan}=require('../db/postgres/provision-application');
test('provision plan contains only sixteen fixed names and no credentials',()=>{const plan=provisioningPlan();assert.equal(plan.length,16);assert.ok(plan.every(row=>/^owasp_ai_goat_[a-z_]+$/.test(row.database)));assert.doesNotMatch(JSON.stringify(plan),/password|postgresql:\/\//);});
test('collision preflight creates no roles, files or databases',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provision-test-')),queries=[];
 try{await assert.rejects(provisionApplication({adminUrl:'postgresql://admin:secret@localhost/postgres',manifestPath:path.join(dir,'manifest.json'),clientFactory:()=>({connect:async()=>{},end:async()=>{},query:async(sql)=>{queries.push(sql);return{rows:sql.includes('server_version_num')?[{server_version_num:'180000'}]:sql.includes('pg_control_system')?[{system_identifier:'fixture'}]:sql.includes('UNION ALL')?[{name:'owasp_ai_goat_identity'}]:[]};}})}),{code:'PROVISIONING_NAME_COLLISION'});assert.ok(!queries.some(sql=>sql.startsWith('CREATE')));assert.ok(queries.findIndex(sql=>sql.includes('server_version_num'))<queries.findIndex(sql=>sql.includes('pg_advisory_lock')));assert.deepEqual(await fs.readdir(dir),[]);}finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('fresh provision persists exclusive private credentials and emits no secret in public plan',async()=>{
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provision-test-'));const file=path.join(dir,'manifest.json');
 try{const result=await provisionApplication({adminUrl:'postgresql://admin:secret@localhost/postgres',manifestPath:file,clientFactory:()=>({connect:async()=>{},end:async()=>{},query:async(sql)=>({rows:sql.includes('server_version_num')?[{server_version_num:'180000'}]:sql.includes('pg_control_system')?[{system_identifier:'fixture'}]:[]})})});const manifest=JSON.parse(await fs.readFile(file,'utf8'));assert.equal(manifest.status,'complete');assert.equal(Object.keys(result.configuration).length,32);assert.equal((await fs.stat(file)).mode&0o777,0o600);assert.equal(manifest.created.length,48);assert.notEqual(new URL(result.configuration.IDENTITY_DATABASE_URL).password,new URL(result.configuration.IDENTITY_MIGRATION_DATABASE_URL).password);}finally{await fs.rm(dir,{recursive:true,force:true});}
});
test('PostgreSQL major version is validated before locks, DDL, or manifest creation',async()=>{
 const cases=[
  {value:'170009',code:'POSTGRES_VERSION_UNSUPPORTED'},
  {value:'190000',code:'POSTGRES_VERSION_UNSUPPORTED'},
  {value:undefined,code:'POSTGRES_VERSION_UNAVAILABLE'},
  {value:'18.0',code:'POSTGRES_VERSION_INVALID'},
 ];
 for(const item of cases){
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'provision-version-test-')),file=path.join(dir,'manifest.json'),queries=[];let ended=false;
  try{
   await assert.rejects(provisionApplication({adminUrl:'postgresql://admin:secret@localhost/postgres',manifestPath:file,clientFactory:()=>({
    connect:async()=>{},end:async()=>{ended=true;},query:async sql=>{queries.push(sql);return{rows:sql.includes('server_version_num')&&item.value!==undefined?[{server_version_num:item.value}]:[]};},
   })}),{code:item.code});
   assert.equal(ended,true,item.code);
   assert.equal(queries.length,1,item.code);
   assert.match(queries[0],/server_version_num/);
   assert.equal(queries.some(sql=>/pg_advisory_lock|^CREATE |^GRANT |^REVOKE /.test(sql)),false,item.code);
   assert.deepEqual(await fs.readdir(dir),[],item.code);
  }finally{await fs.rm(dir,{recursive:true,force:true});}
 }
});
test('provision rejects remote plaintext and URL TLS overrides before connecting',async()=>{
 let connected=false;const clientFactory=()=>{connected=true;throw Error('unexpected');};
 await assert.rejects(provisionApplication({adminUrl:'postgresql://user:secret@remote.example/postgres',env:{},clientFactory}),{code:'REMOTE_POSTGRES_REQUIRES_TLS'});
 await assert.rejects(provisionApplication({adminUrl:'postgresql://user:secret@localhost/postgres?sslmode=disable',env:{},clientFactory}),{code:'ADMIN_URL_OPTIONS_NOT_SUPPORTED'});
 assert.equal(connected,false);
});

test('session disclosure has dedicated database and role configuration',()=>{const row=provisioningPlan().find(item=>item.schema==='session_disclosure');assert.equal(row.database,'owasp_ai_goat_session_disclosure');assert.equal(row.runtimeRole,'dvaia_session_disclosure_runtime');assert.equal(row.runtimeVariable,'SESSION_DISCLOSURE_DATABASE_URL');assert.equal(row.migrationVariable,'SESSION_DISCLOSURE_MIGRATION_DATABASE_URL');});

test('bound reviews have a dedicated database and role configuration',()=>{const row=provisioningPlan().find(item=>item.schema==='secureshop_review');assert.deepEqual(row,{schema:'secureshop_review',database:'owasp_ai_goat_secureshop_review',runtimeRole:'dvaia_secureshop_review_runtime',migrationRole:'dvaia_secureshop_review_migration',runtimeVariable:'SECURESHOP_REVIEW_DATABASE_URL',migrationVariable:'SECURESHOP_REVIEW_MIGRATION_DATABASE_URL'});});

test('fresh credential directory publication must succeed before any external DDL', async t => {
 const dir=await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(),'provision-durability-test-')));
 const file=path.join(dir,'manifest.json'),queries=[];
 const originalOpen=fs.open;let directoryClosed=false;
 t.mock.method(fs,'open',async(name,...args)=>{
  const handle=await originalOpen(name,...args);
  if(name!==dir)return handle;
  return {sync:async()=>{throw Object.assign(Error('controlled directory flush failure'),{code:'EIO'});},close:async()=>{directoryClosed=true;await handle.close();}};
 });
 try{
  await assert.rejects(provisionApplication({adminUrl:'postgresql://admin:secret@localhost/postgres',manifestPath:file,clientFactory:()=>({
   connect:async()=>{},end:async()=>{},query:async sql=>{queries.push(sql);return{rows:sql.includes('server_version_num')?[{server_version_num:'180000'}]:sql.includes('pg_control_system')?[{system_identifier:'fixture'}]:[]};},
  })}),{code:'EIO'});
  assert.equal(directoryClosed,true);
  assert.equal(queries.some(sql=>/^(CREATE|GRANT|REVOKE) /.test(sql)),false);
  const retained=JSON.parse(await fs.readFile(file,'utf8'));
  assert.equal(retained.status,'incomplete');assert.equal(Object.keys(retained.configuration).length,32);
  assert.deepEqual(retained.created,[]);
 }finally{t.mock.restoreAll();await fs.rm(dir,{recursive:true,force:true});}
});
