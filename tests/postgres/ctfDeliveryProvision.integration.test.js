'use strict';
// Requires an exclusively owned fresh PG18 cluster with TCP password auth.
// Reuses actual application provisioning; no migrations, installed config or services.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {Client}=require('pg');
const {provisionApplication,provisioningPlan}=require('../../db/postgres/provision-application');
const {provisionCtfDelivery}=require('../../db/postgres/provision-ctf-delivery');
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&process.env.PG_PROVISION_FRESH_CLUSTER==='yes'&&process.env.CTF_DELIVERY_PROVISION_ISOLATED==='1';
test('actual delivery provisioner authenticates generated credential and preserves private ownership on reuse',{skip:!enabled,timeout:180000},async t=>{
 const adminUrl=process.env.PG_ADMIN_DATABASE_URL;assert(adminUrl);
 const adminAddress=new URL(adminUrl);assert.equal(adminAddress.hostname,'127.0.0.1');assert(adminAddress.password);assert(!adminAddress.search&&!adminAddress.hash);
 const admin=new Client({connectionString:adminUrl,connectionTimeoutMillis:5000,statement_timeout:5000});await admin.connect();t.after(()=>admin.end());
 assert.equal((await admin.query("SELECT count(*)::int AS n FROM pg_roles WHERE rolname LIKE 'owasp_ai_goat_%'")).rows[0].n,0,'fresh cluster only');
 assert.equal((await admin.query("SELECT current_setting('password_encryption') AS value")).rows[0].value,'scram-sha-256');
 // Invalid password must fail before any provisioning; trust-auth fixtures are rejected.
 const wrongAdmin=new URL(adminUrl);wrongAdmin.password+='-wrong';const bad=new Client({connectionString:wrongAdmin.href,connectionTimeoutMillis:2000});
 try{await assert.rejects(bad.connect(),{code:'28P01'});}finally{await bad.end().catch(()=>{});}
 const dir=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-delivery-provision-'));await fs.chmod(dir,0o700);t.after(()=>fs.rm(dir,{recursive:true,force:true}));
 const manifestPath=path.join(dir,'base.json'),outputPath=path.join(dir,'delivery.json');
 const base=await provisionApplication({adminUrl,manifestPath,env:{PG_TLS:'disable'}});assert.equal(base.status,'created');
 const baseBytes=await fs.readFile(manifestPath);assert.deepEqual(JSON.parse(baseBytes).plan,provisioningPlan());
 const options={adminUrl,manifestPath,outputPath,env:{PG_TLS:'disable'}};
 const mode=process.env.CTF_DELIVERY_PROVISION_CASE;assert(['fresh-reuse','completion-failure'].includes(mode));
 if(mode==='completion-failure'){
  await assert.rejects(provisionCtfDelivery({...options,completionWriter:async()=>{throw Object.assign(Error('owned post-DDL completion failure'),{code:'EIO'});}}),{code:'EIO'});
  const pending=await fs.readFile(outputPath+'.pending'),journal=JSON.parse(pending);assert.equal(journal.status,'incomplete');
  const st=await fs.lstat(outputPath+'.pending');assert(st.isFile()&&!st.isSymbolicLink());assert.equal(st.mode&0o777,0o600);assert.equal(st.uid,process.getuid());
  await assert.rejects(fs.stat(outputPath),{code:'ENOENT'});
  const role=async()=>(await admin.query("SELECT oid::text,rolpassword FROM pg_authid WHERE rolname='dvaia_ctf_delivery'")).rows[0];const before=await role();assert(before.rolpassword.startsWith('SCRAM-SHA-256$'));
  const login=new Client({connectionString:journal.configuration.CTF_DELIVERY_DATABASE_URL,connectionTimeoutMillis:2000});try{await login.connect();assert.equal((await login.query('SELECT session_user AS login')).rows[0].login,'dvaia_ctf_delivery');}finally{await login.end();}
  await assert.rejects(provisionCtfDelivery(options),{code:'CTF_DELIVERY_PROVISION_PENDING'});assert(JSON.stringify(await role())===JSON.stringify(before),'role unchanged');assert((await fs.readFile(outputPath+'.pending')).equals(pending),'private bytes unchanged');assert((await fs.readFile(manifestPath)).equals(baseBytes),'private bytes unchanged');return;
 }
 const first=await provisionCtfDelivery(options);assert.equal(first.status,'created');
 const completed=await fs.readFile(outputPath),pending=await fs.readFile(outputPath+'.pending');
 for(const file of [manifestPath,outputPath,outputPath+'.pending']){const st=await fs.lstat(file);assert(st.isFile()&&!st.isSymbolicLink());assert.equal(st.mode&0o777,0o600);assert.equal(st.uid,process.getuid());}
 assert.equal(JSON.parse(completed).status,'complete');assert.equal(JSON.parse(pending).status,'incomplete');
 assert(JSON.stringify(JSON.parse(pending).configuration)===JSON.stringify(first.configuration),'pending credential preserved');
 const role=async()=>(await admin.query("SELECT oid::text,rolpassword,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_authid WHERE rolname='dvaia_ctf_delivery'")).rows[0];
 const originalRole=await role();assert(originalRole.rolpassword.startsWith('SCRAM-SHA-256$'));assert(originalRole.rolcanlogin);for(const key of ['rolsuper','rolcreatedb','rolcreaterole','rolreplication','rolbypassrls'])assert.equal(originalRole[key],false);
 const login=new Client({connectionString:first.configuration.CTF_DELIVERY_DATABASE_URL,connectionTimeoutMillis:2000});try{await login.connect();assert.deepEqual((await login.query('SELECT session_user AS login,current_database() AS database')).rows[0],{login:'dvaia_ctf_delivery',database:'owasp_ai_goat_ctf'});}finally{await login.end();}
 const wrong=new URL(first.configuration.CTF_DELIVERY_DATABASE_URL);wrong.password+='-wrong';const rejected=new Client({connectionString:wrong.href,connectionTimeoutMillis:2000});try{await assert.rejects(rejected.connect(),{code:'28P01'});}finally{await rejected.end().catch(()=>{});}
 const again=await provisionCtfDelivery(options);assert.equal(again.status,'existing');assert(JSON.stringify(again.configuration)===JSON.stringify(first.configuration),'credential unchanged');
 await assert.rejects(provisionCtfDelivery({...options,outputPath:path.join(dir,'foreign.json')}),{code:'CTF_DELIVERY_ROLE_COLLISION'});
 await fs.chmod(outputPath,0o644);await assert.rejects(provisionCtfDelivery(options),{code:'CTF_DELIVERY_MANIFEST_NOT_PRIVATE'});await fs.chmod(outputPath,0o600);
 assert((await fs.readFile(outputPath)).equals(completed),'private bytes unchanged');assert((await fs.readFile(manifestPath)).equals(baseBytes),'private bytes unchanged');assert(JSON.stringify(await role())===JSON.stringify(originalRole),'role identity and password unchanged');
 assert.equal((await admin.query("SELECT count(*)::int AS n FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member OR r.oid=m.roleid WHERE r.rolname='dvaia_ctf_delivery'")).rows[0].n,0);
 // All provisioned databases/roles belong to the outer fresh-cluster owner.
 // This fixture never issues DROP/ALTER ROLE or destroys an existing cluster.
});
