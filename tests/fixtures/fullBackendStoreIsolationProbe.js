'use strict';
const assert=require('node:assert/strict');
// Caller supplies its already-admitted canonical sixteen-store bindings and runtime
// query clients. No connection creation, credentials, DDL, or lifecycle ownership.
async function probeStoreIsolation({stores,signal}){
 assert.equal(stores.length,16);assert.equal(new Set(stores.map(s=>s.database)).size,16);
 const roles=stores.flatMap(s=>[s.runtimeRole,s.migrationRole]);assert.equal(new Set(roles).size,32);
 for(const s of stores)for(const key of ['database','runtimeRole','migrationRole'])assert.match(s[key],/^[a-z][a-z0-9_]*$/);
 let checked=0;
 for(const s of stores){
  signal.throwIfAborted();
  const {rows}=await s.client.query({text:`SELECT current_user AS role,current_database() AS database,rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,
    ARRAY(SELECT d FROM unnest($1::text[]) d WHERE has_database_privilege(current_user,d,'CONNECT') ORDER BY d) AS connect,
    ARRAY(SELECT r FROM unnest($2::text[]) r WHERE pg_has_role(current_user,r,'MEMBER') ORDER BY r) AS memberships
    FROM pg_roles WHERE rolname=current_user`,values:[stores.map(x=>x.database),roles.filter(r=>r!==s.runtimeRole)],query_timeout:5000});
  signal.throwIfAborted();assert.equal(rows.length,1);const r=rows[0];
  assert.equal(r.role,s.runtimeRole);assert.equal(r.database,s.database);
  for(const k of ['rolsuper','rolcreatedb','rolcreaterole','rolbypassrls'])assert.equal(r[k],false,k);
  assert.deepEqual(r.connect,[s.database]);assert.deepEqual(r.memberships,[]);checked++;
 }
 return {scope:'canonical-sixteen-store-runtime-isolation',stores:checked,ownConnect:true,siblingConnectDenied:true,privilegedRoleFlagsDenied:true,migrationAndSiblingMembershipDenied:true};
}
async function qualifyStoreIsolation({manifest,env,signal,createPool}){
 const pools=[];let failure,result,closing;
 const close=()=>closing||(closing=Promise.allSettled(pools.map(pool=>Promise.resolve().then(()=>pool.end()))));
 const abort=()=>{void close();};
 try{
  signal.throwIfAborted();assert.equal(manifest.length,16);
  const stores=manifest.map(row=>{
   const runtime=new URL(env[row.runtimeVariable]),migration=new URL(env[row.migrationVariable]);
   assert.equal(runtime.hostname,'127.0.0.1');assert.equal(runtime.host,migration.host);
   assert.equal(runtime.pathname,migration.pathname);assert.equal(runtime.username,row.runtimeRole);
   assert.equal(migration.username,`dvaia_${row.schema}_migration`);
   const client=createPool(env,row.runtimeVariable);pools.push(client);
   return {database:decodeURIComponent(runtime.pathname.slice(1)),runtimeRole:row.runtimeRole,migrationRole:migration.username,client};
  });
  signal.addEventListener('abort',abort,{once:true});signal.throwIfAborted();
  result=await probeStoreIsolation({stores,signal});
 }catch(error){failure=error;}
 finally{signal.removeEventListener('abort',abort);const failures=(await close()).filter(x=>x.status==='rejected').map(x=>x.reason);if(failures.length)throw new AggregateError([...(failure?[failure]:[]),...failures],'Store isolation probe/cleanup failed');}
 if(failure)throw failure;return result;
}
module.exports={probeStoreIsolation,qualifyStoreIsolation};
