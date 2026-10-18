'use strict';
// Fixture-only native support. No environment loading, default URL or model transport.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID}=require('node:crypto');
const STORES=Object.freeze({identity:'IDENTITY',aria:'SQL_WORKSHOP',nova:'NOSQL_WORKSHOP',excessive_agency:'EXCESSIVE_AGENCY',xss:'XSS_WORKSHOP'});
function assertEnvironment(families=Object.keys(STORES)){
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));
 for(const [store,prefix]of Object.entries(STORES).filter(([key])=>families.includes(key)))for(const role of ['runtime','migration']){const u=new URL(process.env[prefix+(role==='migration'?'_MIGRATION':'')+'_DATABASE_URL']);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,new RegExp('^/dvaia_test_workshop_session_[a-f0-9]+_'+store+'$'));assert.equal(u.username,'dvaia_'+store+'_'+role);}
}
function barrier(){let enter,release,timer;const entered=new Promise(resolve=>enter=resolve);return{entered,async reached(pending,timeoutMs=10000){let deadline;try{await Promise.race([entered,Promise.resolve(pending).then(async result=>{throw Error('Request terminated before controlled barrier: '+result.status);}),new Promise((_,reject)=>deadline=setTimeout(()=>reject(Error('Controlled barrier was not reached')),timeoutMs))]);}finally{clearTimeout(deadline);}},async wait(signal){enter();await new Promise((resolve,reject)=>{const abort=()=>{clearTimeout(timer);reject(signal.reason);};release=()=>{clearTimeout(timer);signal?.removeEventListener('abort',abort);resolve();};timer=setTimeout(()=>reject(Error('Owned fixture barrier timed out')),15000);signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();});signal?.throwIfAborted();},release(){release?.();clearTimeout(timer);}};}
async function initialize(family){
 assert.ok(Object.hasOwn(STORES,family)&&family!=='identity');assertEnvironment(['identity',family]);
 const pg=require('../../server/database/postgres'),pool=key=>pg.createPool(process.env,key),identityPool=pool('IDENTITY_DATABASE_URL'),identityMigration=pool('IDENTITY_MIGRATION_DATABASE_URL'),runtime=pool(STORES[family]+'_DATABASE_URL'),migration=pool(STORES[family]+'_MIGRATION_DATABASE_URL');
 const api=require('../../server/database/postgres/identityRepository');await api.initializeIdentityRepository(identityPool,identityMigration);await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
 if(family==='aria')await require('../../server/database/postgres/sqlWorkshopDb').createSqlWorkshopDb(runtime).initializeSqlWorkshopDb(migration);
 if(family==='nova')await require('../../server/database/postgres/nosqlWorkshopDb').createNosqlWorkshopDb(runtime).initializeNosqlWorkshopDb(migration);
 if(family==='excessive_agency')await require('../../server/database/postgres/excessiveAgencyLabDb').createExcessiveAgencyDatabaseManager(runtime).initialize(migration);
 if(family==='xss')await require('../../server/database/postgres/xssWorkshopDb').createXssWorkshopDb(runtime).initializeXssWorkshopDb(migration);
 const adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter(),owners={};
 for(const key of ['owner','sibling']){const user=await adapter.repository.createUser({username:'session-'+family+'-'+key+'-'+randomUUID().slice(0,6),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash(randomUUID(),4)});owners[key]={user};}
 const mint=async key=>owners[key].session=await adapter.createSession(await adapter.repository.findCredentialById(owners[key].user.id),{ip:'127.0.0.1',get:()=>undefined});await mint('owner');await mint('sibling');
 let server;const mount=async(router,{anonymous=false}={})=>{const app=require('express')();app.use(require('express').json());if(anonymous)app.use(require('express-session')({secret:'owned-session-fixture-only',resave:false,saveUninitialized:true}));app.use(router);server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});return server;};
 const send=(route,body,key='owner',extra={})=>fetch('http://127.0.0.1:'+server.address().port+route,{method:body===undefined?'GET':'POST',headers:{authorization:'Bearer '+owners[key].session.token,'content-type':'application/json',...extra},...(body===undefined?{}:{body:JSON.stringify(body)})});
 const canonical=async key=>(await identityPool.query('SELECT evaluation_id,result_digest FROM workshop_platform.objective_judgments WHERE user_id=$1 ORDER BY evaluation_id',[owners[key].user.id])).rows;
 const effects=async(key,graphFamily)=>(await identityPool.query('SELECT run_id,effect_key,status FROM graph_runtime.effects WHERE owner_key=$1 ORDER BY run_id,effect_key',[JSON.stringify([graphFamily,String(owners[key].user.id)])])).rows;
 const close=async()=>{if(server)await new Promise(resolve=>server.close(resolve));await pg.closePostgresPools();};
 return{identityPool,runtime,migration,adapter,owners,mint,mount,send,canonical,effects,close,base:()=> 'http://127.0.0.1:'+server.address().port};
}
function assertMutationReadback(family,record,expected){
 if(family==='xss')assert.equal(record?.profile?.bio,expected,'exact owned profile HTML readback');
 else if(family==='excessive_agency')assert.ok(Array.isArray(record?.notes)&&record.notes.some(note=>note.title===expected),'exact owned note title readback');
 else throw Error('Unknown mutation readback family');
}
// Explicit simulation of the live decision wire in controlled native fixtures.
// This avoids the separate mock/regex dispatcher; it is never inference proof.
function selectControlledDecisionWire(ai){
 const prior=ai.provider;ai.provider='ollama';
 return {provider:'ollama',model:'CONTROLLED-NOT-ACTUAL',qualification:'synthetic live-wire adapter; no transport or genuine credit',restore(){ai.provider=prior;}};
}
function trackedRequests(){
 const pending=new Set();
 return {track(promise){pending.add(promise);promise.then(()=>pending.delete(promise),()=>pending.delete(promise));return promise;},async drain(timeoutMs=5000){let timer;try{return await Promise.race([Promise.allSettled([...pending]).then(()=>true),new Promise(resolve=>timer=setTimeout(()=>resolve(false),timeoutMs))]);}finally{clearTimeout(timer);}}};
}
module.exports={selectControlledDecisionWire,trackedRequests,STORES,assertEnvironment,barrier,initialize,assertMutationReadback};
