'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {Client}=require('pg');
const {acquireApplicationMaintenanceLease:acquire}=require('../../server/services/applicationMaintenanceLease');
const {getPoolBudgetSnapshot}=require('../../server/database/postgres');
function ownedUrls(env,index){
 assert.equal(env.PG_TEST_DISPOSABLE,'yes');assert.equal(env.APPLICATION_MAINTENANCE_LEASE_ISOLATED,'1');
 const pair=['RUNTIME','MIGRATION'].map(role=>{const raw=env[`PG_APPLICATION_LEASE_${index}_${role}_URL`];assert.ok(raw);const u=new URL(raw);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,new RegExp(`^/owasp_ai_goat_test_lease_${index}_[a-f0-9]{12}$`));return u;});
 assert.equal(pair[0].pathname,pair[1].pathname);assert.equal(pair[0].port,pair[1].port);assert.notEqual(pair[0].username,pair[1].username);
 return {IDENTITY_DATABASE_URL:pair[0].href,IDENTITY_MIGRATION_DATABASE_URL:pair[1].href,PG_POOL_BUDGET:'16'};
}
async function bounded(promise,ms=5000){let timer;try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Owned lease deadline')),ms);})]);}finally{clearTimeout(timer);}}
// Empty databases: this is lock/session qualification, not populated migration proof.
test('real dedicated maintenance leases contend and observe owned backend loss',{skip:process.env.APPLICATION_MAINTENANCE_LEASE_ISOLATED!=='1',timeout:120000},async()=>{
 for(const index of [1,2]){
  const env=ownedUrls(process.env,index),leases=[],clients=[];const baseline=getPoolBudgetSnapshot().reserved;
  async function take(mode){let client;const lease=await acquire({mode,env,probeMs:50,timeoutMs:2000,closeMs:2000,clientFactory:config=>{client=new Client(config);clients.push(client);return client;}});leases.push(lease);return {lease,client};}
  let control;
  try{
   const a=await take('application'),b=await take('application');assert.notEqual(a.client.processID,b.client.processID);
   await assert.rejects(take('maintenance'),{code:'APPLICATION_MAINTENANCE_BUSY'});
   await a.lease.close();await assert.rejects(take('maintenance'),{code:'APPLICATION_MAINTENANCE_BUSY'});
   await b.lease.close();const exclusive=await take('maintenance');await assert.rejects(take('application'),{code:'APPLICATION_MAINTENANCE_BUSY'});
   await exclusive.lease.close();await exclusive.lease.close();
   const victim=await take('application');control=new Client({connectionString:env.IDENTITY_DATABASE_URL,connectionTimeoutMillis:2000,query_timeout:2000});await control.connect();
   const self=(await victim.client.query('SELECT pg_backend_pid() AS pid,current_user AS username,current_database() AS database')).rows[0];
   const owned=(await control.query('SELECT pid,usename,datname FROM pg_stat_activity WHERE pid=$1 AND usename=current_user AND datname=current_database()',[self.pid])).rows;
   assert.equal(owned.length,1);assert.equal(owned[0].usename,self.username);assert.equal(owned[0].datname,self.database);assert.equal(self.pid,victim.client.processID);assert.notEqual(self.pid,control.processID);
   const lost=new Promise(resolve=>victim.lease.signal.addEventListener('abort',resolve,{once:true}));
   assert.equal((await control.query('SELECT pg_terminate_backend($1) AS terminated',[self.pid])).rows[0].terminated,true);
   await bounded(lost);assert.throws(()=>victim.lease.assertHeld(),{code:'APPLICATION_LEASE_NOT_HELD'});await victim.lease.close();
   const after=await take('maintenance');await after.lease.close();
  }finally{
   const cleanup=await Promise.allSettled(leases.map(x=>x.close()));if(control)await bounded(control.end());
   assert.ok(cleanup.every(x=>x.status==='fulfilled'),'all owned lease sessions must close');
  }
  assert.equal(getPoolBudgetSnapshot().reserved,baseline);
 }
});
module.exports={ownedUrls};
