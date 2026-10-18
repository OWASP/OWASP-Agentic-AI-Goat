'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {cleanCheckpoint}=require('./postgres/setupDatabasePhase.integration.test');
function client({state='clean',epoch='2',installation='same',finished=true}={}){return{async query(sql){return{rows:sql.includes('FROM dvaia_maintenance.control')?[{installation_id:installation,epoch,state}]:Array.from({length:Number(epoch)},(_,i)=>({epoch:String(i+1),finished_at:finished?'timestamp':null}))};}};}
test('clean qualification checkpoint requires exact next epoch and all epochs finished',async()=>{
 const prior={installation_id:'same',epoch:'1'};assert.equal((await cleanCheckpoint(client(),prior)).epoch,'2');
 for(const value of [{state:'dirty'},{epoch:'1'},{epoch:'3'},{installation:'other'},{finished:false}])await assert.rejects(cleanCheckpoint(client(value),prior));
});
