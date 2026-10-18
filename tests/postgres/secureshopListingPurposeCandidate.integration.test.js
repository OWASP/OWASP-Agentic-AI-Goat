'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{Pool}=require('pg'),{randomUUID}=require('node:crypto'),{migrate}=require('../../db/postgres/migrate');
const {createBoundConversationsRepository}=require('../../server/database/postgres/secureshopBoundConversationsRepository');
test('listing purpose fresh populated no-op and scope',{skip:process.env.LISTING_PURPOSE_CANDIDATE_NATIVE!=='1'},async()=>{
const pools=[];const cases=[];try{
for(const variant of['FRESH','WORKING']){
 const migration=new Pool({connectionString:process.env[`LISTING_PURPOSE_${variant}_MIGRATION_URL`],max:2}),runtime=new Pool({connectionString:process.env[`LISTING_PURPOSE_${variant}_RUNTIME_URL`],max:2});pools.push(migration,runtime);
 await migrate(migration,variant==='FRESH'?process.env.LISTING_PURPOSE_CANDIDATE_MIGRATIONS:process.env.LISTING_PURPOSE_CANONICAL_MIGRATIONS);
 const repo=createBoundConversationsRepository({pool:runtime,queue:async(_id,work)=>work()});const binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:101,platformSessionId:102,shopUserId:103,role:'merchant'};
 const old=randomUUID();await repo.acquireBoundSession({id:old,binding,purpose:'general'});await repo.activateBoundSession(old,binding,'general');await repo.appendMessage(old,binding,{role:'user',content:'preserved'},'general');
 const before=(await migration.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[old])).rows;
 await migrate(migration,process.env.LISTING_PURPOSE_CANDIDATE_MIGRATIONS);assert.deepEqual(await migrate(migration,process.env.LISTING_PURPOSE_CANDIDATE_MIGRATIONS),[]);assert.deepEqual((await migration.query('SELECT * FROM secureshop_agents.agent_sessions WHERE id=$1',[old])).rows,before);
 for(const purpose of['secureshop_listing_rewrite','secureshop_listing_import']){const id=randomUUID();await repo.acquireBoundSession({id,binding,purpose});assert.equal(await repo.activateBoundSession(id,binding,purpose),true);await repo.appendMessage(id,binding,{role:'user',content:purpose},purpose);assert.deepEqual(await repo.getMessages(id,binding,purpose),[{role:'user',content:purpose}]);await assert.rejects(repo.getMessages(id,binding,'general'),{code:'CONVERSATION_UNAVAILABLE'});await assert.rejects(runtime.query('INSERT INTO secureshop_agents.agent_sessions(id,user_id,role,conversation_purpose) VALUES($1,103,$2,$3)',[randomUUID(),'merchant',purpose]),{code:'23514'});await assert.rejects(runtime.query("UPDATE secureshop_agents.agent_sessions SET conversation_purpose='general' WHERE id=$1",[id]),{code:'55000'});}
 cases.push(variant+' legacy rows preserved; both bound listing purposes accepted; cross-purpose and legacy mode denied; no-op');
}fs.writeFileSync(process.env.LISTING_PURPOSE_RESULT,JSON.stringify({cases,modelCalls:0,status:'passed',policyLimitation:'0037 does not modify policy rows or SQL enum; application recipient selection remains controlled-test evidence'},null,2));
}finally{await Promise.all(pools.map(p=>p.end()));}
});
