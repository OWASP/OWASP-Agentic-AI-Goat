'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),{randomUUID}=require('node:crypto'),{Pool}=require('pg');
const {migrate}=require('../../db/postgres/migrate');
const {createBoundConversationsRepository}=require('../../server/database/postgres/secureshopBoundConversationsRepository');
const {SECURESHOP_CONVERSATION_PURPOSES:PURPOSES}=require('../../server/services/secureshopConversationPurpose');
const enabled=process.env.ANALYTICS_PURPOSE_NATIVE==='1';
test('0031 preserves all prior purposes and admits only bound Analytics', {skip:!enabled,timeout:90000},async()=>{
 const directory=path.join(__dirname,'../../db/postgres/workshop-migrations/secureshop_agents'),prefix=await fs.mkdtemp(path.join(os.tmpdir(),'analytics-purpose-prefix-'));
 const pools=[];try{
  for(const name of (await fs.readdir(directory)).filter(n=>n.endsWith('.sql')&&!n.startsWith('0031_')))await fs.copyFile(path.join(directory,name),path.join(prefix,name));
  for(const variant of ['FRESH','POPULATED']){
   const pair={};for(const kind of ['MIGRATION','RUNTIME']){const url=new URL(process.env[`ANALYTICS_PURPOSE_${variant}_${kind}_URL`]);assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,new RegExp(`^/owasp_ai_goat_test_analytics_purpose_${process.env.ANALYTICS_PURPOSE_OWNER}_${variant.toLowerCase()}$`));pair[kind]=new Pool({connectionString:url.href,max:3,query_timeout:10000,connectionTimeoutMillis:1500});pair[kind].on('error',()=>{});pools.push(pair[kind]);}
   await migrate(pair.MIGRATION,variant==='FRESH'?directory:prefix);
   const repository=createBoundConversationsRepository({pool:pair.RUNTIME,queue:async(_id,work)=>work()});
   const binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:101,platformSessionId:102,shopUserId:103,role:'merchant'},sessions=[];
   for(const purpose of Object.values(PURPOSES).filter(v=>v!=='secureshop_analytics')){const id=randomUUID();await repository.acquireBoundSession({id,binding,purpose});await repository.activateBoundSession(id,binding,purpose);await repository.appendMessage(id,binding,{role:'user',content:`retain:${purpose}`},purpose);sessions.push({id,purpose});}
   const before=(await pair.MIGRATION.query('SELECT * FROM secureshop_agents.agent_sessions ORDER BY id')).rows;
   const applied=await migrate(pair.MIGRATION,directory);assert.deepEqual(applied,variant==='FRESH'?[]:['0031_secureshop_analytics_purpose.sql']);assert.deepEqual(await migrate(pair.MIGRATION,directory),[]);
   assert.deepEqual((await pair.MIGRATION.query('SELECT * FROM secureshop_agents.agent_sessions ORDER BY id')).rows,before);
   for(const {id,purpose} of sessions)assert.deepEqual(await repository.getMessages(id,binding,purpose),[{role:'user',content:`retain:${purpose}`}]);
   const id=randomUUID();await repository.acquireBoundSession({id,binding,purpose:PURPOSES.analytics});assert.equal(await repository.activateBoundSession(id,binding,PURPOSES.analytics),true);await repository.appendMessage(id,binding,{role:'user',content:'Analytics native'},PURPOSES.analytics);
   assert.deepEqual(await repository.getMessages(id,binding,PURPOSES.analytics),[{role:'user',content:'Analytics native'}]);
   await assert.rejects(repository.getMessages(id,binding,'general'),{code:'CONVERSATION_UNAVAILABLE'});
   await assert.rejects(pair.RUNTIME.query("INSERT INTO secureshop_agents.agent_sessions(id,user_id,role,conversation_purpose) VALUES($1,103,'merchant','secureshop_analytics')",[randomUUID()]),{code:'23514'});
   await assert.rejects(pair.RUNTIME.query("UPDATE secureshop_agents.agent_sessions SET conversation_purpose='general' WHERE id=$1",[id]),{code:'55000'});
   console.log(JSON.stringify({case:variant,priorPurposes:sessions.length,analyticsBound:true,legacyRejected:true,noop:true,modelCalls:0}));
  }
 }finally{await Promise.allSettled(pools.map(p=>p.end()));await fs.rm(prefix,{recursive:true,force:true});}
});
