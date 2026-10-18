'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createPostgresRagProgressStore}=require('../server/services/ragProgressStore');
const {createEmailWorkshopRepository}=require('../server/database/postgres/emailWorkshopRepository');

test('RAG PostgreSQL projection uses canonical owner progress and filters unknown objectives',async()=>{
 const calls=[];const store=createPostgresRagProgressStore({progress:{getWorkshopProgress:async(...args)=>{calls.push(args);return {objectives:[{id:'rag_query',completed:true,completedAt:'canonical-time'},{id:'foreign',completed:true}]};}}},['rag_query','rag_upload']);
 assert.deepEqual(await store.get({platformUserId:71,userKey:'ignored-legacy-key'}),{rag_query:{completed:true,completedAt:'canonical-time'},rag_upload:{completed:false}});
 assert.deepEqual(calls,[[71,'indirect_prompt_injection']]);
 assert.deepEqual(await store.get({}),{rag_query:{completed:false},rag_upload:{completed:false}});assert.equal(calls.length,1);
});
test('RAG durable grading avoids duplicate completion and reset keeps exact canonical objective scope',async()=>{
 const calls=[];const progress={getWorkshopProgress:async()=>({objectives:[]}),syncObjectiveComplete:async(...args)=>calls.push(['complete',...args]),checkAndMarkWorkshopComplete:async(...args)=>calls.push(['summary',...args]),resetWorkshopProgress:async(...args)=>calls.push(['reset',...args])};
 const ids=['rag_upload','rag_query'],store=createPostgresRagProgressStore({progress},ids);
 await store.complete({platformUserId:71,objectiveId:'rag_query',durable:true});await store.complete({objectiveId:'rag_query'});assert.deepEqual(calls,[]);
 await store.complete({platformUserId:71,objectiveId:'rag_upload'});
 assert.deepEqual(calls,[['complete',71,'indirect_prompt_injection','rag_upload','rag_upload'],['summary',71,'indirect_prompt_injection']]);
 calls.length=0;await store.reset({platformUserId:71});assert.deepEqual(calls,[['reset',71,'indirect_prompt_injection',{objectiveIds:ids}]]);
 const error=Error('Controlled reset fence');progress.resetWorkshopProgress=async()=>{throw error;};await assert.rejects(store.reset({platformUserId:71}),actual=>actual===error);
});
test('email PostgreSQL repository binds every public effect to the supplied owner using parameters',async()=>{
 const calls=[],pool={query:async(sql,args)=>{calls.push({sql,args});return {rows:sql.includes('RETURNING id')?[{id:9}]:sql.includes('SELECT user_email')?[{user_email:'owner@example.invalid'}]:[{objective_number:1,completed:1,completed_at:'canonical-time'}]};}};
 const store=createEmailWorkshopRepository(pool),owner='71';
 await store.saveConfiguredEmail(owner,'owner@example.invalid');
 assert.deepEqual(await store.logSentEmail(owner,'lab@example.invalid','controlled','Subject','effect-id'),{id:9});
 await store.completeObjective(owner,2,'owner@example.invalid');
 assert.deepEqual(await store.listProgress(owner),[{objective_number:1,completed:1,completed_at:'canonical-time'}]);
 await store.resetProgress(owner);assert.equal(await store.getConfiguredEmail(owner),'owner@example.invalid');
 assert.equal(calls.length,6);
 for(const {sql,args} of calls){assert.equal(args[0],owner);assert(sql.includes('$1'));assert(!sql.includes("'71'"));}
 assert.deepEqual(calls.map(row=>row.args),[[owner,'owner@example.invalid'],[owner,'lab@example.invalid','controlled','Subject','effect-id'],[owner,2,'owner@example.invalid'],[owner],[owner],[owner]]);
 assert.match(calls[4].sql,/WHERE user_key=\$1/);
});
test('email repository propagates effect failure instead of inventing success and retired legacy exports are absent',async()=>{
 const error=Error('Controlled persistence failure'),store=createEmailWorkshopRepository({query:async()=>{throw error;}});
 await assert.rejects(store.logSentEmail('71','lab@example.invalid','controlled','Subject','effect-id'),actual=>actual===error);
 assert.equal(require('../server/services/emailWorkshopStore').createLegacyEmailWorkshopStore,undefined);
 assert.equal(require('../server/services/ragProgressStore').createSqliteRagProgressStore,undefined);
});
