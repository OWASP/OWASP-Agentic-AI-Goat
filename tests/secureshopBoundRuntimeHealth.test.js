'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http');
const {createSecureShopBoundRuntimeHealth:create}=require('../server/services/secureshopBoundRuntimeHealth');
const {OllamaProvider}=require('../server/services/secureshop/providers/ollamaProvider');
test('real bounded tags HTTP distinguishes configured model from inference and mock/cloud availability',async t=>{
 let requested;const server=http.createServer((q,r)=>{requested=q.url;r.setHeader('content-type','application/json');r.end(JSON.stringify({models:[{name:'fixture:8b'}]}));});await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const provider={providers:{ollama:new OllamaProvider({baseUrl:`http://127.0.0.1:${server.address().port}`,model:'fixture:8b'}),openai:{apiKey:'never-exposed'},mock:{}}};let reads=0;
 const read=create({repository:{probe:async()=>{reads++;}},provider,isServing:()=>true});const state=await read({});assert.equal(requested,'/api/tags');assert.equal(reads,1);assert.equal(state.status,'SERVICE_READY');assert.deepEqual(state.providers.map(p=>p.availability),['model_present','configured_unknown','mock_not_genuine']);assert.ok(!JSON.stringify(state).includes('never-exposed'));assert.equal(state.model_execution,'not_tested');
});
test('missing model, transport failure and draining are independent of scoped-store success',async()=>{
 const provider=new OllamaProvider({model:'fixture:8b'}),repository={probe:async()=>{}};
 assert.equal((await create({repository,provider,isServing:()=>true,probeTags:async()=>({models:[]})})({})).providers[0].availability,'model_missing');
 assert.equal((await create({repository,provider,isServing:()=>true,probeTags:async()=>{throw Error('offline');}})({})).providers[0].availability,'unreachable');
 await assert.rejects(create({repository,provider,isServing:()=>false})({}),{statusCode:503});
 await assert.rejects(create({repository:{probe:async()=>{throw Error('db offline');}},provider,isServing:()=>true})({}),/db offline/);
});

test('empty scoped storage probes are cheap and never masquerade as provisioned targets',async()=>{
 const {createSecureShopBoundAdminReadRepository}=require('../server/database/postgres/secureshopBoundAdminReadRepository');const sql=[];let fail=false;
 const pool={query:async statement=>{sql.push(statement);if(fail)throw Error('read denied');return{rows:[]};}};
 const repo=createSecureShopBoundAdminReadRepository({agentsPool:pool,reviewPool:pool});const scope={launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:1,platformSessionId:2};
 assert.equal(await repo.probe(scope),true);assert.ok(sql.every(s=>s.includes('LIMIT 1')&&!/sum|to_jsonb|octet_length/i.test(s)));fail=true;await assert.rejects(repo.probe(scope),/read denied/);
});
