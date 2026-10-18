'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {profileFor}=require('./fixtures/ariaNovaCurrentProfiles');
const {budget}=require('./postgres/ariaNovaCurrentActualTransport');
test('remaining profiles preserve exact matrix request literals and closed bounds',()=>{
 const fs=require('node:fs'),vm=require('node:vm'),source=fs.readFileSync(require.resolve('./postgres/sqlNoSqlRoute.integration.test'),'utf8');
 const marker='const SCENARIO_MATRIX = Object.freeze(',start=source.indexOf(marker)+marker.length;
 const matrix=vm.runInNewContext(source.slice(start,source.indexOf('\n]);',start)+2));
 for(const name of ['aria-remaining','nova-remaining']){
  const input=require('../tests/release-inputs/'+name+'-frozen-inputs-v1.json'),p=profileFor(name);
  assert.deepEqual(input.turns.map(t=>t.id),p.cases);assert.equal(p.chat,p.chats.reduce((a,b)=>a+b));assert.equal(p.external,p.generate+p.chat+1);
  for(const t of input.turns){const old=matrix.find(r=>r.objective===t.objectiveId);assert.equal(t.query,old.payloads[0]);assert.equal(t.message,`Search ${t.family==='ARIA'?'products using this exact searchTerm':'papers using this exact query'}: ${t.query}`);}
  const b=budget(name);b.reserve('tags');for(let n=0;n<p.generate;n++)b.reserve('generate');for(let n=0;n<p.chat;n++)b.reserve('chat');assert.throws(()=>b.reserve('chat'));assert.equal(b.counts.external,p.external);
 }
 assert.throws(()=>profileFor('all'));assert.equal(profileFor().external,69);
});
test('native effect binding requires exact coordinator namespace, owner, generation and result status',()=>{
 const {bindEffects}=require('./fixtures/ariaNovaRemainingNativeChecks'),{effectKey}=require('../server/agent-runtime/workshopGraph');
 const run={run_id:'owned-run',owner_key:'owned-user',generation:1},o={index:0,toolUsed:'search_products',invocation:{params:{searchTerm:"'"}},toolResult:{error:'syntax error'}};
 const row={...run,effect_key:`owned-run:${effectKey(0,o.toolUsed,o.invocation.params)}`,status:'uncertain'};delete row.run_id;row.run_id=run.run_id;
 assert.equal(bindEffects({run,effects:[row],body:{toolObservations:[o]}}).length,1);
 for(const change of [{effect_key:'bare'},{owner_key:'foreign'},{generation:2},{status:'started'}])assert.throws(()=>bindEffects({run,effects:[{...row,...change}],body:{toolObservations:[o]}}));
 assert.throws(()=>bindEffects({run,effects:[row],body:{toolObservations:[{...o,toolResult:[]}]}}));
});
test('reset proof requires generation advance, exact immutable history and nonempty sibling preservation',()=>{
 const {verifyResetEvidence}=require('./fixtures/ariaNovaRemainingNativeChecks');
 const before={generation:0,immutable:{judgments:[{evaluation_id:'existing'}]},sibling:{cart:[{quantity:1}]}},after={...structuredClone(before),generation:1,completed:0,mutable:0,history:0};verifyResetEvidence(before,after);
 for(const change of [{generation:0},{completed:1},{mutable:1},{history:1},{immutable:{}},{sibling:{}}])assert.throws(()=>verifyResetEvidence(before,{...after,...change}));
});
test('immutable graph snapshot preserves microsecond text and detects one-microsecond drift',async()=>{
 const {immutableSnapshot,graphProjection,verifyResetEvidence}=require('./fixtures/ariaNovaRemainingNativeChecks');
 const fs=require('node:fs');const migrations=fs.readFileSync('db/postgres/identity-migrations/0004_graph_runtime.sql','utf8')+fs.readFileSync('db/postgres/identity-migrations/0006_graph_trace.sql','utf8');
 for(const [table,columns] of Object.entries({runs:['started_at','finished_at'],effects:['updated_at'],events:['created_at']}))for(const column of columns){assert.match(migrations,new RegExp(column+' timestamptz'));assert(graphProjection(table).includes(`to_char(t.${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS ${column}`));}
 assert.throws(()=>graphProjection('other'));
 const effect={run_id:'11111111-1111-4111-8111-111111111111',owner_key:'["ARIA","7"]',updated_at:'2026-01-01T00:00:00.123456Z'};
 const snapshot=await immutableSnapshot({query:async sql=>{if(sql.includes('FROM graph_runtime.effects')){assert(sql.startsWith('SELECT '+graphProjection('effects')));return {rows:[effect]};}return {rows:[]};}},7,'sql_injection_workshop',[effect.run_id]);
 assert.deepEqual(snapshot.graph_effects[0].row,effect);
 const before={generation:0,immutable:snapshot,sibling:{cart:[{quantity:1}]}},after={...structuredClone(before),generation:1,completed:0,mutable:0,history:0};verifyResetEvidence(before,after);
 after.immutable.graph_effects[0].row.updated_at='2026-01-01T00:00:00.123457Z';assert.throws(()=>verifyResetEvidence(before,after));
});
test('remaining semantic resistance stays incomplete; genuine independent effect and exact award both required',()=>{
 const {classifyOutcome}=require('./fixtures/ariaNovaRemainingNativeChecks');const turn={family:'ARIA',objectiveId:'sqli_1',query:"'"},body={toolObservations:[{toolUsed:'search_products',invocation:{params:{searchTerm:"'"}},toolResult:{error:'syntax error',code:'42601'}}],judgments:[{objectiveId:'sqli_1',evaluationId:'e',verdict:'pass'}],completedObjectives:['sqli_1']},records=[{judgment:{evaluation_id:'e',objective_id:'sqli_1',verdict:'pass',disposition:'awarded'}}];
 assert.equal(classifyOutcome({turn,body,records}).outcome,'qualified');
 for(const changed of [{...body,toolObservations:[]},{...body,completedObjectives:[]},{...body,judgments:[]}])assert.equal(classifyOutcome({turn,body:changed,records}).outcome,'incomplete');
 assert.equal(classifyOutcome({turn,body,records:[]}).outcome,'incomplete');
});
test('canonical packet must describe exact observed result/request/answer and actual owner completion',()=>{
 const {bindPackets}=require('./fixtures/ariaNovaRemainingNativeChecks');const turn={family:'ARIA',message:'exact source'},o={toolUsed:'search_products',invocation:{tool:'search_products',params:{searchTerm:"'"},decisionSource:'model'},toolResult:{error:'syntax error'}};
 const body={response:'exact answer',toolObservations:[o],completedObjectives:['sqli_1'],judgments:[{evaluationId:'e',objectiveId:'sqli_1',verdict:'pass'}]},record={judgment:{workshop_key:'sql_injection_workshop',evaluation_id:'e',objective_id:'sqli_1',verdict:'pass',disposition:'awarded'},packet:{rubric:{objectiveId:'sqli_1',family:'ARIA',scenario:'product_search',version:'aria_sql.v3',mode:'vuln'},evidence:[{id:'request',source:'student_input',content:turn.message},{id:'answer',source:'assistant_response',content:body.response},{id:'tool',source:'tool_result',content:{tool:o.toolUsed,invocation:o.invocation,result:o.toolResult}},{id:'context',source:'server_observation',content:{authenticatedOwnerId:'7',mode:'vuln',decisionSource:'model',executionSource:'database_query',normalPaperAccessLevels:null}}]}};
 const input={turn,body,records:[record],userId:7,completions:[{user_id:7,workshop_key:'sql_injection_workshop',objective_id:'sqli_1'}]};bindPackets(input);
 for(const mutate of [x=>x.records[0].packet.evidence[2].content.result={error:'other'},x=>x.records[0].packet.evidence[0].content='other',x=>x.body.response='other',x=>x.completions[0].user_id=8,x=>x.body.judgments[0].evaluationId='other',x=>x.completions.push({...x.completions[0],objective_id:'sqli_2'}),x=>x.body.completedObjectives.push('sqli_2'),x=>x.records[0].packet.rubric.objectiveId='sqli_2',x=>x.records[0].judgment.workshop_key='nosql_injection_workshop']){const changed=structuredClone(input);mutate(changed);assert.throws(()=>bindPackets(changed));}
});
