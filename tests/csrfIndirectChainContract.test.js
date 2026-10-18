'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {validateDeclaration,cohort}=require('./fixtures/csrfIndirectChainEvidence');
const {observeFactory}=require('./fixtures/csrfIndirectSearchObserver.cjs');
test('declared MFA source and clean source remain byte-exact; both questions distinct',()=>{assert.equal(validateDeclaration(),cohort);assert.equal(cohort.source.sha256,'d0fb777981a05915cb6252a6c4e03f26c90849b80270c3c44a5b5ad6075e0eda');assert.notEqual(cohort.queries.first.normalizedQuerySha256,cohort.queries.second.normalizedQuerySha256);});
test('search observer preserves exact argument and result identity, ranks and receipts',async()=>{const args=[{ownerId:4,family:'CSRF',runId:'owned'}, {documentId:'doc',embedding:[1,2],limit:3}],result=Object.freeze({chunks:[{score:.6,text:'owned',chunkIndex:0}],receipt:{ownerId:4}}),rows=[];const factory=observeFactory(()=>({async search(...actual){assert.equal(actual[0],args[0]);assert.equal(actual[1],args[1]);return result;}}),row=>rows.push(row));assert.equal(await factory().search(...args),result);assert.equal(rows.length,1);assert.deepEqual(rows[0].result,result);assert.match(rows[0].query.embeddingSha256,/^[a-f0-9]{64}$/);});
test('search observer propagates original error without fabricating observation or fallback',async()=>{const error=Error('owned failure');let recorded=0;const factory=observeFactory(()=>({async search(){throw error;}}),()=>recorded++);await assert.rejects(factory().search({ownerId:4},{embedding:[1]}),e=>e===error);assert.equal(recorded,0);});
test('observer rejects mutated arguments and mutation by recorder',async()=>{await assert.rejects(observeFactory(()=>({async search(x){x.ownerId=8;return{};}}),()=>{})().search({ownerId:4},{embedding:[1]}));const args=[{ownerId:4},{embedding:[1]}];await assert.rejects(observeFactory(()=>({async search(){return{chunks:[]};}}),()=>args[0].ownerId=9)().search(...args));});
test('same normalized successful query and blocked outcomes cannot increase persistence count',()=>{const {recordSuccessfulRagQuery}=require('../server/agent-runtime/csrfRagGraph'),t={};assert.equal(recordSuccessfulRagQuery(t,cohort.queries.first.text,{executed:true,blocked:false}).isNewQ,true);assert.equal(recordSuccessfulRagQuery(t,cohort.queries.first.text.toUpperCase(),{executed:true,blocked:false}).isNewQ,false);assert.equal(recordSuccessfulRagQuery(t,cohort.queries.second.text,{executed:true,blocked:true}).isNewQ,false);assert.equal(t.ragFiredQuestions.length,1);assert.equal(recordSuccessfulRagQuery(t,cohort.queries.second.text,{executed:true,blocked:false}).isNewQ,true);});
test('actual actor wire requires complete hash-bound terminal output and exact model',()=>{const {assertActualCalls}=require('./fixtures/csrfIndirectChainEvidence'),sha=s=>require('node:crypto').createHash('sha256').update(s).digest('hex');const request=JSON.stringify({model:cohort.model.name,stream:false,messages:[{role:'system',content:"VaultLink's AI knowledge-base"}]});const response=JSON.stringify({model:cohort.model.name,message:{content:'owned output'},done:true});const call={request,response,requestSha256:sha(request),responseSha256:sha(response),status:200,responseComplete:true,responseCaptureTruncated:false};assert.equal(assertActualCalls([call]).text,'owned output');for(const change of [{responseComplete:false},{responseCaptureTruncated:true},{responseSha256:'f'.repeat(64)},{response:JSON.stringify({model:'wrong',message:{content:'owned'},done:true})}])assert.throws(()=>assertActualCalls([{...call,...change}]));});

test('defense assertion rejects unblocked repeat despite unchanged deduped query state, and requires a new activity',()=>{
 const {assertDefendedActivity}=require('./fixtures/csrfIndirectChainApi');
 const {recordSuccessfulRagQuery}=require('../server/agent-runtime/csrfRagGraph');
 const state={};recordSuccessfulRagQuery(state,cohort.queries.second.text,{executed:true,blocked:false});
 const beforeState=structuredClone(state),before={entries:[{id:1,name:'rag → disable_mfa',flag:'critical',success:true}]};
 assert.equal(recordSuccessfulRagQuery(state,cohort.queries.second.text,{executed:true,blocked:false}).isNewQ,false);
 assert.deepEqual(state,beforeState);
 assert.throws(()=>assertDefendedActivity(before,{entries:[...before.entries,{id:2,name:'rag → disable_mfa',flag:'critical',success:true}]}));
 assert.throws(()=>assertDefendedActivity(before,{entries:[...before.entries,{id:2,name:'rag → disable_mfa',flag:'warning',success:true}]}));
 assert.throws(()=>assertDefendedActivity(before,before),/Exactly one new gadget activity required/);
 const blocked={id:2,name:'rag → disable_mfa',flag:'warning',success:false};
 assert.equal(assertDefendedActivity(before,{entries:[...before.entries,blocked]}),blocked);
});


test('historical document evidence uses explicit migration reader; runtime judgment queries remain separate',async()=>{
 const {createIndirectEvidence}=require('./fixtures/csrfIndirectChainEvidence');
 const calls=[],retired={document_id:'retired-owned',retired_at:'retained',chunks:null};
 const identity={async query(sql,args){assert(!sql.includes('workshop_rag.'),'Runtime must not read private RAG tables');calls.push(['runtime',sql,args]);return{rows:[]};}};
 const documentEvidenceReader={async query(sql,args){assert(sql.includes('workshop_rag.documents'));assert(sql.includes("family='CSRF'"));assert(!sql.includes('retired_at IS NULL'),'Historical reset proof must retain retired rows');calls.push(['migration',sql,args]);return{rows:[retired]};}};
 const args={identity,documentEvidenceReader,student:{id:1},sibling:{id:2},state:async u=>({owner:u.id}),root:'/unused'};
 assert.throws(()=>createIndirectEvidence({...args,documentEvidenceReader:undefined}),/Explicit historical/);
 const evidence=createIndirectEvidence(args);
 assert.deepEqual(await evidence.siblingSnapshot(),{documents:[retired],state:{owner:2}});
 assert.deepEqual(await evidence.documents(args.student),[retired]);
 await evidence.finalSnapshot();
 assert.deepEqual(calls.map(x=>x[0]),['migration','migration','runtime','runtime']);
 assert.deepEqual(calls.slice(0,2).map(x=>x[2]),[[2],[1]]);
 const fs=require('node:fs');
 assert.match(fs.readFileSync(require.resolve('./postgres/csrfFullIndex.native.js'),'utf8'),/runIndirectChain\(\{[^}]*documentEvidenceReader:migration/);
 assert.match(fs.readFileSync(require.resolve('./fixtures/csrfIndirectChainApi'),'utf8'),/createIndirectEvidence\(\{identity,documentEvidenceReader,/);
});
