'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {sourceFixture}=require('./secureshopMcpDescriptionEvidence.test');
const {createMcpDescriptionEvidenceRepository}=require('../server/database/postgres/secureshopMcpDescriptionEvidenceRepository');
function fixture(){const f=sourceFixture(),s=f.source,calls=[];let active=true,missing=false;
 const binding={...s.binding.scope,shopUserId:s.binding.persona.id,role:'admin'},check=async()=>{if(!active)throw Error('stale');};
 const repo=createMcpDescriptionEvidenceRepository({launches:{assertCurrent:check},identityPool:{query:async(sql,args)=>{calls.push({sql,args});assert.doesNotMatch(sql,/INSERT|UPDATE|DELETE/);assert.match(sql,/JOIN graph_runtime.owners/);return{rows:missing?[]:sql.includes('FROM graph_runtime.runs')?[s.run]:s.effects};}},
 conversationRepository:{getBoundSession:async id=>id===s.turn.sessionId?{id,state:'active',purpose:'general',binding}:null,getTraceEvents:async(id,b,ids,purpose)=>{assert.equal(purpose,'general');assert.deepEqual(ids,s.turn.record.result_json.taskMetadata.registeredAdmin.traceEventIds);return s.traces;}},
 journal:{readRegisteredAdminRequest:async()=>s.turn.record},registryRepository:{readAssessmentManifest:async input=>{assert.deepEqual(input.entries,s.turn.record.result_json.taskMetadata.registeredDescription.entries);return s.publications;}},invocationJournal:{readCompleted:async()=>s.stored},current:async()=>({state:{...s.binding,sourceBinding:s.sourceBinding},check}),qualifyModelTrace:f.qualifyModelTrace});
 return{...f,repo,calls,missing:()=>{missing=true;},stale:()=>{active=false;}};}
test('description reader reopens exact source and immutable competing revisions without effect dispatch',async()=>{const f=fixture();const got=await f.repo.readSource(f.source.binding,f.source.turn);assert.deepEqual(got.source,f.source);assert.equal(f.calls.length,2);});
test('foreign source session, stale authority, absent owner generation and altered original manifest deny',async()=>{
 for(const change of [f=>f.stale(),f=>f.missing(),f=>{f.source.turn.record.result_json.taskMetadata.registeredDescription.manifestSha256='0'.repeat(64);}]){const f=fixture();change(f);await assert.rejects(f.repo.readSource(f.source.binding,f.source.turn));}
 const f=fixture();await assert.rejects(f.repo.readSource(f.source.binding,{...f.source.turn,sessionId:'10000000-0000-4000-8000-000000000099'}));assert.equal(f.calls.length,0);
});
