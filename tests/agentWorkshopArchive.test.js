'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),path=require('node:path');
const {input,archive}=require('./fixtures/agentWorkshopArchive');
const {mapAgentWorkshopArchive}=require('../db/postgres/map-agent-workshop-archive');
const {prepareAgentWorkshopImport,readAgentWorkshopArchive}=require('../db/postgres/import-agent-workshop-archive');
test('native agent snapshot preserves source identity, exact owner keys and explicit timestamps',()=>{
 for(const family of ['finflow','supply_chain']){const result=prepareAgentWorkshopImport(input(family));assert.equal(result.snapshot.progress[0].userId,'0007');assert.equal(result.snapshot.progress[0].sourceId,17);assert.equal(result.snapshot.progress[0].completedAt,'2025-01-02T03:04:05.123456Z');assert.equal(result.report.canonicalProgressImported,false);}
 const raw=input('finflow');raw.tables.finflow_progress[0].user_id={type:'integer',value:'9007199254740993'};assert.equal(mapAgentWorkshopArchive(raw).snapshot.progress[0].userId,'9007199254740993');
});
test('unknown and externally mapped content requires exact archive-bound retention decisions',()=>{
 const raw=input('finflow');raw.tables.file_registry=[{arbitrary:'retained'}];raw.tables.finflow_solutions=[{edited:'content'}];
 assert.throws(()=>prepareAgentWorkshopImport(raw),{code:'INCOMPLETE_OR_STALE_WORKSHOP_REVIEW'});
 raw.review.tables=[{table:'file_registry',disposition:'retain_archive_no_native_equivalent'},{table:'finflow_solutions',disposition:'retain_archive_import_separately_to_platform_solutions'}];assert.equal(prepareAgentWorkshopImport(raw).decisions.length,2);
 raw.review.archiveDigest='b'.repeat(64);assert.throws(()=>prepareAgentWorkshopImport(raw),{code:'ARCHIVE_BOUND_WORKSHOP_REVIEW_REQUIRED'});
});
test('rejects duplicate owner/objective, unknown IDs, missing completion timestamp and unsafe IDs',()=>{
 let raw=input('finflow');raw.tables.finflow_progress.push({...raw.tables.finflow_progress[0],id:18});assert.throws(()=>mapAgentWorkshopArchive(raw),{code:'DUPLICATE_WORKSHOP_PROGRESS'});
 raw=input('finflow');raw.tables.finflow_progress[0].objective_id='unknown';assert.throws(()=>mapAgentWorkshopArchive(raw),{code:'UNKNOWN_WORKSHOP_OBJECTIVE'});
 raw=input('finflow');raw.tables.finflow_progress[0].completed_at=null;assert.throws(()=>mapAgentWorkshopArchive(raw),{code:'HISTORICAL_COMPLETION_TIMESTAMP_REQUIRED'});
 raw=input('finflow');raw.tables.finflow_progress[0].id={type:'integer',value:'9007199254740993'};assert.throws(()=>mapAgentWorkshopArchive(raw),{code:'UNSAFE_WORKSHOP_INTEGER'});
});
test('both archive readers verify synthetic exporter bytes and reject altered contents',async()=>{
 for(const family of ['finflow','supply_chain']){const dir=await archive(family);try{const result=await readAgentWorkshopArchive({archive:dir,family,naiveTimestamps:'UTC'});assert.equal(result.snapshot.progress.length,1);await fs.appendFile(path.join(dir,'schema.json'),' ');await assert.rejects(readAgentWorkshopArchive({archive:dir,family,naiveTimestamps:'UTC'}),{code:'ARCHIVE_HASH_MISMATCH'});}finally{await fs.rm(dir,{recursive:true,force:true});}}
});

test('tool log sequence exhaustion rejects before pool checkout', async()=>{
 const raw=input('finflow');raw.tables.finflow_tool_log[0].id=2147483647;
 let connected=false;
 await assert.rejects(require('../db/postgres/import-agent-workshop-archive').importAgentWorkshopArchive({connect:async()=>{connected=true;}},raw,{apply:true}),{code:'TOOL_LOG_SEQUENCE_EXHAUSTED'});
 assert.equal(connected,false);
});
