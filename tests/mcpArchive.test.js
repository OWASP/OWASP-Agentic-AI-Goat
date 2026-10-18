'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {mapMcpArchive}=require('../db/postgres/map-mcp-archive');
const {input}=require('./fixtures/mcpArchive');
test('MCP archive preserves exact owners/raw payload/null fields/microseconds and provenance',()=>{
 const raw=input(),mapped=mapMcpArchive(raw);assert.equal(mapped.snapshot.progress[0].userKey,'0007');assert.equal(mapped.snapshot.progress[0].createdAt,'2025-01-02T03:04:05.123456Z');
 assert.equal(mapped.snapshot.toolLog[0].args,raw.tables.mcp_workshop_tool_log[0].args);assert.equal(mapped.snapshot.toolLog[0].success,null);
 assert.deepEqual(mapped.snapshot.provenance[1].row,raw.tables.mcp_workshop_tool_log[0]);raw.tables.mcp_workshop_tool_log[0].args='changed';assert.notEqual(mapped.snapshot.provenance[1].row.args,'changed');
 assert.ok(!JSON.stringify(mapped.report).includes('synthetic private result'));
});
test('MCP rejects ambiguous time, unsafe IDs, stale review, duplicates and unknown columns',()=>{
 for(const mutate of [r=>r.naiveTimestamps='reject',r=>r.tables.mcp_workshop_tool_log[0].id={type:'integer',value:'9007199254740992'},r=>r.review.archiveDigest='b'.repeat(64),r=>r.tables.mcp_workshop_progress.push({...r.tables.mcp_workshop_progress[0]}),r=>r.tables.mcp_workshop_tool_log[0].flag='legacy',r=>r.tables.mcp_workshop_progress[0].completed=2]){const raw=input();mutate(raw);assert.throws(()=>mapMcpArchive(raw));}
 const raw=input();raw.tables.retired=[{private:'retained'}];assert.throws(()=>mapMcpArchive(raw));raw.review.retainedTables=['retired'];assert.deepEqual(mapMcpArchive(raw).report.retainedTables,['retired']);
});
test('verified MCP archive reader produces import input and rejects altered source bytes',async()=>{
 const fs=require('node:fs/promises'),path=require('node:path'),{archive}=require('./fixtures/mcpArchive');
 const {readMcpArchive}=require('../db/postgres/import-mcp-archive');const directory=await archive();
 try{
  const raw=await readMcpArchive({archive:directory,naiveTimestamps:'UTC'});raw.review={archiveDigest:raw.archiveDigest,retainedTables:[]};
  assert.equal(mapMcpArchive(raw).snapshot.toolLog[0].id,29);
  await fs.appendFile(path.join(directory,'mcp_workshop_tool_log.jsonl'),'\n');
  await assert.rejects(readMcpArchive({archive:directory,naiveTimestamps:'UTC'}));
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
