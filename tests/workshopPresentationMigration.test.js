'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {traceData}=require('../server/agent-runtime/runTraceStore');
const {NAME,PREVIOUS,snapshot,boundarySnapshot,invalidSnapshots,migrationPlan}=require('./fixtures/workshopPresentationMigration');
const directory=path.join(__dirname,'../db/postgres/identity-migrations'),sql=fs.readFileSync(path.join(directory,NAME),'utf8');
test('new migration preserves exact prior keys and validators, adding only closed presentation metadata',()=>{
 const old=fs.readFileSync(path.join(directory,'0102_graph_prompt_policy_snapshot.sql'),'utf8'),keys=s=>[...s.match(/metadata - ARRAY\[([^\]]+)\]/)[1].matchAll(/'([^']+)'/g)].map(m=>m[1]);assert.deepEqual(keys(sql),[...keys(old),'presentationSnapshot']);
 for(const name of ['valid_trace_values','valid_tool_policy_trace','valid_prompt_policy_snapshot'])assert(sql.includes('graph_runtime.'+name+'('));
 const drops=[...sql.matchAll(/DROP CONSTRAINT ([a-z0-9_]+)/g)].map(m=>m[1]);assert.deepEqual(drops,['events_metadata_keys_check','events_metadata_values_check','events_metadata_check2']);
 assert.match(sql,/REVOKE ALL ON FUNCTION graph_runtime\.valid_presentation_snapshot\(jsonb\) FROM PUBLIC/);assert.match(sql,/GRANT EXECUTE ON FUNCTION graph_runtime\.valid_presentation_snapshot\(jsonb\) TO dvaia_identity_runtime/);assert.match(sql,/SET search_path=pg_catalog/);
 assert.match(sql,/octet_length\(\(metadata-'presentationSnapshot'\)::text\)<=2048/);assert.match(sql,/octet_length\(\(metadata->'presentationSnapshot'\)::text\)<=8192/);assert.match(sql,/octet_length\(metadata::text\)<=10240/);
});
test('actual trace serializer accepts supported four-block prefix and Unicode boundaries; rejects malformed corpus',()=>{
 for(const value of [snapshot(0),snapshot(4),boundarySnapshot(),boundarySnapshot(true)])assert.deepEqual(traceData({presentationSnapshot:value}).presentationSnapshot,value);
 for(const {id,value}of invalidSnapshots())assert.equal(Object.hasOwn(traceData({presentationSnapshot:value}),'presentationSnapshot'),false,id);
 // Demonstrate why ordinary 2048 cannot contain the supported prefix; SQL
 // native probe later checks jsonb's actual text representation and constraint.
 const spaced=value=>JSON.stringify(value).replace(/:/g,': ').replace(/,/g,', ');
 assert(Buffer.byteLength(spaced({presentationSnapshot:boundarySnapshot()}))>2048);
 assert(Buffer.byteLength(spaced(boundarySnapshot(true)))<8192);
 for(const literal of ['jsonb_array_length(value->\'blocks\')>4','ascii(c)>65535','effect_key=ANY(seen)','(item->>\'index\')::numeric<>ordinal-1'])assert(sql.includes(literal));
});
test('predecessor migration metadata plan binds every canonical file and rejects a changed pin',()=>{
 const pins=Object.fromEntries(fs.readdirSync(directory).filter(n=>n.endsWith('.sql')).map(n=>['db/postgres/identity-migrations/'+n,crypto.createHash('sha256').update(fs.readFileSync(path.join(directory,n))).digest('hex')]));const plan=migrationPlan(pins);assert.equal(plan.at(-1).name,PREVIOUS);assert(!plan.some(p=>p.name===NAME));assert(plan.every(p=>path.dirname(p.file)===directory));pins['db/postgres/identity-migrations/'+PREVIOUS]='0'.repeat(64);assert.throws(()=>migrationPlan(pins),/captured exactly/);
});
test('native negative matrix covers SQL-null separately and JSON-null, unknown keys, duplicates and old metadata boundaries',()=>{
 const ids=invalidSnapshots().map(x=>x.id);for(const id of ['json-null','missing-version','extra-payload','null-blocks','extra-block','duplicate-effect','utf16-effect'])assert(ids.includes(id));assert.equal(new Set(ids).size,ids.length);
 const helper=fs.readFileSync(path.join(__dirname,'fixtures/workshopPresentationMigration.js'),'utf8');assert.match(helper,/valid_presentation_snapshot\(NULL::jsonb\)/);assert.match(helper,/constraint:'events_metadata_size_check'/);assert.match(helper,/assert\.deepEqual\(await migrate\(migration,directory\),\[\]\)/);
});
