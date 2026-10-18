'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {COLUMNS,mapPlatformSnapshot}=require('../db/postgres/map-platform-snapshot');
function input(){return{tables:Object.fromEntries(Object.keys(COLUMNS).map(table=>[table,[]])),identityMap:{'7':71},archiveDigest:'a'.repeat(64)};}
const stamp='2026-01-01T01:02:03.123456Z';
function row(table,values){return Object.fromEntries(COLUMNS[table].split(' ').map(column=>[column,Object.hasOwn(values,column)?values[column]:null]));}
test('offline mapper preserves historical credit provenance and independent hint flags',()=>{
 const source=input();source.tables.workshop_objectives_progress=[row('workshop_objectives_progress',{id:4,user_id:7,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',completed:1,completed_at:stamp,created_at:stamp,updated_at:stamp,objective_label:'Old label',objective_category:'SQL'})];
 source.tables.workshop_hints=[row('workshop_hints',{id:5,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',title:'Custom',hints:'[ "raw <script>fixture()</script>" ]'})];
 source.tables.workshop_hint_visibility=[row('workshop_hint_visibility',{id:6,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',is_enabled:1,updated_at:stamp})];
 source.tables.nosql_injection_solutions=[{objective_id:'nosqli_1'}];
 const mapped=mapPlatformSnapshot(source);assert.equal(mapped.snapshot.historicalCompletions[0].userId,71);assert.equal(mapped.snapshot.historicalCompletions[0].completedAt,stamp);assert.equal(mapped.snapshot.historicalCompletions[0].provenance.kind,'legacy_import');assert.equal('verdict'in mapped.snapshot.historicalCompletions[0],false);assert.equal(mapped.snapshot.hints[0].rawHints,source.tables.workshop_hints[0].hints);assert.equal(mapped.snapshot.hintVisibility[0].enabled,true);assert.equal(mapped.snapshot.objectiveVisibility.length,0);assert.equal(mapped.report.requiresReview,true);assert.equal(mapped.report.unmappedTables[0].reason,'solution_precedence_requires_review');
});
test('ambiguous identities, timestamps and duplicate canonical rows fail rather than merge',()=>{
 const source=input();source.tables.workshop_time_tracking=[row('workshop_time_tracking',{id:1,user_id:7,workshop_key:'sql_injection_workshop',session_start:stamp,last_heartbeat:stamp,duration_seconds:42})];
 assert.equal(mapPlatformSnapshot(source).snapshot.timeTracking[0].durationSeconds,42);
 source.identityMap={'7':71,'8':71};assert.throws(()=>mapPlatformSnapshot(source),{code:'AMBIGUOUS_IDENTITY_MERGE'});source.identityMap={'8':72};assert.throws(()=>mapPlatformSnapshot(source),{code:'UNMAPPED_IDENTITY'});source.identityMap={'7':71};source.tables.workshop_time_tracking[0].session_start='2026-01-01 00:00:00';assert.throws(()=>mapPlatformSnapshot(source),{code:'AMBIGUOUS_TIMESTAMP'});source.naiveTimestamps='UTC';assert.equal(mapPlatformSnapshot(source).report.naiveTimestamps,'UTC');
 source.tables.workshop_time_tracking.push({...source.tables.workshop_time_tracking[0]});assert.throws(()=>mapPlatformSnapshot(source),{code:'DUPLICATE_SOURCE_ID'});
});
test('completion timestamp is mandatory and unknown fields are rejected',()=>{
 const source=input();source.tables.workshop_objectives_progress=[row('workshop_objectives_progress',{id:1,user_id:7,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',completed:1,created_at:stamp,updated_at:stamp})];assert.throws(()=>mapPlatformSnapshot(source));source.tables.workshop_objectives_progress[0].completed_at=stamp;source.tables.workshop_objectives_progress[0].extra='retain';assert.throws(()=>mapPlatformSnapshot(source),{code:'UNMAPPED_COLUMNS'});
});

test('disabled visibility remains independent of historical completion and hint visibility',()=>{
 const source=input();const scope={workshop_key:'sql_injection_workshop',objective_id:'sqli_1'};
 source.tables.workshop_objective_visibility=[row('workshop_objective_visibility',{...scope,id:1,is_enabled:0,updated_at:stamp})];
 source.tables.workshop_hint_visibility=[row('workshop_hint_visibility',{...scope,id:2,is_enabled:1,updated_at:stamp})];
 source.tables.workshop_objectives_progress=[row('workshop_objectives_progress',{...scope,id:3,user_id:7,completed:0,created_at:stamp,updated_at:stamp})];
 const result=mapPlatformSnapshot(source);assert.equal(result.snapshot.objectiveVisibility[0].enabled,false);assert.equal(result.snapshot.hintVisibility[0].enabled,true);assert.equal(result.snapshot.historicalCompletions.length,0);assert.equal(result.report.retainedRows[0].rowId,3);assert.equal(result.report.retainedRows[0].archiveDigest,source.archiveDigest);
 source.tables.workshop_objectives_progress[0].completed=1;source.tables.workshop_objectives_progress[0].completed_at=stamp;assert.equal(mapPlatformSnapshot(source).snapshot.historicalCompletions.length,1);
});
test('canonical duplicate keys are rejected even when source IDs differ',()=>{
 const source=input(),value=row('workshop_hint_visibility',{id:1,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',is_enabled:1,updated_at:stamp});
 source.tables.workshop_hint_visibility=[value,{...value,id:2,is_enabled:0}];assert.throws(()=>mapPlatformSnapshot(source),{code:'CONFLICTING_SOURCE_ROWS'});
 source.tables.workshop_hint_visibility=[value,{...value}];assert.throws(()=>mapPlatformSnapshot(source),{code:'DUPLICATE_SOURCE_ID'});
});
test('timestamps reject invalid calendar dates and preserve explicit offsets and microseconds',()=>{
 const source=input();source.tables.workshop_time_tracking=[row('workshop_time_tracking',{id:1,user_id:'7',workshop_key:'sql_injection_workshop',session_start:'2026-02-30T00:00:00Z',last_heartbeat:stamp,duration_seconds:0})];
 assert.throws(()=>mapPlatformSnapshot(source),{code:'INVALID_CALENDAR_DATE'});
 const value='2026-02-28T03:04:05.123456+05:30';source.tables.workshop_time_tracking[0].session_start=value;assert.equal(mapPlatformSnapshot(source).snapshot.timeTracking[0].sessionStart,value);
 source.tables.workshop_time_tracking[0].duration_seconds=-1;assert.throws(()=>mapPlatformSnapshot(source),{code:'INVALID_INTEGER'});
});
test('owner mappings require exact keys and do not coerce zero-padded identifiers',()=>{
 const source=input();source.tables.workshop_user_modes=[row('workshop_user_modes',{user_id:'007',workshop_key:'sql_injection_workshop',mode:'fixed',created_at:stamp,updated_at:stamp})];
 assert.throws(()=>mapPlatformSnapshot(source),{code:'UNMAPPED_IDENTITY'});source.identityMap={'007':71};const mode=mapPlatformSnapshot(source).snapshot.modes[0];assert.equal(mode.userId,71);assert.equal(mode.provenance.source,'users_auth.db');assert.equal(mode.provenance.rowId,null);assert.equal(mode.provenance.rowIndex,0);
 source.tables.workshop_user_modes[0].mode='vulnerable';assert.throws(()=>mapPlatformSnapshot(source),{code:'INVALID_MODE'});
});
test('unmapped populated solution tables require review without entering mapped state',()=>{
 const source=input();source.tables.prompt_injection_solutions=[{challenge_id:'unknown',examples:'raw'}];source.tables.extra_empty=[];
 const result=mapPlatformSnapshot(source);assert.equal(result.report.requiresReview,true);assert.deepEqual(result.report.unmappedTables,[{table:'prompt_injection_solutions',rows:1,reason:'solution_precedence_requires_review'},{table:'extra_empty',rows:0,reason:'outside_adapter_scope'}]);assert.equal('solutions'in result.snapshot,false);
});
test('explicit UTC policy emits timezone-qualified values without losing microseconds',()=>{
 const source=input();source.naiveTimestamps='UTC';source.tables.workshop_time_tracking=[row('workshop_time_tracking',{id:1,user_id:7,workshop_key:'sql_injection_workshop',session_start:'2026-01-01 03:04:05.123456',last_heartbeat:'2026-01-01T03:05:00',duration_seconds:55})];
 const result=mapPlatformSnapshot(source).snapshot.timeTracking[0];assert.equal(result.sessionStart,'2026-01-01T03:04:05.123456Z');assert.equal(result.lastHeartbeat,'2026-01-01T03:05:00Z');
 source.tables.workshop_time_tracking[0].session_start='2026-01-01T24:00:00Z';assert.throws(()=>mapPlatformSnapshot(source),{code:'INVALID_CLOCK_TIME'});
 for(const invalid of ['2026-01-01T23:60:00Z','2026-01-01T23:59:60Z']){source.tables.workshop_time_tracking[0].session_start=invalid;assert.throws(()=>mapPlatformSnapshot(source));}
});
test('sparse catalog state explicitly requires missing-default review',()=>{
 const empty=mapPlatformSnapshot(input());assert.equal(empty.report.requiresReview,true);assert.equal(empty.report.missingCatalogRows.objectiveVisibility.length,115);assert.equal(empty.report.missingCatalogRows.hintVisibility.length,115);assert.ok(empty.report.missingCatalogRows.exercises.length>0);
 const source=input();source.tables.workshop_objective_visibility=[row('workshop_objective_visibility',{id:1,workshop_key:'sql_injection_workshop',objective_id:'sqli_1',is_enabled:0,updated_at:stamp})];
 const sparse=mapPlatformSnapshot(source);assert.equal(sparse.report.missingCatalogRows.objectiveVisibility.length,114);assert.equal(sparse.report.missingCatalogRows.hintVisibility.length,115);assert.equal(sparse.report.requiresReview,true);assert.equal(sparse.snapshot.objectiveVisibility[0].enabled,false);
});


test('legacy imports cannot manufacture SecureShop launch-bound credit or enablement',()=>{
 for(const table of ['workshop_objective_visibility','workshop_hint_visibility','workshop_objectives_progress']) {
  const source=input();source.tables[table]=[row(table,{id:1,user_id:7,workshop_key:'secureshop_agent_security',objective_id:'ss_loop_observation',is_enabled:1,completed:1,completed_at:stamp,created_at:stamp,updated_at:stamp})];
  assert.throws(()=>mapPlatformSnapshot(source),{code:'UNKNOWN_WORKSHOP'},table);
 }
 const report=mapPlatformSnapshot(input()).report;
 assert.ok(!report.missingCatalogRows.objectiveVisibility.some(row=>row.workshopKey==='secureshop_agent_security'));
});
