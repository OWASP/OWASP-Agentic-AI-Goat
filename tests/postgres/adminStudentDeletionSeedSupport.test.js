'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),s=require('./adminStudentDeletionSeedSupport');
test('MCP controlled seed uses a current canonical objective, not an arbitrary accepted prefix',()=>{
 const catalog=require('../../server/config/workshopCatalog').WORKSHOP_OBJECTIVES.mcp_workshop;
 const sql=s.DEFINITIONS.find(d=>d.schema==='mcp').insert;
 const objective=sql.match(/VALUES\(\$1,'([^']+)'\)/)[1];
 assert.equal(objective,'mcp_recon');assert.ok(catalog.some(row=>row.id===objective));
});
test('service deletion oracle rejects every retained target and changed sibling without claiming full coverage',()=>{
 const before=Object.fromEntries(s.SERVICE_TABLES.map(d=>[d.table,{target:[{row:{id:19}}],sibling:[{row:{id:20}}]}]));
 const after=structuredClone(before);for(const row of Object.values(after))row.target=[];
 assert.equal(s.assertServiceRowsDeleted(before,after).fullStoreCoverage,false);
 for(const d of s.SERVICE_TABLES){const retained=structuredClone(after);retained[d.table].target=before[d.table].target;
  assert.throws(()=>s.assertServiceRowsDeleted(before,retained));
  const changed=structuredClone(after);changed[d.table].sibling=[];assert.throws(()=>s.assertServiceRowsDeleted(before,changed));}
 assert.ok(s.UNSUPPORTED.includes('ctf'));assert.ok(s.UNSUPPORTED.includes('session_disclosure'));
});
function pools(){return Object.fromEntries(s.DEFINITIONS.map(d=>{const rows=new Map();return[d.schema,{rows,async query(sql,args){
 if(sql.startsWith('SELECT'))return{rows:structuredClone(rows.get(args[0])||[])};
 rows.set(args[0],[{row:{owner:args[0],synthetic:true}}]);return{rowCount:1};}}];}));}
test('nine exact workshop seeds are nonempty, isolated, source-scoped and never full coverage',async()=>{
 const p=pools(),seed=await s.seedWorkshopRows(p,{targetId:19,siblingId:20});assert.equal(seed.fullStoreCoverage,false);assert.equal(seed.unsupportedStores.length,7);
 for(const d of s.DEFINITIONS)p[d.schema].rows.delete('19');
 const after=await s.snapshotWorkshopRows(p,{targetId:19,siblingId:20});assert.equal(s.assertWorkshopRowsDeleted(seed.snapshot,after).canonicalCredit,false);
 for(const d of s.DEFINITIONS){const bad=structuredClone(after);bad[d.schema].target=[{row:{unexpected:true}}];assert.throws(()=>s.assertWorkshopRowsDeleted(seed.snapshot,bad));
  const sibling=structuredClone(after);sibling[d.schema].sibling=[];assert.throws(()=>s.assertWorkshopRowsDeleted(seed.snapshot,sibling));}
 assert.throws(()=>s.requireCompleteStoreCoverage(),/incomplete/);
});
test('seed preflight forbids overlapping or nonempty owners before inserts',async()=>{
 const p=pools();await assert.rejects(s.seedWorkshopRows(p,{targetId:19,siblingId:19}));
 p.xss.rows.set('19',[{row:{existing:true}}]);await assert.rejects(s.seedWorkshopRows(p,{targetId:19,siblingId:20}),/not empty/);
 assert.equal(p.aria.rows.size,0);
});
test('CodeBot absence is exact boolean and cannot establish all external resource absence',async()=>{
 for(const absent of [false,null,undefined,'true'])await assert.rejects(s.readCodeBotAbsence({query:async()=>({rows:[{absent}]})},19));
 const proof=await s.readCodeBotAbsence({query:async(sql,args)=>{assert.deepEqual(args,[19,'["CodeBot","19"]']);return{rows:[{absent:true}]};}},19);
 assert.equal(proof.allExternalResourcesAbsent,false);
});
async function admitted(work){
 const {STORES}=require('./adminStudentDeletionRenderedSupport');
 const values={PG_TEST_DISPOSABLE:'yes',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',PG_POOL_BUDGET:'78',LEGACY_PLATFORM_LIFECYCLE_ENABLED:undefined};
 for(const row of STORES)for(const [key,role]of [[row.runtimeVariable,row.runtimeRole],[row.migrationVariable,row.migrationRole]])
  values[key]=`postgresql://${role}@127.0.0.1:54321/dvaia_test_student_deletion_123456abcdef_${row.schema}`;
 const prior=Object.fromEntries(Object.keys(values).map(key=>[key,process.env[key]]));
 try{for(const [key,value]of Object.entries(values))if(value===undefined)delete process.env[key];else process.env[key]=value;return await work();}
 finally{for(const [key,value]of Object.entries(prior))if(value===undefined)delete process.env[key];else process.env[key]=value;}
}
// SQL doubles exercise the original factory implementation, not a replacement
// seed function. They do not establish PostgreSQL grants/cascades/native proof.
function servicePools(){
 const data=new Map(s.NON_CTF_SERVICE_TABLES.map(d=>[d.table,new Map()])),calls=[];
 function make(schema){return {async connect(){return {query:this.query,release(){calls.push({sql:'release',schema});}};},async query(sql,args=[]){
  calls.push({sql,args,schema});
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql)||sql.startsWith('SELECT pg_advisory_xact_lock'))return {rows:[]};
  const read=sql.match(/^SELECT to_jsonb\(r\) AS row FROM ([a-z_.]+) r WHERE ([a-z_]+)=\$1 ORDER BY to_jsonb\(r\)::text$/);
  if(read){assert.ok(read[1].startsWith(schema+'.'));return {rows:structuredClone((data.get(read[1]).get(String(args[0]))||[]).map(row=>({row}))) };}
  const insert=sql.match(/^INSERT INTO ([a-z_.]+)\s*\(([^)]+)\)/);
  if(insert){const table=insert[1];assert.ok(table.startsWith(schema+'.'));assert.ok(data.has(table));
   let row=Object.fromEntries(insert[2].split(',').map((key,i)=>[key.trim(),args[i]]));
   if(table==='session_disclosure.labs')row={platform_owner_id:args[0],generation:1,lab_session_id:args[1],lab_cookie:args[2],csrf_token:args[3],lab_user_id:args[4],lab_role:'lab_admin',created_at:new Date('2026-01-01Z'),updated_at:new Date('2026-01-01Z')};
   const key=String(args[0]),rows=data.get(table).get(key)||[];rows.push(row);data.get(table).set(key,rows);return {rows:[row],rowCount:1};}
  if(sql==='SELECT * FROM session_disclosure.labs WHERE platform_owner_id=$1')return {rows:structuredClone(data.get('session_disclosure.labs').get(String(args[0]))||[])};
  throw Error('Unexpected controlled SQL: '+sql);
 }};}
 const pools={excessive_agency:make('excessive_agency'),session_disclosure:make('session_disclosure')};
 Object.defineProperty(pools,'ctf',{get(){throw Error('CTF pool must not be accessed');}});
 return {pools,data,calls};
}
test('non-CTF path runs real EA/session factories for both owners without CTF authority or duplicate registration',async()=>admitted(async()=>{
 const {pools,data,calls}=servicePools(),ids={targetId:19,siblingId:20};
 const result=await s.seedNonCtfServiceRows(pools,ids);
 assert.deepEqual(result.supportedStores,['excessive_agency','session_disclosure']);
 assert.equal(result.canonicalCredit,false);assert.equal(result.nativeVerified,false);assert.equal(result.fullStoreCoverage,false);
 assert.equal(calls.filter(c=>c.sql==='COMMIT').length,4);assert.equal(calls.filter(c=>c.sql==='release').length,4);
 for(const id of ['19','20']){
  assert.deepEqual(data.get('excessive_agency.users').get(id).map(row=>row.user_id),['alice','bob','charlie','dave','eve']);
  assert.ok(data.get('excessive_agency.notes').get(id).length>0);assert.ok(data.get('excessive_agency.orders').get(id).length>0);
  const lab=data.get('session_disclosure.labs').get(id)[0];assert.match(lab.lab_cookie,/^dvaia_lab_[A-Za-z0-9_-]{43}$/);assert.equal(lab.generation,1);
 }
 assert.notEqual(data.get('session_disclosure.labs').get('19')[0].lab_session_id,data.get('session_disclosure.labs').get('20')[0].lab_session_id);
 // Controlled post-deletion state only; actual deletion/cascade is a native gate.
 for(const rows of data.values())rows.delete('19');
 const after=await s.snapshotNonCtfServiceRows(pools,ids);
 assert.equal(s.assertNonCtfServiceRowsDeleted(result.snapshot,after).siblingRowsUnchanged,true);
 assert.equal(calls.some(c=>/ctf|progress|objective/i.test(c.sql)),false);
}));
test('non-CTF preflights every table and both owners before any factory mutation',async()=>admitted(async()=>{
 for(const d of s.NON_CTF_SERVICE_TABLES)for(const id of ['19','20']){
  const {pools,data,calls}=servicePools();data.get(d.table).set(id,[{existing:true}]);
  await assert.rejects(s.seedNonCtfServiceRows(pools,{targetId:19,siblingId:20}),/not empty/);
  assert.equal(calls.some(c=>c.sql==='BEGIN'||c.sql.startsWith('INSERT')),false);
 }
 const {pools,calls}=servicePools();await assert.rejects(s.seedNonCtfServiceRows(pools,{targetId:19,siblingId:19}));assert.equal(calls.length,0);
}));
test('non-CTF oracle rejects missing/extra tables, empty before, retained target and byte-changed sibling',()=>{
 const before=Object.fromEntries(s.NON_CTF_SERVICE_TABLES.map(d=>[d.table,{target:[{row:{id:19,text:'exact\u0000λ'}}],sibling:[{row:{id:20,text:'exact\u0000λ'}}]}]));
 const after=structuredClone(before);for(const row of Object.values(after))row.target=[];
 assert.equal(s.assertNonCtfServiceRowsDeleted(before,after).canonicalCredit,false);
 for(const d of s.NON_CTF_SERVICE_TABLES){
  for(const mutate of [v=>delete v[d.table],v=>v[d.table].target.push({row:{id:19}}),v=>v[d.table].sibling[0].row.text='changed']){
   const bad=structuredClone(after);mutate(bad);assert.throws(()=>s.assertNonCtfServiceRowsDeleted(before,bad));}
  for(const side of ['target','sibling']){const bad=structuredClone(before);bad[d.table][side]=[];assert.throws(()=>s.assertNonCtfServiceRowsDeleted(bad,after));}
 }
 assert.throws(()=>s.assertNonCtfServiceRowsDeleted(before,{...after,'ctf.ctf_participants':{target:[],sibling:[]}}));
 assert.equal(s.SERVICE_TABLES.length,6);assert.equal(s.NON_CTF_SERVICE_TABLES.length,5);
});
