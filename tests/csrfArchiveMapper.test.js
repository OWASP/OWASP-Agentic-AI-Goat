'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const{fixture}=require('./fixtures/csrfArchive');const{mapCsrfArchive}=require('../db/postgres/map-csrf-archive');
test('CSRF maps full integer balances, raw victim JSON, nullable flags and raw payloads',()=>{
 const raw=fixture(),result=mapCsrfArchive(raw);assert.equal(result.snapshot.wallets[0].balance,'9007199254740993');assert.equal(result.snapshot.wallets[1].balance,'-50');assert.equal(result.snapshot.tool_log[0].args,' { "amount": 1 } ');assert.equal(result.snapshot.progress[1].completed,null);assert.equal(result.snapshot.victim_state[0].state_json,raw.sources['users_auth.db'].tables.csrf_victim_state[0].state_json);
});
test('missing victims and unrelated identity rows require exact explicit source review',()=>{
 const raw=fixture();delete raw.sources['users_auth.db'];assert.throws(()=>mapCsrfArchive(raw),{code:'MISSING_CSRF_SOURCE_TABLE'});raw.review.missingVictimState='absent_source_no_victims_synthesized';assert.equal(mapCsrfArchive(raw).snapshot.victim_state.length,0);
 raw.sources['users_auth.db']={tables:{users:[{private:'keep archive'}]}};assert.throws(()=>mapCsrfArchive(raw),{code:'INCOMPLETE_CSRF_SOURCE_REVIEW'});raw.review.retainedTables=[{source:'users_auth.db',table:'users',policy:'retain_archive_only'}];assert.equal(mapCsrfArchive(raw).report.retainedTables.length,1);
});
test('out-of-range money and invalid victim JSON fail without invented state',()=>{
 let raw=fixture();raw.sources['csrf_workshop.db'].tables.csrf_workshop_wallets[0].balance={type:'integer',value:'9223372036854775808'};assert.throws(()=>mapCsrfArchive(raw),{code:'INVALID_CSRF_BALANCE'});
 raw=fixture();raw.sources['users_auth.db'].tables.csrf_victim_state[0].state_json='{broken';assert.throws(()=>mapCsrfArchive(raw),{code:'INVALID_CSRF_VICTIM_JSON'});
});

test('owner binding remaps authenticated CSRF keys and derived victim sessions while preserving local evidence',()=>{
 const raw=fixture();
 raw.sources['csrf_workshop.db'].tables.csrf_workshop_wallets[0].user_key='7';
 raw.sources['csrf_workshop.db'].tables.csrf_workshop_progress.forEach(row=>{row.user_key='7';});
 raw.sources['csrf_workshop.db'].tables.csrf_workshop_tool_log[0].user_key='7';
 raw.sources['users_auth.db'].tables.csrf_victim_state[0].session_key='csrf_7';
 raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};
 raw.opaqueOwnerResolutions=[{sourceKey:'other',disposition:'preserve_opaque'}];
 const result=mapCsrfArchive(raw);
 assert.equal(result.snapshot.wallets[0].user_key,'71');
 assert.equal(result.snapshot.progress[0].user_key,'71');
 assert.equal(result.snapshot.tool_log[0].user_key,'71');
 assert.equal(result.snapshot.wallets[1].user_key,'other');
 assert.equal(result.snapshot.victim_state[0].session_key,'csrf_71');
 assert.equal(result.provenance.find(row=>row.table==='csrf_workshop_tool_log').row.user_key,'7');
 assert.match(result.report.identityMapSha256,/^[a-f0-9]{64}$/);
});

test('CSRF requires explicit numeric alias and opaque-owner resolutions and imports require branded proof before pool access',async()=>{
 const raw=fixture();raw.sources['csrf_workshop.db'].tables.csrf_workshop_wallets[0].user_key='007';raw.sources['csrf_workshop.db'].tables.csrf_workshop_progress.forEach(row=>row.user_key='007');raw.sources['csrf_workshop.db'].tables.csrf_workshop_tool_log.forEach(row=>row.user_key='007');raw.sources['users_auth.db'].tables.csrf_victim_state.forEach(row=>row.session_key='csrf_007');raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};
 assert.throws(()=>mapCsrfArchive(raw),{code:'UNRESOLVED_OPAQUE_ARCHIVE_OWNER'});
 raw.opaqueOwnerResolutions=[{sourceKey:'007',disposition:'map_source_identity',sourceId:'7'},{sourceKey:'other',disposition:'preserve_opaque'}];
 assert.equal(mapCsrfArchive(raw).snapshot.wallets[0].user_key,'71');
 raw.opaqueOwnerResolutions[0]={sourceKey:'007',disposition:'map_source_identity',sourceId:'8'};
 assert.throws(()=>mapCsrfArchive(raw),{code:'MISMATCHED_NUMERIC_OWNER_ALIAS'});
 raw.opaqueOwnerResolutions=[{sourceKey:'007',disposition:'map_source_identity',sourceId:'7'},{sourceKey:'other',disposition:'preserve_opaque'},{sourceKey:'unused',disposition:'preserve_opaque'}];
 assert.throws(()=>mapCsrfArchive(raw),{code:'UNUSED_OPAQUE_OWNER_RESOLUTION'});
 await assert.rejects(require('../db/postgres/import-csrf-archive').importCsrfArchive({connect:()=>{throw Error('pool must not open');}},raw),{code:'OWNER_PROOF_REQUIRED'});
 const {fixtureOwnerProof}=require('./fixtures/archiveOwnerBinding');
 const wrongProof=await fixtureOwnerProof({archiveDigest:'b'.repeat(64),identityMap:{7:71}});
 await assert.rejects(require('../db/postgres/import-csrf-archive').importCsrfArchive({connect:()=>{throw Error('pool must not open');}},raw,{ownerProof:wrongProof}),{code:'VERIFIED_ARCHIVE_OWNER_BINDING_REQUIRED'});
});

test('CSRF rejects owner collisions after remapping',()=>{
 const raw=fixture();raw.sources['csrf_workshop.db'].tables.csrf_workshop_wallets[0].user_key='0007';raw.sources['csrf_workshop.db'].tables.csrf_workshop_wallets[1].user_key='0007';raw.sources['csrf_workshop.db'].tables.csrf_workshop_progress.forEach(row=>row.user_key='0007');raw.sources['csrf_workshop.db'].tables.csrf_workshop_tool_log.forEach(row=>row.user_key='0007');raw.sources['users_auth.db'].tables.csrf_victim_state.forEach(row=>row.session_key='csrf_0007');raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};raw.opaqueOwnerResolutions=[{sourceKey:'0007',disposition:'map_source_identity',sourceId:'7'}];
 assert.throws(()=>mapCsrfArchive(raw),{code:'DUPLICATE_CSRF_TARGET_KEY'});
});

test('verified reader retains both CSRF and users_auth victim source bytes',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'csrf-archive-')),raw=fixture(),files=[];let number=0;
 try{
  const write=async(file,text)=>{await fs.writeFile(path.join(directory,file),text);return{bytes:Buffer.byteLength(text),sha256:crypto.createHash('sha256').update(text).digest('hex')};};
  for(const[name,source]of Object.entries(raw.sources)){
   const tables=[];
   for(const[table,rows]of Object.entries(source.tables)){
    const columns=Object.keys(rows[0]),file=`rows-${number++}.jsonl`,text=rows.map(row=>JSON.stringify(columns.map(key=>row[key]===null?{type:'null'}:typeof row[key]==='object'?row[key]:typeof row[key]==='number'?{type:'integer',value:String(row[key])}:{type:'text',value:row[key]}))+'\n').join('');tables.push({name:table,columns,rows:rows.length,file,...await write(file,text)});
   }
   const schemaFile=`schema-${number++}.json`,schema=await write(schemaFile,JSON.stringify(tables.map(table=>({type:'table',name:table.name}))));files.push({name,sourceSha256:'b'.repeat(64),schemaFile,schema,tables});
  }
  await write('manifest.json',JSON.stringify({version:1,format:'owasp-ai-goat-sqlite-archive-v1',complete:true,files}));
  const{readCsrfArchive}=require('../db/postgres/import-csrf-archive');const read=await readCsrfArchive({archive:directory,naiveTimestamps:'UTC'});read.review={...raw.review,archiveDigest:read.archiveDigest};assert.equal(mapCsrfArchive(read).snapshot.victim_state.length,1);
  await fs.appendFile(path.join(directory,files[1].tables[0].file),'tamper');await assert.rejects(readCsrfArchive({archive:directory}),{code:'ARCHIVE_HASH_MISMATCH'});
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
