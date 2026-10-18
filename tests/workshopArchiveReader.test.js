'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {catalogs,mapSnapshotOwners,normalizeImportMetadata}=require('../db/postgres/import-workshop-snapshot'),{
 readWorkshopArchive,readArchiveFile,readVerifiedArchiveFile,createArchiveReadBudget,
 MAX_ARCHIVE_MANIFEST_BYTES,MAX_ARCHIVE_SCHEMA_BYTES,MAX_ARCHIVE_TABLE_BYTES,
}=require('../db/postgres/read-workshop-archive');
const {validateReview}=require('../db/postgres/import-workshop-archive');
const {fixtureOwnerProof}=require('./fixtures/archiveOwnerBinding');
async function fixture(family='nova'){
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'workshop-archive-'));const tables=[];
 async function write(name,text){await fs.writeFile(path.join(root,name),text);return{bytes:Buffer.byteLength(text),sha256:crypto.createHash('sha256').update(text).digest('hex')};}
 for(const [name,cols]of Object.entries(catalogs[family])){
  const columns=cols.split(' ').filter(c=>!(family==='nova'&&name==='papers'&&c==='access_level'));let rows=[];
  if(name==='chat_history')rows=[columns.map(c=>c==='id'?{type:'integer',value:'41'}:c==='user_id'?{type:'integer',value:'9007199254740993'}:c==='timestamp'?{type:'null'}:{type:'text',value:c==='message'?'  { raw JSON }  ':'user'})];
  const file=name+'.jsonl',text=rows.map(row=>JSON.stringify(row)+'\n').join('');tables.push({name,columns,file,rows:rows.length,...await write(file,text)});
 }
 const schemaFile='schema.json',schema=await write(schemaFile,JSON.stringify(tables.map(t=>({type:'table',name:t.name}))));
 const manifest={version:1,format:'dvaia-sqlite-archive-v1',complete:true,files:[{name:family==='nova'?'nosql_workshop.db':'sql_workshop.db',schemaFile,schema,tables}]};
 await fs.writeFile(path.join(root,'manifest.json'),JSON.stringify(manifest));return{root,manifest};
}
test('archive mapper preserves text and exact large integer owner keys',async()=>{const{root}=await fixture();try{const result=await readWorkshopArchive({archive:root,family:'nova'});assert.equal(result.snapshot.tables.chat_history[0].user_id,'9007199254740993');assert.equal(result.snapshot.tables.chat_history[0].message,'  { raw JSON }  ');assert.equal(result.report.normalizations.integerOwnerKeys,1);}finally{await fs.rm(root,{recursive:true,force:true});}});
test('snapshot owner mapping requires a verified binding and preserves raw provenance',async()=>{
 const snapshot={version:1,family:'aria',tables:Object.fromEntries(Object.keys(catalogs.aria).map(table=>[table,[]]))};
 snapshot.tables.chat_history=[{id:41,user_id:'7',message_type:'user',message:'raw',timestamp:'2026-01-01T00:00:00Z'}];
 const binding={archiveDigest:'a'.repeat(64),identityMap:{7:71}};
 await assert.rejects(Promise.resolve().then(()=>mapSnapshotOwners(snapshot)),{code:'OWNER_BINDING_REQUIRED'});
 const proof=await fixtureOwnerProof(binding),mapped=mapSnapshotOwners(snapshot,{ownerBinding:binding,ownerProof:proof});
 assert.equal(mapped.snapshot.tables.chat_history[0].user_id,'71');
 assert.equal(mapped.sourceRows[0].sourceRow.user_id,'7');
 assert.equal(mapped.binding.identityMapSha256,proof.identityMapSha256);
});
test('snapshot provenance uses natural keys for NOVA catalog rows',async()=>{
 const snapshot={version:1,family:'nova',tables:Object.fromEntries(Object.keys(catalogs.nova).map(table=>[table,[]]))};
 snapshot.tables.nosql_injection_solution_visibility=[
  {objective_id:'objective-one',solutions_enabled:1,updated_at:'2026-01-01T00:00:00Z'},
  {objective_id:'objective-two',solutions_enabled:0,updated_at:'2026-01-02T00:00:00Z'},
 ];
 snapshot.tables.nosql_injection_solutions=[
  {objective_id:'objective-one',title:'one',difficulty:'easy',hints:'h',examples:'e',approach:'a',tips:'t'},
  {objective_id:'objective-two',title:'two',difficulty:'hard',hints:'h2',examples:'e2',approach:'a2',tips:'t2'},
 ];
 const binding={archiveDigest:'b'.repeat(64),identityMap:{7:71}},mapped=mapSnapshotOwners(snapshot,{ownerBinding:binding,ownerProof:await fixtureOwnerProof(binding)});
 assert.deepEqual(mapped.sourceRows.map(row=>[row.sourceTable,row.sourceId]),[
  ['nosql_injection_solution_visibility','objective-one'],
  ['nosql_injection_solution_visibility','objective-two'],
  ['nosql_injection_solutions','objective-one'],
  ['nosql_injection_solutions','objective-two'],
 ]);
});
test('owner remapping rejects duplicate NOVA reading-list state after aliases converge',async()=>{
 const snapshot={version:1,family:'nova',tables:Object.fromEntries(Object.keys(catalogs.nova).map(table=>[table,[]]))};
 snapshot.tables.reading_lists=[
  {id:1,user_id:'7',paper_id:'paper-1',added_at:'2026-01-01T00:00:00Z',notes:'first'},
  {id:2,user_id:'0007',paper_id:'paper-1',added_at:'2026-01-02T00:00:00Z',notes:'alias'},
 ];
 const binding={archiveDigest:'c'.repeat(64),identityMap:{7:71}},proof=await fixtureOwnerProof(binding);
 await assert.rejects(Promise.resolve().then(()=>mapSnapshotOwners(snapshot,{ownerBinding:binding,ownerProof:proof,opaqueOwnerResolutions:[{sourceKey:'0007',disposition:'map_source_identity',sourceId:'7'}]})),{code:'DUPLICATE_MAPPED_OWNER_STATE'});
});
test('archive reader rejects incomplete, tampered and escaping files',async()=>{const{root,manifest}=await fixture();try{
 await fs.writeFile(path.join(root,'INCOMPLETE'),'');await assert.rejects(readWorkshopArchive({archive:root,family:'nova'}),{code:'INCOMPLETE_ARCHIVE'});await fs.unlink(path.join(root,'INCOMPLETE'));
 await fs.appendFile(path.join(root,'chat_history.jsonl'),'x');await assert.rejects(readWorkshopArchive({archive:root,family:'nova'}),{code:'ARCHIVE_HASH_MISMATCH'});
 manifest.files[0].schemaFile='../escape';await fs.writeFile(path.join(root,'manifest.json'),JSON.stringify(manifest));await assert.rejects(readWorkshopArchive({archive:root,family:'nova'}),{code:'UNSAFE_ARCHIVE_PATH'});
 manifest.files[0].schemaFile='linked';await fs.symlink(path.join(root,'schema.json'),path.join(root,'linked'));await fs.writeFile(path.join(root,'manifest.json'),JSON.stringify(manifest));await assert.rejects(readWorkshopArchive({archive:root,family:'nova'}));
 }finally{await fs.rm(root,{recursive:true,force:true});}});
test('archive reader applies the reviewed naive-timestamp policy',async()=>{const{root,manifest}=await fixture('nova');try{
 const table=manifest.files[0].tables.find(item=>item.name==='chat_history'),file=path.join(root,table.file);
 const rows=(await fs.readFile(file,'utf8')).trim().split('\n').map(line=>JSON.parse(line));
 const timestampIndex=table.columns.indexOf('timestamp');rows[0][timestampIndex]={type:'text',value:'2026-01-01 00:00:00'};
 let text=rows.map(row=>JSON.stringify(row)).join('\n')+'\n';await fs.writeFile(file,text);table.bytes=Buffer.byteLength(text);table.sha256=crypto.createHash('sha256').update(text).digest('hex');await fs.writeFile(path.join(root,'manifest.json'),JSON.stringify(manifest));
 await assert.rejects(readWorkshopArchive({archive:root,family:'nova',naiveTimestamps:'reject'}),{code:'NAIVE_TIMESTAMP_REJECTED'});
 rows[0][timestampIndex]={type:'text',value:'2026-01-01T00:00:00Z'};text=rows.map(row=>JSON.stringify(row)).join('\n')+'\n';await fs.writeFile(file,text);table.bytes=Buffer.byteLength(text);table.sha256=crypto.createHash('sha256').update(text).digest('hex');await fs.writeFile(path.join(root,'manifest.json'),JSON.stringify(manifest));
 const result=await readWorkshopArchive({archive:root,family:'nova',naiveTimestamps:'reject'});assert.equal(result.report.naiveTimestamps,'reject');
 }finally{await fs.rm(root,{recursive:true,force:true});}});
test('workshop review validation fails closed before any pool can be opened',async()=>{
 const digest='d'.repeat(64),envelope={family:'aria',naiveTimestamps:'reject',review:{archiveDigest:digest,retainedOtherSources:[]},ownerBinding:{archiveDigest:digest,identityMap:{7:71}},opaqueOwnerResolutions:[]};
 assert.equal(validateReview(envelope,'aria',digest,[]).archiveDigest,digest);
 for(const malformed of [
  {...envelope,review:undefined},
  {...envelope,naiveTimestamps:'local'},
  {...envelope,ownerBinding:{archiveDigest:'e'.repeat(64),identityMap:{7:71}}},
 ]) assert.throws(()=>validateReview(malformed,'aria',digest,[]),error=>['INVALID_WORKSHOP_REVIEW','OWNER_ARCHIVE_MISMATCH'].includes(error.code));
});
test('snapshot metadata distinguishes direct UTC imports from reviewed archives',()=>{
 const binding={archiveDigest:'e'.repeat(64),identityMap:{7:71}};
 const direct=normalizeImportMetadata(undefined,{binding});assert.deepEqual(direct,{source:'direct_snapshot',naiveTimestamps:'UTC',archiveDigest:binding.archiveDigest,reviewSha256:null,normalizations:{integerOwnerKeys:0,novaPublicAccess:0},retainedOtherSources:[],opaqueOwnerResolutions:[]});
 const archive=normalizeImportMetadata({source:'archive_review',naiveTimestamps:'reject',archiveDigest:binding.archiveDigest,reviewSha256:'f'.repeat(64),normalizations:{integerOwnerKeys:1,novaPublicAccess:2},retainedOtherSources:['sensitive_info.db'],opaqueOwnerResolutions:[]},{binding});
 assert.equal(archive.source,'archive_review');const opaque=[{sourceKey:'legacy-demo',disposition:'preserve_opaque'}];
 assert.deepEqual(normalizeImportMetadata(undefined,{binding,opaqueOwnerResolutions:opaque}).opaqueOwnerResolutions,opaque);
 assert.throws(()=>normalizeImportMetadata({...archive,reviewSha256:null},{binding}),{code:'INVALID_IMPORT_METADATA'});
 assert.throws(()=>normalizeImportMetadata({...archive,opaqueOwnerResolutions:opaque},{binding,opaqueOwnerResolutions:[]}),{code:'IMPORT_METADATA_OWNER_RESOLUTION_MISMATCH'});
});
test('shared archive reads enforce manifest, schema, table, and aggregate byte bounds before allocation',async()=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'archive-reader-bounds-'));
 try{
  const manifest=path.join(root,'manifest.json'),handle=await fs.open(manifest,'w');
  await handle.truncate(MAX_ARCHIVE_MANIFEST_BYTES+1);await handle.close();
  await assert.rejects(readArchiveFile(root,'manifest.json'),{code:'ARCHIVE_MANIFEST_TOO_LARGE'});
  await fs.writeFile(path.join(root,'small'),'123456');
  const sha=crypto.createHash('sha256').update('123456').digest('hex');
  await assert.rejects(readVerifiedArchiveFile(root,'small',{bytes:MAX_ARCHIVE_SCHEMA_BYTES+1,sha256:sha},undefined,'schema'),{code:'ARCHIVE_SCHEMA_TOO_LARGE'});
  await assert.rejects(readVerifiedArchiveFile(root,'small',{bytes:MAX_ARCHIVE_TABLE_BYTES+1,sha256:sha,rows:1},undefined,'table'),{code:'ARCHIVE_TABLE_TOO_LARGE'});
  await fs.writeFile(path.join(root,'second'),'abcdef');
  const budget=createArchiveReadBudget(10);
  assert.equal(await readVerifiedArchiveFile(root,'small',{bytes:6,sha256:sha},budget,'schema'),'123456');
  await assert.rejects(readVerifiedArchiveFile(root,'second',{bytes:6,sha256:crypto.createHash('sha256').update('abcdef').digest('hex')},budget,'schema'),{code:'ARCHIVE_TOTAL_BYTES_LIMIT'});
 }finally{await fs.rm(root,{recursive:true,force:true});}
});
test('shared verified read rejects declared-size mismatch without accepting partial bytes',async()=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'archive-reader-mismatch-'));
 try{
  await fs.writeFile(path.join(root,'table.jsonl'),'[]\n');
  const sha=crypto.createHash('sha256').update('[]\n').digest('hex');
  await assert.rejects(readVerifiedArchiveFile(root,'table.jsonl',{bytes:2,sha256:sha,rows:1},createArchiveReadBudget(),'table'),{code:'ARCHIVE_HASH_MISMATCH'});
 }finally{await fs.rm(root,{recursive:true,force:true});}
});
