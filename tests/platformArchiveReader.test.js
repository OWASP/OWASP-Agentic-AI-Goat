'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {COLUMNS}=require('../db/postgres/map-platform-snapshot'),{readPlatformArchive}=require('../db/postgres/read-platform-archive');
const {readVerifiedLegacyArchive}=require('../db/postgres/read-platform-archive');
async function fixture(){
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'platform-archive-'));const tables=[];
 const write=async(name,value)=>{await fs.writeFile(path.join(directory,name),value);return{bytes:Buffer.byteLength(value),sha256:crypto.createHash('sha256').update(value).digest('hex')};};
 for(const [name,list]of Object.entries(COLUMNS)){
  const columns=list.split(' ');let rows=[];
  if(name==='workshop_time_tracking'){const values={id:{type:'integer',value:'1'},user_id:{type:'integer',value:'9007199254740993'},workshop_key:{type:'text',value:'sql_injection_workshop'},session_start:{type:'text',value:'2026-01-01 00:00:00.123456'},last_heartbeat:{type:'text',value:'2026-01-01 00:01:00'},duration_seconds:{type:'integer',value:'60'}};rows=[columns.map(column=>values[column])];}
  const file=name+'.jsonl';tables.push({name,columns,file,rows:rows.length,...await write(file,rows.map(row=>JSON.stringify(row)+'\n').join(''))});
 }
 const unknown='unknown.jsonl',cells=[{type:'integer',value:'9007199254740993'},{type:'blob',base64:'AP8='},{type:'text',value:' raw JSON ' }];tables.push({name:'custom_state',columns:['wide','bytes','text'],file:unknown,rows:1,...await write(unknown,JSON.stringify(cells)+'\n')});
 const schemaFile='schema.json',schema=await write(schemaFile,JSON.stringify(tables.map(table=>({type:'table',name:table.name}))));
 const manifest={version:1,format:'dvaia-sqlite-archive-v1',complete:true,files:[{name:'users_auth.db',sourceSha256:'b'.repeat(64),schemaFile,schema,tables}]};
 await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest));return{directory,manifest,write};
}
test('platform archive verifies bytes, exact owner keys, UTC and JSON-safe unmapped values',async()=>{
 const{directory}=await fixture();try{const result=await readPlatformArchive({archive:directory,identityMap:{'9007199254740993':7},naiveTimestamps:'UTC'});assert.equal(result.snapshot.timeTracking[0].userId,7);assert.equal(result.snapshot.timeTracking[0].sessionStart,'2026-01-01T00:00:00.123456Z');assert.equal(result.unmappedRows.custom_state[0].wide.value,'9007199254740993');assert.equal(result.unmappedRows.custom_state[0].bytes.base64,'AP8=');assert.equal(result.unmappedRows.custom_state[0].text,' raw JSON ');assert.doesNotThrow(()=>JSON.stringify(result));assert.equal(result.report.requiresReview,true);}finally{await fs.rm(directory,{recursive:true,force:true});}
});
test('platform archive rejects incomplete, sidecars and tampered payloads',async()=>{
 const{directory,manifest}=await fixture();try{
  const options={archive:directory,identityMap:{'9007199254740993':7},naiveTimestamps:'UTC'};
  await fs.writeFile(path.join(directory,'INCOMPLETE'),'');await assert.rejects(readPlatformArchive(options),{code:'INCOMPLETE_ARCHIVE'});await fs.unlink(path.join(directory,'INCOMPLETE'));
  manifest.files[0].wal={present:false};await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest));await assert.rejects(readPlatformArchive(options),{code:'UNSUPPORTED_SIDECAR_METADATA'});delete manifest.files[0].wal;
  await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest));await fs.appendFile(path.join(directory,'unknown.jsonl'),'tamper');await assert.rejects(readPlatformArchive(options),{code:'ARCHIVE_HASH_MISMATCH'});
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
test('unsafe mapped numeric IDs reject while source owner strings remain lossless',async()=>{
 const{directory,manifest,write}=await fixture();try{
  const table=manifest.files[0].tables.find(t=>t.name==='workshop_time_tracking'),cells=JSON.parse((await fs.readFile(path.join(directory,table.file),'utf8')).trim());cells[0]={type:'integer',value:'9007199254740993'};Object.assign(table,await write(table.file,JSON.stringify(cells)+'\n'));await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest));await assert.rejects(readPlatformArchive({archive:directory,identityMap:{'9007199254740993':7},naiveTimestamps:'UTC'}),{code:'UNSAFE_MAPPED_INTEGER'});
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
test('platform manifest paths reject traversal and symlink escapes',async()=>{
 const{directory,manifest}=await fixture();try{
  const options={archive:directory,identityMap:{'9007199254740993':7},naiveTimestamps:'UTC'};
  manifest.files[0].schemaFile='../schema.json';await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest));await assert.rejects(readPlatformArchive(options),{code:'UNSAFE_ARCHIVE_PATH'});
  await fs.symlink(path.join(directory,'schema.json'),path.join(directory,'linked.json'));manifest.files[0].schemaFile='linked.json';await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest));await assert.rejects(readPlatformArchive(options));
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});

test('verified archive retains every source without coercing tagged values',async()=>{
 const{directory,manifest,write}=await fixture();try{
  const cells=[{type:'integer',value:'9007199254740993'},{type:'text',value:' { "edited": true } '},{type:'real',value:'-0'},{type:'blob',base64:'AP8='}];
  const table={name:'custom_history',columns:['owner','content','number','bytes'],file:'nova-history.jsonl',rows:1,...await write('nova-history.jsonl',JSON.stringify(cells)+'\n')};
  manifest.files.push({name:'nosql_workshop.db',sourceSha256:'c'.repeat(64),schemaFile:'nova-schema.json',schema:await write('nova-schema.json',JSON.stringify([{type:'table',name:'custom_history'}])),tables:[table]});
  await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest));
  const result=await readVerifiedLegacyArchive({archive:directory});
  assert.deepEqual(Object.keys(result.sources),['users_auth.db','nosql_workshop.db']);
  const row=result.sources['nosql_workshop.db'].tables.custom_history[0];
  assert.deepEqual(row,{owner:{type:'integer',value:'9007199254740993'},content:' { "edited": true } ',number:{type:'real',value:'-0'},bytes:{type:'blob',base64:'AP8='}});
  assert.match(result.archiveDigest,/^[a-f0-9]{64}$/);
  assert.equal(result.sources['users_auth.db'].tables.workshop_time_tracking[0].id.value,'1');
  await fs.appendFile(path.join(directory,table.file),'tamper');
  await assert.rejects(readVerifiedLegacyArchive({archive:directory}),{code:'ARCHIVE_HASH_MISMATCH'});
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});

test('verified archive rejects duplicated schema table declarations',async()=>{
 const{directory,manifest,write}=await fixture();try{
  const source=manifest.files[0],schema=source.tables.map(table=>({type:'table',name:table.name}));
  schema[1]={...schema[0]};source.schema=await write(source.schemaFile,JSON.stringify(schema));
  await fs.writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest));
  await assert.rejects(readVerifiedLegacyArchive({archive:directory}),{code:'ARCHIVE_SCHEMA_TABLE_MISMATCH'});
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
