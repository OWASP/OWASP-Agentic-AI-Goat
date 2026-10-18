'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path');
const {createPool}=require('../../server/database/postgres');const {migrate}=require('../../db/postgres/migrate');
const {catalogs,importWorkshopSnapshot}=require('../../db/postgres/import-workshop-snapshot');
const {createNativeOwnerProof}=require('./helpers/archiveOwnerBinding');
const fs=require('node:fs/promises'),os=require('node:os'),crypto=require('node:crypto');
async function archiveSnapshot(snapshot){
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'workshop-native-archive-'));const tables=[];
 const write=async(name,value)=>{await fs.writeFile(path.join(directory,name),value);return{bytes:Buffer.byteLength(value),sha256:crypto.createHash('sha256').update(value).digest('hex')};};
 for(const [name,rows]of Object.entries(snapshot.tables)){const columns=catalogs[snapshot.family][name].split(' '),file=name+'.jsonl';
  const encoded=rows.map(row=>JSON.stringify(columns.map(column=>{const value=row[column];return value===null?{type:'null'}:typeof value==='string'?{type:'text',value}:Number.isInteger(value)?{type:'integer',value:String(value)}:{type:'real',value};}))+'\n').join('');
  tables.push({name,columns,file,rows:rows.length,...await write(file,encoded)});
 }
 const schemaFile='schema.json',schema=await write(schemaFile,JSON.stringify(tables.map(table=>({type:'table',name:table.name}))));
 await write('manifest.json',JSON.stringify({version:1,format:'dvaia-sqlite-archive-v1',complete:true,files:[{name:snapshot.family==='aria'?'sql_workshop.db':'nosql_workshop.db',schemaFile,schema,tables}]}));return directory;
}
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&!!process.env.PG_ARIA_IMPORT_TEST_MIGRATION_URL;
function row(family,table,values){return Object.fromEntries(catalogs[family][table].split(' ').map(key=>[key,Object.hasOwn(values,key)?values[key]:null]));}
for(const family of ['aria','nova'])test(`${family} snapshot owner remap, dry run, rollback and seed suppression`,{skip:!enabled},async()=>{
 const pool=createPool(process.env,`PG_${family.toUpperCase()}_IMPORT_TEST_MIGRATION_URL`);let archive,ownerFixture;
 try{
  await migrate(pool,path.join(__dirname,'../../db/postgres/workshop-migrations',family));
  const tables=Object.fromEntries(Object.keys(catalogs[family]).map(table=>[table,[]]));
  const stamp='2026-01-02T03:04:05.123456Z';
  tables.chat_history=[row(family,'chat_history',{id:41,user_id:'7',message_type:'user',message:'  {"unparsed": true}  ',timestamp:stamp})];
  if(family==='aria'){
   tables.products=[row(family,'products',{id:77,product_id:'preserved',name:'Raw product',category:'custom',price:1.25})];
   tables.orders=[row(family,'orders',{id:88,order_number:'O-88',user_id:'7',product_name:'Raw product',quantity:2,total_amount:2.5,created_at:stamp})];
   tables.receipts=[row(family,'receipts',{id:99,order_number:'O-88',receipt_number:'R-99',amount:2.5,issued_at:stamp})];
  }else{
   tables.papers=[row(family,'papers',{id:77,paper_id:'raw-paper',title:'Paper',authors:'[ "A" ]',topics:'invalid JSON retained',cited_by:'[]',access_level:'restricted'})];
   tables.reading_lists=[row(family,'reading_lists',{id:99,user_id:'7',paper_id:'raw-paper',added_at:stamp,notes:'raw notes'})];
   tables.nosql_injection_solution_visibility=[
    row(family,'nosql_injection_solution_visibility',{objective_id:'objective-one',solutions_enabled:1,updated_at:stamp}),
    row(family,'nosql_injection_solution_visibility',{objective_id:'objective-two',solutions_enabled:0,updated_at:stamp}),
   ];
   tables.nosql_injection_solutions=[
    row(family,'nosql_injection_solutions',{objective_id:'objective-one',title:'One',difficulty:'easy',hints:'h1',examples:'e1',approach:'a1',tips:'t1'}),
    row(family,'nosql_injection_solutions',{objective_id:'objective-two',title:'Two',difficulty:'hard',hints:'h2',examples:'e2',approach:'a2',tips:'t2'}),
   ];
  }
  const snapshot={version:1,family,tables};archive=await archiveSnapshot(snapshot);
  const mapped=await require('../../db/postgres/read-workshop-archive').readWorkshopArchive({archive,family});assert.deepEqual(mapped.snapshot,snapshot);
  const ownerBinding={archiveDigest:mapped.archiveDigest,identityMap:{7:71}};ownerFixture=await createNativeOwnerProof(pool,ownerBinding);
  const review={family,naiveTimestamps:'reject',review:{archiveDigest:mapped.archiveDigest,retainedOtherSources:[]},ownerBinding,opaqueOwnerResolutions:[]};
  const cli=require('../../db/postgres/import-workshop-archive').importWorkshopArchive;
  const archiveDry=await cli({archive,family,databaseEnv:`PG_${family.toUpperCase()}_IMPORT_TEST_MIGRATION_URL`,review,ownerProof:ownerFixture.ownerProof});
  assert.equal(archiveDry.applied,false);assert.equal(archiveDry.reviewMetadata.source,'archive_review');assert.equal(archiveDry.reviewMetadata.naiveTimestamps,'reject');assert.match(archiveDry.reviewMetadata.reviewSha256,/^[a-f0-9]{64}$/);
  const directDry=await importWorkshopSnapshot(pool,snapshot,{ownerBinding,ownerProof:ownerFixture.ownerProof,archiveDigest:mapped.archiveDigest});
  assert.equal(directDry.applied,false);assert.equal(directDry.reviewMetadata.source,'direct_snapshot');assert.equal(directDry.reviewMetadata.naiveTimestamps,'UTC');assert.equal(directDry.reviewMetadata.reviewSha256,null);assert.equal((await pool.query(`SELECT count(*)::integer AS n FROM ${family}.chat_history`)).rows[0].n,0);
  await assert.rejects(importWorkshopSnapshot(pool,snapshot,{apply:true}),{code:'OWNER_BINDING_REQUIRED'});
  const broken=structuredClone(snapshot);broken.tables.chat_history.push({...broken.tables.chat_history[0],id:41});await assert.rejects(importWorkshopSnapshot(pool,broken,{apply:true,ownerBinding,ownerProof:ownerFixture.ownerProof,archiveDigest:mapped.archiveDigest}),{code:'23505'});
  assert.equal((await pool.query(`SELECT count(*)::integer AS n FROM ${family}.chat_history`)).rows[0].n,0);
  assert.equal((await cli({archive,family,databaseEnv:`PG_${family.toUpperCase()}_IMPORT_TEST_MIGRATION_URL`,review,ownerProof:ownerFixture.ownerProof,apply:true})).applied,true);
  const history=(await pool.query(`SELECT id,user_id,message,to_char(timestamp AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS stamp FROM ${family}.chat_history`)).rows[0];assert.equal(history.id,41);assert.equal(history.user_id,'71');assert.equal(history.stamp,stamp);assert.equal(history.message,tables.chat_history[0].message);
  assert.equal((await pool.query(`SELECT source_row->>'user_id' AS source_user FROM ${family}.import_provenance WHERE source_table='chat_history'`)).rows[0].source_user,'7');
  assert.equal((await pool.query(`SELECT identity_map_sha256 FROM ${family}.import_batches`)).rows[0].identity_map_sha256,ownerFixture.ownerProof.identityMapSha256);
  const metadata=(await pool.query(`SELECT review_metadata FROM ${family}.import_batches`)).rows[0].review_metadata;
  assert.equal(metadata.source,'archive_review');assert.equal(metadata.naiveTimestamps,'reject');assert.equal(metadata.archiveDigest,mapped.archiveDigest);assert.match(metadata.reviewSha256,/^[a-f0-9]{64}$/);assert.deepEqual(metadata.retainedOtherSources,[]);assert.deepEqual(metadata.opaqueOwnerResolutions,[]);
  if(family==='nova'){
   assert.deepEqual((await pool.query("SELECT source_table,source_id FROM nova.import_provenance WHERE source_table LIKE 'nosql_injection_solution_%' ORDER BY source_table,source_id")).rows,[
    {source_table:'nosql_injection_solutions',source_id:'objective-one'},
    {source_table:'nosql_injection_solutions',source_id:'objective-two'},
    {source_table:'nosql_injection_solution_visibility',source_id:'objective-one'},
    {source_table:'nosql_injection_solution_visibility',source_id:'objective-two'},
   ]);
  }
  if(family==='nova')assert.equal((await pool.query('SELECT topics FROM nova.papers')).rows[0].topics,'invalid JSON retained');
  const next=(await pool.query(`INSERT INTO ${family}.chat_history(user_id,message_type,message) VALUES('next','user','next') RETURNING id`)).rows[0].id;assert.equal(next,42);
  assert.equal((await pool.query(`SELECT version FROM ${family}.seed_state`)).rows[0].version,1);
  await assert.rejects(importWorkshopSnapshot(pool,snapshot,{apply:true,ownerBinding,ownerProof:ownerFixture.ownerProof,archiveDigest:mapped.archiveDigest}),/empty workshop/);
 }finally{await ownerFixture?.cleanup();await pool.end();if(archive)await fs.rm(archive,{recursive:true,force:true});}
});
