'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const{fixture}=require('./fixtures/xssArchive');
const{mapXssArchive}=require('../db/postgres/map-xss-archive');
test('XSS mapping preserves raw HTML, nullable state, IDs and subject rename without inventing judges',()=>{
 const result=mapXssArchive(fixture());assert.equal(result.snapshot.email_templates[0].subject,'Original subject');assert.equal(result.snapshot.email_templates[0].is_favorite,null);assert.equal(result.snapshot.profiles[0].name,'<img src=x onerror=fixture()>');assert.equal(result.snapshot.progress[0].created_at,null);assert.equal(result.snapshot.xss_email_judge_receipts.length,0);assert.equal(result.provenance[0].row.id,5);
});
test('missing preJudge tables and duplicate/unsupported source state require explicit handling',()=>{
 let raw=fixture();raw.review.missingTables=[];assert.throws(()=>mapXssArchive(raw),{code:'INCOMPLETE_XSS_SOURCE_REVIEW'});
 raw=fixture();raw.sources['xss_email_challenge.db'].tables.shared_templates=[{private:'retained'}];assert.throws(()=>mapXssArchive(raw),{code:'INCOMPLETE_XSS_SOURCE_REVIEW'});
 raw.review.retainedTables=[{source:'xss_email_challenge.db',table:'shared_templates',policy:'retain_archive_only'}];assert.equal(mapXssArchive(raw).report.retainedTables.length,1);
 raw=fixture();raw.sources['xss_email_challenge.db'].tables.xss_workshop_profiles[0].extra='lost';assert.throws(()=>mapXssArchive(raw),{code:'UNMAPPED_XSS_COLUMNS'});
 raw=fixture();raw.sources['xss_email_challenge.db'].tables.email_templates[0].id=2147483647;assert.throws(()=>mapXssArchive(raw),{code:'DUPLICATE_OR_EXHAUSTED_XSS_ID'});
});

test('owner binding remaps XSS workshop and builder owners without changing local IDs or payloads',()=>{
 const raw=fixture();
 raw.sources['xss_email_challenge.db'].tables.xss_workshop_profiles[0].user_key='7';
 raw.sources['xss_email_challenge.db'].tables.xss_workshop_progress[0].user_key='7';
 raw.sources['xss_email_challenge.db'].tables.xss_workshop_emails[0].user_key='7';
 for(const table of ['email_profiles','email_templates','template_previews','xss_challenge_progress'])for(const row of raw.sources['xss_email_challenge.db'].tables[table])row.user_id=7;
 raw.sources['xss_email_challenge.db'].tables.xss_workshop_emails.push({...raw.sources['xss_email_challenge.db'].tables.xss_workshop_emails[0],id:10,user_key:'anon_public'});
 raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};
 const result=mapXssArchive(raw);
 assert.equal(result.snapshot.profiles[0].user_key,'71');
 assert.equal(result.snapshot.progress[0].user_key,'71');
 assert.equal(result.snapshot.emails[0].user_key,'71');
 assert.equal(result.snapshot.emails[1].user_key,'anon_public');
 assert.equal(result.snapshot.email_profiles[0].user_id,71);
 assert.equal(result.snapshot.email_templates[0].profile_id,70,'Builder-local profile identity remains unchanged');
 assert.equal(result.snapshot.template_previews[0].template_id,80,'Teaching-local template identity remains unchanged');
 assert.equal(result.provenance.find(row=>row.table==='email_templates').row.user_id,7);
 assert.match(result.report.identityMapSha256,/^[a-f0-9]{64}$/);
});

test('XSS requires explicit numeric alias resolution and imports require branded proof before pool access',async()=>{
 const raw=fixture();raw.sources['xss_email_challenge.db'].tables.xss_workshop_profiles[0].user_key='007';raw.sources['xss_email_challenge.db'].tables.xss_workshop_progress[0].user_key='007';raw.sources['xss_email_challenge.db'].tables.xss_workshop_emails[0].user_key='007';raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};
 assert.throws(()=>mapXssArchive(raw),{code:'UNRESOLVED_OPAQUE_ARCHIVE_OWNER'});
 raw.opaqueOwnerResolutions=[{sourceKey:'007',disposition:'map_source_identity',sourceId:'7'}];
 assert.equal(mapXssArchive(raw).snapshot.profiles[0].user_key,'71');
 raw.opaqueOwnerResolutions=[{sourceKey:'007',disposition:'map_source_identity',sourceId:'7'},{sourceKey:'unused',disposition:'preserve_opaque'}];
 assert.throws(()=>mapXssArchive(raw),{code:'UNUSED_OPAQUE_OWNER_RESOLUTION'});
 await assert.rejects(require('../db/postgres/import-xss-archive').importXssArchive({connect:()=>{throw Error('pool must not open');}},raw),{code:'OWNER_PROOF_REQUIRED'});
 const {fixtureOwnerProof}=require('./fixtures/archiveOwnerBinding');
 const wrongProof=await fixtureOwnerProof({archiveDigest:'b'.repeat(64),identityMap:{7:71}});
 await assert.rejects(require('../db/postgres/import-xss-archive').importXssArchive({connect:()=>{throw Error('pool must not open');}},raw,{ownerProof:wrongProof}),{code:'VERIFIED_ARCHIVE_OWNER_BINDING_REQUIRED'});
});

test('XSS rejects owner collisions after remapping',()=>{
 const raw=fixture(),profile=raw.sources['xss_email_challenge.db'].tables.xss_workshop_profiles[0];raw.sources['xss_email_challenge.db'].tables.xss_workshop_profiles.push({...profile,id:11});raw.ownerBinding={archiveDigest:raw.archiveDigest,identityMap:{7:71}};raw.opaqueOwnerResolutions=[{sourceKey:'0007',disposition:'map_source_identity',sourceId:'7'}];
 assert.throws(()=>mapXssArchive(raw),{code:'DUPLICATE_XSS_TARGET_KEY'});
});

test('verified XSS archive preserves tagged rows and rejects altered exporter bytes',async()=>{
 const fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
 const{readXssArchive}=require('../db/postgres/import-xss-archive');
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'xss-archive-fixture-'));const raw=fixture(),tables=[];
 try{
  const write=async(file,content)=>{await fs.writeFile(path.join(directory,file),content);return{bytes:Buffer.byteLength(content),sha256:crypto.createHash('sha256').update(content).digest('hex')};};
  for(const[table,rows]of Object.entries(raw.sources['xss_email_challenge.db'].tables)){
   const columns=require('../db/postgres/map-xss-archive').TABLES[table].columns.split(' '),file=table+'.jsonl';
   const content=rows.map(row=>JSON.stringify(columns.map(key=>row[key]===null?{type:'null'}:typeof row[key]==='number'?{type:'integer',value:String(row[key])}:{type:'text',value:row[key]}))+'\n').join('');
   tables.push({name:table,columns,rows:rows.length,file,...await write(file,content)});
  }
  const schemaFile='schema.json',schema=await write(schemaFile,JSON.stringify(tables.map(table=>({type:'table',name:table.name}))));
  await write('manifest.json',JSON.stringify({version:1,format:'owasp-ai-goat-sqlite-archive-v1',complete:true,files:[{name:'xss_email_challenge.db',sourceSha256:'b'.repeat(64),schemaFile,schema,tables}]}));
  const read=await readXssArchive({archive:directory,naiveTimestamps:'UTC'});read.review={...raw.review,archiveDigest:read.archiveDigest};assert.equal(mapXssArchive(read).snapshot.email_templates[0].id,80);
  await fs.appendFile(path.join(directory,'email_templates.jsonl'),'tamper');await assert.rejects(readXssArchive({archive:directory}),{code:'ARCHIVE_HASH_MISMATCH'});
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
