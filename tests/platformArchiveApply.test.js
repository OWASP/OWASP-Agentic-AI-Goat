'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs/promises'),os=require('node:os'),path=require('node:path');
const {argumentsFor,applyPlatformArchive}=require('../db/postgres/apply-platform-archive');
test('operator parser defaults to native dryrun and rejects credential/duplicate arguments',()=>{
 const options=argumentsFor(['--archive','archive','--review','review']);assert.equal(options.apply,false);assert.equal(options.databaseEnv,'IDENTITY_MIGRATION_DATABASE_URL');
 assert.equal(argumentsFor(['--archive','a','--review','r','--apply']).apply,true);
 for(const args of [['constructor','x'],['__proto__','x'],['--url','postgres://secret'],['--archive','a','--review','r','--apply','--apply'],['--archive','a','--review','r','--database-env','DATABASE_URL']])assert.throws(()=>argumentsFor(args));
});
test('CLI invokes native dryrun by default, closes pool and returns no private DTO',async()=>{
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'apply-cli-test-'));const reviewFile=path.join(directory,'review.json');await fs.writeFile(reviewFile,'{}');let closed=false;
 try{
  const result=await applyPlatformArchive({archive:'fixture',reviewFile,apply:false,databaseEnv:'IDENTITY_MIGRATION_DATABASE_URL'},{
   prepare:async()=>({inputs:{private:'secret'},report:{archiveDigest:'a'.repeat(64),wholeArchiveImported:false}}),
   createPool:()=>({end:async()=>{closed=true;}}),
   importer:async(pool,input,options)=>{assert.equal(input.private,'secret');assert.equal(options.dryRun,true);return{applied:false,dryRun:true,nativeConstraintsChecked:true};},
  });assert.equal(result.nativeConstraintsChecked,true);assert.equal(JSON.stringify(result).includes('secret'),false);assert.equal(closed,true);
  const child=require('node:child_process').spawnSync(process.execPath,['db/postgres/apply-platform-archive.js','--archive','missing','--review',reviewFile],{encoding:'utf8'});
  assert.equal(child.status,1);assert.match(child.stderr,/\{"error":"[A-Z_]+"\}/);assert.equal(child.stderr.includes(' at '),false);
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});

test('reviewed full archive prepares once with exact retained coverage and revalidated private identity review',async()=>{
 const crypto=require('node:crypto');
 const {COLUMNS:identityColumns}=require('../db/postgres/map-identity-archive');
 const {COLUMNS:platformColumns}=require('../db/postgres/map-platform-snapshot');
 const {FAMILIES}=require('../db/postgres/map-platform-solutions');
 const {preparePlatformApply}=require('../db/postgres/prepare-platform-apply');
 const {buildImportBatch}=require('../db/postgres/import-batch');
 const extra=require('./fixtures/platformAdditionalSolutions').fixture();
 const sources=extra.sources,users=sources['users_auth.db'].tables,stamp='2026-01-01T00:00:00Z';
 const row=(table,values)=>Object.fromEntries(identityColumns[table].split(' ').map(key=>[key,Object.hasOwn(values,key)?values[key]:null]));
 Object.assign(users,Object.fromEntries(Object.keys(platformColumns).map(table=>[table,[]])));
 users.users=[row('users',{id:71,username:'fixture-admin',email:'fixture@example.test',password:require('bcryptjs').hashSync('private-password',4),role:'admin',admin_level:1,email_verified:0,is_active:1,login_attempts:0,last_password_change:stamp,password_reset_required:0,two_factor_enabled:0,created_at:stamp,updated_at:stamp})];
 users.admin_permissions=[row('admin_permissions',{id:1,admin_id:71,permission_name:'user_management',granted_at:stamp,is_active:1})];users.user_sessions=[];users.activity_logs=[];
 Object.assign(users,require('./fixtures/identityAuxiliaryImport').fixture().tables);
 for(const config of Object.values(FAMILIES)){
  users[config.contentTable]=config.objectiveIds.map((id,index)=>({...config.contentHasId?{id:index+1}:{},[config.idColumn]:id,title:'Title',difficulty:'Intermediate',hints:'[]',examples:'[]',approach:'private approach',tips:'[]',...config.contentHasTimestamp?{updated_at:stamp}:{}}));
  users[config.visibilityTable]=config.objectiveIds.map((id,index)=>({...config.visibilityHasId?{id:index+1}:{},[config.idColumn]:id,solutions_enabled:0,...config.visibilityTracksActor?{enabled_by:null,enabled_at:null}:{},updated_at:stamp}));
 }
 users.retired_private_table=[{value:'private-retained-value'}];sources['sensitive_info_workshop.db'].tables.finflow_progress=[{user:'other-native-scope'}];
 const directory=await fs.mkdtemp(path.join(os.tmpdir(),'reviewed-platform-'));
 try{
  const write=async(file,content)=>{await fs.writeFile(path.join(directory,file),content);return{bytes:Buffer.byteLength(content),sha256:crypto.createHash('sha256').update(content).digest('hex')};};
  const files=[];let index=0;
  for(const [name,envelope] of Object.entries(sources)){
   const tables=[];
   for(const [table,rows] of Object.entries(envelope.tables)){
    const columns=rows.length?Object.keys(rows[0]):(platformColumns[table]||identityColumns[table]||'').split(' ').filter(Boolean);
    const file=`table-${index++}.jsonl`;
    const content=rows.map(row=>JSON.stringify(columns.map(key=>row[key]===null?{type:'null'}:typeof row[key]==='number'?{type:'integer',value:String(row[key])}:{type:'text',value:row[key]}))+'\n').join('');
    tables.push({name:table,columns,rows:rows.length,file,...await write(file,content)});
   }
   const schemaFile=`schema-${index++}.json`,schema=await write(schemaFile,JSON.stringify(tables.map(table=>({type:'table',name:table.name}))));files.push({name,sourceSha256:'b'.repeat(64),schemaFile,schema,tables});
  }
  const manifest=JSON.stringify({version:1,format:'dvaia-sqlite-archive-v1',complete:true,files});await write('manifest.json',manifest);
  const archiveDigest=crypto.createHash('sha256').update(manifest).digest('hex');
  const review={version:1,archiveDigest,identityMap:{71:71},naiveTimestamps:'UTC',resolutions:{},identityNormalizations:[],platformDefaults:Object.fromEntries(['exercises','objectiveVisibility','hintVisibility'].map(key=>[key,'catalog_visibility_defaults_without_content'])),retainedPlatformTables:[{table:'retired_private_table',policy:'retain_archive_only'}]};
  const prepared=await preparePlatformApply({archive:directory,review});
  assert.equal(prepared.report.wholeArchiveImported,false);assert.equal(prepared.report.otherChallengeTableCount,1);
  assert.equal(prepared.report.counts.solutions_solutions,52);assert.equal(prepared.report.counts.additional_solutions,48);
  assert.equal(JSON.stringify(prepared.report).includes('private'),false);
  assert.equal(buildImportBatch(prepared.inputs).planSha256,prepared.report.planSha256);
  if(process.env.PG_TEST_DISPOSABLE==='yes' && process.env.PG_PLATFORM_APPLY_TEST_MIGRATION_URL){
   const pool=require('../server/database/postgres').createPool(process.env,'PG_PLATFORM_APPLY_TEST_MIGRATION_URL');
   try{
    await require('../db/postgres/migrate').migrate(pool,path.join(__dirname,'../db/postgres/identity-migrations'));
    const reviewFile=path.join(directory,'review.json');await fs.writeFile(reviewFile,JSON.stringify(review),{mode:0o600});
    const options={archive:directory,reviewFile,apply:false,databaseEnv:'PG_PLATFORM_APPLY_TEST_MIGRATION_URL'};
    const dryrun=await applyPlatformArchive(options);assert.equal(dryrun.dryRun,true);
    assert.equal((await pool.query('SELECT count(*)::int n FROM identity.users')).rows[0].n,0);
    const applied=await applyPlatformArchive({...options,apply:true});assert.equal(applied.applied,true);
    assert.equal((await pool.query('SELECT count(*)::int n FROM identity.import_batches')).rows[0].n,1);
    await assert.rejects(applyPlatformArchive({...options,apply:true}),/initial platform revision/);
   }finally{await pool.end();}
  }

  const changed=structuredClone(prepared.inputs);changed.archiveReview.identityReview.normalizations.push({});assert.throws(()=>buildImportBatch(changed),/digest mismatch/);
  await assert.rejects(preparePlatformApply({archive:directory,review:{...review,retainedPlatformTables:[]}}),{code:'INCOMPLETE_PLATFORM_RETENTION_REVIEW'});
  await assert.rejects(preparePlatformApply({archive:directory,review:{...review,identityNormalizations:[{collection:'audit',sourceId:1,field:'error_message',reason:'no_native_column',policy:'apply_native_metadata_policy_retain_source_archive'}]}}),{code:'STALE_OR_EXTRA_IDENTITY_NORMALIZATION_DECISION'});
 }finally{await fs.rm(directory,{recursive:true,force:true});}
});
