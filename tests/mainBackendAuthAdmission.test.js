'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {admit,launchLocation,ownershipEnvironment,FIXTURES}=require('./fixtures/mainBackendAuthAdmission');
function fixture(){const source='/owned/main',evidence=source+'/backups/private-recovery/backend-auth/run-x',root=evidence+'/runtime';const env={MAIN_BACKEND_AUTH_APP_DATA:'/owned/data',PG_MAIN_BACKEND_AUTH:'1',PG_TEST_DISPOSABLE:'yes',MAIN_BACKEND_AUTH_EVIDENCE:evidence,DVAIA_FULL_BACKEND_RUNTIME_ROOT:root};const row={privateAppData:{path:'/owned/data',device:1,inode:2,uid:process.getuid()},cohort:'main-backend-auth',evidenceRoot:evidence,nativeStarted:true,nativePid:process.pid,sourceRoot:source,owner:'a'.repeat(32),containerId:'b'.repeat(64),databasePort:55432};const io={realpathSync:p=>p,lstatSync:p=>({isDirectory:()=>p!==evidence+'/ownership.json',isFile:()=>p===evidence+'/ownership.json',isSymbolicLink:()=>false,dev:1,ino:2,uid:process.getuid(),mode:p===evidence+'/ownership.json'?0o600:0o700,size:1000}),readFileSync:()=>JSON.stringify(row)};return {source,env,row,io};}
test('explicit main cohort binds native parent and owned database journal',()=>{const f=fixture();assert.equal(admit(f.env,f).port,55432);f.row.nativePid++;assert.throws(()=>admit(f.env,f));});
test('copy sentinel, other cohorts and foreign evidence are denied',()=>{for(const delta of [{DVAIA_ISOLATED_TEST_WORKSPACE:'/owned/main'},{PG_FULL_BACKEND_RENDERED:'1'},{MAIN_BACKEND_AUTH_EVIDENCE:'/other'}]){const f=fixture();assert.throws(()=>admit({...f.env,...delta},f));}});
test('absolute source entry runs with private cwd and no caller traversal',()=>{assert.deepEqual(launchLocation('/main','/private','server/index.js'),{file:'/main/server/index.js',cwd:'/private'});assert.throws(()=>launchLocation('/main','/private','../index.js'));});
test('ownership cohort aliases exact pairs without inherited application configuration',()=>{const env={IDENTITY_DATABASE_URL:'a',IDENTITY_MIGRATION_DATABASE_URL:'b',SECURESHOP_AGENTS_DATABASE_URL:'c',SECURESHOP_AGENTS_MIGRATION_DATABASE_URL:'d',SECRET:'notcopied'};const out=ownershipEnvironment(env);assert.equal(out.PG_READS_TEST_RUNTIME_URL,'a');assert.equal(out.PG_SECURESHOP_AGENTS_TEST_MIGRATION_URL,'d');assert.equal(out.SECRET,undefined);assert.equal(FIXTURES.length,2);});
test('existing fixture username fits actual canonical fifty-character validator',()=>{require('../server/database/postgres/identityValidation').text('run-auth-'+'0'.repeat(36),'username',50);});
test('actual dotenv default resolution reads private cwd rather than source environment',()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),dotenv=require('dotenv');
 const previous=process.cwd(),root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-auth-cwd-control-'))),runtime=path.join(root,'runtime');fs.mkdirSync(runtime);fs.writeFileSync(path.join(root,'.env'),'QUALIFICATION_SYNTHETIC=source\n');fs.writeFileSync(path.join(runtime,'.env'),'QUALIFICATION_SYNTHETIC=private\n');
 const read=fs.readFileSync,observed=[];try{process.chdir(runtime);fs.readFileSync=function(file,...args){observed.push(String(file));assert.notEqual(String(file),path.join(root,'.env'));return read.call(this,file,...args);};const target={};const result=dotenv.config({processEnv:target,quiet:true});assert.equal(result.parsed.QUALIFICATION_SYNTHETIC,'private');assert(observed.includes(path.join(runtime,'.env')));}finally{fs.readFileSync=read;process.chdir(previous);fs.rmSync(root,{recursive:true,force:true});}
 const entry=fs.readFileSync(path.join(previous,'server/index.js'),'utf8');assert.match(entry,/require\('dotenv'\)\.config\(\)/);
});
test('startup gate cannot admit EOF or a wrong release token',()=>{
 const {awaitStartupGate}=require('./fixtures/mainBackendAuthAdmission');
 assert.throws(()=>awaitStartupGate(()=>0));assert.throws(()=>awaitStartupGate((_fd,b)=>{b[0]=50;return 1;}));
 awaitStartupGate((fd,b,offset,length,position)=>{assert.equal(fd,0);assert.equal(length,1);b[0]=49;return 1;});
});

test('changed external data identity is denied',()=>{const f=fixture();f.row.privateAppData.inode=3;assert.throws(()=>admit(f.env,f));});
test('standalone core is an exact model-free main-workspace ownership profile',()=>{
 const f=fixture();f.env.PG_FULL_BACKEND_STANDALONE_CORE='1';f.row.standaloneCore={profile:'standalone-core',modelCalls:0,sourceCopy:false};
 assert.deepEqual(admit(f.env,f).standaloneCore,f.row.standaloneCore);
 for(const marker of [{profile:'standalone-core',modelCalls:1,sourceCopy:false},{profile:'other',modelCalls:0,sourceCopy:false},{profile:'standalone-core',modelCalls:0,sourceCopy:true}]){f.row.standaloneCore=marker;assert.throws(()=>admit(f.env,f));}
 f.row.standaloneCore={profile:'standalone-core',modelCalls:0,sourceCopy:false};
 for(const flags of [{PG_FULL_BACKEND_STANDALONE_CORE:undefined},{PG_MAIN_CAPACITY_200:'1',PG_FULL_BACKEND_CAPACITY:'1'},{PG_MAIN_RENDERED_PLATFORM:'1',PG_FULL_BACKEND_RENDERED:'1'}])assert.throws(()=>admit({...f.env,...flags},f));
});
test('actual production data-root guard rejects main overlap and accepts owned external data',()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');const {ensureApplicationDataRoot}=require('../scripts/application-data-root');
 const workspace=process.cwd(),root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-auth-data-control-')));fs.chmodSync(root,0o700);
 try{assert.throws(()=>ensureApplicationDataRoot({workspace,environment:{DVAIA_APP_DATA_ROOT:path.join(workspace,'backups/private-recovery/app-data')}}),{code:'INVALID_APPLICATION_DATA_ROOT'});assert.equal(ensureApplicationDataRoot({workspace,environment:{DVAIA_APP_DATA_ROOT:root}}),root);}finally{fs.rmdirSync(root);}
});

test('rendered platform is a closed journal-bound profile, never generic browser admission',()=>{
 const f=fixture();Object.assign(f.env,{PG_MAIN_RENDERED_PLATFORM:'1',PG_FULL_BACKEND_RENDERED:'1',PG_FULL_BACKEND_BROWSER:'/owned/browser',PG_FULL_BACKEND_BROWSER_SHA256:'c'.repeat(64)});
 f.row.renderedPlatform={profile:'rendered-platform',buildRoot:f.source+'/client/build',buildInventorySha256:'d'.repeat(64),browser:'/owned/browser',browserSha256:'c'.repeat(64)};
 assert.equal(admit(f.env,f).renderedPlatform.buildRoot,f.source+'/client/build');
 for(const delta of [{PG_MAIN_RENDERED_PLATFORM:undefined},{PG_MAIN_CAPACITY_200:'1',PG_FULL_BACKEND_CAPACITY:'1'},{PG_FULL_BACKEND_BROWSER:'/foreign'}])assert.throws(()=>admit({...f.env,...delta},f));
 f.row.renderedPlatform.buildRoot='/foreign/build';assert.throws(()=>admit(f.env,f));
});
test('standalone rendered browser needs its distinct journal and cannot inherit platform admission',()=>{
 const f=fixture();Object.assign(f.env,{PG_FULL_BACKEND_STANDALONE_CORE:'1',PG_MAIN_RENDERED_STANDALONE:'1',
  PG_FULL_BACKEND_RENDERED:'1',PG_FULL_BACKEND_BROWSER:'/owned/browser',PG_FULL_BACKEND_BROWSER_SHA256:'c'.repeat(64)});
 f.row.standaloneCore={profile:'standalone-core-rendered',modelCalls:0,sourceCopy:false};
 f.row.renderedStandalone={profile:'standalone-core-rendered',buildRoot:f.source+'/client/build',
  buildInventorySha256:'d'.repeat(64),browser:'/owned/browser',browserSha256:'c'.repeat(64)};
 assert.equal(admit(f.env,f).renderedStandalone.profile,'standalone-core-rendered');
 for(const delta of [{PG_FULL_BACKEND_STANDALONE_CORE:undefined},{PG_MAIN_RENDERED_STANDALONE:undefined},
  {PG_MAIN_RENDERED_PLATFORM:'1'},{PG_FULL_BACKEND_BROWSER:'/foreign/browser'}])
  assert.throws(()=>admit({...f.env,...delta},f));
 const saved=f.row.renderedStandalone;delete f.row.renderedStandalone;assert.throws(()=>admit(f.env,f));
 f.row.renderedStandalone={...saved,buildInventorySha256:'invalid'};assert.throws(()=>admit(f.env,f));
});
test('bound sessions require exact rendered parent journal opt-in',()=>{
 const f=fixture();Object.assign(f.env,{PG_MAIN_BOUND_SESSIONS:'1',PG_MAIN_RENDERED_PLATFORM:'1',PG_FULL_BACKEND_RENDERED:'1',PG_FULL_BACKEND_BROWSER:'/owned/browser',PG_FULL_BACKEND_BROWSER_SHA256:'c'.repeat(64)});
 f.row.renderedPlatform={profile:'rendered-platform',boundSessions:true,buildRoot:f.source+'/client/build',buildInventorySha256:'d'.repeat(64),browser:'/owned/browser',browserSha256:'c'.repeat(64)};
 assert.equal(admit(f.env,f).renderedPlatform.boundSessions,true);
 for(const v of [undefined,'0','true'])assert.throws(()=>admit({...f.env,PG_MAIN_BOUND_SESSIONS:v},f));
 delete f.row.renderedPlatform.boundSessions;assert.throws(()=>admit(f.env,f));
});
