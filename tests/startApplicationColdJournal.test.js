'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
test('cold actual startup CLI exposes cleanup before journal helper circular import',()=>{
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'dvaia-cold-entry-')),home=fs.realpathSync(directory);const preload=path.join(directory,'guard.cjs');
 fs.writeFileSync(preload,`
 const Module=require('node:module'),{EventEmitter}=require('node:events');const load=Module._load;let cleanup=false;process.execArgv=[];
 process.kill=(pid,signal)=>{if(pid!==-424242)throw Error('Unexpected signal target');cleanup=true;throw Object.assign(Error('absent'),{code:'ESRCH'});};
 Module._load=function(name,parent,isMain){
 if(['pg','sqlite3','better-sqlite3'].includes(name))throw Error('Resource module forbidden');
 if(name==='node:net'||name==='net')return {createServer(){const server=new EventEmitter();server.listen=(options,callback)=>{if(!Number.isInteger(options.port)||options.exclusive!==true)throw Error('Unexpected port probe');queueMicrotask(callback);};server.close=callback=>queueMicrotask(()=>callback());return server;}};
 if(name==='node:child_process')return {execFile(){throw Error('Unexpected subprocess');},spawn(exe,args,opts){if(!args[0].endsWith('application-journal-bound-maintenance.js'))throw Error('Unexpected child');const c=new EventEmitter();c.pid=424242;c.connected=true;c.disconnect=()=>{c.connected=false;};c.send=(message,callback)=>{if(message.type!=='prospective-original-grant'||message.installationBinding!=='binding')throw Error('Unexpected grant');callback();queueMicrotask(()=>{c.emit('message',{type:'journal-bound-complete',completed:true});c.emit('exit',0,null);});};queueMicrotask(()=>c.emit('message',{type:'prospective-original-ready',nonce:'11111111-1111-4111-8111-111111111111',childPid:424242,parentPid:process.pid,installationBinding:'binding'}));return c;}};
 if(name==='./lib/application-maintenance-installation')return {resolveMaintenanceInstallation(root){return{installationRoot:root,bindingSha256:'binding',assertCurrent(){}};}};
 if(name==='./application-node-runtime')return {assertSupportedApplicationNodeVersion(){}};
 if(name==='./local-mailpit')return {assertLocalMailpitReady(){throw Error('Unexpected mail readiness');}};
 if(name==='dotenv')return {config(){}};
 if(name.endsWith('secureshopPolicyRendererManagedEnvironment'))return {load(){return{};}};
 if(name.endsWith('secureshopSystemManagedEnvironment'))return {loadWithQualified(){return{};},async assertReady(){if(!cleanup)throw Error('Cleanup missing');console.log('COLD_START_CLEANUP_BOUNDARY');throw Object.assign(Error('bounded test stop'),{code:'TEST_BOUNDARY'});}};
 if(name.endsWith('secureshopPricingManagedConfiguration'))return {environment(){return{};}};
 if(name.endsWith('applicationDatabaseEngine'))return {assertApplicationDatabaseEngine(){}};
 if(name==='./lib/start-managed-listings')return {startManagedListings:async()=>({absent:true})};
 if(name==='./install/secureshop-owned-listing-template')return {startExisting:async()=>({absent:true})};
 if(name.endsWith('db/postgres/initialize-application'))return {configurationPlan(){return[];}};
 if(name==='./application-data-root')return {ensureApplicationDataRoot(){return process.env.TEST_ROOT;}};
 if(name.endsWith('platformSigningConfiguration'))return {assertPlatformSigningConfiguration(){}};
 return load.apply(this,arguments);
 };
 `);
 try{const result=spawnSync(process.execPath,['--require',preload,path.resolve('scripts/start-application.js'),'--init-db','--maintenance-profile=canonical16-ctf-inprocess-v1'],{env:{PATH:'/usr/bin:/bin',HOME:home,USERPROFILE:home,PLATFORM_DATABASE_ENGINE:'postgres',TEST_ROOT:directory},encoding:'utf8',timeout:5000});assert.ifError(result.error);assert.equal(result.status,1);assert.match(result.stdout,/COLD_START_CLEANUP_BOUNDARY/,result.stderr);assert.match(result.stderr,/TEST_BOUNDARY/);}
 finally{fs.rmSync(directory,{recursive:true,force:true});}
});
