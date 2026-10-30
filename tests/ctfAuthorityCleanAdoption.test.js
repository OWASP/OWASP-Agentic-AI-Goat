'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
const {createHash,randomUUID}=require('node:crypto');
const {createRequire,Module}=require('node:module');
const encode=value=>Buffer.from(JSON.stringify(value,null,2)+'\n');
function fixture(t,{fsOverrides={},cleanOverride}={}){
 const directory=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ctf-clean-adoption-')));
 t.after(()=>fs.rmSync(directory,{recursive:true,force:true}));
 const binding={workspaceId:'a'.repeat(64),provisioningSha256:'b'.repeat(64),identityStoreId:randomUUID(),ctfStoreId:randomUUID()};
 const saved={version:1,binding,bootstrapId:randomUUID(),activationId:randomUUID(),phase:'complete',revision:4,
   checkpoint:{sourceRevision:'3',manifestSha256:'c'.repeat(64),authoritySha256:'d'.repeat(64)}};
 const originalBytes=encode(saved),target=path.join(directory,'ctf-authority.json');
 fs.writeFileSync(target,originalBytes,{mode:0o600});
 const predecessor=path.join(directory,`ctf-authority-v1-${createHash('sha256').update(originalBytes).digest('hex')}.json`);
 const activation={activation_id:saved.activationId,bootstrap_operation_id:saved.bootstrapId,
   identity_store_id:binding.identityStoreId,ctf_store_id:binding.ctfStoreId,protocol_version:1,
   source_revision:'3',manifest_sha256:saved.checkpoint.manifestSha256,authority_sha256:saved.checkpoint.authoritySha256};
 const abort=new AbortController();let live=true,cleanReads=0;
 const clean={epoch:'3',installationId:randomUUID()};
 const lease={assertHeld(){assert(live);abort.signal.throwIfAborted();},signal:abort.signal,
   async assertClean(){cleanReads++;if(cleanOverride)return cleanOverride(cleanReads,clean);return clean;}};
 const launch={installation:{directory,assertCurrent(){assert(live);}},assertCurrent(){assert(live);}};
 const file=require.resolve('../scripts/install/ctf-authority-clean-adoption'),local=createRequire(file),loaded=new Module(file,module);
 loaded.filename=file;loaded.require=name=>{
   if(name==='node:fs')return new Proxy(fs,{get:(object,key)=>Object.hasOwn(fsOverrides,key)?fsOverrides[key]:object[key]});
   if(name==='../../server/services/applicationMaintenanceExecutionAdmission')return{assertOwnedLaunch(l,s){
     assert.equal(l,launch);assert.equal(s,lease);lease.assertHeld();launch.assertCurrent();}};
   return local(name);
 };
 loaded._compile(fs.readFileSync(file,'utf8'),file);
 const args={directory,originalBytes,binding,activation,launch,lease};
 return{...args,saved,target,predecessor,abort,args,adopt:loaded.exports.adoptLegacyCtfAuthorityJournal,
   revoke(){live=false;},cleanReads:()=>cleanReads};
}
test('complete verified v1 adoption preserves exact predecessor, IDs, revision and checkpoints and replays',async t=>{
 const f=fixture(t),result=await f.adopt(f.args);
 assert.equal(result.adopted,true);assert.deepEqual(fs.readFileSync(f.predecessor),f.originalBytes);
 assert.deepEqual(JSON.parse(fs.readFileSync(f.target)),{...f.saved,version:2});
 assert.equal(fs.statSync(f.predecessor).mode&0o777,0o600);assert.equal(fs.statSync(f.target).mode&0o777,0o600);
 assert.equal(fs.statSync(f.predecessor).nlink,1);
 assert.deepEqual((await f.adopt(f.args)).resultBytes,result.resultBytes);
 assert.deepEqual(fs.readFileSync(f.predecessor),f.originalBytes);assert.equal(f.cleanReads(),4);
});
test('incomplete, noncanonical and already-v2 inputs do not publish or invent checkpoints',async t=>{
 for(const patch of [{phase:'prepared'},{version:2}]){
   const f=fixture(t),bytes=encode({...f.saved,...patch});fs.writeFileSync(f.target,bytes);
   await assert.rejects(f.adopt({...f.args,originalBytes:bytes}));assert.deepEqual(fs.readFileSync(f.target),bytes);assert(!fs.existsSync(f.predecessor));
 }
 const f=fixture(t),bytes=Buffer.from(JSON.stringify(f.saved));fs.writeFileSync(f.target,bytes);
 await assert.rejects(f.adopt({...f.args,originalBytes:bytes}));assert.deepEqual(fs.readFileSync(f.target),bytes);
});
test('activation, store, binding and checkpoint mismatches fail before filesystem mutation',async t=>{
 for(const key of ['activation_id','bootstrap_operation_id','identity_store_id','ctf_store_id','source_revision','manifest_sha256','authority_sha256']){
   const f=fixture(t),activation={...f.activation,[key]:key==='source_revision'?'4':key.endsWith('sha256')?'e'.repeat(64):randomUUID()};
   await assert.rejects(f.adopt({...f.args,activation}));assert.deepEqual(fs.readFileSync(f.target),f.originalBytes);assert(!fs.existsSync(f.predecessor));
 }
 const f=fixture(t);await assert.rejects(f.adopt({...f.args,binding:{...f.binding,workspaceId:'e'.repeat(64)}}));
 assert(!fs.existsSync(f.predecessor));
});
test('same binding but changed current revision or checkpoints rejects the captured predecessor',async t=>{
 for(const patch of [{revision:5},{checkpoint:{sourceRevision:'4',manifestSha256:'c'.repeat(64),authoritySha256:'d'.repeat(64)}}]){
   const f=fixture(t),changed=encode({...f.saved,...patch});fs.writeFileSync(f.target,changed);
   await assert.rejects(f.adopt(f.args));assert.deepEqual(fs.readFileSync(f.target),changed);assert(!fs.existsSync(f.predecessor));
 }
});
test('unowned launch, lost lease, dirty state and epoch drift cannot report adoption success',async t=>{
 const f=fixture(t);await assert.rejects(f.adopt({...f.args,launch:{...f.launch}}));assert(!fs.existsSync(f.predecessor));
 f.abort.abort();await assert.rejects(f.adopt(f.args));assert.deepEqual(fs.readFileSync(f.target),f.originalBytes);
 const dirty=fixture(t,{cleanOverride(){throw Error('dirty');}});await assert.rejects(dirty.adopt(dirty.args));assert(!fs.existsSync(dirty.predecessor));
 const changed=fixture(t,{cleanOverride:(n,c)=>n===1?c:{...c,epoch:'4'}});await assert.rejects(changed.adopt(changed.args));
 assert.deepEqual(fs.readFileSync(changed.predecessor),changed.originalBytes);
});
test('unknown journal lock, conflicting archive and symlink cannot be overwritten',async t=>{
 const locked=fixture(t);fs.writeFileSync(locked.target+'.lock','unknown',{mode:0o600});await assert.rejects(locked.adopt(locked.args));
 assert.equal(fs.readFileSync(locked.target+'.lock','utf8'),'unknown');assert(!fs.existsSync(locked.predecessor));
 const conflict=fixture(t);fs.writeFileSync(conflict.predecessor,'other',{mode:0o600});await assert.rejects(conflict.adopt(conflict.args));assert.equal(fs.readFileSync(conflict.predecessor,'utf8'),'other');
 const linked=fixture(t);fs.symlinkSync(linked.target,linked.predecessor);await assert.rejects(linked.adopt(linked.args));assert(fs.lstatSync(linked.predecessor).isSymbolicLink());
});
test('failed publication keeps original; retry uses the exact durable archive',async t=>{
 let fail=true;const f=fixture(t,{fsOverrides:{renameSync(...args){if(fail)throw Error('owned-before-rename-failure');return fs.renameSync(...args);}}});
 await assert.rejects(f.adopt(f.args));assert.deepEqual(fs.readFileSync(f.target),f.originalBytes);assert.deepEqual(fs.readFileSync(f.predecessor),f.originalBytes);
 fail=false;await f.adopt(f.args);assert.equal(JSON.parse(fs.readFileSync(f.target)).version,2);
});
test('lost response after atomic publication retains both versions and retries without another write',async t=>{
 let renames=0;const f=fixture(t,{fsOverrides:{renameSync(...args){fs.renameSync(...args);renames++;throw Error('owned-after-rename-loss');}}});
 await assert.rejects(f.adopt(f.args));assert.deepEqual(fs.readFileSync(f.predecessor),f.originalBytes);assert.equal(JSON.parse(fs.readFileSync(f.target)).version,2);
 await f.adopt(f.args);assert.equal(renames,1);
});
test('a v2 target without its exact predecessor cannot claim a resumed adoption',async t=>{
 const f=fixture(t);fs.writeFileSync(f.target,encode({...f.saved,version:2}));await assert.rejects(f.adopt(f.args));assert(!fs.existsSync(f.predecessor));
});
test('adoption holds the legacy writer lock through final clean-state verification',async t=>{
 let entered,release;
 const inside=new Promise(resolve=>{entered=resolve;}),held=new Promise(resolve=>{release=resolve;});
 const f=fixture(t,{cleanOverride:async(n,clean)=>{if(n===2){entered();await held;}return clean;}});
 const adoption=f.adopt(f.args);
 await inside;
 const lock=f.target+'.lock',stat=fs.lstatSync(lock);
 assert.equal(stat.mode&0o777,0o600);
 assert.deepEqual(JSON.parse(fs.readFileSync(lock)),{pid:process.pid});
 let writerEntered=false;
 try{
   await assert.rejects(require('../scripts/install/ctf-authority-journal').withCtfAuthorityJournal(
     {directory:f.directory,binding:f.binding},async()=>{writerEntered=true;}),{code:'CTF_JOURNAL_BUSY'});
   assert.equal(writerEntered,false);
   assert.equal(fs.lstatSync(lock).ino,stat.ino);
 }finally{release();}
 await adoption;
 assert.equal(fs.existsSync(lock),false);
 assert.deepEqual(fs.readFileSync(f.predecessor),f.originalBytes);
 assert.deepEqual(JSON.parse(fs.readFileSync(f.target)),{...f.saved,version:2});
});
test('a real legacy writer excludes adoption and retains its lock until its own release',async t=>{
 const f=fixture(t);let entered,release;
 const inside=new Promise(resolve=>{entered=resolve;}),held=new Promise(resolve=>{release=resolve;});
 const writer=require('../scripts/install/ctf-authority-journal').withCtfAuthorityJournal(
   {directory:f.directory,binding:f.binding},async()=>{entered();await held;});
 await inside;
 const lock=f.target+'.lock',before=fs.lstatSync(lock);
 try{
   await assert.rejects(f.adopt(f.args));
   assert.equal(fs.lstatSync(lock).ino,before.ino);
   assert.deepEqual(fs.readFileSync(f.target),f.originalBytes);
   assert.equal(fs.existsSync(f.predecessor),false);
 }finally{release();}
 await writer;
 assert.equal(fs.existsSync(lock),false);
 await f.adopt(f.args);
});
test('replaced lock identity is retained and adoption cannot report success or delete another writer',async t=>{
 let f;
 f=fixture(t,{cleanOverride(n,clean){if(n===2){
   fs.renameSync(f.target+'.lock',f.target+'.owned-old-lock');
   fs.writeFileSync(f.target+'.lock',JSON.stringify({pid:process.pid})+'\n',{mode:0o600});
 }return clean;}});
 await assert.rejects(f.adopt(f.args),AggregateError);
 assert.equal(fs.existsSync(f.target+'.lock'),true);
 assert.notEqual(fs.lstatSync(f.target+'.lock').ino,fs.lstatSync(f.target+'.owned-old-lock').ino);
});
test('controlled Windows prepared archive or journal intent retries with the same operation identity',async()=>{
 for(const failSuffix of ['.adoption','.publication']){
   const directory='C:\\owned\\private',target=path.win32.join(directory,'ctf-authority.json');
   const binding={workspaceId:'a'.repeat(64),provisioningSha256:'b'.repeat(64),identityStoreId:randomUUID(),ctfStoreId:randomUUID()};
   const saved={version:1,binding,bootstrapId:randomUUID(),activationId:randomUUID(),phase:'complete',revision:4,
     checkpoint:{sourceRevision:'3',manifestSha256:'c'.repeat(64),authoritySha256:'d'.repeat(64)}};
   const originalBytes=encode(saved),files=new Map([[target,originalBytes]]),intents=new Map();let failed=false;
   const lock=target+'.lock';let lockIdentity,serial=0;
   const activation={activation_id:saved.activationId,bootstrap_operation_id:saved.bootstrapId,
     identity_store_id:binding.identityStoreId,ctf_store_id:binding.ctfStoreId,protocol_version:1,
     source_revision:'3',manifest_sha256:saved.checkpoint.manifestSha256,authority_sha256:saved.checkpoint.authoritySha256};
   const lease={assertHeld(){},signal:new AbortController().signal,async assertClean(){return{epoch:'3',installationId:'owned'};}};
   const launch={installation:{directory,assertCurrent(){}},assertCurrent(){}};
   const native={preparePrivatePublication(options){
     assert(files.has(lock),'native archive and journal preparation requires the held journal lock');
     const prior=intents.get(options.intentPath);if(prior){assert.equal(prior.operationId,options.operationId);
       assert.deepEqual(prior.originalBytes,options.originalBytes);assert.deepEqual(prior.resultBytes,options.resultBytes);}
     else intents.set(options.intentPath,{...options});
     if(!failed&&options.intentPath.endsWith(failSuffix)){failed=true;throw Error('controlled lost response after prepare');}
   },publishPrivatePublication(options){
     assert(files.has(lock),'native archive and journal publication requires the held journal lock');
     const intent=intents.get(options.intentPath);assert(intent);assert.equal(intent.operationId,options.operationId);
     const current=files.get(options.targetPath)||null;
     assert(current===null&&intent.originalBytes===null||Buffer.isBuffer(current)
       &&(current.equals(intent.originalBytes||Buffer.alloc(0))||current.equals(intent.resultBytes)));
     files.set(options.targetPath,Buffer.from(intent.resultBytes));
   }};
   const filename=require.resolve('../scripts/install/ctf-authority-clean-adoption'),local=createRequire(filename),loaded=new Module(filename,module);
   loaded.filename=filename;loaded.require=name=>{
     if(name==='node:fs')return{lstatSync(file){if(files.has(file))return{};throw Object.assign(Error('absent'),{code:'ENOENT'});}};
     if(name==='../../server/services/applicationMaintenanceExecutionAdmission')return{assertOwnedLaunch(l,s){assert.equal(l,launch);assert.equal(s,lease);}};
     if(name==='../../server/services/applicationMaintenanceInprocessAdmission')return{privateRead(file){assert(files.has(file));return Buffer.from(files.get(file));}};
     if(name==='../lib/windows-private-publication')return native;
     if(name==='../lib/windows-ctf-authority-journal-storage')return{
       createWindowsCtfAuthorityJournalStorage(options){
         return require('../scripts/lib/windows-ctf-authority-journal-storage').createWindowsCtfAuthorityJournalStorage({...options,
           fileSystem:{lstatSync(file){if(files.has(file))return{};throw Object.assign(Error('absent'),{code:'ENOENT'});}},
           privateState:{
             inspectPrivateDirectory(file){assert.equal(file,directory);return{path:file,size:null,identity:{volumeSerial:1,fileId:'1111111111111111'}};},
             createPrivateFile(file,bytes){assert.equal(file,lock);if(files.has(file))throw Error('busy');
               lockIdentity={volumeSerial:1,fileId:(++serial).toString(16).padStart(16,'0')};files.set(file,Buffer.from(bytes));
               return{path:file,size:bytes.length,identity:{...lockIdentity}};},
             readAndFlushPrivateFileSnapshot(file){assert.equal(file,lock);assert(files.has(file));
               return{path:file,size:files.get(file).length,identity:{...lockIdentity},bytes:Buffer.from(files.get(file))};},
             deleteMatchingPrivateFile(file,bytes,identity){assert.equal(file,lock);assert.deepEqual(identity,lockIdentity);
               assert.deepEqual(files.get(file),bytes);files.delete(file);return{path:file,size:bytes.length,identity:{...identity},deleted:true};},
           },publication:native});
       },
     };
     return local(name);
   };
   loaded._compile('const process={platform:"win32",pid:123};\n'+fs.readFileSync(filename,'utf8'),filename);
   const args={directory,originalBytes,binding,activation,launch,lease};
   await assert.rejects(loaded.exports.adoptLegacyCtfAuthorityJournal(args));assert.deepEqual(files.get(target),originalBytes);
   assert.equal(files.has(lock),false,'failed publication releases only its exact native lock');
   await loaded.exports.adoptLegacyCtfAuthorityJournal(args);
   assert.deepEqual(JSON.parse(files.get(target)),{...saved,version:2});assert.equal(intents.size,2);
   assert.equal(files.has(lock),false);
   const archive=path.win32.join(directory,`ctf-authority-v1-${createHash('sha256').update(originalBytes).digest('hex')}.json`);
   assert.deepEqual(files.get(archive),originalBytes);
 }
});
test('controlled prospective admission verifies legacy activation and drains both stores before real filesystem adoption',async t=>{
 for(const mismatch of [false,true]){
   const home=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'ctf-adoption-admission-'))),root=path.join(home,'app');
   t.after(()=>fs.rmSync(home,{recursive:true,force:true}));fs.mkdirSync(root);
   const sha=value=>createHash('sha256').update(value).digest('hex');
   const directory=path.join(home,'.owasp-ai-goat',sha(root).slice(0,12));fs.mkdirSync(directory,{recursive:true,mode:0o700});
   const sql='db/postgres/identity-migrations/0001.sql';fs.mkdirSync(path.dirname(path.join(root,sql)),{recursive:true});fs.writeFileSync(path.join(root,sql),'SELECT 1;');
   const plan=require('../db/postgres/provision-application').provisioningPlan(),env={PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
   for(const row of plan)for(const kind of ['runtime','migration'])env[row[kind+'Variable']]=`postgresql://${row[kind+'Role']}:fixture@127.0.0.1/${row.database}`;
   env.CTF_DELIVERY_DATABASE_URL='postgresql://dvaia_ctf_delivery:fixture@127.0.0.1/owasp_ai_goat_ctf';
   const admin={username:'owned-admin',email:'owned@example.test',password:'owned-synthetic-password'};
   const write=(name,value)=>fs.writeFileSync(path.join(directory,name),encode(value),{mode:0o600});
   write('administrator.json',admin);write('provisioning.json',{version:1,status:'complete',configuration:env,plan});write('ctf-delivery.json',{version:1,status:'complete'});
   fs.writeFileSync(path.join(root,'.env'),Object.entries(env).map(([k,v])=>`${k}=${v}`).join('\n'),{mode:0o600});
   const binding={workspaceId:sha(root),provisioningSha256:sha(fs.readFileSync(path.join(directory,'provisioning.json'))),
     identityStoreId:'11111111-1111-4111-8111-111111111111',ctfStoreId:'22222222-2222-4222-8222-222222222222'};
   const saved={version:1,binding,bootstrapId:randomUUID(),activationId:randomUUID(),phase:'complete',revision:4,
     checkpoint:{sourceRevision:'3',manifestSha256:'c'.repeat(64),authoritySha256:'d'.repeat(64)}};
   write('ctf-authority.json',saved);const originalBytes=encode(saved),events=[];
   const activation={activation_id:saved.activationId,bootstrap_operation_id:saved.bootstrapId,
     identity_store_id:binding.identityStoreId,ctf_store_id:binding.ctfStoreId,protocol_version:1,
     source_revision:mismatch?'4':'3',manifest_sha256:saved.checkpoint.manifestSha256,authority_sha256:saved.checkpoint.authoritySha256};
   const identity={},lease={assertHeld(){},signal:new AbortController().signal,async assertExecutionReady(){},
     async assertClean(){return{epoch:'3',installationId:randomUUIDFixed};}};
   const randomUUIDFixed=randomUUID();
   const launch={installation:{installationRoot:root,homeDirectory:home,directory,assertCurrent(){}},assertCurrent(){}};
   const issuer={async admitOwnedLaunch(){return launch;},assertOwnedLaunch(l,s){assert.equal(l,launch);assert.equal(s,lease);}};
   const helperFile=require.resolve('../scripts/install/ctf-authority-clean-adoption'),helperRequire=createRequire(helperFile),helper=new Module(helperFile,module);
   helper.filename=helperFile;helper.require=name=>name==='../../server/services/applicationMaintenanceExecutionAdmission'?issuer:helperRequire(name);
   helper._compile(fs.readFileSync(helperFile,'utf8'),helperFile);
   const manifest={version:1,profile:'canonical16-ctf-inprocess-v1',files:{[sql]:sha('SELECT 1;')},recoveryFiles:[sql]};
   const stores=plan.map((row,i)=>({storeKey:row.schema,clusterIdentifier:'123',databaseOid:i+1,databaseName:row.database,
     runtimeRole:row.runtimeRole,migrationRole:row.migrationRole,deliveryRole:row.schema==='ctf'?'dvaia_ctf_delivery':null,endpointPolicySha256:'a'.repeat(64)}));
   let closed=0;
   const overrides={
     './applicationMaintenanceExecutionAdmission':issuer,
     './applicationMaintenanceLease':{inprocessLeaseIdentity(l){assert.equal(l,lease);return identity;}},
     '../../scripts/lib/application-maintenance-plan-configuration':{loadMaintenancePlanConfiguration:()=>({environment:env,deliveryManifestPath:path.join(directory,'ctf-delivery.json')})},
     '../database/postgres/applicationMaintenanceStoreInspection':{createApplicationMaintenanceStoreInspection:()=>({async inspect(){return{stores,recordedBackendsAbsent:true};}})},
     '../database/postgres':{getPoolBudgetSnapshot:()=>({reserved:1}),createPool:()=>({async query(query){return{rows:query.includes('identity.users')?[{...admin,role:'super_admin',admin_level:2,is_active:1}]:[{store_id:query.includes('identity.')?binding.identityStoreId:binding.ctfStoreId,activation_id:saved.activationId}]};},async end(){closed++;events.push('drain');}})},
     '../database/postgres/ctfDeliveryActivation':{createCtfDeliveryActivation:()=>({async loadCurrent(){events.push('activation');return activation;}})},
     'bcryptjs':{compare:async(a,b)=>a===b},
     '../../scripts/install/ctf-authority-clean-adoption':{async adoptLegacyCtfAuthorityJournal(options){events.push('adopt');assert.equal(closed,2);return helper.exports.adoptLegacyCtfAuthorityJournal(options);}},
     '../../scripts/lib/setup-local-process-identity':{isSupportedLocalAncestorBinding:require('../scripts/lib/setup-local-process-identity').isSupportedLocalAncestorBinding,
       captureLocalAncestorBinding:o=>({version:2,ancestry:'complete-supported-chain',ancestors:[{pid:process.pid}],workspaceSha256:sha(root),hostSha256:'b'.repeat(64),...o})},
   };
   const file=require.resolve('../server/services/applicationMaintenanceInprocessAdmission'),local=createRequire(file),loaded=new Module(file,module);
   loaded.filename=file;loaded.require=name=>name.startsWith('./applicationMaintenanceInprocessSources-v')?manifest:Object.hasOwn(overrides,name)?overrides[name]:local(name);
   // The historical fixture supplies only a fake source root, not copied source.
   loaded._compile('const __fixtureDirectory='+JSON.stringify(path.join(root,'server/services'))+';\n'+fs.readFileSync(file,'utf8').replace(/__dirname/g,'__fixtureDirectory'),file);
   const prior=Object.fromEntries(Object.keys(env).map(key=>[key,process.env[key]]));Object.assign(process.env,env);
   try{
     const work=loaded.exports.prepareProspectiveInprocessAdmission({lease,root,homeDirectory:home,installationRoot:root});
     if(mismatch){await assert.rejects(work);assert.deepEqual(fs.readFileSync(path.join(directory,'ctf-authority.json')),originalBytes);}
     else{const token=await work,prepared=loaded.exports.consumePrepared(token,identity);
       assert.equal(prepared.bootstrapId,saved.bootstrapId);assert.equal(prepared.activationId,saved.activationId);
       assert.deepEqual(JSON.parse(fs.readFileSync(path.join(directory,'ctf-authority.json'))),{...saved,version:2});
       assert.deepEqual(fs.readFileSync(path.join(directory,`ctf-authority-v1-${sha(originalBytes)}.json`)),originalBytes);}
     assert.deepEqual(events,['activation','drain','drain','adopt']);
   }finally{for(const [key,value]of Object.entries(prior))if(value===undefined)delete process.env[key];else process.env[key]=value;}
 }
});
