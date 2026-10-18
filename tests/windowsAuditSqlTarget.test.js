'use strict';
// Controlled native-byte and branded-session harness; no Docker, DB, VM or OS helper.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),{createRequire}=require('node:module'),{createHash}=require('node:crypto');
const root=path.resolve(__dirname,'..'),id='abcdef123456';
function load(relative,overrides={},platform='win32'){
 const filename=path.join(root,relative),module={exports:{}},real=createRequire(filename);
 vm.runInThisContext(`(function(require,module,exports,__filename,__dirname,process){${fs.readFileSync(filename,'utf8')}\n})`,{filename})(name=>Object.hasOwn(overrides,name)?overrides[name]:real(name),module,module.exports,filename,path.dirname(filename),{platform,env:{},getuid(){assert.fail('POSIX UID must not admit Windows bytes');}});return module.exports;
}
function harness(){
 const events=[],files=new Map(),calls=[],descriptors=new WeakMap();let container=false,volume=false,denial=false,failWrite=false,forwardFailure=false,foreign=false,running=true,startForeign=false,imageMissing=false;
 const binding={workspaceId:id,daemonId:'owned-daemon',host:'owned-hyperv:controlled',bindingSha256:'c'.repeat(64)};
 const ownLabChild=()=>{},lab={async executeDocker(args){calls.push(args);assert(!args.some(arg=>/^[A-Za-z]:\\/.test(arg)));const p=target.plan(options);
  if(args[0]==='pull'){assert.deepEqual(args,['pull','postgres:18']);imageMissing=false;return'';}
  if(args[0]==='image'&&args[1]==='ls')return imageMissing?'':'sha256:'+'e'.repeat(64);
  if(args[0]==='image'&&args[1]==='inspect')return JSON.stringify([{Id:'sha256:'+'e'.repeat(64)}]);
  if(args[0]==='ps')return container?JSON.stringify({ID:'d'.repeat(64)}):'';
  if(args[0]==='volume'){if(args[1]==='create'){volume=true;return'';}if(!volume)throw Object.assign(Error('missing'),{code:1});return JSON.stringify([{Labels:{'dvaia.workspace':id,'dvaia.purpose':'owned-audit-sql'}}]);}
  if(args[0]==='run'){container=true;return'd'.repeat(64);}
  if(args[0]==='start'){assert.equal(args[1],'d'.repeat(64));running=true;if(startForeign)foreign=true;return'';}
  if(args[0]==='inspect')return JSON.stringify([{Id:'d'.repeat(64),Image:'sha256:'+'e'.repeat(64),Config:{Labels:{'dvaia.workspace':foreign?'foreign':id,'dvaia.purpose':'owned-audit-sql'}},State:{Running:running},Mounts:[{Type:'volume',Name:p.volume,Destination:'/var/lib/postgresql'}],HostConfig:{PortBindings:{'5432/tcp':[{HostIp:'127.0.0.1'}]}},NetworkSettings:{Ports:{'5432/tcp':[{HostIp:'127.0.0.1',HostPort:'55432'}]}}}]);
  throw Error('unexpected '+args.join(' '));
 },async stagePrivateEnvironment({bytes,sha256}){assert.equal(sha256,createHash('sha256').update(bytes).digest('hex'));events.push(['stage',Buffer.from(bytes)]);return'/var/lib/dvaia/owned/private/env-'+sha256;},async openLoopbackForwards(ports,{ownChild}){assert.equal(ownChild,ownLabChild);events.push(['forward',ports]);if(forwardFailure)throw Error('forward denied');}};descriptors.set(lab,binding);
 const privateState={inspectPrivateDirectory(){events.push('parent');},readPrivateFile(file){if(denial)throw Object.assign(Error('denied'),{code:'ENOENT'});return Buffer.from(files.get(file));}};
 const fileSystem={lstatSync(file){if(!files.has(file))throw Object.assign(Error('missing'),{code:'ENOENT'});return{};}};
 const journal={createJournal({filePath,bytes}){assert(!files.has(filePath),'create-only');if(failWrite)throw Error('publication denied');events.push(['create',filePath]);files.set(filePath,Buffer.from(bytes));},updateJournal({filePath,originalBytes,resultBytes}){assert(files.get(filePath).equals(originalBytes),'exact prior bytes');if(failWrite)throw Error('publication denied');events.push(['update',filePath]);files.set(filePath,Buffer.from(resultBytes));}};
 const storage=require('../scripts/lib/audit-sql-private-state').createAuditSqlPrivateState({filesystemPlatform:'win32',fileSystem,privateState,journal});
 const target=load('scripts/install/audit-sql-target.js',{'node:path':path.win32,'../../server/services/mcp/ownedManagedConfiguration':{workspaceId:()=>id},'../lib/windows-owned-lab':{describeOwnedLab(session){if(!descriptors.has(session))throw Error('unbranded');return descriptors.get(session);}},'../lib/audit-sql-private-state':storage});
 const options={root:'C:\\Source Folder\\app',home:'C:\\Users\\Synthetic',platform:'win32',ownedLabSession:lab,ownLabChild,createPool(settings){assert(events.some(e=>Array.isArray(e)&&e[0]==='forward'));events.push(['pool',settings]);return{async query(){return{rows:[]};},async end(){events.push('end');}};},initializeControl:async()=>events.push('initialize'),assertReadiness:async()=>events.push('ready')};
 return{target,options,storage,files,events,calls,binding,lab,privateState,fileSystem,journal,denyRead(){denial=true;},denyWrite(){failWrite=true;},denyForward(){forwardFailure=true;},foreign(){foreign=true;},missingImage(){imageMissing=true;},stopContainer(){running=false;},removeContainer(){container=false;},foreignAfterStart(){startForeign=true;},config(){return JSON.parse(files.get(target.plan(options).file));}};
}
test('native audit SQL stages credentials, forwards before readiness, and reuses exact retained state',async()=>{
 const h=harness();const result=await h.target.provision(h.options),saved=h.config();assert.equal(result.created,true);assert.equal(saved.enabled,false);assert.equal(saved.activationPending,true);assert.equal(saved.provisioned,true);assert.equal(saved.databasePort,55432);
 assert(h.events.find(e=>Array.isArray(e)&&e[0]==='stage')[1].equals(Buffer.from(`POSTGRES_USER=audit_service_admin\nPOSTGRES_PASSWORD=${saved.password}\nPOSTGRES_DB=${saved.database}\n`)));
 const run=h.calls.find(a=>a[0]==='run');assert.match(run[run.indexOf('--env-file')+1],/^\/var\/lib\/dvaia\/owned\/private\/env-/);assert(!run.join(' ').includes(saved.password));assert.deepEqual(h.events.find(e=>Array.isArray(e)&&e[0]==='forward')[1],[{local:55432,guest:55432}]);
 const before=Buffer.from(h.files.get(result.file)),writes=h.events.filter(e=>Array.isArray(e)&&['create','update'].includes(e[0])).length;
 assert.equal((await h.target.provision(h.options)).created,false);assert(h.files.get(result.file).equals(before));assert.equal(h.calls.filter(a=>a[0]==='run').length,1);assert.equal(h.events.filter(e=>Array.isArray(e)&&['create','update'].includes(e[0])).length,writes);
});
test('unbranded/mismatched session, absent owner and ambient endpoint deny before publication',async()=>{
 for(const change of [{ownedLabSession:{}},{ownLabChild:undefined},{commandEnv:{DOCKER_HOST:'ssh://foreign'}}]){const h=harness();await assert.rejects(h.target.provision({...h.options,...change}));assert.equal(h.calls.length,0);assert.equal(h.files.size,0);}
 const h=harness();h.binding.workspaceId='ffffffffffff';await assert.rejects(h.target.provision(h.options));assert.equal(h.files.size,0);
});
test('existing denied native read never creates, resets credentials or reaches Docker',async()=>{
 const h=harness();await h.target.provision(h.options);const file=h.target.plan(h.options).file,before=Buffer.from(h.files.get(file)),calls=h.calls.length;h.denyRead();await assert.rejects(h.target.provision(h.options),/Private owned audit/);assert.equal(h.calls.length,calls);assert(h.files.get(file).equals(before));
});
test('fresh publication failure stops before Docker and forwarding failure stops before Pool',async()=>{
 const h=harness();h.denyWrite();await assert.rejects(h.target.provision(h.options),/Private owned audit/);assert.equal(h.calls.length,0);assert.equal(h.files.size,0);
 const g=harness();g.denyForward();await assert.rejects(g.target.provision(g.options),/forward denied/);assert(!g.events.some(e=>Array.isArray(e)&&e[0]==='pool'));assert.equal(g.config().provisioned,undefined);
});
test('retained foreign container or session binding denies without publishing success',async()=>{
 const h=harness();await h.target.provision(h.options);const file=h.target.plan(h.options).file,before=Buffer.from(h.files.get(file));h.foreign();await assert.rejects(h.target.provision(h.options),/OWNERSHIP_CONFLICT/);assert(h.files.get(file).equals(before));
 const g=harness();await g.target.provision(g.options);const calls=g.calls.length;g.binding.bindingSha256='f'.repeat(64);await assert.rejects(g.target.provision(g.options),/OWNERSHIP_CONFLICT/);assert.equal(g.calls.length,calls);
});
test('native helper admits only genuine missing leaves and exact acknowledged replacements',()=>{
 const h=harness(),file=h.target.plan(h.options).file;assert.equal(h.storage.read(file,{allowMissing:true}),null);h.storage.write(file,Buffer.from('original'),null);
 assert.throws(()=>h.storage.write(file,Buffer.from('new'),Buffer.from('wrong')),/Private owned audit/);assert.equal(h.storage.read(file).toString(),'original');h.denyRead();assert.throws(()=>h.storage.read(file,{allowMissing:true}),/Private owned audit/);
 for(const error of [Object.assign(Error('permission'),{code:'EACCES'}),Error('bad metadata')]){const helper=require('../scripts/lib/audit-sql-private-state').createAuditSqlPrivateState({filesystemPlatform:'win32',fileSystem:{lstatSync(){throw error;}},privateState:h.privateState,journal:h.journal});assert.throws(()=>helper.read(file,{allowMissing:true}),/Private owned audit/);}
});
test('setup dispatch uses the verified retained Docker authority on POSIX',async()=>{
 const target=require('../scripts/install/audit-sql-target');let prepared=false,activated=false;
 const id=require('../server/services/mcp/ownedManagedConfiguration').workspaceId(root);
 const result=await target.provisionForSetup({root,platform:'linux',environment:{},resolveAuthority:async()=>({persisted:true,authority:{version:1,workspaceId:id,platform:'linux',host:'unix:///fixture/owned.sock'}}),provisionTarget:async options=>{prepared=true;assert.equal(options.dockerHost,'unix:///fixture/owned.sock');return{created:false};},activate:async()=>{activated=true;return{preserved:true};}});assert(prepared&&activated);assert.equal(result.preserved,true);
});
test('Windows activation requires prerequisites and exact unchanged private bytes',async()=>{
 const h=harness();await h.target.provision(h.options);const file=h.target.plan(h.options).file;
 const activate=load('scripts/install/audit-sql-activate.js',{'node:path':path.win32,'../../server/services/mcp/ownedManagedConfiguration':{workspaceId:()=>id},'../lib/audit-sql-private-state':h.storage}).activateForSetup;
 const events=[],opts={root:h.options.root,homeDirectory:h.options.home,environment:{},checkPrerequisites:async()=>events.push('prerequisites'),start:async()=>({async close(){events.push('close');}}),createClient:()=>({async readiness(){events.push('ready');return{ready:true,capability:'owned-audit-postgres.v1'};}})};
 const before=Buffer.from(h.files.get(file));await assert.rejects(activate({...opts,checkPrerequisites:async()=>{throw Error('unqualified');}}),/unqualified/);assert(h.files.get(file).equals(before));
 await activate(opts);assert.deepEqual(events,['prerequisites','ready','close']);assert.equal(h.config().enabled,true);assert.equal(h.config().activationPending,false);
 let checked=false;await activate({...opts,checkPrerequisites:async()=>{checked=true;}});assert.equal(checked,false);
});
test('Windows activation refuses concurrent change and failed acknowledged publication',async()=>{
 for(const change of ['concurrent','failure']){const h=harness();await h.target.provision(h.options);const file=h.target.plan(h.options).file;const activate=load('scripts/install/audit-sql-activate.js',{'node:path':path.win32,'../../server/services/mcp/ownedManagedConfiguration':{workspaceId:()=>id},'../lib/audit-sql-private-state':h.storage}).activateForSetup;
 await assert.rejects(activate({root:h.options.root,homeDirectory:h.options.home,checkPrerequisites:async()=>{},start:async()=>({async close(){if(change==='concurrent')h.files.set(file,Buffer.from(JSON.stringify({...h.config(),port:8094})));else h.denyWrite();}}),createClient:()=>({async readiness(){return{ready:true,capability:'owned-audit-postgres.v1'};}})}));assert.equal(h.config().enabled,false);assert.equal(h.config().activationPending,true);}
});
test('Windows production reader safely omits missing state and preserves disabled cleanup authority',async()=>{
 const h=harness();let starts=0,closed=0;const production=load('server/services/secureshopOwnedAuditProduction.js',{'node:path':path.win32,'./mcp/ownedManagedConfiguration':{workspaceId:()=>id},'../../scripts/lib/audit-sql-private-state':h.storage});
 const options={root:h.options.root,home:h.options.home,start:async(_file,opts)=>{starts++;assert.equal(opts.cleanupOnly,true);return{async close(){closed++;}};},createClient:()=>({async readiness(){return{ready:true};}})};
 const missing=production.createOwnedAuditProduction(options);assert.equal(await missing.get(),null);assert.equal(starts,0);await missing.close();await h.target.provision(h.options);
 const owned=production.createOwnedAuditProduction(options);assert.equal((await owned.get()).admissions,false);await owned.close();assert.equal(closed,1);h.denyRead();await assert.rejects(production.createOwnedAuditProduction(options).get());assert.equal(starts,1);
});
test('retained Windows startup only inspects and forwards, with no bootstrap or state mutation',async()=>{
 const h=harness();await h.target.provision(h.options);const file=h.target.plan(h.options).file,before=Buffer.from(h.files.get(file)),eventCount=h.events.length,callCount=h.calls.length;
 const result=await h.target.startExisting({...h.options,createPool:()=>assert.fail('startup cannot bootstrap database'),initializeControl:()=>assert.fail('startup cannot initialize'),assertReadiness:()=>assert.fail('startup database readiness belongs to runtime')});
 assert.equal(result.databasePort,55432);assert.equal(result.created,false);assert(h.files.get(file).equals(before));assert(!h.events.slice(eventCount).some(e=>Array.isArray(e)&&['create','update','stage','pool'].includes(e[0])));assert(h.calls.slice(callCount).every(a=>['ps','inspect'].includes(a[0])));
});
test('retained startup denies absent/unprovisioned state without creation or Docker',async()=>{
 const h=harness();await assert.rejects(h.target.startExisting(h.options),/RETAINED_CONFIGURATION/);assert.equal(h.files.size,0);assert.equal(h.calls.length,0);
 await h.target.provision(h.options);const file=h.target.plan(h.options).file;h.files.set(file,Buffer.from(JSON.stringify({...h.config(),provisioned:false})));const calls=h.calls.length;await assert.rejects(h.target.startExisting(h.options),/RETAINED_CONFIGURATION/);assert.equal(h.calls.length,calls);
});
test('native service main reads admitted bytes without POSIX UID and preserves readiness/cleanup',async()=>{
 const h=harness();await h.target.provision(h.options);const file=h.target.plan(h.options).file;h.files.set(file,Buffer.from(JSON.stringify({...h.config(),enabled:true})));const events=[];
 const main=load('sidecars/audit-sql-target/main.js',{'../../scripts/lib/audit-sql-private-state':h.storage,pg:{Pool:class{constructor(settings){assert.equal(settings.port,55432);}async end(){events.push('pool-end');}}},'./service':{createService:()=>({async close(){events.push('service-close');}})},'./journal':{createJournal:()=>({})},'./readiness':{assertReadiness:async()=>events.push('readiness')},'./http':{createPrivateAuditServer:()=>({async listen(port){assert.equal(port,h.config().port);events.push('listen');},async close(){events.push('http-close');}})},'../../server/services/secureshopOwnedAuditSearchBackend':{createOwnedAuditBackend:()=>({})}});
 const app=await main.start(file);assert.deepEqual(events,['readiness','listen']);await app.close();assert(events.includes('http-close')&&events.includes('pool-end'));h.denyRead();await assert.rejects(main.start(file));
});
test('retained startup resumes only verified ID and reinspection rejects changed ownership',async()=>{
 const h=harness();await h.target.provision(h.options);h.stopContainer();const before=h.calls.length;await h.target.startExisting(h.options);assert.deepEqual(h.calls.slice(before).find(a=>a[0]==='start'),['start','d'.repeat(64)]);assert.equal(h.calls.slice(before).filter(a=>a[0]==='inspect').length,2);
 const g=harness();await g.target.provision(g.options);g.stopContainer();g.foreignAfterStart();const forwards=g.events.filter(e=>Array.isArray(e)&&e[0]==='forward').length;await assert.rejects(g.target.startExisting(g.options),/OWNERSHIP_CONFLICT/);assert.equal(g.events.filter(e=>Array.isArray(e)&&e[0]==='forward').length,forwards);
});
test('missing retained container never authorizes new volume, env staging or container creation',async()=>{
 const h=harness();await h.target.provision(h.options);h.removeContainer();const before=h.calls.length,eventCount=h.events.length;await assert.rejects(h.target.startExisting(h.options),/RETAINED_CONTAINER/);assert.deepEqual(h.calls.slice(before).map(a=>a[0]),['ps']);assert(!h.events.slice(eventCount).some(e=>Array.isArray(e)&&['create','update','stage','forward','pool'].includes(e[0])));
});
test('fresh missing postgres18 pulls exact tag then binds immutable image before managed run',async()=>{
 const h=harness();h.missingImage();await h.target.provision(h.options);assert.deepEqual(h.calls.slice(0,3),[['image','ls','--quiet','postgres:18'],['pull','postgres:18'],['image','inspect','postgres:18']]);const saved=h.config(),run=h.calls.find(a=>a[0]==='run');assert.equal(run.at(-1),saved.image);assert.match(saved.image,/^sha256:/);
 const before=h.calls.length;h.missingImage();await h.target.startExisting(h.options);assert(!h.calls.slice(before).some(a=>['image','pull'].includes(a[0])));assert.equal(h.config().image,saved.image);
});
