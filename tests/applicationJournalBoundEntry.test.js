'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
const {PROFILE,selectProfile,runJournalBoundMaintenance}=require('../scripts/application-journal-bound-maintenance');

function prospectiveSupervisor({stop}={}){
 const child=new EventEmitter(),processMock=new EventEmitter(),installation={installationRoot:'/installation',bindingSha256:'binding',assertCurrent(){}};
 Object.assign(child,{pid:50,connected:true,disconnect(){this.connected=false;}});
 Object.assign(processMock,{pid:40,platform:'darwin',execPath:'/pinned/node',execArgv:[],env:{}});
 let stopped=0,granted=0;
 const req=name=>{
  if(name==='node:path')return path;
  if(name==='node:child_process')return{spawn(node,args,options){assert.equal(node,'/pinned/node');assert.equal(args[1],'--owned-prospective-original');assert.equal(options.detached,true);return child;}};
  if(name==='./start-application')return{stopOwnedChild:async value=>{stopped++;return stop?stop(value):undefined;}};
  if(name==='./lib/application-maintenance-installation')return{resolveMaintenanceInstallation:()=>installation};
  throw Error('Unexpected import '+name);
 };req.main={};const module={exports:{}};
 vm.runInNewContext(fs.readFileSync(require.resolve('../scripts/application-journal-bound-maintenance'),'utf8'),{require:req,module,__dirname:'/owned/scripts',__filename:'/owned/scripts/application-journal-bound-maintenance.js',process:processMock,setTimeout,clearTimeout,Object,Reflect});
 child.send=(message,callback)=>{assert.equal(message.type,'prospective-original-grant');assert.equal(message.installationBinding,'binding');granted++;callback?.();};
 const start=()=>module.exports.runProspectiveJournalBoundMaintenance({});
 const ready=()=>child.emit('message',{type:'prospective-original-ready',nonce:'11111111-1111-4111-8111-111111111111',childPid:50,parentPid:40,installationBinding:'binding'});
 return{child,processMock,start,ready,stopped:()=>stopped,granted:()=>granted};
}

test('fixed prospective profile is the only supported selection',()=>{
 assert.equal(selectProfile([]),PROFILE);assert.equal(selectProfile(['--maintenance-profile='+PROFILE]),PROFILE);assert.equal(selectProfile(['--init-db','--maintenance-profile='+PROFILE],{startup:true}),PROFILE);
 for(const args of [['--maintenance-profile=x'],['--maintenance-profile'],['--maintenance-profile=ordinary'],['--maintenance-profile='+PROFILE,'--maintenance-profile='+PROFILE]])assert.throws(()=>selectProfile(args));
 assert.throws(()=>selectProfile(['--maintenance-profile='+PROFILE],{startup:true}));
});
test('successful IPC is not success before physical exit and owned group cleanup',async()=>{
 let release,entered;const held=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{entered=resolve;});
 const f=prospectiveSupervisor({stop:async({child})=>{assert.equal(child,f.child);entered();await held;}});let done=false;const work=f.start().then(()=>{done=true;});f.ready();
 f.child.emit('message',{type:'journal-bound-complete',completed:true});await new Promise(resolve=>setImmediate(resolve));assert.equal(done,false);assert.equal(f.stopped(),0);
 f.child.emit('exit',0,null);await started;assert.equal(done,false);release();await work;assert.equal(done,true);assert.equal(f.stopped(),1);assert.equal(f.granted(),1);
});
test('failure and missing completion clean owned process without fallback',async()=>{
 for(const completed of [false,true]){const f=prospectiveSupervisor(),work=f.start();f.ready();if(completed)f.child.emit('message',{type:'journal-bound-complete',completed:true});f.child.emit('exit',completed?1:0,null);await assert.rejects(work,{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});assert.equal(f.stopped(),1);}
});
test('importing child module does not load parent supervisor or construct runtime resources',()=>{
 const seen=[],source=fs.readFileSync(require.resolve('../scripts/application-journal-bound-maintenance'),'utf8');
 const req=name=>{seen.push(name);if(name==='node:path')return require(name);throw Error('Unexpected import '+name);};req.main={};
 vm.runInNewContext(source,{require:req,module:{exports:{}},__dirname:'/owned/scripts'});assert.deepEqual(seen,['node:path']);
});
test('entry source selects the fixed profile before configuration and dispatches prospective maintenance',()=>{
 const source=fs.readFileSync(require.resolve('../db/postgres/initialize-application'),'utf8');
 assert.ok(source.indexOf('const profile=entry.selectProfile(args)')<source.indexOf("require('dotenv').config({ quiet: true })"));
 assert.match(source,/await entry\.runProspectiveJournalBoundMaintenance\(/);
 assert.doesNotMatch(source.slice(0,source.indexOf('if (require.main === module)')),/runProspectiveJournalBoundMaintenance/);
});
test('SIGINT and SIGTERM during post-exit cleanup cannot admit application startup',async()=>{
 for(const signal of ['SIGINT','SIGTERM']){let release,entered;const held=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{entered=resolve;});const f=prospectiveSupervisor({stop:async()=>{entered();await held;}}),before=f.processMock.listenerCount(signal),work=f.start();f.ready();f.child.emit('message',{type:'journal-bound-complete',completed:true});f.child.emit('exit',0,null);await started;f.processMock.emit(signal);release();await assert.rejects(work,{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});assert.equal(f.processMock.listenerCount(signal),before);assert.equal(f.stopped(),1);}
});
test('failed ownership cleanup is sanitized and cancellation rejects without child exit',async()=>{
 for(const afterExit of [true,false]){const f=prospectiveSupervisor({stop:async()=>{throw Error('private cleanup detail');}}),work=f.start();f.ready();if(afterExit){f.child.emit('message',{type:'journal-bound-complete',completed:true});f.child.emit('exit',0,null);}else f.processMock.emit('SIGTERM');await assert.rejects(work,error=>error.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&!error.message.includes('private cleanup detail'));assert.equal(f.child.connected,false);assert.equal(f.stopped(),1);}
});
test('public entry rejects injected lifecycle seams before constructing a child',async()=>{
 let invoked=false;for(const key of ['spawn','stop','environment'])await assert.rejects(runJournalBoundMaintenance({[key]:()=>{invoked=true;}}),{code:'APPLICATION_INITIALIZATION_REQUIRES_EXIT'});assert.equal(invoked,false);
});
test('closed child diagnostic is retained only after owned cleanup and cannot admit success',async()=>{
 let release,entered;const held=new Promise(resolve=>{release=resolve;}),started=new Promise(resolve=>{entered=resolve;});const f=prospectiveSupervisor({stop:async()=>{entered();await held;}});let settled=false;const work=f.start().catch(error=>{settled=true;return error;});f.ready();f.child.emit('message',{type:'journal-bound-failed',code:'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE'});f.child.emit('message',{type:'journal-bound-complete',completed:true});f.child.emit('exit',0,null);await started;assert.equal(settled,false);release();const error=await work;assert.equal(error.code,'APPLICATION_INITIALIZATION_REQUIRES_EXIT');assert.equal(error.diagnosticCode,'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE');assert.equal(f.stopped(),1);
});
test('malformed or arbitrary child diagnostic cannot become success or leak payload',async()=>{
 for(const message of [{type:'journal-bound-failed',code:'SECRET_TOKEN'},{type:'journal-bound-failed',code:'APPLICATION_MAINTENANCE_EXECUTION_UNAVAILABLE',message:'postgres://SECRET'},{type:'journal-bound-failed'}]){const f=prospectiveSupervisor(),work=f.start();f.ready();f.child.emit('message',message);f.child.emit('message',{type:'journal-bound-complete',completed:true});f.child.emit('exit',0,null);await assert.rejects(work,error=>error.code==='APPLICATION_INITIALIZATION_REQUIRES_EXIT'&&error.diagnosticCode===undefined&&!JSON.stringify(error).includes('SECRET'));assert.equal(f.stopped(),1);}
});
test('diagnostic producer selects only bounded allowlisted codes and ignores sensitive error text',()=>{
 const {sanitizedFailureCode}=require('../scripts/application-journal-bound-maintenance');assert.equal(sanitizedFailureCode(Object.assign(Error('postgres://SECRET SQL SELECT private'),{code:'MAINTENANCE_INSPECTION_STORE_MISMATCH'})),'MAINTENANCE_INSPECTION_STORE_MISMATCH');assert.equal(sanitizedFailureCode({code:'SECRET_TOKEN',message:'APPLICATION_MAINTENANCE_DIRTY',stack:'secret'}),'APPLICATION_MAINTENANCE_UNAVAILABLE');assert.equal(sanitizedFailureCode(new AggregateError([Object.assign(Error('SECRET'),{code:'APPLICATION_MAINTENANCE_UPGRADE_UNCERTAIN'})],'SECRET')),'APPLICATION_MAINTENANCE_UPGRADE_UNCERTAIN');const cyclic={};cyclic.errors=[cyclic];assert.equal(sanitizedFailureCode(cyclic),'APPLICATION_MAINTENANCE_UNAVAILABLE');assert.equal(sanitizedFailureCode({get code(){throw Error('SECRET');}}),'APPLICATION_MAINTENANCE_UNAVAILABLE');
});
test('actual child rejection sends only closed sanitized diagnostic and exits unsuccessfully',async()=>{
 const source=fs.readFileSync(require.resolve('../scripts/application-journal-bound-maintenance'),'utf8'),p=new EventEmitter(),messages=[],exits=[];Object.assign(p,{argv:['node','/owned/scripts/application-journal-bound-maintenance.js','--owned-prospective-original','/installation'],send(message,callback){messages.push(message);callback?.();},exit:code=>exits.push(code)});const module={exports:{}};
 const req=name=>{if(name==='node:path')return path;if(name==='./lib/application-maintenance-installation')return{resolveMaintenanceInstallation(){throw Object.assign(Error('SECRET credentials and SQL'),{code:'APPLICATION_MAINTENANCE_INSTALLATION_INVALID'});}};throw Error('Unexpected child resource');};req.main=module;
 vm.runInNewContext(source,{require:req,module,__dirname:'/owned/scripts',__filename:'/owned/scripts/application-journal-bound-maintenance.js',process:p,setTimeout,clearTimeout,Object,Reflect});await new Promise(resolve=>setImmediate(resolve));assert.deepEqual(JSON.parse(JSON.stringify(messages)),[{type:'journal-bound-failed',code:'APPLICATION_MAINTENANCE_INSTALLATION_INVALID'}]);assert.deepEqual(exits,[1]);assert(!JSON.stringify(messages).includes('SECRET'));
});
