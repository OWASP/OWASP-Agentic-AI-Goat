'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path'),{createRequire}=require('node:module'),{EventEmitter}=require('node:events');
function issuer({ledger=true,channel=true,wrongParent=false,wrongInstallation=false,abort=false,timeout=false,wrongAncestry=false,upgradeFailure=false,readyDrift=false}={}){
 const entry='/owned/scripts/application-journal-bound-maintenance.js',p=new EventEmitter();Object.assign(p,{pid:50,ppid:40,argv:['node',entry,'--owned-prospective-original','/installation'],connected:channel,execArgv:[],env:{}});
 const events=[],clean={epoch:'2',installationId:'11111111-1111-4111-8111-111111111111'},controller=new AbortController(),lease={signal:controller.signal,assertHeld(){if(controller.signal.aborted)throw Error('lost');},async assertClean(){events.push('clean');if(!ledger)throw Error('invalid known ledger');return{...clean};},async upgradeExecutionSchema(expected){events.push('upgrade');assert.deepEqual(expected,clean);if(upgradeFailure)throw Error('unknown upgrade');return{...clean};},async assertExecutionReady(){events.push('ready');return{...clean,epoch:readyDrift?'3':clean.epoch};}};
 let observations=0,requests=0;const record={ancestors:[{pid:50},{pid:wrongAncestry?99:40}]};
 p.send=(m,cb)=>{requests++;events.push('request');cb?.();if(timeout)return;queueMicrotask(()=>{if(abort)controller.abort();else p.emit('message',{type:'prospective-original-grant',nonce:m.nonce,childPid:50,parentPid:wrongParent?41:40,installationBinding:wrongInstallation?'other':'binding'});});};
 const nativeRequire=require,req=n=>{
  if(n==='node:fs')return{realpathSync:x=>x,readFileSync:()=>Buffer.from('reviewed-source')};
  if(n==='../../scripts/lib/application-maintenance-installation')return{resolveMaintenanceInstallation:()=>({installationRoot:'/installation',homeDirectory:'/home',bindingSha256:'binding',assertCurrent(){}})};
  if(n==='./applicationMaintenanceLease')return{inprocessLeaseIdentity:l=>{assert.equal(l,lease);return{};}};
  if(n==='../../scripts/lib/setup-local-process-identity')return{captureLocalAncestorBinding:()=>{observations++;return structuredClone(record);}};
  return nativeRequire(n);
 };req.main={filename:entry};const module={exports:{}};
 vm.runInNewContext(fs.readFileSync(require.resolve('../server/services/applicationMaintenanceExecutionAdmission'),'utf8'),{require:req,module,__dirname:'/owned/server/services',__filename:'/owned/server/services/applicationMaintenanceExecutionAdmission.js',process:p,Buffer,setTimeout:timeout?(fn=>setTimeout(fn,0)):setTimeout,clearTimeout,Object,Reflect});
 return{api:module.exports,lease,p,record,controller,requests:()=>requests,observations:()=>observations,events,options:{lease,root:'/owned',homeDirectory:'/home'}};
}
test('owned launch binds fixed policy and exact live channel/ancestry; one issuer only',async()=>{
 const f=issuer(),v=await f.api.admitOwnedLaunch(f.options);assert.match(v.binding.policySha256,/^[a-f0-9]{64}$/);assert(Object.isFrozen(v.binding));v.assertCurrent();assert.equal(f.requests(),1);await assert.rejects(f.api.admitOwnedLaunch(f.options));f.record.ancestors[1].pid=99;assert.throws(v.assertCurrent);
});
test('invalid clean ledger denies before handshake; invalid parent, disconnected or abort never upgrades',async()=>{
 for(const opts of [{ledger:false},{channel:false},{wrongParent:true},{wrongInstallation:true},{abort:true},{timeout:true},{wrongAncestry:true}]){const f=issuer(opts);await assert.rejects(f.api.admitOwnedLaunch(f.options));if(opts.ledger===false||opts.channel===false)assert.equal(f.requests(),0);assert(!f.events.includes('upgrade'));}
});
test('caller authority fields, alternate entry and injected process arguments deny',async()=>{
 for(const change of [f=>{f.options.policySha256='a'.repeat(64);},f=>{f.p.execArgv=['--require','other'];},f=>{f.p.env.NODE_OPTIONS='--require other';},f=>{f.p.argv[2]='--owned-journal-bound';},f=>{f.options.lease={};}]){const f=issuer();change(f);await assert.rejects(f.api.admitOwnedLaunch(f.options));assert.equal(f.requests(),0);}
});
test('prospective launcher admits no injected spawn/stop/environment or ordinary option escape',async()=>{
 const entry=require('../scripts/application-journal-bound-maintenance');let invoked=false;
 for(const key of ['spawn','stop','environment'])await assert.rejects(entry.runProspectiveJournalBoundMaintenance({[key]:()=>{invoked=true;}}));
 await assert.rejects(entry.runJournalBoundMaintenance({prospective:true,spawn:()=>{invoked=true;}}));await assert.rejects(entry.runJournalBoundMaintenance(Object.create({prospective:true,spawn:()=>{invoked=true;}})));assert.equal(invoked,false);
 assert.equal(entry.selectProfile(['--maintenance-profile=canonical16-ctf-inprocess-v1']),'canonical16-ctf-inprocess-v1');
});
test('prospective prepare denies readiness before publication/source/filesystem inspection',async()=>{
 const filename=require.resolve('../server/services/applicationMaintenanceInprocessAdmission'),admissionRequire=createRequire(filename),req=n=>{
  if(n==='./applicationMaintenanceExecutionAdmission')return{admitOwnedLaunch:async()=>{throw Error('missing exact ledger4');}};
  if(n==='node:fs')return new Proxy({},{get(){throw Error('filesystem must not run');}});
  return admissionRequire(n);
 };const module={exports:{}};vm.runInNewContext(fs.readFileSync(filename,'utf8'),{require:req,module,__dirname:path.dirname(filename),Buffer,Object,Reflect});await assert.rejects(module.exports.prepareProspectiveInprocessAdmission({}),/missing exact ledger4/);
});
test('closed prospective supervisor requires nonce handshake and physical cleanup before success',async()=>{
 for(const wrong of [false,true]){
  const p=new EventEmitter();Object.assign(p,{pid:40,platform:'darwin',execPath:'/pinned/node',execArgv:[],env:{}});const child=new EventEmitter();child.pid=50;child.connected=true;child.disconnect=()=>{child.connected=false;};let stopped=0,grants=0;
  child.send=(message,callback)=>{assert.equal(message.type,'prospective-original-grant');assert.equal(message.nonce,'11111111-1111-4111-8111-111111111111');grants++;callback();queueMicrotask(()=>{child.emit('message',{type:'journal-bound-complete',completed:true});child.emit('exit',0,null);});};
  const req=n=>{if(n==='node:path')return path;if(n==='./lib/application-maintenance-installation')return{resolveMaintenanceInstallation:()=>({installationRoot:'/installation',bindingSha256:'binding',assertCurrent(){}})};if(n==='node:child_process')return{spawn:(node,args,options)=>{assert.equal(node,'/pinned/node');assert.equal(args[1],'--owned-prospective-original');assert.equal(options.detached,true);queueMicrotask(()=>child.emit('message',{type:'prospective-original-ready',nonce:'11111111-1111-4111-8111-111111111111',childPid:wrong?99:50,parentPid:40,installationBinding:'binding'}));return child;}};if(n==='./start-application')return{stopOwnedChild:async({child:c})=>{assert.equal(c,child);stopped++;}};throw Error('unexpected import');};req.main={};const module={exports:{}};
  vm.runInNewContext(fs.readFileSync(require.resolve('../scripts/application-journal-bound-maintenance'),'utf8'),{require:req,module,__dirname:'/owned/scripts',__filename:'/owned/scripts/application-journal-bound-maintenance.js',process:p,setTimeout,clearTimeout,Object,Reflect});
  const work=module.exports.runProspectiveJournalBoundMaintenance({});if(wrong)await assert.rejects(work);else await work;assert.equal(stopped,1);assert.equal(grants,wrong?0:1);
 }
});
test('actual control readiness accepts only exact clean five-entry ledger without DDL',async()=>{
 const c=require('../server/database/postgres/applicationMaintenanceControl'),names=['BOOTSTRAP','RECOVERY','REPLAY','EXECUTION','WINDOWS_OWNER'],files=['0001_maintenance_fence.sql','0002_local_recovery.sql','0003_canonical_inprocess_recovery.sql','0004_executable_recovery_admission.sql','0005_windows_owner_records.sql'];
 for(const n of [1,2,3,4,5])for(const dirty of [false,true]){const calls=[];const api=c.createApplicationMaintenanceControl({identity:{},mode:'maintenance',assertHeld(){},query:async sql=>{calls.push(sql);if(sql.includes('pg_locks'))return{rows:[{held:true}]};if(sql.startsWith('SELECT name'))return{rows:files.slice(0,n).map((name,i)=>({name,checksum:c['MAINTENANCE_'+names[i]+'_SHA256']}))};return{rows:[{version:1,target_matches:true,installation_id:'11111111-1111-4111-8111-111111111111',operation_id:'22222222-2222-4222-8222-222222222222',epoch:'2',state:dirty?'dirty':'clean'}]};}});if(n===5&&!dirty)assert.equal((await api.assertExecutionReady()).epoch,'2');else await assert.rejects(api.assertExecutionReady());assert(calls.every(s=>s.startsWith('SELECT')));}
});

test('owned IPC grant precedes explicit upgrade and exact readiness; failure never yields admission',async()=>{const f=issuer();await f.api.admitOwnedLaunch(f.options);assert.deepEqual(f.events,['clean','request','upgrade','ready']);for(const patch of [{upgradeFailure:true},{readyDrift:true}]){const bad=issuer(patch);await assert.rejects(bad.api.admitOwnedLaunch(bad.options));assert.equal(bad.requests(),1);assert(bad.events.includes('upgrade'));await assert.rejects(bad.api.admitOwnedLaunch(bad.options));}});
