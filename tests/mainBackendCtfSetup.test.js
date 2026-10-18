'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
test('genuine setup constituents receive same private roots, delivery config and authentic scope in order',async()=>{
 const calls=[],scope={},env={},config={IDENTITY_DATABASE_URL:'owned-runtime',IDENTITY_MIGRATION_DATABASE_URL:'owned-migration'},delivery={CTF_DELIVERY_DATABASE_URL:'owned-delivery'};
 const modules={
 'node:assert/strict':assert,'node:path':path,'node:fs/promises':{mkdir:async p=>calls.push(['mkdir',p]),readFile:async p=>{assert.equal(p,'/owned/external/installation/private/ctf-authority.json');return JSON.stringify({phase:'complete',checkpoint:{authoritySha256:'a'.repeat(64)}});}},
 '../../scripts/lib/setup-password-reset-key':{ensurePasswordResetKey:o=>{assert.equal(o.directory,'/owned/external/installation/private');calls.push(['reset-key']);return {filePath:path.join(o.directory,'secureshop-reset-key.json'),created:true};}},
 '../../db/postgres/provision-application':{provisionApplication:async o=>{assert.equal(o.manifestPath,'/owned/external/installation/private/provisioning.json');assert.equal(o.adminUrl,'owned-admin');calls.push(['provision']);return {configuration:config,plan:Array(16).fill({})};}},
 '../../scripts/install/ctf-delivery-setup':{prepareCtfDelivery:async o=>{assert.equal(o.directory,'/owned/external/installation/private');calls.push(['delivery']);return {configuration:delivery};}},
 '../../scripts/lib/application-maintenance-scope':{withApplicationMaintenanceScope:async(o,work)=>{assert.equal(o.environment,env);calls.push(['scope']);await work(scope);calls.push(['drained']);}},
 '../../db/postgres/initialize-application':{initializeApplication:async o=>{assert.equal(o.maintenanceScope,scope);calls.push(['initialize']);}},
 '../../scripts/install/ctf-authority-setup':{prepareCtfAuthority:async o=>{assert.equal(o.maintenanceScope,scope);assert.equal(o.root,'/owned/external/installation');assert.equal(o.environment.CTF_DELIVERY_DATABASE_URL,'owned-delivery');calls.push(['authority']);}}
 };
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(require.resolve('./fixtures/mainBackendCtfSetup'),'utf8'),{module,exports:module.exports,process:{env},require:id=>{assert(Object.hasOwn(modules,id),id);return modules[id];}});
 const result=await module.exports.prepare({owned:{appData:'/owned/external'},adminUrl:'owned-admin',environment:{PG_TLS:'disable'}});
 assert.deepEqual(calls.map(c=>c[0]),['mkdir','mkdir','reset-key','provision','delivery','scope','initialize','authority','drained']);assert.equal(result.configuration.CTF_DELIVERY_DATABASE_URL,'owned-delivery');assert.equal(result.publicResult.ctfJournalComplete,true);assert.equal(result.publicResult.passwordResetKeyReady,true);assert.equal(result.publicResult.actualModel,false);assert.doesNotMatch(JSON.stringify(result),/secureshop-reset-key|activeKeyId|private-key-value/);
});
test('owned setup child awaits physical cleanup and preserves failed exit',async()=>{
 const {runOwnedSetup}=require('./fixtures/mainBackendCtfSetup');let release,finished=false;const child={},seen=[];
 const controls={createOwnedChildren:()=>({launch:(command,args,options)=>{seen.push(options);return child;},cleanup:()=>new Promise(r=>{release=r;})}),waitForChild:async actual=>{assert.equal(actual,child);return 0;}};
 const work=runOwnedSetup({source:'/main',root:'/private',environment:{PRIVATE:'yes'}},{spawn:()=>assert.fail(),controls}).then(()=>{finished=true;});
 await new Promise(r=>setImmediate(r));assert.equal(finished,false);assert.equal(seen[0].cwd,'/private');assert.deepEqual(seen[0].stdio,['ignore','ignore','inherit']);release();await work;assert(finished);
 let cleaned=false;controls.createOwnedChildren=()=>({launch:()=>child,cleanup:async()=>{cleaned=true;}});controls.waitForChild=async()=>1;
 await assert.rejects(runOwnedSetup({source:'/main',root:'/private',environment:{}},{spawn:()=>assert.fail(),controls}));assert(cleaned);
});
test('private configuration admits exactly owned endpoint roles and rejects extra authority',()=>{
 const {validateConfiguration}=require('./fixtures/mainBackendCtfSetup'),manifest=Array.from({length:16},(_,i)=>({schema:'s'+i,runtimeRole:'dvaia_s'+i+'_runtime',runtimeVariable:'R'+i,migrationVariable:'M'+i})),c={CTF_DELIVERY_DATABASE_URL:'postgresql://dvaia_ctf_delivery:synthetic@127.0.0.1:54321/dvaia_ctf'};
 for(const r of manifest){c[r.runtimeVariable]=`postgresql://${r.runtimeRole}:synthetic@127.0.0.1:54321/dvaia_${r.schema}`;c[r.migrationVariable]=`postgresql://dvaia_${r.schema}_migration:synthetic@127.0.0.1:54321/dvaia_${r.schema}`;}
 assert.equal(validateConfiguration(c,manifest,54321),c);assert.throws(()=>validateConfiguration({...c,NODE_OPTIONS:'unsafe'},manifest,54321));assert.throws(()=>validateConfiguration(c,manifest,54322));assert.throws(()=>validateConfiguration({...c,CTF_DELIVERY_DATABASE_URL:c.CTF_DELIVERY_DATABASE_URL.replace('127.0.0.1','elsewhere.invalid')},manifest,54321));
});
test('private result FD reader rejects oversize and symlink artifacts',async()=>{
 const io=require('node:fs/promises'),os=require('node:os'),{readResult}=require('./fixtures/mainBackendCtfSetup');const dir=await io.mkdtemp(path.join(os.tmpdir(),'dvaia-ctf-read-control-')),file=path.join(dir,'result');
 try{await io.writeFile(file,'{"synthetic":true}',{mode:0o600});assert.deepEqual(await readResult(file),{synthetic:true});await io.symlink(file,path.join(dir,'link'));await assert.rejects(readResult(path.join(dir,'link')));await io.writeFile(file,'x'.repeat(65537));await assert.rejects(readResult(file));}finally{await io.rm(dir,{recursive:true,force:true});}
});
