'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const filename=path.resolve(__dirname,'../scripts/install/ctf-authority-setup.js');
function fixture({active=false,failPrepare=false,failClose=false,staged=0,conflict=false,phase=null,partial=false,failActivate=false,grow=false}={}){
 const calls=[],env={IDENTITY_DATABASE_URL:'i',IDENTITY_MIGRATION_DATABASE_URL:'im',CTF_DATABASE_URL:'c',CTF_MIGRATION_DATABASE_URL:'cm',CTF_DELIVERY_DATABASE_URL:'d'};
 const tuple={activation_id:'a',bootstrap_operation_id:'b',identity_store_id:'i',ctf_store_id:'c',source_revision:'1',manifest_sha256:'m',authority_sha256:'h'};
 let saved={bootstrapId:'b',activationId:'a',phase:phase||(active?'complete':'initialized'),checkpoint:(active||partial)?{sourceRevision:'1',manifestSha256:'m',authoritySha256:'h'}:{sourceRevision:null,manifestSha256:null,authoritySha256:null}};
 const base={version:1,status:'complete',plan:[],cluster:'cluster',configuration:env},delivery={version:1,status:'complete',cluster:'cluster',role:'dvaia_ctf_delivery',configuration:{CTF_DELIVERY_DATABASE_URL:'d'}};
 const pool=key=>({key,async end(){calls.push('close:'+key);if(failClose)throw Error('close');}});
 const stubs={
  'node:fs/promises':{realpath:async p=>p,lstat:async()=>({dev:1,ino:1,isFile:()=>true,isSymbolicLink:()=>false,uid:process.getuid(),mode:0o600,nlink:1}),open:async p=>{const raw=Buffer.from(JSON.stringify(p.endsWith('provisioning.json')?base:p.endsWith('ctf-delivery.json')?delivery:saved));return{stat:async()=>({isFile:()=>true,uid:process.getuid(),mode:0o600,nlink:1,size:raw.length,dev:1,ino:1}),read:async(buffer,offset,length,position)=>{if(grow){buffer.fill(65,offset,offset+length);return{bytesRead:length};}const bytesRead=raw.copy(buffer,offset,position,position+length);return{bytesRead};},close:async()=>{}};}},
  '../lib/application-maintenance-scope':{hasPreparedMaintenanceScope(){return false;},assertApplicationMaintenanceScope(){calls.push('held');},invalidateApplicationMaintenanceScope(){calls.push('invalidated');}},
  '../../server/database/postgres':{createPool:(env,key)=>{calls.push('pool:'+key);return pool(key);}},
  '../../db/postgres/provision-application':{provisioningPlan:()=>[]},
  '../../db/postgres/migrate':{migrate:async(p,d)=>calls.push('migrate:'+path.basename(d))},
  '../../server/database/postgres/ctfLifecycleRepository':{withCtfTransaction:async(p,fn)=>fn({query:async sql=>({rows:sql.includes('current_user')?[{role:p.key==='IDENTITY_MIGRATION_DATABASE_URL'?'dvaia_identity_migration':'dvaia_ctf_migration',login:p.key==='IDENTITY_MIGRATION_DATABASE_URL'?'dvaia_identity_migration':'dvaia_ctf_migration'}]:sql.includes('store_id')?[{store_id:p.key==='IDENTITY_MIGRATION_DATABASE_URL'?'i':'c'}]:[{activation_id:(active||(partial&&p.key==='CTF_MIGRATION_DATABASE_URL'))?'a':null}]})})},
  '../../server/database/postgres/ctfAuthorityBootstrapRepository':{createCtfAuthorityBootstrapRepository:()=>({preparationStatus:async()=>({prepared:true})})},
  '../../server/services/ctfAuthorityBootstrap':{createCtfAuthorityBootstrap:()=>({prepare:async({operationId})=>{assert.equal(operationId,'b');calls.push('prepare');if(failPrepare)throw Error('uncertain commit');return{prepared:true,revision:'1',manifestSha256:'m'};}})},
  '../../server/database/postgres/ctfDeliveryActivationOperator':{createCtfDeliveryActivationOperator:()=>({activate:async p=>{calls.push('activate');if(failActivate)throw Error('uncertain activation commit');assert.equal(p.activationId,'a');assert.equal(p.pageBudget,16);return staged-->0?{staged:true}:{activation:tuple};}})},
  '../../server/database/postgres/ctfDeliveryActivation':{createCtfDeliveryActivation:()=>({loadCurrent:async()=>({...tuple,activation_id:conflict?'foreign':'a'}),verify:async()=>tuple})},
  './ctf-authority-journal':{withCtfAuthorityJournal:async(args,fn)=>fn({read:async()=>saved,advance:async update=>{calls.push('journal:'+update.phase);saved={...saved,...update};return saved;}})},
 };
 const module={exports:{}};vm.runInNewContext(fs.readFileSync(filename,'utf8'),{module,exports:module.exports,require:n=>stubs[n]||require(n),__dirname:path.dirname(filename),process,AbortSignal,Buffer,console});
 return{calls,run:()=>module.exports.prepareCtfAuthority({root:'/repo',directory:'/private-install',environment:env,maintenanceScope:{}})};
}
test('fresh preparation journals IDs, migrates both existing stores, drains all pools before return',async()=>{const f=fixture({staged:2});assert.equal((await f.run()).state,'active');assert.equal(f.calls.filter(x=>x==='activate').length,3);assert(f.calls.indexOf('journal:preparing')<f.calls.indexOf('prepare'));assert(f.calls.includes('migrate:identity-migrations'));assert(f.calls.includes('migrate:ctf'));assert.equal(f.calls.filter(x=>x.startsWith('close:')).length,2);});
test('active paired no-op never imports or reactivates',async()=>{const f=fixture({active:true});assert.equal((await f.run()).changed,false);assert(!f.calls.includes('prepare'));assert(!f.calls.includes('activate'));});
test('foreign active tuple refuses and invalidates maintenance without fallback',async()=>{const f=fixture({active:true,conflict:true});await assert.rejects(f.run());assert(f.calls.includes('invalidated'));assert(!f.calls.includes('prepare'));});
test('uncertain prepare is surfaced once and both pools close',async()=>{const f=fixture({failPrepare:true});await assert.rejects(f.run());assert.equal(f.calls.filter(x=>x==='prepare').length,1);assert(!f.calls.includes('activate'));assert.equal(f.calls.filter(x=>x.startsWith('close:')).length,2);});
test('owned cleanup failure cannot return successful activation',async()=>{const f=fixture({failClose:true});await assert.rejects(f.run());assert.equal(f.calls.filter(x=>x.startsWith('close:')).length,2);});

test('one-sided activation resumes journal ID without reimporting source',async()=>{const f=fixture({partial:true,phase:'activating'});await f.run();assert(!f.calls.includes('prepare'));assert.equal(f.calls.filter(x=>x==='activate').length,1);});
test('uncertain activation commit is never implicitly retried',async()=>{const f=fixture({failActivate:true});await assert.rejects(f.run());assert.equal(f.calls.filter(x=>x==='activate').length,1);assert(!f.calls.includes('journal:complete'));assert(f.calls.includes('invalidated'));});

test('private manifest growth after stat is bounded and rejected before pools',async()=>{const f=fixture({grow:true});await assert.rejects(f.run());assert(!f.calls.some(x=>x.startsWith('pool:')));});
