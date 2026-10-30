'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),os=require('node:os'),fs=require('node:fs/promises'),{EventEmitter}=require('node:events');
const {createLegacyUploadLifecycle}=require('../server/services/legacyUploadLifecycle');
function fixture({intent={file_path:null,state:'admitted'},stat={isFile:()=>true,isSymbolicLink:()=>false}}={}){
 const events=[];const client={async query(sql,args){events.push([sql,args]);
  if(sql.includes('read_legacy_upload_intent'))return{rows:[intent]};
  if(sql.includes('list_legacy_upload_cleanup'))return{rows:[{intent_id:'intent',...intent}]};
  return{rows:[{}]};},release(){events.push(['release']);}};
 const lifecycle=createLegacyUploadLifecycle({identityPool:{connect:async()=>client},uploadRoot:'/owned/uploads',fileSystem:{lstat:async()=>stat,unlink:async target=>events.push(['unlink',target]),mkdir:async target=>events.push(['mkdir',target]),rm:async target=>events.push(['rm',target])}});
 return{lifecycle,events};
}
test('upload lifecycle creates its unique namespace before admission, then publishes under the global lock',async()=>{
 const {lifecycle,events}=fixture();const value=await lifecycle.runUpload({ownerId:7,sessionId:8},async lease=>{await lease.bindFilename('payload.js');return'written';});
 assert.equal(value,'written');const sql=events.map(row=>row[0]);
 assert.match(sql[0],/pg_advisory_lock/);const mkdir=events.findIndex(row=>row[0]==='mkdir'),admit=events.findIndex(row=>String(row[0]).includes('admit_legacy_upload')),bind=events.findIndex(row=>String(row[0]).includes('bind_legacy_upload_path')),publish=events.findIndex(row=>String(row[0]).includes('publish_legacy_upload'));assert.ok(mkdir>=0&&mkdir<admit&&admit<bind&&bind<publish);assert.match(sql.at(-2),/pg_advisory_unlock/);
});
test('failed upload removes a bound regular file before retiring its durable intent',async()=>{
 const {lifecycle,events}=fixture({intent:{file_path:'/owned/uploads/partial.bin',state:'admitted'}});
 await assert.rejects(lifecycle.runUpload({ownerId:7,sessionId:8},async lease=>{await lease.bindFilename('partial.bin');throw Error('write failed');}),/write failed/);
 const removed=events.findIndex(row=>row[0]==='rm'),retire=events.findIndex(row=>String(row[0]).includes('retire_legacy_upload('));assert.ok(removed>=0&&retire>removed);
});
test('deletion serializes on the same global lock and delegates exact durable intents to the legacy store',async()=>{
 const {lifecycle,events}=fixture({intent:{file_path:'/owned/uploads/orphan.bin',state:'published'}});let seen;
 assert.deepEqual(await lifecycle.destroyOwner(7,async(owner,paths,intentIds)=>{seen={owner,paths,intentIds};return{removed:4,filesRemoved:1};}),{removed:4,filesRemoved:1});
 assert.deepEqual(seen.paths,['/owned/uploads/orphan.bin']);assert.deepEqual(seen.intentIds,['intent']);assert.equal(seen.owner,7);
 assert.ok(events.some(row=>String(row[0]).includes('retire_legacy_uploads')));
});
test('upload lifecycle rejects unmanaged paths and invalid owner/session before filesystem mutation',async()=>{
 const {lifecycle}=fixture();await assert.rejects(lifecycle.runUpload({ownerId:7,sessionId:8},lease=>lease.bindFilename('../host')),/logical/);await assert.rejects(lifecycle.runUpload({ownerId:'bad',sessionId:8},async()=>{}),TypeError);
});
test('connection loss while creating the namespace aborts and removes it without admitting or starting a write',async()=>{
 const events=[],client=new EventEmitter();client.query=async(sql,args)=>{events.push([sql,args]);return{rows:[{}]};};client.release=error=>events.push(['release',Boolean(error)]);
 let finishMkdir;const mkdirStarted=new Promise(resolve=>{finishMkdir=resolve;});let entered=false;
 const lifecycle=createLegacyUploadLifecycle({identityPool:{connect:async()=>client},uploadRoot:'/owned/uploads',fileSystem:{
  async mkdir(target){events.push(['mkdir',target]);await mkdirStarted;},async rm(target){events.push(['rm',target]);}
 }});
 const running=lifecycle.runUpload({ownerId:7,sessionId:8},async()=>{entered=true;});
 await new Promise(resolve=>setImmediate(resolve));client.emit('error',new Error('connection lost'));finishMkdir();
 await assert.rejects(running,/connection lost/);assert.equal(entered,false);assert.equal(events.some(row=>String(row[0]).includes('admit_legacy_upload')),false);assert.ok(events.some(row=>row[0]==='rm'));
});
test('connection loss after admission lets deletion remove the namespace and a delayed writer cannot recreate it',async()=>{
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'owasp-ai-goat-upload-fence-'));const first=new EventEmitter(),second=new EventEmitter();let admitted=false;
 for(const client of [first,second]){client.release=()=>{};client.query=async sql=>{if(String(sql).includes('admit_legacy_upload'))admitted=true;if(String(sql).includes('list_legacy_upload_cleanup'))return{rows:[{intent_id:'retired-intent',file_path:null,state:'admitted'}]};return{rows:[{}]};};}
 let calls=0;const lifecycle=createLegacyUploadLifecycle({identityPool:{connect:async()=>calls++===0?first:second},uploadRoot:root});let lease,continueWrite;const gate=new Promise(resolve=>{continueWrite=resolve;});
 const upload=lifecycle.runUpload({ownerId:7,sessionId:8},async value=>{lease=value;await gate;await fs.writeFile(path.join(value.directory,'late.bin'),'late');});
 while(!lease)await new Promise(resolve=>setImmediate(resolve));assert.equal(admitted,true);first.emit('error',new Error('connection lost'));
 await lifecycle.destroyOwner(7,async()=>({removed:0,filesRemoved:0}));continueWrite();await assert.rejects(upload,/ENOENT|connection lost/);
 await assert.rejects(fs.stat(path.join(root,'managed','7',lease.intentId)),/ENOENT/);await fs.rm(root,{recursive:true,force:true});
});
