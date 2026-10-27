'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),{EventEmitter}=require('node:events');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03ParentProtocol'),'utf8');
const make=new Function(source.slice(source.indexOf('const CAP='),source.indexOf('function serveParent('))+';return protocol;')();
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function fixture(){
 const channel=new EventEmitter(),writes=[],calls=[];
 channel.pause=()=>{};channel.write=(raw,cb)=>{writes.push(JSON.parse(raw));cb();};
 const controller={owner:{binding:()=>({runId:'a'.repeat(32),planSha256:'b'.repeat(64)}),remainingMs:()=>6000000,
  nowMs:()=>0,wrapperWindow:()=>({deadlineMs:1800000})},
  status:()=>({stage:'ready'}),claimCohort:async()=>{calls.push('claim');return {environment:{}};}};
 const main={assertCurrent:async()=>{},attachBrowser:async()=>{calls.push('attach');},requireBrowserAbsent:async()=>{calls.push('browser-proof');},
  retire:async()=>{calls.push('main-retire');return {groupAbsent:true};}};
 const watchdog={armCohort:()=>calls.push('arm'),close:async()=>{const proof=await main.retire();
  if(proof.groupAbsent!==true)throw Error('unjoined');calls.push('producer-retire');return {publicationVerified:true,candidate:{cleanupVerified:true}};}};
 const postgres={requireBound:()=>true,createIntent:async()=>({intent:{}}),bind:async()=>({bound:true})};
 const postWork={noteWorkHandoff:failed=>{calls.push('handoff');assert.equal(typeof failed,'boolean');}};
 const server=make(controller,main,channel,watchdog,postgres,postWork);let sequence=0;
 const send=(op,payload={})=>channel.emit('data',Buffer.from(JSON.stringify({version:1,runId:'a'.repeat(32),planSha256:'b'.repeat(64),sequence:sequence++,op,payload})+'\n'));
 return {channel,writes,calls,controller,main,watchdog,server,send,postgres};
}
test('start attests existing readiness without preparing again; claim precedes verified attachment',async()=>{
 const f=fixture();f.send('start');await tick();assert.equal(f.writes[0].result.parentRemainingMsAtAdmission,6000000);
 f.send('claim-cohort');await tick();f.send('attach-browser',{birth:{pid:10}});await tick();
 assert.deepEqual(f.calls,['claim','arm','attach']);
 f.send('finish-work',{browserAbsent:true,primaryFailed:false});await tick();
 assert.deepEqual(f.calls.slice(-2),['browser-proof','handoff']);
 assert.deepEqual(f.writes.at(-1).result,{accepted:true,cleanupPending:true,qualificationComplete:false});
 assert.equal(f.calls.includes('producer-retire'),false);
});
test('EOF independently retires main and both producers',async()=>{
 const f=fixture();f.channel.emit('end');const result=await f.server.done;
 assert.deepEqual(f.calls,['main-retire','producer-retire']);assert.equal(result.cleanupVerified,true);
});
test('failed browser attachment poisons channel and invokes owned retirement',async()=>{
 const f=fixture();f.main.attachBrowser=async()=>{throw Error('foreign birth');};
 f.send('start');await tick();f.send('claim-cohort');await tick();f.send('attach-browser',{birth:{pid:10}});
 await f.server.done;assert.deepEqual(f.calls.slice(-2),['main-retire','producer-retire']);assert.equal(f.writes.length,2);
});
test('caller browser absence does not replace independent proof',async()=>{
 const f=fixture();f.main.requireBrowserAbsent=async()=>{throw Error('still live');};
 f.send('start');await tick();f.send('finish-work',{browserAbsent:true,primaryFailed:false});await f.server.done;
 assert.equal(f.writes.length,1);assert.deepEqual(f.calls,['main-retire','producer-retire']);
});
test('duplicate JSON keys and pipelining retire without dispatch',async()=>{
 for(const raw of ['{"version":1,"version":1}\n','{}\n{}\n']){
  const f=fixture();f.channel.emit('data',Buffer.from(raw));await f.server.done;assert.equal(f.writes.length,0);
 }
});
test('failed local retirement remains debt and never starts producer deletion',async()=>{
 const f=fixture();f.main.retire=async()=>{throw Error('unjoined');};f.channel.emit('end');
 assert.equal((await f.server.done).cleanupVerified,false);
 assert.equal(f.calls.includes('producer-retire'),false);
});
const guardedSource=source.slice(source.indexOf(' let retirement;'),source.indexOf('\n const watchdog=require(',source.indexOf(' let retirement;')));
const guardedFactory=(controller,main,postWork,postgres)=>new Function('controller','main','postWork','postgres','fail',guardedSource+';return guarded;')(
 controller,main,postWork,postgres,code=>Object.assign(Error(code),{code}));
test('actual guarded retirement waits for handed-off MAIN but unexpected EOF/expiry is child-first',async()=>{
 for(const reason of ['main-terminal','inherited-fd-eof','absolute-cohort-expiry']){
  const calls=[];
  const guarded=guardedFactory({owner:{}},
   {retire:async()=>{calls.push('main');return {groupAbsent:true};}},
   {status:()=>({handoff:reason==='main-terminal'?{}:null})},{finalize:async()=>{calls.push('post-work');return {};}});
  await guarded.retire(reason);await guarded.retire('duplicate');
  assert.deepEqual(calls,reason==='main-terminal'?['post-work']:['main','post-work']);
 }
});
test('actual watchdog guard cannot delete producers after failed or false MAIN proof',async()=>{
 for(const throws of [false,true]){
  let deleted=false;
  const guarded=guardedFactory({owner:{}},
   {retire:async()=>{if(throws)throw Error('unknown');return {groupAbsent:false};}},
   {status:()=>({handoff:null})},{finalize:async()=>{deleted=true;}});
  await assert.rejects(guarded.retire('absolute-cohort-expiry'),e=>e.code==='V03_PARENT_MAIN_ABSENCE_UNPROVEN'&&e.cleanupDebt);
  assert.equal(deleted,false);
 }
});
