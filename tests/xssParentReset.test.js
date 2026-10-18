'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createXssParentReset}=require('../server/services/xssParentReset');
function fixture(){
 const calls=[];const op={operationId:'op',ownerId:42,status:'pending',childOperationId:'child',lease:{token:'lease'}};
 const lifecycle={ownerId:42,check:async()=>{}};
 const dependencies={journal:{begin:async()=>{calls.push('begin');return op;},claim:async()=>{calls.push('claim');return op;},assertCurrent:async()=>{},
 acknowledgeChild:async()=>{calls.push('child-ack');},acknowledgeClear:async()=>{calls.push('clear-ack');},
 finalize:async()=>{calls.push('finalize');op.status='completed';return op;},fail:async()=>{calls.push('fail');}},
 childJournal:{read:async()=>({operationId:'child',ownerId:42,graphParentGeneration:'0',workshopGeneration:'0',children:{}})},
 store:{retireOrRead:async()=>{calls.push('retire');return {kind:'retired_no_effect'};},clearParent:async()=>{calls.push('clear');return {}; }},
 runs:{reset:async(owner,work)=>{assert.equal(owner,'42');calls.push('graph-reset');await work({ownerKey:'["XSS","42"]',durableGeneration:'1',check:async()=>{}});}}};
 return {calls,op,lifecycle,dependencies,run:()=>createXssParentReset(dependencies)({ownerId:42,operationId:'op',lifecycle})};
}
test('parent reset orders durable retirement, idempotent clear and atomic finalize',async()=>{
 const f=fixture();assert.equal((await f.run()).status,'completed');
 assert.deepEqual(f.calls,['begin','claim','graph-reset','retire','child-ack','clear','clear-ack','finalize']);
});
test('completed response replay never resets graph or clears store again',async()=>{
 const f=fixture();await f.run();f.calls.length=0;await f.run();assert.deepEqual(f.calls,['begin']);
});
test('authority loss after atomic finalize replays completed result without repeating reset',async()=>{
 const f=fixture();f.dependencies.journal.finalize=async()=>{
  f.calls.push('finalize');f.op.status='completed';f.lifecycle.check=async()=>{throw new Error('lost');};return f.op;
 };
 await assert.rejects(f.run(),/lost/);f.lifecycle.check=async()=>{};f.calls.length=0;
 assert.equal((await f.run()).status,'completed');assert.deepEqual(f.calls,['begin']);
});
test('clear failure preserves failed recovery without canonical finalization',async()=>{
 const f=fixture();f.dependencies.store.clearParent=async()=>{throw new Error('unavailable');};
 await assert.rejects(f.run(),/unavailable/);assert.ok(f.calls.includes('fail'));assert.ok(!f.calls.includes('finalize'));
});
test('lost lifecycle after retirement prevents clear and finalization',async()=>{
 const f=fixture();f.dependencies.store.retireOrRead=async()=>{f.lifecycle.check=async()=>{throw new Error('lost');};return {};};
 await assert.rejects(f.run(),/lost/);assert.ok(!f.calls.includes('clear'));assert.ok(!f.calls.includes('finalize'));
});
test('no child operation skips retirement without fabricating an outcome',async()=>{
 const f=fixture();f.op.childOperationId=null;await f.run();assert.ok(!f.calls.includes('retire'));assert.ok(!f.calls.includes('child-ack'));
});
test('sibling lifecycle fails before journal admission',async()=>{
 const f=fixture();f.lifecycle.ownerId=43;await assert.rejects(f.run(),TypeError);assert.deepEqual(f.calls,[]);
});
test('unchanged graph parent refuses retirement and store clear',async()=>{
 const f=fixture();f.dependencies.childJournal.read=async()=>({ownerId:42,graphParentGeneration:'1'});
 await assert.rejects(f.run(),/not superseded/);assert.ok(!f.calls.includes('retire'));assert.ok(!f.calls.includes('clear'));
});

test('unexpired lease loser never invalidates the graph or fails the winning lease',async()=>{
 const f=fixture();f.dependencies.journal.claim=async()=>null;
 await assert.rejects(f.run(),/already leased/);
 assert.deepEqual(f.calls,['begin']);
});
test('graph reset admission failure releases only the claimed journal lease',async()=>{
 const f=fixture();f.dependencies.runs.reset=async()=>{throw new Error('graph unavailable');};
 await assert.rejects(f.run(),/graph unavailable/);
 assert.deepEqual(f.calls,['begin','claim','fail']);
});
test('concurrent duplicate cannot supersede the winning graph reset',async()=>{
 const f=fixture();let claimed=false,entered,release;
 const ready=new Promise(resolve=>{entered=resolve;});const gate=new Promise(resolve=>{release=resolve;});
 f.dependencies.journal.claim=async()=>{if(claimed)return null;claimed=true;return f.op;};
 const original=f.dependencies.runs.reset;
 f.dependencies.runs.reset=async(...args)=>{entered();await gate;return original(...args);};
 const winner=f.run();await ready;
 try{await assert.rejects(f.run(),/already leased/);}finally{release();}
 await winner;assert.equal(f.calls.filter(call=>call==='graph-reset').length,1);
 assert.ok(!f.calls.includes('fail'));
});
