'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const api=require('./postgres/ownedV03ListingsBridgeHost');
const source=fs.readFileSync(require.resolve('./postgres/ownedV03ListingsBridgeHost'),'utf8');
const terminalClean=new Function(source.slice(source.indexOf('function terminalClean('),source.indexOf('function clockMap('))+';return terminalClean;')();
const map=new Function('fail',source.slice(source.indexOf('function clockMap('),source.indexOf('async function createListingsBridgeHost('))+';return clockMap;')(
 code=>Object.assign(Error(code),{code}));
test('actual local clock bracket maps absolute expiry conservatively without renewal',()=>{
 const clock=map({monotonicMs:9000},1000,1020);
 assert.equal(clock.uncertaintyMs,21);assert.equal(clock.map(11000),18979);
 assert.equal(clock.map(11000)-clock.map(9790),1210);
});
test('uncertain or regressing local clock bracket denies listener ownership',()=>{
 for(const [sent,received]of [[1000,999],[1000,3000],[1.5,2]])assert.throws(()=>map({monotonicMs:9000},sent,received));
});
test('expired mapped endpoint is not replaced with a fresh timeout',()=>{
 const clock=map({monotonicMs:9000},1000,1020);assert.throws(()=>clock.map(1020));
});
test('JSON owner, caller commands and fake receipt never mint host capability',async()=>{
 await assert.rejects(api.createListingsBridgeHost({command:'true'}),{code:'V03_BRIDGE_HOST_OPTIONS'});
 await assert.rejects(api.createListingsBridgeHost({owner:{},root:'/synthetic',sourcePins:{},expectedPythonSha256:'a'.repeat(64)}),{code:'V03_COMBINED_OWNER_REQUIRED'});
 assert.throws(()=>api.assertListingsBridgeHost({listenerClosed:true}),{code:'V03_BRIDGE_HOST_REQUIRED'});
});
const catchBody=source.slice(source.indexOf(' }catch(error){primary=error;'),source.indexOf('\n }finally{',source.indexOf(' }catch(error){primary=error;')));
const partial=new Function('scope','return (async()=>{with(scope){try{throw failure;'+catchBody+'}}}) ();');
function partialFixture(remaining=60000){
 const calls=[],birth={pid:42,birth:123};
 const scope={failure:Error('original'),primary:null,birth:null,closed:true,writes:Promise.resolve(),
  window:{deadlineMs:remaining},owner:{nowMs:()=>0},fail:code=>Object.assign(Error(code),{code}),
  child:{pid:42,stdin:{end(){calls.push('eof');}},stdout:{removeAllListeners(){calls.push('detach');},destroy(){calls.push('pipe-close');}}},
  observer:{async observe(row){calls.push(row);return row.op==='inspect'?{observed:birth}:{groupAbsent:true};},status:()=>({pending:0,debts:0})},
  waitFor:async predicate=>{assert.equal(predicate(),true);}};
 return {scope,calls,birth};
}
test('actual constructor catch observes and joins its partial child before publication closes',async()=>{
 const f=partialFixture();await assert.rejects(partial(f.scope),error=>error===f.scope.failure);
 assert.deepEqual(f.calls.filter(x=>typeof x==='object').map(x=>x.op),['inspect','retire']);
 assert.equal(f.calls[2].expected,f.birth);
 assert.equal(f.scope.failure.bridgePartial.groupAbsent,true);
 assert.equal(f.scope.failure.cleanupDebt,true);
});
test('expired constructor window retains unknown child debt without signaling',async()=>{
 const f=partialFixture(0);await assert.rejects(partial(f.scope));
 assert.equal(f.calls.some(x=>typeof x==='object'),false);
 assert.equal(f.scope.failure.bridgePartial.groupAbsent,false);
 assert.equal(f.scope.failure.bridgePartial.birth,null);
});
test('constructor observation failure preserves primary and cannot authorize retirement',async()=>{
 const f=partialFixture();f.scope.observer.observe=async row=>{f.calls.push(row);throw Error('observation');};
 await assert.rejects(partial(f.scope),error=>error===f.scope.failure);
 assert.deepEqual(f.calls.filter(x=>typeof x==='object').map(x=>x.op),['inspect']);
 assert.equal(f.scope.failure.bridgePartial.groupAbsent,false);
});
test('owning transport rejects constructor-close terminal even when no-bridge local closure is true',()=>{
 const local={listenerClosed:true,localChannelsRetired:true,channelIds:[],channelStates:{}};
 const good={failure:null,cleanupDebt:false,leaseSourceCloseUnproven:false,local};
 assert.equal(terminalClean(good,local),true);
 const constructorCloseFailure={...good,failure:'OSError',cleanupDebt:true,leaseSourceCloseUnproven:true};
 assert.equal(terminalClean(constructorCloseFailure,local),false);
 for(const field of ['failure','cleanupDebt','leaseSourceCloseUnproven']){
  const missing={...good};delete missing[field];assert.equal(terminalClean(missing,local),false);
 }
});
