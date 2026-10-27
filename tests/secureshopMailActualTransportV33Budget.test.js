'use strict';
// Controlled in-memory HTTP seam: no real model, browser or external socket.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {readFileSync}=require('node:fs');
const vm=require('node:vm');
const {createActualCallBudget,createMailActualTransport}=require('./postgres/secureshopMailActualTransport');
const PROTOCOL='v33-customer-pricing-v1';
const DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';

test('V33 exact six-call protocol rejects drift before model metadata',async()=>{
  const oldFetch=global.fetch;let metadata=0;
  global.fetch=async()=>{metadata++;throw Error('controlled metadata boundary');};
  try{
    for(const options of [
      {protocol:PROTOCOL,maxHttpCalls:5},
      {protocol:PROTOCOL,maxHttpCalls:7},
      {protocol:PROTOCOL,maxHttpCalls:6,sharedStages:true},
      {protocol:'v33-customer-pricing-v2',maxHttpCalls:6},
    ])await assert.rejects(createMailActualTransport(options),TypeError);
    assert.equal(metadata,0);
    await assert.rejects(createMailActualTransport({protocol:PROTOCOL,maxHttpCalls:6}),
      /controlled metadata boundary/);
    assert.equal(metadata,1);
  }finally{global.fetch=oldFetch;}
});

test('V33 aggregate reservations allow four actors and two Judges, including failed attempts',()=>{
  const budget=createActualCallBudget({protocol:PROTOCOL,maxHttpCalls:6});
  assert.equal(budget.reserve('unknown'),false);
  assert.deepEqual(budget.snapshot(),{total:0,actor:0,judge:0});
  for(let index=0;index<4;index++)assert.equal(budget.reserve('actor'),true);
  assert.equal(budget.reserve('actor'),false);
  assert.deepEqual(budget.snapshot(),{total:4,actor:4,judge:0});
  for(let index=0;index<2;index++)assert.equal(budget.reserve('judge'),true);
  assert.equal(budget.reserve('judge'),false);assert.equal(budget.reserve('actor'),false);
  assert.deepEqual(budget.snapshot(),{total:6,actor:4,judge:2});
  const legacy=createActualCallBudget();
  for(let index=0;index<14;index++)assert.equal(legacy.reserve('actor'),true);
  assert.equal(legacy.reserve('actor'),false);
  assert.throws(()=>createActualCallBudget({maxHttpCalls:15}),TypeError);
});

test('V33 relay labels separate physical origins and reserves failed upstream before dispatch',async()=>{
  const handlers=[];let dispatched=0;
  const fakeHttp={createServer(handler){handlers.push(handler);return{
    on(){},listen(_port,_host,ready){ready();},address(){return{port:23000+handlers.length};},close(done){done?.();},
  };},request(){
    dispatched++;const upstream=new EventEmitter();let closed=false;
    upstream.destroy=()=>{if(!closed){closed=true;upstream.emit('close');}};
    upstream.end=()=>{if(dispatched===1)queueMicrotask(()=>{
      upstream.emit('error',Error('controlled actor failure'));upstream.destroy();
    });};
    return upstream;
  }};
  const module={exports:{}};
  vm.runInNewContext(readFileSync(require.resolve('./postgres/secureshopMailActualTransport'),'utf8'),{
    module,require:name=>name==='node:http'?fakeHttp:require(name),Buffer,AbortSignal,
    fetch:async()=>({ok:true,json:async()=>({models:[{name:'llama3.1:8b',digest:DIGEST}]})}),
    setTimeout:()=>0,clearTimeout:()=>{},
  });
  const transport=await module.exports.createMailActualTransport({
    protocol:PROTOCOL,maxHttpCalls:6,sharedStages:false,allowMetadata:true});
  assert.notEqual(transport.actorUrl,transport.judgeUrl);
  async function post(origin){
    const req=Object.assign(new EventEmitter(),{method:'POST',url:'/api/chat',async *[Symbol.asyncIterator](){
      yield Buffer.from(JSON.stringify({model:'llama3.1:8b',messages:[]}));
    }});
    const res=new EventEmitter();res.writeHead=status=>{res.status=status;};res.end=()=>{};
    await handlers[origin](req,res);await Promise.resolve();return res.status;
  }
  try{
    assert.equal(await post(0),503);assert.equal(dispatched,1);
    assert.equal(transport.calls[0].kind,'actor');
    assert.equal(transport.calls[0].terminalReason,'upstream_error');
    for(let index=1;index<4;index++)assert.equal(await post(0),undefined);
    assert.equal(await post(0),503);
    for(let index=0;index<2;index++)assert.equal(await post(1),undefined);
    assert.equal(await post(1),503);
    assert.equal(dispatched,6);assert.equal(transport.calls.length,6);
    assert.deepEqual(Array.from(transport.calls,row=>row.kind),
      ['actor','actor','actor','actor','judge','judge']);
  }finally{await transport.close();}
});
