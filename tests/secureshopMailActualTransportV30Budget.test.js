'use strict';
// Controlled local HTTP seams only: no real model, browser or network socket.
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {readFileSync}=require('node:fs');
const vm=require('node:vm');
const {createActualCallBudget,createMailActualTransport}=require('./postgres/secureshopMailActualTransport');
const PROTOCOL='v30-customer-disclosure-actors-v2';
const DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';

test('V30 closed admission rejects wrong budget, shared origins and unknown protocol before metadata',async()=>{
  const oldFetch=global.fetch;let metadata=0;
  global.fetch=async()=>{metadata++;throw Error('controlled metadata boundary');};
  try{
    for(const options of [
      {protocol:PROTOCOL,maxHttpCalls:15},
      {protocol:PROTOCOL,maxHttpCalls:17},
      {protocol:PROTOCOL,maxHttpCalls:16,sharedStages:true},
      {protocol:'v30-customer-disclosure-actors-v1',maxHttpCalls:16},
    ])await assert.rejects(createMailActualTransport(options),TypeError);
    assert.equal(metadata,0);
    await assert.rejects(createMailActualTransport({protocol:PROTOCOL,maxHttpCalls:16}),/controlled metadata boundary/);
    assert.equal(metadata,1);
  }finally{global.fetch=oldFetch;}
});

test('V30 actor-only reservations spend exactly sixteen, rejecting Judge and unknown kinds without spend',()=>{
  const budget=createActualCallBudget({protocol:PROTOCOL,maxHttpCalls:16});
  assert.equal(budget.reserve('judge'),false);assert.equal(budget.reserve('unknown'),false);
  assert.deepEqual(budget.snapshot(),{total:0,actor:0,judge:0});
  for(let index=0;index<16;index++)assert.equal(budget.reserve('actor'),true);
  assert.equal(budget.reserve('actor'),false);assert.equal(budget.reserve('judge'),false);
  assert.deepEqual(budget.snapshot(),{total:16,actor:16,judge:0});
  const legacy=createActualCallBudget();
  for(let index=0;index<14;index++)assert.equal(legacy.reserve('actor'),true);
  assert.equal(legacy.reserve('actor'),false);
  assert.throws(()=>createActualCallBudget({maxHttpCalls:16}),TypeError);
});

test('V30 physical relay reserves before dispatch; a failed upstream consumes one of sixteen calls',async()=>{
  const handlers=[];let dispatched=0;
  const fakeHttp={createServer(handler){handlers.push(handler);return{
    on(){},listen(_port,_host,ready){ready();},address(){return{port:22000+handlers.length};},close(done){done?.();},
  };},request(){
    dispatched++;const upstream=new EventEmitter();let closed=false;
    upstream.destroy=()=>{if(!closed){closed=true;upstream.emit('close');}};
    upstream.end=()=>{if(dispatched===1)queueMicrotask(()=>{
      upstream.emit('error',Error('controlled upstream failure'));upstream.destroy();
    });};
    return upstream;
  }};
  const module={exports:{}};
  vm.runInNewContext(readFileSync(require.resolve('./postgres/secureshopMailActualTransport'),'utf8'),{
    module,require:name=>name==='node:http'?fakeHttp:require(name),Buffer,AbortSignal,
    fetch:async()=>({ok:true,json:async()=>({models:[{name:'llama3.1:8b',digest:DIGEST}]})}),
    setTimeout:()=>0,clearTimeout:()=>{},
  });
  const transport=await module.exports.createMailActualTransport({protocol:PROTOCOL,maxHttpCalls:16});
  assert.notEqual(transport.actorUrl,transport.judgeUrl);
  async function post(origin){
    const req=Object.assign(new EventEmitter(),{method:'POST',url:'/api/chat',async *[Symbol.asyncIterator](){
      yield Buffer.from(JSON.stringify({model:'llama3.1:8b',messages:[]}));
    }});
    const res=new EventEmitter();res.writeHead=status=>{res.status=status;};res.end=()=>{};
    await handlers[origin](req,res);await Promise.resolve();return res.status;
  }
  try{
    assert.equal(await post(1),503);assert.equal(dispatched,0);assert.equal(transport.calls.length,0);
    assert.equal(await post(0),503);assert.equal(dispatched,1);
    assert.equal(transport.calls[0].kind,'actor');assert.equal(transport.calls[0].terminalReason,'upstream_error');
    for(let index=1;index<16;index++)assert.equal(await post(0),undefined);
    assert.equal(await post(0),503);assert.equal(await post(1),503);
    assert.equal(dispatched,16);assert.equal(transport.calls.length,16);
    assert(transport.calls.every(call=>call.kind==='actor'));
  }finally{await transport.close();}
});
