"use strict";
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createActualCallBudget,createMailActualTransport}=require('./postgres/secureshopMailActualTransport');
const make=()=>createActualCallBudget({protocol:'v19-file-summary-v1',maxHttpCalls:26});
const makeV29=()=>createActualCallBudget({protocol:'v29-agency-browser-v1',maxHttpCalls:9});
test('V19 reserves at most ten physical actor and sixteen physical Judge requests',()=>{
 const budget=make();
 for(let n=0;n<10;n++)assert.equal(budget.reserve('actor'),true);
 assert.equal(budget.reserve('actor'),false);
 for(let n=0;n<16;n++)assert.equal(budget.reserve('judge'),true);
 assert.equal(budget.reserve('judge'),false);
 assert.deepEqual(budget.snapshot(),{total:26,actor:10,judge:16});
});
test('V19 actor and Judge caps are independent in either order',()=>{
 const budget=make();
 for(let n=0;n<16;n++)assert.equal(budget.reserve('judge'),true);
 assert.equal(budget.reserve('judge'),false);
 assert.equal(budget.reserve('unexpected'),false);
 for(let n=0;n<10;n++)assert.equal(budget.reserve('actor'),true);
 assert.equal(budget.reserve('actor'),false);
 assert.deepEqual(budget.snapshot(),{total:26,actor:10,judge:16});
});
test('V19 lower explicit total stops physical dispatch before per-origin caps',()=>{
 const budget=createActualCallBudget({protocol:'v19-file-summary-v1',maxHttpCalls:3});
 assert.equal(budget.reserve('actor'),true);assert.equal(budget.reserve('judge'),true);
 assert.equal(budget.reserve('judge'),true);assert.equal(budget.reserve('actor'),false);
 assert.deepEqual(budget.snapshot(),{total:3,actor:1,judge:2});
});
test('V19 closed protocol rejects shared routing and excessive budgets before metadata',async()=>{
 const previous=global.fetch;let probes=0;
 global.fetch=async()=>{probes++;throw Error('controlled metadata boundary');};
 try {
  for(const options of [{protocol:'v19-file-summary-v1',maxHttpCalls:27},
   {protocol:'v19-file-summary-v1',maxHttpCalls:26,sharedStages:true},
   {protocol:'v19-other-v1',maxHttpCalls:26}])await assert.rejects(createMailActualTransport(options),TypeError);
  assert.equal(probes,0);
  await assert.rejects(createMailActualTransport({protocol:'v19-file-summary-v1',maxHttpCalls:26,allowMetadata:true}),/controlled metadata boundary/);
  assert.equal(probes,1);
 }finally{global.fetch=previous;}
});
test('V29 reserves at most eight physical actor and one physical Judge request',()=>{
 const budget=makeV29();
 for(let n=0;n<8;n++)assert.equal(budget.reserve('actor'),true);
 assert.equal(budget.reserve('actor'),false);
 assert.equal(budget.reserve('judge'),true);
 assert.equal(budget.reserve('judge'),false);
 assert.deepEqual(budget.snapshot(),{total:9,actor:8,judge:1});
 assert.throws(()=>createActualCallBudget({protocol:'v29-agency-browser-v1',maxHttpCalls:8}),TypeError);
 assert.throws(()=>createActualCallBudget({protocol:'v29-agency-browser-v1',maxHttpCalls:9,sharedStages:true}),TypeError);
});
test('Existing default and V03 protocols retain their budgets and shared-stage behavior',()=>{
 for(const [options,maximum] of [[{},14],[{protocol:'v03-listing-optimize-v1',maxHttpCalls:27,sharedStages:true},27]]) {
  const budget=createActualCallBudget(options);
  for(let n=0;n<maximum;n++)assert.equal(budget.reserve('actor'),true);
  assert.equal(budget.reserve('judge'),false);
 }
 assert.throws(()=>createActualCallBudget({maxHttpCalls:15}),TypeError);
 assert.throws(()=>createActualCallBudget({protocol:'v03-listing-optimize-v1',maxHttpCalls:28}),TypeError);
});
test('Actual HTTP handler spends V19 origin budgets before every upstream dispatch',async()=>{
 const {EventEmitter}=require('node:events');
 const {readFileSync}=require('node:fs');
 const vm=require('node:vm');
 const handlers=[];let dispatched=0;
 const fakeHttp={createServer(handler){handlers.push(handler);return {
  on(){},listen(port,host,ready){ready();},address(){return {port:20000+handlers.length};},close(done){done?.();},
 };},request(){dispatched++;const upstream=new EventEmitter();upstream.end=()=>{};upstream.destroy=()=>upstream.emit('close');return upstream;}};
 const module={exports:{}};
 vm.runInNewContext(readFileSync(require.resolve('./postgres/secureshopMailActualTransport'),'utf8'),{
  module,require:name=>name==='node:http'?fakeHttp:require(name),Buffer,AbortSignal,
  fetch:async()=>({ok:true,json:async()=>({models:[{name:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}]})}),
  setTimeout:()=>0,clearTimeout:()=>{},
 });
 const transport=await module.exports.createMailActualTransport({protocol:'v19-file-summary-v1',maxHttpCalls:26});
 async function post(index) {
  const req=Object.assign(new EventEmitter(),{method:'POST',url:'/api/chat',async *[Symbol.asyncIterator](){yield Buffer.from(JSON.stringify({model:'llama3.1:8b',messages:[]}));}});
  const res=new EventEmitter();res.writeHead=status=>{res.status=status;};res.end=()=>{};
  await handlers[index](req,res);return res.status;
 }
 try {
  for(let n=0;n<10;n++)await post(0);
  assert.equal(await post(0),503);assert.equal(dispatched,10);
  for(let n=0;n<16;n++)await post(1);
  assert.equal(await post(1),503);assert.equal(await post(0),503);
  assert.equal(dispatched,26);assert.equal(transport.calls.length,26);
  assert.equal(transport.calls.filter(call=>call.kind==='actor').length,10);
  assert.equal(transport.calls.filter(call=>call.kind==='judge').length,16);
 }finally{await transport.close();}
});

test('Actual HTTP handler rejects V29 Judge repair before upstream dispatch',async()=>{
 const {EventEmitter}=require('node:events');
 const {readFileSync}=require('node:fs');
 const vm=require('node:vm');
 const handlers=[];let dispatched=0;
 const fakeHttp={createServer(handler){handlers.push(handler);return {
  on(){},listen(port,host,ready){ready();},address(){return {port:21000+handlers.length};},close(done){done?.();},
 };},request(){dispatched++;const upstream=new EventEmitter();upstream.end=()=>{};upstream.destroy=()=>upstream.emit('close');return upstream;}};
 const module={exports:{}};
 vm.runInNewContext(readFileSync(require.resolve('./postgres/secureshopMailActualTransport'),'utf8'),{
  module,require:name=>name==='node:http'?fakeHttp:require(name),Buffer,AbortSignal,
  fetch:async()=>({ok:true,json:async()=>({models:[{name:'llama3.1:8b',digest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'}]})}),
  setTimeout:()=>0,clearTimeout:()=>{},
 });
 const transport=await module.exports.createMailActualTransport({protocol:'v29-agency-browser-v1',maxHttpCalls:9});
 async function post(index) {
  const req=Object.assign(new EventEmitter(),{method:'POST',url:'/api/chat',async *[Symbol.asyncIterator](){yield Buffer.from(JSON.stringify({model:'llama3.1:8b',messages:[]}));}});
  const res=new EventEmitter();res.writeHead=status=>{res.status=status;};res.end=()=>{};
  await handlers[index](req,res);return res.status;
 }
 try {
  for(let n=0;n<6;n++)assert.equal(await post(0),undefined);
  assert.equal(await post(1),undefined);assert.equal(await post(1),503);assert.equal(dispatched,7);
  assert.equal(await post(0),undefined);assert.equal(await post(0),undefined);assert.equal(await post(0),503);
  assert.equal(dispatched,9);assert.equal(transport.calls.length,9);
  assert.equal(transport.calls.filter(call=>call.kind==='actor').length,8);
  assert.equal(transport.calls.filter(call=>call.kind==='judge').length,1);
 }finally{await transport.close();}
});

test('V34 manual/experiment uses closed nineteen-call cap with sixteen actors and three bounded Judge stages',()=>{
 const {createActualCallBudget}=require('./postgres/secureshopMailActualTransport');
 const value=createActualCallBudget({protocol:'v34-manual-experiment-v1',maxHttpCalls:19,sharedStages:true});
 assert.equal(value.reserve('unexpected'),false);for(let i=0;i<16;i++)assert.equal(value.reserve('actor'),true);
 assert.equal(value.reserve('actor'),false);for(let i=0;i<3;i++)assert.equal(value.reserve('judge'),true);
 assert.equal(value.reserve('judge'),false);assert.deepEqual(value.snapshot(),{total:19,actor:16,judge:3});
 assert.throws(()=>createActualCallBudget({protocol:'v34-manual-experiment-v1',maxHttpCalls:20}));
});
