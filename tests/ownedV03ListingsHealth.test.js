'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),{EventEmitter}=require('node:events');
const health=require('./postgres/ownedV03ListingsHealth'),adapter=require('./postgres/ownedMcpOriginalBuildAdapter')._internals;
const client=JSON.parse(health.program().split('\n').find(line=>line.startsWith(' health_source=')).slice(15));
function run(status=200,row={version:1,ready:true,capability:'owned-listings-manager.v1',runtimeDigest:'digest'},oversize=false){
 const request=new EventEmitter(),response=new EventEmitter();let output='',destroyed=0,timer,options;
 request.destroy=()=>{destroyed++;};response.statusCode=status;
 const context={Buffer,process:{env:{LISTINGS_CONTROL_TOKEN:'private'},argv:['-e','digest'],stdout:{write:x=>{output+=x;}}},
  setTimeout:fn=>{timer=fn;return 1;},clearTimeout:()=>{},require:name=>{assert.equal(name,'node:http');return{get:(value,callback)=>{options=value;queueMicrotask(()=>{callback(response);response.emit('data',oversize?Buffer.alloc(16385):Buffer.from(JSON.stringify(row)));response.emit('end');});return request;}};}};
 vm.runInNewContext(client,context);return {request,context,get output(){return output;},get destroyed(){return destroyed;},get options(){return options;},timeout:()=>timer()};
}
test('actual emitted client authenticates only fixed loopback health and validates runtime',async()=>{
 const f=run();await new Promise(resolve=>setImmediate(resolve));assert.equal(f.output,'ready');
 assert.equal(f.options.host,'127.0.0.1');assert.equal(f.options.path,'/manager/health');assert.equal(f.options.headers.authorization,'Bearer private');
});
test('nonready, wrong runtime, oversized body and timeout never publish readiness',async()=>{
 for(const [status,row,oversize]of [[503,{},false],[200,{ready:true},false],[200,{},true]]){
  const f=run(status,row,oversize);await new Promise(resolve=>setImmediate(resolve));assert.equal(f.output,'not-ready');assert.equal(f.destroyed,1);
 }
 const f=run();f.timeout();await new Promise(resolve=>setImmediate(resolve));assert.equal(f.output,'not-ready');
});
test('actual legacy manager output is unchanged; V03 health precedes exclusive handoff',()=>{
 const captured={digest:'a',runtimeDigest:'b',workspaceId:'c',profileSha256:'d'},spec={mount:'/private',runId:'e'};
 const old=adapter.listingsManagerProgram(spec,'name','volume',captured,'resource','start');
 const explicitOld=adapter.listingsManagerProgram(spec,'name','volume',{...captured,v03Health:false},'resource','start');
 const current=adapter.listingsManagerProgram(spec,'name','volume',{...captured,v03Health:true},'resource','start');
 assert.equal(old,explicitOld);assert.equal(current.replace(health.program(),''),old);
 assert.ok(current.indexOf('health_end=')<current.indexOf("save('listings-manager-handoff.json'"));
 assert.equal(health.program().includes('except'),false); // Unknown Docker failure is never retried.
});
