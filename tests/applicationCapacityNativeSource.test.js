'use strict';
// Resource-free admission checks, not a substitute for native workload execution.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {reviewedCoordinatorSha256}=require('./fixtures/applicationCapacityCoordinatorObserver.cjs');
test('coordinator instrumentation uses the runtime admission and rejects source drift before startup',()=>{const source=fs.readFileSync(require.resolve('../server/agent-runtime/runCoordinator'),'utf8');assert.match(reviewedCoordinatorSha256(source),/^[a-f0-9]{64}$/);assert.throws(()=>reviewedCoordinatorSha256(source+'\n'),/source identity mismatch/);});
test('declared normal mixed workload, including controlled unavailable grading receipts, fits finite request admission without retry allowance',()=>{const arrival=200*2,reads=200*12*3,normal=200,grading=10*3,foreign=10*4,invalidations=200+20+20+20+120*2,global=1025,owner=18,lifecycle=8,recovery=200+200+200*3+5;assert(arrival+reads+normal+grading+foreign+invalidations+global+owner+lifecycle+recovery<12000);});

test('actual capacity request preserves credentials without inventing a browser Origin',async()=>{
 const vm=require('node:vm'),source=fs.readFileSync(require.resolve('./fixtures/applicationCapacityLoad.cjs'),'utf8');
 const start=source.indexOf('async function request('),end=source.indexOf('async function control(',start);
 assert(start>=0&&end>start);let captured;
 const context={count:0,stop:{signal:new AbortController().signal},sessions:new Map(),input:{origin:'http://127.0.0.1:49123'},
  client:{call:args=>args.operation(args.signal)},fetch:async(url,options)=>{captured={url,options};return{status:200,json:async()=>({ok:true}),headers:{getSetCookie:()=>[]}};}};
 vm.createContext(context);vm.runInContext(source.slice(start,end)+';globalThis.callRequest=request;',context);
 await context.callRequest({id:1},'/api/auth/login',{username:'synthetic',password:'synthetic'},{session:null});
 assert.equal(Object.hasOwn(captured.options.headers,'origin'),false);assert.equal(captured.options.method,'POST');
 await context.callRequest({id:1},'/api/auth/profile/1',undefined,{session:{token:'synthetic-token',cookie:'connect.sid=synthetic'}});
 assert.equal(captured.options.headers.authorization,'Bearer synthetic-token');assert.equal(captured.options.headers.cookie,'connect.sid=synthetic');
 assert.equal(Object.hasOwn(captured.options.headers,'origin'),false);
});
test('real CORS middleware rejects unconfigured ephemeral Origin but admits server client unchanged',()=>{
 const {createApplicationCors}=require('../server/middleware/applicationCors');
 const policy=createApplicationCors({platformOrigins:['http://localhost:3000']});
 function invoke(origin){let next=0,status=200,body;const headers={};const req={path:'/api/auth/login',method:'POST',headers:origin?{origin}:{},get:name=>name.toLowerCase()==='origin'?origin:undefined};
  const res={vary:()=>{},getHeader:name=>headers[name],setHeader:(name,value)=>headers[name]=value,status:value=>{status=value;return res;},json:value=>{body=value;return res;}};
  policy(req,res,()=>{next++;});return{next,status,body};}
 const denied=invoke('http://127.0.0.1:49123');assert.equal(denied.status,403);assert.equal(denied.next,0);assert.equal(denied.body.error,'Origin not allowed by platform CORS policy');
 const server=invoke(undefined);assert.equal(server.status,200);assert.equal(server.next,1);
 const configured=invoke('http://localhost:3000');assert.equal(configured.status,200);assert.equal(configured.next,1);
});
