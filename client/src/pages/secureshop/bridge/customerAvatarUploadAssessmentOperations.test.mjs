import{compileOperation}from'./operations.mjs';
import{createBridgeFetch}from'./fetchAdapter.mjs';
import{createHostTransport}from'./transport.mjs';
Object.assign(global,require('node:stream/web'));global.MessagePort=require('node:worker_threads').MessagePort;
const web=require('undici');global.Request=web.Request;global.Response=web.Response;global.Headers=web.Headers;
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
test('avatar assessment bridge compiles the exact POST and saved GET',()=>{
 expect(compileOperation('agent.customer.avatarUpload.assess',{body:{sessionId,requestId}})).toEqual({
  path:'/api/secureshop/agents/customer/avatar-upload/assess',method:'POST',responseKind:'json',body:{sessionId,requestId}});
 expect(compileOperation('agent.customer.avatarUpload.assessment',{params:{sessionId,requestId}})).toEqual({
  path:'/api/secureshop/agents/customer/avatar-upload/assess/'+sessionId+'/'+requestId,method:'GET',responseKind:'json'});
 expect(()=>compileOperation('agent.customer.avatarUpload.assess',{body:{sessionId,requestId,completed:true}})).toThrow();
 expect(compileOperation('agent.customer.avatarUpload.svgAssess',{body:{sessionId,requestId}})).toEqual({path:'/api/secureshop/agents/customer/avatar-upload/svg-assess',method:'POST',responseKind:'json',body:{sessionId,requestId}});
 expect(compileOperation('agent.customer.avatarUpload.svgAssessment',{params:{sessionId,requestId}})).toEqual({path:'/api/secureshop/agents/customer/avatar-upload/svg-assess/'+sessionId+'/'+requestId,method:'GET',responseKind:'json'});
 expect(()=>compileOperation('agent.customer.avatarUpload.svgAssess',{body:{sessionId,requestId,completed:true}})).toThrow();
 expect(()=>compileOperation('agent.customer.avatarUpload.svgAssess',{body:{sessionId:sessionId.toUpperCase(),requestId}})).toThrow();
 expect(()=>compileOperation('agent.customer.avatarUpload.svgAssessment',{params:{sessionId,requestId:requestId.toUpperCase()}})).toThrow();
});

test('frame fetch maps only exact SVG assessment POST and IDs-only GET',async()=>{
 const calls=[],bridge={request:async(...args)=>{calls.push(args);return new Response('{}',{status:200,headers:{'content-type':'application/json'}})}};
 const fetch=createBridgeFetch({bridge,origin:'https://shop.test'});
 await fetch('/api/secureshop/agents/customer/avatar-upload/svg-assess',{method:'POST',headers:{accept:'application/json','content-type':'application/json'},body:JSON.stringify({sessionId,requestId})});
 await fetch('/api/secureshop/agents/customer/avatar-upload/svg-assess/'+sessionId+'/'+requestId,{method:'GET',headers:{accept:'application/json'}});
 expect(calls.map(call=>call[0])).toEqual(['agent.customer.avatarUpload.svgAssess','agent.customer.avatarUpload.svgAssessment']);
 expect(calls[0][1]).toEqual({params:{},query:{},body:{sessionId,requestId}});expect(calls[1][1]).toEqual({params:{sessionId,requestId},query:{}});
 await expect(fetch('/api/secureshop/agents/customer/avatar-upload/svg-assess/'+sessionId+'/'+requestId,{method:'GET',headers:{'content-type':'application/json'},body:'{}'})).rejects.toThrow();
});
function fakePort(){const listeners=new Set(),messages=[];return{messages,addEventListener:(_t,l)=>listeners.add(l),removeEventListener:(_t,l)=>listeners.delete(l),start(){},close(){},postMessage(m){messages.push(m);if(m.type==='start'||m.type==='chunk')queueMicrotask(()=>listeners.forEach(l=>l({data:{type:'pull',id:m.id}})));},dispatch:m=>listeners.forEach(l=>l({data:m}))}}
const waitFor=predicate=>new Promise((resolve,reject)=>{const start=Date.now(),check=()=>predicate()?resolve():Date.now()-start>1000?reject(Error('timeout')):setTimeout(check,0);check()});
test('host transport emits exact SVG assessment POST and saved GET requests',async()=>{
 const port=fakePort(),fetchImpl=jest.fn(async()=>new Response('{}',{status:200,headers:{'content-type':'application/json'}}));
 const transport=createHostTransport({port,origin:'https://shop.test',compileOperation,fetchImpl,getLaunchBearer:()=> 'a'.repeat(43)});
 try{port.dispatch({type:'request',id:1,operation:'agent.customer.avatarUpload.svgAssess',input:{body:{sessionId,requestId}},shopBearer:'persona'});await waitFor(()=>port.messages.some(m=>m.type==='end'&&m.id===1));
  port.dispatch({type:'request',id:2,operation:'agent.customer.avatarUpload.svgAssessment',input:{params:{sessionId,requestId}},shopBearer:'persona'});await waitFor(()=>port.messages.some(m=>m.type==='end'&&m.id===2));
  expect(port.messages.filter(m=>m.type==='error')).toEqual([]);expect(fetchImpl).toHaveBeenCalledTimes(2);
  const [postUrl,post]=fetchImpl.mock.calls[0],[getUrl,get]=fetchImpl.mock.calls[1];expect(postUrl).toBe('https://shop.test/api/secureshop/agents/customer/avatar-upload/svg-assess');expect(post.method).toBe('POST');expect(JSON.parse(post.body)).toEqual({sessionId,requestId});
  expect(getUrl).toBe('https://shop.test/api/secureshop/agents/customer/avatar-upload/svg-assess/'+sessionId+'/'+requestId);expect(get.method).toBe('GET');expect(get.body).toBeUndefined();
 }finally{transport.close();}
});

test('legacy preview bridge keeps processing and grading distinct and accepts only original source IDs',async()=>{
 const calls=[],bridge={request:async(...args)=>{calls.push(args);return new Response('{}',{status:200,headers:{'content-type':'application/json'}})}};
 const fetch=createBridgeFetch({bridge,origin:'https://shop.test'}),base='/api/secureshop/agents/customer/avatar-upload';
 expect(compileOperation('agent.customer.avatarUpload.polyglotReadiness',{})).toEqual({path:base+'/polyglot-readiness',method:'GET',responseKind:'json'});
 for(const [post,get,suffix]of [['polyglotPreview','polyglotPreviewSaved','polyglot-preview'],['polyglotAssess','polyglotAssessment','polyglot-assess']]){
  expect(compileOperation('agent.customer.avatarUpload.'+post,{body:{sessionId,requestId}})).toEqual({path:base+'/'+suffix,method:'POST',responseKind:'json',body:{sessionId,requestId}});
  expect(compileOperation('agent.customer.avatarUpload.'+get,{params:{sessionId,requestId}})).toEqual({path:base+'/'+suffix+'/'+sessionId+'/'+requestId,method:'GET',responseKind:'json'});
  for(const body of [{sessionId,requestId,bytes:'untrusted'},{sessionId,requestId,operationId:requestId},{sessionId:sessionId.toUpperCase(),requestId}])expect(()=>compileOperation('agent.customer.avatarUpload.'+post,{body})).toThrow();
  expect(()=>compileOperation('agent.customer.avatarUpload.'+get,{params:{sessionId,requestId:requestId.toUpperCase()}})).toThrow();
  await fetch(base+'/'+suffix,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({sessionId,requestId})});
  await fetch(base+'/'+suffix+'/'+sessionId+'/'+requestId,{method:'GET'});
 }
 expect(calls.map(call=>call[0])).toEqual(['agent.customer.avatarUpload.polyglotPreview','agent.customer.avatarUpload.polyglotPreviewSaved','agent.customer.avatarUpload.polyglotAssess','agent.customer.avatarUpload.polyglotAssessment']);
});
