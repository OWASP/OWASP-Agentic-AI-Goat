import{compileBridgeOperation}from'./compiler.mjs';
import{createBridgeFetch}from'./fetchAdapter.mjs';
import{createHostTransport}from'./transport.mjs';
Object.assign(global,require('node:stream/web'));
global.MessagePort=require('node:worker_threads').MessagePort;
const web=require('undici');
global.Request=web.Request;global.Response=web.Response;global.Headers=web.Headers;
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
test('avatar multipart follows the typed frame bridge and preserves legacy upload isolation',async()=>{
 const calls=[];const bridge={request:async(...args)=>{calls.push(args);return{ok:true}}};
 const fetch=createBridgeFetch({bridge,origin:'https://shop.test'});const form=new FormData();
 form.append('sessionId',sessionId);form.append('requestId',requestId);form.append('message','Upload selected avatar');form.append('public','true');form.append('file',new Blob(['x'],{type:'image/png'}),'a.png');
 await fetch('/api/secureshop/agents/customer/avatar-upload/run',{method:'POST',body:form,headers:{accept:'application/json'}});
 expect(calls[0][0]).toBe('agent.customer.avatarUpload.run');expect(Object.keys(calls[0][1].fields)).toEqual(['sessionId','requestId','message','public']);
 expect(()=>compileBridgeOperation('uploads.create',calls[0][1])).toThrow();
 const compiled=compileBridgeOperation('agent.customer.avatarUpload.run',calls[0][1]);expect(compiled.path).toBe('/api/secureshop/agents/customer/avatar-upload/run');
 expect(compiled.body.file).toBeInstanceOf(Blob);
});
test('avatar saved routes are exact and lowercase UUID bound',()=>{
 expect(compileBridgeOperation('agent.customer.avatarUpload.request',{params:{requestId}}).path).toContain(`/requests/${requestId}`);
 expect(()=>compileBridgeOperation('agent.customer.avatarUpload.request',{params:{requestId:requestId.toUpperCase()}})).toThrow();
 expect(()=>compileBridgeOperation('agent.customer.avatarUpload.asset',{params:{operationId:requestId},body:{unexpected:true}})).toThrow();
});

function fakePort(){const listeners=new Set(),messages=[];return{messages,addEventListener:(_t,l)=>listeners.add(l),removeEventListener:(_t,l)=>listeners.delete(l),start(){},close(){},postMessage(m){messages.push(m);if(m.type==='start'||m.type==='chunk')queueMicrotask(()=>listeners.forEach(l=>l({data:{type:'pull',id:m.id}})));},dispatch:m=>listeners.forEach(l=>l({data:m}))}}
const waitFor=predicate=>new Promise((resolve,reject)=>{const started=Date.now();const check=()=>predicate()?resolve():Date.now()-started>1000?reject(Error('timeout')):setTimeout(check,0);check()});
test('host transport reconstructs exact avatar multipart without overriding content type',async()=>{
 const port=fakePort(),fetchImpl=jest.fn(async()=>new Response('{}',{status:200,headers:{'content-type':'application/json'}}));
 const transport=createHostTransport({port,origin:'https://shop.test',compileOperation:compileBridgeOperation,fetchImpl,getLaunchBearer:()=> 'a'.repeat(43)});
 try{const input={file:new Blob(['x'],{type:'image/png'}),filename:'a.png',fields:{sessionId,requestId,message:'Upload selected avatar',public:'true'}};
 port.dispatch({type:'request',id:1,operation:'agent.customer.avatarUpload.run',input,shopBearer:'persona'});await waitFor(()=>port.messages.some(m=>m.type==='end'||m.type==='error'));
 expect(port.messages.filter(m=>m.type==='error')).toEqual([]);const[url,options]=fetchImpl.mock.calls[0];expect(url).toBe('https://shop.test/api/secureshop/agents/customer/avatar-upload/run');
 expect(options.headers.has('Content-Type')).toBe(false);expect([...options.body.keys()]).toEqual(['sessionId','requestId','message','public','file']);expect(options.body.get('file')).toBeInstanceOf(Blob);
 }finally{transport.close();}
});
