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
 form.append('sessionId',sessionId);form.append('requestId',requestId);form.append('message','Upload selected avatar');form.append('public','true');form.append('logicalFilename','....//!escaped.txt');form.append('file',new Blob(['x'],{type:'image/png'}),'a.png');
 await fetch('/api/secureshop/agents/customer/avatar-upload/path-traversal/run',{method:'POST',body:form,headers:{accept:'application/json'}});
 expect(calls[0][0]).toBe('agent.customer.avatarTraversal.run');expect(Object.keys(calls[0][1].fields)).toEqual(['sessionId','requestId','message','public','logicalFilename']);
 expect(()=>compileBridgeOperation('uploads.create',calls[0][1])).toThrow();
 const compiled=compileBridgeOperation('agent.customer.avatarTraversal.run',calls[0][1]);expect(compiled.path).toBe('/api/secureshop/agents/customer/avatar-upload/path-traversal/run');
 expect(compiled.body.file).toBeInstanceOf(Blob);
});
test('avatar saved routes are exact and lowercase UUID bound',()=>{
 expect(compileBridgeOperation('agent.customer.avatarTraversal.request',{params:{requestId}}).path).toContain(`/requests/${requestId}`);
 expect(()=>compileBridgeOperation('agent.customer.avatarTraversal.request',{params:{requestId:requestId.toUpperCase()}})).toThrow();
 expect(()=>compileBridgeOperation('agent.customer.avatarTraversal.assess',{body:{sessionId,requestId,unexpected:true}})).toThrow();
});

function fakePort(){const listeners=new Set(),messages=[];return{messages,addEventListener:(_t,l)=>listeners.add(l),removeEventListener:(_t,l)=>listeners.delete(l),start(){},close(){},postMessage(m){messages.push(m);if(m.type==='start'||m.type==='chunk')queueMicrotask(()=>listeners.forEach(l=>l({data:{type:'pull',id:m.id}})));},dispatch:m=>listeners.forEach(l=>l({data:m}))}}
const waitFor=predicate=>new Promise((resolve,reject)=>{const started=Date.now();const check=()=>predicate()?resolve():Date.now()-started>1000?reject(Error('timeout')):setTimeout(check,0);check()});
test('host transport reconstructs exact avatar multipart without overriding content type',async()=>{
 const port=fakePort(),fetchImpl=jest.fn(async()=>new Response('{}',{status:200,headers:{'content-type':'application/json'}}));
 const transport=createHostTransport({port,origin:'https://shop.test',compileOperation:compileBridgeOperation,fetchImpl,getLaunchBearer:()=> 'a'.repeat(43)});
 try{const input={file:new Blob(['x'],{type:'image/png'}),filename:'a.png',fields:{sessionId,requestId,message:'Upload selected avatar',public:'true',logicalFilename:'....//!escaped.txt'}};
 port.dispatch({type:'request',id:1,operation:'agent.customer.avatarTraversal.run',input,shopBearer:'persona'});await waitFor(()=>port.messages.some(m=>m.type==='end'||m.type==='error'));
 expect(port.messages.filter(m=>m.type==='error')).toEqual([]);const[url,options]=fetchImpl.mock.calls[0];expect(url).toBe('https://shop.test/api/secureshop/agents/customer/avatar-upload/path-traversal/run');
 expect(options.headers.has('Content-Type')).toBe(false);expect([...options.body.keys()]).toEqual(['sessionId','requestId','message','public','logicalFilename','file']);expect(options.body.get('file')).toBeInstanceOf(Blob);
 }finally{transport.close();}
});

test('traversal multipart preserves logical filename and rejects duplicate or foreign fields', async()=>{
 const input={file:new Blob(['owned'],{type:'text/plain'}),filename:'source.txt',fields:{sessionId,requestId,message:'Upload avatar',public:'false',logicalFilename:'....//!owned.txt'}};
 const compiled=compileBridgeOperation('agent.customer.avatarTraversal.run',input);
 expect(compiled.body.fields.logicalFilename).toBe('....//!owned.txt');
 expect(()=>compileBridgeOperation('agent.customer.avatarUpload.run',input)).toThrow();
 for(const value of ['', 'x\0y', 'x\ny', 'x'.repeat(4097)])expect(()=>compileBridgeOperation('agent.customer.avatarTraversal.run',{...input,fields:{...input.fields,logicalFilename:value}})).toThrow();
 const form=new FormData();for(const [key,value]of Object.entries(input.fields))form.append(key,value);
 form.append('file',input.file,input.filename);form.append('logicalFilename','duplicate');
 const bridge={request:jest.fn()},fetch=createBridgeFetch({bridge,origin:'https://shop.test'});
 await expect(fetch('/api/secureshop/agents/customer/avatar-upload/path-traversal/run',{method:'POST',body:form})).rejects.toThrow();
 expect(bridge.request).not.toHaveBeenCalled();
});

test('traversal session and assessment keep exact route and ID-only contracts', async()=>{
 const calls=[],bridge={request:async(...args)=>{calls.push(args);return {ok:true};}};
 const fetch=createBridgeFetch({bridge,origin:'https://shop.test'}),base='/api/secureshop/agents/customer/avatar-upload/path-traversal';
 await fetch(`${base}/session`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
 await fetch(`${base}/assess`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({sessionId,requestId})});
 await fetch(`${base}/assessment/${sessionId}/${requestId}`,{method:'GET'});
 expect(calls.map(row=>row[0])).toEqual(['agent.customer.avatarTraversal.session','agent.customer.avatarTraversal.assess','agent.customer.avatarTraversal.assessment']);
 expect(()=>compileBridgeOperation('agent.customer.avatarTraversal.assessment',{params:{sessionId,requestId:requestId.toUpperCase()}})).toThrow();
 expect(()=>compileBridgeOperation('agent.customer.avatarTraversal.assess',{body:{sessionId,requestId,operationId:requestId}})).toThrow();
 expect(()=>compileBridgeOperation('agent.customer.avatarTraversal.session',{body:{ownerId:7}})).toThrow();
});
