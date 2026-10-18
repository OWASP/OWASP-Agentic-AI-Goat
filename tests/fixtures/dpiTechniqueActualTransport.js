'use strict';
const {createHash}=require('node:crypto');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=code=>Object.assign(Error(code),{code});
const REQUEST_LIMIT=262144,RESPONSE_LIMIT=4194304;
function createTechniqueTransport({phase,fetch:upstream=global.fetch,record=()=>{},clock=()=>performance.now()}={}){
 if(!['A','B','RAG8'].includes(phase)||typeof upstream!=='function')throw fail('TRANSPORT_CONFIG');
 const maximumCases=phase==='RAG8'?8:phase==='A'?18:12,maximumHops=phase==='RAG8'?97:phase==='A'?73:109;
 const maximumExternal=phase==='RAG8'?49:37,maximumJudge=phase==='RAG8'?6:2,judgeMilliseconds=phase==='RAG8'?120000:90000;
 const calls=[],pending=new Set(),controllers=new Set(),unknownBodies=new Set(),servers=new Set(),sockets=new Set();let active=null,closed=false,metadata=null,initialized=false,external=0,hops=0,cases=0;
 const seen=new Set();
 function reserve(kind,scope){if(closed)throw fail('TRANSPORT_CLOSED');if(++hops>maximumHops)throw fail('HTTP_HOP_BUDGET');const row={index:calls.length+1,kind,caseId:scope?.id||null,status:'pending'};calls.push(row);record(snapshot());return row;}
 function snapshot(){return {phase,model:MODEL,modelDigest:DIGEST,hops,external,cases,calls:structuredClone(calls),physicalPending:pending.size+unknownBodies.size};}
 async function externalCall(path,body,deadline,scope){
  if(external>=maximumExternal)throw fail('EXTERNAL_BUDGET');external++;const row=reserve('external'+path,scope),controller=new AbortController();controllers.add(controller);
  row.request=body||'';row.requestBytes=Buffer.byteLength(row.request);row.requestSha256=sha(row.request);
  let timer,abortListener;const remaining=deadline-clock();if(remaining<=0){controllers.delete(controller);row.status='incomplete';throw fail('DEADLINE');}
  const chunks=[];let size=0;
  const retain=()=>{const bytes=Buffer.concat(chunks);row.response=bytes.toString('utf8');row.responseBytes=bytes.length;row.observedBytes=size;row.responseSha256=sha(bytes);};
  const task=(async()=>{
   const response=await upstream('http://127.0.0.1:11434'+path,{method:body?'POST':'GET',headers:body?{'content-type':'application/json'}:{},body:body||undefined,signal:controller.signal});
   row.httpStatus=response.status;
   if(!response.body?.getReader)throw fail('MISSING_WIRE');const reader=response.body.getReader();
   let consumed=false;
   try{while(true){const chunk=await reader.read();if(chunk.done){consumed=true;break;}size+=chunk.value.byteLength;if(size>RESPONSE_LIMIT){const remaining=RESPONSE_LIMIT-chunks.reduce((n,b)=>n+b.length,0);if(remaining>0)chunks.push(Buffer.from(chunk.value).subarray(0,remaining));throw fail('RESPONSE_LIMIT');}chunks.push(Buffer.from(chunk.value));if(clock()>=deadline)throw fail('DEADLINE');}}finally{if(!consumed){try{await reader.cancel('DPI bounded transport stopped');}catch(error){unknownBodies.add(reader);throw error;}}reader.releaseLock();}
   const bytes=Buffer.concat(chunks);row.response=bytes.toString('utf8');row.responseBytes=size;row.responseSha256=sha(bytes);
   if(response.status!==200)throw fail('HTTP_STATUS');if(clock()>=deadline||controller.signal.aborted)throw fail('DEADLINE');row.status='returned';return row.response;
  })();pending.add(task);task.catch(()=>{}).finally(()=>{pending.delete(task);controllers.delete(controller);});
  try{return await Promise.race([task,new Promise((_,reject)=>{abortListener=()=>reject(fail('CANCELLED'));controller.signal.addEventListener('abort',abortListener,{once:true});timer=setTimeout(()=>{reject(fail('DEADLINE'));controller.abort();},remaining);})]);}
  catch(error){controller.abort();retain();row.status='incomplete';row.errorCode=error.code||'TRANSPORT_ERROR';throw error;}
  finally{clearTimeout(timer);controller.signal.removeEventListener('abort',abortListener);record(snapshot());}
 }
 async function initialize(){if(initialized||closed)throw fail('METADATA_ALREADY_REQUESTED');initialized=true;
  const deadline=clock()+5000;const raw=await externalCall('/api/tags',null,deadline,null);const value=JSON.parse(raw);if(clock()>=deadline||closed)throw fail('DEADLINE');
  const model=value.models?.find(m=>(m.name===MODEL||m.model===MODEL)&&m.digest===DIGEST);if(!model)throw fail('MODEL_IDENTITY');
  metadata=JSON.stringify({models:[model]});return {model:MODEL,digest:DIGEST};
 }
 function beginCase(id){if(!metadata||closed||active||pending.size||unknownBodies.size||typeof id!=='string'||!id||seen.has(id)||cases>=maximumCases)throw fail('CASE_SCOPE');seen.add(id);cases++;active={id,actor:0,judge:0,tags:0,actorDeadline:null,judgeDeadline:null};}
 async function executeRequest(kind,{method,path,body='',signal}={},local){
  const scope=active;if(!scope||closed||!['actor','judge'].includes(kind)||pending.size||unknownBodies.size){local.status='incomplete';local.errorCode='CASE_SCOPE';record(snapshot());throw fail('CASE_SCOPE');}
  try{
  signal?.throwIfAborted();
  scope[kind+'Deadline']??=clock()+(kind==='actor'?120000:judgeMilliseconds);
  if(clock()>=scope[kind+'Deadline'])throw fail('DEADLINE');
   if(method==='GET'&&path==='/api/tags'&&kind==='actor'&&phase==='B'){
    if(++scope.tags>3)throw fail('LOCAL_METADATA_BUDGET');local.status='returned';local.responseSha256=sha(metadata);return {status:200,body:metadata};
   }
   if(method!=='POST'||path!=='/api/chat'||typeof body!=='string'||Buffer.byteLength(body)>REQUEST_LIMIT)throw fail('REQUEST_SHAPE');
   if(kind==='actor'&&(phase!=='B'||++scope.actor>1)||kind==='judge'&&++scope.judge>maximumJudge)throw fail('CASE_INFERENCE_BUDGET');
   const parsed=JSON.parse(body);if(parsed.model!==MODEL||parsed.stream!==true)throw fail('MODEL_REQUEST');
   local.request=body;local.requestBytes=Buffer.byteLength(body);local.requestSha256=sha(body);
   const field=kind+'Deadline';scope[field]??=clock()+(kind==='actor'?120000:judgeMilliseconds);
   const abort=()=>{for(const c of controllers)c.abort();};signal?.addEventListener('abort',abort,{once:true});
   let raw;try{raw=await externalCall('/api/chat',body,phase==='RAG8'?Math.min(scope[field],clock()+60000):scope[field],scope);signal?.throwIfAborted();}finally{signal?.removeEventListener('abort',abort);}
   const frames=raw.trim().split('\n').map(line=>JSON.parse(line));if(!frames.length||frames.at(-1).done!==true||frames.at(-1).done_reason!=='stop'||frames.some((f,i)=>f.model!==MODEL||f.error||i<frames.length-1&&f.done===true))throw fail('INCOMPLETE_TERMINATION');
   if(clock()>=scope[field]||closed)throw fail('DEADLINE');signal?.throwIfAborted();
   local.responseSha256=sha(raw);if(clock()>=scope[field]||closed)throw fail('DEADLINE');local.status='returned';return {status:200,body:raw};
  }catch(error){local.status='incomplete';local.errorCode=error.code||'TRANSPORT_ERROR';throw error;}finally{record(snapshot());}
 }
 async function request(kind,options={}){return executeRequest(kind,options,reserve('local:'+kind+':'+options.method+':'+options.path,active));}
 async function ingress(kind,req,res){
  let local;const controller=new AbortController();
  try{
   local=reserve('local:'+kind+':'+req.method+':'+req.url,active);
   req.on('aborted',()=>controller.abort());res.on('close',()=>{if(!res.writableFinished)controller.abort();});
   let size=0;const chunks=[];
   for await(const chunk of req){size+=chunk.length;local.observedRequestBytes=size;if(size>REQUEST_LIMIT)throw fail('REQUEST_LIMIT');chunks.push(chunk);}
   const result=await executeRequest(kind,{method:req.method,path:req.url,body:Buffer.concat(chunks).toString('utf8'),signal:controller.signal},local);res.writeHead(result.status,{'content-type':'application/x-ndjson'});res.end(result.body);
  }catch(error){if(local){local.status='incomplete';local.errorCode=error.code||'INGRESS_INCOMPLETE';record(snapshot());}res.writeHead(503);res.end();}
 }
 function endCase(){if(!active||pending.size||unknownBodies.size)throw fail('CASE_PENDING');active=null;}
 async function close(){closed=true;for(const c of controllers)c.abort();for(const socket of sockets)socket.destroy();const closing=[...servers].map(server=>new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve())));let timer;try{await Promise.race([Promise.all([Promise.allSettled([...pending]),Promise.all(closing)]),new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('PHYSICAL_TRANSPORT_PENDING')),5000);})]);}finally{clearTimeout(timer);}if(pending.size||unknownBodies.size)throw fail('PHYSICAL_TRANSPORT_PENDING');return snapshot();}
 async function listen(){
  if(closed||servers.size)throw fail('LISTENER_STATE');const urls={};
  try{for(const kind of phase!=='B'?['judge']:['actor','judge']){
   const server=require('node:http').createServer((req,res)=>ingress(kind,req,res));server.requestTimeout=5000;server.headersTimeout=5000;server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});servers.add(server);
   await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(fail('LISTENER_DEADLINE')),5000);server.once('error',error=>{clearTimeout(timer);reject(error);});server.listen(0,'127.0.0.1',()=>{clearTimeout(timer);resolve();});});urls[kind+'Url']='http://127.0.0.1:'+server.address().port;
  }return urls;}catch(error){await close();throw error;}
 }
 return {initialize,beginCase,request,ingress,endCase,listen,close,snapshot};
}
module.exports={createTechniqueTransport,MODEL,DIGEST,REQUEST_LIMIT,RESPONSE_LIMIT};
