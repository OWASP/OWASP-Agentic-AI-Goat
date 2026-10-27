'use strict';
// Transparent, bounded local transport only. It never supplies a model response.
const http=require('node:http'),{createHash}=require('node:crypto');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const MAX_RESPONSE_BYTES=4194304;
// Ordered, bounded diagnostics only: no URL, header, payload or error text.
function createLifecycleCapture(call,record){
 const allowed=new Set(['downstream_aborted','downstream_close_open','downstream_close_finished',
  'upstream_headers','upstream_end','upstream_error','upstream_close',
  'socket_reused','socket_fresh','socket_unknown','owner_cleanup_destroy',
  'recording_failure_destroy','deadline_destroy','response_bound_destroy']);
 call.lifecycle=[];let recording=false;
 return event=>{
  if(!allowed.has(event))throw TypeError('Closed lifecycle event required');
  if(call.lifecycle.length>=24)return;
  call.lifecycle.push(call.lifecycle.length===23?'truncated':event);
  if(recording)return;
  recording=true;try{record();}finally{recording=false;}
 };
}
function createResponseCapture(call,{record,now=()=>new Date().toISOString(),maxBytes=MAX_RESPONSE_BYTES}={}){
 if(!Number.isInteger(maxBytes)||maxBytes<1||maxBytes>MAX_RESPONSE_BYTES)throw TypeError('Bounded response capture required');
 const parts=[];let retained=0,observed=0,chunks=0,settled=false;
 return Object.freeze({
  headers(status){call.status=status;call.headersAt=now();record?.();},
  data(chunk){if(settled)return false;const bytes=Buffer.from(chunk),time=now();observed+=bytes.length;chunks++;call.firstDataAt??=time;call.lastDataAt=time;const take=Math.min(bytes.length,maxBytes-retained);if(take){parts.push(Buffer.from(bytes.subarray(0,take)));retained+=take;}return observed<=maxBytes;},
  finish(complete,reason){if(settled)return;settled=true;const body=Buffer.concat(parts);Object.assign(call,{responseBytes:retained,responseObservedBytes:observed,responseChunkCount:chunks,response:body.toString('utf8'),responseSha256:createHash('sha256').update(body).digest('hex'),responseComplete:complete===true&&observed===retained,responseCaptureTruncated:observed>retained,finishedAt:now(),terminalReason:reason});record?.();},
 });
}

// Reservations happen synchronously immediately before an upstream request.
// Failed or incomplete upstream calls retain their reservation; retries spend it.
function createActualCallBudget({maxHttpCalls=14,protocol,sharedStages=false}={}) {
 const v19=protocol==='v19-file-summary-v1',v29=protocol==='v29-agency-browser-v1',v34=protocol==='v34-manual-experiment-v1',v37=protocol==='v37-customer-consumption-v1',v30=protocol==='v30-customer-disclosure-actors-v2',v33=protocol==='v33-customer-pricing-v1',v39=protocol==='v39-mcp-description-atomic-arm-v1',v23=protocol==='v23-independent-judge-v1';
 const maximum=protocol==='v03-listing-optimize-v1'?27:v19?26:v29?9:v34?19:v37?6:v30?16:v33?6:14;
 if(protocol!==undefined&&protocol!=='v03-listing-optimize-v1'&&!v19&&!v29&&!v34&&!v37&&!v30&&!v33&&!v39&&!v23)throw TypeError('Closed actual HTTP protocol required');
 if(!Number.isInteger(maxHttpCalls)||maxHttpCalls<1||maxHttpCalls>maximum)throw TypeError('Bounded actual HTTP budget required');
 if(v19&&sharedStages!==false)throw TypeError('V19 requires separate actor and Judge origins');
 if(v29&&maxHttpCalls!==9)throw TypeError('V29 requires its exact nine-call physical budget');
 if(v29&&sharedStages!==false)throw TypeError('V29 requires separate actor and Judge origins');
 if(v37&&(maxHttpCalls!==6||sharedStages!==false))throw TypeError('V37 requires six physical actor calls and separate origins');
 if(v30&&(maxHttpCalls!==16||sharedStages!==false))throw TypeError('V30 requires sixteen physical actor calls and separate origins');
 if(v33&&(maxHttpCalls!==6||sharedStages!==false))throw TypeError('V33 requires aggregate four actor and two Judge calls on separate origins');
 if(v39&&(maxHttpCalls!==14||sharedStages!==false))throw TypeError('V39 atomic arm requires fourteen physical calls and separate origins');
 if(v23&&(maxHttpCalls!==2||sharedStages!==false))throw TypeError('V23 requires exactly two Judge-only physical calls');
 let total=0,actor=0,judge=0,failed=false;
 return Object.freeze({
  reserve(kind) {
   if(failed||total>=maxHttpCalls){if(v39)failed=true;return false;}
   if(v39&&(!['actor','judge'].includes(kind)||(kind==='actor'?actor>=13:judge>=4))){failed=true;return false;}
   if(v23&&kind!=='judge')return false;
   if((v37||v30)&&kind!=='actor')return false;
   if(v33&&(!['actor','judge'].includes(kind)||(kind==='actor'?actor>=4:judge>=2)))return false;
   if(v19&&(!['actor','judge'].includes(kind)||(kind==='actor'?actor>=10:judge>=16)))return false;
   if(v29&&(!['actor','judge'].includes(kind)||(kind==='actor'?actor>=8:judge>=1)))return false;
   if(v34&&(!['actor','judge'].includes(kind)||(kind==='actor'?actor>=16:judge>=3)))return false;
   total++;if(kind==='actor')actor++;if(kind==='judge')judge++;
   return true;
  },
  fail(){if(v39)failed=true;},
  snapshot:()=>Object.freeze(v39?{total,actor,judge,failed}:{total,actor,judge}),
 });
}

async function createMailActualTransport({record,maxHttpCalls=14,allowMetadata=false,sharedStages=false,protocol,pairArm,v23JudgeTarget}={}){
 let targetModel=MODEL,targetDigest=DIGEST,targetPort=11434;
 if(protocol==='v23-independent-judge-v1'){
  const checked=require('../../tasks/qualification/v23-independent-judge-channel').descriptor(v23JudgeTarget,v23JudgeTarget?.planSha256);
  targetModel=checked.model;targetDigest=checked.digest;targetPort=checked.port;
 }else if(v23JudgeTarget!==undefined)throw TypeError('V23-only owned Judge endpoint required');
 return createBoundTransport();
 async function createBoundTransport(){
 const MODEL=targetModel,DIGEST=targetDigest;
 if(typeof sharedStages!=='boolean')throw TypeError('Explicit shared stage policy required');
 if(typeof allowMetadata!=='boolean')throw TypeError('Explicit metadata policy required');
 if(record!==undefined&&typeof record!=='function')throw TypeError('Synchronous actual wire recorder required');
 if(protocol==='v39-mcp-description-atomic-arm-v1'
   ? !['control','treatment'].includes(pairArm) : pairArm!==undefined)
  throw TypeError('Exact V39 atomic arm required');
 const budget=createActualCallBudget({maxHttpCalls,protocol,sharedStages});
 const tags=await fetch(`http://127.0.0.1:${targetPort}/api/tags`,{redirect:'error',signal:AbortSignal.timeout(5000)});if(!tags.ok)throw Error('Ollama preflight unavailable');
 const model=(await tags.json()).models?.find(row=>(row.name===MODEL||row.model===MODEL)&&row.digest===DIGEST);if(!model)throw Error('Exact mail qualification model digest unavailable');
 const calls=[],servers=[],sockets=new Set(),upstreams=new Set(),handlers=new Set(),metadataControllers=new Set();
 const lifecycleByUpstream=new WeakMap();
 let closing=false,metadataCalls=0,stage=null,recordingError=null,closePromise;
 const hash=data=>createHash('sha256').update(data).digest('hex');
 const abortOwned=(event='owner_cleanup_destroy')=>{closing=true;for(const controller of metadataControllers)controller.abort();
  for(const upstream of upstreams){lifecycleByUpstream.get(upstream)?.(event);upstream.destroy();}for(const socket of sockets)socket.destroy();};
 const failRecording=cause=>{
  if(!recordingError)recordingError=Object.assign(new Error('Actual wire recording failed'),
    {code:'ACTUAL_WIRE_RECORDING_FAILED',cause});
  abortOwned('recording_failure_destroy');return false;
 };
 const recordWire=()=>{
  if(recordingError)return false;
  try{
   const result=record?.({modelDigest:DIGEST,calls});
   if(result&&typeof result.then==='function'){
    Promise.resolve(result).catch(()=>{});
    return failRecording(TypeError('Actual wire recorder must be synchronous'));
   }
   return true;
  }catch(error){return failRecording(error);}
 };
 const assertHealthy=()=>{if(recordingError)throw recordingError;};
 async function listen(kind){
  async function handle(req,res){
   if(!closing&&allowMetadata&&req.method==='GET'&&req.url==='/api/tags'){
    if(++metadataCalls>64){res.writeHead(429);return res.end();}
    const controller=new AbortController();metadataControllers.add(controller);
    try{const response=await fetch(`http://127.0.0.1:${targetPort}/api/tags`,{redirect:'error',signal:AbortSignal.any([AbortSignal.timeout(5000),controller.signal])});if(!response.ok)throw Error('Model metadata unavailable');const value=await response.json();if(closing)return;if(!value.models?.some(row=>(row.name===MODEL||row.model===MODEL)&&row.digest===DIGEST))throw Error('Pinned model changed');res.setHeader('content-type','application/json');return res.end(JSON.stringify(value));}catch{if(!closing){res.writeHead(503);return res.end();}}
    finally{metadataControllers.delete(controller);}return;
   }
   if(closing||req.method!=='POST'||req.url!=='/api/chat'){
    if(pairArm&&!closing)budget.fail();res.writeHead(503);res.end();return;
   }
   let bytes=0;const parts=[];for await(const chunk of req){bytes+=chunk.length;if(bytes>262144){res.writeHead(413);res.end();return;}parts.push(chunk);}const body=Buffer.concat(parts);
   if(closing)return;
   let parsed;try{parsed=JSON.parse(body);}catch{res.writeHead(400);res.end();return;}if(parsed.model!==MODEL){res.writeHead(400);res.end();return;}
   const observedKind=sharedStages?(stage||'unexpected'):kind;
   if(!budget.reserve(observedKind)){res.writeHead(503);res.end();return;}
   const call={index:calls.length+1,kind:observedKind,...(pairArm?{arm:pairArm}:{}),model:MODEL,request:body.toString('utf8'),requestSha256:hash(body),requestBytes:body.length,startedAt:new Date().toISOString()};calls.push(call);
   if(!recordWire()){call.error='ACTUAL_WIRE_RECORDING_FAILED';res.writeHead(503);res.end();return;}
   const capture=createResponseCapture(call,{record:recordWire});let timer;
   const event=createLifecycleCapture(call,recordWire);
   req.on('aborted',()=>event('downstream_aborted'));
   const upstream=http.request({hostname:'127.0.0.1',port:targetPort,path:'/api/chat',method:'POST',headers:{'content-type':'application/json','content-length':body.length}},response=>{
    event('upstream_headers');
    response.on('aborted',()=>capture.finish(false,'response_aborted'));
    response.on('error',error=>{call.error??=error.message;capture.finish(false,'response_error');});
    capture.headers(response.statusCode);if(recordingError)return;
    res.writeHead(response.statusCode,{'content-type':response.headers['content-type']||'application/json'});
    response.on('data',chunk=>{if(!capture.data(chunk)){event('response_bound_destroy');upstream.destroy(Error('Model response exceeds bound'));return;}if(!recordingError)res.write(chunk);});
    response.on('end',()=>{event('upstream_end');capture.finish(true,'end');if(!recordingError)res.end();});
   });
   lifecycleByUpstream.set(upstream,event);upstreams.add(upstream);
   upstream.on('socket',()=>event(upstream.reusedSocket===true?'socket_reused':upstream.reusedSocket===false?'socket_fresh':'socket_unknown'));
   timer=setTimeout(()=>{event('deadline_destroy');upstream.destroy(Error('Actual mail model60s deadline'));},60000);
   upstream.on('close',()=>{event('upstream_close');clearTimeout(timer);upstreams.delete(upstream);capture.finish(false,'upstream_closed');});upstream.on('error',error=>{call.error??=error.message;event('upstream_error');capture.finish(false,'upstream_error');if(recordingError)return;if(!res.headersSent)res.writeHead(503);res.end();});res.on('close',()=>{event(res.writableFinished?'downstream_close_finished':'downstream_close_open');upstream.destroy();});upstream.end(body);
  }
  const server=http.createServer((req,res)=>{
   const task=handle(req,res).catch(()=>{if(!closing&&!res.destroyed){
    try{if(!res.headersSent)res.writeHead(503);res.end();}catch{res.destroy();}
   }});
   handlers.add(task);task.then(()=>handlers.delete(task),()=>handlers.delete(task));
   return task;
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);return `http://127.0.0.1:${server.address().port}`;
 }
 try{const actorUrl=await listen('actor'),judgeUrl=await listen('judge');return {actorUrl,judgeUrl,model:MODEL,digest:DIGEST,calls,metadataCount:()=>metadataCalls,assertHealthy,budgetSnapshot:()=>budget.snapshot(),setStage(value){if(!sharedStages||!['actor','judge'].includes(value))throw TypeError('Closed observed stage required');stage=value;},async close(){
  if(!closePromise)closePromise=(async()=>{
   const outbound=[...upstreams].map(upstream=>new Promise(resolve=>upstream.once('close',resolve)));
   const inbound=[...sockets].map(socket=>new Promise(resolve=>socket.once('close',resolve)));
   const active=[...handlers];abortOwned();
   const serversClosed=servers.map(server=>new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve())));
   let timer;try{await Promise.race([
    Promise.all([...outbound,...inbound,...active,...serversClosed]),
    new Promise((_,reject)=>{timer=setTimeout(()=>reject(Object.assign(new Error('Actual transport cleanup unverified'),
     {code:'ACTUAL_TRANSPORT_CLEANUP_UNVERIFIED'})),5000);}),
   ]);}finally{clearTimeout(timer);}
   if(upstreams.size||sockets.size||handlers.size||metadataControllers.size)throw Object.assign(
    new Error('Actual transport cleanup unverified'),{code:'ACTUAL_TRANSPORT_CLEANUP_UNVERIFIED'});
  })();
  await closePromise;assertHealthy();
 }};}catch(error){for(const server of servers)server.close();throw error;}
}
}
// Each arm gets new actor/Judge listeners. A late request to a retired control
// origin therefore cannot be counted as treatment traffic. This coordinator
// does not itself qualify either arm; the rendered fixture joins its snapshots
// to the persisted source, Judge, and lifecycle evidence.
function createMcpDescriptionAtomicPairTransport({controlRunId,treatmentRunId,record}={}){
 const runId=/^[a-f0-9]{32}$/;
 if(!runId.test(controlRunId||'')||!runId.test(treatmentRunId||'')||controlRunId===treatmentRunId
   ||(record!==undefined&&typeof record!=='function'))throw TypeError('Distinct V39 pair runs and synchronous recorder required');
 const ids={control:controlRunId,treatment:treatmentRunId},rows=[],states={control:'waiting',treatment:'waiting'};
 let active=null,failed=false;
 const snapshot=()=>Object.freeze({protocol:'v39-mcp-description-atomic-pair-v1',failed,
  totalPhysical:rows.reduce((sum,row)=>sum+row.calls.length,0),
  arms:Object.freeze(Object.fromEntries(['control','treatment'].map(arm=>{
   const row=rows.find(value=>value.arm===arm),calls=row?.calls||[];
   return [arm,Object.freeze({runId:ids[arm],state:states[arm],physical:calls.length,
    actor:calls.filter(call=>call.kind==='actor').length,
    judge:calls.filter(call=>call.kind==='judge').length})];
  })))});
 return Object.freeze({snapshot,async beginArm(arm,identity){
  if(failed||active||!Object.hasOwn(ids,arm)||ids[arm]!==identity||states[arm]!=='waiting'
    ||(arm==='treatment'&&states.control!=='finished')){
   failed=true;throw TypeError('V39 pair arm sequence invalid');
  }
  active=arm;states[arm]='starting';
  try{
   const transport=await createMailActualTransport({protocol:'v39-mcp-description-atomic-arm-v1',
    pairArm:arm,maxHttpCalls:14,sharedStages:false,allowMetadata:true,
    record:value=>record?.(arm,value)});
   const row={arm,transport,calls:transport.calls};rows.push(row);states[arm]='running';
   return Object.freeze({arm,runId:identity,transport,async finish(){
    if(failed||active!==arm||states[arm]!=='running')throw TypeError('V39 pair arm not running');
    states[arm]='retiring';
    try{
     await transport.close();
     const budget=transport.budgetSnapshot();
     if(budget.failed||budget.total!==row.calls.length||budget.actor<7||budget.actor>13
       ||budget.judge<1||budget.judge>4||budget.total>14
       ||row.calls.some(call=>call.arm!==arm||call.status!==200||call.responseComplete!==true||call.error))
      throw Error('V39 physical arm incomplete');
     states[arm]='finished';active=null;return snapshot();
    }catch(error){failed=true;states[arm]='failed';throw error;}
   }});
  }catch(error){failed=true;states[arm]='failed';throw error;}
 },async close(){
  if(active){failed=true;states[active]='failed';}
  const errors=[];
  for(const row of rows){try{await row.transport.close();}catch(error){errors.push(error);}}
  if(errors.length)throw new AggregateError(errors,'V39 pair transport cleanup failed');
 }});
}
module.exports={createMailActualTransport,createResponseCapture,createActualCallBudget,createMcpDescriptionAtomicPairTransport};
