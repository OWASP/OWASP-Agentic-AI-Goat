'use strict';
// Transparent, bounded local transport only. It never supplies a model response.
const http=require('node:http'),{createHash}=require('node:crypto');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const MAX_RESPONSE_BYTES=4194304;
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
 const v19=protocol==='v19-file-summary-v1',v29=protocol==='v29-agency-browser-v1',v34=protocol==='v34-manual-experiment-v1';
 const maximum=protocol==='v03-listing-optimize-v1'?27:v19?26:v29?9:v34?19:14;
 if(protocol!==undefined&&protocol!=='v03-listing-optimize-v1'&&!v19&&!v29&&!v34)throw TypeError('Closed actual HTTP protocol required');
 if(!Number.isInteger(maxHttpCalls)||maxHttpCalls<1||maxHttpCalls>maximum)throw TypeError('Bounded actual HTTP budget required');
 if(v19&&sharedStages!==false)throw TypeError('V19 requires separate actor and Judge origins');
 if(v29&&maxHttpCalls!==9)throw TypeError('V29 requires its exact nine-call physical budget');
 if(v29&&sharedStages!==false)throw TypeError('V29 requires separate actor and Judge origins');
 let total=0,actor=0,judge=0;
 return Object.freeze({
  reserve(kind) {
   if(total>=maxHttpCalls)return false;
   if(v19&&(!['actor','judge'].includes(kind)||(kind==='actor'?actor>=10:judge>=16)))return false;
   if(v29&&(!['actor','judge'].includes(kind)||(kind==='actor'?actor>=8:judge>=1)))return false;
   if(v34&&(!['actor','judge'].includes(kind)||(kind==='actor'?actor>=16:judge>=3)))return false;
   total++;if(kind==='actor')actor++;if(kind==='judge')judge++;
   return true;
  },
  snapshot:()=>Object.freeze({total,actor,judge}),
 });
}

async function createMailActualTransport({record,maxHttpCalls=14,allowMetadata=false,sharedStages=false,protocol}={}){
 if(typeof sharedStages!=='boolean')throw TypeError('Explicit shared stage policy required');
 if(typeof allowMetadata!=='boolean')throw TypeError('Explicit metadata policy required');
 const budget=createActualCallBudget({maxHttpCalls,protocol,sharedStages});
 const tags=await fetch('http://127.0.0.1:11434/api/tags',{redirect:'error',signal:AbortSignal.timeout(5000)});if(!tags.ok)throw Error('Ollama preflight unavailable');
 const model=(await tags.json()).models?.find(row=>(row.name===MODEL||row.model===MODEL)&&row.digest===DIGEST);if(!model)throw Error('Exact mail qualification model digest unavailable');
 const calls=[],servers=[],sockets=new Set(),upstreams=new Set();let closing=false,metadataCalls=0,stage=null;
 const hash=data=>createHash('sha256').update(data).digest('hex');
 async function listen(kind){
  const server=http.createServer(async(req,res)=>{
   if(!closing&&allowMetadata&&req.method==='GET'&&req.url==='/api/tags'){
    if(++metadataCalls>64){res.writeHead(429);return res.end();}
    try{const response=await fetch('http://127.0.0.1:11434/api/tags',{redirect:'error',signal:AbortSignal.timeout(5000)});if(!response.ok)throw Error('Model metadata unavailable');const value=await response.json();if(!value.models?.some(row=>(row.name===MODEL||row.model===MODEL)&&row.digest===DIGEST))throw Error('Pinned model changed');res.setHeader('content-type','application/json');return res.end(JSON.stringify(value));}catch{res.writeHead(503);return res.end();}
   }
   if(closing||req.method!=='POST'||req.url!=='/api/chat'||calls.length>=maxHttpCalls){res.writeHead(503);res.end();return;}
   let bytes=0;const parts=[];for await(const chunk of req){bytes+=chunk.length;if(bytes>262144){res.writeHead(413);res.end();return;}parts.push(chunk);}const body=Buffer.concat(parts);
   let parsed;try{parsed=JSON.parse(body);}catch{res.writeHead(400);res.end();return;}if(parsed.model!==MODEL){res.writeHead(400);res.end();return;}
   const observedKind=sharedStages?(stage||'unexpected'):kind;
   if(!budget.reserve(observedKind)){res.writeHead(503);res.end();return;}
   const call={index:calls.length+1,kind:observedKind,model:MODEL,request:body.toString('utf8'),requestSha256:hash(body),requestBytes:body.length,startedAt:new Date().toISOString()};calls.push(call);record?.({modelDigest:DIGEST,calls});
   const capture=createResponseCapture(call,{record:()=>record?.({modelDigest:DIGEST,calls})});let timer;
   const upstream=http.request({hostname:'127.0.0.1',port:11434,path:'/api/chat',method:'POST',headers:{'content-type':'application/json','content-length':body.length}},response=>{
    capture.headers(response.statusCode);res.writeHead(response.statusCode,{'content-type':response.headers['content-type']||'application/json'});
    response.on('data',chunk=>{if(!capture.data(chunk)){upstream.destroy(Error('Model response exceeds bound'));return;}res.write(chunk);});
    response.on('end',()=>{capture.finish(true,'end');res.end();});
    response.on('aborted',()=>capture.finish(false,'response_aborted'));response.on('error',error=>{call.error??=error.message;capture.finish(false,'response_error');});
   });
   upstreams.add(upstream);timer=setTimeout(()=>upstream.destroy(Error('Actual mail model60s deadline')),60000);
   upstream.on('close',()=>{clearTimeout(timer);upstreams.delete(upstream);capture.finish(false,'upstream_closed');});upstream.on('error',error=>{call.error=error.message;capture.finish(false,'upstream_error');record?.({modelDigest:DIGEST,calls});if(!res.headersSent)res.writeHead(503);res.end();});res.on('close',()=>upstream.destroy());upstream.end(body);
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);return `http://127.0.0.1:${server.address().port}`;
 }
 try{const actorUrl=await listen('actor'),judgeUrl=await listen('judge');return {actorUrl,judgeUrl,model:MODEL,digest:DIGEST,calls,metadataCount:()=>metadataCalls,setStage(value){if(!sharedStages||!['actor','judge'].includes(value))throw TypeError('Closed observed stage required');stage=value;},async close(){closing=true;for(const upstream of upstreams)upstream.destroy();for(const socket of sockets)socket.destroy();await Promise.all(servers.map(server=>new Promise(resolve=>server.close(resolve))));}};}catch(error){for(const server of servers)server.close();throw error;}
}
module.exports={createMailActualTransport,createResponseCapture,createActualCallBudget};
