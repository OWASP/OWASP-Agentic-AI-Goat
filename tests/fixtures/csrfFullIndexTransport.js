'use strict';
// Transparent, bounded local transport only. It never supplies a model response.
const http=require('node:http'),{createHash}=require('node:crypto');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
const SELECTED_70B_MODEL='llama3.3:70b',SELECTED_70B_DIGEST='a6eb4748fd2990ad2952b2335a95a7f952d1a06119a0aa6a2df6cd052a93a3fa';
const MAX_RESPONSE_BYTES=4194304;
function qualificationModel(selected70b=false){
 if(typeof selected70b!=='boolean')throw TypeError('Closed CSRF model selection required');
 return Object.freeze(selected70b?{model:SELECTED_70B_MODEL,digest:SELECTED_70B_DIGEST}:{model:MODEL,digest:DIGEST});
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
async function createCsrfFullIndexTransport({record,maxHttpCalls=8,selected70b=false}={}){
 if(!Number.isInteger(maxHttpCalls)||maxHttpCalls<1||maxHttpCalls>18)throw TypeError('Bounded actual HTTP budget required');
 const {model:expectedModel,digest:expectedDigest}=qualificationModel(selected70b);
 const tags=await fetch('http://127.0.0.1:11434/api/tags',{signal:AbortSignal.timeout(5000)});if(!tags.ok)throw Error('Ollama preflight unavailable');
 const model=(await tags.json()).models?.find(row=>(row.name===expectedModel||row.model===expectedModel)&&row.digest===expectedDigest);if(!model)throw Error('Exact CSRF qualification model digest unavailable');
 const calls=[],servers=[],sockets=new Set(),upstreams=new Set();let closing=false;
 const hash=data=>createHash('sha256').update(data).digest('hex');
 async function listen(kind){
  const server=http.createServer(async(req,res)=>{
   if(!closing&&req.method==='GET'&&req.url==='/api/tags'){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({models:[model]}));return;}
   if(closing||req.method!=='POST'||!['/api/chat','/api/generate'].includes(req.url)||calls.length>=maxHttpCalls){res.writeHead(503);res.end();return;}
   let bytes=0;const parts=[];for await(const chunk of req){bytes+=chunk.length;if(bytes>262144){res.writeHead(413);res.end();return;}parts.push(chunk);}const body=Buffer.concat(parts);
   let parsed;try{parsed=JSON.parse(body);}catch{res.writeHead(400);res.end();return;}if(parsed.model!==expectedModel){res.writeHead(400);res.end();return;}
   if(calls.length>=maxHttpCalls){res.writeHead(503);res.end();return;}
   const call={index:calls.length+1,kind,endpoint:req.url,model:expectedModel,request:body.toString('utf8'),requestSha256:hash(body),requestBytes:body.length,startedAt:new Date().toISOString()};calls.push(call);record?.({modelDigest:expectedDigest,calls});
   const capture=createResponseCapture(call,{record:()=>record?.({modelDigest:expectedDigest,calls})});let timer;
   const upstream=http.request({hostname:'127.0.0.1',port:11434,path:req.url,method:'POST',headers:{'content-type':'application/json','content-length':body.length}},response=>{
    capture.headers(response.statusCode);res.writeHead(response.statusCode,{'content-type':response.headers['content-type']||'application/json'});
    response.on('data',chunk=>{if(!capture.data(chunk)){upstream.destroy(Error('Model response exceeds bound'));return;}res.write(chunk);});
    response.on('end',()=>{capture.finish(true,'end');res.end();});
    response.on('aborted',()=>capture.finish(false,'response_aborted'));response.on('error',error=>{call.error??=error.message;capture.finish(false,'response_error');});
   });
   upstreams.add(upstream);timer=setTimeout(()=>upstream.destroy(Error('Actual CSRF model60s deadline')),60000);
   upstream.on('close',()=>{clearTimeout(timer);upstreams.delete(upstream);capture.finish(false,'upstream_closed');});upstream.on('error',error=>{call.error=error.message;capture.finish(false,'upstream_error');record?.({modelDigest:expectedDigest,calls});if(!res.headersSent)res.writeHead(503);res.end();});res.on('close',()=>upstream.destroy());upstream.end(body);
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);return `http://127.0.0.1:${server.address().port}`;
 }
 try{const baseUrl=await listen('shared_actor_and_judge');return {baseUrl,model:expectedModel,digest:expectedDigest,calls,async close(){closing=true;for(const upstream of upstreams)upstream.destroy();for(const socket of sockets)socket.destroy();await Promise.all(servers.map(server=>new Promise(resolve=>server.close(resolve))));}};}catch(error){for(const server of servers)server.close();throw error;}
}
module.exports={createCsrfFullIndexTransport,createResponseCapture,qualificationModel};
