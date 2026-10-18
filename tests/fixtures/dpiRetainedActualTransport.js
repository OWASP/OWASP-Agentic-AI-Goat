'use strict';
// Transparent, bounded local transport only. It never supplies a model response.
const http=require('node:http'),{createHash}=require('node:crypto');
const MODEL='llama3.1:8b',DIGEST='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e';
async function createDpiRetainedActualTransport({record,maxHttpCalls=32,protocol}={}){
 if(!Number.isInteger(maxHttpCalls)||maxHttpCalls<1||maxHttpCalls>(['dpi-content-witness-v11','dpi-content-witness-v12'].includes(protocol)?72:48))throw TypeError('Bounded actual HTTP budget required');
 if(protocol!==undefined&&!['dpi-content-witness-v11','dpi-content-witness-v12','dpi-existential-v13','dpi-task-contribution-v14','dpi-whole-turn-disclosed-v1','dpi-whole-turn-references-disclosed-v1','dpi-compact-existential-disclosed-v1','dpi-grounded-predicates-disclosed-v1','dpi-response-passages-disclosed-v1'].includes(protocol))throw TypeError('Unknown diagnostic transport protocol');
 if(['dpi-content-witness-v11','dpi-content-witness-v12'].includes(protocol)&&maxHttpCalls!==72)throw TypeError('Exact versioned HTTP budget required');
 if((protocol==='dpi-existential-v13'||protocol==='dpi-task-contribution-v14'||protocol==='dpi-whole-turn-disclosed-v1'||protocol==='dpi-whole-turn-references-disclosed-v1'||protocol==='dpi-compact-existential-disclosed-v1'||protocol==='dpi-grounded-predicates-disclosed-v1'||protocol==='dpi-response-passages-disclosed-v1')&&maxHttpCalls!==48)throw TypeError('Exact existential HTTP budget required');
 const tags=await fetch('http://127.0.0.1:11434/api/tags',{signal:AbortSignal.timeout(5000)});if(!tags.ok)throw Error('Ollama preflight unavailable');
 const model=(await tags.json()).models?.find(row=>(row.name===MODEL||row.model===MODEL)&&row.digest===DIGEST);if(!model)throw Error('Exact DPI qualification model digest unavailable');
 const calls=[],servers=[],sockets=new Set(),upstreams=new Set();let closing=false;
 const hash=data=>createHash('sha256').update(data).digest('hex');
 async function listen(kind){
  const server=http.createServer(async(req,res)=>{
   if(!closing&&req.method==='GET'&&req.url==='/api/tags'){res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({models:[model]}));return;}
   if(closing||req.method!=='POST'||req.url!=='/api/chat'||calls.length>=maxHttpCalls){res.writeHead(503);res.end();return;}
   let bytes=0;const parts=[];for await(const chunk of req){bytes+=chunk.length;if(bytes>262144){res.writeHead(413);res.end();return;}parts.push(chunk);}const body=Buffer.concat(parts);
   let parsed;try{parsed=JSON.parse(body);}catch{res.writeHead(400);res.end();return;}if(parsed.model!==MODEL){res.writeHead(400);res.end();return;}
   if(calls.length>=maxHttpCalls){res.writeHead(503);res.end();return;}
   const call={index:calls.length+1,kind,model:MODEL,request:body.toString('utf8'),requestSha256:hash(body),requestBytes:body.length,startedAt:new Date().toISOString()};calls.push(call);record?.({modelDigest:DIGEST,calls});
   const responseParts=[];let responseBytes=0,timer;
   const upstream=http.request({hostname:'127.0.0.1',port:11434,path:'/api/chat',method:'POST',headers:{'content-type':'application/json','content-length':body.length}},response=>{
    call.status=response.statusCode;res.writeHead(response.statusCode,{'content-type':response.headers['content-type']||'application/json'});
    response.on('data',chunk=>{responseBytes+=chunk.length;if(responseBytes>4194304){upstream.destroy(Error('Model response exceeds bound'));return;}responseParts.push(chunk);res.write(chunk);});
    response.on('end',()=>{call.responseBytes=responseBytes;call.response=Buffer.concat(responseParts).toString('utf8');call.responseSha256=hash(Buffer.concat(responseParts));call.finishedAt=new Date().toISOString();record?.({modelDigest:DIGEST,calls});res.end();});
   });
   upstreams.add(upstream);timer=setTimeout(()=>upstream.destroy(Error('Actual DPI model60s deadline')),60000);
   upstream.on('close',()=>{clearTimeout(timer);upstreams.delete(upstream);});upstream.on('error',error=>{call.error=error.message;call.responseBytes=responseBytes;call.response=Buffer.concat(responseParts).toString('utf8');call.responseSha256=hash(Buffer.concat(responseParts));record?.({modelDigest:DIGEST,calls});if(!res.headersSent)res.writeHead(503);res.end();});res.on('close',()=>upstream.destroy());upstream.end(body);
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));servers.push(server);return `http://127.0.0.1:${server.address().port}`;
 }
 try{const actorUrl=await listen('actor'),judgeUrl=await listen('judge');return {actorUrl,judgeUrl,model:MODEL,digest:DIGEST,calls,async close(){closing=true;for(const upstream of upstreams)upstream.destroy();for(const socket of sockets)socket.destroy();await Promise.all(servers.map(server=>new Promise(resolve=>server.close(resolve))));}};}catch(error){for(const server of servers)server.close();throw error;}
}
module.exports={createDpiRetainedActualTransport};
