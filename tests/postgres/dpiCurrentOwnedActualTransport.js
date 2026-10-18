'use strict';
// Transparent proxy for the current production DPI route. Importing is inert.
const assert=require('node:assert/strict'),http=require('node:http'),fs=require('node:fs'),path=require('node:path');
const {performance}=require('node:perf_hooks'),{AsyncLocalStorage}=require('node:async_hooks');
const C=require('../fixtures/dpiCurrentOwnedContractV2');
const {createResponseCapture}=require('./secureshopMailActualTransport');
const {saveBounded}=require('../fixtures/boundedJsonArtifact');
const context=new AsyncLocalStorage(),token=Object.freeze({});
const allowsUpstream=()=>context.getStore()===token;
function assertDeadline(deadline,now=performance.now()){assert(now<deadline,'DPI absolute dispatch deadline');}
function validateResponse(row){
 if(row.kind!=='tags')return C.responseText(row);
 assert.equal(row.status,200);assert.equal(row.responseComplete,true);assert.equal(row.responseCaptureTruncated,false);assert.equal(C.sha(row.response),row.responseSha256);
 assert(JSON.parse(row.response).models?.some(x=>(x.name===C.MODEL||x.model===C.MODEL)&&x.digest===C.DIGEST));
 return null;
}
async function retire({upstreams,sockets,handlers,servers},timeoutMs=5000){
 assert(Number.isInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=5000);let timer;
 try{const waits=[...upstreams,...sockets].map(r=>new Promise(resolve=>r.once('close',resolve)));
  for(const resource of [...upstreams,...sockets])resource.destroy();
  waits.push(...servers.map(s=>new Promise((resolve,reject)=>s.close(e=>e&&e.code!=='ERR_SERVER_NOT_RUNNING'?reject(e):resolve()))),...handlers);
  await Promise.race([Promise.all(waits),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('DPI physical cleanup timeout')),timeoutMs);})]);
  assert.equal(upstreams.size+sockets.size+handlers.size,0);
 }finally{clearTimeout(timer);}
}
async function createTransport({evidence}){
 assert.equal(fs.realpathSync(evidence),evidence);const st=fs.lstatSync(evidence);assert(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o777)===0o700);
 const calls=[],failures=[],sockets=new Set(),upstreams=new Set(),handlers=new Set(),servers=[];
 const budget=C.createBudget(),end=performance.now()+C.TOTAL.workMs;let caseEnd=null,closing=false,closePromise;
 const snapshot=()=>({version:'dpi-current-owned-wire-v1',model:C.MODEL,digest:C.DIGEST,counts:{...budget.counts},calls,failures,physicalPending:sockets.size+upstreams.size,handlersPending:handlers.size,closed:closing&&!sockets.size&&!upstreams.size&&!handlers.size});
 function checkpoint(){const value=snapshot(),bytes=Buffer.byteLength(JSON.stringify(value))+1,file=path.join(evidence,'actual-model-wire.json');const old=fs.existsSync(file)?fs.statSync(file).size:0;assert(old+bytes<=128*1024*1024,'DPI aggregate wire/temp ceiling');saveBounded(file,value);}
 function fail(index,code){failures.push({index,code});}
 async function forward(kind,method,url,body,downstream){
  assert(!closing&&failures.length===0);budget.reserve(kind);const deadline=Math.min(end,caseEnd??end,performance.now()+(kind==='tags'?5000:C.TOTAL.wireMs));
  const row={index:calls.length,kind,caseId:budget.active?.id??null,method,path:url,request:body.toString(),requestBytes:body.length,requestSha256:C.sha(body),terminal:'pending'};calls.push(row);checkpoint();
  return new Promise((resolve,reject)=>{
   let timer,settled=false,upstream;const capture=createResponseCapture(row);
   const disconnected=()=>{if(!downstream.writableFinished)upstream?.destroy(Error('DPI consumer closed'));};
   const finish=error=>{if(settled)return;settled=true;row.terminal=error?'incomplete':'returned';if(error)fail(row.index,'WIRE_INCOMPLETE');try{checkpoint();}catch(e){error??=e;}error?reject(error):resolve(row);};
   try{assertDeadline(deadline);upstream=context.run(token,()=>http.request({hostname:'127.0.0.1',port:11434,path:url,method,headers:{'content-type':'application/json','content-length':body.length}},response=>{
    capture.headers(response.statusCode);downstream?.writeHead(response.statusCode,{'content-type':response.headers['content-type']||'application/json'});
    response.on('data',chunk=>{if(!capture.data(chunk)){upstream.destroy(Error('DPI response cap'));return;}downstream?.write(chunk);});
    response.once('end',()=>{capture.finish(true,'end');try{assertDeadline(deadline);const parsed=validateResponse(row);assertDeadline(deadline);if(parsed)row.doneReason=parsed.doneReason;downstream?.end();finish();}catch(error){downstream?.destroy();upstream.destroy(error);finish(error);}});
    response.once('aborted',()=>{capture.finish(false,'aborted');finish(Error('DPI response aborted'));});
    response.once('error',error=>{capture.finish(false,'error');finish(error);});
   }));}catch(error){capture.finish(false,'dispatch_denied');finish(error);return;}
   upstreams.add(upstream);timer=setTimeout(()=>upstream.destroy(Error('DPI wire deadline')),Math.max(1,deadline-performance.now()));
   upstream.once('close',()=>{clearTimeout(timer);upstreams.delete(upstream);downstream?.off('close',disconnected);capture.finish(false,'closed');if(!settled)finish(Error('DPI incomplete close'));});
   upstream.once('error',error=>{capture.finish(false,'error');downstream?.destroy();finish(error);});
   downstream?.once('close',disconnected);upstream.end(body);
  });
 }
 async function listen(role){
  const server=http.createServer((req,res)=>{
   const pending=(async()=>{let timer;try{assert(!closing&&failures.length===0);assertDeadline(Math.min(end,caseEnd??end));timer=setTimeout(()=>req.destroy(),5000);let n=0;const chunks=[];for await(const chunk of req){n+=chunk.length;assert(n<=262144);chunks.push(chunk);}clearTimeout(timer);const body=Buffer.concat(chunks);const kind=C.validateRequest(role,req.method,req.url,body,budget.active);if(kind==='review'){const actor=calls.filter(row=>row.caseId===budget.active.id&&row.kind==='actor').at(-1);assert(actor&&actor.terminal==='returned');assert.equal(JSON.parse(JSON.parse(body).messages[1].content).candidateResponse,C.responseText(actor).text);}await forward(kind,req.method,req.url,body,res);}catch{fail(null,'REQUEST_DENIED_OR_INCOMPLETE');if(!res.headersSent)res.writeHead(503);res.end();}finally{clearTimeout(timer);}})();
   handlers.add(pending);pending.finally(()=>handlers.delete(pending));
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});servers.push(server);
  await new Promise((resolve,reject)=>{const error=e=>reject(e);server.once('error',error);server.listen(0,'127.0.0.1',()=>{server.off('error',error);resolve();});});return `http://127.0.0.1:${server.address().port}`;
 }
 async function close(){
  if(closePromise)return closePromise;closing=true;
  closePromise=(async()=>{try{await retire({upstreams,sockets,handlers,servers});}finally{checkpoint();}})();return closePromise;
 }
 try{
  await forward('tags','GET','/api/tags',Buffer.alloc(0));const actorUrl=await listen('actor'),judgeUrl=await listen('judge');
  return {actorUrl,judgeUrl,model:C.MODEL,digest:C.DIGEST,allowsUpstream,close,
   beginCase(id){assert(!closing&&failures.length===0);assert.equal(upstreams.size+handlers.size,0);assertDeadline(end);budget.begin(id);caseEnd=Math.min(end,performance.now()+C.TOTAL.turnMs);},
   async endCase(){let timer;try{const waits=[...upstreams].map(r=>new Promise(resolve=>r.once('close',resolve)));waits.push(...handlers);await Promise.race([Promise.all(waits),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('DPI case drain timeout')),5000);})]);assert.equal(upstreams.size+handlers.size,0,'Physical requests must retire before next case');assertDeadline(caseEnd);budget.end();caseEnd=null;checkpoint();}finally{clearTimeout(timer);}},
   snapshot(){return structuredClone(snapshot());},
   assertComplete(){assert.equal(failures.length,0);assert.equal(budget.active,null);assert.equal(budget.attempted,C.TOTAL.turns);assert.equal(upstreams.size+handlers.size,0);for(const row of calls)validateResponse(row);}
  };
 }catch(error){try{await close();}catch(cleanup){throw new AggregateError([error,cleanup],'DPI transport setup and cleanup');}throw error;}
}
module.exports={createTransport,allowsUpstream,assertDeadline,validateResponse,retire};
