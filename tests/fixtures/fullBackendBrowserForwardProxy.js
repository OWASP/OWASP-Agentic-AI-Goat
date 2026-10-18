'use strict';
const http = require('node:http');
const { apiTimeout, backendEndpoint } = require('./fullBackendBrowserProxy');
async function createBrowserForwardProxy({ appOrigin, mcpChatTimeoutMs = 10000, secureShopTimeoutMs = 10000 }) {
  const upstream=backendEndpoint(appOrigin);
  apiTimeout('GET', '/', mcpChatTimeoutMs, secureShopTimeoutMs);
  const counters={allowed:0,denied:0,connectDenied:0,upgradeDenied:0,idlePreconnectTimeouts:0,
    browserTeardownResets:0,browserCancelledResets:0};
  const pending=new Set(),sockets=new Set(),deniedSockets=new WeakSet(),admittedSockets=new WeakSet(),
    browserCancelledSockets=new WeakSet(),unclassifiedResets=new Map(),socketFailures=[];
  const startedAt=process.hrtime.bigint();
  const elapsedMs=()=>Number((process.hrtime.bigint()-startedAt)/1000000n);
  let closing=false,browserTeardown=false,browserTeardownBeganAfterMs=null,browserTeardownLastResetAfterMs=null,
    browserCancelledLastResetAfterMs=null;
  const server=http.createServer((req,res)=>{
    admittedSockets.add(req.socket);
    let target;
    try {target=new URL(req.url);}catch {counters.denied++;res.writeHead(403);res.end('Denied');return;}
    if(target.protocol!=='http:'||target.origin!==upstream.origin||target.username||target.password||target.hash){
      counters.denied++;res.writeHead(403);res.end('Denied');return;
    }
    counters.allowed++;
    const headers={...req.headers,host:upstream.host};
    for(const name of ['proxy-authorization','proxy-connection','connection'])delete headers[name];
    const request=http.request({host:upstream.hostname,port:upstream.port,path:target.pathname+target.search,method:req.method,headers,
      timeout:apiTimeout(req.method,target.pathname,mcpChatTimeoutMs,secureShopTimeoutMs)},response=>{res.writeHead(response.statusCode,response.headers);response.pipe(res);});
    const cancel=()=>{
      if(!closing&&!browserTeardown){
        browserCancelledSockets.add(req.socket);
        const unresolved=unclassifiedResets.get(req.socket);
        if(unresolved){
          clearTimeout(unresolved.timer);
          unclassifiedResets.delete(req.socket);
          counters.browserCancelledResets++;browserCancelledLastResetAfterMs=elapsedMs();
        }
      }
      request.destroy();
    };
    const disconnect=()=>{if(!res.writableFinished)cancel();};
    pending.add(request);request.once('close',()=>pending.delete(request));
    request.on('timeout',()=>request.destroy(Error('Owned application proxy timeout')));
    request.on('error',()=>{if(!res.headersSent&&!res.destroyed)res.writeHead(502);if(!res.destroyed)res.end();});
    req.once('aborted',cancel);res.once('close',disconnect);req.pipe(request);
  });
  server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));
    // A denied peer or our own teardown can reset an owned socket. Preserve
    // errors outside those narrow cancellation cases as cleanup failures.
    socket.on('error',error=>{
      const denied=deniedSockets.has(socket),admitted=admittedSockets.has(socket);
      const idlePreconnect=error.code==='ERR_HTTP_REQUEST_TIMEOUT'&&socket.bytesRead===0&&!admitted&&!denied;
      const phase=closing?'closing':denied?'denied':browserTeardown?'browser-teardown':admitted?'admitted':socket.bytesRead>0?'partial':'active';
      const failure=()=>{
        const failure=new Error('Owned forward proxy socket error',{cause:error});
        failure.code=typeof error.code==='string'&&/^[A-Z0-9_]{1,64}$/.test(error.code)?error.code:'UNKNOWN';
        failure.phase=phase;
        return failure;
      };
      if(idlePreconnect)counters.idlePreconnectTimeouts++;
      else if((denied||closing||browserTeardown)&&['ECONNRESET','EPIPE'].includes(error.code)){
        if(browserTeardown&&!closing&&!denied){counters.browserTeardownResets++;browserTeardownLastResetAfterMs=elapsedMs();}
      }else if(admitted&&['ECONNRESET','EPIPE'].includes(error.code)){
        // Node can emit this before req.aborted and res.close. Retain the exact
        // failure until downstream cancellation is observed. Destroying here
        // would itself emit res.close and falsely supply cancellation proof.
        if(browserCancelledSockets.has(socket)){
          counters.browserCancelledResets++;browserCancelledLastResetAfterMs=elapsedMs();
        }else{
          const unresolved={failure:failure(),timer:null};
          unresolved.timer=setTimeout(()=>{
            if(unclassifiedResets.get(socket)!==unresolved)return;
            unclassifiedResets.delete(socket);socketFailures.push(unresolved.failure);
            socket.destroy();
          },1000);
          unresolved.timer.unref?.();
          unclassifiedResets.set(socket,unresolved);
          return;
        }
      }else{
        socketFailures.push(failure());
      }
      socket.destroy();
    });
  });
  server.on('connect',(_req,socket)=>{counters.connectDenied++;deniedSockets.add(socket);socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');});
  server.on('upgrade',(_req,socket)=>{counters.upgradeDenied++;deniedSockets.add(socket);socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');});
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  return {origin:`http://127.0.0.1:${server.address().port}`,
    counters:()=>({...counters,browserTeardownBeganAfterMs,browserTeardownLastResetAfterMs,
      browserCancelledLastResetAfterMs}),
    beginBrowserTeardown(){browserTeardown=true;if(browserTeardownBeganAfterMs===null)browserTeardownBeganAfterMs=elapsedMs();},
    async close(){closing=true;for(const request of pending)request.destroy();for(const socket of sockets)socket.destroy();server.closeAllConnections();await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));await new Promise(resolve=>setImmediate(resolve));for(const unresolved of unclassifiedResets.values()){clearTimeout(unresolved.timer);socketFailures.push(unresolved.failure);}unclassifiedResets.clear();if(socketFailures.length)throw new AggregateError(socketFailures,'Owned forward proxy socket failure');}};
}
module.exports={createBrowserForwardProxy};
