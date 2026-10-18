'use strict';
// Test-only loopback proxy: forward one real POST, then discard its response.
const http=require('node:http');
async function createResponseLossProxy(upstream){
 const target=new URL(upstream);if(target.protocol!=='http:'||target.hostname!=='127.0.0.1')throw Error('Owned loopback upstream required');
 let dropNext=false;const counters={posts:0,gets:0,dropped:0};const sockets=new Set();
 const server=http.createServer((req,res)=>{
  if(req.method==='POST'&&req.url==='/operations')counters.posts++;
  if(req.method==='GET'&&req.url.startsWith('/operations/'))counters.gets++;
  const drop=dropNext&&req.method==='POST'&&req.url==='/operations';if(drop)dropNext=false;
  const outgoing=http.request(new URL(req.url,target),{method:req.method,headers:req.headers},incoming=>{
   if(drop){incoming.resume();incoming.once('end',()=>{counters.dropped++;res.destroy();});}
   else{res.writeHead(incoming.statusCode,incoming.headers);incoming.pipe(res);}
  });outgoing.once('error',()=>res.destroy());req.pipe(outgoing);
 });server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 return{origin:'http://127.0.0.1:'+server.address().port,counters,dropNext(){dropNext=true;},async close(){for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}};
}
module.exports={createResponseLossProxy};
