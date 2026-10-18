'use strict';
const http=require('node:http'),crypto=require('node:crypto');
function createListingsManagerHttp({manager,controlToken,host='127.0.0.1',port=0}){
 if(!/^[A-Za-z0-9_-]{43,128}$/.test(controlToken||'')||typeof manager?.register!=='function'||typeof manager?.handleTarget!=='function')throw TypeError('Private manager required');
 const expected=Buffer.from('Bearer '+controlToken),pending=new Set();let closing=false;
 const send=(res,status,value)=>{if(!res.destroyed){res.writeHead(status,{'content-type':'application/json','cache-control':'no-store'});res.end(JSON.stringify(value));}};
 async function control(req,res){
  const actual=Buffer.from(req.headers.authorization||'');if(actual.length!==expected.length||!crypto.timingSafeEqual(actual,expected))return send(res,401,{error:'UNAUTHORIZED'});
  if(req.method==='GET'&&req.url==='/manager/health')return send(res,200,await manager.health());
  if(req.method!=='POST'||!['/targets','/targets/inspect','/targets/retire','/targets/forget'].includes(req.url))return send(res,404,{error:'NOT_FOUND'});
  let size=0;const chunks=[];for await(const chunk of req){size+=chunk.length;if(size>4096)throw Error('limit');chunks.push(chunk);}const value=JSON.parse(Buffer.concat(chunks));
  if(['/targets/retire','/targets/forget'].includes(req.url)){
   if(!value||Object.keys(value).sort().join(',')!=='canonicalReceiptSha256,mode,operationId,scope,targetId')throw Error('invalid');
   const {operationId,canonicalReceiptSha256,...binding}=value;return send(res,200,await manager[req.url==='/targets/retire'?'retire':'forget'](binding,{operationId,canonicalReceiptSha256}));
  }
  return send(res,200,await manager[req.url==='/targets'?'register':'inspect'](value));
 }
 const server=http.createServer({headersTimeout:5000,requestTimeout:20000,maxHeaderSize:8192},(req,res)=>{
  if(closing)return send(res,503,{error:'CLOSING'});
  const work=(req.url.startsWith('/targets')||req.url.startsWith('/manager/')?control(req,res):manager.handleTarget(req,res)).catch(()=>send(res,503,{error:'LISTINGS_MANAGER_UNAVAILABLE'}));
  pending.add(work);work.finally(()=>pending.delete(work));
 });server.maxConnections=256;
 return{async start(){await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});return server.address();},async close(){closing=true;await manager.close();await Promise.allSettled([...pending]);await new Promise(resolve=>{server.close(resolve);server.closeAllConnections();});}};
}
module.exports={createListingsManagerHttp};
