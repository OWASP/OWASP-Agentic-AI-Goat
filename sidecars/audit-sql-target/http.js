'use strict';
const http=require('node:http');const {timingSafeEqual}=require('node:crypto');
function createPrivateAuditServer({token,backend,maxActive=2,admissions=true}={}){
 if(typeof token!=='string'||!/^[-_A-Za-z0-9]{43,128}$/.test(token)||!Number.isInteger(maxActive)||maxActive<1||maxActive>8)throw TypeError('Private service configuration required');
 for(const name of ['readiness','provision','search','retire','close'])if(typeof backend?.[name]!=='function')throw TypeError('Complete backend required');
 const pending=new Set();let active=0,closing=false;
 const server=http.createServer(async(req,res)=>{
  const supplied=Buffer.from(req.headers.authorization||''),expected=Buffer.from('Bearer '+token);
  if(supplied.length!==expected.length||!timingSafeEqual(supplied,expected)){res.writeHead(401).end();req.resume();return;}
  if(closing||active>=maxActive){res.writeHead(503).end();req.resume();return;}
  active++;let finish;const joined=new Promise(resolve=>{finish=resolve;});pending.add(joined);
  try{
   if(req.method!=='POST'||!['/readiness','/provision','/search','/retire','/receipt','/destroy','/target'].includes(req.url))throw Error('Invalid request');
   const chunks=[];let bytes=0;for await(const chunk of req){bytes+=chunk.length;if(bytes>17*1024*1024)throw Error('Request too large');chunks.push(chunk);}
   const body=JSON.parse(Buffer.concat(chunks).toString());
   if(!body||Array.isArray(body)||typeof body!=='object')throw Error('Invalid request');
   if(!admissions&&['/provision','/search'].includes(req.url))throw Error('New audit admissions disabled');
   const value=await backend[req.url.slice(1)](body);
   const output=JSON.stringify(value??{});if(Buffer.byteLength(output)>17*1024*1024)throw Error('Response too large');
   if(!res.destroyed)res.writeHead(200,{'content-type':'application/json'}).end(output);
  }catch(error){const code=['AUDIT_QUERY_UNCERTAIN','AUDIT_QUERY_CONFLICT','AUDIT_QUERY_RETIRED'].includes(error.code)?error.code:'AUDIT_TARGET_OPERATION_UNAVAILABLE';if(!res.destroyed)res.writeHead(409,{'content-type':'application/json'}).end(JSON.stringify({error:code}));}
  finally{active--;pending.delete(joined);finish();}
 });
 server.requestTimeout=10000;server.headersTimeout=10000;server.keepAliveTimeout=1000;
 return Object.freeze({server,
  async listen(port=0){await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,'127.0.0.1',resolve);});return server.address();},
  async close(){closing=true;const closed=new Promise(resolve=>server.close(resolve));server.closeIdleConnections();await Promise.all([...pending]);await backend.close();await closed;}
 });
}
module.exports={createPrivateAuditServer};
