'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const http=require('node:http'),{PassThrough}=require('node:stream');
const express=require('express');
const root=path.resolve(__dirname,'..');
const source=fs.readFileSync(path.join(root,'tests/postgres/secureshopV23PublicRendered.integration.test.js'),'utf8');
function middleware(){
 const start=source.indexOf('app.use(express.static(build');
 assert(start>=0);const end=source.indexOf(';app.get',start);assert(end>start);
 let selected;vm.runInNewContext(source.slice(start,end),{
  app:{use:value=>{selected=value;}},express,build:path.join(root,'tests/fixtures')});
 assert.equal(typeof selected,'function');return selected;
}
function request(method,url){
 return new Promise((resolve,reject)=>{
  const socket=new PassThrough();socket.resume();
  const req=new http.IncomingMessage(socket);req.method=method;req.url=url;
  req.headers={origin:'null',host:'localhost'};
  const res=new http.ServerResponse(req);res.set=express.response.set;res.assignSocket(socket);
  const timer=setTimeout(()=>finish(Error('static middleware did not terminate')),2000);
  function finish(error,fallthrough=false){
   clearTimeout(timer);const value={headers:res.getHeaders(),fallthrough,status:res.statusCode};
   socket.destroy();error?reject(error):resolve(value);
  }
  res.once('finish',()=>finish());res.once('error',finish);
  middleware()(req,res,error=>finish(error,true));
 });
}
test('opaque public module GET and HEAD receive CORS without credentials',async()=>{
 for(const method of ['GET','HEAD']){
  const result=await request(method,'/secureshopDarwinBrowserBirth.js');
  assert.equal(result.fallthrough,false);assert.equal(result.status,200);
  assert.equal(result.headers['access-control-allow-origin'],'*');
  assert.equal(result.headers['access-control-allow-credentials'],undefined);
 }
});
test('missing public asset, API path, and unsupported method do not leak static CORS',async()=>{
 for(const [method,url] of [['GET','/not-a-public-file.js'],['GET','/api/secureshop/auth/bootstrap'],['POST','/secureshopDarwinBrowserBirth.js']]){
  const result=await request(method,url);assert.equal(result.fallthrough,true);
  assert.equal(result.headers['access-control-allow-origin'],undefined);
 }
});
test('static CORS stays after protected API mounts and opaque sandbox is retained',()=>{
 const staticAt=source.indexOf('app.use(express.static(build');
 assert(source.indexOf("app.use('/api/secureshop/auth'")<staticAt);
 assert(source.indexOf("app.use('/api/secureshop',")<staticAt);
 assert.equal((source.match(/Access-Control-Allow-Origin/g)||[]).length,1);
 const handshake=fs.readFileSync(path.join(root,'client/src/pages/secureshop/bridge/handshake.mjs'),'utf8');
 assert(handshake.includes("frame.setAttribute('sandbox', 'allow-scripts allow-forms')"));
 assert(!handshake.includes("frame.setAttribute('sandbox', 'allow-scripts allow-forms allow-same-origin')"));
});
