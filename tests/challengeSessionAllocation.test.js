'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const express=require('express'),session=require('express-session');
const {createPostgresSessionManager}=require('../server/middleware/postgresSessionManager');
test('PostgreSQL teaching-session configuration persists no anonymous or bearer metadata-only sessions',async t=>{
 const store=new session.MemoryStore();
 const entry=fs.readFileSync(path.join(__dirname,'../server/applicationServer.js'),'utf8');
 const runtime=fs.readFileSync(path.join(__dirname,'../server/services/teachingSessionRuntime.js'),'utf8');
 const start=runtime.indexOf('const middleware = session({'),end=runtime.indexOf('\n  const resolveAuthority',start);
 assert.ok(start>0&&end>start);
 assert.ok(entry.indexOf('app.use(teachingSessionProduction.middleware)')<entry.indexOf('app.use(sessionManager.middleware())'));
 const context={store,secret:'controlled-teaching-secret',session:options=>{
  assert.equal(options.saveUninitialized,false);assert.equal(options.cookie.httpOnly,false);assert.equal(options.cookie.sameSite,'lax');
  return session({...options,store});
 }};
 vm.runInNewContext(runtime.slice(start,end)+'\nglobalThis.result=middleware;',context);const middleware=context.result;
 const manager=createPostgresSessionManager({jwtSecret:'fixture',repository:{touchSession:async()=>{},cleanupExpiredSessions:async()=>{}},
  validateSession:async token=>token==='owned'?{user:{id:7},session:{id:71,expires_at:new Date(Date.now()+3600000),device_info:{private:'metadata'}}}:null,
  userDto:user=>user});
 const app=express();app.use(middleware);app.use(manager.middleware());
 for(const route of ['/api/monitoring/ping','/static/fixture.css','/event-gate/status'])app.get(route,(_req,res)=>res.json({ok:true}));
 app.get('/current',(req,res)=>res.json({user:req.user,sessionKeys:Object.keys(req.session||{}).filter(k=>k!=='cookie')}));
 app.get('/lab-bind',(req,res)=>{Object.assign(req.session,{userId:7,username:'learner',platformOwnerId:7,platformSessionId:71});res.json({ok:true});});
 app.use((_req,res)=>res.status(404).json({error:'Not found'}));
 const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 t.after(async()=>{manager.stopCleanupTask();await new Promise(r=>server.close(r));});
 const base='http://127.0.0.1:'+server.address().port;
 const length=()=>new Promise((resolve,reject)=>store.length((e,n)=>e?reject(e):resolve(n)));
 for(const route of ['/api/monitoring/ping','/static/fixture.css','/event-gate/status','/missing']){
  const res=await fetch(base+route);await res.text();assert.equal(res.headers.get('set-cookie'),null);assert.equal(await length(),0);
 }
 const res=await fetch(base+'/current',{headers:{authorization:'Bearer owned'}}),body=await res.json();
 assert.equal(body.user.id,7);assert.deepEqual(body.sessionKeys,[]);assert.equal(res.headers.get('set-cookie'),null);assert.equal(await length(),0);
 const bound=await fetch(base+'/lab-bind');await bound.text();assert.ok(bound.headers.get('set-cookie'));assert.equal(await length(),1);
});
