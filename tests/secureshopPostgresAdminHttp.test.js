'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module'),express=require('express');
test('native admin HTTP awaits repositories, ACL and tool DTOs; forwards rejected queries',async()=>{
 const original=Module._load, previous=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';
 const calls=[];const repository={kpis:async()=>({ok:true,total_users:13}),users:async args=>{calls.push(args);return{rows:[{id:1}],total:1};},trace:async()=>{throw Error('database unavailable');}};
 Module._load=function(name,parent,main){
  if(/sqlite/.test(name))throw Error('PostgreSQL admin imported SQLite');
  if(name.includes('secureshopAdminRepository'))return{getSecureShopAdminRepository:()=>repository};
  if(name.includes('adminSupervisor'))return{adminSupervisor:{}};
  if(name.includes('sessionStore'))return{
   createSession:async()=>({id:'fixture'}),
   getSession:async id=>({id,userId:1,role:'admin'}),
   runSessionExclusive:async(_id,operation)=>operation(),
  };
  if(name.includes('toolAcl'))return{listAllPermissions:async()=>[{tool_name:'fixture',role:'admin',allowed:1}],isEnforcementEnabled:async()=>true,setPermission:async()=>({ok:true}),setEnforcement:async()=>({ok:true})};
  if(name.includes('_ssAuthMiddleware'))return{requireRole:()=>((req,res,next)=>{req.ssUser={id:1,role:'admin'};next();}),verifyJwt:()=>({id:1,role:'admin'})};
  if(name.includes('user-management/tools'))return{setRole:async()=>({ok:true,changes:1})};
  return original.call(this,name,parent,main);
 };
 let server;
 try{
  const build=require('../server/routes/secureshop/admin');
  const app=express();app.use(express.json());app.use(build({pool:{},manifest:{},provider:{}}));app.use((err,req,res,next)=>res.status(500).json({error:err.message}));
  server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));const base=`http://127.0.0.1:${server.address().port}`;
  assert.equal((await(await fetch(base+'/admin/overview/kpis')).json()).total_users,13);
  const users=await(await fetch(base+'/admin/users?page=2&pageSize=3&search=fixture')).json();assert.equal(users.page,2);assert.equal(calls[0].pageSize,3);
  const acl=await(await fetch(base+'/admin/access-control')).json();assert.equal(acl.enforcement_enabled,true);assert.equal(acl.tools[0].admin,1);
  const role=await(await fetch(base+'/admin/users/1/role',{method:'POST',headers:{'content-type':'application/json'},body:'{"role":"admin"}'})).json();assert.equal(role.changes,1);
  const failure=await fetch(base+'/agents/admin/trace/fixture');assert.equal(failure.status,500);assert.equal((await failure.json()).error,'database unavailable');
 }finally{Module._load=original;if(previous===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=previous;if(server)await new Promise(resolve=>server.close(resolve));}
});
