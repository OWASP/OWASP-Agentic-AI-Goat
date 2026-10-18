'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {createBoundUserAdministrationRouter:create}=require('../server/routes/secureshop/boundUserAdministration');
test('owned lookup route takes only username and verified original middleware credentials',async t=>{
 const calls=[];const scope={launchId:'trusted'},credential={sessionId:'original',authorityVersion:'2'};
 const app=express();app.use(express.json());app.use(create({service:{users(){},mutate(){},lookup:async input=>{calls.push(input);return{ok:true,synthetic:true,user:null};}},authenticatePersona(req,res,next){req.ssLaunch=scope;req.ssUser={id:3,role:req.headers['x-role']||'admin'};req.ssPersonaSession=credential;next();}}));
 const server=await new Promise(resolve=>{const value=app.listen(0,'127.0.0.1',()=>resolve(value));});t.after(()=>new Promise(resolve=>server.close(resolve)));
 const url=`http://127.0.0.1:${server.address().port}/admin/users/lookup`;
 const send=(body,role)=>fetch(url,{method:'POST',headers:{'content-type':'application/json',...(role?{'x-role':role}:{})},body:JSON.stringify(body)});
 assert.equal((await send({username:'student_admin'})).status,200);assert.deepEqual(calls[0],{scope,persona:{id:3,role:'admin'},personaSession:credential,username:'student_admin'});
 assert.equal((await send({username:'student_admin',personaSession:{sessionId:'forged'}})).status,400);
 assert.equal((await send({username:'student_admin'},'customer')).status,403);assert.equal(calls.length,1);
});
