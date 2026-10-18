'use strict';

const test=require('node:test');
const assert=require('node:assert/strict');
const {EventEmitter}=require('node:events');
const {createBoundRoleChatRouter}=require('../server/routes/secureshop/boundRoleChat');

const launch=Object.freeze({launchId:'10000000-0000-4000-8000-000000000001',scenarioId:'20000000-0000-4000-8000-000000000001',generation:1,platformOwnerId:4,platformSessionId:5});
const source=Object.freeze({sessionId:'30000000-0000-4000-8000-000000000001',requestId:'40000000-0000-4000-8000-000000000001',proposalId:'50000000-0000-4000-8000-000000000001'});
const admin=Object.freeze({id:9,role:'admin'});
const personaSession=Object.freeze({sessionId:'60000000-0000-4000-8000-000000000001',authorityVersion:'1'});

// Exercise the mounted production route stack. The effect services are
// deliberately stubbed: this file proves route parsing and trusted-context
// forwarding only; RoleChat authority is covered by its repository fixtures.
function invoke(router,path,{body,token='admin'}={}){
 const route=router.stack.find(layer=>layer.route?.path===path&&layer.route.methods.post)?.route;
 assert.ok(route,`mounted ${path} route required`);
 const req=new EventEmitter();Object.assign(req,{body,params:{},query:{},headers:{'x-dvaia-secureshop-launch':'a'.repeat(43),authorization:`Bearer ${token}`},rawHeaders:['x-dvaia-secureshop-launch','a'.repeat(43),'authorization',`Bearer ${token}`],is:type=>type==='application/json'});
 const res=new EventEmitter();Object.assign(res,{statusCode:200,writableEnded:false,destroyed:false,
  setHeader(){},set(){return this;},status(value){this.statusCode=value;return this;}});
 return new Promise((resolve,reject)=>{
  res.json=value=>{res.writableEnded=true;resolve({status:res.statusCode,body:value});return res;};
  let index=0;const next=error=>{if(error)return reject(error);const handler=route.stack[index++]?.handle;
   if(!handler)return reject(Error('mounted route did not finish'));try{Promise.resolve(handler(req,res,next)).catch(reject);}catch(cause){reject(cause);}};next();
 });
}

function fixture(){
 const calls=[];
 const runtime={
  async createSession(){return{id:source.sessionId};},async run(){},async readRequest(){return{};},
  async confirmUserAdministration(){},async confirmPolicy(){},async confirmSystemRestart(){},async confirmAcl(){},
  async readAuditJob(){return{status:'unconfirmed'};},async readAuditOperation(){return{status:'unconfirmed'};},async readSystemConfigOperation(){return{state:'unconfirmed'};},
  async runAuditJob(input){calls.push({kind:'audit',input});return{status:'completed',proposalId:input.proposalId};},
  async confirmMcpRegistry(input){calls.push({kind:'mcp',input});return{state:'completed',proposalId:input.proposalId};},
 };
 const router=createBoundRoleChatRouter({role:'admin',runtime,launches:{async resolveCapability(){return launch;}},authenticatePersona(req,_res,next){
  req.ssUser=req.headers.authorization==='Bearer merchant'?{id:6,role:'merchant'}:admin;req.ssPersonaSession=personaSession;next();
 }});
 return{calls,router};
}

for(const [kind,path] of [
 ['audit','/agents/admin/assistant/audit/job/run'],
 ['mcp','/agents/admin/assistant/mcp/confirm'],
]) test(`mounted admin ${kind} confirmation route closes its body and forwards the server context`,async()=>{
 const f=fixture();
 const malformed=await invoke(f.router,path,{body:{...source,confirmed:true}});
 assert.equal(malformed.status,400);assert.equal(f.calls.length,0,'closed request body prevents dispatch');
 const wrongRole=await invoke(f.router,path,{body:source,token:'merchant'});
 assert.equal(wrongRole.status,403);assert.equal(f.calls.length,0,'role guard prevents dispatch');
 const valid=await invoke(f.router,path,{body:source});
 assert.equal(valid.status,200);assert.equal(f.calls.length,1);
 const forwarded=f.calls[0];assert.equal(forwarded.kind,kind);
 assert.deepEqual(forwarded.input.scope,launch);assert.deepEqual(forwarded.input.persona,admin);
 assert.deepEqual(forwarded.input.personaSession,personaSession);
 assert.deepEqual(Object.fromEntries(['sessionId','requestId','proposalId'].map(key=>[key,forwarded.input[key]])),source);
 assert.ok(forwarded.input.signal instanceof AbortSignal);
});
