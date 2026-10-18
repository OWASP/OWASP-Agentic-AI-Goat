'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
const routePath=require.resolve('../server/routes/ctf');
const actualCoordinator=require('../server/agent-runtime/runCoordinator');
function fixture(){
 let entered=0,validations=0,current={user:{id:701},session:{id:11,user_id:701}};const original=Module._load;
 const helpers={getConfig:async()=> 'true',findActiveParticipant:async owner=>{assert.equal(owner,701);entered++;return null;}};
 const load=function(request,parent,isMain){
  if(parent?.filename===routePath&&request==='../agent-runtime/runCoordinator')return{createRunCoordinator:options=>actualCoordinator.createRunCoordinator({...options,ledger:null})};
  if(parent?.filename===routePath&&request==='../database/ctfDb')return{engine:'postgres',CTFHelpers:helpers};
  if(parent?.filename===routePath&&request==='../services/postgresIdentityAdapter')return{getPostgresIdentityAdapter:()=>({async validateSession(token){assert.equal(token,'canonical-token');validations++;return current;}})};
  if(request==='../services/multiProviderAIService'||request==='./multiProviderAIService')return{};
  if(parent?.filename===routePath&&request==='../utils/contextLogger')return{error(){}};
  return original.call(this,request,parent,isMain);
 };
 Module._load=load;let router;try{delete require.cache[routePath];router=require(routePath).router;}finally{Module._load=original;delete require.cache[routePath];}
 const handler=router.stack.find(x=>x.route?.path==='/stage/:stageId/attempt').route.stack.at(-1).handle;
 return{set(value){current=value;},counts:()=>({entered,validations}),async invoke(overrides={}){const req={user:{id:701},identitySession:{id:11},headers:{authorization:'Bearer canonical-token'},params:{stageId:'1'},body:{payload:'Public status.'},...overrides};const res={statusCode:200,status(n){this.statusCode=n;return this;},json(body){this.body=body;return this;}};Module._load=load;try{await handler(req,res,error=>{if(error)throw error;});return res;}finally{Module._load=original;}}};
}
test('CTF coordinated attempt requires current canonical owner and session before participant lookup',async()=>{
 const f=fixture(),response=await f.invoke();assert.equal(response.statusCode,400);assert.equal(response.body.error,'Not registered for CTF');assert.equal(f.counts().entered,1);assert(f.counts().validations>=2);
});
test('missing bearer or mismatched/revoked session denies admission without challenge access',async()=>{
 for(const current of[null,{user:{id:702},session:{id:11,user_id:702}},{user:{id:701},session:{id:12,user_id:701}},{user:{id:701},session:{id:11,user_id:702}}]){const f=fixture();f.set(current);assert.equal((await f.invoke()).statusCode,401);assert.equal(f.counts().entered,0);}
 const f=fixture();assert.equal((await f.invoke({headers:{}})).statusCode,401);assert.equal(f.counts().entered,0);assert.equal(f.counts().validations,0);
});
