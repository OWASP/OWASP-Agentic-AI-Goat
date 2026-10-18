'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module');
test('actual FinFlow chat route fences paused model before effects and publication',async t=>{
 let live=true,phase='normal',entered,release,effects=0,logs=0;
 const execution={check:async()=>{},effect:async function(key,work){return work();},trace:async()=>{}};
 class Agent{async runUserExclusive(id,work){return work({},execution);}async processMessage(a,b,c,d,e,f,{execution:run}){if(phase==='before-effect'){entered();await new Promise(r=>release=r);}await run.effect('owned',async()=>{effects++;});if(phase==='before-publication'){entered();await new Promise(r=>release=r);}return {success:true,response:'PRIVATE_FIN_FLOW_RESPONSE',toolCalls:[],completedObjectiveIds:[]};}}
 const stubs={
 '../database/sensitiveInfoWorkshopDb':{logToolCall:async()=>{logs++;}},
 '../services/sensitiveInfoWorkshopAgent':{SensitiveInfoWorkshopAgent:Agent,OBJECTIVES:[],createSensitiveInfoWorkshopStateStore:()=>({}),getConfiguredSsrfExamples:()=>[]},
 '../middleware/adminAuth':{authenticateToken:(req,res,next)=>{req.user={id:7};req.identitySession={id:11};next();}},
 '../services/postgresIdentityAdapter':{getPostgresIdentityAdapter:()=>({validateSession:async()=>live?{user:{id:7},session:{id:11,user_id:7}}:null})},
 '../services/workshopModeService':{getMode:async()=> 'fixed'},
 '../services/workshopModeHandlers':{createWorkshopModeHandlers:()=>({get(){},set(){}})},
 '../services/sensitiveInfoResetComposition':{createConfiguredFinflowTraversalManager:()=>({})},
 '../services/finflowAgentResourceComposition':{configuredFinflowAgentResources:()=>({})},
 '../services/postgresPlatformStores':{getPostgresPlatformStores:()=>({pool:{}})},
 '../services/finflowObjectiveAdmission':{createWorkshopObjectiveAdmission:()=>({admit:async()=>({generalChat:true})})},
 '../utils/progressSync':{checkAndMarkWorkshopComplete:async()=>{},syncObjectiveComplete:async()=>{}},
 '../utils/contextLogger':{info(){},error(){}},
 };
 const old=Module._load;Module._load=function(name,parent,isMain){if(Object.hasOwn(stubs,name))return stubs[name];if(/(?:^|\/)authDb(?:\.js)?$/.test(name))throw Error('legacy DB forbidden');return old.call(this,name,parent,isMain);};t.after(()=>{Module._load=old;});
 const routePath=require.resolve('../server/routes/sensitiveInfoWorkshop');delete require.cache[routePath];const router=require(routePath),express=require('express'),app=express();app.use(express.json());app.use(router);const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>server.close(resolve)));
 const send=()=>fetch(`http://127.0.0.1:${server.address().port}/chat`,{method:'POST',headers:{authorization:'Bearer private-controlled','content-type':'application/json'},body:JSON.stringify({userMessage:'Explain my account'})});
 assert.equal((await send()).status,200);assert.equal(effects,1);
 for(const kind of ['before-effect','before-publication']){live=true;phase=kind;const waiting=new Promise(resolve=>entered=resolve),before=effects,pending=send();await waiting;live=false;release();const response=await pending;assert.notEqual(response.status,200);assert.equal((await response.text()).includes('PRIVATE_FIN_FLOW_RESPONSE'),false);assert.equal(effects,before+(kind==='before-publication'?1:0));}
 assert.equal(logs,0);
});
