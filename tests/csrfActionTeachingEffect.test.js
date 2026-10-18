'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {withOwnerExecution}=require('../server/agent-runtime/ownerWorkflowRoutes');
const {createCsrfActionHandler}=require('../server/services/csrfActionHandler');
for(const blocked of [true,false])test(`token and defense decision captured inside lease; blocked=${blocked}`,async()=>{
 let held=false,modelCalls=0,status;const events=[],sent=[];
 const state={defenses:{csrfToken:!blocked},csrfToken:'old',attackLog:[]};
 const outside=name=>{assert.equal(held,false);events.push(name);};
 const sandbox={tab:()=>{assert.equal(held,true);events.push('read');return state;},getTabState:()=>{assert.equal(held,true);return{defenses:state.defenses,attackLog:state.attackLog};},flush:async()=>{assert.equal(held,true);events.push('flush');}};
 const execution={check:async()=>assert.equal(held,false),withTeachingEffect:async work=>{held=true;events.push('acquire');state.defenses.csrfToken=blocked;state.csrfToken='current';try{return await work();}finally{held=false;events.push('release');state.defenses.csrfToken=false;}}};
 const handler=createCsrfActionHandler({getUserKey:()=> '7',getUserId:()=>7,sessionIdFor:()=> 'csrf_7',tabOf:()=> 'get',detectForgedVector:()=> 'direct_get',victimSandbox:{VECTORS:{direct_get:{crossSite:true}},getOrCreateSandbox:()=>sandbox},csrfAgent:{chat:async()=>{outside('model');modelCalls++;return{response:'controlled',objectivesHit:[],victimState:{}};}},recordActivity:async()=>outside('activity'),getCompleted:async()=>new Set(),creditObjective:async()=>{outside('judge');return false;},pushCsrfEvent:(_owner,event)=>{outside('event');sent.push(event);},syncWorkshopStarted:async()=>outside('started')});
 await withOwnerExecution(execution,()=>handler({method:'POST',body:{message:'test',csrfToken:'old'},query:{}},{status:code=>{status=code;},setHeader:()=>{},send:()=>outside('response')}));
 assert.equal(status,blocked?403:200);assert.equal(modelCalls,blocked?0:1);
 assert.deepEqual(events.slice(0,blocked?4:3),blocked?['acquire','read','flush','release']:['acquire','read','release']);
 if(blocked){assert.equal(state.attackLog.length,1);assert.equal(sent[0].victimState.defenses.csrfToken,true);assert.equal(sent[0].toolResult.defenses.csrfToken,true);}
});
for(const tokenOn of [false,true])test(`fixed forged GET has no actor effect or attack credit; token defense=${tokenOn}`,async()=>{
 const state={defenses:{csrfToken:tokenOn,sameSite:tokenOn?'Strict':'None'},csrfToken:'owned',attackLog:[]};
 const sandbox={tab:()=>state,getTabState:()=>({victim:{balance:100},defenses:state.defenses}),flush:async()=>{}};
 const execution={check:async()=>{},withTeachingEffect:async work=>work()};
 let status,actorCalls=0,credits=0,modeChecks=0,observed;
 const handler=createCsrfActionHandler({getUserKey:()=> '7',getUserId:()=>7,sessionIdFor:()=> 'csrf_7',tabOf:()=> 'get',detectForgedVector:()=> 'direct_get',victimSandbox:{VECTORS:{direct_get:{crossSite:true,label:'GET'}},getOrCreateSandbox:()=>sandbox},canonicalMode:()=> 'fixed',assertCanonicalMode:async()=>{modeChecks++;},csrfAgent:{chat:async()=>{actorCalls++;throw Error('fixed actor must not run');}},recordActivity:async(_owner,_tab,_name,_args,result)=>{observed=result;},getCompleted:async()=>new Set(),creditObjective:async()=>{credits++;return false;},pushCsrfEvent:()=>{},syncWorkshopStarted:async()=>{}});
 await withOwnerExecution(execution,()=>handler({method:'GET',body:{},query:{message:'change email'}},{status:code=>{status=code;},setHeader:()=>{},send:()=>{}}));
 assert.equal(status,403);assert.equal(actorCalls,0);assert.equal(observed.blocked,true);assert.equal(observed.executed,false);assert.equal(observed.stateChanged,false);assert.equal(credits,tokenOn?1:0);assert.equal(modeChecks,2);assert.equal(state.attackLog.length,1);
});
