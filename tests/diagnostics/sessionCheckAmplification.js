'use strict';
// Read-only controlled call counters: no DB/provider; no production changes.
const {EventEmitter}=require('node:events');
const {createAdmittedPlatformSessionFence}=require('../../server/agent-runtime/admittedPlatformSession');
const {ownerWorkflowRoute,getOwnerExecution}=require('../../server/agent-runtime/ownerWorkflowRoutes');
const {createXssOwnerWorkflowRoute}=require('../../server/agent-runtime/xssOwnerWorkflowRoute');
const assert=require('node:assert/strict');
const request=()=>Object.assign(new EventEmitter(),{headers:{authorization:'Bearer controlled'},user:{id:7},identitySession:{id:11}});
async function measure(style,operation){const c={session:0,execution:0,mutationAdmission:0,callback:0,publication:0};const validateSession=async()=>{c.session++;return{user:{id:7},session:{id:11,user_id:7}};};const execution={check:async()=>{c.execution++;},effect:async(_key,work)=>work(),checkpoint:async()=>{}};const req=request();const action=async e=>{if(operation==='check')await e.check();if(operation==='effect')await e.effect('tool',async()=>{c.callback++;});if(operation==='checkpoint')await e.checkpoint('node');};
if(style==='single-wrap'){await action(createAdmittedPlatformSessionFence(req,{validateSession}).wrap(execution));return c;}
const res=Object.assign(new EventEmitter(),{headersSent:false,destroyed:false,json(){this.headersSent=true;},status(){return this;}});const coordinator={run:async(_owner,_options,work)=>work(execution)};
const handler=async(_req,response)=>{await action(getOwnerExecution());response.json({ok:true});};let route;
if(style==='EA')route=ownerWorkflowRoute(coordinator,()=>7,handler,{withAdmission:async(_owner,work,r)=>{const fence=createAdmittedPlatformSessionFence(r,{validateSession});await fence.check();return work({...fence,wrapOwnsAdmission:true,checkPublication:async()=>{c.publication++;await fence.check();}});}});
else route=createXssOwnerWorkflowRoute({coordinator,ownerFor:()=>7,postgres:true,validateSession,admit:async(_owner,work)=>work({ownerId:7,check:async()=>{c.mutationAdmission++;}}),pendingProfileReset:async()=>{}})(handler);
await route(req,res,()=>{});assert.equal(res.headersSent,true);return c;}
(async()=>{const result={};for(const style of ['single-wrap','EA','XSS']){result[style]={};for(const operation of ['none','check','effect','checkpoint'])result[style][operation]=await measure(style,operation);}assert.deepEqual(Object.fromEntries(Object.entries(result.EA).map(([k,v])=>[k,v.session])),{none:5,check:6,effect:9,checkpoint:7});assert.deepEqual(Object.fromEntries(Object.entries(result.XSS).map(([k,v])=>[k,[v.session,v.mutationAdmission]])),{none:[5,10],check:[6,14],effect:[9,30],checkpoint:[7,22]});console.log(JSON.stringify(result,null,2));})();
