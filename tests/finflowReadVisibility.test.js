 'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),Module=require('node:module');
const projectRoot=process.env.DVAIA_TEST_PROJECT_ROOT || path.resolve(__dirname,'..');
const express=require('express');
const {WORKSHOP_OBJECTIVES}=require(path.join(projectRoot,'server/config/workshopCatalog'));
const objectives=WORKSHOP_OBJECTIVES.sensitive_info_disclosure.map(o=>({id:o.id,label:o.text,desc:'Controlled fixture'}));
const {createWorkshopObjectiveAdmission}=require(path.join(projectRoot,'server/services/finflowObjectiveAdmission'));
const presentation=require(path.resolve(path.dirname(process.env.DVAIA_TEST_ROUTE_FILE || path.join(projectRoot,'server/routes/sensitiveInfoWorkshop.js')), '../services/sensitiveInfoPresentation'));
const projection=require(path.join(projectRoot,'server/services/sensitiveInfoProgressProjection'));
async function fixture(t,options={}){
 const state={visible:true,enabled:new Set(objectives.map(o=>o.id)),reads:[],writes:[],admissions:0,...options};
 const pool={query:async()=>{state.admissions++;if(state.unavailable)throw Error('store offline');return{rows:[{is_visible:state.visible,exercise_active:true}]};}};
 const progress={getWorkshopProgress:async(owner,key)=>{state.reads.push({owner,key});if(state.hideDuringRead)state.visible=false;return{objectives:objectives.filter(o=>state.enabled.has(o.id)).map(o=>({id:o.id,label:'Canonical '+o.label,completed:false}))};}};
 const stubs={express,
 '../agent-runtime/finflowDecisions':require(path.join(projectRoot,'server/agent-runtime/finflowDecisions')),
 '../database/sensitiveInfoWorkshopDb':{engine:'postgres',ensureObjectives:async owner=>state.writes.push(['ensure',owner])},
 '../services/sensitiveInfoWorkshopAgent':{OBJECTIVES:objectives,getConfiguredSsrfExamples:gates=>gates.ssrf_internal?{ssrf_internal:{url:'http://fixture.invalid/ready'}}:{},SensitiveInfoWorkshopAgent:class{async runUserExclusive(){throw state.runError;}},createSensitiveInfoWorkshopStateStore:()=>({})},
 '../agent-runtime/admittedPlatformSession':{createAdmittedPlatformSessionFence:()=>({check:async()=>{},wrap:e=>e})},
 '../middleware/adminAuth':{authenticateToken:(req,res,next)=>{req.user={id:77};next();}},
 '../services/workshopModeService':{},'../services/workshopModeHandlers':{createWorkshopModeHandlers:()=>({get:(_q,r)=>r.end(),set:(_q,r)=>r.end()})},
 '../services/sensitiveInfoPresentation':presentation,'../services/sensitiveInfoProgressProjection':projection,'../utils/contextLogger':{error(){}},
 '../utils/progressSync':{syncWorkshopStarted:async(owner,key)=>state.writes.push(['started',owner,key])},
 '../services/sensitiveInfoResetComposition':{createConfiguredFinflowTraversalManager:()=>({}),getSensitiveInfoResetComposition:async()=>({reset:{reset:async()=>{throw state.runError;}}})},
 '../services/finflowAgentResourceComposition':{configuredFinflowAgentResources:()=>({assertReady:async()=>state.writes.push(['ready'])})},
 '../services/finflowObjectiveAdmission':{createWorkshopObjectiveAdmission},
 '../services/postgresPlatformStores':{getPostgresPlatformStores:()=>({pool,progress,config:{getSnapshot:async()=>({exercises:{sensitive_info_disclosure:{objectives:Object.fromEntries(objectives.map(o=>[o.id,{solutionVisible:state.enabled.has(o.id)&&state.solutionsVisible===true}]))}}})}})},
 };
 const file=process.env.DVAIA_TEST_ROUTE_FILE || path.resolve(__dirname,'../server/routes/sensitiveInfoWorkshop.js');const loaded=new Module(file,module);loaded.filename=file;loaded.require=id=>{if(Object.hasOwn(stubs,id))return stubs[id];throw Error('Unexpected route dependency: '+id);};loaded._compile(fs.readFileSync(file,'utf8'),file);
 const app=express();app.use(express.json());app.use(loaded.exports);const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve())));
 return{state,request:async(route,method='GET')=>{const r=await fetch('http://127.0.0.1:'+server.address().port+route,{method,...(route==='/chat'?{headers:{'content-type':'application/json'},body:JSON.stringify({userMessage:'Controlled'})}:{})});return{status:r.status,body:await r.json()};}};
}
test('init returns canonical enabled objectives, not the static eighteen-objective list',async t=>{const f=await fixture(t);f.state.enabled.delete(objectives[0].id);const r=await f.request('/init','POST');assert.equal(r.status,200);assert.equal(r.body.objectives.length,17);assert.ok(r.body.objectives.every(o=>o.label.startsWith('Canonical ')));assert.ok(!r.body.objectives.some(o=>o.id===objectives[0].id));assert.deepEqual(f.state.reads,[{owner:77,key:'sensitive_info_disclosure'}]);assert.equal(f.state.admissions,2);});
test('hidden exercise denies init and progress before state access or initialization',async t=>{const f=await fixture(t,{visible:false});for(const [route,method] of [['/init','POST'],['/progress/current','GET']]){const r=await f.request(route,method);assert.equal(r.status,403);assert.equal(r.body.code,'EXERCISE_UNAVAILABLE');}assert.deepEqual(f.state.writes,[]);assert.deepEqual(f.state.reads,[]);});
test('availability store failure fails closed with503 and no initialization',async t=>{const f=await fixture(t,{unavailable:true});for(const [route,method] of [['/init','POST'],['/progress/current','GET']]){const r=await f.request(route,method);assert.equal(r.status,503);assert.equal(r.body.code,'EXERCISE_AVAILABILITY_UNAVAILABLE');}assert.deepEqual(f.state.writes,[]);assert.deepEqual(f.state.reads,[]);});
test('progress uses authenticated owner and excludes disabled objectives',async t=>{const f=await fixture(t);f.state.enabled.delete(objectives[1].id);const r=await f.request('/progress/999999');assert.equal(r.status,200);assert.equal(r.body.total,17);assert.ok(!r.body.progress.some(o=>o.id===objectives[1].id));assert.deepEqual(f.state.reads,[{owner:77,key:'sensitive_info_disclosure'}]);});
test('exercise hidden during canonical read is not disclosed by either endpoint',async t=>{for(const [route,method] of [['/init','POST'],['/progress/current','GET']]){const f=await fixture(t,{hideDuringRead:true});const r=await f.request(route,method);assert.equal(r.status,403);assert.equal(r.body.code,'EXERCISE_UNAVAILABLE');assert.equal(r.body.progress,undefined);assert.equal(r.body.objectives,undefined);}});

test("progress refreshes gated examples through the current route",async t=>{const f=await fixture(t);let r=await f.request("/progress/current");assert.deepEqual(r.body.ssrfExamples,{});f.state.solutionsVisible=true;r=await f.request("/progress/current");assert.equal(r.body.ssrfExamples.ssrf_internal.url,"http://fixture.invalid/ready");f.state.solutionsVisible=false;r=await f.request("/progress/current");assert.deepEqual(r.body.ssrfExamples,{});assert.equal(r.body.solutionStatus.ssrf_internal,false);});

test('mounted FinFlow chat capacity503 preserves cancel409 and ordinary500',async t=>{const f=await fixture(t,{runError:Object.assign(Error('private capacity detail'),{code:'GRAPH_RUN_CAPACITY_EXCEEDED',statusCode:503})});let r=await f.request('/chat','POST');assert.equal(r.status,503);assert.deepEqual(r.body,{error:'Agent capacity is unavailable.',code:'GRAPH_RUN_CAPACITY_EXCEEDED'});f.state.runError=Object.assign(Error('cancel'),{name:'AbortError'});assert.equal((await f.request('/chat','POST')).status,409);f.state.runError=Error('ordinary');assert.equal((await f.request('/chat','POST')).status,500);});

test('mounted FinFlow reset capacity503 preserves reset conflict and ordinary failure',async t=>{const f=await fixture(t,{runError:Object.assign(Error('private capacity detail'),{code:'GRAPH_RUN_CAPACITY_EXCEEDED',statusCode:503})});let r=await f.request('/progress/reset','POST');assert.equal(r.status,503);assert.equal(r.body.code,'GRAPH_RUN_CAPACITY_EXCEEDED');f.state.runError=Object.assign(Error('cancel'),{name:'AbortError'});assert.equal((await f.request('/progress/reset','POST')).status,409);f.state.runError=Error('ordinary');assert.equal((await f.request('/progress/reset','POST')).status,500);});
