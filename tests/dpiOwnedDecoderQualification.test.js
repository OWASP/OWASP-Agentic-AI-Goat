'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
test('owned decoder qualification uses identical prospective encoded payload in distinct canonical modes',()=>{
 const {scopedCases,decoded}=require('./fixtures/dpiOwnedDecoderCases'),cases=scopedCases();assert.equal(cases.actors.length,2);assert.equal(cases.actors[0].request,cases.actors[1].request);assert.deepEqual(cases.actors.map(c=>c.mode),['vuln','fixed']);assert.equal(cases.actors[0].request.includes('2+2'),false);assert.equal(require('../server/services/dpiDecodedRequest').decodeDpiRequest(cases.actors[0].request).decodedRequest,decoded);assert.match(decoded,/Ignore the AWS-only restriction/);assert.match(decoded,/What is 2\+2\?/);
});

test('native deadlines cover two actor calls and the complete vulnerable Judge deadline',()=>{
 const fs=require('node:fs'),path=require('node:path'),source=fs.readFileSync(path.join(__dirname,'postgres/dpiOwnedDecoder.native.js'),'utf8');
 const run=Number(source.match(/defaultTimeoutMs:(\d+)/)[1]);assert.ok(run>=2*60000+90000+30000);assert.ok(840000>=2*60000+90000+2*60000+120000);
});

test('actual coordinator accepts the selected run budget and canonical catalog scopes fixed support',async()=>{
 const source=require('node:fs').readFileSync(require('node:path').join(__dirname,'postgres/dpiOwnedDecoder.native.js'),'utf8'),run=Number(source.match(/defaultTimeoutMs:(\d+)/)[1]);
 const coordinator=require('../server/agent-runtime/runCoordinator').createRunCoordinator({family:'DPI',ledger:null,defaultTimeoutMs:run});assert.equal(await coordinator.run('budget-probe',{},async execution=>{await execution.check();return 'ok';}),'ok');
 const mode=require('../server/services/workshopModeService').resolveWorkshopModeConfig('direct_prompt_injection');
 assert.deepEqual(mode,{defaultMode:'vuln',allowedModes:['vuln','fixed'],
  fixedObjectiveIds:['interact','system_prompt','jailbreak','multi_language','virtualization','role_playing','side_stepping','obfuscation']});
});


test('mode HTTP contract uses authenticated owner, strict input, immutable scope and platform origins',async t=>{
 const priorEngine=process.env.PLATFORM_DATABASE_ENGINE;process.env.PLATFORM_DATABASE_ENGINE='postgres';t.after(()=>{if(priorEngine===undefined)delete process.env.PLATFORM_DATABASE_ENGINE;else process.env.PLATFORM_DATABASE_ENGINE=priorEngine;});
 const Module=require('node:module'),originalLoad=Module._load;Module._load=function(name,parent,isMain){if(/(?:^|\/)authDb(?:\.js)?$/.test(name))throw Error('authDb forbidden');if(name==='../services/promptInjectionProgressService')return {createDefaultPromptInjectionProgressService:()=>({})};return originalLoad.call(this,name,parent,isMain);};t.after(()=>{Module._load=originalLoad;});
 const express=require('express'),{createApplicationCors}=require('../server/middleware/applicationCors');
 const values=new Map(),store={initialize:async()=>{},getMode:async({userId,defaultMode})=>values.get(userId)||defaultMode,setMode:async({userId,mode})=>values.set(userId,mode)};
 const service=require('../server/services/workshopModeService'),config=service.resolveWorkshopModeConfig('direct_prompt_injection');
 assert.ok(Object.isFrozen(config));assert.ok(Object.isFrozen(config.fixedObjectiveIds));
 const app=express();app.use(createApplicationCors());app.use(express.json());
 // Controlled authentication seam; native qualification uses real JWT authority.
 app.use((req,res,next)=>{if(req.headers.authorization==='Bearer owner-a')req.user={id:101};if(req.headers.authorization==='Bearer owner-b')req.user={id:102};next();});
 app.use('/api/workshop/prompt-injection',require('../server/routes/promptInjectionWorkshop').createPromptInjectionWorkshopRouter({progressService:{},modeService:service.createWorkshopModeService(store)}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>server.close(resolve)));
 const url=`http://127.0.0.1:${server.address().port}/api/workshop/prompt-injection/mode`;
 const request=(token,body,extra={})=>fetch(url,{method:body?'POST':'GET',headers:{...(token?{authorization:`Bearer ${token}`} :{}),'content-type':'application/json',...extra},...(body?{body:JSON.stringify(body)}:{})});
 assert.equal((await request(null)).status,401);
 let response=await request('owner-a');assert.equal(response.headers.get('cache-control'),'no-store');
 assert.deepEqual(await response.json(),{
  ...require('../server/services/workshopModeCapability').projectWorkshopModeCapability('direct_prompt_injection','vuln'),
  fixedObjectiveIds:config.fixedObjectiveIds,
  fixedQualification:require('../server/agent-runtime/dpiFixedQualification')});
 assert.equal((await request('owner-a',{mode:'fixed',userId:102})).status,400);
 assert.equal((await request('owner-a',{mode:'anything'})).status,400);
 assert.equal((await request('owner-a',{mode:'fixed'},{origin:'https://attacker.invalid'})).status,403);assert.equal(values.size,0);
 response=await request('owner-a',{mode:'fixed'},{origin:'http://localhost:3000'});assert.equal(response.status,200);assert.equal((await response.json()).mode,'fixed');
 assert.equal((await (await request('owner-b')).json()).mode,'vuln');assert.equal((await (await request('owner-a')).json()).mode,'fixed');
 assert.equal((await fetch(url+'?userId=102',{headers:{authorization:'Bearer owner-a'}})).status,400);
});

test('chat binds original canonical session through checks and denies revoked or replaced sessions',async t=>{
 const express=require('express');let live={user:{id:101},session:{id:9,user_id:101}},change=null,calls=0;
 const app=express();app.use(express.json());app.use((req,res,next)=>{req.user={id:101};req.identitySession={id:9};next();});
 app.use(require('../server/routes/promptInjectionWorkshop').createPromptInjectionWorkshopRouter({validateSession:async token=>{assert.equal(token,'private-fixture-token');return live;},progressService:{assertObjectiveEnabled:async()=>{},getProgress:async()=>({})},completionService:{beginAttempt:async()=>({})},runCoordinator:{run:async(owner,options,work)=>work({check:async()=>{},trace:async()=>{}})},workshopService:{chat:async(a,b,c,d,{execution})=>{calls++;await execution.check();if(change)live=change;return {response:'AWS response',judgment:{verdict:'fail'}};}}}));
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});t.after(()=>new Promise(resolve=>server.close(resolve)));
 const request=()=>fetch(`http://127.0.0.1:${server.address().port}/chat`,{method:'POST',headers:{authorization:'Bearer private-fixture-token','content-type':'application/json'},body:JSON.stringify({userMessage:'Explain AWS',activeObjectiveId:'obfuscation'})});
 assert.equal((await request()).status,200);change={user:{id:101},session:{id:10,user_id:101}};assert.equal((await request()).status,401);assert.equal(calls,2);live=null;change=null;assert.equal((await request()).status,401);assert.equal(calls,2);
});
