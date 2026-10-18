'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const native=fs.readFileSync('tests/postgres/dpiFullAppRendered.native.js','utf8');
const ddl=fs.readdirSync('db/postgres/identity-migrations').filter(f=>f.endsWith('.sql')).map(f=>fs.readFileSync('db/postgres/identity-migrations/'+f,'utf8')).join('\n');
test('every direct SQL table in the DPI display fixture exists in the canonical migration chain',()=>{
 const queries=[...native.matchAll(/\.query\((['"])(.*?)\1/g)].map(m=>m[2]);assert.ok(queries.length>=3);
 for(const sql of queries)for(const match of sql.matchAll(/\b(?:FROM|UPDATE)\s+([a-z_]+\.[a-z_]+)/gi)){assert.match(ddl,new RegExp('CREATE TABLE(?: IF NOT EXISTS)? '+match[1].replace('.','\\.')+' \\('),match[1]);}
 assert.doesNotMatch(native,/platform_identity/);
});
test('DPI effective teaching gates include eight hints and seven attack solutions, with no invented practice solution',()=>{
 const ids=require('../server/config/workshopCatalog').WORKSHOP_OBJECTIVES.direct_prompt_injection.map(x=>x.id),hints=require('../server/data/workshopHints').direct_prompt_injection,solutions=require('../server/data/promptInjectionSolutions').solutions;
 assert.equal(ids.length,8);assert.ok(ids.every(id=>hints[id]));assert.deepEqual(Object.keys(solutions).sort(),ids.filter(id=>id!=='interact').sort());
});

test('DPI fixture exact random origin passes real platform CORS while foreign and opaque origins stay denied',async t=>{
 const express=require('express'),{once}=require('node:events'),{createApplicationCors}=require('../server/middleware/applicationCors');
 const app=express(),server=app.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(r=>server.close(r)));
 const port=server.address().port,origin='http://127.0.0.1:'+port;
 const env=require('./fixtures/dpiFullAppEnvironment').createDpiFullAppEnvironment({parent:{PATH:'/usr/bin'},home:'/owned-home',root:'/owned-evidence',port,origin});
 assert.equal(env.SS_ENABLE,'false');assert.equal(env.SS_ALLOWED_ORIGINS,origin);assert.equal(env.NODE_ENV,'test');assert.ok(env.JWT_SECRET.length>60);assert.equal(env.EVENT_GATE_ENABLED,'false');
 app.use(createApplicationCors({secureShopOrigins:env.SS_ALLOWED_ORIGINS.split(',')}));let effects=0;app.use((_req,res)=>{effects++;res.json({ok:true});});
 for(const route of ['/api/auth/login','/api/admin/exercises/direct_prompt_injection','/api/workshop/config/snapshot']){
  const response=await fetch(origin+route,{method:'POST',headers:{origin,'content-type':'application/json'},body:'{}'});assert.equal(response.status,200);assert.equal(response.headers.get('access-control-allow-origin'),origin);assert.equal(response.headers.get('access-control-allow-credentials'),'true');
  for(const denied of ['null','http://127.0.0.1:1'])assert.equal((await fetch(origin+route,{method:'POST',headers:{origin:denied}})).status,403);
 }
 assert.equal(effects,3);
});


test('DPI backend environment explicitly preserves shared context only for the selected profile',()=>{
 const {createDpiFullAppEnvironment}=require('./fixtures/dpiFullAppEnvironment');
 const args={parent:{PATH:'/usr/bin',OLLAMA_CONTEXT_WINDOW:'4096',JUDGE_CONTEXT_TOKENS:'4096'},home:'/owned-home',root:'/owned-evidence',port:43210,origin:'http://127.0.0.1:43210'};
 const ordinary=createDpiFullAppEnvironment(args);
 assert.equal(ordinary.OLLAMA_CONTEXT_WINDOW,undefined);assert.equal(ordinary.JUDGE_CONTEXT_TOKENS,undefined);
 const selected=createDpiFullAppEnvironment({...args,sharedModelContext:32768});
 assert.equal(selected.OLLAMA_CONTEXT_WINDOW,'32768');assert.equal(selected.JUDGE_CONTEXT_TOKENS,'32768');
 const techniques=createDpiFullAppEnvironment({...args,sharedModelContext:20480});
 assert.equal(techniques.OLLAMA_CONTEXT_WINDOW,'20480');assert.equal(techniques.JUDGE_CONTEXT_TOKENS,'20480');
 for(const sharedModelContext of [8192,'32768',null,NaN])assert.throws(()=>createDpiFullAppEnvironment({...args,sharedModelContext}));
 assert.match(native,/createDpiFullAppEnvironment\(\{home,root,port,origin,sharedModelContext:actualTechniquesSelected70b\?20480:actualWholeTask70b\|\|actualSideSelected70b\|\|actualSideSelectedV16_70b\?32768:undefined\}\)/);
});
test('retained pending browser input admits zero model calls and zero credit',()=>{
 const crypto=require('node:crypto'),input=fs.readFileSync('tests/fixtures/dpiRetainedPendingBrowserInput.json'),hash=value=>crypto.createHash('sha256').update(value).digest('hex');
 assert.equal(hash(input),'978eb07e0ba3404f0cce70d9231d7c08f130eaea44ad315dd5dd8717f10989c9');
 const value=JSON.parse(input);assert.deepEqual(value.objectiveIds,['virtualization','side_stepping','obfuscation']);assert.equal(value.maximumModelCalls,0);assert.equal(value.expectedCompletions,0);assert.equal(value.model,'llama3.1:8b');
 const {spawnSync}=require('node:child_process'),script='import importlib.util,pathlib,json; p=pathlib.Path("tests/postgres/run-finflow-backup-browser-main.py").resolve(); s=importlib.util.spec_from_file_location("dpi",p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(json.dumps({"profile":m.DPI_PENDING_PROFILE,"cohort":m.selected_cohort(type("Args",(),{"profile":m.DPI_PENDING_PROFILE})()),"inputSha256":m.DPI_PENDING_INPUT_SHA256,"fullApp":m.DPI_PENDING_PROFILE in m.DPI_PROFILES}))';
 const checked=spawnSync('python3',['-B','-c',script],{encoding:'utf8',timeout:5000});assert.equal(checked.status,0,checked.stderr);assert.deepEqual(JSON.parse(checked.stdout),{profile:'actual-dpi-retained-pending8b',cohort:'dpi-retained-pending8b-browser-main',inputSha256:hash(input),fullApp:true});
});
test('retained pending disposable initialization keeps the guard and maintenance lease',()=>{
 assert.match(native,/const initialization=retainedPending8b\s*\?\['-e',`const m=require\(/);
 assert.match(native,/m\.initializeApplication\(\)\.catch\(error=>\{console\.error\('PostgreSQL initialization failed:',JSON\.stringify\(m\.initializationFailureSummary\(error\)\)\);process\.exit\(1\);\}\)/);
 assert.match(native,/:[[]path\.join\(source,'db\/postgres\/initialize-application\.js'\)\]/);
 assert.match(native,/owned\.launch\(process\.execPath,args,\{cwd:actualDpi\?process\.cwd\(\):source,env,stdio:'inherit'\}\)/);
 const initializer=fs.readFileSync('db/postgres/initialize-application.js','utf8');
 assert.match(initializer,/async function initializeApplication\(\{ maintenanceScope \} = \{\}\)/);
 assert.match(initializer,/await lease\.beginMaintenance\(\)/);
 assert.match(initializer,/await lease\.finishMaintenance\(maintenanceEpoch\)/);
});
