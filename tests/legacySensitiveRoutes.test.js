'use strict';
const {test,after}=require('node:test'),assert=require('node:assert/strict'),Module=require('node:module'),path=require('node:path'),fs=require('node:fs'),os=require('node:os');
const routePath=path.resolve(__dirname,'../server/routes/sensitiveInfo.js');const load=Module._load;const captured=[];
const sensitiveFilesDir=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-legacy-sensitive-route-')),publicDir=path.join(sensitiveFilesDir,'public');
let resetComposition=null, canonicalFailure=false;
let selectedModeScope={generation:0,mode:null,modeStamp:'default'};
const fixtureLegacyRuns=require('../server/agent-runtime/runCoordinator').createRunCoordinator({family:'LegacySensitiveInfoFixture',ledger:null});
for(const directory of [publicDir,path.join(sensitiveFilesDir,'secret')])fs.mkdirSync(directory,{recursive:true});
function write(relative,content){const target=path.join(sensitiveFilesDir,relative);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,content);return content;}
let fileContent=write('secret/file.txt','FLAG: SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}');
after(()=>fs.rmSync(sensitiveFilesDir,{recursive:true,force:true}));
Module._load=function(r,p,m){
 if(p?.filename===routePath){
  if(r==='../database/sensitiveInfoDb')return {db:{},engine:'postgres',logFileAccess:async()=>{},reset:async()=>{},sensitiveFilesDir,publicDir,getPublicDocuments:async()=>[],getAccessLogs:async()=>[],getChallengeStats:async()=>[]};
  if(r==='../middleware/adminAuth')return {authenticateToken:(req,res,next)=>req.user?next():res.status(401).json({error:'Authentication required'})};
  if(r==='../services/multiProviderAIService')return {
   processSensitiveInfoRequest:async()=>({response:'Fixture model response',provider:'ollama',model:'fixture',payload:'../secret/file.txt',vulnerability:'path_traversal'}),
   generateResponse:async()=>({response:JSON.stringify({payload:'fixture-text-only',explanation:'fixture explanation',example:'fixture',vulnerability:'ssi_injection'}),provider:'ollama',model:'fixture'}),
  };
  if(r==='../services/legacySensitiveProgressStore')return {createLegacySensitiveProgressStore:()=>({recordJudgment:async row=>captured.push(row)})};
  if(r==='../services/legacySensitiveRunCoordinator')return {legacySensitiveRuns:fixtureLegacyRuns};
  if(r==='../services/postgresPlatformStores')return {getPostgresPlatformStores:()=>({progress:{getEvaluationScope:async()=>({...selectedModeScope})}})};
  // Explicit retained legacy-grader fixture. Production default-on canonical
  // composition is qualified separately; this fixture never initializes it.
  if(r==='../services/legacySensitiveCandidateComposition')return {getLegacySensitiveCandidateComposition:async()=>{if(canonicalFailure)throw Error('owned canonical unavailable');return resetComposition;}};
  if(r==='../agent-runtime/legacySensitiveJudge'){
   const actual=load.call(this,r,p,m);return {...actual,createLegacySensitiveGrader:deps=>actual.createLegacySensitiveGrader({...deps,judge:async packet=>({verdict:packet.rubric.requiredFacts.every(k=>packet.facts[k])?'pass':'fail',rubricVersion:packet.rubric.version})})};
  }
 }
 if(/(?:^|\/)(authDb|ctfDb|sensitiveInfoDb|sensitiveInfoWorkshopDb)(?:\.js)?$/.test(r))throw Error('Real database initializer forbidden');return load.call(this,r,p,m);
};
const router=require(routePath);
function response(){return {statusCode:200,status(n){this.statusCode=n;return this},json(value){this.body=value;return this}};}
async function invoke(route,body,headers={}){const handler=router.stack.find(layer=>layer.route?.path===route).route.stack.at(-1).handle;const res=response();await handler({body,user:{id:41},ip:'fixture',path:route,url:route,hostname:'fixture',get:name=>headers[name.toLowerCase()]||'fixture'},res,()=>{});return res;}
test('Mounted legacy file route ignores supplied owner and writes judge-derived progress with original output intact',async()=>{
 captured.length=0;const res=await invoke('/file/read',{filename:'../secret/file.txt',userId:999});assert.equal(res.statusCode,200);assert.equal(res.body.content,fileContent);assert.equal(captured[0].userId,41);assert.equal(captured[0].objectiveId,'path_traversal');assert.equal(res.body.judgments[0].completed,true);
});
test('Fixed direct file and SSI actions confine reads and leave directives literal',async()=>{
 selectedModeScope={generation:0,mode:'fixed',modeStamp:'fixed'};
 try{
  captured.length=0;
  const denied=await invoke('/file/read',{filename:'../secret/file.txt'});
  assert.equal(denied.statusCode,404);assert.equal(denied.body.code,'PUBLIC_FILE_ONLY');
  const publicText=write('public/fixed-welcome.txt','Public teaching content');
  const read=await invoke('/file/read',{filename:'fixed-welcome.txt'});
  assert.equal(read.statusCode,200);assert.equal(read.body.content,publicText);assert.equal(read.body.exploited,false);
  const directive='<!--#echo var="DATABASE_PASSWORD" -->|<!--#include file="secret/file.txt" -->|<!--#exec cmd="whoami" -->';
  const rendered=await invoke('/template/render',{template:directive});
  assert.equal(rendered.statusCode,200);assert.equal(rendered.body.rendered,directive);
  assert.equal(rendered.body.executionMode,'literal_template');assert.equal(rendered.body.flagFound,false);
  write('public/fixed-template.txt',directive);
  const document=await invoke('/document/process',{documentPath:'fixed-template.txt',processSSI:true});
  assert.equal(document.statusCode,200);assert.equal(document.body.content,directive);
  assert.equal(document.body.processedSSI,false);
  const protectedDocument=await invoke('/document/process',{documentPath:'../secret/file.txt',processSSI:true});
  assert.equal(protectedDocument.statusCode,404);
  assert.deepEqual(captured,[]);
 }finally{selectedModeScope={generation:0,mode:null,modeStamp:'default'};}
});
test('Combined route cannot earn combined credit merely by reading a flagged secret file without SSI',async()=>{
 captured.length=0;const res=await invoke('/document/process',{documentPath:'../secret/file.txt',processSSI:false,userId:999});assert.equal(res.statusCode,200);assert.equal(captured.some(row=>row.completed),false);assert.equal(res.body.content,fileContent);
});
test('AI-assisted file route grades actual execution under authenticated owner',async()=>{
 captured.length=0;const res=await invoke('/ai/chat',{message:'read fixture',userId:999});assert.equal(res.statusCode,200);assert.equal(captured[0].objectiveId,'ai_assisted_path_traversal');assert.equal(captured[0].userId,41);assert.equal(captured[0].completed,true);assert.equal(res.body.executionResult.content,fileContent);
});
test('Public config/admin filenames and arbitrary FLAG markers cannot produce protected-file credit',async()=>{
 captured.length=0;fileContent=write('public/config-admin-guide.txt','FLAG: SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}');let res=await invoke('/file/read',{filename:'public/config-admin-guide.txt',userId:999});assert.equal(res.statusCode,200);assert.equal(captured[0].completed,false);assert.equal(res.body.content,fileContent);
 captured.length=0;fileContent=write('secret/tutorial.txt','FLAG: DEMO_EXAMPLE_NOT_A_CHALLENGE_FLAG');res=await invoke('/file/read',{filename:'../secret/tutorial.txt'});assert.equal(res.statusCode,200);assert.equal(captured.some(row=>row.completed),false);assert.equal(res.body.flagFound,null);assert.equal(res.body.content,fileContent);
});
test('Payload helper uses the selected provider service and remains text-only with no judgment',async()=>{
 captured.length=0;const res=await invoke('/ai/generate-payload',{userPrompt:'suggest a teaching payload',targetVulnerability:'ssi_injection',userId:999});
 assert.equal(res.statusCode,200);assert.equal(res.body.generatedPayload,'fixture-text-only');assert.equal(res.body.vulnerability,'ssi_injection');assert.deepEqual(captured,[]);
});
test('Mounted file route cannot traverse or follow a symlink outside the owned teaching root',async()=>{
 const outside=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-legacy-sensitive-host-fixture-'));
 try{
  fs.writeFileSync(path.join(outside,'private.txt'),'host-private-fixture');
  fs.symlinkSync(path.join(outside,'private.txt'),path.join(publicDir,'escape.txt'));
  captured.length=0;
  for(const filename of ['../../../outside-private.txt','escape.txt']){
   const res=await invoke('/file/read',{filename});assert.equal(res.statusCode,404);assert.doesNotMatch(JSON.stringify(res.body),/host-private-fixture/);
  }
  assert.deepEqual(captured,[]);
 }finally{fs.rmSync(outside,{recursive:true,force:true});}
});
test('mounted reset binds the authenticated owner and exact operation ID',async t=>{
 t.after(()=>{resetComposition=null;});const seen=[];
 resetComposition={reset:{async reset(owner,options){seen.push({owner,options});
  if(!/^[0-9a-f-]{36}$/.test(options.operationId||''))throw new TypeError('invalid');
  return{operationId:options.operationId,fromGeneration:2,toGeneration:3,status:'completed'};}}};
 const operationId='11111111-1111-4111-8111-111111111111';
 const ok=await invoke('/progress/reset',{userId:999},{'x-reset-operation-id':operationId});
 assert.equal(ok.statusCode,200);assert.deepEqual(seen,[{owner:41,options:{operationId}}]);
 assert.deepEqual(ok.body.reset,{operationId,fromGeneration:2,toGeneration:3,status:'completed'});
 const malformed=await invoke('/progress/reset',{}, {'x-reset-operation-id':'not-a-reset-id'});
 assert.equal(malformed.statusCode,400);assert.equal(seen.length,2);
});
test('PostgreSQL reset maintenance opt-out fails closed instead of performing a local-only reset',async()=>{
 resetComposition=null;
 const res=await invoke('/progress/reset',{});
 assert.equal(res.statusCode,503);assert.equal(res.body.unavailable,true);
});


test('manual SSI routes preserve literal bytes included from an owned file', async () => {
 const bytes = "literal $& $$ $` $' end";
 write('secret/literal.txt', bytes);
 const template = 'before <!--#include file="secret/literal.txt" --> after';
 write('secret/literal-template.txt', template);
 const rendered = await invoke('/template/render', { template });
 assert.equal(rendered.statusCode, 200);
 assert.equal(rendered.body.rendered, `before ${bytes} after`);
 const document = await invoke('/document/process', { documentPath: '../secret/literal-template.txt', processSSI: true });
 assert.equal(document.statusCode, 200);
 assert.equal(document.body.content, `before ${bytes} after`);
});

test('manual SSI credit requires a resolved own echo or successful include', async () => {
 write('secret/ssi-include.txt', 'included fixture');
 const cases = [
  { name: 'failed include', template: '<!--#include file="secret/missing.txt" -->', completed: false },
  { name: 'unknown echo', template: '<!--#echo var="UNKNOWN_VARIABLE" -->', completed: false },
  { name: 'inherited echo', template: '<!--#echo var="toString" -->', completed: false },
  { name: 'simulated exec', template: '<!--#exec cmd="whoami" -->', completed: false },
  { name: 'valid echo', template: '<!--#echo var="DATABASE_PASSWORD" -->', completed: true },
  { name: 'valid include', template: '<!--#include file="secret/ssi-include.txt" -->', completed: true },
  { name: 'mixed include outcomes', template: '<!--#include file="secret/ssi-include.txt" --> <!--#include file="secret/missing.txt" -->', completed: true },
  { name: 'echo and failed include', template: '<!--#echo var="DATABASE_PASSWORD" --> <!--#include file="secret/missing.txt" -->', completed: true },
 ];
 for (const entry of cases) {
  captured.length = 0;
  const rendered = await invoke('/template/render', { template: entry.template, ssiSucceeded: true });
  assert.equal(rendered.statusCode, 200, entry.name);
  assert.equal(captured.length, 1, entry.name);
  assert.equal(captured[0].completed, entry.completed, `template: ${entry.name}`);
  write('secret/ssi-outcome-template.txt', `FLAG: SENSITIVE_DATA_FLAG_1{Path_Traversal_Success} ${entry.template}`);
  captured.length = 0;
  const document = await invoke('/document/process', { documentPath: '../secret/ssi-outcome-template.txt', processSSI: true, ssiSucceeded: true });
  assert.equal(document.statusCode, 200, entry.name);
  assert.equal(captured.length, 1, entry.name);
  assert.equal(captured[0].completed, entry.completed, `document: ${entry.name}`);
 }
});

test('unavailable canonical composition fails closed instead of falling back to legacy credit', async t => {
 canonicalFailure=true;t.after(()=>{canonicalFailure=false;});captured.length=0;
 const result=await invoke('/file/read',{filePath:'../secret/file.txt'});
 assert.equal(result.statusCode,503);assert.equal(result.body.unavailable,true);assert.deepEqual(captured,[]);
});
