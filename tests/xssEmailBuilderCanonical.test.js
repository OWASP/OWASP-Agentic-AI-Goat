'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const {createXssEmailBuilderCanonical}=require('../server/services/xssEmailBuilderCanonical');
const curriculum=require('../server/config/xssEmailBuilderCurriculum');
function fixture(){
 let pending,fail=false,clears=0,resets=0,finishes=0;const id='00000000-0000-4000-8000-000000000001';
 const pool={query:async(sql,args)=>{
  if(sql.includes('WHERE operation_id=$1'))return {rows:pending&&pending.operation_id===args[0]?[pending]:[]};
  if(sql.startsWith('SELECT * FROM identity.xss_email_builder_resets'))return {rows:pending?.status==='pending'?[pending]:[]};
  if(sql.includes('begin_xss')){pending||={operation_id:args[1],owner_id:1,from_generation:'0',to_generation:'1',status:'pending'};return {rows:[pending]};}
  if(sql.includes('finish_xss')){finishes++;if(fail)throw Error('identity unavailable');pending={...pending,status:'completed'};return {rows:[pending]};}
  throw Error(sql);
 }};
 const config={getSnapshot:async()=>({exercises:{xss_email_builder:{isVisible:true,objectives:Object.fromEntries(curriculum.OBJECTIVES.map(o=>[o.id,{isVisible:true}]))}}}) };
 const completion={beginAttempt:async x=>x,evaluate:async x=>x};
 const api=createXssEmailBuilderCanonical({pool,config,completion,progress:{getVisibleUserProgress:async()=>[]},store:{clearBuilder:async intent=>{clears++;return {...intent};}}});
 const execution={check:async()=>{}};const lifecycle={ownerId:1,check:async()=>{}};const runs={reset:async(owner,work)=>{resets++;await work(execution);}};
 return {api,id,execution,lifecycle,runs,setFail:v=>{fail=v;},counts:()=>({clears,resets,finishes})};
}
test('four frozen IDs and authentic source-specific content are separate from inbox XSS',()=>{
 assert.deepEqual(curriculum.OBJECTIVES.map(o=>o.id),[1,2,3,4].map(n=>`xss_email_level_${n}`));
 for(const o of curriculum.OBJECTIVES){assert.equal(curriculum.HINTS[o.id].hints.length,2);assert.ok(curriculum.SOLUTIONS[o.id].approach.length>50);}
 assert.match(curriculum.SOLUTIONS.xss_email_level_4.approach,/raw model output/);
});
test('canonical begin binds exact owner, objective and protected execution',async()=>{
 const f=fixture();const a=await f.api.begin(1,3,f.execution);assert.equal(a.workshopKey,'xss_email_builder');assert.equal(a.objectiveId,'xss_email_level_3');assert.equal(a.execution,f.execution);
 await assert.rejects(f.api.begin(1,5,f.execution));
});
test('interrupted reset blocks admission; implicit recovery reuses intent; terminal replay does not reset again',async()=>{
 const f=fixture();f.setFail(true);await assert.rejects(f.api.reset({owner:1,operationId:f.id,lifecycle:f.lifecycle,runs:f.runs}),/identity unavailable/);
 await assert.rejects(f.api.begin(1,1,f.execution),/BUILDER_RESET_PENDING/);
 f.setFail(false);const done=await f.api.reset({owner:1,lifecycle:f.lifecycle,runs:f.runs});assert.equal(done.operation_id,f.id);assert.equal(done.status,'completed');
 const counts=f.counts();await f.api.reset({owner:1,operationId:f.id,lifecycle:f.lifecycle,runs:f.runs});assert.deepEqual(f.counts(),counts);
});
test('reset rejects mismatched operation and revoked session before cleanup',async()=>{
 const f=fixture();f.setFail(true);await assert.rejects(f.api.reset({owner:1,operationId:f.id,lifecycle:f.lifecycle,runs:f.runs}));
 const before=f.counts();await assert.rejects(f.api.reset({owner:1,operationId:'00000000-0000-4000-8000-000000000002',lifecycle:f.lifecycle,runs:f.runs}),/SCOPE_MISMATCH/);assert.deepEqual(f.counts(),before);
 await assert.rejects(f.api.reset({owner:1,lifecycle:f.lifecycle,runs:f.runs,sessionCheck:async()=>{throw Error('revoked');}}),/revoked/);assert.deepEqual(f.counts(),before);
});
test('real bounded graph decisions select read and generate, preserving HTML provenance',async()=>{
 const {runEmailTemplateGraph,getEmailTemplateGraphDefinition}=require('../server/agent-runtime/emailTemplateGraph');
 const replies=['{"tool":"read_profile"}','{"tool":"generate_template"}','<p>{{name}}</p>'];let calls=0;const effects=[];
 const result=await runEmailTemplateGraph({userId:1,prompt:'Greeting'}, {loadProfile:async()=>({id:1,full_name:'<script>alert(1)</script>'}),saveTemplate:async()=>1,
  aiService:{generateResponse:async()=>({response:replies[calls++],provider:'ollama',model:'controlled-response-test'})},execution:{check:async()=>{},effect:async(key,work)=>{effects.push(key);return work();}}});
 assert.equal(calls,3);assert.equal(result.template.html,'<p><script>alert(1)</script></p>');assert.deepEqual(effects,['read_profile']);
 assert.equal(getEmailTemplateGraphDefinition().nodes.some(n=>n.id==='judge_model'),false);
});
test('decision traces survive the durable trace contract without exposing raw model text',async()=>{
 const {runEmailTemplateGraph}=require('../server/agent-runtime/emailTemplateGraph');
 const {traceData}=require('../server/agent-runtime/runTraceStore');
 const replies=['{"tool":"generate_template"}','{"tool":"read_profile"}','{"tool":"generate_template"}','<p>{{name}}</p>'];
 const events=[],schemas=[];let calls=0;
 await runEmailTemplateGraph({userId:1,prompt:'Greeting'},{
  loadProfile:async()=>({id:1,full_name:'Learner'}),saveTemplate:async()=>1,
  aiService:{generateResponse:async(prompt,options)=>{
   if(options.format){schemas.push(options.format.properties.tool.enum);assert(prompt.includes(JSON.stringify(options.format.properties.tool.enum)));}
   return {response:replies[calls++],provider:'ollama',model:'controlled-test'};
  }},
  execution:{trace:async event=>{
   assert(['node_start','node_end','decision','provisional','tool','error'].includes(event.type));
   if(event.type==='decision'){assert.deepEqual(traceData(event.data),event.data);events.push(event);}
  }},
 });
 assert.equal(calls,4);assert.deepEqual(events.map(x=>x.data.attempt),[1,2,1]);
 assert.deepEqual(schemas,[['read_profile','finish'],['read_profile','finish'],['generate_template','finish']]);
 for(const [i,event] of events.entries()){
  assert.equal(event.data.decisionSource,'model');
  assert.equal(event.data.evidenceSummary,require('node:crypto').createHash('sha256').update(replies[i]).digest('hex'));
  assert.equal(Object.hasOwn(event.data,'raw'),false);
 }
});
test('model refusal and invalid decisions never generate or persist',async()=>{
 const {runEmailTemplateGraph}=require('../server/agent-runtime/emailTemplateGraph');let generated=0;
 const dependencies={loadProfile:async()=>{throw Error('unexpected read');},saveTemplate:async()=>{throw Error('unexpected write');},aiService:{generateResponse:async()=>{generated++;return {provider:'ollama',model:'test-model',response:'{"tool":"finish"}'};}}};
 assert.equal((await runEmailTemplateGraph({userId:1,prompt:'hello'},dependencies)).success,false);assert.equal(generated,1);
 dependencies.aiService.generateResponse=async()=>({provider:'ollama',model:'test-model',response:'{"tool":"generate_template"}'});
 await assert.rejects(runEmailTemplateGraph({userId:1,prompt:'hello'},dependencies),/Invalid model decision/);
});
test('canonical grading has one authority and exact completed effect/genuine generation prerequisites',async()=>{
 const {createXssEmailObjectiveGrader}=require('../server/services/xssEmailObjectiveGrader');let calls=0,legacy=0,writes=0;
 const check=async()=>{};const execution={runId:'run',ownerKey:'owner',durableGeneration:'4',check};
 const browser={qualify:async()=>({executed:true}),qualifyDocument:async()=>({executed:true,scriptExecuted:true})};
 let captured;const canonical={evaluate:async value=>{calls++;captured=value;return {judgment:{verdict:'pass'},completed:value.rubric.requiredFacts.every(k=>value.facts[k]===true)};}};
 const grader=createXssEmailObjectiveGrader({canonical,browserQualification:browser,judge:async()=>{legacy++;throw Error('second Judge');},persistJudgment:async()=>{},persistCompletion:async()=>{writes++;}});
 const input={userId:1,templateId:1,profile:{full_name:'<script>alert(1)</script>'},persistedHtml:'<script>alert(1)</script>',requestedLevel:1,execution,attempt:{},rawModelResponse:{provider:'ollama',model:'model',response:'{{name}}'},templateEffect:{status:'completed',runId:'run',ownerKey:'owner',generation:'4',effectKey:'run:persist_template'}};
 const accepted=await grader.evaluate(input);assert.deepEqual(accepted.completedLevels,[1]);assert.equal(accepted.judgments[0].objectiveId,'xss_email_level_1');assert.equal(accepted.judgments[0].level,1);assert.equal(calls,1);assert.equal(legacy,0);assert.equal(writes,1);assert.equal(captured.rubric.objectiveId,'xss_email_level_1');
 for(const bad of [{templateEffect:{...input.templateEffect,ownerKey:'other'}},{rawModelResponse:{...input.rawModelResponse,provider:'controlled'}},{rawModelResponse:{response:'{{name}}'}}])assert.deepEqual((await grader.evaluate({...input,...bad})).completedLevels,[]);
 assert.equal(writes,1);canonical.evaluate=async()=>null;await assert.rejects(grader.evaluate(input),/Canonical builder evaluation unavailable/);assert.equal(legacy,0);
});
test('canonical defaults register all four content keys and public solution paths',()=>{
 const catalog=require('../server/config/workshopCatalog');
 assert.deepEqual(catalog.WORKSHOP_OBJECTIVES.xss_email_builder,curriculum.OBJECTIVES);
 assert.deepEqual(require('../server/data/workshopHints').xss_email_builder,curriculum.HINTS);
 assert.deepEqual(require('../server/database/postgres/workshopPlatformSeed').solutionFixtures().xss_email_builder,curriculum.SOLUTIONS);
 assert.equal(require('../server/config/workshopSolutionPaths').xss_email_builder.statusPrefix,'xss-email-builder');
 assert.equal(require('../db/postgres/workshopChallengeFixtures').filter(c=>c.key==='xss_email_builder').length,1);
 assert.ok(catalog.WORKSHOP_OBJECTIVES.xss_workshop.some(o=>o.id==='xss_e3'));
});
test('existing reset service cancels builder before lifecycle acquisition and delegates canonical retirement exactly once',async()=>{
 const {createPostgresWorkshopResetAdapters,createPostgresWorkshopResetService}=require('../server/services/postgresWorkshopResetService');
 const events=[];const lifecycle={ownerId:1,check:async()=>{}};const runs={cancel:owner=>events.push('cancel:'+owner)};
 const application={cancelBeforeReset:async({owner,runs})=>runs.cancel(String(owner)),assertReady:async()=>true,reset:async input=>{assert.equal(input.lifecycle,lifecycle);assert.equal(input.runs,runs);events.push('reset');return {status:'completed'};}};
 const adapters=createPostgresWorkshopResetAdapters(path=>{
  if(path==='./xssEmailBuilderCanonical')return {getXssEmailBuilderCanonical:()=>application};
  if(path==='../routes/xssEmail')return {builderRuns:runs};
  if(path==='./postgresIdentityAdapter')return {getPostgresIdentityAdapter:()=>({pool:{}})};
  if(path==='../database/postgres/xssParentResetJournalRepository')return {createXssParentResetJournalRepository:()=>({assertMutationAdmitted:async()=>{}})};
  if(path==='./xssMutationAdmission')return {configuredXssProfileResetPendingCheck:async()=>{}};
  throw Error(path);
 });
 const service=createPostgresWorkshopResetService({adapters,progress:{resetWorkshopProgress:async()=>{throw Error('duplicate canonical reset');}},withStudentResetAdmission:async(owner,work)=>{events.push('lock');return work(lifecycle);}});
 await service.resetStudent({userId:1,workshopKey:'xss_email_builder'});
 assert.deepEqual(events,['cancel:1','lock','reset']);assert.equal(await adapters.xss_email_builder.bulkResetReplaySafe(),true);
});
test('existing parent reset preserves builder artifacts while owner destruction clears them',()=>{
 const sql=require('node:fs').readFileSync(require('node:path').join(__dirname,'../db/postgres/workshop-migrations/xss/0014_parent_profile_reset_receipt.sql'),'utf8');
 const parent=sql.slice(sql.indexOf('CREATE FUNCTION xss.clear_parent_profile_reset('),sql.indexOf('CREATE OR REPLACE FUNCTION xss.destroy_student_owner'));
 assert.match(parent,/DELETE FROM xss\.progress/);assert.doesNotMatch(parent,/DELETE FROM xss\.(email_templates|email_profiles|xss_challenge_progress|xss_email_judge_receipts)/);
 const destruction=sql.slice(sql.indexOf('CREATE OR REPLACE FUNCTION xss.destroy_student_owner'));
 assert.match(destruction,/DELETE FROM xss\.email_templates/);
});
test('terminal reset replay does not cancel a newer run; pending and new reset still cancel',async()=>{
 const f=fixture();let cancelled=0;const runs={...f.runs,cancel:()=>{cancelled++;}};
 await f.api.cancelBeforeReset({owner:1,operationId:f.id,runs});assert.equal(cancelled,1);
 await f.api.reset({owner:1,operationId:f.id,runs,lifecycle:f.lifecycle});
 await f.api.cancelBeforeReset({owner:1,operationId:f.id,runs});assert.equal(cancelled,1);
 await f.api.cancelBeforeReset({owner:1,runs});assert.equal(cancelled,2);
 await assert.rejects(f.api.cancelBeforeReset({owner:2,operationId:f.id,runs}),/SCOPE_MISMATCH/);assert.equal(cancelled,2);
 await assert.rejects(f.api.cancelBeforeReset({owner:1,operationId:'invalid',runs}),/UUID/);assert.equal(cancelled,2);
});
