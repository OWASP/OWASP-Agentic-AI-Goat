'use strict';
// Observers delegate unchanged to real production actors, browser qualification and grader.
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const {CASES,PROFILE,configuration,requestRole}=require('./xssReflectedActualWirePolicy');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const copy=x=>JSON.parse(JSON.stringify(x));
async function connectOwnedQualificationBrowser(browser,puppeteer=require('puppeteer')){
 assert(browser&&typeof browser.wsEndpoint==='function','Owned browser required');
 const endpoint=browser.wsEndpoint(),url=new URL(endpoint);
 assert.equal(url.protocol,'ws:');assert.equal(url.hostname,'127.0.0.1');assert(Number(url.port)>1024&&Number(url.port)<65536);assert.match(url.pathname,/^\/devtools\/browser\/[a-f0-9-]{36}$/);assert.equal(url.search,'');assert.equal(url.hash,'');assert.equal(url.username,'');assert.equal(url.password,'');
 // A separate CDP connection lets the service retire its own contexts and disconnect,
 // while the existing owned UI browser remains under the owner's close/reap path.
 return puppeteer.connect({browserWSEndpoint:endpoint,protocolTimeout:15000});
}
function installObservation({connectBrowser,profile=PROFILE}={}){
 assert.equal(typeof connectBrowser,'function','Actual qualification requires the owned browser connector');
 const cases=configuration(profile).CASES;
 const ai=require('../../server/services/multiProviderAIService');
 const browserModule=require('../../server/services/xssBrowserQualification');
 const graderModule=require('../../server/services/xssObjectiveGrader');
 const originalActor=ai.chatWithMessages,originalBrowser=browserModule.createXssBrowserQualification,originalGrader=graderModule.createXssObjectiveGrader;
 let active=null;const captures=[];
 ai.chatWithMessages=async function(messages,options){assert(active);const row={messages:copy(messages),options:{temperature:options.temperature,max_tokens:options.max_tokens,timeout:options.timeout}};active.actors.push(row);const result=await originalActor.call(this,messages,options);row.result=copy(result);return result;};
 graderModule.createXssObjectiveGrader=function(options){
  const browser=originalBrowser({connectBrowser});const observedBrowser={...browser,async qualify(html,opts){assert(active);const row={html,options:copy({...opts,signal:undefined})};active.browsers.push(row);const result=await browser.qualify(html,opts);row.result=copy(result);return result;},close:()=>browser.close()};
  const grader=originalGrader({...options,browserQualification:observedBrowser});
  return {...grader,async evaluate(input){assert(active);const {execution,attempt,...rest}=input;const row={input:copy(rest),execution:copy({runId:execution.runId,ownerKey:execution.ownerKey,generation:execution.generation,durableGeneration:execution.durableGeneration}),attempt:copy(attempt)};active.grades.push(row);const result=await grader.evaluate(input);row.output=copy(result);return result;}};
 };
 return {begin(id){assert.equal(active,null);assert.equal(id,cases[captures.length].id);active={caseId:id,actors:[],browsers:[],grades:[]};captures.push(active);},end(){assert(active);const row=copy(active);active=null;return row;},restore(){ai.chatWithMessages=originalActor;graderModule.createXssObjectiveGrader=originalGrader;},originalGrader};
}
function rawText(row){require('../postgres/finflowBackupBrowserActualTransport').validateResponse(row);assert.equal(row.terminal,'returned');assert.equal(sha(row.request),row.requestSha256);return row.response.trim().split('\n').map(x=>JSON.parse(x).message.content).join('');}
function object(value){if(typeof value==='string'){assert(Buffer.byteLength(value)<=262144);value=JSON.parse(value);}assert(value&&typeof value==='object'&&!Array.isArray(value));return value;}
function validatePrerequisites(value,policy,ownerId){
 if(!policy.prerequisiteIds.length){assert.equal(value,null);return [];}
 assert(value);assert.equal(value.version,'xss-reflected-prerequisites-v1');assert.equal(String(value.ownerId),String(ownerId));assert.deepEqual(value.judgments,[]);assert.deepEqual(value.packets,[]);
 assert.deepEqual(value.completions.map(x=>x.objective_id),policy.prerequisiteIds);assert.deepEqual(value.progress.map(x=>x.objective_id),policy.prerequisiteIds);
 for(const row of value.completions){assert.equal(String(row.user_id),String(ownerId));assert.equal(row.workshop_key,'xss_workshop');}
 for(const row of value.progress){assert.equal(row.user_key,String(ownerId));assert.equal(row.completed,1);}
 return value.completions;
}
async function bindCapture({capture,body,records,run,events,completions,wire,ownerId,originalGrader,prior=[],profile=PROFILE,prerequisites=null,progress=null}){
 const policy=configuration(profile),cases=policy.CASES;
 const spec=cases.find(x=>x.id===capture.caseId);assert(spec);assert.equal(capture.grades.length,1);const grade=capture.grades[0],input=grade.input,execution=grade.execution;
 assert.equal(input.userId,ownerId);assert.equal(input.exerciseId,'reflected');assert.equal(input.objectiveId,spec.objective);assert.equal(input.message,spec.message);assert.equal(input.response,body.response);assert.equal(input.grading.modelSucceeded,true);assert.equal(input.grading.decisionSource,'model');assert.equal(input.grading.modelProvider,'ollama');assert.equal(input.grading.modelName,'llama3.1:8b');assert.equal(input.grading.toolCall,null);assert.equal(input.grading.toolSteps,0);
 assert.equal(run.run_id,execution.runId);assert.equal(run.owner_key,execution.ownerKey);assert.equal(run.owner_key,JSON.stringify(['XSS',String(ownerId)]));assert.equal(run.status,'completed');assert.equal(String(run.generation),String(execution.durableGeneration));
 const rows=wire.filter(x=>x.caseId===spec.id&&x.kind==='chat'),actors=rows.filter(x=>requestRole(JSON.parse(x.request))==='actor'),judges=rows.filter(x=>requestRole(JSON.parse(x.request))==='judge');assert(actors.length>=1&&actors.length<=2);assert.equal(actors.length,capture.actors.length);
 for(let i=0;i<actors.length;i++){const observed=capture.actors[i],request=JSON.parse(actors[i].request);assert.deepEqual(request.messages,observed.messages);assert.equal(observed.options.temperature,.7);assert.equal(observed.options.max_tokens,512);assert.equal(observed.options.timeout,60000);assert.equal(rawText(actors[i]),observed.result.response);assert.equal(observed.result.provider,'ollama');assert.equal(observed.result.model,'llama3.1:8b');assert.notEqual(observed.result.mocked,true);assert.notEqual(observed.result.fallback,true);assert(observed.messages.some(m=>m.role==='user'&&m.content===spec.message));}
 assert.equal(capture.actors.at(-1).result.response,input.grading.llmResponse);assert.equal(input.grading.llmResponse,input.response);assert.equal(input.grading.terminationReason,'model_finished');
 const decisions=events.filter(e=>e.node==='decide'&&e.event_type==='decision');assert.equal(decisions.length,actors.length);for(const event of decisions){assert.equal(event.run_id,run.run_id);assert.equal(event.owner_key,run.owner_key);assert.equal(event.metadata.decisionSource,'model');assert.equal(event.metadata.provider,'ollama');assert.equal(event.metadata.model,'llama3.1:8b');}
 if(actors.length===2){const rejected=events.filter(e=>e.node==='validate'&&e.event_type==='decision'&&e.metadata.accepted===false);assert.equal(rejected.length,1);assert.equal(rejected[0].metadata.decisionDigest,sha(rawText(actors[0])));assert.equal(rejected[0].owner_key,run.owner_key);assert.equal(rejected[0].run_id,run.run_id);}
 assert.equal(records.length,1);const record=records[0],packet=object(record.packet),result=object(record.result_json);assert.equal(result.provider,'ollama');assert.equal(result.model,'llama3.1:8b');assert(Number.isInteger(result.attempts)&&result.attempts>=1&&result.attempts<=2);assert.equal(String(record.user_id),String(ownerId));assert.equal(record.run_id,run.run_id);assert.equal(record.owner_key,run.owner_key);assert.equal(String(record.owner_generation),String(execution.durableGeneration));assert.equal(record.objective_id,spec.objective);assert.equal(body.objectiveCandidate,spec.objective);assert.deepEqual(body.projectionPending,[]);assert.deepEqual(body.judgments,[grade.output.judgment]);assert.equal(body.judgments[0].evaluationId,record.evaluation_id);assert.equal(body.judgments[0].verdict,record.verdict);assert.equal(grade.output.receipt.runId,run.run_id);assert.equal(grade.output.receipt.evaluationId,record.evaluation_id);assert.equal(grade.output.receipt.disposition,record.disposition);assert.deepEqual(grade.output.receipt.result,result);assert.equal(record.workshop_key,'xss_workshop');assert.equal(String(record.generation),String(grade.attempt.generation));assert.equal(packet.rubric.objectiveId,spec.objective);
 let browserIndex=0,rebuilt;
 const grader=originalGrader({postgres:true,completionService:{async evaluate(value){assert.equal(rebuilt,undefined);rebuilt=value;return grade.output;}},browserQualification:{async qualify(html,options){const row=capture.browsers[browserIndex++];assert(row);assert.equal(html,row.html);assert.deepEqual(copy({...options,signal:undefined}),row.options);return copy(row.result);},close:async()=>{}}});
 await grader.evaluate({...input,attempt:grade.attempt,execution:{...execution,check:async()=>{}}});assert.equal(browserIndex,capture.browsers.length);assert(rebuilt);
 const judge=require('../../server/agent-runtime/objectiveJudge');const prepared=judge.prepareJudgeInput(rebuilt);assert.equal(prepared.evidenceError,undefined);assert.deepEqual(JSON.parse(prepared.packet),packet);assert.equal(prepared.evidenceDigest,record.evidence_digest);
 let index=0;const replay=await judge.createObjectiveJudge({model:{async chat(messages,tools,options){const row=judges[index++];assert(row);const request=JSON.parse(row.request);assert.deepEqual(request.messages,messages);assert.deepEqual(request.format,options.format);assert.deepEqual(tools,[]);return {response:rawText(row),provider:'ollama',model:'llama3.1:8b'};}}})({...packet,execution:{runId:run.run_id,check:async()=>{}}});assert.equal(index,judges.length);assert.equal(index,result.attempts);for(const key of ['verdict','criteria','explanation','attempts','judgeVersion','judgePolicyDigest','evidenceDigest','rubricVersion'])assert.deepEqual(replay[key],result[key],key);
 assert.equal(record.verdict,spec.completed?'pass':'fail');assert.equal(result.verdict,record.verdict);assert.equal(record.disposition,spec.completed?'awarded':'not_pass');assert.equal(body.completedObjectiveId,spec.completed);assert.equal(grade.output.completed,!!spec.completed);
 const priorExpected=cases.slice(0,cases.indexOf(spec));assert.deepEqual(prior.map(x=>x.binding?.caseId),priorExpected.map(x=>x.id));for(const earlier of prior){assert.equal(earlier.binding.status,'verified');const previous=earlier.records.find(x=>x.evaluation_id===earlier.binding.evaluationId);assert(previous);assert.notEqual(previous.run_id,record.run_id);assert.notEqual(previous.evaluation_id,record.evaluation_id);assert.equal(String(previous.generation),String(record.generation));assert.equal(String(previous.user_id),String(ownerId));for(const retained of earlier.completions){const current=completions.filter(x=>x.objective_id===retained.objective_id);assert.equal(current.length,1);assert.deepEqual(current[0],retained);}}
 const prerequisiteRows=validatePrerequisites(prerequisites,policy,ownerId);if(prerequisites){assert(Array.isArray(progress));for(const row of prerequisites.progress)assert.deepEqual(progress.find(x=>x.objective_id===row.objective_id),row);}for(const retained of prerequisiteRows){assert.deepEqual(completions.find(x=>x.objective_id===retained.objective_id),retained);}
 const expected=[...policy.prerequisiteIds,...cases.slice(0,cases.indexOf(spec)+1).filter(x=>x.completed).map(x=>x.completed)].sort();assert.deepEqual(completions.map(x=>x.objective_id).sort(),expected);for(const row of completions){assert.equal(String(row.user_id),String(ownerId));assert.equal(row.workshop_key,'xss_workshop');}
 if(spec.id==='reflected-preserve'){assert.equal(packet.facts.raw_html_dom_preserved,true);assert.equal(capture.browsers[0].result.learnerElementPreserved,true);}
 if(spec.objective==='xss_r3')assert.equal(packet.facts.isolated_browser_executed,!!spec.completed);
 return {caseId:spec.id,runId:run.run_id,evaluationId:record.evaluation_id,objectiveId:spec.objective,actorIndexes:actors.map(x=>x.index),judgeIndexes:judges.map(x=>x.index),selectedActorIndex:actors.at(-1).index,packetSha256:sha(typeof record.packet==='string'?record.packet:JSON.stringify(record.packet)),browserCalls:capture.browsers.length,status:'verified'};
}
module.exports={validatePrerequisites,connectOwnedQualificationBrowser,installObservation,bindCapture,rawText,object};
