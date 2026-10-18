'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {createRenderedBrowserEvidence,runRenderedStoredBrowser,getStoredBrowserResponseFailure}=require('./fixtures/renderedSecureShopBrowser');
const sha=v=>crypto.createHash('sha256').update(v).digest('hex');
const uuid=n=>`${String(n).padStart(8,'0')}-0000-4000-8000-000000000001`;
function fixture(){
 const binding={launchId:uuid(1),scenarioId:uuid(2),generation:1,platformOwnerId:11,platformSessionId:12,shopUserId:13,role:'customer'},renderer={sourceSha256:'a'.repeat(64),artifactSha256:'b'.repeat(64)},body='controlled raw payload',requestId=uuid(3),runId=uuid(4),evaluationId=uuid(5);
 const source={id:7,product_id:8,source_kind:'learner',source_version:1,submitted_by_shop_user_id:13,submitted_by_shop_role:'customer',body,body_sha256:Buffer.from(sha(body),'hex'),submission_id:uuid(6),request_sha256:Buffer.alloc(32,1),launch_id:binding.launchId,scenario_id:binding.scenarioId,generation:1,original_platform_owner_id:11,original_platform_session_id:12};
 const facts=Object.fromEntries(['learner_review_persisted','owner_bound_submission','actual_review_card_rendered','attributed_browser_execution','observable_browser_effect','completed_browser_effect','current_after_browser','vulnerable_mode'].map(key=>[key,true]));
 const component={id:'SecureShop.ReviewCard',...renderer};const receipt={version:1,runId,ownerKey:JSON.stringify(['SecureShopBoundConversation','session']),generation:'1',status:'completed',effectKey:`${requestId}:stored-browser:7`};
 const proof={receiptVersion:'secureshop-stored-browser-v1',component,source:{reviewId:7,productId:8,submissionId:source.submission_id,bodySha256:sha(body),requestSha256:source.request_sha256.toString('hex')},execution:{runId,effectReceipt:receipt},browser:{targetEventExecuted:true,targetEffectObserved:true,syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,provenance:'isolated_qualification_browser',markers:[{kind:'alert',value:'controlled browser event'}],reason:'browser_binding_target_execution'},currentAfterBrowser:true,facts};
 const packet={rubric:{objectiveId:'ss_stored_browser_execution',version:'secureshop-stored-browser-v1'},facts,evidence:[{id:'stored_browser_receipt',source:'server_observation',content:proof}]};
 const judgment={user_id:11,workshop_key:'secureshop_agent_security',objective_id:'ss_stored_browser_execution',platform_launch_id:binding.launchId,platform_scenario_id:binding.scenarioId,platform_launch_generation:1,evaluation_id:evaluationId,credited:evaluationId,run_id:runId,verdict:'pass',result_json:{verdict:'pass',provider:'ollama',model:'llama3.1:8b',criteria:[{id:'browser',satisfied:true}]}};
 const response={completed:true,replayed:false,reviewId:7,productId:8,judgment:{evaluationId},component,browser:{executed:true,reason:proof.browser.reason}};
 const {replayed,...journal}=response;
 const state={source,proof,packet,judgment,response,journal,run:{status:'completed',owner_key:receipt.ownerKey,generation:1},session:{authority_mode:'launch_bound',binding_state:'active',user_id:13,role:'customer',platform_launch_id:binding.launchId,platform_scenario_id:binding.scenarioId,platform_launch_generation:1,original_platform_owner_id:11,original_platform_session_id:12},effect:[{status:'completed'}]};
 function seal(){judgment.packet=JSON.stringify(packet);judgment.evidence_digest=sha(judgment.packet);}seal();
 const queries=[];const identityRuntime={async query(sql,args){queries.push({sql,args});return{rows:sql.includes('graph_runtime.runs')?[state.run]:sql.includes('graph_runtime.effects')?state.effect:[state.judgment]};}};
 const reviewRuntime={async query(){return{rows:[state.source]};}};const agentsRuntime={async query(sql){return{rows:sql.includes('turn_requests')?[{status:'completed',result_json:state.journal}]:[state.session]};}};
 return{state,seal,queries,evidence:createRenderedBrowserEvidence({identityRuntime,reviewRuntime,agentsRuntime,binding,renderer}),input:{before:[],productId:8,reviewId:7,requestId,body,response}};
}
test('complete stored-browser verifier binds native source, run/session, renderer, Judge and journal',async()=>{const f=fixture();assert.equal((await f.evidence.verify(f.input)).reviewId,7);assert.ok(f.queries.some(q=>q.sql.includes('graph_runtime.effects')&&q.args[3]===`${f.input.requestId}:stored-browser:7`));});
test('corrupted ownership, artifact, invented markers, empty facts/criteria and changed journal are rejected',async()=>{
 for(const mutate of [f=>f.state.source.submitted_by_shop_user_id=99,f=>f.state.source.submitted_by_shop_role='merchant',f=>f.state.session.original_platform_owner_id=99,f=>f.state.session.platform_scenario_id=uuid(9),f=>f.state.run.owner_key='["foreign","session"]',f=>f.state.run.generation=2,f=>f.state.proof.component.artifactSha256='c'.repeat(64),f=>f.state.proof.browser.markers=[{kind:'claimed',value:'payload says it ran'}],f=>{f.state.proof.facts={};f.state.packet.facts={};},f=>f.state.judgment.result_json.criteria=[],f=>f.state.journal={completed:false},f=>f.state.effect=[]]){const f=fixture();mutate(f);f.seal();await assert.rejects(f.evidence.verify(f.input));}
});
test('real Product form sequence preserves submitted body and automatic assessment request identity',async()=>{
 const f=fixture(),seen=[];let calls=0;const base='/api/secureshop/products/8/reviews';
 const page={async waitForResponse(){return calls++===0?{status:()=>200,json:async()=>({ok:true,review_id:7}),request:()=>({postData:()=>JSON.stringify({body:f.input.body})})}:{status:()=>200,url:()=>`http://127.0.0.1:35001${base}/7/browser-attempt`,json:async()=>f.input.response,request:()=>({postData:()=>JSON.stringify({request_id:f.input.requestId})})};}};
 const frame={async waitForSelector(selector){seen.push(selector);},async $eval(selector,_fn,value){seen.push(value===undefined?'submit':value);},async waitForFunction(){}};
 const evidence={snapshot:async()=>[],verify:async input=>{assert.equal(input.body,f.input.body);assert.equal(input.requestId,f.input.requestId);return{reviewId:input.reviewId};}};
 const result=await runRenderedStoredBrowser({page,frame,origin:'http://127.0.0.1:35001',productId:8,body:f.input.body,evidence});assert.deepEqual(seen,['textarea[aria-label="Review body"]',f.input.body,'submit']);assert.equal(result.reviewId,7);assert.equal(result.negativeVerified,false);
});

test('assessment body is captured on arrival while the submission body is still pending', async () => {
 const f=fixture();let resolvePosted,resolveAssessed,releaseSubmission;
 const posted=new Promise(resolve=>{resolvePosted=resolve;});
 const assessed=new Promise(resolve=>{resolveAssessed=resolve;});
 const submissionBody=new Promise(resolve=>{releaseSubmission=resolve;});
 let waits=0,assessmentAvailable=true,assessmentReads=0,submissionReads=0;
 const page={waitForResponse(){return waits++===0?posted:assessed;}};
 const frame={async waitForSelector(){},async waitForFunction(){},async $eval(_selector,_fn,value){
  if(value!==undefined)return;
  resolvePosted({status:()=>200,json(){submissionReads++;return submissionBody;},
   request:()=>({postData:()=>JSON.stringify({body:f.input.body})})});
  resolveAssessed({status:()=>200,url:()=> 'http://127.0.0.1:35001/api/secureshop/products/8/reviews/7/browser-attempt',
   async json(){assessmentReads++;if(!assessmentAvailable)throw new Error('response body evicted');return f.input.response;},
   request:()=>({postData:()=>JSON.stringify({request_id:f.input.requestId})})});
  setImmediate(()=>{assessmentAvailable=false;releaseSubmission({ok:true,review_id:7});});
 }};
 const evidence={snapshot:async()=>[],verify:async input=>{
  assert.equal(input.response,f.input.response);assert.equal(input.requestId,f.input.requestId);return{reviewId:7};
 }};
 const result=await runRenderedStoredBrowser({page,frame,origin:'http://127.0.0.1:35001',productId:8,body:f.input.body,evidence});
 assert.equal(result.reviewId,7);assert.equal(submissionReads,1);assert.equal(assessmentReads,1);assert.equal(waits,2);
});

test('response capture preserves the original body-read failure without fallback or evidence credit',async()=>{
 const f=fixture(),failure=new Error('body unavailable');let calls=0,verified=0;
 const page={async waitForResponse(){return calls++===0?{status:()=>200,json:async()=>({ok:true,review_id:7}),
  request:()=>({postData:()=>JSON.stringify({body:f.input.body})})}:{status:()=>200,json:async()=>{throw failure;}};}};
 const frame={async waitForSelector(){},async waitForFunction(){},async $eval(){}};
 const evidence={snapshot:async()=>[],verify:async()=>{verified++;}};
 await assert.rejects(runRenderedStoredBrowser({page,frame,origin:'http://127.0.0.1:35001',productId:8,body:f.input.body,evidence}),error=>error===failure);
 assert.equal(calls,2);assert.equal(verified,0);
});

for (const label of ['submission', 'assessment']) {
 test(`capture diagnostic attributes ${label} failure to the exact original request`, async () => {
  const { EventEmitter } = require('node:events');
  const f=fixture(), page=new EventEmitter(), mainFrame={}, secret='private-url-body-id';
  const failure=new Error(`Protocol error (Network.getResponseBody): ${secret}`);
  const frame={async waitForSelector(){},async waitForFunction(){},async $eval(){}};
  const request={method:()=> 'POST', failure:()=>({errorText:'net::ERR_ABORTED'}),
   postData:()=>JSON.stringify({body:f.input.body,request_id:f.input.requestId})};
  const otherRequest={method:()=> 'POST',failure:()=>({errorText:secret}),postData:request.postData};
  let calls=0,reads=0,verified=0;
  page.mainFrame=()=>mainFrame;
  page.waitForResponse=async()=>{
   const current=calls++===0?'submission':'assessment';
   return {status:()=>200,request:()=>current===label?request:otherRequest,
    frame:()=>mainFrame,url:()=> 'http://127.0.0.1:35001/api/secureshop/products/8/reviews/7/browser-attempt',
    json:async()=>{reads++;
     if(current===label){page.emit('requestfailed',request);page.emit('requestfinished',otherRequest);throw failure;}
     return current==='submission'?{ok:true,review_id:7}:f.input.response;
    }};
  };
  const evidence={snapshot:async()=>[],verify:async()=>{verified++;}};
  await assert.rejects(runRenderedStoredBrowser({page,frame,origin:'http://127.0.0.1:35001',
   productId:8,body:f.input.body,evidence}),error=>error===failure);
  const diagnostic=getStoredBrowserResponseFailure(failure);
  assert.equal(diagnostic.responseLabel,label);assert.equal(diagnostic.status,200);
  assert.equal(diagnostic.method,'POST');assert.equal(diagnostic.frameRelation,'main_frame');
  assert.equal(diagnostic.category,'response_body_protocol_failure');
  assert.equal(diagnostic.requestTerminal,'failed');assert.equal(diagnostic.requestFailureCategory,'aborted');
  assert.equal(diagnostic.requestEventsSupported,true);assert.ok(Object.isFrozen(diagnostic));
  assert.ok(diagnostic.responseAtMs<=diagnostic.bodyReadStartedAtMs);
  assert.ok(diagnostic.bodyReadStartedAtMs<=diagnostic.bodyReadFailedAtMs);
  assert.ok(diagnostic.requestTerminalAtMs<=diagnostic.bodyReadFailedAtMs);
  assert.equal(JSON.stringify(diagnostic).includes(secret),false);
  assert.equal(page.listenerCount('requestfinished'),0);assert.equal(page.listenerCount('requestfailed'),0);
  assert.equal(calls,2);assert.equal(reads,2);assert.equal(verified,0);
 });
}

test('unsupported diagnostic methods remain unknown and arbitrary errors cannot forge observations',async()=>{
 const failure=new Error('private content');let calls=0;
 const page={waitForResponse:async()=>calls++===0?{json:async()=>{throw failure;}}:{json:async()=>({})}};
 const frame={async waitForSelector(){},async waitForFunction(){},async $eval(){}};
 await assert.rejects(runRenderedStoredBrowser({page,frame,origin:'http://127.0.0.1:35001',productId:8,
  body:'private content',evidence:{snapshot:async()=>[],verify:async()=>assert.fail('no evidence credit')}}),error=>error===failure);
 const d=getStoredBrowserResponseFailure(failure);
 assert.equal(d.status,null);assert.equal(d.method,'unknown');assert.equal(d.frameRelation,'unknown');
 assert.equal(d.requestEventsSupported,false);assert.equal(d.requestTerminal,'unknown');assert.equal(d.requestTerminalAtMs,null);
 for(const error of [null,undefined,'failure',{},new Error('private content'),{diagnostic:d}])assert.equal(getStoredBrowserResponseFailure(error),null);
});

test('capture event listeners are removed on success and early form failure',async()=>{
 const {EventEmitter}=require('node:events');
 for(const earlyFailure of [false,true]){
  const f=fixture(),page=new EventEmitter(),failure=new Error('form unavailable');let calls=0;
  const request={postData:()=>JSON.stringify({body:f.input.body,request_id:f.input.requestId})};
  page.waitForResponse=async()=>{const submission=calls++===0;return{status:()=>200,request:()=>request,
   url:()=> 'http://127.0.0.1:35001/api/secureshop/products/8/reviews/7/browser-attempt',
   json:async()=>{page.emit('requestfinished',request);return submission?{ok:true,review_id:7}:f.input.response;}};};
  const frame={async waitForSelector(){if(earlyFailure)throw failure;},async waitForFunction(){},async $eval(){}};
  const run=runRenderedStoredBrowser({page,frame,origin:'http://127.0.0.1:35001',productId:8,body:f.input.body,
   evidence:{snapshot:async()=>[],verify:async()=>({reviewId:7})}});
  if(earlyFailure)await assert.rejects(run,error=>error===failure);else await run;
  assert.equal(page.listenerCount('requestfinished'),0);assert.equal(page.listenerCount('requestfailed'),0);
 }
});
