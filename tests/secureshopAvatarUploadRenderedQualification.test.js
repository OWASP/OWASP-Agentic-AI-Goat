'use strict';
const assert=require('node:assert/strict');
const fs=require('node:fs');const path=require('node:path');const{test}=require('node:test');
const helper=require('./fixtures/secureshopAvatarUploadRenderedQualification');
test('V06 qualification helper pins the canonical objective and assessment contract',()=>{assert.equal(helper.V06_BROWSER_OBJECTIVE,'ss_upload_extension_bypass');assert.equal(helper.V06_BROWSER_RUBRIC,'secureshop-upload-extension-bypass-v3-layered');assert.equal(helper.V06_BROWSER_RUBRIC,require('../server/services/secureshopV06UploadEvidence').UPLOAD_RUBRIC.version);assert.equal(helper.V06_BROWSER_SCENARIO,'bound_upload_extension_bypass');assert.deepEqual(helper.assertAssessment({completed:false,status:'ineligible',modelEvaluated:false},{completed:false}),{completed:false,status:'ineligible',modelEvaluated:false});assert.throws(()=>helper.assertAssessment({completed:true,judgment:{verdict:'fail',evaluationId:'00000000-0000-4000-8000-000000000001',canRetry:false},replayed:false},{completed:true}));});
test('V06 graph observation captures the actual parsed attachment bytes and exact request fields',()=>{const bytes=Buffer.from('<p>owned</p>','utf8');const captured=helper.captureGraphRunAttachment({sessionId:'00000000-0000-4000-8000-000000000001',requestId:'00000000-0000-4000-8000-000000000002',message:'Upload this bounded synthetic attachment.',attachment:{bytes,filename:'owned.html',mime:'text/html',public:true}});assert.deepEqual(captured.fields,{sessionId:'00000000-0000-4000-8000-000000000001',requestId:'00000000-0000-4000-8000-000000000002',message:'Upload this bounded synthetic attachment.',public:'true'});assert.deepEqual({...captured.file,bodySha256:'[sha]'},{filename:'owned.html',mime:'text/html',byteCount:12,bodySha256:'[sha]',bodyBase64:bytes.toString('base64'),partCount:1});assert.throws(()=>helper.captureGraphRunAttachment({sessionId:captured.fields.sessionId,requestId:captured.fields.requestId,message:'x',attachment:{bytes:Buffer.alloc(8193),filename:'x',mime:'text/plain',public:true}}));});
test('V06 actor request rejects wrong call counts and retains exact original fields',()=>{const input={sessionId:'00000000-0000-4000-8000-000000000001',requestId:'00000000-0000-4000-8000-000000000002',message:'Upload this bounded synthetic attachment.',public:'true',calls:2};assert.equal(helper.assertActorRequest(input,{sessionId:input.sessionId,requestId:input.requestId,message:input.message,publicAsset:true}),input);for(const calls of[true,1,3])assert.throws(()=>helper.assertActorRequest({...input,calls},{sessionId:input.sessionId,requestId:input.requestId,message:input.message,publicAsset:true}));});
test('V06 helper uses physical file selection, bound-frame reads, reload reselection, and exact grading actions',()=>{const source=fs.readFileSync(path.join(__dirname,'fixtures/secureshopAvatarUploadRenderedQualification.js'),'utf8');for(const pattern of[/waitForFileChooser/,/chooser\.accept/,/captureGraphRunAttachment/,/readOriginalMultipart/,/assertOriginalGraphEvidence/,/readCanonicalProgress/,/frame\.evaluate\(async/,/await selectLesson\(page,frame\)/,/Assess saved avatar upload/,/Check saved avatar-upload assessment/])assert.match(source,pattern);assert.doesNotMatch(source,/fetchPostData|getRequestPostData|localStorage/);assert.doesNotMatch(source,/page\.evaluate\(async\(\{base,operationId\}|setInputFiles|file_bytes_base64|frame\.select/);});
test('V06 cohort observes acknowledged parent state through the exact controller storage branch',()=>{const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');for(const pattern of[/assert\.notEqual\(target\.scene\.sceneId,actor\.scope\.scenarioId\)/,/v06ParentStorageBase=`owasp-ai-goat:secureshop:\$\{actor\.scope\.launchId\.toLowerCase\(\)\}:\$\{actor\.scope\.generation\}`/,/localStorage\.getItem\(`\$\{baseKey\}:scene-storage-v1`\)/,/marker!==null&&marker!=='1'/,/marker===null\?baseKey:`\$\{baseKey\}:scene:\$\{sceneId\}`/,/sceneId:target\.scene\.sceneId\.toLowerCase\(\)/])assert.match(source,pattern);assert.doesNotMatch(source,/readV06AcknowledgedReference[\s\S]{0,900}localStorage\.length/);});
test('V06 actual evidence reader joins production turn, trace, graph, file, serve, Judge and progress rows',()=>{const source=fs.readFileSync(path.join(__dirname,'fixtures/secureshopV06ActualEvidence.js'),'utf8');for(const phrase of['secureshop_agents.turn_requests','getTraceEvents','graph_runtime.effects','bound_upload_admissions','bound_upload_effects','bound_upload_serves','stored_binding_sha256','stored_effect_sha256','stored_serve_sha256','buildUploadCandidate','assertRetainedPacket','assessment_judgments','result_serialized','result_digest','active_assessment_contributions','assessment_completions','readCanonicalProgress','bound_upload_cleanup_receipts'])assert.ok(source.includes(phrase),phrase);});
test('V08 reuses the neutral qualified upload source without requiring V06 extension candidate admission',()=>{const upload=fs.readFileSync(path.join(__dirname,'fixtures/secureshopV06ActualEvidence.js'),'utf8'),svg=fs.readFileSync(path.join(__dirname,'fixtures/secureshopV08ActualEvidence.js'),'utf8');const neutral=upload.slice(upload.indexOf('function requireQualifiedUploadSource'),upload.indexOf('async function readOriginalUploadEvidence'));const v06=upload.slice(upload.indexOf('async function readOriginalUploadEvidence'),upload.indexOf('async function assertCanonicalUploadAssessment'));assert.ok(neutral.includes('readOriginalUploadTurnGraph'));assert.ok(neutral.includes('bound_upload_serves'));assert.ok(neutral.includes('readQualifiedUploadSource'));assert.ok(neutral.includes('assert.ok(provenance)'));assert.match(neutral,/readOriginalUploadReceipt\(\{[^}]*personaSession/);assert.ok(!neutral.includes('buildUploadCandidate'));assert.ok(v06.includes('buildUploadCandidate'));assert.ok(v06.includes('assert.ok(candidate)'));assert.ok(svg.includes('Upload.readOriginalUploadReceipt(input)'));assert.ok(svg.includes('value.provenance'));assert.ok(!svg.includes('Upload.readOriginalUploadEvidence(input)'));});
test('neutral retained upload qualification forwards the exact persona session to the source validator',()=>{const evidence=require('./fixtures/secureshopV06ActualEvidence'),sentinels={binding:{id:'binding'},personaSession:{sessionId:'00000000-0000-4000-8000-000000000001'},row:{id:'row'},traces:[{id:'trace'}],retained:{id:'retained'},graphEffect:{id:'effect'},qualifyModel:()=>true};let observed;evidence.requireQualifiedUploadSource({...sentinels,reader:value=>{observed=value;return Object.freeze({verified:true});}});assert.deepEqual(observed,sentinels);assert.throws(()=>evidence.requireQualifiedUploadSource({...sentinels,reader:()=>null}));});
test('V06 candidate admission rejects non-disposable use before catalog access or fixture SQL',async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='no';let effects=0;
 const unexpected=()=>{effects++;throw Error('No candidate effect outside disposable qualification');};
 try{await assert.rejects(admitV06DisposableCandidate({migration:{query:unexpected},catalog:{list:unexpected,set:unexpected}}),assert.AssertionError);assert.equal(effects,0);}
 finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
test('V06 plan keeps upload, serve, Judge, progress, fixed, sibling and reset evidence distinct',()=>{const plan=fs.readFileSync(path.join(__dirname,'../tasks/secureshop-v06-actual-browser-qualification-plan-2026-10-15.md'),'utf8');for(const phrase of['ss_upload_extension_bypass','secureshop-upload-extension-bypass-v2','uploads.upload_avatar','first-serve receipt','canonical progress','ineligible projection','Sibling owner','Reset fences','no POST retries'])assert.ok(plan.includes(phrase),phrase);});
test('V06 canonical progress excludes a completion with a mismatched objective or generation',()=>{const source=fs.readFileSync(path.join(__dirname,'fixtures/secureshopV06ActualEvidence.js'),'utf8');for(const phrase of['h.objective_id=c.objective_id','h.generation=c.generation','j.objective_id=c.objective_id','j.generation=c.generation'])assert.ok(source.includes(phrase),phrase);});
test('V06 GET-only reload recovery accepts the exact six-counter contract and preserves every counter',async()=>{const uuid='00000000-0000-4000-8000-000000000001',calls={reload:0,lesson:0,get:0};const selector={click:async()=>{},evaluate:async()=> 'avatar-upload-lesson'};const handle={asElement:()=>({evaluate:async()=>{},click:async()=>{}}),dispose:async()=>{}};const frame={waitForSelector:async(value)=>{if(value==='[data-testid="agent-lane"] select')calls.lesson++;return selector;},waitForFunction:async()=>handle};const page={reload:async()=>{calls.reload++;},waitForRequest:async predicate=>{assert.equal(predicate({method:()=> 'GET',url:()=>`http://app/api/secureshop/agents/customer/avatar-upload/operations/${uuid}`}),true);calls.get++;},keyboard:{type:async()=>{},press:async()=>{}}};const counters={actor:2,tools:1,writes:1,mints:1,judges:0,serves:1};assert.equal(await helper.recoverAfterReload({page,getFrame:async()=>frame,reference:{operationId:uuid},beforeCounters:async()=>({...counters}),afterCounters:async()=>({...counters})}),frame);assert.deepEqual(calls,{reload:1,lesson:1,get:1});await assert.rejects(()=>helper.recoverAfterReload({page,getFrame:async()=>frame,reference:{operationId:uuid},beforeCounters:async()=>({actor:2,tools:1,writes:1,mints:1,judges:0}),afterCounters:async()=>({...counters})}));});
test('V06 canonical assessment traverses the product selector and exact saved identity',async()=>{const sessionId='00000000-0000-4000-8000-000000000001',requestId='00000000-0000-4000-8000-000000000002',evaluationId='00000000-0000-4000-8000-000000000003',seen=[];const result={completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:false};const response={status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify(result),request:()=>({postData:()=>JSON.stringify({sessionId,requestId})})};let reads=0;const handle={asElement:()=>({evaluate:async()=>{},click:async()=>{}}),dispose:async()=>{}};const frame={waitForFunction:async(fn)=>{seen.push(String(fn));return handle;}};const observedRequest={method:()=> 'POST',url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/assess',postData:()=>JSON.stringify({sessionId,requestId})};const page={waitForRequest:async predicate=>{assert.equal(predicate(observedRequest),true);return observedRequest;},waitForResponse:async predicate=>{assert.equal(predicate({request:()=>observedRequest,url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/assess'}),true);return response;}};const assessmentRef={version:1,shopUserId:7,sessionId,requestId,startedAt:1};assert.deepEqual(await helper.runCanonicalAssessment({page,frame,sessionId,requestId,completed:true,readCanonicalProgress:async objective=>{assert.equal(objective,'ss_upload_extension_bypass');return true;},readAcknowledgedReference:async()=>reads++===0?null:assessmentRef}),result);assert.equal(reads,3);assert.ok(seen.some(value=>value.includes('[aria-label="Saved avatar upload"]')));assert.ok(seen.every(value=>!value.includes('Saved avatar upload request')));});
test('V06 saved assessment recovery uses all six no-replay counters',async()=>{const sessionId='00000000-0000-4000-8000-000000000001',requestId='00000000-0000-4000-8000-000000000002',evaluationId='00000000-0000-4000-8000-000000000003';const result={completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:true};const response={status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify(result),request:()=>({method:()=> 'GET'}),url:()=>`http://app/api/secureshop/agents/customer/avatar-upload/assess/${sessionId}/${requestId}`};const handle={asElement:()=>({evaluate:async()=>{},click:async()=>{}}),dispose:async()=>{}};const frame={waitForFunction:async()=>handle};const page={waitForResponse:async predicate=>{assert.equal(predicate(response),true);return response;}};const counters={actor:2,tools:1,writes:1,mints:1,judges:1,serves:1};assert.deepEqual(await helper.recoverCanonicalAssessment({page,frame,sessionId,requestId,evaluationId,beforeCounters:async()=>({...counters}),afterCounters:async()=>({...counters})}),result);await assert.rejects(()=>helper.recoverCanonicalAssessment({page,frame,sessionId,requestId,evaluationId,beforeCounters:async()=>({...counters}),afterCounters:async()=>({...counters,writes:2})}));});
test('V06 fixture persists bounded private original evidence even when the success receipt is absent',()=>{const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');assert.match(source,/if\(UPLOAD_BROWSER\)\{const evidenceText=/);assert.doesNotMatch(source,/if\(V06_UPLOAD&&v06Receipt\)\{const evidenceText=/);assert.match(source,/if\(v06Receipt\)\{v06Receipt\.evidenceSha256=/);assert.match(source,/readV06AcknowledgedReference=async referenceKey=>page\.evaluate/);});
test('upload browser reset and bound review composition share one owned files primitive',()=>{const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');assert.match(source,/const sharedFiles = V44_PATH_SUMMARY\?require[\s\S]{0,180}:require\('\.\.\/fixtures\/secureshopAvatarUploadRenderedQualification'\)[\s\S]{0,180}createUploadBrowserFiles\(\{ uploadRoot, v19Files: v19\?\.files, uploadBrowser: UPLOAD_BROWSER \}\)/);assert.match(source,/createSecureShopCleanupComposition\(\{[\s\S]{0,300}\.\.\.\(sharedFiles \? \{ files: sharedFiles \} : \{\}\)/);assert.match(source,/if \(UPLOAD_BROWSER\) assert\.equal\(reset\.files, sharedFiles\)/);assert.match(source,/createSecureShopBoundReviewComposition\(\{[\s\S]{0,900}\.\.\.\(sharedFiles \? \{ files: sharedFiles \} : \{\}\)/);assert.match(source,/\.\.\.\(v19 \? \{ fileSummaryFeature: true \} : \{\}\)/);});
test('upload browser files are explicit and non-vacuous in the clean launcher environment',()=>{const prior=process.env.OWASP_AI_GOAT_APP_DATA_ROOT;delete process.env.OWASP_AI_GOAT_APP_DATA_ROOT;const calls=[],files=Object.freeze(Object.fromEntries(['provisionReservedTarget','openExistingReservedTarget','readReservedCleanupReceipt','retireReservedTarget'].map(name=>[name,()=>name])));try{const selected=helper.createUploadBrowserFiles({uploadRoot:'/private/owned-run/v08-upload-root',uploadBrowser:true,createFiles:options=>{calls.push(options);return files;}});assert.equal(selected,files);assert.deepEqual(calls,[{root:'/private/owned-run/v08-upload-root-owned-files',maxReadBytes:20*1024*1024,maxWriteBytes:20*1024*1024}]);assert.equal(helper.createUploadBrowserFiles({uploadRoot:'/unused',v19Files:files,uploadBrowser:false,createFiles:()=>{throw Error('V19 must retain its object');}}),files);assert.equal(helper.createUploadBrowserFiles({uploadRoot:'/unused',uploadBrowser:false,createFiles:()=>{throw Error('inactive cohort must not construct files');}}),undefined);assert.throws(()=>helper.createUploadBrowserFiles({uploadRoot:'/private/owned-run/v08-upload-root',uploadBrowser:true,createFiles:()=>({})}));}finally{if(prior===undefined)delete process.env.OWASP_AI_GOAT_APP_DATA_ROOT;else process.env.OWASP_AI_GOAT_APP_DATA_ROOT=prior;}});
test('V06 raw actor choice is exactly joined to the persisted decision and graph receipt',()=>{const Evidence=require('./fixtures/secureshopV06ActualEvidence');const response=(tool_uses=[])=>({provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false,tool_uses});const actorSpans=[{method:'chat',response:response([{id:'call-owned',name:'uploads.upload_avatar',args:{}}])},{method:'finalResponse',response:response([])}];const traces=[{kind:'model_decision',step:1,provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'call-owned',name:'uploads.upload_avatar',args:{}}]})},{kind:'local_tool_call',step:1,agent_ns:'uploads',tool_name:'upload_avatar',params_json:'{}'},{kind:'local_tool_result',step:1,agent_ns:'uploads',tool_name:'upload_avatar',result_json:'{}'},{kind:'model_decision',step:2,provider:'ollama',result_json:JSON.stringify({decision:'final'})}];const graphEffect={step:1,callId:'call-owned'};assert.deepEqual(Evidence.assertActorTraceJoin({actorSpans,traces,graphEffect}),{callId:'call-owned',provider:'ollama',model:'llama3.1:8b'});assert.throws(()=>Evidence.assertActorTraceJoin({actorSpans:[...actorSpans,{method:'finalResponse',response:response([])}],traces,graphEffect}));assert.throws(()=>Evidence.assertActorTraceJoin({actorSpans:[{...actorSpans[0],response:response([{id:'call-owned',name:'uploads.other',args:{}}])},actorSpans[1]],traces,graphEffect}));assert.throws(()=>Evidence.assertActorTraceJoin({actorSpans:[{...actorSpans[0],response:response([{id:'call-owned',name:'uploads.upload_avatar',args:{extra:true}}])},actorSpans[1]],traces,graphEffect}));});
test('V06 controlled rendered upload traverses physical chooser, parent acknowledgement, graph bytes and bound GET',async()=>{const os=require('node:os'),filePath=path.join(os.tmpdir(),`v06-controlled-${process.pid}.html`),bytes=Buffer.from('<p>owned</p>');fs.writeFileSync(filePath,bytes,{mode:0o600});const sessionId='00000000-0000-4000-8000-000000000001',requestId='00000000-0000-4000-8000-000000000002',operationId='00000000-0000-4000-8000-000000000003',intent={version:1,shopUserId:7,sessionId,requestId,operationId:null,startedAt:1},reference={...intent,operationId};let active='',typed='',accepted=[],referenceReads=0;const element=selector=>({click:async()=>{active=selector;},evaluate:async fn=>selector.includes('agent-lane')?'avatar-upload-lesson':fn({value:typed,scrollIntoView(){}})});const handle={asElement:()=>({evaluate:async()=>{},click:async()=>{}}),dispose:async()=>{}};const frame={waitForSelector:async selector=>element(selector),waitForFunction:async fn=>String(fn).includes('querySelectorAll')?handle:true,$eval:async()=>true,$:async selector=>element(selector),evaluate:async()=>({status:200,type:'application/json',text:JSON.stringify({operationId,uploadRequestId:requestId,status:'completed',filename:path.basename(filePath),byteCount:bytes.length,bodySha256:require('node:crypto').createHash('sha256').update(bytes).digest('hex')})})};const request={method:()=> 'POST',url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/run',headers:()=>({'content-type':'multipart/form-data; boundary=physical'})};const sessionResponse={status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify({id:sessionId}),request:()=>({method:()=> 'POST'}),url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/session'};const page={waitForFileChooser:async()=>({accept:async paths=>{accepted=paths;}}),waitForResponse:async predicate=>{assert.equal(predicate({request:()=>({method:()=> 'POST'}),url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/session'}),true);return sessionResponse;},waitForRequest:async predicate=>{assert.equal(predicate(request),true);return request;},keyboard:{type:async value=>{if(active.includes('message'))typed+=value;},press:async key=>{if(active.includes('message')&&key==='Backspace')typed=typed.slice(0,-1);}}};const bodySha256=require('node:crypto').createHash('sha256').update(bytes).digest('hex');try{const result=await helper.runRenderedUpload({page,frame,filePath,filename:path.basename(filePath),mime:'text/html',byteCount:bytes.length,message:'Upload owned bytes.',expectedStatus:'completed',bodySha256,readAcknowledgedReference:async key=>{assert.equal(key,'secureshop.customer-avatar-upload.lesson.v1');return referenceReads++===0?intent:reference;},observeSessionResponse:async value=>{assert.deepEqual(value,{method:'POST',pathname:'/api/secureshop/agents/customer/avatar-upload/session',status:200,contentType:'application/json',category:'success',body:{id:sessionId},responseBodyError:null});},readOriginalMultipart:async()=>helper.captureGraphRunAttachment({sessionId,requestId,message:'Upload owned bytes.',attachment:{bytes,filename:path.basename(filePath),mime:'text/html',public:true}}),assertOriginalGraphEvidence:async()=>true});assert.deepEqual(accepted,[filePath]);assert.equal(result.reference,reference);assert.equal(referenceReads,2);assert.equal(result.saved.bodySha256,bodySha256);}finally{fs.rmSync(filePath,{force:true});}});

test('V06 session failure is retained before any multipart upload is accepted',async()=>{const os=require('node:os'),filePath=path.join(os.tmpdir(),`v06-session-failure-${process.pid}.html`);fs.writeFileSync(filePath,'<p>owned</p>',{mode:0o600});let active='',typed='',observed=null,runAccepted=false;const element=selector=>({click:async()=>{active=selector;},evaluate:async fn=>selector.includes('agent-lane')?'avatar-upload-lesson':fn({value:typed,scrollIntoView(){}})});const handle={asElement:()=>({evaluate:async()=>{},click:async()=>{}}),dispose:async()=>{}};const frame={waitForSelector:async selector=>element(selector),waitForFunction:async()=>handle,$eval:async()=>true,$:async selector=>element(selector)};const session={status:()=>503,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify({error:'Avatar upload unavailable'}),request:()=>({method:()=> 'POST'}),url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/session'};const page={waitForFileChooser:async()=>({accept:async()=>{}}),waitForResponse:async predicate=>{assert.equal(predicate({request:()=>({method:()=> 'POST'}),url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/session'}),true);return session;},waitForRequest:async()=>new Promise(()=>{}),keyboard:{type:async value=>{if(active.includes('message'))typed+=value;},press:async key=>{if(active.includes('message')&&key==='Backspace')typed=typed.slice(0,-1);}}};try{await assert.rejects(()=>helper.runRenderedUpload({page,frame,filePath,filename:path.basename(filePath),mime:'text/html',byteCount:12,message:'Upload owned bytes.',expectedStatus:'completed',bodySha256:'0'.repeat(64),readAcknowledgedReference:async()=>null,observeSessionResponse:async value=>{observed=value;},readOriginalMultipart:async()=>{runAccepted=true;},assertOriginalGraphEvidence:async()=>true}),error=>error?.code==='ERR_ASSERTION');assert.deepEqual(observed,{method:'POST',pathname:'/api/secureshop/agents/customer/avatar-upload/session',status:503,contentType:'application/json',category:'public-error',body:{error:'Avatar upload unavailable'},responseBodyError:null});assert.equal(runAccepted,false);}finally{fs.rmSync(filePath,{force:true});}});
test('V06 session capture preserves status and path when CDP response body is unavailable',async()=>{const error=Object.assign(new Error('No data found for resource'),{name:'ProtocolError',code:'ERR_PROTOCOL'});const response={status:()=>503,headers:()=>({'content-type':'application/json'}),text:async()=>{throw error;},request:()=>({method:()=> 'POST'}),url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/session'};assert.deepEqual(await helper.readSessionResponse(response),{method:'POST',pathname:'/api/secureshop/agents/customer/avatar-upload/session',status:503,contentType:'application/json',category:'body-unavailable',body:null,responseBodyError:{name:'ProtocolError',code:'ERR_PROTOCOL'}});});
test('V06 owned server capture snapshots the public session path before nested routing mutates it',()=>{const{EventEmitter}=require('node:events'),res=new EventEmitter(),req={method:'POST',path:'/agents/customer/avatar-upload/session'};res.statusCode=503;res.getHeader=name=>name==='content-type'?'application/json; charset=utf-8':undefined;res.end=function(){this.emit('finish');};let observed;helper.captureFinishedSessionResponse(req,res,value=>{observed=value;});req.method='GET';req.path='/session';res.end(JSON.stringify({error:'Avatar upload unavailable'}));assert.deepEqual(observed,{method:'POST',pathname:'/api/secureshop/agents/customer/avatar-upload/session',status:503,contentType:'application/json; charset=utf-8',body:{error:'Avatar upload unavailable'},error:null});});
test('V06 session body capture times out as a diagnostic failure without cancelling the product request',async()=>{const response={status:()=>404,headers:()=>({'content-type':'application/json'}),text:()=>new Promise(()=>{}),request:()=>({method:()=> 'POST'}),url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/session'};assert.deepEqual(await helper.readSessionResponse(response,{bodyTimeoutMs:5}),{method:'POST',pathname:'/api/secureshop/agents/customer/avatar-upload/session',status:404,contentType:'application/json',category:'body-unavailable',body:null,responseBodyError:{name:'TimeoutError',code:'RESPONSE_BODY_TIMEOUT'}});});
test('V06 fixture has a dedicated pre-checkout branch and preserves V01 checkout isolation',()=>{const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');assert.match(source,/const CHECKOUT_LIFECYCLE = process\.env\.SECURESHOP_CUSTOMER_CHECKOUT_NATIVE === '1' \|\| V01_AUDIT;/);assert.doesNotMatch(source,/CHECKOUT_NATIVE === '1' \|\| V01_AUDIT \|\| V06_UPLOAD/);assert.ok(source.indexOf("if(V06_UPLOAD){\n        stage='v06-vulnerable-rendered'")<source.indexOf('if (PRODUCT_DETAILS || STOCK_REJECTION)'));assert.match(source,/else \{\n      const home =/);assert.match(source,/if\(V01_AUDIT\)\{\n        stage='v01-vulnerable-rendered'/);assert.match(source,/V01_AUDIT \? V01_CHECKOUT_FLAGS : CHECKOUT_FLAGS/);});
test('V06 session diagnostics classify malformed public responses before shape assertions',()=>{const source=fs.readFileSync(path.join(__dirname,'fixtures/secureshopAvatarUploadRenderedQualification.js'),'utf8');for(const phrase of["'body-unavailable'","'body-too-large'","'content-type'","'invalid-json'","'invalid-shape'","'public-error'",'responseBodyError','readSessionResponse'])assert.ok(source.includes(phrase));assert.ok(source.indexOf('await observeSessionResponse(sessionObservation)')<source.indexOf("assert.equal(sessionObservation.category,'success')"));assert.match(source,/then\(async value=>\(\{value,intent:structuredClone\(await readAcknowledgedReference/);assert.match(source,/assert\.equal\(intent\.sessionId,sessionBody\.id\)/);});

test('V08 SVG assessment has a distinct objective, exact physical action, and one browser effect plus Judge',async()=>{assert.equal(helper.V08_BROWSER_OBJECTIVE,'ss_upload_svg_browser_execution');assert.equal(helper.V08_BROWSER_RUBRIC,'secureshop-upload-svg-browser-v3-layered');assert.equal(helper.V08_BROWSER_RUBRIC,require('../server/services/secureshopV08SvgEvidence').RUBRIC.version);assert.equal(helper.V08_BROWSER_SCENARIO,'bound_upload_svg_browser');const sessionId='00000000-0000-4000-8000-000000000011',requestId='00000000-0000-4000-8000-000000000012',evaluationId='00000000-0000-4000-8000-000000000013';const result={completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:false};const observed={method:()=> 'POST',url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/svg-assess',postData:()=>JSON.stringify({sessionId,requestId})};const response={status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify(result),request:()=>observed};const clicked=[];const handle={asElement:()=>({evaluate:async()=>{},click:async()=>{clicked.push('assess');}}),dispose:async()=>{}};const frame={waitForFunction:async(fn,{},{label,selector}={})=>{if(label)assert.deepEqual({label,selector},{label:'Assess saved SVG browser execution',selector:'[data-testid="avatar-svg-assess"]'});return handle;}};const page={waitForRequest:async predicate=>{assert.equal(predicate(observed),true);return observed;},waitForResponse:async predicate=>{assert.equal(predicate({request:()=>observed,url:()=>observed.url()}),true);return response;}};let reads=0;const ref={version:1,shopUserId:9,sessionId,requestId,startedAt:1},before={actor:2,tools:1,writes:1,mints:1,judges:0,serves:1,svgEffects:0,svgMints:0},after={...before,judges:1,svgEffects:1,svgMints:1};assert.deepEqual(await helper.runSvgCanonicalAssessment({page,frame,sessionId,requestId,readCanonicalProgress:async objective=>{assert.equal(objective,'ss_upload_svg_browser_execution');return true;},readAcknowledgedReference:async key=>{assert.equal(key,'secureshop.customer-avatar-upload.svg-assessment.v1');return reads++===0?null:ref;},readAssessmentResponse:async value=>JSON.parse(await value.text()),beforeCounters:async()=>before,afterCounters:async()=>after}),result);assert.equal(reads,3);assert.deepEqual(clicked,['assess']);});
test('V08 helper exposes no manufactured fixed assessment action',()=>{const body=String(helper.runSvgCanonicalAssessment);assert.match(body,/completed:true/);assert.doesNotMatch(body,/completed:false|ineligible/);});
test('V08 saved GET recovery is exact and preserves all eight counters',async()=>{const sessionId='00000000-0000-4000-8000-000000000031',requestId='00000000-0000-4000-8000-000000000032',evaluationId='00000000-0000-4000-8000-000000000033',result={completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:true},response={status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify(result),request:()=>({method:()=> 'GET'}),url:()=>`http://app/api/secureshop/agents/customer/avatar-upload/svg-assess/${sessionId}/${requestId}`},handle={asElement:()=>({evaluate:async()=>{},click:async()=>{}}),dispose:async()=>{}},frame={waitForFunction:async()=>handle},page={waitForResponse:async predicate=>{assert.equal(predicate(response),true);return response;}},counters={actor:2,tools:1,writes:1,mints:1,judges:1,serves:1,svgEffects:1,svgMints:1};assert.deepEqual(await helper.recoverSvgCanonicalAssessment({page,frame,sessionId,requestId,evaluationId,readAssessmentResponse:async value=>JSON.parse(await value.text()),beforeCounters:async()=>counters,afterCounters:async()=>({...counters})}),result);await assert.rejects(()=>helper.recoverSvgCanonicalAssessment({page,frame,sessionId,requestId,evaluationId,readAssessmentResponse:async value=>JSON.parse(await value.text()),beforeCounters:async()=>counters,afterCounters:async()=>({...counters,svgMints:2})}));});

test('V46 graph observation preserves distinct physical and traversal filenames',()=>{const bytes=Buffer.from('<svg>owned traversal</svg>'),sessionId='00000000-0000-4000-8000-000000000041',requestId='00000000-0000-4000-8000-000000000042';const captured=helper.captureTraversalGraphRunAttachment({sessionId,requestId,message:'Store this owned avatar with the requested logical filename.',attachment:{bytes,filename:'owned.svg',logicalFilename:'....//escaped.svg',mime:'image/svg+xml',public:false}});assert.deepEqual(captured.fields,{sessionId,requestId,message:'Store this owned avatar with the requested logical filename.',public:'false',logicalFilename:'....//escaped.svg'});assert.deepEqual(captured.file,{filename:'owned.svg',mime:'image/svg+xml',byteCount:bytes.length,bodySha256:require('node:crypto').createHash('sha256').update(bytes).digest('hex'),bodyBase64:bytes.toString('base64'),partCount:1});assert.throws(()=>helper.captureTraversalGraphRunAttachment({sessionId,requestId,message:'x',attachment:{bytes,filename:'owned.svg',logicalFilename:'escaped.svg',mime:'image/svg+xml',public:false}}));});

test('V46 rendered helper uses the physical chooser, logical filename, safe learner destination, and exact saved GET',async()=>{const os=require('node:os'),filePath=path.join(os.tmpdir(),`v46-controlled-${process.pid}.svg`),bytes=Buffer.from('<svg>owned traversal</svg>'),filename=path.basename(filePath),logicalFilename='....//escaped.svg',operationRelativePath='avatars/escaped.svg',bodySha256=require('node:crypto').createHash('sha256').update(bytes).digest('hex');fs.writeFileSync(filePath,bytes,{mode:0o600});const sessionId='00000000-0000-4000-8000-000000000041',requestId='00000000-0000-4000-8000-000000000042',operationId='00000000-0000-4000-8000-000000000043',intent={version:1,shopUserId:46,sessionId,requestId,operationId:null,startedAt:1},reference={...intent,operationId};let active='',logical='....//avatar.txt',message='',accepted=[],referenceReads=0;const values=selector=>selector.includes('filename')?logical:selector.includes('message')?message:'';const element=selector=>({click:async()=>{active=selector;},evaluate:async fn=>selector.includes('agent-lane')?'avatar-traversal-lesson':fn({value:values(selector),scrollIntoView(){}})}),handle={asElement:()=>({evaluate:async()=>{},click:async()=>{}}),dispose:async()=>{}};const frame={waitForSelector:async selector=>element(selector),waitForFunction:async fn=>String(fn).includes('querySelectorAll')?handle:true,$eval:async()=>false,$:async selector=>element(selector),evaluate:async()=>({status:200,type:'application/json',text:JSON.stringify({operationId,uploadRequestId:requestId,status:'completed',filename:logicalFilename,byteCount:bytes.length,bodySha256,traversal:true,operationRelativePath,escapedAvatarSubdirectory:true})})};const runRequest={method:()=> 'POST',url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/path-traversal/run',headers:()=>({'content-type':'multipart/form-data; boundary=physical'})},sessionResponse={status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify({id:sessionId}),request:()=>({method:()=> 'POST'}),url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/path-traversal/session'};const page={waitForFileChooser:async()=>({accept:async paths=>{accepted=paths;}}),waitForResponse:async predicate=>{assert.equal(predicate(sessionResponse),true);return sessionResponse;},waitForRequest:async predicate=>{assert.equal(predicate(runRequest),true);return runRequest;},keyboard:{type:async value=>{if(active.includes('filename'))logical+=value;if(active.includes('message'))message+=value;},press:async key=>{if(key==='Backspace'&&active.includes('filename'))logical=logical.slice(0,-1);if(key==='Backspace'&&active.includes('message'))message=message.slice(0,-1);}}};try{const result=await helper.runRenderedTraversalUpload({page,frame,filePath,filename,logicalFilename,mime:'image/svg+xml',byteCount:bytes.length,message:'Store this owned avatar with the requested logical filename.',expectedStatus:'completed',bodySha256,operationRelativePath,readAcknowledgedReference:async key=>{assert.equal(key,'secureshop.customer-avatar-traversal.lesson.v1');return referenceReads++===0?intent:reference;},observeSessionResponse:async value=>assert.deepEqual(value,{method:'POST',pathname:'/api/secureshop/agents/customer/avatar-upload/path-traversal/session',status:200,contentType:'application/json',category:'success',body:{id:sessionId},responseBodyError:null}),readOriginalMultipart:async()=>helper.captureTraversalGraphRunAttachment({sessionId,requestId,message:'Store this owned avatar with the requested logical filename.',attachment:{bytes,filename,logicalFilename,mime:'image/svg+xml',public:false}}),assertOriginalGraphEvidence:async value=>{assert.deepEqual(value,{reference,expectedStatus:'completed',bodySha256,logicalFilename,operationRelativePath});return true;}});assert.deepEqual(accepted,[filePath]);assert.equal(referenceReads,2);assert.deepEqual(result,{reference,saved:{operationId,uploadRequestId:requestId,status:'completed',filename:logicalFilename,byteCount:bytes.length,bodySha256,traversal:true,operationRelativePath,escapedAvatarSubdirectory:true}});}finally{fs.rmSync(filePath,{force:true});}});

test('V46 saved decoder rejects fabricated destinations and fixed results cannot expose one',()=>{const common={operationId:'00000000-0000-4000-8000-000000000043',uploadRequestId:'00000000-0000-4000-8000-000000000042',filename:'....//escaped.svg',byteCount:27};const completed={...common,status:'completed',bodySha256:'a'.repeat(64),traversal:true,operationRelativePath:'avatars/escaped.svg',escapedAvatarSubdirectory:true};assert.equal(helper.assertTraversalSaved(completed,{requestId:common.uploadRequestId,operationId:common.operationId,status:'completed',logicalFilename:common.filename,byteCount:common.byteCount,bodySha256:completed.bodySha256,operationRelativePath:completed.operationRelativePath}),completed);for(const operationRelativePath of ['avatars/.','avatars/..','avatars/escape\\name.svg','avatars/escape\nname.svg','foreign/escaped.svg'])assert.throws(()=>helper.assertTraversalSaved({...completed,operationRelativePath},{requestId:common.uploadRequestId,operationId:common.operationId,status:'completed',logicalFilename:common.filename,byteCount:common.byteCount,bodySha256:completed.bodySha256,operationRelativePath}));const denied={...common,status:'denied',denialCode:'PATH_TRAVERSAL_DENIED'};assert.equal(helper.assertTraversalSaved(denied,{requestId:common.uploadRequestId,operationId:common.operationId,status:'denied',logicalFilename:common.filename,byteCount:common.byteCount,bodySha256:completed.bodySha256}),denied);assert.throws(()=>helper.assertTraversalSaved({...denied,operationRelativePath:'avatars/escaped.svg',escapedAvatarSubdirectory:true},{requestId:common.uploadRequestId,operationId:common.operationId,status:'denied',logicalFilename:common.filename,byteCount:common.byteCount,bodySha256:completed.bodySha256}));});

test('V46 assessment and reload recovery use only the traversal routes and preserve counters',async()=>{const sessionId='00000000-0000-4000-8000-000000000041',requestId='00000000-0000-4000-8000-000000000042',operationId='00000000-0000-4000-8000-000000000043',evaluationId='00000000-0000-4000-8000-000000000044',assessment={completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:false},assessmentGet={...assessment,replayed:true},assessmentRequest={method:()=> 'POST',url:()=> 'http://app/api/secureshop/agents/customer/avatar-upload/path-traversal/assess',postData:()=>JSON.stringify({sessionId,requestId})},assessmentResponse={status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify(assessment),request:()=>assessmentRequest,url:()=>assessmentRequest.url()},recoveryResponse={status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify(assessmentGet),request:()=>({method:()=> 'GET'}),url:()=>`http://app/api/secureshop/agents/customer/avatar-upload/path-traversal/assessment/${sessionId}/${requestId}`};const clicked=[];const handle={asElement:()=>({evaluate:async()=>{},click:async()=>{clicked.push('click');}}),dispose:async()=>{}},frame={waitForFunction:async()=>handle};let assessmentReads=0;const assessmentReference={version:1,shopUserId:46,sessionId,requestId,startedAt:1},page={waitForRequest:async predicate=>{assert.equal(predicate(assessmentRequest),true);return assessmentRequest;},waitForResponse:async predicate=>{const response=assessmentReads<3?assessmentResponse:recoveryResponse;assert.equal(predicate(response),true);return response;}};const result=await helper.runTraversalCanonicalAssessment({page,frame,sessionId,requestId,completed:true,readCanonicalProgress:async objective=>{assert.equal(objective,'ss_upload_path_traversal_write');return true;},readAcknowledgedReference:async key=>{assert.equal(key,'secureshop.customer-avatar-traversal.assessment.v1');return assessmentReads++===0?null:assessmentReference;}});assert.deepEqual(result,assessment);assert.equal(assessmentReads,3);const counters={actor:2,tools:1,writes:1,mints:0,judges:1,serves:0};assert.deepEqual(await helper.recoverTraversalCanonicalAssessment({page,frame,sessionId,requestId,evaluationId,beforeCounters:async()=>counters,afterCounters:async()=>({...counters})}),assessmentGet);assert.deepEqual(clicked,['click','click']);assert.throws(()=>helper.assertTraversalSaved({operationId,uploadRequestId:requestId,status:'completed',filename:'....//escaped.svg',byteCount:1,bodySha256:'a'.repeat(64),traversal:true,operationRelativePath:'avatars/..',escapedAvatarSubdirectory:true},{requestId,operationId,status:'completed',logicalFilename:'....//escaped.svg',byteCount:1,bodySha256:'a'.repeat(64),operationRelativePath:'avatars/..'}));});

test('V46 rendered host keeps genuine graph, physical readback, Judge, fixed, sibling and reset gates distinct',()=>{const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8'),start=source.indexOf("} else if(V46_TRAVERSAL){"),end=source.indexOf("} else if(V08_SVG){",start);assert.ok(start>0&&end>start);const branch=source.slice(start,end);for(const phrase of['v06Evidence.catalogAdmission=structuredClone(v46Candidate)','runRenderedTraversalUpload','readOriginalUploadTurnGraph','secureshop_review.bound_upload_admissions','fs.readFile(path.join(uploadRoot,effect.stored_virtual_path))','runTraversalCanonicalAssessment','traversalAssessment.assertRetainedPacket','recoverTraversalCanonicalAssessment',"mode:'fixed'",'Start another traversal upload','secureshop.customer-avatar-traversal.lesson.v1','PATH_TRAVERSAL_DENIED','siblingReady.persona.token','launchResetCoordinator.reset','assertUploadReset','snapshotHistory(assessed.judgment.evaluationId)','v46.immutableHistoryRetained=true','assert.equal(v06AssetPosts.length,0)',"v06SessionDiagnostics.map(value=>value.status),['completed','completed']"])assert.ok(branch.includes(phrase),phrase);assert.match(branch,/logicalFilename=`\.\.\.\.\/\/escaped-v46-/);assert.match(branch,/operationRelativePath=`avatars\/\$\{escapedFilename\}`/);assert.match(branch,/assert\.equal\(fixedCounts\.serves,0\)/);assert.match(branch,/assert\.equal\(reply\.status,503\)/);assert.match(branch,/personaSession:siblingActor\.personaSession\}\),\{code:'CONVERSATION_UNAVAILABLE'\}/);assert.match(branch,/assert\.equal\(stale\.status,401\)/);assert.match(branch,/stale\.json\(\),\{error:'Shop authentication required'\}/);const retire=branch.indexOf("await click(frame,'Start another traversal upload')"),clear=branch.indexOf("assert.deepEqual(await counts(),retirementBefore)"),fixedMode=branch.indexOf("const fixedMode=await mode.set"),fixedReload=branch.indexOf("await page.reload",fixedMode);assert.ok(retire>0&&clear>retire&&fixedMode>clear&&fixedReload>fixedMode,'physically retire both resolved refs with no replay before changing mode and reloading');assert.doesNotMatch(branch,/openSandboxPreview|asset_url|firstServe=true/);assert.match(source,/V46_TRAVERSAL\?'v46-original-evidence\.json'/);
 const terminal=source.slice(source.lastIndexOf('for (const flag of FLAGS)'),source.lastIndexOf('\n  });'));
 const FLAGS=['fixtureLocalCandidateAdmission','canonicalJudgeCredit','resetFenced'];
 for(const lane of ['V46_TRAVERSAL','V08_SVG','V07_POLYGLOT'])for(const candidate of [true,false]){
  const context={assert,status:{cleanupErrors:[],fixtureLocalCandidateAdmission:candidate,canonicalJudgeCredit:true,resetFenced:true},FLAGS,V46_TRAVERSAL:lane==='V46_TRAVERSAL',V08_SVG:lane==='V08_SVG',V44_PATH_SUMMARY:false,V01_AUDIT:false,V07_POLYGLOT:lane==='V07_POLYGLOT',UPLOAD_BROWSER:true,v06Evidence:{catalogAdmission:{fixtureLocalCandidateAdmission:candidate}}};
  require('node:vm').runInNewContext(terminal,context);
  assert.throws(()=>require('node:vm').runInNewContext(terminal,{...context,status:{...context.status,resetFenced:false}}),assert.AssertionError);
  assert.throws(()=>require('node:vm').runInNewContext(terminal,{...context,status:{...context.status,fixtureLocalCandidateAdmission:!candidate}}),assert.AssertionError);
 }
});

const {V08_OBJECTIVE,admitV08DisposableCandidate}=require('./fixtures/secureshopV08CandidateCatalog');
test('V08 candidate admission is disposable, pending-only, default-disabled and exact-source bound',async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 let qualification='pending',enabled=false,revision=1,updates=0,denials=0;
 const row={id:V08_OBJECTIVE,text:'SVG browser execution',defaultEnabled:false,qualification:'pending'};
 const curriculum={OBJECTIVES:[row],isQualifiedObjective:id=>{assert.equal(id,V08_OBJECTIVE);return false;}};
 const catalog={list:async()=>({objectives:[{objectiveId:V08_OBJECTIVE,qualification,enabled,revision}]}),set:async(_ctx,input)=>{assert.equal(input.objectiveId,V08_OBJECTIVE);assert.equal(input.expectedRevision,revision);if(qualification==='pending'){denials++;throw Object.assign(Error('unqualified'),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});}enabled=input.enabled;revision++;return{enabled,qualification};}};
 const migration={query:async(sql,args)=>{updates++;assert.match(sql,/qualification='pending'/);assert.match(sql,/configuration_source='checked_in_default'/);assert.equal(args[0],V08_OBJECTIVE);const source=JSON.stringify({version:1,id:row.id,label:row.text,defaultEnabled:false,qualification:'pending'});assert.equal(args[2],source);assert.equal(args[1],require('node:crypto').createHash('sha256').update(source).digest('hex'));qualification='native-browser-judge';return{rowCount:1,rows:[{objective_id:V08_OBJECTIVE,qualification,is_enabled:false}]};}};
 try{assert.deepEqual(await admitV08DisposableCandidate({migration,catalog,administratorContext:{controlled:true},curriculum}),{objectiveId:V08_OBJECTIVE,fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false});assert.equal(updates,1);assert.equal(denials,1);assert.equal(enabled,true);}finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
test('V08 qualified catalog uses normal administrator enablement without a fixture SQL transition',async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 let enabled=false,revision=4,sets=0;
 const row={id:V08_OBJECTIVE,text:'SVG browser execution',defaultEnabled:false,qualification:'native-browser-judge'};
 const curriculum={OBJECTIVES:[row],isQualifiedObjective:id=>{assert.equal(id,V08_OBJECTIVE);return true;}};
 const catalog={list:async()=>({objectives:[{objectiveId:V08_OBJECTIVE,qualification:row.qualification,enabled,revision}]}),
  set:async(_ctx,input)=>{sets++;assert.deepEqual(input,{objectiveId:V08_OBJECTIVE,enabled:true,expectedRevision:revision});enabled=true;revision++;return{enabled,qualification:row.qualification};}};
 const migration={query:async()=>{throw Error('Qualified V08 catalog must not use fixture SQL admission');}};
 try{assert.deepEqual(await admitV08DisposableCandidate({migration,catalog,administratorContext:{controlled:true},curriculum}),
  {objectiveId:V08_OBJECTIVE,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
  assert.equal(sets,1);assert.equal(enabled,true);
 }finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});

const{V06_OBJECTIVE,admitV06DisposableCandidate}=require('./fixtures/secureshopV06CandidateCatalog');
test('V06 candidate admission is disposable, pending-only, default-disabled and exact-source bound',async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 let qualification='pending',enabled=false,revision=1,updates=0,denials=0;
 const row={id:V06_OBJECTIVE,text:'Synthetic customer upload',defaultEnabled:false,qualification:'pending'};
 const curriculum={OBJECTIVES:[row],isQualifiedObjective:id=>{assert.equal(id,V06_OBJECTIVE);return false;}};
 const catalog={list:async()=>({objectives:[{objectiveId:V06_OBJECTIVE,qualification,enabled,revision}]}),set:async(_ctx,input)=>{assert.equal(input.objectiveId,V06_OBJECTIVE);assert.equal(input.expectedRevision,revision);if(qualification==='pending'){denials++;throw Object.assign(Error('unqualified'),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});}enabled=input.enabled;revision++;return{enabled,qualification};}};
 const migration={query:async(sql,args)=>{updates++;assert.match(sql,/qualification='pending'/);assert.match(sql,/configuration_source='checked_in_default'/);assert.equal(args[0],V06_OBJECTIVE);const source=JSON.stringify({version:1,id:row.id,label:row.text,defaultEnabled:false,qualification:'pending'});assert.equal(args[2],source);assert.equal(args[1],require('node:crypto').createHash('sha256').update(source).digest('hex'));qualification='native-browser-judge';return{rowCount:1,rows:[{objective_id:V06_OBJECTIVE,qualification,is_enabled:false}]};}};
 try{assert.deepEqual(await admitV06DisposableCandidate({migration,catalog,administratorContext:{controlled:true},curriculum}),{objectiveId:V06_OBJECTIVE,fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false});assert.equal(updates,1);assert.equal(denials,1);assert.equal(enabled,true);}finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
test('V06 qualified catalog uses normal administrator enablement without a fixture SQL transition',async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 let enabled=false,revision=4,sets=0;
 const row={id:V06_OBJECTIVE,text:'Synthetic customer upload',defaultEnabled:false,qualification:'native-browser-judge'};
 const curriculum={OBJECTIVES:[row],isQualifiedObjective:id=>{assert.equal(id,V06_OBJECTIVE);return true;}};
 const catalog={list:async()=>({objectives:[{objectiveId:V06_OBJECTIVE,qualification:row.qualification,enabled,revision}]}),
  set:async(_ctx,input)=>{sets++;assert.deepEqual(input,{objectiveId:V06_OBJECTIVE,enabled:true,expectedRevision:revision});enabled=true;revision++;return{enabled,qualification:row.qualification};}};
 const migration={query:async()=>{throw Error('Qualified V06 catalog must not use fixture SQL admission');}};
 try{assert.deepEqual(await admitV06DisposableCandidate({migration,catalog,administratorContext:{controlled:true},curriculum}),
  {objectiveId:V06_OBJECTIVE,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});
  assert.equal(sets,1);assert.equal(enabled,true);
 }finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
for(const [name,mutate] of [
 ['true checked-in default',({row})=>{row.defaultEnabled=true;}],
 ['unqualified curriculum projection',({state})=>{state.isQualified=false;}],
 ['catalog qualification drift',({state})=>{state.catalogQualification='pending';}],
])test(`V06 normal qualified admission rejects ${name}`,async()=>{
 const prior=process.env.PG_TEST_DISPOSABLE;process.env.PG_TEST_DISPOSABLE='yes';
 const row={id:V06_OBJECTIVE,text:'Synthetic customer upload',defaultEnabled:false,qualification:'native-browser-judge'};
 const state={isQualified:true,catalogQualification:'native-browser-judge'};mutate({row,state});
 const curriculum={OBJECTIVES:[row],isQualifiedObjective:()=>state.isQualified};
 const catalog={list:async()=>({objectives:[{objectiveId:V06_OBJECTIVE,
  qualification:state.catalogQualification,enabled:false,revision:2}]}),set:async()=>{throw Error('Drifted catalog must fail before enablement');}};
 try{await assert.rejects(admitV06DisposableCandidate({migration:{query:async()=>{throw Error('No fixture SQL');}},
  catalog,administratorContext:{controlled:true},curriculum}),assert.AssertionError);
 }finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});

// Controlled producer compatibility only: these imported suites are resource-free;
// their test registration is intentionally retained, and none qualifies model/Node credit.
const {fixture:polyglotGraphFixture}=require('./secureshopV07UploadPreview.test');
const polyglotCounters=()=>({actor:2,uploadTools:1,previewTools:0,writes:1,previews:0,judges:0,serves:1});
async function polyglotProduced(mode='vuln'){
 const f=await polyglotGraphFixture(mode),response=await f.graph.run(f.input);
 const reference={version:1,shopUserId:f.f.persona.id,sessionId:f.input.sessionId,requestId:f.input.requestId,
  operationId:f.f.retained().admission.operationId,startedAt:1};
 const loaded=await f.sourceReader.load({binding:f.d.binding,personaSession:f.f.personaSession,target:f.d.target,
  mode:(await f.d.modeAuthority.capture()).snapshot,sessionId:reference.sessionId,requestId:reference.requestId,check:f.d.check});
 const original=await f.sourceReader.readPreview({scope:f.d.binding,persona:f.f.persona},loaded.retained);
 return{f,response,reference,original};
}
function polyglotPhysical({reference,body,kind='preview',saved=false,markerMutation,before=polyglotCounters(),after=before}){
 const seen={clicks:[],requests:[],responses:[],dom:[],reads:0},base='/api/secureshop/agents/customer/avatar-upload';
 const suffix=kind==='preview'?'polyglot-preview':'polyglot-assess',route=`${base}/${suffix}`;
 const request={method:()=> 'POST',url:()=>`http://app${route}`,postData:()=>JSON.stringify({sessionId:reference.sessionId,requestId:reference.requestId})};
 const response={request:()=>saved?{method:()=> 'GET'}:request,url:()=>`http://app${route}${saved?`/${reference.sessionId}/${reference.requestId}`:''}`,
  status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify(body)};
 const marker={version:1,shopUserId:reference.shopUserId,sessionId:reference.sessionId,requestId:reference.requestId,startedAt:1};
 markerMutation?.(marker);
 const frame={waitForFunction:async(fn,options,args)=>{seen.dom.push({source:String(fn),args});return {
  asElement:()=>({evaluate:async()=>{},click:async()=>{seen.clicks.push(args);}}),dispose:async()=>{}};}};
 const page={waitForRequest:async predicate=>{assert.equal(predicate(request),true);seen.requests.push(request.method());return request;},
  waitForResponse:async predicate=>{assert.equal(predicate(response),true);seen.responses.push(response.request().method());return response;}};
 return {page,frame,seen,reference,readAcknowledgedReference:async()=>seen.reads++===0?null:structuredClone(marker),
  beforeCounters:async()=>({...before}),afterCounters:async()=>({...after})};
}
test('V07 helper pins production rubric and exact physical polyglot bytes without execution',()=>{
 const fixture=require('./fixtures/secureshopV06ActualEvidence').v07PolyglotFixture();
 assert.equal(helper.V07_BROWSER_OBJECTIVE,require('../server/services/secureshopV07UploadEvidence').OBJECTIVE);
 assert.equal(helper.V07_BROWSER_RUBRIC,require('../server/services/secureshopV07UploadEvidence').RUBRIC.version);
 assert.equal(helper.V07_BROWSER_SCENARIO,'bound_upload_polyglot');assert.equal(fixture.filename,'owned-polyglot-avatar.gif');
 assert.equal(fixture.mime,'image/gif');assert.equal(fixture.byteCount,fixture.bytes.length);assert.equal(fixture.bytes.length,180);
 assert.equal(require('node:crypto').createHash('sha256').update(fixture.bytes).digest('hex'),fixture.bodySha256);
 assert.equal(fixture.bodySha256,'61ab6f86b4d2c458f9e09dcccc60c7c8aedf88dd1c39f60347f42e5ada60729d');
});
for(const mode of ['vuln','fixed'])test(`V07 ${mode} preview physical helper joins real controlled graph/source producer and exact counters`,async()=>{
 const p=await polyglotProduced(mode),before=polyglotCounters(),after={...before,actor:4,previewTools:1,previews:1};
 const ui=polyglotPhysical({...p,body:p.response,before,after});
 const out=await helper.runPolyglotPreview({...ui,expectedStatus:p.response.status,sourceSha256:p.response.sourceSha256,
  readOriginalPreview:async input=>{assert.deepEqual(input,{reference:p.reference,response:p.response});return p.original;}});
 assert.deepEqual(out.response,p.response);assert.equal(out.original,p.original);assert.equal(ui.seen.clicks.length,1);
 assert.deepEqual(ui.seen.requests,['POST']);assert.deepEqual(ui.seen.responses,['POST']);assert.equal(ui.seen.reads,3);
 assert.equal(ui.seen.clicks[0].selector,'[data-testid="avatar-polyglot-preview"]');
 assert.ok(ui.seen.dom.some(x=>x.args?.text===p.response.text&&x.args?.status===p.response.status));
 assert.equal(p.f.counts().actors,2);assert.equal(p.f.counts().calls,1);
});
test('V07 lost preview acknowledgement accepts only original saved GET without a repeated POST',async()=>{
 const p=await polyglotProduced(),saved=await p.f.graph.read(p.f.input),before=polyglotCounters();
 const ui=polyglotPhysical({...p,body:saved,saved:true,before,after:{...before,actor:4,previewTools:1,previews:1}});
 const out=await helper.runPolyglotPreview({...ui,acknowledgement:'saved-get',expectedStatus:'executed',sourceSha256:saved.sourceSha256,
  readOriginalPreview:async()=>p.original});
 assert.deepEqual(out.response,saved);assert.deepEqual(ui.seen.requests,['POST']);assert.deepEqual(ui.seen.responses,['GET']);
 assert.equal(p.f.counts().actors,2);assert.equal(p.f.counts().calls,1);
});
test('V07 preview rejects changed original source, receipt, trace, effect, final response and alias shapes',async()=>{
 const p=await polyglotProduced();assert.equal(helper.assertPolyglotOriginal(p.original,p),p.original);
 for(const mutate of [x=>x.row.result_json.text+=' substituted',x=>x.receipt.effectSha256='0'.repeat(64),
  x=>x.request.bytesBase64=Buffer.from('changed').toString('base64'),x=>x.traces.pop(),x=>x.graphEffect.status='pending',
  x=>x.graphEffect.live_generation='99',x=>x.row.request_id=p.reference.requestId,x=>x.extra=true]){
  const copy=structuredClone(p.original);mutate(copy);assert.throws(()=>helper.assertPolyglotOriginal(copy,p));
 }
 for(const change of [{replayed:true},{sourceSha256:'0'.repeat(64)},{text:null},{status:'pending'},{operationId:p.reference.operationId},{extra:true}]){
  assert.throws(()=>helper.assertPolyglotPreview({...p.response,...change},{reference:p.reference,status:'executed',sourceSha256:p.response.sourceSha256,replayed:false}));
 }
 const pending={...p.response,status:'pending',text:null,replayed:true};assert.equal(helper.assertPolyglotPreview(pending,
  {reference:p.reference,status:'pending',sourceSha256:p.response.sourceSha256,replayed:true}),pending);
});
test('V07 preview aborts on wrong acknowledged identity or any extra actor/tool/write/read effect',async()=>{
 const p=await polyglotProduced(),before=polyglotCounters();
 for(const field of Object.keys(before)){
  const after={...before,actor:4,previewTools:1,previews:1};after[field]++;
  const ui=polyglotPhysical({...p,body:p.response,before,after});await assert.rejects(helper.runPolyglotPreview({...ui,
   expectedStatus:'executed',sourceSha256:p.response.sourceSha256,readOriginalPreview:async()=>p.original}));
 }
 let sourceReads=0;const ui=polyglotPhysical({...p,body:p.response,before,after:before,markerMutation:m=>m.requestId=p.response.operationId});
 await assert.rejects(helper.runPolyglotPreview({...ui,expectedStatus:'executed',sourceSha256:p.response.sourceSha256,
  readOriginalPreview:async()=>{sourceReads++;return p.original;}}));assert.equal(sourceReads,0);
});
for(const completed of [true,false])test(`V07 physical assessment ${completed?'canonical pass':'fixed ineligible'} preserves exact DTO, marker and Judge budget`,async()=>{
 const p=await polyglotProduced(completed?'vuln':'fixed'),before={...polyglotCounters(),actor:4,previews:1,previewTools:1};
 const body=completed?{completed:true,judgment:{verdict:'pass',evaluationId:'00000000-0000-4000-8000-000000000004',canRetry:false},replayed:false}
  :{completed:false,status:'ineligible',modelEvaluated:false};
 const ui=polyglotPhysical({...p,kind:'assessment',body,before,after:{...before,judges:completed?2:0}});
 const result=await helper.runPolyglotAssessment({...ui,completed,readCanonicalProgress:async objective=>{assert.equal(objective,helper.V07_BROWSER_OBJECTIVE);return completed;},
  readAssessmentResponse:async response=>JSON.parse(await response.text())});
 assert.deepEqual(result,body);assert.deepEqual(ui.seen.requests,['POST']);assert.equal(ui.seen.clicks[0].selector,'[data-testid="avatar-polyglot-assess"]');
 assert.equal(ui.seen.reads,3);
});
test('V07 assessment failure, false replay marker, optional status fields and Judge repairs cannot qualify',async()=>{
 const p=await polyglotProduced(),before=polyglotCounters(),positive={completed:true,judgment:{verdict:'pass',evaluationId:'00000000-0000-4000-8000-000000000004',canRetry:false},replayed:false};
 for(const mutate of [x=>x.completed=false,x=>x.judgment.verdict='fail',x=>x.judgment.canRetry=true,x=>x.replayed=true]){
  const body=structuredClone(positive);mutate(body);const ui=polyglotPhysical({...p,kind:'assessment',body,before,after:{...before,judges:2}});
  await assert.rejects(helper.runPolyglotAssessment({...ui,completed:true,readCanonicalProgress:async()=>true,readAssessmentResponse:async r=>JSON.parse(await r.text())}));
 }
 const ui=polyglotPhysical({...p,kind:'assessment',body:positive,before,after:{...before,judges:3}});
 await assert.rejects(helper.runPolyglotAssessment({...ui,completed:true,readCanonicalProgress:async()=>true,readAssessmentResponse:async r=>JSON.parse(await r.text())}));
 assert.throws(()=>helper.assertPolyglotAssessment({completed:false,status:'ineligible',modelEvaluated:false,replayed:false},{completed:false}));
 assert.throws(()=>helper.assertPolyglotAssessment({completed:false,status:'pending',modelEvaluated:false},{completed:true}));
});
test('V07 manual saved preview and assessment recovery use GET only with exact replay marker and no counter changes',async()=>{
 const p=await polyglotProduced(),before=polyglotCounters(),saved=await p.f.graph.read(p.f.input);
 const ui=polyglotPhysical({...p,body:saved,saved:true,before});
 assert.deepEqual((await helper.recoverPolyglotPreview({...ui,expected:p.response,readOriginalPreview:async()=>p.original})).response,saved);
 assert.deepEqual(ui.seen.requests,[]);assert.deepEqual(ui.seen.responses,['GET']);
 const expected={completed:true,judgment:{verdict:'pass',evaluationId:'00000000-0000-4000-8000-000000000004',canRetry:false},replayed:false};
 const assess=polyglotPhysical({...p,kind:'assessment',body:{...expected,replayed:true},saved:true,before});
 assert.deepEqual(await helper.recoverPolyglotAssessment({...assess,expected,readAssessmentResponse:async r=>JSON.parse(await r.text())}),{...expected,replayed:true});
 assert.deepEqual(assess.seen.requests,[]);assert.deepEqual(assess.seen.responses,['GET']);
 await assert.rejects(helper.recoverPolyglotPreview({...ui,expected:p.response,readOriginalPreview:async()=>p.original,afterCounters:async()=>({...before,previews:1})}));
});
test('V07 reload prearms source/preview/assessment GETs before navigation and preserves exact original final plus counters',async()=>{
 const p=await polyglotProduced(),before=polyglotCounters(),assessment={completed:true,judgment:{verdict:'pass',evaluationId:'00000000-0000-4000-8000-000000000004',canRetry:false},replayed:false};
 const {admission,effect}=p.f.f.retained(),source={operationId:admission.operationId,uploadRequestId:admission.uploadRequestId,status:effect.outcome,filename:admission.request.originalFilename,byteCount:admission.request.byteCount,bodySha256:effect.file.bodySha256};
 for(const mutate of [null,x=>x.operationId=p.response.operationId,x=>x.uploadRequestId=p.response.operationId,x=>x.bodySha256='0'.repeat(64),x=>x.filename='substituted.gif',x=>x.byteCount++,x=>x.extra=true]){
 const recoveredSource=structuredClone(source);mutate?.(recoveredSource);
 const base='/api/secureshop/agents/customer/avatar-upload',events=[],responses=[
  [`${base}/operations/${p.reference.operationId}`,recoveredSource],
  [`${base}/polyglot-preview/${p.reference.sessionId}/${p.reference.requestId}`,{...p.response,replayed:true}],
  [`${base}/polyglot-assess/${p.reference.sessionId}/${p.reference.requestId}`,{...assessment,replayed:true}]];
 const ui=polyglotPhysical({...p,body:p.response,before}),selector={click:async()=>{},evaluate:async()=> 'avatar-upload-lesson'};
 ui.frame.waitForSelector=async()=>selector;
 const page={waitForResponse:async predicate=>{const [route,body]=responses.shift();events.push('armed');const response={url:()=>`http://app${route}`,request:()=>({method:()=> 'GET'}),status:()=>200,headers:()=>({'content-type':'application/json'}),text:async()=>JSON.stringify(body)};
  assert.equal(predicate(response),true);return response;},reload:async()=>{assert.equal(events.length,3);events.push('reload');},keyboard:{type:async()=>{},press:async()=>{}}};
 const recover=()=>helper.recoverPolyglotAfterReload({...ui,page,getFrame:async()=>ui.frame,source,preview:p.response,assessment,
  readOriginalPreview:async()=>p.original,readAssessmentResponse:async r=>JSON.parse(await r.text())});
 if(mutate){await assert.rejects(recover);continue;}const out=await recover();assert.deepEqual(out.source,source);
 assert.deepEqual(out.preview,{...p.response,replayed:true});assert.deepEqual(out.assessment,{...assessment,replayed:true});
 assert.deepEqual(events,['armed','armed','armed','reload']);assert.equal(responses.length,0);
 }
});

test('V07 pending candidate requires exact source, normal administrator denial and guarded disposable admission',async()=>{
 const {admitV07DisposableCandidate}=require('./fixtures/secureshopV06CandidateCatalog'),objectiveId=helper.V07_BROWSER_OBJECTIVE;
 const checked=structuredClone(require('../server/config/secureshopCurriculum').OBJECTIVES.find(row=>row.id===objectiveId));
 checked.qualification='pending'; // Historical default required by this disposable candidate-only control.
 assert.equal(checked.qualification,'pending');assert.equal(checked.defaultEnabled,false);
 const curriculum={OBJECTIVES:[checked],isQualifiedObjective:()=>false},prior=process.env.PG_TEST_DISPOSABLE;
 let qualification='pending',denials=0,updates=0,enables=0;process.env.PG_TEST_DISPOSABLE='yes';
 const administratorContext={controlled:'owned-disposable-administrator'};
 const catalog={list:async context=>{assert.equal(context,administratorContext);return{objectives:[{objectiveId,qualification,enabled:false,revision:1}]};},
  set:async(context,input)=>{assert.equal(context,administratorContext);assert.deepEqual(input,{objectiveId,enabled:true,expectedRevision:1});
   if(qualification==='pending'){denials++;throw Object.assign(Error('Unqualified'),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});}enables++;return{enabled:true,qualification};}};
 try{const result=await admitV07DisposableCandidate({curriculum,catalog,administratorContext,migration:{query:async(sql,args)=>{
  updates++;assert.equal(denials,1);assert.match(sql,/configuration_source='checked_in_default'/);assert.match(sql,/source_sha256=\$2 AND source_document=\$3::jsonb/);
  assert.match(sql,/qualification='pending'/);assert.match(sql,/is_enabled=false AND catalog_active=true/);
  assert.deepEqual(args,[objectiveId,'00be7f7921bafa94f62a633575f39e63469369c30d935239a67f41540f238dd8',JSON.stringify({version:1,id:objectiveId,label:checked.text,defaultEnabled:false,qualification:'pending'})]);
  qualification='native-browser-judge';return{rowCount:1,rows:[{objective_id:objectiveId,qualification,is_enabled:false}]};}}});
  assert.deepEqual(result,{objectiveId,fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false});
  assert.deepEqual({denials,updates,enables},{denials:1,updates:1,enables:1});
 }finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
test('V07 future qualified admission uses normal administrator enablement without fixture SQL',async()=>{
 const {admitV07DisposableCandidate}=require('./fixtures/secureshopV06CandidateCatalog'),objectiveId=helper.V07_BROWSER_OBJECTIVE;
 const checked={...require('../server/config/secureshopCurriculum').OBJECTIVES.find(row=>row.id===objectiveId),qualification:'native-browser-judge'},prior=process.env.PG_TEST_DISPOSABLE;
 let lists=0,enables=0;process.env.PG_TEST_DISPOSABLE='yes';
 try{const result=await admitV07DisposableCandidate({curriculum:{OBJECTIVES:[checked],isQualifiedObjective:()=>true},administratorContext:{controlled:true},
  migration:{query:async()=>{throw Error('Qualified admission must not mutate provenance');}},catalog:{
   list:async()=>{lists++;return{objectives:[{objectiveId,qualification:'native-browser-judge',enabled:false,revision:7}]};},
   set:async(context,input)=>{enables++;assert.deepEqual(input,{objectiveId,enabled:true,expectedRevision:7});return{enabled:true,qualification:'native-browser-judge'};}}});
  assert.deepEqual(result,{objectiveId,fixtureLocalCandidateAdmission:false,productionQualification:'native-browser-judge',productionDefaultEnabled:false});assert.deepEqual({lists,enables},{lists:1,enables:1});
 }finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});
test('V07 admission rejects non-disposable, text, default and qualification drift before catalog effects',async()=>{
 const {admitV07DisposableCandidate}=require('./fixtures/secureshopV06CandidateCatalog'),objectiveId=helper.V07_BROWSER_OBJECTIVE,prior=process.env.PG_TEST_DISPOSABLE;
 try{for(const qualified of [false,true])for(const kind of ['non-disposable','text','default','qualification']){
  const checked={...require('../server/config/secureshopCurriculum').OBJECTIVES.find(row=>row.id===objectiveId),qualification:qualified?'native-browser-judge':'pending'};
  process.env.PG_TEST_DISPOSABLE=kind==='non-disposable'?'no':'yes';if(kind==='text')checked.text+=' drift';if(kind==='default')checked.defaultEnabled=true;if(kind==='qualification')checked.qualification='unknown';
  let effects=0;const unexpected=async()=>{effects++;throw Error('No effects after drift');};
  await assert.rejects(admitV07DisposableCandidate({curriculum:{OBJECTIVES:[checked],isQualifiedObjective:()=>qualified},catalog:{list:unexpected,set:unexpected},migration:{query:unexpected}}),assert.AssertionError);
  assert.equal(effects,0,`${qualified}/${kind}`);
 }}finally{if(prior===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=prior;}
});

test('V07 actual host provider wrapper binds two upload calls and isolates two preview calls from upload records',async()=>{
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');
 const start=source.indexOf("if(V07_POLYGLOT)for(const method of ['chat','finalResponse'])"),end=source.indexOf('if (!v19&&!V29_AGENCY&&!V44_PATH_SUMMARY&&!V07_POLYGLOT)',start);
 assert.ok(start>0&&end>start);const wrapper=source.slice(start,end),vm=require('node:vm');
 const requestId='00000000-0000-4000-8000-000000000071',previewId='00000000-0000-4000-8000-000000000072';
 const transport={calls:[]};let saves=0,invocations=0;
 const context=vm.createContext({assert,V07_POLYGLOT:true,status:{actualModelCalls:0},v07CurrentTurn:{phase:'upload',requestId,calls:0},
  v06Posts:[{requestId,calls:0}],v06ActorSpans:[],v44Transport:transport,saveV07:()=>{saves++;},
  provider:{chat:async()=>{invocations++;transport.calls.push({kind:'decision'});return{provider:'controlled',mocked:true,text:'decision'};},
   finalResponse:async()=>{invocations++;transport.calls.push({kind:'final'});return{provider:'controlled',mocked:true,text:'final'};}}});
 vm.runInContext(wrapper,context);
 await context.provider.chat({messages:[]});assert.equal(context.v06Posts[0].calls,1);
 await context.provider.finalResponse({messages:[]});assert.equal(context.v06Posts[0].calls,2);
 assert.deepEqual(Object.keys(context.v06Posts[0]).sort(),['calls','requestId']);
 context.v07CurrentTurn={phase:'preview',requestId:previewId,calls:0};
 await context.provider.chat({messages:[]});await context.provider.finalResponse({messages:[]});
 assert.equal(context.v06Posts[0].calls,2);assert.equal(context.v07CurrentTurn.calls,2);assert.equal(context.status.actualModelCalls,4);
 assert.equal(invocations,4);assert.equal(saves,8);assert.equal(context.v06ActorSpans.length,4);
 for(const [index,span] of context.v06ActorSpans.entries()){
  assert.deepEqual(Array.from(span.wireIndices),[index]);assert.equal(span.phase,index<2?'upload':'preview');
  assert.equal(span.requestId,index<2?requestId:previewId);assert.equal(span.method,index%2===0?'chat':'finalResponse');
 }
 await assert.rejects(context.provider.chat({messages:[]}),assert.AssertionError);assert.equal(invocations,4);
 context.v07CurrentTurn={phase:'upload',requestId:previewId,calls:0};
 await assert.rejects(context.provider.chat({messages:[]}),assert.AssertionError);assert.equal(invocations,4);assert.equal(context.v06Posts[0].calls,2);
});
test('V07 original browser-cookie bootstrap reauthenticates the same launch after persona revocation',async()=>{
 // Real auth factories and mounted HTTP bootstrap; controlled repositories only.
 // This establishes no model, database, uploaded-code execution or objective credit.
 const {createSecureShopStandaloneAuthService}=require('../server/services/secureshopStandaloneAuth');
 const {createSecureShopStandaloneBootstrap}=require('../server/services/secureshopStandaloneBootstrap');
 const {createSecureShopBoundPersonaAuth}=require('../server/services/secureshopBoundPersonaAuth');
 const {createSecureShopStandaloneAuthRouter}=require('../server/routes/secureshopStandaloneAuth');
 const {requireSecureShopLaunch}=require('../server/middleware/secureshopLaunch');
 const express=require('express'),http=require('node:http');
 let sequence=100,tokenSequence=0,principal;const authSessions=new Map(),executions=new Map(),boundSessions=new Map(),launchesBySession=new Map(),calls=[];
 const unexpected=async()=>{throw Error('Unexpected controlled repository method');};
 const authRow=session=>({principalId:principal.principalId,ownerId:90,shopUserId:1000000001,username:principal.username,email:principal.email,role:'customer',credentialVersion:'1',authorityVersion:'1',sessionId:session.id,expiresAt:session.expiresAt});
 const authRepository=Object.fromEntries(['registerWithSession','findCredential','recordFailedLogin','createSession','readCurrentSession','rotateSession','revokeSession','readCredentialForSession','changePassword','revokeAll','readOrCreateDefaultExecutionSession'].map(key=>[key,unexpected]));
 Object.assign(authRepository,{
  registerWithSession:async input=>{principal={...input,isActive:true,lockedUntil:null,credentialVersion:'1',authorityVersion:'1'};const session={id:++sequence,expiresAt:input.expiresAt};authSessions.set(input.tokenHash,session);return authRow(session);},
  findCredential:async username=>username===principal.username?principal:null,
  createSession:async input=>{assert.equal(input.principalId,principal.principalId);const session={id:++sequence,expiresAt:input.expiresAt};authSessions.set(input.tokenHash,session);return authRow(session);},
  readCurrentSession:async hash=>authSessions.has(hash)?authRow(authSessions.get(hash)):null,
  readOrCreateDefaultExecutionSession:async input=>{const session=[...authSessions.values()].find(value=>value.id===input.authSessionId);assert.ok(session);assert.equal(input.principalId,principal.principalId);
   if(!executions.has(session.id))executions.set(session.id,++sequence);
   return{...authRow(session),principalOwnerId:90,ownerId:500,authSessionId:session.id,sessionId:executions.get(session.id),tenantId:'00000000-0000-4000-8000-000000000090',membershipVersion:'1'};},
 });
 const auth=createSecureShopStandaloneAuthService({repository:authRepository,randomBytes:()=>Buffer.alloc(32,++tokenSequence),hashPassword:async value=>`controlled:${value}`,comparePassword:async(value,hash)=>hash===`controlled:${value}`});
 const registered=await auth.register({username:'v07_owned',email:'v07@owned.invalid',password:'controlled-password',role:'customer'});
 const physicalLogin=await auth.login({username:'v07_owned',password:'controlled-password'});assert.notEqual(registered.token,physicalLogin.token);assert.notEqual(registered.context.sessionId,physicalLogin.context.sessionId);
 const physicalExecution=await auth.establishTenantContext(await auth.authenticate(physicalLogin.token));
 const registrationExecution=await auth.establishTenantContext(await auth.authenticate(registered.token));
 assert.notEqual(physicalExecution.sessionId,registrationExecution.sessionId);assert.notEqual(physicalExecution.sessionId,physicalLogin.context.sessionId);
 const {createLaunchScope}=require('../server/services/secureshopConversationBinding');
 const sameScope=(a,b)=>JSON.stringify(createLaunchScope(a))===JSON.stringify(createLaunchScope(b));
 // Use the real launch repository's SQL producer: renewal advances metadata
 // while the standalone execution's private launch bearer stays unchanged.
 let connected=0;const launchQueries=[];
 const launchQuery=async(sql,values=[])=>{
  launchQueries.push({sql,values});const rows=value=>({rows:value});
  if(['BEGIN','COMMIT','ROLLBACK'].includes(sql))return rows([]);
  if(sql.startsWith('SELECT id,realm,is_active')){assert.deepEqual(values,[500]);return rows([{id:500,realm:'shop',is_active:1,account_locked_until:null}]);}
  if(sql.startsWith('SELECT id,user_id,realm,is_active')){assert.ok([...executions.values()].includes(values[0]));return rows([{id:values[0],user_id:500,realm:'shop',is_active:1,expires_at:new Date(physicalExecution.expiresAt)}]);}
  if(sql==='SELECT clock_timestamp() AS now')return rows([{now:new Date()}]);
  if(sql.includes('FOR UPDATE OF l'))return rows(launchesBySession.has(values[0])?[{...launchesBySession.get(values[0])}]:[]);
  if(sql.includes("to_regprocedure('identity.secureshop_launch_is_retired"))return rows([{ready:true,live_capacity:true}]);
  if(sql.includes('SELECT count(*)::int AS count FROM identity.secureshop_launches'))return rows([{count:launchesBySession.size}]);
  if(sql.includes('INSERT INTO identity.secureshop_launches')){const[launchId,sessionId,ownerId,hash,scenarioId,expiry]=values;
   assert.equal(ownerId,500);assert.equal(launchesBySession.has(sessionId),false);const row={launch_id:launchId,platform_session_id:sessionId,platform_owner_id:ownerId,original_platform_session_id:sessionId,original_platform_owner_id:ownerId,handle_hash:hash,scenario_id:scenarioId,expires_at:new Date(expiry),generation:1,credential_version:1,status:'active'};
   launchesBySession.set(sessionId,row);return rows([{...row}]);}
  if(sql.includes('credential_version=credential_version+1')){assert.equal(values.length,3);const row=[...launchesBySession.values()].find(value=>value.launch_id===values[2]);assert.ok(row);row.handle_hash=values[0];row.expires_at=new Date(values[1]);row.credential_version++;return rows([{...row}]);}
  if(sql.includes('WHERE l.handle_hash=$1'))return rows([...launchesBySession.values()].filter(row=>row.handle_hash.equals(values[0])).map(row=>({...row})));
  if(sql.includes('WHERE l.launch_id=$1 AND l.platform_session_id=$2')){const[launchId,sessionId,ownerId,scenarioId,generation]=values;const row=launchesBySession.get(sessionId);
   return rows(row&&row.launch_id===launchId&&row.platform_owner_id===ownerId&&row.scenario_id===scenarioId&&row.generation===generation&&row.status==='active'?[{...row}]:[]);}
  throw Error(`Unexpected controlled launch SQL: ${sql}`);
 };
 const launchPool={query:launchQuery,connect:async()=>{connected++;return{query:launchQuery,release:()=>{connected--;}};}};
 const launches=require('../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(launchPool);
 const actor={id:physicalExecution.shopUserId,username:physicalExecution.username,email:physicalExecution.email,role:'customer',full_name:null,phone:null};
 const authority={read:async(scope,id,expected)=>{await launches.assertCurrent(scope);assert.equal(id,actor.id);if(expected){assert.equal(expected.role,'customer');assert.equal(expected.version,'1');}return{role:'customer',authority_version:'1'};}};
 const personaRepository=Object.fromEntries(['findCredential','findCredentialById','createSession','readSession','extendSession','revokeSession','listSessions','revokeOwnedSession','changePassword','readApiKey','rotateApiKey','authenticateApiKey'].map(key=>[key,unexpected]));
 Object.assign(personaRepository,{candidatePersonaAuthority:authority,
  ensureStandaloneActor:async({scope,shopPrincipal})=>{calls.push(['actor',scope.platformSessionId]);assert.equal(shopPrincipal.sessionId,scope.platformSessionId);return actor;},
  createSession:async input=>{calls.push(['persona-session',input.scope.platformSessionId]);const prior=[...boundSessions.values()].find(row=>sameScope(row.scope,input.scope));if(prior)return{jti:prior.jti,expiresAt:prior.expiresAt,reused:true};boundSessions.set(input.jti,input);return{jti:input.jti,expiresAt:input.expiresAt,reused:false};},
  readSession:async({jti,scope})=>{const row=boundSessions.get(jti);return row&&sameScope(row.scope,scope)?{session_id:row.sessionId,shop_user_id:row.persona.id,username:row.persona.username,email:row.persona.email,role:row.persona.role,full_name:null,phone:null,expires_at:row.expiresAt}:null;},
  revokeOwnedSession:async({scope,shopUserId,sessionId,actingCredential})=>{assert.equal(shopUserId,actor.id);assert.equal(actingCredential.sessionId,sessionId);assert.equal(actingCredential.authorityVersion,'1');for(const[jti,row]of boundSessions)if(row.sessionId===sessionId&&sameScope(row.scope,scope))return boundSessions.delete(jti);return false;},
  revokeSession:async({jti})=>boundSessions.delete(jti),
 });
 const personaAuth=createSecureShopBoundPersonaAuth({repository:personaRepository,personaAuthority:authority,launches,jwtSecret:'v07-controlled-bound-persona-secret-at-least-32-bytes'});
 let bootstrapTick=0;const bootstrap=createSecureShopStandaloneBootstrap({authService:auth,launches,personaAuth,now:()=>Date.now()+(bootstrapTick++*1000)});
 const app=express();app.use(express.json());let origin,originalHttpBearer;
 // allowedOrigins must be exact, so mount after the owned loopback port is known.
 const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));origin=`http://127.0.0.1:${server.address().port}`;
 app.use('/api/secureshop/auth',createSecureShopStandaloneAuthRouter({service:auth,bootstrap,allowedOrigins:[origin]}));
 app.get('/api/secureshop/controlled-v07-readiness',requireSecureShopLaunch({launches}),personaAuth.authenticatePersona,(_req,res)=>res.json({ready:true}));
 const readiness=async token=>{const response=await fetch(`${origin}/api/secureshop/controlled-v07-readiness`,{headers:{authorization:`Bearer ${token}`,'x-owasp-ai-goat-secureshop-launch':originalHttpBearer},signal:AbortSignal.timeout(5000)});return{status:response.status,body:await response.json()};};
 const request=async token=>{const response=await fetch(`${origin}/api/secureshop/auth/bootstrap`,{method:'POST',headers:{origin,'content-type':'application/json',cookie:`owasp_ai_goat_shop_session=${token}`},body:'{}',signal:AbortSignal.timeout(5000)});return{status:response.status,body:await response.json()};};
 const host=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');
 const helperStart=host.indexOf('async function reauthenticateV07OriginalLaunch('),helperEnd=host.indexOf('async function readV07AssessmentHistory(',helperStart);assert.ok(helperStart>0&&helperEnd>helperStart);
 let browserCookie=physicalLogin.token,bootstrapPosts=0;
 const context=require('node:vm').createContext({assert,AbortSignal,require:require('node:module').createRequire(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js')),fetch:async(url,options)=>{assert.equal(url,'/api/secureshop/auth/bootstrap');assert.equal(options.method,'POST');assert.equal(options.credentials,'same-origin');assert.deepEqual({...options.headers},{'content-type':'application/json'});assert.equal(options.body,'{}');bootstrapPosts++;
  return fetch(`${origin}${url}`,{...options,headers:{...options.headers,origin,cookie:`owasp_ai_goat_shop_session=${browserCookie}`}});}});
 const reauthenticate=require('node:vm').runInContext(`${host.slice(helperStart,helperEnd)};reauthenticateV07OriginalLaunch`,context);
 const page={evaluate:async callback=>callback()};
 const actorFor=async ready=>{const scope=await launches.resolveCapability(ready.bearer);assert.ok(scope);const value=await personaAuth.authenticateBoundToken({token:ready.persona.token,scope});return{scope,persona:value.user,personaSession:{sessionId:value.sessionId,authorityVersion:value.authorityVersion}};};
 try{
  const initial=await request(physicalLogin.token);assert.equal(initial.status,200);const selected=launchesBySession.get(physicalExecution.sessionId),scope=await launches.resolveCapability(initial.body.bearer),originalBearer=initial.body.bearer;
  originalHttpBearer=originalBearer;
  assert.equal(scope.platformSessionId,physicalExecution.sessionId);assert.notEqual(scope.platformSessionId,registrationExecution.sessionId);
  assert.deepEqual(await readiness(initial.body.persona.token),{status:200,body:{ready:true}});
  const original=await personaAuth.authenticateBoundToken({token:initial.body.persona.token,scope});assert.equal(original.authorityVersion,'1');
  const originalActor=await actorFor(initial.body);const repeated=await reauthenticate({page,actorFor,originalActor,originalReady:initial.body});assert.deepEqual(createLaunchScope(repeated.actor.scope),createLaunchScope(originalActor.scope));assert.notDeepEqual(repeated.actor.scope,originalActor.scope);assert.equal(bootstrapPosts,1);assert.equal(repeated.actor.scope.credentialVersion,originalActor.scope.credentialVersion+1);assert.ok(Date.parse(repeated.actor.scope.expiresAt)>Date.parse(originalActor.scope.expiresAt));assert.equal(repeated.ready.bearer,originalBearer);assert.deepEqual(await readiness(initial.body.persona.token),{status:200,body:{ready:true}});
  const writesBefore=calls.filter(row=>row[0]==='actor'||row[0]==='persona-session').length;
  for(const wrong of [registered.context,registrationExecution,structuredClone(physicalExecution)])await assert.rejects(personaAuth.establishSession({scope,shopPrincipal:wrong}),{code:'SHOP_AUTH_INVALID'});
  assert.equal(calls.filter(row=>row[0]==='actor'||row[0]==='persona-session').length,writesBefore);
  assert.equal(await personaAuth.revokeOwnedSession({scope,shopPersona:original.user,currentSessionId:original.sessionId,authorityVersion:original.authorityVersion,sessionId:original.sessionId}),true);
  await assert.rejects(personaAuth.authenticateBoundToken({token:initial.body.persona.token,scope}),{code:'SHOP_AUTH_INVALID'});
  assert.deepEqual(await readiness(initial.body.persona.token),{status:401,body:{error:'Shop authentication required'}});
  const renewed=await reauthenticate({page,actorFor,originalActor,originalReady:initial.body,requireNewSession:true});assert.equal(renewed.ready.launch.launchId,initial.body.launch.launchId);assert.equal(renewed.ready.launch.generation,initial.body.launch.generation);assert.ok(renewed.ready.launch.credentialVersion>initial.body.launch.credentialVersion);assert.equal(renewed.ready.bearer,originalBearer);assert.equal(bootstrapPosts,2);
  const fresh=await personaAuth.authenticateBoundToken({token:renewed.ready.persona.token,scope});assert.notEqual(fresh.sessionId,original.sessionId);assert.deepEqual(fresh.user,original.user);assert.equal(fresh.authorityVersion,original.authorityVersion);
  assert.deepEqual(await readiness(renewed.ready.persona.token),{status:200,body:{ready:true}});
  await assert.rejects(reauthenticate({page,actorFor,originalActor,originalReady:initial.body}),assert.AssertionError);
  await assert.rejects(reauthenticate({page,actorFor,originalActor:renewed.actor,originalReady:renewed.ready,requireNewSession:true}),assert.AssertionError);
  browserCookie=registered.token;await assert.rejects(reauthenticate({page,actorFor,originalActor,originalReady:initial.body,requireNewSession:true}),assert.AssertionError);
  const wrongCookie=await request(registered.token);assert.equal(wrongCookie.status,200);assert.notEqual(wrongCookie.body.launch.launchId,initial.body.launch.launchId);await assert.rejects(personaAuth.authenticateBoundToken({token:wrongCookie.body.persona.token,scope}),{code:'SHOP_AUTH_INVALID'});
  selected.generation=scope.generation+1;await assert.rejects(personaAuth.authenticateBoundToken({token:renewed.ready.persona.token,scope}),{code:'STALE_LAUNCH'});
  assert.deepEqual(await readiness(renewed.ready.persona.token),{status:401,body:{error:'Shop authentication required'}});
  assert.ok(launchQueries.some(row=>row.sql.includes('credential_version=credential_version+1')));assert.equal(connected,0);
 }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));assert.equal(server.listening,false);}
});
test('V07 actual history readers use canonical owner/evaluation joins and preserve complete original rows',async()=>{
 // Controlled query/adapter regression only; actual PostgreSQL schema execution
 // remains the host's mandatory pre-model preflight.
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');
 const start=source.indexOf('async function readV07AssessmentHistory('),end=source.indexOf('function createV07CommittedAckObserver(',start);
 assert.ok(start>0&&end>start);
 const readers=new Function(`${source.slice(start,end)};return {readV07AssessmentHistory,readV07ActiveAssessments};`)();
 const objectiveId='ss_upload_polyglot_execution',persona={id:907},scope={launchId:'launch-original',scenarioId:'scenario-original',generation:31,platformOwnerId:709,platformSessionId:801};
 const expectedValues=[objectiveId,persona.id,scope.launchId,scope.scenarioId,'31','709','801'];
 const tables=['assessment_judgments','assessment_completions','assessment_contributions'],calls=[];
 const rows=Object.fromEntries(tables.map((table,index)=>[table,[{row:{tenant_id:'tenant-original',principal_id:'principal-original',evaluation_id:'evaluation-original',
  created_at:'2026-10-16T08:00:00.123456+00:00',original_table:table,opaque_original:{nested:[index,{preserve:'all original fields'}]},
  ...(table==='assessment_judgments'?{packet:'exact original packet bytes\n',execution_json:{scope},result_json:{verdict:'pass'},result_digest:'a'.repeat(64)}:
   table==='assessment_completions'?{objective_id:objectiveId,generation:31}:{})}}]]));
 let empty=false;
 const identity={query:async(sql,values)=>{
  calls.push({sql,values});assert.deepEqual(values,expectedValues);assert.match(sql,/^SELECT /);assert.doesNotMatch(sql,/\b(?:INSERT|UPDATE|DELETE)\b/);
  const active=sql.includes('secureshop_auth.active_assessment_contributions c'),alias=active?'c':'t';
  assert.match(sql,new RegExp(`ON j\\.tenant_id=${alias}\\.tenant_id AND j\\.principal_id=${alias}\\.principal_id AND j\\.evaluation_id=${alias}\\.evaluation_id`));
  assert.match(sql,/JOIN secureshop_auth\.assessment_judgments j/);assert.match(sql,/WHERE j\.objective_id=\$1 AND j\.shop_user_id=\$2/);
  for(const [index,field] of ['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].entries())
   assert.ok(sql.includes(`j.execution_json->'scope'->>'${field}'=$${index+3}`),field);
  assert.doesNotMatch(sql,/\b[tc]\.objective_id/);
  if(active){assert.match(sql,/^SELECT c\.evaluation_id FROM/);assert.match(sql,/ORDER BY c\.evaluation_id/);return{rows:empty?[]:[{evaluation_id:'evaluation-original'}]};}
  assert.match(sql,/^SELECT to_jsonb\(t\) row FROM/);assert.match(sql,/ORDER BY t\.tenant_id,t\.principal_id,t\.evaluation_id/);
  const table=sql.match(/FROM secureshop_auth\.(assessment_\w+) t/)[1];assert.ok(tables.includes(table));return{rows:empty?[]:rows[table]};
 }};
 const input={identity,objectiveId,scope,persona},history=await readers.readV07AssessmentHistory(input);
 assert.deepEqual(history,rows);assert.notEqual(history,rows);assert.notEqual(history.assessment_contributions[0].row,rows.assessment_contributions[0].row);
 assert.equal(Object.hasOwn(history.assessment_contributions[0].row,'objective_id'),false);
 assert.deepEqual(await readers.readV07ActiveAssessments(input),[{evaluation_id:'evaluation-original'}]);
 assert.equal(calls.length,4);assert.deepEqual(calls.slice(0,3).map(call=>call.sql.match(/FROM secureshop_auth\.(assessment_\w+) t/)[1]),tables);
 empty=true;assert.deepEqual(await readers.readV07AssessmentHistory(input),Object.fromEntries(tables.map(table=>[table,[]])));assert.deepEqual(await readers.readV07ActiveAssessments(input),[]);
});
test('V07 exact history and active readers preflight before inference and retain history through reset',()=>{
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');
 const start=source.indexOf('const historyInput={identity,objectiveId:Contract.OBJECTIVE,scope:actor.scope,persona:actor.persona};');
 const end=source.indexOf('} else if(V06_UPLOAD)',start);assert.ok(start>0&&end>start);const branch=source.slice(start,end);
 assert.ok(branch.includes('const history=()=>readV07AssessmentHistory(historyInput),activeAssessments=()=>readV07ActiveAssessments(historyInput);'));
 const upload=branch.indexOf('const upload=await H.runRenderedUpload(');assert.ok(upload>0);
 const preflight=branch.slice(0,upload);
 for(const literal of ['polyglotHistoryPreflight=await history()','assessment_judgments:[],assessment_completions:[],assessment_contributions:[]','assert.deepEqual(await activeAssessments(),[])','assert.equal(v44Transport.calls.length,0)'])assert.ok(preflight.includes(literal),literal);
 const reset=branch.indexOf('const resetResult=await reset.launchResetCoordinator.reset(');assert.ok(reset>upload);
 assert.ok(branch.slice(upload,reset).includes('assessment_judgments:1,assessment_completions:1,assessment_contributions:1'));
 assert.ok(branch.slice(upload,reset).includes('assert.deepEqual(await activeAssessments(),[{evaluation_id:originalAssessment.judgment.evaluationId}])'));
 assert.ok(branch.slice(reset).includes('assert.deepEqual(await history(),immutable)'));
 assert.ok(branch.slice(reset).includes('const active=await activeAssessments();assert.deepEqual(active,[])'));
});
test('V07 actual host POST validator rejects duplicate, mixed identity, lost-ack and original DTO substitutions',async()=>{
 const source=fs.readFileSync(path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),'utf8');
 const start=source.indexOf('function assertV07HttpPosts('),end=source.indexOf('async function bounded(',start);assert.ok(start>0&&end>start);
 const producer=[await polyglotProduced(),await polyglotProduced('fixed')],references=producer.map(p=>p.reference),evaluationId='00000000-0000-4000-8000-000000000073';
 const records=producer.flatMap((p,index)=>['polyglot-preview','polyglot-assess'].map(suffix=>({method:'POST',path:`/agents/customer/avatar-upload/${suffix}`,
  request:{sessionId:p.reference.sessionId,requestId:p.reference.requestId},status:200,droppedAcknowledgement:index===0,
  body:suffix==='polyglot-preview'?p.response:index===0?{completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:false}:{completed:false,status:'ineligible',modelEvaluated:false}})));
 for(const record of records.filter(row=>row.droppedAcknowledgement)){const originalBody=JSON.stringify(record.body),bytes=Buffer.from(originalBody);record.acknowledgement={mode:'headers-and-original-byte',originalStatus:200,contentType:'application/json',originalBody,originalBodySha256:require('node:crypto').createHash('sha256').update(bytes).digest('hex'),originalByteCount:bytes.length,transmittedPrefixBase64:bytes.subarray(0,1).toString('base64'),prefixWritten:true,responseClosed:true};}
 const validate=rows=>require('node:vm').runInNewContext(`${source.slice(start,end)};assertV07HttpPosts(JSON.parse(recordsJSON),JSON.parse(referencesJSON),evaluationId)`,
  {assert,Buffer,require,UUID:/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,recordsJSON:JSON.stringify(rows),referencesJSON:JSON.stringify(references),evaluationId});
 assert.equal(validate(records),true);
 for(const mutate of [rows=>rows.push(structuredClone(rows[0])),rows=>rows[0].request.requestId=references[1].requestId,
  rows=>rows[0].request.sessionId=references[1].sessionId,rows=>rows[0].request.extra=true,rows=>rows[0].droppedAcknowledgement=false,
  rows=>rows[2].droppedAcknowledgement=true,rows=>rows[1].status=503,rows=>rows[0].body.uploadOperationId=references[1].operationId,
  rows=>rows[0].body.replayed=true,rows=>rows[0].body.status='fixed_reencoded',rows=>rows[0].body.extra=true,
  rows=>rows[1].body.judgment.verdict='fail',rows=>rows[1].body.judgment.evaluationId=references[0].operationId,
  rows=>rows[3].body={completed:true,judgment:{verdict:'pass',evaluationId,canRetry:false},replayed:false},rows=>rows[0].acknowledgement.prefixWritten=false,rows=>rows[1].acknowledgement.responseClosed=false,rows=>rows[0].acknowledgement.originalBodySha256='0'.repeat(64),rows=>rows[2].acknowledgement={forged:true}]){
  const changed=structuredClone(records);mutate(changed);assert.throws(()=>validate(changed),assert.AssertionError);
 }
});

test('V07 committed ACK loss uses real Chrome and actual hook GET recovery with one POST per phase',
 {skip:!process.env.OWASP_AI_GOAT_V07_ACK_SMOKE_CHROME,timeout:60000},async()=>{
 // Controlled HTTP protocol smoke only: no database, model, uploaded-code
 // execution, canonical Judge or objective credit is established by this test.
 const http=require('node:http'),os=require('node:os'),{pathToFileURL}=require('node:url'),{createRequire}=require('node:module');
 const hostFile=path.join(__dirname,'postgres/secureshopCustomerCheckoutRendered.integration.test.js'),host=fs.readFileSync(hostFile,'utf8');
 const start=host.indexOf('function createV07CommittedAckObserver('),end=host.indexOf('function assertV07HttpPosts(',start);assert.ok(start>0&&end>start);
 const createObserver=new Function('assert','UUID','require',host.slice(start,end)+';return createV07CommittedAckObserver;')
  (assert,/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/,createRequire(hostFile));
 const reference={version:1,shopUserId:7,sessionId:'00000000-0000-4000-8000-000000000081',requestId:'00000000-0000-4000-8000-000000000082',operationId:'00000000-0000-4000-8000-000000000083',startedAt:1};
 const source={operationId:reference.operationId,uploadRequestId:reference.requestId,status:'completed',filename:'controlled.gif',byteCount:1,bodySha256:'a'.repeat(64)};
 const preview={operationId:'00000000-0000-4000-8000-000000000084',uploadOperationId:reference.operationId,status:'executed',sourceSha256:source.bodySha256,text:'Controlled original preview final.',replayed:false};
 const assessment={completed:true,judgment:{verdict:'pass',evaluationId:'00000000-0000-4000-8000-000000000085',canRetry:false},replayed:false};
 const clientRoot=path.resolve(__dirname,'../client'),entry='virtual:v07-committed-ack-smoke';
 const component=path.join(clientRoot,'src/pages/secureshop/components/CustomerAvatarUploadLesson.jsx'),refs=path.join(clientRoot,'src/pages/secureshop/utils/customerAvatarUploadReference.mjs'),grades=path.join(clientRoot,'src/pages/secureshop/utils/customerAvatarUploadAssessmentReference.mjs');
 const code=`import React from ${JSON.stringify(path.join(clientRoot,'node_modules/react/index.js'))};
import{createRoot}from ${JSON.stringify(path.join(clientRoot,'node_modules/react-dom/client.js'))};
import Lesson from ${JSON.stringify(component)};
import{createCustomerAvatarUploadReferenceStore,CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY}from ${JSON.stringify(refs)};
import{createCustomerAvatarUploadAssessmentStore,createCustomerAvatarSvgAssessmentStore,createCustomerAvatarPolyglotPreviewStore,createCustomerAvatarPolyglotAssessmentStore}from ${JSON.stringify(grades)};
const parentKey='controlled-v07-ack-smoke-parent-state',persisted=localStorage.getItem(parentKey),values=new Map(persisted?JSON.parse(persisted):[]),storage={getItem:key=>values.get(key)??null,setItem:(key,value)=>values.set(key,value),removeItem:key=>values.delete(key)};
if(persisted===null)values.set(CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY,JSON.stringify(${JSON.stringify(reference)}));
const refKeys=[CUSTOMER_AVATAR_UPLOAD_REFERENCE_KEY,${JSON.stringify(helper.POLYGLOT_PREVIEW_KEY)},${JSON.stringify(helper.POLYGLOT_ASSESSMENT_KEY)}];
let acknowledged=new Map(values),deferClears=false;const pendingClears=[],acknowledgements=[];
const snapshot=()=>Object.fromEntries(refKeys.map(key=>[key,acknowledged.get(key)??null]));
const flush=()=>new Promise(resolve=>{const submitted=new Map(values),commit=()=>{acknowledged=submitted;localStorage.setItem(parentKey,JSON.stringify([...acknowledged]));acknowledgements.push(snapshot());resolve();};
 if(deferClears&&refKeys.some(key=>acknowledged.has(key)&&!submitted.has(key)))pendingClears.push(commit);else commit();});
Object.defineProperty(window,'v07SmokeStorageAcknowledgements',{value:Object.freeze({snapshot,deferClears(){deferClears=true;},pending:()=>pendingClears.length,
 releaseNext(){if(pendingClears.length!==1)throw Error('Exactly one pending clear acknowledgement required');pendingClears.shift()();},history:()=>acknowledgements.slice()})});
const props={shopUserId:7,authorityKey:'controlled-owned-ack-smoke',referenceStore:createCustomerAvatarUploadReferenceStore({storage,flush}),assessmentStore:createCustomerAvatarUploadAssessmentStore({storage,flush}),svgAssessmentStore:createCustomerAvatarSvgAssessmentStore({storage,flush}),polyglotPreviewStore:createCustomerAvatarPolyglotPreviewStore({storage,flush}),polyglotAssessmentStore:createCustomerAvatarPolyglotAssessmentStore({storage,flush})};
createRoot(document.getElementById('root')).render(React.createElement(Lesson,props));`;
 const {build}=await import(pathToFileURL(path.join(clientRoot,'node_modules/vite/dist/node/index.js')).href);
 const built=await build({root:clientRoot,configFile:false,publicDir:false,logLevel:'silent',define:{'process.env.NODE_ENV':JSON.stringify('production')},plugins:[{name:'controlled-v07-ack-smoke',resolveId:id=>(id===entry||id.endsWith('/'+entry))?'\0'+entry:undefined,load:id=>id==='\0'+entry?code:undefined}],
  build:{write:false,emptyOutDir:false,target:'es2022',lib:{entry,name:'V07AckSmoke',formats:['iife']},rollupOptions:{output:{inlineDynamicImports:true}}}});
 const outputs=Array.isArray(built)?built:[built];assert.equal(outputs.length,1);const chunks=outputs[0].output.filter(row=>row.type==='chunk');assert.equal(chunks.length,1);const bundle=chunks[0].code;
 const app=require('express')(),records=[],requests=[],allRequests=[],errors=[],sockets=new Set();let saves=0,browser,page,profile,browserPid,retirementProof,reloadProof;
 app.use(require('express').json());
 app.use((req,res,next)=>{if(req.path.startsWith('/api/secureshop/'))allRequests.push({method:req.method,path:req.path});if(req.path.includes('/polyglot-preview')||req.path.includes('/polyglot-assess'))requests.push({method:req.method,path:req.path,body:structuredClone(req.body)});next();});
 const base='/api/secureshop/agents/customer/avatar-upload',routeBase='/agents/customer/avatar-upload',api=require('express').Router();
 app.use('/api/secureshop',(_req,res,next)=>{res.set('cache-control','no-store');next();},createObserver({records,save:()=>{saves++;}}),api);
 app.get('/',(_req,res)=>res.type('html').send('<!doctype html><div id="root"></div><script src="/smoke.js"></script>'));
 app.get('/smoke.js',(_req,res)=>res.type('js').send(bundle));app.get('/benign-avatar',(_req,res)=>res.type('html').send('<!doctype html><p>Controlled benign avatar</p>'));
 api.get(routeBase+'/operations/'+reference.operationId,(_req,res)=>res.json(source));
 api.post(routeBase+'/operations/'+reference.operationId+'/asset',(_req,res)=>res.json({operationId:reference.operationId,assetUrl:`http://127.0.0.1:${server.address().port}/benign-avatar`,expiresAt:Date.now()+60000}));
 api.get(routeBase+'/polyglot-readiness',(_req,res)=>res.json({ready:true}));
 for(const [suffix,packet]of [['polyglot-preview',preview],['polyglot-assess',assessment]]){
  api.post(routeBase+'/'+suffix,(req,res)=>{assert.deepEqual(req.body,{sessionId:reference.sessionId,requestId:reference.requestId});res.json(packet);});
  api.get(routeBase+'/'+suffix+'/'+reference.sessionId+'/'+reference.requestId,(_req,res)=>res.json({...packet,replayed:true}));
 }
 const server=http.createServer(app);server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
 try{
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
  profile=fs.mkdtempSync(path.join(os.tmpdir(),'owasp-ai-goat-v07-ack-smoke-'));
  browser=await require('puppeteer').launch({headless:true,executablePath:process.env.OWASP_AI_GOAT_V07_ACK_SMOKE_CHROME,userDataDir:profile,timeout:15000,protocolTimeout:15000});browserPid=browser.process().pid;
  page=await browser.newPage();page.on('pageerror',error=>errors.push(error.message));await page.goto(`http://127.0.0.1:${server.address().port}`,{waitUntil:'domcontentloaded'});
  const click=async selector=>{await page.waitForFunction(selector=>{const node=document.querySelector(selector);return node&&!node.disabled;},{timeout:10000},selector);await page.click(selector);};
  await page.waitForFunction(()=>document.querySelector('[data-testid="avatar-upload-status"]')?.textContent.includes('completed'),{timeout:10000});
  const open=await page.waitForFunction(()=>[...document.querySelectorAll('button')].find(node=>node.textContent.trim()==='Open sandbox preview'&&!node.disabled),{timeout:10000});
  try{await open.asElement().click();}finally{await open.dispose();}
  await click('[data-testid="avatar-polyglot-preview"]');
  await page.waitForFunction(text=>document.querySelector('[data-testid="avatar-polyglot-reply"]')?.textContent===text,{timeout:10000},preview.text);
  await click('[data-testid="avatar-polyglot-assess"]');
  await page.waitForFunction(()=>document.querySelector('[aria-label="Saved legacy image preview"]')?.textContent.includes('Polyglot objective completed in canonical progress.'),{timeout:10000});
  assert.deepEqual(errors,[]);assert.equal(saves,records.length+4);
  for(const [suffix,original]of [['polyglot-preview',preview],['polyglot-assess',assessment]]){
   const phase=requests.filter(row=>row.path===base+'/'+suffix||row.path.startsWith(base+'/'+suffix+'/'));assert.deepEqual(phase.map(row=>row.method),['POST','GET']);
   const originalRecord=records.find(row=>row.method==='POST'&&row.path==='/agents/customer/avatar-upload/'+suffix);assert.ok(originalRecord);assert.deepEqual(originalRecord.body,original);assert.equal(originalRecord.droppedAcknowledgement,true);
   const ack=originalRecord.acknowledgement,body=JSON.stringify(original);assert.equal(ack.originalBody,body);assert.equal(ack.originalBodySha256,require('node:crypto').createHash('sha256').update(body).digest('hex'));
   assert.equal(ack.originalByteCount,Buffer.byteLength(body));assert.equal(ack.transmittedPrefixBase64,Buffer.from(body).subarray(0,1).toString('base64'));assert.equal(ack.prefixWritten,true);assert.equal(ack.responseClosed,true);
   const saved=records.find(row=>row.method==='GET'&&row.path.startsWith('/agents/customer/avatar-upload/'+suffix+'/'));assert.deepEqual(saved.body,{...original,replayed:true});
  }
  const reloadBefore=structuredClone({requests,allRequests,records,saves});
  const reloadPaths=[base+'/operations/'+reference.operationId,base+'/polyglot-preview/'+reference.sessionId+'/'+reference.requestId,base+'/polyglot-assess/'+reference.sessionId+'/'+reference.requestId];
  const reloadResponses=reloadPaths.map(pathname=>page.waitForResponse(response=>response.request().method()==='GET'&&new URL(response.url()).pathname===pathname,{timeout:10000}));
  await page.reload({waitUntil:'domcontentloaded'});
  const savedPackets=await Promise.all(reloadResponses.map(async pending=>{const response=await pending;assert.equal(response.status(),200);return{path:new URL(response.url()).pathname,body:await response.json()};}));
  assert.deepEqual(savedPackets.map(row=>row.body),[source,{...preview,replayed:true},{...assessment,replayed:true}]);
  await page.waitForFunction(text=>document.querySelector('[data-testid="avatar-polyglot-reply"]')?.textContent===text&&document.querySelector('[aria-label="Saved legacy image preview"]')?.textContent.includes('Polyglot objective completed in canonical progress.'),{timeout:10000},preview.text);
  const reloadedRequests=requests.slice(reloadBefore.requests.length);assert.deepEqual(reloadedRequests.map(row=>({method:row.method,path:row.path})),reloadPaths.slice(1).map(path=>({method:'GET',path})));
  assert.ok(allRequests.slice(reloadBefore.allRequests.length).every(row=>row.method==='GET'));assert.equal(requests.filter(row=>row.method==='POST').length,2);
  reloadProof={before:reloadBefore,after:structuredClone({requests,allRequests,records,saves}),savedPackets};
  const clearKeys=['secureshop.customer-avatar-upload.lesson.v1',helper.POLYGLOT_PREVIEW_KEY,helper.POLYGLOT_ASSESSMENT_KEY];
  const readAcknowledged=()=>page.evaluate(()=>window.v07SmokeStorageAcknowledgements.snapshot());
  const initialAcknowledged=await readAcknowledged();assert.deepEqual(JSON.parse(initialAcknowledged[clearKeys[0]]),reference);
  for(const key of clearKeys.slice(1)){const saved=JSON.parse(initialAcknowledged[key]);assert.equal(saved.sessionId,reference.sessionId);assert.equal(saved.requestId,reference.requestId);}
  const retirementBefore=structuredClone({requests,allRequests,records,saves});
  await page.evaluate(()=>window.v07SmokeStorageAcknowledgements.deferClears());
  const startAnother=await page.waitForFunction(()=>[...document.querySelectorAll('button')].find(node=>node.textContent.trim()==='Start another avatar upload'&&!node.disabled),{timeout:10000});
  try{await startAnother.asElement().click();}finally{await startAnother.dispose();}
  const retirementAcknowledgements=[];
  for(const key of [helper.POLYGLOT_PREVIEW_KEY,helper.POLYGLOT_ASSESSMENT_KEY,clearKeys[0]]){
   await page.waitForFunction(()=>window.v07SmokeStorageAcknowledgements.pending()===1,{timeout:10000});
   const beforeAck=await readAcknowledged();assert.notEqual(beforeAck[key],null);
   assert.equal(await page.$('[data-testid="avatar-upload-file"]'),null);
   assert.equal(await page.$eval('[aria-label="Saved avatar upload"]',node=>[...node.querySelectorAll('button')].filter(button=>button.textContent.trim()==='Start another avatar upload').some(button=>button.disabled)),true);
   await page.evaluate(()=>window.v07SmokeStorageAcknowledgements.releaseNext());
   await page.waitForFunction(key=>window.v07SmokeStorageAcknowledgements.snapshot()[key]===null,{timeout:10000},key);
   retirementAcknowledgements.push(await readAcknowledged());
  }
  await page.waitForFunction(()=>{const input=document.querySelector('[data-testid="avatar-upload-file"]');return input&&!input.disabled&&!document.querySelector('[aria-label="Saved avatar upload"]')&&!document.querySelector('[aria-label="Saved legacy image preview"]');},{timeout:10000});
  assert.deepEqual(await readAcknowledged(),Object.fromEntries(clearKeys.map(key=>[key,null])));
  assert.equal(await page.evaluate(()=>window.v07SmokeStorageAcknowledgements.pending()),0);
  assert.deepEqual({requests,allRequests,records,saves},retirementBefore);
  assert.equal(retirementAcknowledgements.length,3);retirementProof={initialAcknowledged,acknowledgements:retirementAcknowledgements,finalAcknowledged:await readAcknowledged(),before:retirementBefore,after:structuredClone({requests,allRequests,records,saves})};
 }catch(error){
  const visible=page?await page.evaluate(()=>document.body.innerText).catch(()=>null):null;
  throw new Error(`Controlled ACK smoke failed: ${error.message}; ${JSON.stringify({errors,requests,records,visible})}`,{cause:error});
 }finally{
  if(browser)await browser.close();for(const socket of sockets)socket.destroy();server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
  if(profile)fs.rmSync(profile,{recursive:true,force:true});
 }
 assert.equal(server.listening,false);assert.equal(sockets.size,0);assert.equal(fs.existsSync(profile),false);assert.throws(()=>process.kill(browserPid,0),{code:'ESRCH'});
 if(process.env.OWASP_AI_GOAT_V07_ACK_SMOKE_EVIDENCE_PATH)fs.writeFileSync(process.env.OWASP_AI_GOAT_V07_ACK_SMOKE_EVIDENCE_PATH,JSON.stringify({version:1,controlled:true,actualModel:false,genuineCredit:false,hook:'useCustomerAvatarUploadLesson',component:'CustomerAvatarUploadLesson',requests,allRequests,records,reload:reloadProof,retirement:retirementProof,originalBodiesRetained:true,onePostThenGetEach:true,retirementAcknowledged:true,retirementNoNetworkReplay:true,readyFileChooser:true,serverClosed:true,browserProcessAbsent:true,profileAbsent:true},null,2)+'\n',{mode:0o600});
});
