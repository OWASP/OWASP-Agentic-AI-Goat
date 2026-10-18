'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const {validateStandaloneSsrfCaptureStructure:structure,validateStandaloneSsrfCapture:qualify,MODEL,OBJECTIVE,CALLER_OBLIGATIONS}=require('./fixtures/secureshopStandaloneSsrfQualification');
const {digestMcpValue}=require('../server/services/secureshopMcpTrustTools');
const {SSRF_EGRESS_POLICY_SHA256}=require('../server/services/secureshopSsrfExternalAdapter');
const {SECURESHOP_SSRF_RUBRIC}=require('../server/services/secureshopSsrfAssessment');
const {prepareJudgeInput,JUDGE_VERSION,createObjectiveJudge,readConfiguredJudgeProvenance}=require('../server/agent-runtime/objectiveJudge');
const {DECISION_SCHEMA}=require('../server/services/secureshop/providers/ollamaProvider');
const {FINAL_RESPONSE_SCHEMA}=require('../server/agent-runtime/providers/finalResponseContract');
const sha=x=>createHash('sha256').update(x).digest('hex'),id=x=>`00000000-0000-4000-8000-${String(x).padStart(12,'0')}`;
const copy=x=>structuredClone(x);
const snapshot=()=>({requests:[],turns:[],traces:[],invocations:[],http:[],effects:[],judgments:[],contributions:[]});

// Entirely constructed contract fixtures. No PostgreSQL, browser, HTTP listener,
// native resources, actual inference, grading or completion writes occur here.
function fixture(){
 const s={tenantId:id(1),principalId:id(2),shopUserId:3,membershipVersion:'1',personaSessionId:id(4),personaAuthorityVersion:'1',role:'customer',launchId:id(5),scenarioId:id(6),generation:1,platformOwnerId:7,platformSessionId:8};
 const scope=Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(k=>[k,s[k]]));
 const pins=Object.fromEntries(['client/src/pages/secureshop/components/ControlledSsrfLab.jsx','server/routes/secureshop/boundSsrf.js','server/services/secureshopSsrfExternalAdapter.js','server/database/postgres/secureshopAssessmentStore.js'].map(k=>[k,'a'.repeat(64)]));
 const f={version:1,subject:s,catalog:{objectiveId:OBJECTIVE,qualification:'native-model',tenantId:s.tenantId,explicitlyEnabled:true,workshopAvailability:{registered:true,visible:true,enabled:true}},cases:[],wire:[],retry:null,lifecycle:null,browser:{executableSha256:'b'.repeat(64),pid:100,owned:true,closed:true},sourcePins:{before:pins,after:copy(pins)}};
 function wire(role,caseId,content,messages=[{role:'user',content:caseId}],format={type:'object'}){const request=JSON.stringify({model:MODEL,messages,format}),response=JSON.stringify({message:{content:JSON.stringify(content)}}),index=f.wire.length;f.wire.push({role,caseId,status:'returned',request,response,requestSha256:sha(request),responseSha256:sha(response)});return index;}
 for(const [offset,name]of ['public','private','fixed-private'].entries()){
  const fixed=name==='fixed-private',resource=name==='public'?'public-policy':'private-policy',requestId=id(20+offset),sessionId=id(30+offset),runId=id(40+offset),targetId=id(50+offset),operationId=id(60+offset),nonce=id(70+offset),url=`http://127.0.0.1:12345/policy/${name}`,args={policy_url:url},callId='call-'+name,ownerKey=JSON.stringify(['SecureShopBoundConversation',sessionId]),ownerGeneration='0';
  const decisionIndex=wire('actor',name,{tool_calls:[{agent:'summarizer',tool:'explain_return_policy',args}]}),answer=fixed?'The private destination was blocked.':'Owned policy '+name,finalIndex=wire('actor',name,fixed?{reply:answer}:{answer},undefined,fixed?DECISION_SCHEMA:FINAL_RESPONSE_SCHEMA);
  const body=JSON.stringify({recordId:'internal-policy:'+targetId,classification:'protected-training-record'}),result={url,status:200,headers:{'content-type':'application/json; charset=utf-8','content-length':String(Buffer.byteLength(body))},body,summary:`Fetched policy from ${url} (status 200). Body follows:\n\n${body}`};
  const receiptBody={version:1,targetId,nonce,operationId,requestId,method:'GET',path:new URL(url).pathname,resourceKind:resource,status:200,responseSha256:sha(result.body)},httpReceipt={...receiptBody,receiptSha256:sha(JSON.stringify(receiptBody))};
  const invocation={targetId,operationId,requestId,sessionId,runId,callId,requestMethod:'GET',requestPath:receiptBody.path,responseStatus:200,resourceKind:resource,policyDecision:name==='public'?'allowed':'denied',egressPolicySha256:SSRF_EGRESS_POLICY_SHA256,argumentsSha256:digestMcpValue(args),resultSha256:digestMcpValue(result),responseSha256:receiptBody.responseSha256,egressReceiptSha256:httpReceipt.receiptSha256,launch:scope};
  const {launch:unused,...invocationMeta}=invocation;
  const output=fixed?{isError:true,content:[{type:'text',text:JSON.stringify({ok:false,code:'INVALID_TOOL_SELECTION',error:'Selected tool was rejected before execution.'})}]}:{content:[{type:'text',text:JSON.stringify(result)}],_meta:{...invocationMeta,version:1,nonce,ownerKey,generation:ownerGeneration}};
  const trace=(kind,params,result_json,provider=null)=>({session_id:sessionId,step:1,kind,provider,agent_ns:kind==='mcp_result'?'summarizer':null,tool_name:kind==='mcp_result'?'explain_return_policy':null,params_json:params===null?null:JSON.stringify(params),result_json:JSON.stringify(result_json)});
  const mode=fixed?'fixed':'vuln',modeGeneration=0,modeRevision=fixed?'2':'1',c={id:name,mode,modeGeneration,modeRevision,modeStamp:sha(JSON.stringify(['shop-tenant-mode-v1',s.tenantId,s.principalId,modeGeneration,modeRevision,mode])),resource,requestId,sessionId,runId,ownerKey,ownerGeneration,
   physical:{label:name==='public'?'Fetch public policy':'Try internal policy',postBody:{resource,request_id:requestId},hit:{x:40,y:80,tagName:'BUTTON',text:name==='public'?'Fetch public policy':'Try internal policy'},renderedText:answer,response:{status:200,body:{stopReason:'end_turn',resourceKind:resource,response:answer,replayed:false}}},
   decision:{wireIndex:decisionIndex,step:1,callId,tool:'summarizer.explain_return_policy',args},final:{wireIndex:finalIndex,text:answer},
   traces:{decision:trace('model_decision',{toolCalls:[{id:callId,name:'summarizer.explain_return_policy',args}]},{model:MODEL,mocked:false},'ollama'),result:trace('mcp_result',null,output),terminal:trace('terminal',null,{stopReason:'end_turn',steps:1,hops:1,model:MODEL,mocked:false},'ollama')},
   request:{operationId,targetId,nonce,requestId,resourceKind:resource,url,policyDecision:invocation.policyDecision,egressPolicySha256:SSRF_EGRESS_POLICY_SHA256},invocation:fixed?null:invocation,httpReceipt:fixed?null:httpReceipt,effect:fixed?null:{version:1,runId,ownerKey,generation:ownerGeneration,effectKey:`${requestId}:${JSON.stringify([1,callId,'summarizer.explain_return_policy'])}`,status:'completed'},effectCounts:{http:fixed?0:1,invocations:fixed?0:1,judgments:name==='private'?1:0,contributions:name==='private'?1:0},judgments:[],contributions:[]};
  f.cases.push(c);
 }
 const c=f.cases[1],i=c.invocation,chain={runId:c.runId,requestId:c.requestId,targetId:i.targetId,operationId:i.operationId,callId:i.callId,toolName:c.decision.tool,requestMethod:i.requestMethod,requestPath:i.requestPath,egressPolicySha256:i.egressPolicySha256,policyDecision:i.policyDecision,responseStatus:i.responseStatus,responseSha256:i.responseSha256,egressReceiptSha256:i.egressReceiptSha256,resultSha256:i.resultSha256,protectedObservation:{recordId:'internal-policy:'+i.targetId,classification:'protected-training-record',contentSha256:i.responseSha256},effectReceipt:c.effect};
 const input={rubric:{...SECURESHOP_SSRF_RUBRIC,mode:'vuln'},facts:Object.fromEntries(SECURESHOP_SSRF_RUBRIC.requiredFacts.map(k=>[k,true])),evidence:[{id:'bound_ssrf_invocation_chain',source:'server_observation',content:chain}],execution:{runId:c.runId,check:async()=>{},emit:async()=>{}}};
 const prepared=prepareJudgeInput(input),evaluationId=id(80),execution_json={tenantId:s.tenantId,principalId:s.principalId,shopUserId:s.shopUserId,membershipVersion:s.membershipVersion,scope,personaSessionId:s.personaSessionId,personaAuthorityVersion:s.personaAuthorityVersion,role:s.role,runId:c.runId,ownerKey:c.ownerKey,ownerGeneration:c.ownerGeneration};
 const j={tenant_id:s.tenantId,principal_id:s.principalId,shop_user_id:s.shopUserId,evaluation_id:evaluationId,objective_id:OBJECTIVE,run_id:c.runId,generation:0,mode:c.mode,mode_stamp:c.modeStamp,execution_json,packet:prepared.packet,evidence_digest:prepared.evidenceDigest,owner_key:c.ownerKey,owner_generation:c.ownerGeneration,verdict:'pass',disposition:'awarded',result_json:null,result_serialized:null,result_digest:null,judge_result_json:null,judge_observations:null};
 c.judgments.push(j);c.contributions.push({tenant_id:s.tenantId,principal_id:s.principalId,evaluation_id:evaluationId});
 const judgeReply={verdict:'pass',explanation:'The owned protected HTTP receipt matches.',criteria:[{id:SECURESHOP_SSRF_RUBRIC.criteria[0].id,satisfied:true,evidenceRefs:['bound_ssrf_invocation_chain']}]};
 const claimed={...judgeReply,provider:'ollama',model:MODEL,runId:c.runId,evidenceDigest:prepared.evidenceDigest,judgeVersion:JUDGE_VERSION};
 wire('judge','private',judgeReply,[{role:'user',content:prepared.packet}]);
 function setJudge(result,proof){j.result_json=copy(result);j.result_serialized=JSON.stringify(result);j.result_digest=sha(j.result_serialized);j.judge_result_json=JSON.stringify(result);j.judge_observations=copy(proof);refresh();}
 function refresh(){const before=snapshot();Object.assign(before,{requests:[copy(c.request)],turns:[{sessionId:c.sessionId,requestId:c.requestId,status:'completed',result:copy(c.physical.response.body)}],traces:Object.values(copy(c.traces)),invocations:[copy(c.invocation)],http:[copy(c.httpReceipt)],effects:[copy(c.effect)],judgments:copy(c.judgments),contributions:copy(c.contributions)});
  const counts={actor:6,judge:f.wire.filter(x=>x.role==='judge').length,http:2,turns:2,invocations:2,traces:6,judgments:1,contributions:1};f.retry={requestId:c.requestId,postBody:copy(c.physical.postBody),response:{status:200,body:{...c.physical.response.body,replayed:true}},renderedText:c.final.text,before,after:copy(before),countsBefore:counts,countsAfter:copy(counts)};
  const sibling=snapshot();sibling.requests=[{targetId:id(90)}];const immutable={judgments:copy(c.judgments),contributions:copy(c.contributions),http:f.cases.slice(0,2).map(x=>copy(x.httpReceipt)),effects:f.cases.slice(0,2).map(x=>copy(x.effect))};
  const siblingSubject={...s,principalId:id(91),launchId:id(92),platformOwnerId:93,platformSessionId:94,personaSessionId:id(95),shopUserId:96};const positive=subject=>({status:200,scope:Object.fromEntries(['launchId','scenarioId','generation','platformOwnerId','platformSessionId'].map(k=>[k,subject[k]])),personaSessionId:subject.personaSessionId,body:{ready:true}});
  f.lifecycle={ownerPositive:positive(s),sessionDenied:401,resetDenied:401,siblingSubject,siblingPositiveBefore:positive(siblingSubject),siblingPositiveAfter:positive(siblingSubject),siblingBefore:sibling,siblingAfter:copy(sibling),immutableBefore:immutable,immutableAfter:copy(immutable),activeAfterReset:[],targetsRetired:true};}
 const proof={version:1,judgeVersion:JUDGE_VERSION,runId:c.runId,evidenceDigest:prepared.evidenceDigest,resultSha256:sha(JSON.stringify(claimed)),calls:[{provider:'ollama',model:MODEL}]};setJudge(claimed,proof);
 return {capture:f,input,judgeReply,claimed,setJudge,refresh};
}

test('constructed standalone capture is complete but serialized Judge claims cannot qualify',()=>{
 const {capture,claimed}=fixture();assert.deepEqual(structure(capture),{captureValid:true,configuredJudgeProof:false,actualModelProof:false,qualification:'pending-owned-caller',callerObligations:CALLER_OBLIGATIONS,actorCalls:6,judgeCalls:1});
 assert.throws(()=>qualify(capture),/Original configured Judge result/);
 assert.throws(()=>qualify(capture,{judgeResults:new Map([[id(80),claimed]])}),/not configured Judge proof/);
 assert.throws(()=>qualify(capture,{judgeResults:new Map([[id(80),copy(claimed)]])}),/not configured Judge proof/);
});

test('final wire normalization uses exact production protocols without changing raw bytes or accepting aliases',()=>{
 const {normalizeStandaloneSsrfFinalWire:normalize}=require('./fixtures/secureshopStandaloneSsrfQualification');
 const {capture}=fixture();
 for(const c of capture.cases){
  const wire=capture.wire[c.final.wireIndex],before=copy(wire);
  assert.equal(normalize(wire,{fixed:c.id==='fixed-private'}),c.final.text);
  assert.deepEqual(wire,before);
 }
 const fixed=capture.wire[capture.cases[2].final.wireIndex];
 for(const value of [{answer:capture.cases[2].final.text},{reply:''},{reply:42},
  {reply:capture.cases[2].final.text,answer:capture.cases[2].final.text},
  {reply:capture.cases[2].final.text,claimedCredit:true},
  {tool_calls:[{agent:'summarizer',tool:'explain_return_policy',args:{}}]}]){
  const changed=copy(fixed);changed.response=JSON.stringify({message:{content:JSON.stringify(value)}});
  assert.throws(()=>normalize(changed,{fixed:true}));
 }
 const changed=copy(fixed);changed.request=JSON.stringify({...JSON.parse(changed.request),format:FINAL_RESPONSE_SCHEMA});
 assert.throws(()=>normalize(changed,{fixed:true}));
 assert.throws(()=>normalize(fixed,{fixed:false}));
});

test('closed standalone contract rejects each independent authority, effect, mode and replay mutation',async t=>{
 const mutations={
  'unknown root field':f=>f.qualified=true,
  'unknown case field':f=>f.cases[0].sceneId=id(99),
  'foreign tenant':f=>f.cases[1].judgments[0].tenant_id=id(99),
  'foreign principal':f=>f.cases[1].judgments[0].principal_id=id(99),
  'foreign shop persona':f=>f.cases[1].judgments[0].shop_user_id=99,
  'foreign membership':f=>f.cases[1].judgments[0].execution_json.membershipVersion='2',
  'foreign persona session':f=>f.cases[1].judgments[0].execution_json.personaSessionId=id(99),
  'revoked persona authority':f=>f.cases[1].judgments[0].execution_json.personaAuthorityVersion='2',
  'merchant substitution':f=>f.cases[1].judgments[0].execution_json.role='merchant',
  'foreign launch':f=>f.cases[1].invocation.launch.launchId=id(99),
  'stale launch generation':f=>f.cases[1].invocation.launch.generation=2,
  'foreign platform session':f=>f.cases[1].invocation.launch.platformSessionId=99,
  'disabled tenant objective':f=>f.catalog.explicitlyEnabled=false,
  'disabled workshop availability':f=>f.catalog.workshopAvailability.enabled=false,
  'unqualified catalog':f=>f.catalog.qualification='controlled',
  'incorrect physical control':f=>f.cases[1].physical.hit.tagName='DIV',
  'different rendered answer':f=>f.cases[1].physical.renderedText='invented',
  'changed fixed raw model answer':f=>{const c=f.cases[2],w=f.wire[c.final.wireIndex];w.response=JSON.stringify({message:{content:JSON.stringify({reply:'Invented final'})}});w.responseSha256=sha(w.response);},
  'different POST identity':f=>f.cases[1].physical.postBody.request_id=id(99),
  'tool-less decision':f=>{const c=f.wire[2];c.response=JSON.stringify({message:{content:'{"tool_calls":[]}'}});c.responseSha256=sha(c.response);},
  'different selected URL':f=>f.cases[1].decision.args.policy_url='http://127.0.0.1:12345/other',
  'non-loopback HTTP':f=>f.cases[1].request.url='http://example.test/policy',
  'unhashed raw wire':f=>f.wire[0].response+=' ',
  'wrong actual model':f=>{const c=f.wire[0];c.request=JSON.stringify({...JSON.parse(c.request),model:'mock'});c.requestSha256=sha(c.request);},
  'failed actor wire':f=>f.wire[0].status='failed',
  'foreign final trace':f=>f.cases[1].traces.terminal.session_id=id(99),
  'mock terminal':f=>f.cases[1].traces.terminal.result_json=JSON.stringify({model:MODEL,mocked:true,stopReason:'end_turn'}),
  'terminal missing actual steps and hops':f=>f.cases[1].traces.terminal.result_json=JSON.stringify({model:MODEL,mocked:false,stopReason:'end_turn'}),
  'terminal fallback':f=>{const c=f.cases[1].traces.terminal;c.result_json=JSON.stringify({...JSON.parse(c.result_json),fallback:true});},
  'terminal steps contradict raw trace':f=>{const c=f.cases[1].traces.terminal;c.result_json=JSON.stringify({...JSON.parse(c.result_json),steps:2});},
  'terminal has no tool hop':f=>{const c=f.cases[1].traces.terminal;c.result_json=JSON.stringify({...JSON.parse(c.result_json),hops:0});},
  'altered HTTP body hash':f=>f.cases[1].httpReceipt.responseSha256='0'.repeat(64),
  'altered immutable invocation':f=>f.cases[1].invocation.resultSha256='0'.repeat(64),
  'unbound effect owner':f=>f.cases[1].effect.ownerKey='foreign',
  'missing complete effect':f=>f.cases[1].effect.status='started',
  'public baseline credit':f=>f.cases[0].contributions=[copy(f.cases[1].contributions[0])],
  'fixed mode stamp drift':f=>f.cases[2].modeStamp=f.cases[1].modeStamp,
  'fixed private HTTP effect':f=>f.cases[2].httpReceipt=copy(f.cases[1].httpReceipt),
  'fixed hidden HTTP effect count':f=>f.cases[2].effectCounts.http=1,
  'fixed credit':f=>f.cases[2].contributions=[copy(f.cases[1].contributions[0])],
  'unsupported fixed error':f=>f.cases[2].traces.result.result_json=JSON.stringify({isError:true,content:[{text:'a generic refusal'}]}),
  'different Judge packet':f=>f.cases[1].judgments[0].packet+=' ',
  'arbitrary passing rubric':f=>{const j=f.cases[1].judgments[0],packet=JSON.parse(j.packet);packet.rubric.requiredFacts=['invented'];packet.facts={invented:true};j.packet=JSON.stringify(packet);j.evidence_digest=sha(j.packet);},
  'forged stored Judge digest':f=>f.cases[1].judgments[0].result_digest='0'.repeat(64),
  'wrong stored Judge run':f=>f.cases[1].judgments[0].judge_observations.runId=id(99),
  'wrong contribution evaluation':f=>f.cases[1].contributions[0].evaluation_id=id(99),
  'retry new UUID':f=>f.retry.requestId=id(99),
  'retry additional model':f=>f.retry.countsAfter.actor++,
  'retry new effect':f=>f.retry.after.effects.push(copy(f.cases[1].effect)),
  'retry unrelated snapshot equality':f=>{f.retry.before.invocations=[copy(f.cases[0].invocation)];f.retry.after=copy(f.retry.before);},
  'retry changed answer':f=>f.retry.response.body.response='invented',
  'same-launch sibling':f=>f.lifecycle.siblingSubject.launchId=f.subject.launchId,
  'same-owner sibling':f=>f.lifecycle.siblingSubject.platformOwnerId=f.subject.platformOwnerId,
  'sibling changed':f=>f.lifecycle.siblingAfter.requests=[],
  'empty preservation equality':f=>{f.lifecycle.siblingBefore.requests=[];f.lifecycle.siblingAfter.requests=[];},
  'lost immutable judgment':f=>f.lifecycle.immutableAfter.judgments=[],
  'unrelated immutable equality':f=>{f.lifecycle.immutableBefore.http=[copy(f.cases[0].httpReceipt)];f.lifecycle.immutableAfter=copy(f.lifecycle.immutableBefore);},
  'reset retained active contribution':f=>f.lifecycle.activeAfterReset=[copy(f.cases[1].contributions[0])],
  'session still authorized':f=>f.lifecycle.sessionDenied=200,
  'owner never positively admitted':f=>f.lifecycle.ownerPositive.status=401,
  'sibling unavailable after reset':f=>f.lifecycle.siblingPositiveAfter.status=401,
  'sibling positive uses wrong scope':f=>f.lifecycle.siblingPositiveBefore.scope.launchId=f.subject.launchId,
  'targets not retired':f=>f.lifecycle.targetsRetired=false,
  'browser left open':f=>f.browser.closed=false,
  'source drift':f=>f.sourcePins.after['server/routes/secureshop/boundSsrf.js']='0'.repeat(64),
  'too many genuine actor calls':f=>{while(f.wire.filter(x=>x.role==='actor').length<25)f.wire.push(copy(f.wire[0]));},
  'Judge outside private case':f=>f.wire.at(-1).caseId='public',
 };
 for(const [name,change]of Object.entries(mutations))await t.test(name,()=>{const {capture}=fixture();change(capture);assert.throws(()=>structure(capture));});
});

test('complete SDK output retains headers and summary in the immutable result digest',async()=>{
 const http=require('node:http'),{EventEmitter}=require('node:events');
 const original=http.request,url='http://127.0.0.1:12345/policy/private';
 const body='Controlled policy bytes',headers={'content-type':'application/json','content-length':String(Buffer.byteLength(body)),'set-cookie':['controlled=a','controlled=b']};
 // Invoke the actual SDK tool with an in-memory HTTP exchange. No socket is
 // opened; this proves producer shape only, never actual HTTP/model provenance.
 http.request=(options,onResponse)=>{
  assert.equal(options.method,'GET');assert.equal(options.hostname,'127.0.0.1');assert.equal(options.path,'/policy/private');
  const request=new EventEmitter();request.setTimeout=()=>request;
  request.end=()=>{queueMicrotask(()=>{const response=new EventEmitter();Object.assign(response,{statusCode:200,headers});onResponse(response);response.emit('data',Buffer.from(body));response.emit('end');});return request;};
  return request;
 };
 let produced;
 try{produced=await require('../agent-host/agents/summarizer/tools/explain_return_policy').explainReturnPolicy({policy_url:url});}finally{http.request=original;}
 assert.deepEqual(produced,{url,status:200,headers,body,summary:`Fetched policy from ${url} (status 200). Body follows:\n\n${body}`});
 assert.notEqual(digestMcpValue(produced),digestMcpValue({url,status:200,body}));
 const f=fixture(),observed=JSON.parse(JSON.parse(f.capture.cases[0].traces.result.result_json).content[0].text);
 assert.deepEqual(Object.keys(observed),['url','status','headers','body','summary']);
 assert.equal(f.capture.cases[0].invocation.resultSha256,digestMcpValue(observed));
 assert.equal(structure(f.capture).captureValid,true);
});

test('changed SDK headers, summary, reduced output or result digest cannot match the saved invocation',async t=>{
 const mutations={
  'changed headers':observed=>observed.headers['content-type']='text/plain',
  'changed summary':observed=>observed.summary='Fabricated policy summary',
  'headers omitted':observed=>delete observed.headers,
  'summary omitted':observed=>delete observed.summary,
  'malformed headers':observed=>observed.headers={'content-type':42},
  'noncanonical header names':observed=>observed.headers={'Content-Type':'application/json'},
  'extra output':observed=>observed.source='fabricated',
 };
 for(const [name,mutate]of Object.entries(mutations))await t.test(name,()=>{
  const f=fixture(),c=f.capture.cases[0],output=JSON.parse(c.traces.result.result_json),observed=JSON.parse(output.content[0].text);
  mutate(observed);output.content[0].text=JSON.stringify(observed);c.traces.result.result_json=JSON.stringify(output);
  assert.throws(()=>structure(f.capture));
 });
 const f=fixture();f.capture.cases[0].invocation.resultSha256='0'.repeat(64);assert.throws(()=>structure(f.capture));
});

test('private source requires the canonical protected record even when HTTP digests are consistently rebound',()=>{
 for(const changed of [{recordId:'internal-policy:'+id(99),classification:'protected-training-record'},{recordId:'internal-policy:'+id(51),classification:'public-training-record'}]){
  const f=fixture(),c=f.capture.cases[1],output=JSON.parse(c.traces.result.result_json),observed=JSON.parse(output.content[0].text);observed.body=JSON.stringify(changed);
  observed.summary=`Fetched policy from ${observed.url} (status ${observed.status}). Body follows:\n\n${observed.body}`;
  c.httpReceipt.responseSha256=sha(observed.body);const {receiptSha256:unused,...body}=c.httpReceipt;c.httpReceipt.receiptSha256=sha(JSON.stringify(body));
  Object.assign(c.invocation,{responseSha256:c.httpReceipt.responseSha256,resultSha256:digestMcpValue(observed),egressReceiptSha256:c.httpReceipt.receiptSha256});
  Object.assign(output._meta,{responseSha256:c.invocation.responseSha256,resultSha256:c.invocation.resultSha256,egressReceiptSha256:c.invocation.egressReceiptSha256});output.content[0].text=JSON.stringify(observed);c.traces.result.result_json=JSON.stringify(output);
  assert.throws(()=>structure(f.capture),error=>error.code==='ERR_ASSERTION'&&(error.actual===changed.recordId||error.actual===changed.classification));
 }
});

test('default configured Judge identity is bound to observed wire under controlled in-memory transport only',async()=>{
 const f=fixture(),priorFetch=global.fetch,keys=['JUDGE_PROVIDER','JUDGE_MODEL','OLLAMA_BASE_URL'],old=Object.fromEntries(keys.map(k=>[k,process.env[k]]));
 process.env.JUDGE_PROVIDER='ollama';process.env.JUDGE_MODEL=MODEL;process.env.OLLAMA_BASE_URL='http://127.0.0.1:1';
 const calls=[];global.fetch=async(url,init)=>{assert.equal(new URL(url).origin,'http://127.0.0.1:1');const request=typeof init.body==='string'?init.body:Buffer.from(init.body).toString();
  const response=JSON.stringify({model:MODEL,message:{role:'assistant',content:JSON.stringify(f.judgeReply)},done:true,done_reason:'stop',prompt_eval_count:20,eval_count:20});calls.push({role:'judge',caseId:'private',status:'returned',request,response,requestSha256:sha(request),responseSha256:sha(response)});
  return new Response(response+'\n',{status:200,headers:{'content-type':'application/x-ndjson'}});};
 try{const result=await createObjectiveJudge()(f.input);assert.equal(result.verdict,'pass');const proof=readConfiguredJudgeProvenance(result);assert(proof);
  f.capture.wire=f.capture.wire.filter(x=>x.role!=='judge').concat(calls);f.setJudge(result,proof);
  const validated=qualify(f.capture,{judgeResults:new Map([[id(80),result]])});assert.equal(validated.configuredJudgeProof,true);assert.equal(validated.actualModelProof,false);assert.equal(validated.qualification,'pending-owned-caller');assert.equal(Object.hasOwn(validated,'genuineCredit'),false);assert.equal(Object.hasOwn(validated,'qualifiedObjectiveIds'),false);
  assert.throws(()=>qualify(f.capture,{judgeResults:new Map([[id(80),copy(result)]])}),/not configured Judge proof/);
  const changed=copy(f.capture);changed.cases[1].judgments[0].judge_observations.calls[0].responseSha256='0'.repeat(64);assert.throws(()=>qualify(changed,{judgeResults:new Map([[id(80),result]])}));
 }finally{global.fetch=priorFetch;for(const key of keys)if(old[key]===undefined)delete process.env[key];else process.env[key]=old[key];}
});

test('V27 admission is confined to exact default-disabled disposable pending source and normal admin enablement',async()=>{
 const {admitPolicyOutputDisposableCandidate:admit,POLICY_OUTPUT_OBJECTIVE:objective}=require('./fixtures/secureshopStandaloneSsrfQualification');
 const curriculum=require('../server/config/secureshopCurriculum'),before=process.env.PG_TEST_DISPOSABLE;let effects=0,enabled=false,promoted=false;
 const catalog={async list(){return{objectives:[{objectiveId:objective,qualification:promoted?'native-browser-judge':'pending',enabled,revision:'1'}]};},
  async set(_context,input){effects++;if(!promoted)throw Object.assign(Error('pending'),{code:'SHOP_OBJECTIVE_UNQUALIFIED'});enabled=input.enabled;return{enabled,qualification:'native-browser-judge'};}};
 const migration={async query(sql,args){effects++;assert(sql.includes("configuration_source='checked_in_default'"));assert.equal(args[0],objective);
  assert.equal(args[1],'87e5d075b76b239f9b0604bc632dbcb18565c255cd99a2c1c4a6245caa8a0a4d');assert.equal(sha(args[2]),args[1]);promoted=true;
  return{rowCount:1,rows:[{objective_id:objective,qualification:'native-browser-judge',is_enabled:false}]};}};
 try{
  process.env.PG_TEST_DISPOSABLE='no';await assert.rejects(admit({migration,catalog,curriculum}));assert.equal(effects,0);
  process.env.PG_TEST_DISPOSABLE='yes';const changed={...curriculum,OBJECTIVES:curriculum.OBJECTIVES.map(row=>row.id===objective?{...row,text:row.text+' drift'}:row)};
  await assert.rejects(admit({migration,catalog,curriculum:changed}));assert.equal(effects,0);
  assert.deepEqual(await admit({migration,catalog,curriculum}),{objectiveId:objective,fixtureLocalCandidateAdmission:true,productionQualification:'pending',productionDefaultEnabled:false});assert.equal(effects,3);
 }finally{if(before===undefined)delete process.env.PG_TEST_DISPOSABLE;else process.env.PG_TEST_DISPOSABLE=before;}
});
test('V27 wire joins exact original tool and structured final model response, never source substitution',()=>{
 const {fixture,qualify}=require('./secureshopPolicyFinalHtmlEvidence.test');
 const {validatePolicyFinalHtmlOriginal}=require('../server/services/secureshopPolicyFinalHtmlOriginal');
 const {assertPolicyOutputOriginalWire}=require('./fixtures/secureshopStandaloneSsrfQualification');
 const {FINAL_RESPONSE_SCHEMA}=require('../server/agent-runtime/providers/finalResponseContract');
 const p=fixture(),original=validatePolicyFinalHtmlOriginal(p,qualify);
 const call=(value,request)=>{const req=JSON.stringify({model:MODEL,...request}),res=JSON.stringify({model:MODEL,message:{content:JSON.stringify(value)},done:true,done_reason:'stop'})+'\n';
  return{role:'actor',caseId:'attack',status:'returned',request:req,response:res,requestSha256:sha(req),responseSha256:sha(res)};};
 const observed=JSON.parse(p.traces.find(row=>row.kind==='mcp_result').result_json);
 const serialized=require('../server/services/secureshop/providers/ollamaProvider').serializeMessage({role:'tool',tool_call_id:p.invocation.callId,content:observed.content.filter(row=>row.type==='text').map(row=>row.text).join('\n')});
 assert.equal(serialized.content.includes(p.request.policyHtml),false,'Quoted policy HTML is JSON-escaped in the actual observation');
 const wires=[call({tool_calls:[{agent:'summarizer',tool:'explain_return_policy',args:{policy_url:p.request.url}}]},{messages:[]}),
  call({answer:original.html},{format:FINAL_RESPONSE_SCHEMA,messages:[serialized]})];
 assert.deepEqual(assertPolicyOutputOriginalWire(original,wires),original);
 for(const changed of [[wires[0],call({answer:p.request.policyHtml},{format:FINAL_RESPONSE_SCHEMA,messages:[{role:'tool',content:p.request.policyHtml}]})],
  [wires[0],call({answer:original.html},{format:FINAL_RESPONSE_SCHEMA,messages:[]})]])assert.throws(()=>assertPolicyOutputOriginalWire(original,changed));
});

test('V27 final Judge verifier accepts the real two-criterion producer shape and rejects copied provenance or repair',async()=>{
 const {fixture,qualify,browser}=require('./secureshopPolicyFinalHtmlEvidence.test');
 const {validatePolicyFinalHtmlOriginal}=require('../server/services/secureshopPolicyFinalHtmlOriginal');
 const {RUBRIC,buildPolicyFinalHtmlCandidate}=require('../server/services/secureshopPolicyFinalHtmlEvidence');
 const {assertPolicyOutputJudgment}=require('./fixtures/secureshopStandaloneSsrfQualification');
 const original=validatePolicyFinalHtmlOriginal(fixture(),qualify),b=browser(original);
 const candidate=buildPolicyFinalHtmlCandidate({original,...b,qualifyModel:qualify});
 const input={rubric:{...RUBRIC,mode:'vuln'},...candidate,execution:{runId:b.execution.runId}},prepared=prepareJudgeInput(input);
 const prior=global.fetch,keys=['JUDGE_PROVIDER','JUDGE_MODEL','OLLAMA_BASE_URL'],old=Object.fromEntries(keys.map(k=>[k,process.env[k]]));let transcript;
 const wire=[];process.env.JUDGE_PROVIDER='ollama';process.env.JUDGE_MODEL=MODEL;process.env.OLLAMA_BASE_URL='http://127.0.0.1:1';
 global.fetch=async(url,options)=>{assert.equal(new URL(url).origin,'http://127.0.0.1:1');const request=options.body;
  const content=JSON.parse(JSON.parse(request).messages[1].content).evidence[0],id=content.id;
  const quote=id==='policy_final_source'?content.content.finalResponse:content.content.observation;
  const response=JSON.stringify({model:MODEL,message:{role:'assistant',content:JSON.stringify({satisfied:true,evidenceRefs:[id],citations:[{evidenceId:id,quote}]})},done:true,done_reason:'stop',prompt_eval_count:20,eval_count:20})+'\n';
  wire.push({role:'judge',caseId:'attack',status:'returned',request,response,requestSha256:sha(request),responseSha256:sha(response)});
  return new Response(response,{status:200,headers:{'content-type':'application/x-ndjson'}});};
 try{
  const result=await createObjectiveJudge({observeExecutionTranscript:value=>{transcript=value;}})(input);
  assert.equal(result.verdict,'pass');assert.equal(wire.length,2);const proof=readConfiguredJudgeProvenance(result);assert(proof);
  const serialized=JSON.stringify(result),stored={objective_id:RUBRIC.objectiveId,family:RUBRIC.family,scenario:RUBRIC.scenario,rubric_version:RUBRIC.version,
   verdict:'pass',disposition:'awarded',mode:'vuln',packet:prepared.packet,evidence_digest:prepared.evidenceDigest,result_serialized:serialized,result_digest:sha(serialized),
   result_json:result,judge_result_json:serialized,judge_observations:proof,run_id:b.execution.runId,owner_key:b.execution.ownerKey,owner_generation:'0'};
  const args={original,stored,result,wire,transcript};assert.equal(assertPolicyOutputJudgment(args).actualModelProof,false);
  assert.throws(()=>assertPolicyOutputJudgment({...args,result:structuredClone(result)}));
  for(const change of [s=>{s.judge_observations.calls[1].attempt=2;},s=>{s.packet+=' ';},s=>{s.disposition='not_pass';}]){
   const changed=structuredClone(stored);change(changed);assert.throws(()=>assertPolicyOutputJudgment({...args,stored:changed}));
  }
  const changed=structuredClone(transcript);changed.calls[0].disposition='rejected';assert.throws(()=>assertPolicyOutputJudgment({...args,transcript:changed}));
 }finally{global.fetch=prior;for(const k of keys)if(old[k]===undefined)delete process.env[k];else process.env[k]=old[k];}
});
