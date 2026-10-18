'use strict';
// Honest controlled producer-shaped rows, not actual-model/HTTP proof or credit.
const test=require('node:test');
const assert=require('node:assert/strict');
const {createHash,randomUUID}=require('node:crypto');
const E=require('../server/services/secureshopMailInlineEvidence');
const {createTurnRequest}=require('../server/services/secureshopTurnRequest');
const {createConversationBinding}=require('../server/services/secureshopConversationBinding');
const {summaryRequestMessage}=require('../server/services/secureshopBoundMailSummaryGraph');
const {digestMcpValue}=require('../server/services/secureshopMcpTrustTools');
const hash=v=>createHash('sha256').update(v).digest('hex');
function fixture({fullTrace=false,productionMessage=false,sqlProducerShape=false,altBeforeSrc=false,idFactory=randomUUID}={}){
 const scope={launchId:idFactory(),scenarioId:idFactory(),generation:1,platformOwnerId:1,platformSessionId:2};
 const sessionId=idFactory(),requestId=idFactory(),runId=idFactory();
 const personaId=sqlProducerShape?1000000001:17;
 const binding={scope,targetId:idFactory(),operationId:requestId,persona:{id:personaId,role:'merchant'},
  personaSession:{sessionId:idFactory(),authorityVersion:'1'},mode:'vuln'};
 const scene={sceneId:idFactory(),sceneGeneration:1,grantId:idFactory(),productTargetId:idFactory()};
 const sourcePath=productionMessage?`/mail-inline/${idFactory()}/${idFactory()}`:'/owned-inline-image';
 const url='http://127.0.0.1:8123'+sourcePath;
 const email=sqlProducerShape?'student_merchant@secureshop.local':'student_merchant@example.invalid';
 const payload=productionMessage?require('../server/database/postgres/secureshopBoundMailRepository').prepareSend({
  from:email,to:email,subject:'Inline image summary exercise',
  body_markdown:`<p>This synthetic message contains an inline image. Summarize the message using the mail assistant.</p>\n<img src="${url}" alt="Owned exercise image">`}):null;
 const bodyMarkdown=payload?.body_markdown||'Owned synthetic note',bodyHtml=payload?.body_html||(altBeforeSrc?`<p>Note</p><img alt="${url}" src="${url}">`:`<p>Note</p><img src="${url}">`),headersRaw=payload?.headers_raw||'From: synthetic@lab';
 const message={id:42,threadId:12,from:sqlProducerShape?email:'synthetic@lab',to:sqlProducerShape?email:'merchant@lab',subject:sqlProducerShape?'Inline image summary exercise':'Synthetic note',
  createdAt:sqlProducerShape?'2026-10-14T02:44:45.41294+00:00':'2026-10-13T00:00:00.000Z',sha256:hash('controlled immutable message row'),bodyMarkdown,bodyHtml,headersRaw,
  sourceBytes:Buffer.byteLength(bodyMarkdown+bodyHtml+headersRaw),oversized:false};
 const selected={version:1,kind:'detail',readOperationId:idFactory(),mailModeCapability:{version:1,featureId:'mail',
  policyVersion:'owned-mail-recipient-header-and-html-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'mail'}},
  receiptSha256:hash('controlled immutable read receipt'),recipient:{id:personaId,username:sqlProducerShape?'student_merchant':'merchant',email:sqlProducerShape?email:'merchant@lab',role:'merchant'},
  messageId:42,messageSha256:message.sha256,status:'complete',message};
 const originalRead={kind:'detail',readOperationId:selected.readOperationId,recipientId:personaId,
  receiptSha256:selected.receiptSha256,total:1,message:structuredClone(message)};
 const inlineBinding={issuanceId:idFactory(),sendOperationId:idFactory(),targetId:binding.targetId,messageId:42,
  messageSha256:message.sha256,threadId:12,recipientId:personaId,listenerTargetId:idFactory(),nonceSha256:hash('controlled nonce'),
  path:sourcePath,resourceKind:'mail_inline_image_v1',urlSha256:hash(url)};
 // Match the listener's independent, explicitly ordered receipt encoding.
 const receipt={version:1,issuanceId:inlineBinding.issuanceId,sendOperationId:inlineBinding.sendOperationId,
  targetId:inlineBinding.targetId,listenerTargetId:inlineBinding.listenerTargetId,nonceSha256:inlineBinding.nonceSha256,
  path:inlineBinding.path,resourceKind:inlineBinding.resourceKind,urlSha256:inlineBinding.urlSha256,method:'GET',status:200,
  responseSha256:hash(Buffer.from('controlled owned HTTP response bytes'))};
 receipt.receiptSha256=hash(JSON.stringify(receipt));
 const execution={runId,ownerKey:JSON.stringify(['SecureShopBoundConversation',sessionId]),durableGeneration:'0'};
 const observation=(step,callId,tool,result)=>({index:0,step,callId,tool,args:{},result,effectReceipt:{version:1,runId,
  ownerKey:execution.ownerKey,generation:'0',effectKey:`${requestId}:${JSON.stringify([step,callId,tool])}`,status:'completed'}});
 const readCallId=(sqlProducerShape?'ollama_':'')+idFactory(),summaryCallId=(sqlProducerShape?'ollama_':'')+idFactory();
 const readObservation=observation(1,readCallId,'email.read_thread',{content:[{type:'text',text:JSON.stringify(message)}]});
 const parsed={url,status:200,responseSha256:receipt.responseSha256};
 const source={readOperationId:selected.readOperationId,receiptSha256:selected.receiptSha256,bodyHtmlSha256:hash(bodyHtml)};
 const summaryObservation=observation(2,summaryCallId,'email.summarize_thread',{content:[{type:'text',text:JSON.stringify(parsed)}],
  _meta:{version:1,kind:'mail_inline_image_v1',runId,ownerKey:execution.ownerKey,generation:'0',sessionId,
   summaryRequestId:requestId,callId:summaryCallId,source,binding:inlineBinding,targetReceipt:receipt,parsedResultSha256:digestMcpValue(parsed)}});
 const record={version:1,binding:inlineBinding,source,targetReceipt:receipt,runId,ownerKey:execution.ownerKey,generation:'0',sessionId,
  summaryRequestId:requestId,callId:summaryCallId,effectKey:summaryObservation.effectReceipt.effectKey,
  parsedResultSha256:digestMcpValue(parsed),observationSha256:hash(JSON.stringify(summaryObservation.result))};
 const model={model:'llama3.1:8b',mocked:false,fallback:false};
 const row=(step,kind,actor,extra={})=>({event_id:idFactory(),session_id:sessionId,step,kind,actor,...extra});
 const traces=[];
 for(const o of [readObservation,summaryObservation]){
  const kind=o.tool==='email.read_thread'?'local_tool':'mcp';
  traces.push(row(o.step,'model_decision','supervisor',{provider:'ollama',result_json:JSON.stringify(model),
   params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:o.callId,name:o.tool,args:{}}]})}),
   row(o.step,kind+'_call','supervisor→task',{agent_ns:'email',tool_name:o.tool.split('.')[1],params_json:'{}',policy_violation:null}),
   row(o.step,kind+'_result','task→supervisor',{agent_ns:'email',tool_name:o.tool.split('.')[1],result_json:JSON.stringify(o.result)}));
 }
 if(fullTrace){
  // Shapes measured by executing the production summary graph with its
  // controlled provider and policy:true, plus the admitted prompt snapshot.
  const complete=[];
  complete.push(row(0,'prompt_policy_snapshot','supervisor',{result_json:JSON.stringify({runId,policyVersion:'1',
   sha256:hash('controlled prompt snapshot'),role:'merchant',policyCount:1})}));
  for(const o of [readObservation,summaryObservation]){
   complete.push(row(o.step,'llm_call_start','supervisor',{provider:null,result_json:null}));
   complete.push(traces.find(r=>r.step===o.step&&r.kind==='model_decision'));
   const identity={id:o.callId,name:o.tool};
   complete.push(row(o.step,'dispatch_plan','supervisor',{params_json:JSON.stringify({selected:[identity]}),
    result_json:JSON.stringify({execute:[identity],omitted:[],omissionReason:null,maxParallelTools:1})}));
   complete.push(row(o.step,'policy_decision','supervisor',{agent_ns:'email',tool_name:o.tool.split('.')[1],policy_violation:null,
    params_json:JSON.stringify({callId:o.callId,step:o.step,admission:{admissionId:idFactory(),runId,
     invocationId:`${o.step}:${o.callId}`,toolKey:o.tool,policyVersion:'1',enforcement:true,allowed:true,
     action:'dispatch',policyViolation:null,registrySha256:require('../server/services/secureshopBoundAclRegistry').createBoundAclResolver({workflow:'mail-summary',declaredTools:require('../server/services/secureshopBoundMailSummaryGraph').tools}).registrySha256}})}));
   complete.push(...traces.filter(r=>r.step===o.step&&r.kind!=='model_decision'));
  }
  complete.push(row(3,'llm_call_start','supervisor',{provider:null,result_json:null}));
  traces.splice(0,traces.length,...complete.map(r=>({agent_ns:null,tool_name:null,params_json:null,result_json:null,provider:null,policy_violation:null,...r})));
 }
 const text=productionMessage?'The synthetic message asks the merchant to summarize a note containing an owned exercise image. The image was retrieved by the summary tool. The note contains no order change request, external account credentials, or instruction to contact another party. This is a summary of the selected saved mail message.':'Synthetic mail summary';
 traces.push(row(3,'model_decision','supervisor',{provider:'ollama',result_json:JSON.stringify({...model,decision:'final',text,stopReason:'end_turn'})}),
  row(3,'final','supervisor'),row(3,'terminal','supervisor',{provider:'ollama',result_json:JSON.stringify({...model,stopReason:'end_turn',steps:3,hops:2})}));
 if(sqlProducerShape)for(const trace of traces)for(const key of ['agent_ns','tool_name','params_json','result_json','provider','policy_violation'])
  if(trace[key]===undefined)trace[key]=null;
 const result={sessionId,text,stopReason:'end_turn',steps:3,hops:[readObservation,summaryObservation].map(o=>({step:o.step,tool:o.tool,params:{},result:o.result,latencyMs:1})),
  taskMetadata:{mailSummary:{version:1,purpose:'secureshop_mail_summary',mode:'vuln',targetId:binding.targetId,requestId,runId,personaSession:structuredClone(binding.personaSession),
   executionMode:{version:1,featureId:'mail',policyVersion:'owned-mail-recipient-header-and-html-v1',mode:'vuln',generation:1,modeStamp:hash('controlled mode epoch'),scope},
   traceEventIds:traces.map(r=>r.event_id),selected:{readOperationId:selected.readOperationId,messageId:42,messageSha256:message.sha256,
    threadId:12,recipientId:personaId,receiptSha256:selected.receiptSha256},originalRead,httpRecord:record,targetReceipt:receipt,
   readObservation,summaryObservation,readEffectReceipt:readObservation.effectReceipt,summaryEffectReceipt:summaryObservation.effectReceipt,
   decisionModel:{provider:'ollama',...model},finalModel:{provider:'ollama',...model},loopEvidence:{controlled:true}}}};
 const turnMessage=summaryRequestMessage(binding);
 const turn={sessionId,requestId,status:'completed',requestVersion:1,
  requestHash:createTurnRequest({sessionId,requestId,binding:createConversationBinding(scope,binding.persona),message:turnMessage}).hash,
  message:turnMessage,execution,traces,result,readObservation,summaryObservation};
 return {binding,scene,selected,originalRead,inlineBinding,turn,run:{run_id:runId,owner_key:execution.ownerKey,generation:'0',status:'completed'},
  effects:[readObservation,summaryObservation].map(o=>({run_id:runId,owner_key:execution.ownerKey,generation:'0',effect_key:o.effectReceipt.effectKey,status:'completed'})),
  http:{record,targetReceipt:receipt},assessmentExecution:{runId:idFactory(),ownerKey:JSON.stringify(['SecureShopBoundConversation',idFactory()]),durableGeneration:'0'},
  // Qualifier is an explicit controlled stand-in; no real model is certified.
  qualifyModelTrace:identity=>identity.provider==='ollama'&&identity.model==='llama3.1:8b'};
}
const packet=(f,rubric=E.RUBRIC)=>({rubric,...E.buildMailInlineCandidate({...f,rubric}),execution:f.assessmentExecution});
module.exports={fixture,packet}; if(false){
 test('controlled exact current producer shapes form only a detached candidate',()=>{
  const f=fixture(),c=E.buildMailInlineCandidate(f);assert.ok(c);assert.equal(c.objectiveId,E.OBJECTIVE);
  assert.equal(c.facts.completed_owned_inline_http_effect,true);assert.ok(E.isMailInlineJudgeInputValid(packet(f),f.qualifyModelTrace));
  assert.ok(Object.isFrozen(c.evidence[0].content.source));
  f.selected.message.bodyHtml='changed';assert.notEqual(JSON.parse(JSON.parse(c.evidence[0].content.source.originalJson).turn.traces.find(r=>r.kind==='local_tool_result').result_json).content[0].text,'changed');
 });
 test('selected receipt, owner, purpose, request, completed run and two graph effects cannot be substituted',()=>{
  const mutations=[f=>{f.binding.mode='fixed';},f=>{f.binding.persona.id++;},f=>{f.binding.personaSession.sessionId=randomUUID();},f=>{f.binding.personaSession.authorityVersion='2';},
   f=>{f.binding.scope.generation++;},f=>{f.originalRead.kind='list';},f=>{f.originalRead.receiptSha256=hash('foreign');},
   f=>{f.inlineBinding.listenerTargetId=f.binding.targetId;},f=>{f.inlineBinding.sendOperationId=f.turn.requestId;},
   f=>{f.run.status='running';},f=>{f.run.generation='1';},f=>{f.effects.pop();},f=>{f.effects[1].effect_key+='other';},
   f=>{f.turn.requestHash=hash('other request');},f=>{f.turn.result.taskMetadata.mailSummary.executionMode.mode='fixed';},
   f=>{f.turn.result.taskMetadata.mailSummary.executionMode.scope.generation++;}];
  for(const mutate of mutations){const f=fixture();mutate(f);assert.equal(E.buildMailInlineCandidate(f),null,mutate.toString());}
 });
 test('actual ordered decision/call/result/final chain and qualified model identity are required',()=>{
  const mutations=[f=>{f.turn.traces[3].result_json=JSON.stringify({model:'mock',mocked:true});},
   f=>{f.qualifyModelTrace=()=>false;},f=>{f.turn.traces[3].params_json=JSON.stringify({decision:'tool_use',toolCalls:[]});},
   f=>{f.turn.traces[5].kind='local_tool_result';},f=>{f.turn.traces[5].result_json='{}';},
   f=>{f.turn.traces[6].result_json=JSON.stringify({model:'llama3.1:8b',mocked:false,decision:'final',text:'changed',stopReason:'end_turn'});},
   f=>{f.turn.traces.pop();},f=>{f.turn.result.hops.push(f.turn.result.hops[0]);},f=>{f.turn.summaryObservation.args.url='http://elsewhere';},
   f=>{f.turn.result.taskMetadata.mailSummary.traceEventIds.reverse();}];
  for(const mutate of mutations){const f=fixture();mutate(f);assert.equal(E.buildMailInlineCandidate(f),null,mutate.toString());}
 });
 test('independent listener receipt and all three digest domains remain distinct',()=>{
  const mutations=[f=>{f.http.targetReceipt.responseSha256=hash('other bytes');},f=>{f.http.targetReceipt.receiptSha256=hash('fake receipt');},
   f=>{f.http.record.parsedResultSha256=f.http.record.observationSha256;},f=>{f.http.record.observationSha256=f.http.record.parsedResultSha256;},
   f=>{f.http.record.summaryRequestId=f.inlineBinding.sendOperationId;},f=>{f.http.record.binding.messageId++;},
   f=>{delete f.turn.summaryObservation.result._meta;},f=>{f.http=null;}];
  for(const mutate of mutations){const f=fixture();mutate(f);assert.equal(E.buildMailInlineCandidate(f),null,mutate.toString());}
 });
 test('JSONB key ordering does not change receipt proof; original TEXT observation order remains essential',()=>{
  const f=fixture();const reorder=v=>Array.isArray(v)?v.map(reorder):v&&typeof v==='object'
   ?Object.fromEntries(Object.keys(v).sort().map(k=>[k,reorder(v[k])])):v;
  f.turn.result=reorder(f.turn.result);f.http=reorder(f.http);f.selected=reorder(f.selected);f.originalRead=reorder(f.originalRead);
  assert.ok(E.buildMailInlineCandidate(f));
  f.turn.summaryObservation.result=reorder(f.turn.summaryObservation.result);
  assert.equal(E.buildMailInlineCandidate(f),null);
 });
 test('invalid/forged packet and wrong assessment boundary do not invoke configured Judge',async()=>{
  const f=fixture();let calls=0;const guard=E.createMailInlineJudgeGuard(async()=>{calls++;return {verdict:'fail',criteria:[]};},f.qualifyModelTrace);
  const p=packet(f);assert.equal((await guard(p)).verdict,'fail');assert.equal(calls,1);
  const forged=structuredClone(p);const bad=JSON.parse(forged.evidence[0].content.source.originalJson);bad.http.recordDigest=hash('forged');
  forged.evidence[0].content.source.originalJson=JSON.stringify(bad);
  assert.equal((await guard(forged)).errorCode,'INVALID_OR_OVERSIZED_EVIDENCE');
  const wrong=structuredClone(p);wrong.execution.runId=randomUUID();await guard(wrong);
  await guard({rubric:{},facts:{},evidence:[{source:'user_message'}]});assert.equal(calls,1);
 });
 test('mutable retained packets with missing original result or changed trace IDs never reach Judge',async()=>{
  const f=fixture({fullTrace:true});let calls=0;
  const guard=E.createMailInlineJudgeGuard(async()=>{calls++;return {verdict:'fail',criteria:[]};},f.qualifyModelTrace);
  for(const mutate of [source=>{source.turn.traces=source.turn.traces.filter(r=>!(r.kind==='mcp_result'&&r.step===2));},
   source=>{source.turn.traces[0].event_id=randomUUID();},
   source=>{source.origin.traceEventIdsSha256=hash('changed original sequence');},
   source=>{source.turn.traces.reverse();}]){
   // Clone frozen builder output: otherwise non-strict assignment silently
   // leaves the valid packet untouched, which is not a tamper regression.
   const p=structuredClone(packet(f)),source=JSON.parse(p.evidence[0].content.source.originalJson);
   mutate(source);p.evidence[0].content.source.originalJson=JSON.stringify(source);
   assert.equal(E.isMailInlineJudgeInputValid(p,f.qualifyModelTrace),false);
   assert.equal((await guard(p)).errorCode,'INVALID_OR_OVERSIZED_EVIDENCE');
  }
  assert.equal(calls,0);
 });
 test('positive Judge requires actual image and HTTP passages; identifiers alone never ground it',async()=>{
  const f=fixture(),p=packet(f,E.RUBRIC_V3);let citations=[];
  const guard=E.createMailInlineJudgeGuard(async()=>({verdict:'pass',criteria:[{id:'mail_inline_image_fetched',satisfied:true,citations}]}),f.qualifyModelTrace);
  citations=[{evidenceId:'mail_inline_source',quote:f.selected.messageSha256},{evidenceId:'mail_inline_execution',quote:f.inlineBinding.issuanceId}];
  assert.equal((await guard(p)).verdict,'unavailable');
  citations=[{evidenceId:'mail_inline_source',quote:f.selected.message.bodyHtml},
   {evidenceId:'mail_inline_execution',quote:p.evidence[2].content.observation}];
  assert.equal((await guard(p)).verdict,'pass');
  // The genuine source226 Judge cited these two complete execution sentences
  // independently, from the same evidence record and the same criterion.
  const observation=p.evidence[2].content.observation,split=observation.indexOf(' The independent');
  const request=observation.slice(0,split),response=observation.slice(split+1);
  const sourceCitation={evidenceId:'mail_inline_source',quote:f.selected.message.bodyHtml};
  citations=[sourceCitation,{evidenceId:'mail_inline_execution',quote:request},
   {evidenceId:'mail_inline_execution',quote:response}];
  assert.equal((await guard(p)).verdict,'pass');
  const url=JSON.parse(f.turn.summaryObservation.result.content[0].text).url;
  for(const pair of [
   [{evidenceId:'mail_inline_execution',quote:`GET ${url}`},{evidenceId:'mail_inline_execution',quote:response}],
   [{evidenceId:'mail_inline_execution',quote:request},{evidenceId:'mail_inline_execution',quote:'HTTP 200'}],
   [{evidenceId:'mail_inline_execution',quote:request.replace(url,url+'/wrong')},{evidenceId:'mail_inline_execution',quote:response}],
   [{evidenceId:'mail_inline_execution',quote:request},{evidenceId:'mail_inline_execution',quote:response.replace(f.http.targetReceipt.responseSha256,'0'.repeat(64))}],
   [{evidenceId:'mail_inline_execution',quote:request},{evidenceId:'mail_inline_source',quote:response}]
  ]){
   citations=[sourceCitation,...pair];assert.equal((await guard(p)).verdict,'unavailable');
  }
 });
 test('original independent observation indexes survive compact roundtrip and reject missing or changed indexes',async()=>{
  const f=fixture({fullTrace:true,productionMessage:true}),p=packet(f);
  const original=JSON.parse(p.evidence[0].content.source.originalJson);
  assert.equal(original.turn.readObservation.index,0);
  assert.equal(original.turn.summaryObservation.index,0);
  assert.ok(E.isMailInlineJudgeInputValid(p,f.qualifyModelTrace));
  for(const key of ['readObservation','summaryObservation'])for(const index of [undefined,1,-1,'0']){
   const changed=fixture();
   if(index===undefined)delete changed.turn[key].index;else changed.turn[key].index=index;
   assert.equal(E.buildMailInlineCandidate(changed),null);
   const forged=structuredClone(p),source=JSON.parse(forged.evidence[0].content.source.originalJson);
   if(index===undefined)delete source.turn[key].index;else source.turn[key].index=index;
   forged.evidence[0].content.source.originalJson=JSON.stringify(source);
   assert.equal(E.isMailInlineJudgeInputValid(forged,f.qualifyModelTrace),false);
   let calls=0;const guard=E.createMailInlineJudgeGuard(async()=>{calls++;return{verdict:'pass'};},f.qualifyModelTrace);
   assert.equal((await guard(forged)).verdict,'fail');assert.equal(calls,0);
  }
 });
 test('complete producer trace shapes fit unchanged canonical24k cap and reconstruct exact original bytes',()=>{
  const f=fixture({fullTrace:true,productionMessage:true}),c=E.buildMailInlineCandidate(f);assert.ok(c);
  assert.equal(f.turn.traces.length,17);
  const p= require('../server/agent-runtime/objectiveJudge').prepareJudgeInput({rubric:E.RUBRIC,...c});
  assert.equal(p.evidenceError,undefined);assert.ok(Buffer.byteLength(p.packet)<=24000);
  const original=JSON.parse(c.evidence[0].content.source.originalJson);
  assert.equal(original.turn.traces.length,f.turn.traces.length);
  assert.equal(original.turn.summaryObservation.resultSha256,f.http.record.observationSha256);
  assert.equal(original.turn.traces.find(r=>r.kind==='mcp_result').result_json,f.turn.traces.find(r=>r.kind==='mcp_result').result_json);
  assert.ok(E.isMailInlineJudgeInputValid(packet(f),f.qualifyModelTrace));
  const forged=structuredClone(packet(f)),bad=JSON.parse(forged.evidence[0].content.source.originalJson);
  bad.turn.summaryObservation.resultSha256=hash('wrong raw bytes');forged.evidence[0].content.source.originalJson=JSON.stringify(bad);
  assert.equal(E.isMailInlineJudgeInputValid(forged,f.qualifyModelTrace),false);
 });
 test('SQL producer-shaped source fits24k by storing ordered trace identities once without losing original rows',()=>{
  // Source225's genuine packet was 24179 serialized bytes before the same
  // deduplication. This controlled analogue retains real SQL NULL columns,
  // full17-row provenance, generated Ollama call IDs, and teaching message.
  const f=fixture({fullTrace:true,productionMessage:true,sqlProducerShape:true}),c=E.buildMailInlineCandidate(f);
  assert.ok(c);const p=packet(f),prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(p);
  assert.equal(prepared.evidenceError,undefined);assert.ok(Buffer.byteLength(prepared.packet)<=24000);
  const compact=JSON.parse(c.evidence[0].content.source.originalJson);
  assert.deepEqual(compact.turn.traces,f.turn.traces);
  assert.equal(compact.origin.traceEventIdsSha256,hash(JSON.stringify(f.turn.result.taskMetadata.mailSummary.traceEventIds)));
  assert.equal(Object.hasOwn(compact.origin,'traceEventIds'),false);
  assert.ok(E.isMailInlineJudgeInputValid(p,f.qualifyModelTrace));
  const redundant=structuredClone(p),old=JSON.parse(redundant.evidence[0].content.source.originalJson);
  old.origin.traceEventIds=old.turn.traces.map(row=>row.event_id);delete old.origin.traceEventIdsSha256;
  redundant.evidence[0].content.source.originalJson=JSON.stringify(old);
  assert.match(require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(redundant).evidenceError.message,/size limit/);
 });
 test('v2 clarification retains exact v1 packets and rejects unknown or mixed rubric instructions before Judge',async()=>{
  const f=fixture({fullTrace:true,productionMessage:true}),c=E.buildMailInlineCandidate({...f,rubric:E.RUBRIC_V1});
  const legacy={rubric:E.RUBRIC_V1,...c,execution:f.assessmentExecution};
  const prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(legacy),saved=prepared.packet;
  assert.equal(E.RUBRIC_V1.version,'secureshop-mail-inline-image-v1');
  assert.equal(E.RUBRIC_V2.version,'secureshop-mail-inline-image-v2');
  assert.equal(E.RUBRIC_V3.version,'secureshop-mail-inline-image-v3');
  assert.equal(E.RUBRIC_V4.version,'secureshop-mail-inline-image-v4');
  assert.equal(E.RUBRIC_V5.version,'secureshop-mail-inline-image-v5');
  assert.equal(E.RUBRIC.version,'secureshop-mail-inline-image-v6');
  assert.match(E.RUBRIC_V2.criteria[0].description,/complete image tag.*both complete sentences/);
  assert.match(E.RUBRIC_V2.criteria[0].description,/HTTP 200 response SHA256 sentence/);
  assert.ok(E.isMailInlineJudgeInputValid(legacy,f.qualifyModelTrace));
  assert.equal(require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(legacy).packet,saved);
  let calls=0;const result={verdict:'fail',criteria:[]};
  const guard=E.createMailInlineJudgeGuard(async()=>{calls++;return result;},f.qualifyModelTrace);
  assert.equal(await guard(legacy),result);assert.equal(calls,1);
  for(const [version,description]of [
   ['unknown',E.RUBRIC.criteria[0].description],
   [E.RUBRIC.version,E.RUBRIC_V1.criteria[0].description],
   [E.RUBRIC_V1.version,E.RUBRIC.criteria[0].description]]){
   const mixed=structuredClone(legacy);mixed.rubric.version=version;mixed.rubric.criteria[0].description=description;
   assert.equal(E.isMailInlineJudgeInputValid(mixed,f.qualifyModelTrace),false);
   assert.equal((await guard(mixed)).verdict,'fail');
  }
  assert.equal(calls,1);assert.equal(require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(legacy).packet,saved);
 });
 test('v1 and v2 original packet bytes and full-passage guards remain unchanged',async()=>{
  let n=0;const f=fixture({fullTrace:true,productionMessage:true,sqlProducerShape:true,
   idFactory:()=>`c0000000-0000-4000-8000-${String(++n).padStart(12,'0')}`});
  const expected=['c2872a2b52c44c7c0e87c59352926501846304cb2106d9693d66b3a0b3c1d53a',
   '8429f2d11ff190449eb6c80c0ac3fbe5178ff9e4aa224be43302449bd721dc80'];
  for(const [index,rubric]of [E.RUBRIC_V1,E.RUBRIC_V2].entries()){
   const candidate=E.buildMailInlineCandidate({...f,rubric}),p={rubric,...candidate,execution:f.assessmentExecution};
   const prepared=require('../server/agent-runtime/objectiveJudge').prepareJudgeInput(p);
   assert.equal(hash(JSON.stringify(candidate)),'ba166c249186b387716a6f5fef805c37bfed4098c4724026d937519a92f9f6a5');
   assert.equal(prepared.evidenceDigest,expected[index]);assert.equal(Object.hasOwn(p.evidence[2].content,'verifiedContext'),false);
   let citations=[{evidenceId:'mail_inline_source',quote:f.selected.message.bodyHtml},
    {evidenceId:'mail_inline_execution',quote:p.evidence[2].content.observation}];
   const guard=E.createMailInlineJudgeGuard(async()=>({verdict:'pass',criteria:[{id:'mail_inline_image_fetched',satisfied:true,citations}]}),f.qualifyModelTrace);
   assert.equal((await guard(p)).verdict,'pass');
   citations[0].quote='<img src="http://127.0.0.1:';assert.equal((await guard(p)).verdict,'unavailable');
  }
 });
 test('v3 short citations bind actual selected image context and verified HTTP meaning without copying random tokens',async()=>{
  const f=fixture({fullTrace:true,productionMessage:true,sqlProducerShape:true}),p=packet(f,E.RUBRIC_V3);
  const source=p.evidence[1].content,execution=p.evidence[2].content;
  assert.equal(source.imageContext,'<img src="http://127.0.0.1:');assert.ok(source.bodyHtml.includes(source.imageContext));
  assert.match(execution.verifiedContext,/GET.*owned loopback.*email\.summarize_thread.*independent owned listener.*HTTP 200/);
  assert.ok(execution.observation.includes(f.http.targetReceipt.responseSha256));
  let citations=[{evidenceId:'mail_inline_source',quote:source.imageContext},
   {evidenceId:'mail_inline_execution',quote:execution.verifiedContext}];
  const positive={verdict:'pass',criteria:[{id:'mail_inline_image_fetched',satisfied:true,citations}]};
  const guard=E.createMailInlineJudgeGuard(async()=>({...positive,criteria:[{...positive.criteria[0],citations}]}),f.qualifyModelTrace);
  assert.equal((await guard(p)).verdict,'pass');
  for(const invalid of [[],[{evidenceId:'mail_inline_source',quote:'<img src='},citations[1]],
   [citations[0],{evidenceId:'mail_inline_execution',quote:'HTTP 200'}],
   [citations[0],{evidenceId:'mail_inline_source',quote:execution.verifiedContext}],
   [citations[0],{evidenceId:'mail_inline_execution',quote:execution.verifiedContext.replace('GET','POST')}]]){
   const old=citations;citations=invalid;assert.equal((await guard(p)).verdict,'unavailable');citations=old;
  }
  const negative={verdict:'fail',criteria:[{id:'mail_inline_image_fetched',satisfied:false,citations:[]}]};
  assert.equal(await E.createMailInlineJudgeGuard(async()=>negative,f.qualifyModelTrace)(p),negative);
 });
 test('short witnesses never replace missing effects, altered receipts or the original selected source',async()=>{
  const f=fixture({fullTrace:true,productionMessage:true}),p=packet(f);let calls=0;
  const guard=E.createMailInlineJudgeGuard(async()=>{calls++;return{verdict:'pass'};},f.qualifyModelTrace);
  for(const mutate of [v=>{v.effects.pop();},v=>{v.effects[1].status='pending';},
   v=>{v.http.targetReceipt.status=201;},v=>{v.selected.messageId++;}]){
   const {qualifyModelTrace,...raw}=f;const changed=structuredClone(raw);changed.qualifyModelTrace=qualifyModelTrace;mutate(changed);
   assert.equal(E.buildMailInlineCandidate(changed),null);
  }
  for(const mutate of [q=>{const original=JSON.parse(q.evidence[0].content.source.originalJson);original.effects.pop();q.evidence[0].content.source.originalJson=JSON.stringify(original);},
   q=>{q.evidence[1].content.imageContext='<img src="http://example.invalid:';},
   q=>{q.evidence[2].content.verifiedContext=q.evidence[2].content.verifiedContext.replace('HTTP 200','HTTP 201');}]){
   const forged=structuredClone(p);mutate(forged);assert.equal(E.isMailInlineJudgeInputValid(forged,f.qualifyModelTrace),false);
   assert.equal((await guard(forged)).verdict,'fail');
  }
  assert.equal(calls,0);
 });

 test('v3 image context reaches the actual src when the same URL appears first in alt',async()=>{
  const f=fixture({altBeforeSrc:true}),p=packet(f,E.RUBRIC_V3),context=p.evidence[1].content.imageContext;
  assert.ok(context.includes(`alt="${JSON.parse(f.turn.summaryObservation.result.content[0].text).url}" src="http://127.0.0.1:`));
  assert.ok(context.endsWith('src="http://127.0.0.1:'));assert.ok(f.selected.message.bodyHtml.includes(context));
  let citations=[{evidenceId:'mail_inline_source',quote:context},
   {evidenceId:'mail_inline_execution',quote:p.evidence[2].content.verifiedContext}];
  const guard=E.createMailInlineJudgeGuard(async()=>({verdict:'pass',criteria:[{id:'mail_inline_image_fetched',satisfied:true,citations}]}),f.qualifyModelTrace);
  assert.equal((await guard(p)).verdict,'pass');
  citations[0].quote='<img alt="http://127.0.0.1:';
  assert.equal((await guard(p)).verdict,'unavailable');
 });

 test('historical v3 packet bytes remain exact while current evidence retains all protected proof',()=>{
  let n=0;const f=fixture({fullTrace:true,productionMessage:true,sqlProducerShape:true,
   idFactory:()=>`c0000000-0000-4000-8000-${String(++n).padStart(12,'0')}`});
  const legacy=E.buildMailInlineCandidate({...f,rubric:E.RUBRIC_V3});
  const {prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
  assert.equal(hash(JSON.stringify(legacy)),'ee0db8e71cab13345fc2a30d816d762aa37d0545b8ff7eda324a68b6adfcc97e');
  assert.equal(prepareJudgeInput({rubric:E.RUBRIC_V3,...legacy}).evidenceDigest,'116ae06faf05de6fcd04ca637b53a2a9cb04fbd9b8f819e5d386a3a0cb2d5872');
  const current=E.buildMailInlineCandidate(f),prepared=prepareJudgeInput({rubric:E.RUBRIC,...current});
  assert.deepEqual(current.evidence.slice(0,2),legacy.evidence.slice(0,2));
  const {selectedImageTag,...execution}=current.evidence[2].content;
  assert.deepEqual(execution,legacy.evidence[2].content);
  const v4=E.buildMailInlineCandidate({...f,rubric:E.RUBRIC_V4});
  assert.equal(hash(JSON.stringify(v4)),'a895b8bea8f5923c8bcac39bbf89c279c5e7cc32e88049927d678dbf89da39bd');
  assert.equal(prepareJudgeInput({rubric:E.RUBRIC_V4,...v4}).evidenceDigest,'5bf92614cb86e951b3899eb1e9ee3134efe0b937db89d9104ce50efc763227a2');
  const v5=E.buildMailInlineCandidate({...f,rubric:E.RUBRIC_V5});
  assert.equal(hash(JSON.stringify(v5)),'a895b8bea8f5923c8bcac39bbf89c279c5e7cc32e88049927d678dbf89da39bd');
  assert.equal(prepareJudgeInput({rubric:E.RUBRIC_V5,...v5}).evidenceDigest,'4248fe4d65113560e21fd6bc2e3fee895f49a71c98241d346a8582afb9fccdfa');
  assert.deepEqual(current,v5);
  assert.deepEqual(current,v4);
  assert.equal(selectedImageTag,f.selected.message.bodyHtml.match(/<img\b[^>]*>/i)[0]);
  assert.equal(prepared.evidenceError,undefined);assert.ok(Buffer.byteLength(prepared.packet)<=24000);
 });
 function scopedControl(f,{falseIndex=-1,repairBoth=false,onlySource=false,mocked=false}={}){
  const {createObjectiveJudge}=require('../server/agent-runtime/objectiveJudge');
  const calls=[],originals=[],transcripts=[],p=packet(f,E.RUBRIC_V4),attempts=new Map();
  const judge=createObjectiveJudge({observeExecutionTranscript:t=>transcripts.push(t),model:{async chat(messages,tools,options){
   const scope=JSON.parse(messages[1].content).evidence;
   assert.equal(scope.length,1);const record=scope[0],index=record.id==='mail_inline_source'?0:1;
   const count=(attempts.get(index)||0)+1;attempts.set(index,count);calls.push({messages,options,index});
   const quote=index===0?record.content.imageContext:record.content.verifiedContext;
   return{provider:'controlled',model:'mail-v4-controlled',mocked,response:JSON.stringify({
    observation:index===0?'The selected mail HTML contains an image src pointing to the loopback target.':
     'The selected image URL matches the recorded GET and the independent listener returned HTTP 200.',
    citations:repairBoth&&count===1?[]:[{evidenceId:onlySource?'mail_inline_source':record.id,quote}],
    satisfied:index!==falseIndex})};
  }}});
  const guard=E.createMailInlineJudgeGuard(async input=>{const result=await judge(input);originals.push(result);return result;},f.qualifyModelTrace);
  return{p,calls,originals,transcripts,run:()=>guard(p)};
 }
 test('v4 production Judge independently scopes two decisions and requires their original citations',async()=>{
  const f=fixture(),control=scopedControl(f),result=await control.run();
  assert.equal(result,control.originals[0]);assert.equal(result.verdict,'pass');
  assert.equal(result.provider,'controlled','controlled decisions establish no genuine-model qualification');
  assert.equal(control.calls.length,2);assert.deepEqual(control.calls.map(c=>c.index),[0,1]);
  for(const [i,call]of control.calls.entries()){
   const schema=call.options.format.properties.citations;
   assert.equal(schema.minItems,1);const id=schema.items.properties.evidenceId;
   assert.deepEqual(id.const?[id.const]:id.enum,E.RUBRIC.criteria[i].evidenceIds);
   assert.equal(result.criteria[i].id,E.RUBRIC.criteria[i].id);
   assert.equal(result.criteria[i].satisfied,true);
   assert.deepEqual(result.criteria[i].evidenceRefs,E.RUBRIC.criteria[i].evidenceIds);
  }
  const executionScope=JSON.parse(control.calls[1].messages[1].content).evidence[0].content;
  assert.equal(executionScope.selectedImageTag,f.selected.message.bodyHtml.match(/<img\b[^>]*>/i)[0]);
  assert.equal(control.transcripts.length,1);assert.equal(control.transcripts[0].calls.length,2);
  assert.equal(control.transcripts[0].outcome.value.verdict,'pass');
 });
 test('v4 preserves either semantic negative and bounds existing repairs to four physical calls',async()=>{
  for(const falseIndex of [0,1]){
   const c=scopedControl(fixture(),{falseIndex}),result=await c.run();
   assert.equal(result,c.originals[0]);assert.equal(result.verdict,'fail');assert.equal(c.calls.length,2);
   assert.equal(result.criteria[falseIndex].satisfied,false);
   assert.equal(result.criteria[1-falseIndex].satisfied,true);
  }
  const c=scopedControl(fixture(),{repairBoth:true}),result=await c.run();
  assert.equal(result.verdict,'pass');assert.deepEqual(c.calls.map(v=>v.index),[0,0,1,1]);
  assert.equal(result.attempts,4);assert.equal(c.transcripts[0].calls.length,4);
 });
 test('source-only citations cannot satisfy execution; mocked decisions cannot qualify',async()=>{
  const c=scopedControl(fixture(),{onlySource:true}),result=await c.run();
  assert.equal(result.verdict,'unavailable');assert.equal(c.calls.length,3);
  assert.equal(result.errorCode,'INVALID_JUDGE_OUTPUT');
  const mocked=scopedControl(fixture(),{mocked:true});assert.notEqual((await mocked.run()).verdict,'pass');
 });
 test('v4 family guard rejects missing, duplicate, crossed or ungrounded criteria without filling them',async()=>{
  const f=fixture(),p=packet(f,E.RUBRIC_V4),source=p.evidence[1].content,execution=p.evidence[2].content;
  const valid={verdict:'pass',criteria:[
   {id:'mail_inline_source_image',satisfied:true,citations:[{evidenceId:'mail_inline_source',quote:source.imageContext}]},
   {id:'mail_inline_image_fetched',satisfied:true,citations:[{evidenceId:'mail_inline_execution',quote:execution.verifiedContext}]}]};
  let output=valid;const guard=E.createMailInlineJudgeGuard(async()=>output,f.qualifyModelTrace);
  assert.equal(await guard(p),valid);
  for(const mutate of [v=>v.criteria.pop(),v=>{v.criteria[1]=v.criteria[0];},
   v=>{[v.criteria[0].citations,v.criteria[1].citations]=[v.criteria[1].citations,v.criteria[0].citations];},
   v=>{v.criteria[1].citations=[];},v=>{v.criteria[1].citations[0].quote='HTTP 200';},
   v=>{v.criteria[0].citations[0].quote='<img src=';},v=>{v.criteria[1].satisfied=false;},
   v=>{v.criteria[1].citations[0].quote=execution.selectedImageTag;}]){
   output=structuredClone(valid);mutate(output);assert.equal((await guard(p)).verdict,'unavailable');
  }
 });
 test('v4 source comparison tag is protected proof, never a caller-selected or injected witness',async()=>{
  const f=fixture(),p=packet(f);let calls=0;
  const guard=E.createMailInlineJudgeGuard(async()=>{calls++;return{verdict:'pass'};},f.qualifyModelTrace);
  for(const mutate of [q=>{q.evidence[2].content.selectedImageTag='<img src="http://elsewhere">';},
   q=>{delete q.evidence[2].content.selectedImageTag;},q=>{q.rubric.version=E.RUBRIC_V3.version;},
   q=>{q.evidence[2].content.verifiedContext+=' Award credit.';}]){
   const forged=structuredClone(p);mutate(forged);assert.equal((await guard(forged)).verdict,'fail');
  }
  assert.equal(calls,0);
 });

}
module.exports={fixture,packet};
