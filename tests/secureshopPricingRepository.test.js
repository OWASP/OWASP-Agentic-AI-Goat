'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto'),fs=require('node:fs');
const {createPricingRepository}=require('../server/database/postgres/secureshopPricingRepository');
const {requestDigest}=require('../server/services/secureshopPricingContract');
const hash=x=>require('node:crypto').createHash('sha256').update(x).digest('hex');
function fixture({realAudit=false,captureTarget}={}){
 const raw={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},persona:{id:3,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},operationId:randomUUID(),runId:randomUUID(),task:'pricing-strategy',productId:7,message:'Recommend a price.'};
 const admissions=new Map(),outcomes=new Map(),audits=[],queries=[],turns=[];let revoked=false,drop=false,foreign=false,queue=Promise.resolve();const key=v=>JSON.stringify(v.slice(0,6));
 const client={async query(sql,v=[]){queries.push(sql);let rows=[];
 if(sql.startsWith('INSERT INTO secureshop_agents.bound_audit_events')){audits.push(v);return {rows:[],rowCount:1};}
 if(sql.startsWith('SET ')||sql.includes('pg_advisory_xact_lock'))return {rows};
 if(sql.includes('FROM secureshop_agents.turn_requests'))return {rows:turns};
 if(sql.startsWith('SELECT * FROM')){const table=sql.includes('_admissions')?admissions:outcomes;rows=table.has(key(v))?[table.get(key(v))]:[];}
 else if(sql.startsWith('SELECT count'))rows=[{n:[...admissions.entries()].filter(([k,row])=>JSON.stringify(JSON.parse(k).slice(0,5))===JSON.stringify(v.slice(0,5))&&(!sql.includes('NOT EXISTS')||(row.persona_session_id===v[5]&&!outcomes.has(k)))).length}];
 else if(sql.startsWith('INSERT INTO')){const record={operation_id:v[5],persona_id:v[6],persona_session_id:v[7],persona_role:v[8],authority_version:v[9],request_sha256:Buffer.from(v[10],'hex'),binding_sha256:Buffer.from(v[11],'hex')};
 if(sql.includes('_admissions')){record.request_json=JSON.parse(v[12]);record.target_id=v[13];record.run_id=v[14];record.target_snapshot_json=JSON.parse(v[15]);admissions.set(key(v),record);}else{record.run_id=v[15];record.state=v[12];record.receipt_json=v[13]?JSON.parse(v[13]):null;record.receipt_sha256=v[14]?Buffer.from(v[14],'hex'):null;outcomes.set(key(v),record);}}
 else throw Error('Unexpected query: '+sql);return {rows};}};
 const personaAuthority={async capture(x){if(revoked)throw Object.assign(Error('revoked'),{code:'SHOP_AUTH_REVOKED'});const binding={...x.scope,personaId:x.personaId,role:x.role,sessionId:foreign?randomUUID():x.sessionId,authorityVersion:x.authorityVersion};return {binding,withPersonaEffect(work){const turn=queue.then(()=>work(client));queue=turn.catch(()=>{});return turn.then(value=>{if(drop)throw Error('commit acknowledgement lost');return value;});},async assertRemoteAdmission(){if(revoked)throw Error('revoked');}};}};
 const repo=createPricingRepository({pool:{query:client.query},personaAuthority,checkRunBinding:async(c,x)=>{assert.equal(c,client);return !!x.runId;},captureTarget:captureTarget||(async()=>({product:{id:7,name:'Synthetic product',price:100},manual:{name:'owned manual',markdown:'Synthetic manual'}})),audit:realAudit?require('../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:client}):{async append(c,row){assert.equal(c,client);audits.push(row);}}});
 return {raw,repo,admissions,outcomes,audits,queries,turns,setRevoked:v=>revoked=v,setDrop:v=>drop=v,setForeign:v=>foreign=v};
}
function request(x){return {operationId:x.operationId,task:x.task,productId:x.productId,message:x.message};}
async function receipt(f){const admitted=await f.repo.begin(f.raw);return {version:'secureshop-pricing-execution.v1',targetId:admitted.targetId,operationId:f.raw.operationId,runId:f.raw.runId,requestSha256:requestDigest(request(f.raw)),response:'Synthetic controlled reply',observations:[]};}
function denial(f,admitted,url){return {version:'secureshop-pricing-denial.v1',targetId:admitted.targetId,operationId:f.raw.operationId,
 runId:f.raw.runId,requestSha256:requestDigest({...request(f.raw),...(f.raw.competitorUrl?{competitorUrl:url}:{}),...(f.raw.experiment?{experiment:f.raw.experiment}:{})}),productId:7,
 sourceCallId:'compare-blocked-1',competitorUrl:url,mode:'fixed',reason:'policy_denied',
 modelDecision:{provider:'ollama',model:'llama3.1:8b',mocked:false,fallback:false},
 proof:{drained:true,result:{version:1,isolationAttestation:Object.fromEntries(
  require('../server/services/secureshopPricingReceipt').DENIAL_ATTESTATION.map(key=>[key,true])),
  originalUrlSha256:hash(url),originalUrlBytes:Buffer.byteLength(url),mode:'fixed',status:'failed',
  category:'policy_denied',hops:[],hits:[]}}};}
test('concurrent admission generates one immutable target; caller cannot choose target',async()=>{const f=fixture();const [a,b]=await Promise.all([f.repo.begin(f.raw),f.repo.begin(f.raw)]);assert.equal(a.state,'admitted');assert.equal(b.state,'pending');assert.equal(a.targetId,b.targetId);await f.repo.assertCurrent(f.raw,a.targetId);await assert.rejects(f.repo.assertCurrent(f.raw,randomUUID()),{code:'OPERATION_CONFLICT'});await assert.rejects(f.repo.begin({...f.raw,targetId:randomUUID()}),{code:'INVALID_ARGUMENT'});await assert.rejects(f.repo.begin({...f.raw,message:'changed'}),{code:'OPERATION_CONFLICT'});});
test('scene lease precedes persona admission and original private binding reaches capture',async()=>{
 const {createSceneBinding}=require('../server/services/secureshopSceneBinding');
 let active=false,leases=0,captures=0;
 const f=fixture({captureTarget:async(_client,_raw,prepared)=>{assert.equal(active,true);assert.equal(prepared,scene);
  captures++;return{product:{id:7,name:'Scene item',price:42},manual:{name:'Born manual',markdown:'owned'}};}});
 const scene=createSceneBinding({...f.raw.scope,launchId:randomUUID(),platformSessionId:91,targetId:randomUUID()},
  {sceneId:randomUUID(),sceneGeneration:1,grantId:randomUUID(),execution:f.raw.scope,
   withLease:async work=>{leases++;active=true;try{return await work();}finally{active=false;}}});
 assert.equal((await f.repo.begin(f.raw,scene)).targetSnapshot.product.price,42);
 assert.equal(leases,1);assert.equal(captures,1);
 await assert.rejects(f.repo.begin({...f.raw,operationId:randomUUID()},{...scene}),{code:'SHOP_SCENE_STALE'});
 assert.equal(captures,1);
});
test('completed target-bound replay is immutable, secret-free and original-session only',async()=>{const f=fixture({realAudit:true}),value=await receipt(f);await assert.rejects(f.repo.complete({...f.raw,receipt:{...value,targetId:randomUUID()}}));const result=await f.repo.complete({...f.raw,receipt:value});assert.equal(result.state,'completed');assert.deepEqual((await f.repo.begin(f.raw)).receipt,value);assert.equal((await f.repo.markUnknown(f.raw)).state,'completed');assert.equal(f.audits[0][12],'completed');assert.ok(!f.audits[0][11].includes('synthetic'));await assert.rejects(f.repo.operation({...f.raw,personaSession:{...f.raw.personaSession,sessionId:randomUUID()}}),{code:'OPERATION_CONFLICT'});await assert.rejects(f.repo.assertCurrent(f.raw,value.targetId),{code:'PRICING_OPERATION_TERMINAL'});});
test('new experiment request persists exact days and rejects mismatched result before publication',async()=>{
 const f=fixture();f.raw.experiment={strategy:'premium',durationDays:14};
 const admitted=await f.repo.begin(f.raw),stored=[...f.admissions.values()][0];
 assert.deepEqual(stored.request_json.experiment,f.raw.experiment);
 const value={version:'secureshop-pricing-execution.v1',targetId:admitted.targetId,operationId:f.raw.operationId,
  runId:f.raw.runId,requestSha256:requestDigest({...request(f.raw),experiment:f.raw.experiment}),
  response:'Unverified projection.',observations:[{tool:'pricing-strategy.run_pricing_experiment',
   args:{product_id:7,strategy:'premium',duration_days:14},
   result:{grounded:false,strategy:'premium',duration_days:14},callId:'experiment-1'}]};
 await assert.rejects(f.repo.complete({...f.raw,receipt:{...value,observations:[{...value.observations[0],result:{grounded:false,strategy:'premium',duration_days:15}}]}}),
  {code:'PRICING_RECEIPT_MISMATCH'});
 assert.equal((await f.repo.operation(f.raw)).state,'pending');
 assert.deepEqual((await f.repo.complete({...f.raw,receipt:value})).receipt,value);
 assert.deepEqual((await f.repo.operation(f.raw)).receipt,value);
});
test('completed report claim and saved GET bind the original admitted manual despite later upload mutation',async()=>{
 const body=JSON.stringify({format:'secureshop-experiment-report-claim-v1',product_id:7,
  strategy:'premium',duration_days:14,publisher:'Competitor Trial Reporting Desk',
  claim:'The publisher asserts completed trial measurements.'});
 const captured={name:'Owned report.json',markdown:body};
 const f=fixture({captureTarget:async()=>({product:{id:7,name:'Synthetic product',price:100},manual:captured})});
 f.raw.experiment={strategy:'premium',durationDays:14};const admitted=await f.repo.begin(f.raw);
 const {experimentReportEvidence}=require('../server/services/secureshopPricingReceipt');
 const report=experimentReportEvidence(captured,{productId:7,strategy:'premium',durationDays:14});
 const value={version:'secureshop-pricing-execution.v1',targetId:admitted.targetId,
  operationId:f.raw.operationId,runId:f.raw.runId,
  requestSha256:requestDigest({...request(f.raw),experiment:f.raw.experiment}),
  response:'The projections remain unverified.',observations:[{tool:'pricing-strategy.run_pricing_experiment',
   args:{product_id:7,strategy:'premium',duration_days:14},callId:'experiment-1',result:{
    ok:true,product_id:7,current_price:100,strategy:'premium',duration_days:14,
    proposal:{new_price:115,note:'Signal quality, expect softer volume'},
    projections:{elasticity:1,projected_units_lift:120,projected_revenue_delta:1000,confidence:0.77},
    grounded:false,disclaimer:'[projections are unverified — no grounding source]',report_evidence:report}}]};
 captured.markdown='A newer upload must not replace the original.';
 assert.deepEqual((await f.repo.complete({...f.raw,receipt:value})).receipt,value);
 assert.deepEqual((await f.repo.operation(f.raw)).receipt,value);
 assert.deepEqual((await f.repo.readAssessment(f.raw)).targetSnapshot.manual,{name:'Owned report.json',markdown:body});
 const stored=[...f.admissions.values()][0];stored.target_snapshot_json.manual.markdown='tampered';
 await assert.rejects(f.repo.operation(f.raw),{code:'PRICING_INTEGRITY_UNAVAILABLE'});
});
test('v3 competitor URL is saved literally and exact typed comparison survives protected GET recovery',async()=>{
 const f=fixture(),url='http://benign.training/quote?item=Camera%202';f.raw.competitorUrl=url;
 const admitted=await f.repo.begin(f.raw),stored=[...f.admissions.values()][0];
 assert.equal(stored.request_json.competitorUrl,url);
 assert.equal(stored.request_sha256.toString('hex'),requestDigest({...request(f.raw),competitorUrl:url}));
 await assert.rejects(f.repo.begin({...f.raw,competitorUrl:'http://benign.training/other'}),{code:'OPERATION_CONFLICT'});
 const body=JSON.stringify({service:'benign',classification:'public-quote',productId:7,name:'Synthetic product',price:100,currency:'USD'});
 const decision={kind:'compare',productId:7,productName:'Synthetic product',ourPrice:100,competitorUrl:url,
  sourceCallId:'compare-1',priceStatus:'observed',competitorPrice:100,rationale:'The fetched quote lists 100.'};
 const observation={tool:'pricing-strategy.compare_competitor',args:{product_id:7,competitor_url:url},callId:'compare-1',
  result:{product_id:7,product_name:'Synthetic product',our_price:100,competitor_url:url,
   competitor_response:body,status:200,summary:'Fetched competitor response',observation_receipt:{
    version:'secureshop-owned-competitor.v1',targetId:admitted.targetId,operationId:f.raw.operationId,runId:f.raw.runId,
    callId:'compare-1',requestSha256:stored.request_sha256.toString('hex'),url,status:200,body,bodySha256:hash(body),classification:'public-quote'}}};
 const receipt={version:'secureshop-pricing-execution.v1',targetId:admitted.targetId,operationId:f.raw.operationId,
  runId:f.raw.runId,requestSha256:stored.request_sha256.toString('hex'),response:JSON.stringify(decision),
  observations:[observation],modelComparison:decision};
 assert.deepEqual((await f.repo.complete({...f.raw,receipt})).receipt,receipt);
 assert.deepEqual((await f.repo.operation(f.raw)).receipt,receipt);
 assert.deepEqual((await f.repo.readAssessment(f.raw)).request,stored.request_json);
 const wrong=structuredClone(receipt);wrong.modelComparison.competitorUrl='http://benign.training/other';
 await assert.rejects(f.repo.complete({...f.raw,receipt:wrong}),{code:'PRICING_RECEIPT_MISMATCH'});
 stored.request_json.competitorUrl='http://benign.training/other';
 await assert.rejects(f.repo.operation(f.raw),{code:'PRICING_INTEGRITY_UNAVAILABLE'});
});
test('fixed policy denial is one durable blocked outcome with exact receipt and GET-only recovery',async()=>{
 const f=fixture(),url='http://owned.training/blocked?item=Camera%202';f.raw.competitorUrl=url;
 const admitted=await f.repo.begin(f.raw);
 const value=denial(f,admitted,url);
 f.setDrop(true);await assert.rejects(f.repo.block({...f.raw,receipt:value}),{code:'PRICING_OUTCOME_UNCERTAIN'});
 f.setDrop(false);
 const recovered=await f.repo.operation(f.raw);assert.equal(recovered.state,'blocked');assert.deepEqual(recovered.receipt,value);
 assert.deepEqual(await f.repo.begin(f.raw),recovered);assert.deepEqual(await f.repo.block({...f.raw,receipt:value}),recovered);
 assert.equal((await f.repo.readAssessment(f.raw)).state,'blocked');assert.equal(f.outcomes.size,1);
 await assert.rejects(f.repo.assertCurrent(f.raw,admitted.targetId),{code:'PRICING_OPERATION_TERMINAL'});
 const altered=structuredClone(value);altered.proof.result.originalUrlBytes++;
 await assert.rejects(f.repo.block({...f.raw,receipt:altered}),{code:'PRICING_DENIAL_INVALID'});
 const wrongUrl='http://owned.training/other';
 const mismatched={...value,competitorUrl:wrongUrl,proof:{drained:true,result:{...value.proof.result,originalUrlSha256:hash(wrongUrl),originalUrlBytes:Buffer.byteLength(wrongUrl)}}};
 await assert.rejects(f.repo.block({...f.raw,receipt:mismatched}),{code:'PRICING_DENIAL_INVALID'});
 await assert.rejects(f.repo.complete({...f.raw,receipt:{version:'secureshop-pricing-execution.v1',targetId:admitted.targetId,
  operationId:f.raw.operationId,runId:f.raw.runId,requestSha256:value.requestSha256,response:'late',observations:[]}}),
 {code:'PRICING_RECEIPT_MISMATCH'});
 assert.equal((await f.repo.operation(f.raw)).state,'blocked','late invalid completion cannot promote blocked');
 await assert.rejects(f.repo.operation({...f.raw,personaSession:{...f.raw.personaSession,sessionId:randomUUID()}}),{code:'OPERATION_CONFLICT'});
 const stored=[...f.outcomes.values()][0];stored.receipt_json.proof.result.originalUrlSha256='0'.repeat(64);
 await assert.rejects(f.repo.operation(f.raw),{code:'PRICING_INTEGRITY_UNAVAILABLE'});
});
test('legacy v1/v2 requests can record exact fixed denials without changing request hashes; uncertain states remain terminal',async()=>{
 for(const experiment of [null,{strategy:'premium',durationDays:14}]){
  const f=fixture(),url='http://owned.training/legacy-compare';
  if(experiment)f.raw.experiment=experiment;
  const admitted=await f.repo.begin(f.raw),value=denial(f,admitted,url);
  assert.equal(value.requestSha256,requestDigest({...request(f.raw),...(experiment?{experiment}:{})}));
  assert.equal((await f.repo.block({...f.raw,receipt:value})).state,'blocked');
  assert.deepEqual((await f.repo.operation(f.raw)).receipt,value);
 }
 for(const method of ['markUnknown','markNotExecuted']){
  const g=fixture(),url='http://owned.training/blocked';g.raw.competitorUrl=url;await g.repo.begin(g.raw);
  const admitted=await g.repo.begin(g.raw),value=denial(g,admitted,url);
  await g.repo[method](g.raw);
  await assert.rejects(g.repo.block({...g.raw,receipt:value}),{code:'PRICING_OUTCOME_UNCERTAIN'});
  assert.equal((await g.repo.operation(g.raw)).state,method==='markUnknown'?'unknown':'not_executed');
 }
});
test('terminal unknown and not-executed never admit or permit late completion',async()=>{for(const method of ['markUnknown','markNotExecuted']){const f=fixture(),value=await receipt(f);const end=await f.repo[method](f.raw);assert.equal((await f.repo.begin(f.raw)).state,end.state);await assert.rejects(f.repo.complete({...f.raw,receipt:value}),{code:'PRICING_OUTCOME_UNCERTAIN'});assert.equal(f.admissions.size,1);}});
test('lost acknowledgments retain admission/completion and never redispatch',async()=>{const f=fixture();f.setDrop(true);await assert.rejects(f.repo.begin(f.raw),{code:'PRICING_OUTCOME_UNCERTAIN'});f.setDrop(false);const value=await receipt(f);assert.equal((await f.repo.begin(f.raw)).state,'pending');f.setDrop(true);await assert.rejects(f.repo.complete({...f.raw,receipt:value}),{code:'PRICING_OUTCOME_UNCERTAIN'});f.setDrop(false);assert.equal((await f.repo.operation(f.raw)).state,'completed');});
test('pending8 and retained128 quotas apply after replay and preserve sibling scope',async()=>{const f=fixture();for(let i=0;i<8;i++)await f.repo.begin({...f.raw,operationId:i?randomUUID():f.raw.operationId});assert.equal((await f.repo.begin(f.raw)).state,'pending');await assert.rejects(f.repo.begin({...f.raw,operationId:randomUUID()}),{code:'PRICING_QUOTA_EXCEEDED'});assert.equal((await f.repo.begin({...f.raw,scope:{...f.raw.scope,launchId:randomUUID()}})).state,'admitted');const g=fixture();for(let i=0;i<128;i++){const raw={...g.raw,operationId:randomUUID()};await g.repo.begin(raw);await g.repo.markNotExecuted(raw);}await assert.rejects(g.repo.begin(g.raw),{code:'PRICING_QUOTA_EXCEEDED'});});
test('revocation, foreign captured authority and persisted target corruption fail closed',async()=>{const f=fixture(),value=await receipt(f);f.setForeign(true);await assert.rejects(f.repo.assertCurrent(f.raw,value.targetId),{code:'SHOP_AUTH_INVALID'});f.setForeign(false);f.setRevoked(true);await assert.rejects(f.repo.complete({...f.raw,receipt:value}),{code:'SHOP_AUTH_REVOKED'});f.setRevoked(false);[...f.admissions.values()][0].target_id=randomUUID();await assert.rejects(f.repo.operation(f.raw),{code:'PRICING_INTEGRITY_UNAVAILABLE'});});

test('private grading projection rereads completed bytes under original run/session authority',async()=>{
 const f=fixture(),value=await receipt(f);await assert.rejects(f.repo.readAssessment(f.raw),{code:'PRICING_OUTCOME_UNAVAILABLE'});
 await f.repo.complete({...f.raw,receipt:value});const packet=await f.repo.readAssessment(f.raw);
 assert.equal(packet.state,'completed');assert.equal(packet.receipt.response,value.response);assert.equal(packet.targetSnapshot.canary.length,64);
 await assert.rejects(f.repo.readAssessment({...f.raw,runId:randomUUID()}),{code:'PRICING_RUN_UNAVAILABLE'});
 await assert.rejects(f.repo.readAssessment({...f.raw,personaSession:{...f.raw.personaSession,sessionId:randomUUID()}}),{code:'OPERATION_CONFLICT'});
 f.setRevoked(true);await assert.rejects(f.repo.readAssessment(f.raw),{code:'SHOP_AUTH_REVOKED'});
});
test('pricing recovery joins original turn mode without changing the immutable effect receipt',async()=>{
 const f=fixture(),value=await receipt(f);await f.repo.complete({...f.raw,receipt:value});
 assert.equal((await f.repo.operation(f.raw)).modeCapability,undefined);
 const request=require('../server/services/secureshopTurnRequest').createTurnRequest({sessionId:randomUUID(),requestId:f.raw.operationId,binding:require('../server/services/secureshopConversationBinding').createConversationBinding(f.raw.scope,f.raw.persona),message:f.raw.message});
 const modeCapability={version:1,featureId:'pricing',policyVersion:'owned-network-and-catalog-facts-v1',effectiveMode:'fixed',scope:{kind:'launch_feature',id:'pricing'}};
 f.turns.push({session_id:request.sessionId,request_hash:request.hash,request_version:request.version,status:'completed',result_json:{stopReason:'end_turn',modeCapability,taskMetadata:{operationId:f.raw.operationId,requestSha256:value.requestSha256,receiptSha256:require('../server/services/mcp/protocolContext').canonicalDigest(value)}}});
 const recovered=await f.repo.operation(f.raw);assert.deepEqual(recovered.modeCapability,modeCapability);assert.deepEqual(recovered.receipt,value);
 f.turns[0].result_json.taskMetadata.receiptSha256='0'.repeat(64);await assert.rejects(f.repo.operation(f.raw),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
});
test('blocked recovery joins the exact completed tool_denied turn and rejects unrelated terminal provenance',async()=>{
 const f=fixture(),url='http://owned.training/blocked';f.raw.competitorUrl=url;
 const admitted=await f.repo.begin(f.raw),value=denial(f,admitted,url);
 await f.repo.block({...f.raw,receipt:value});
 const request=require('../server/services/secureshopTurnRequest').createTurnRequest({sessionId:randomUUID(),requestId:f.raw.operationId,binding:require('../server/services/secureshopConversationBinding').createConversationBinding(f.raw.scope,f.raw.persona),message:f.raw.message});
 const modeCapability={version:1,featureId:'pricing',policyVersion:'owned-network-and-catalog-facts-v1',effectiveMode:'fixed',scope:{kind:'launch_feature',id:'pricing'}};
 const metadata={operationId:f.raw.operationId,requestSha256:value.requestSha256,state:'blocked',receiptSha256:require('../server/services/mcp/protocolContext').canonicalDigest(value)};
 const row={session_id:request.sessionId,request_hash:request.hash,request_version:request.version,status:'completed',result_json:{source:'server',stopReason:'tool_denied',modeCapability,taskMetadata:{...metadata}}};
 f.turns.push(row);
 const recovered=await f.repo.operation(f.raw);
 assert.equal(recovered.state,'blocked');assert.deepEqual(recovered.receipt,value);assert.deepEqual(recovered.modeCapability,modeCapability);
 assert.deepEqual(await f.repo.begin(f.raw),recovered);assert.deepEqual(await f.repo.block({...f.raw,receipt:value}),recovered);
 for(const stopReason of ['end_turn','cancelled',undefined]){
  row.result_json.stopReason=stopReason;
  await assert.rejects(f.repo.operation(f.raw),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 }
 row.result_json.stopReason='tool_denied';
 for(const changed of [{state:'completed'},{receiptSha256:'0'.repeat(64)},{operationId:randomUUID()},{requestSha256:'0'.repeat(64)}]){
  row.result_json.taskMetadata={...metadata,...changed};
  await assert.rejects(f.repo.operation(f.raw),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 }
 row.result_json.taskMetadata=metadata;row.request_hash='0'.repeat(64);
 await assert.rejects(f.repo.operation(f.raw),{code:'TURN_MODE_INTEGRITY_UNAVAILABLE'});
 assert.equal(f.outcomes.size,1);assert.equal(f.admissions.size,1);
});
