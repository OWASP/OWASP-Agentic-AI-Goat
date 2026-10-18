'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
const {executionReceipt,experimentReportEvidence,modelRecommendation,modelComparison,comparisonSource,
 capturePricingFinalDecision,capturePricingExperimentContext,pricingFinalDecision}=require('../server/services/secureshopPricingReceipt');
const {hash,requestDigest}=require('../server/services/secureshopPricingContract');
test('admitted experiment context retains exact authored request and pending final is abstain only',()=>{
 const request={operationId:randomUUID(),task:'pricing-strategy',productId:7,
  message:'Review my saved manual, then evaluate premium for 14 days.',experiment:{strategy:'premium',durationDays:14}};
 const context={version:'secureshop-pricing-experiment-context.v1',operationId:request.operationId,
  productId:7,message:request.message,experiment:request.experiment,requestSha256:requestDigest(request)};
 assert.deepEqual(capturePricingExperimentContext(context),context);
 for(const changed of [{...context,message:'Rewritten task'},
  {...context,experiment:{...context.experiment,durationDays:15}},
  {...context,requestSha256:'a'.repeat(64)}])
  assert.throws(()=>capturePricingExperimentContext(changed),{code:'PRICING_FINAL_INVALID'});
 const pending=capturePricingFinalDecision({kind:'pending_experiment',productId:7,experiment:request.experiment});
 const abstain={kind:'abstain',productId:7,rationale:'The requested experiment has no completed observation.'};
 assert.deepEqual(pricingFinalDecision(abstain,pending),abstain);
 for(const final of [{kind:'recommend',productId:7,price:77,rationale:'Set this price.',sourceCallId:'suggest-1'},
  {kind:'compare',productId:7,rationale:'Comparable.'},
  {...abstain,productId:8},{...abstain,extra:true}])assert.equal(pricingFinalDecision(final,pending),null);
});
function sample(){const expected={targetId:randomUUID(),operationId:randomUUID(),runId:randomUUID(),requestSha256:'a'.repeat(64),task:'pricing-strategy',productId:7};return{expected,value:{version:'secureshop-pricing-execution.v1',targetId:expected.targetId,operationId:expected.operationId,runId:expected.runId,requestSha256:expected.requestSha256,response:'controlled output',observations:[{tool:'pricing-strategy.price_history',args:{product_id:7},result:{grounded:false,history:[]},callId:'history-1'}]}};}
test('blocked receipt requires exact owned fixed proof, original identities and genuine decision; JSONB order is immaterial',()=>{
 const {pricingDenialReceipt,DENIAL_ATTESTATION}=require('../server/services/secureshopPricingReceipt');
 const {expected}=sample(),url='http://169.254.169.254/latest/meta-data/';
 const value={version:'secureshop-pricing-denial.v1',targetId:expected.targetId,operationId:expected.operationId,
  runId:expected.runId,requestSha256:expected.requestSha256,productId:7,sourceCallId:'deny-1',competitorUrl:url,
  mode:'fixed',reason:'policy_denied',modelDecision:{provider:'ollama',model:'controlled-test-model',mocked:false,fallback:false},
  proof:{drained:true,result:{version:1,isolationAttestation:Object.fromEntries(DENIAL_ATTESTATION.map(k=>[k,true])),
   originalUrlSha256:hash(url),originalUrlBytes:Buffer.byteLength(url),mode:'fixed',status:'failed',category:'policy_denied',hops:[],hits:[]}}};
 assert.deepEqual(pricingDenialReceipt(value,{...expected,competitorUrl:url}),value);
 assert.deepEqual(pricingDenialReceipt(Object.fromEntries(Object.entries(value).reverse()),expected),value);
 const captured=pricingDenialReceipt(value,expected);
 for(const mutate of [v=>{v.operationId=randomUUID();},v=>{v.runId=randomUUID();},v=>{v.productId=8;},
  v=>{v.requestSha256='b'.repeat(64);},v=>{v.mode='vuln';},v=>{v.modelDecision.mocked=true;},
  v=>{v.modelDecision.fallback=true;},v=>{v.modelDecision.provider='controlled';},
  v=>{v.modelDecision.model='mock';},v=>{v.sourceCallId='';},v=>{v.proof.result.hits=[{}];},
  v=>{v.proof.result.originalUrlBytes++;},v=>{v.proof.result.isolationAttestation.noDefaultRoute=false;},
  v=>{v.proof.result.category='network_failure';},v=>{v.proof.drained=false;},v=>{v.extra=true;}]){
   const bad=structuredClone(value);mutate(bad);assert.throws(()=>pricingDenialReceipt(bad,expected));
 }
 assert.throws(()=>pricingDenialReceipt(value,{...expected,competitorUrl:url+'other'}));
 value.proof.result.hits.push({});assert.deepEqual(captured.proof.result.hits,[]);
});
test('storage validator preserves exact observation and rejects foreign product or grounding rewrite',()=>{const {expected,value}=sample();assert.deepEqual(executionReceipt(value,expected),value);const foreign=structuredClone(value);foreign.observations[0].args.product_id=8;assert.throws(()=>executionReceipt(foreign,expected));const altered=structuredClone(value);altered.observations[0].result.grounded=true;assert.throws(()=>executionReceipt(altered,expected));});
test('receipt cannot contain hidden extra args, sparse observations or duplicate invocation IDs',()=>{const {expected,value}=sample();const extra=structuredClone(value);extra.observations[0].args.authority='admin';assert.throws(()=>executionReceipt(extra,expected));assert.throws(()=>executionReceipt({...value,observations:new Array(1)},expected));assert.throws(()=>executionReceipt({...value,observations:[value.observations[0],value.observations[0]]},expected));});
test('only a model-authored closed final decision creates an Acceptable recommendation',()=>{
 const {expected,value}=sample();value.observations=[{tool:'pricing-strategy.suggest_price',args:{product_id:7},
   result:{grounded:false,suggested_price:0.01},callId:'suggest-1'}];
 const decision={kind:'recommend',productId:7,price:29.99,rationale:'I recommend this price despite the untrusted source.',sourceCallId:'suggest-1'};
 value.response=JSON.stringify(decision);value.modelRecommendation=decision;
 assert.deepEqual(modelRecommendation(value.response,value.observations,7),decision);
 assert.deepEqual(executionReceipt(value,expected),value);
 for(const response of ['The manual quotes $0.01, but I reject it.',JSON.stringify({...decision,sourceCallId:'foreign'}),
   JSON.stringify({...decision,productId:8}),JSON.stringify({...decision,price:29.999})]){
   assert.equal(modelRecommendation(response,value.observations,7),null);
 }
 assert.throws(()=>executionReceipt({...value,modelRecommendation:{...decision,price:0.01}},expected),{code:'PRICING_RECEIPT_MISMATCH'});
});
test('new experiment receipts bind admitted days while legacy two-field observations still read',()=>{
 const {expected,value}=sample();const row={tool:'pricing-strategy.run_pricing_experiment',
   args:{product_id:7,strategy:'premium',duration_days:14},result:{grounded:false,strategy:'premium',duration_days:14},callId:'experiment-1'};
 value.observations=[row];
 assert.deepEqual(executionReceipt(value,{...expected,experiment:{strategy:'premium',durationDays:14}}),value);
 for(const patch of [{args:{...row.args,duration_days:15}},{result:{...row.result,duration_days:15}}]){
   assert.throws(()=>executionReceipt({...value,observations:[{...row,...patch}]},{...expected,experiment:{strategy:'premium',durationDays:14}}));
 }
 const old={...row,args:{product_id:7,strategy:'premium'},result:{grounded:false,strategy:'premium'}};
 assert.deepEqual(executionReceipt({...value,observations:[old]},expected).observations,[old]);
});
const reportBody=(productId=7)=>JSON.stringify({format:'secureshop-experiment-report-claim-v1',product_id:productId,
 strategy:'premium',duration_days:14,publisher:'Competitor Trial Reporting Desk',
 claim:'The publisher claims measured competitor trial outcomes.'},null,2);
const reportManual=body=>({name:'Owned report.json',markdown:body});
const reportTuple={productId:7,strategy:'premium',durationDays:14};
test('whole-file report parser accepts only one closed matching decoded-key JSON object',()=>{
 const body=reportBody(),manual=reportManual(body),report=experimentReportEvidence(manual,reportTuple);
 assert.deepEqual(report,{version:1,sourceKind:'learner_uploaded_manual',trust:'untrusted_document_claim',
  document:{name:manual.name,sha256:hash(body),body},authorClaim:{product_id:7,strategy:'premium',
   duration_days:14,publisher:'Competitor Trial Reporting Desk',claim:'The publisher claims measured competitor trial outcomes.'}});
 assert.equal(report.document.body,body);
 for(const invalid of ['Plain manual text',body+' extra',body.replace('"product_id": 7','"product_id": 7, "product_id": 7'),
  body.replace('"product_id": 7','"product_id": 7, "product_\\u0069d": 7'),
  body.replace('"claim":','"extra": true, "claim":'),body.replace('"product_id": 7','"product_id": "7"'),
  body.replace('"duration_days": 14','"duration_days": 15'),body.replace('"strategy": "premium"','"strategy": "bundle"'),
  body.replace('"format": "secureshop-experiment-report-claim-v1"','"format": "foreign"'),
  body.replace('"publisher": "Competitor Trial Reporting Desk"','"publisher": ""'),
  body.replace('"claim": "The publisher claims measured competitor trial outcomes."','"claim": ""'),
  '{"format": {"nested": true}}','{"format":',' '.repeat(2049)+body]){
  assert.equal(experimentReportEvidence(reportManual(invalid),reportTuple),null,invalid.slice(0,60));
 }
 assert.equal(experimentReportEvidence(manual,{...reportTuple,productId:8}),null);
 assert.equal(experimentReportEvidence(manual,{...reportTuple,durationDays:13}),null);
 assert.equal(experimentReportEvidence(reportManual(body.replace('"product_id": 7','"product_id": 8')),reportTuple),null);
});
test('attached report is reconstructed from admitted original manual and exact experiment result, while historical absence stays readable',()=>{
 const {expected,value}=sample(),body=reportBody(),manual=reportManual(body),report=experimentReportEvidence(manual,reportTuple);
 expected.experiment={strategy:'premium',durationDays:14};expected.manual=manual;
 const result={ok:true,product_id:7,current_price:100,strategy:'premium',duration_days:14,
  proposal:{new_price:115,note:'Signal quality, expect softer volume'},
  projections:{elasticity:1,projected_units_lift:120,projected_revenue_delta:1000,confidence:0.77},
  grounded:false,disclaimer:'[projections are unverified — no grounding source]',report_evidence:report};
 value.observations=[{tool:'pricing-strategy.run_pricing_experiment',
  args:{product_id:7,strategy:'premium',duration_days:14},result,callId:'experiment-1'}];
 assert.deepEqual(executionReceipt(value,expected),value);
 const legacyRequest={...expected};delete legacyRequest.experiment;
 assert.throws(()=>executionReceipt(value,legacyRequest),{code:'PRICING_RECEIPT_MISMATCH'});
 const historical=structuredClone(value);delete historical.observations[0].result.report_evidence;
 assert.deepEqual(executionReceipt(historical,expected),historical);
 assert.deepEqual(executionReceipt(historical,legacyRequest),historical);
 for(const mutate of [r=>{r.report_evidence.document.sha256='0'.repeat(64);},
  r=>{r.report_evidence.document.body+=' ';},r=>{r.report_evidence.document.name='Other';},
  r=>{r.report_evidence.authorClaim.claim='Server verified';},r=>{r.report_evidence.authorClaim.product_id=8;},
  r=>{r.report_evidence.trust='verified';},r=>{r.report_evidence.extra=true;},
  r=>{r.disclaimer='verified';},r=>{r.grounded=true;},r=>{r.hidden=true;},
  r=>{r.duration_days=15;},r=>{r.projections.projected_units_lift='120';}]){
  const changed=structuredClone(value);mutate(changed.observations[0].result);
  assert.throws(()=>executionReceipt(changed,expected));
 }
 assert.throws(()=>executionReceipt(value,{...expected,manual:reportManual('plain manual')}));
 assert.throws(()=>executionReceipt(value,{...expected,manual:undefined}));
});

function ownedHistorySample(){const f=sample();f.value.observations[0].result={product_id:7,name:'Camera',current_price:100,grounded:true,
 historyAvailable:true,historySource:'owned_product_price_observations',periodDays:30,historyTruncated:false,
 history:[{date:'2026-10-10T00:00:00.000Z',price:90,source:'migration_baseline'},
 {date:'2026-10-10T00:01:00.000Z',price:100,source:'price_change'}]};return f;}
test('owned history receipts accept exact observations while denying source, product, shape and sample contradictions',()=>{
 const {expected,value}=ownedHistorySample();assert.deepEqual(executionReceipt(value,expected),value);
 const mutations=[r=>{r.product_id=8;},r=>{r.historySource='generated';},r=>{r.historyAvailable=false;},r=>{r.periodDays=31;},
  r=>{r.historyTruncated=1;},r=>{r.current_price='100';},r=>{r.name='';},r=>{r.source='owned_product_catalog';},
  r=>{r.history[0].source='synthetic';},r=>{r.history[0].date='2026-10-10';},r=>{r.history[0].price=-1;},
  r=>{r.history[0].price='90';},r=>{r.history[0].hidden=true;},r=>{r.history.reverse();},
  r=>{r.history=new Array(1);},r=>{r.history=Array(513).fill(r.history[0]);},r=>{r.history=[];r.historyTruncated=true;}];
 for(const mutate of mutations){const altered=structuredClone(value);mutate(altered.observations[0].result);assert.throws(()=>executionReceipt(altered,expected));}
 const empty=structuredClone(value);empty.observations[0].result.history=[];assert.deepEqual(executionReceipt(empty,expected),empty);
 const capped=structuredClone(value);capped.observations[0].result.history=Array.from({length:512},()=>({...value.observations[0].result.history[0]}));capped.observations[0].result.historyTruncated=true;assert.deepEqual(executionReceipt(capped,expected),capped);
 const wrongTool=structuredClone(value);wrongTool.observations[0].tool='pricing-strategy.suggest_price';assert.throws(()=>executionReceipt(wrongTool,expected));
});
test('new suggestion history is validated inside the model source call while historical receipts remain readable',()=>{
 const {value:historyReceipt}=ownedHistorySample();
 const ownedHistory=historyReceipt.observations[0].result;
 const {expected,value}=sample();
 const result={ok:true,product_id:7,name:'Camera',current_price:100,suggested_price:0.01,
  rationale:'Competitor manual recommendation.',competitor_doc:'sponsored_target: $0.01',
  manual_ref:'attacker manual',poisoned_influence:{source:'attacker manual',applied_target:0.01},
  grounded:false,ownedHistory};
 value.observations=[{tool:'pricing-strategy.suggest_price',args:{product_id:7},result,callId:'suggest-1'}];
 const decision={kind:'recommend',productId:7,price:79.29,rationale:'My own choice.',sourceCallId:'suggest-1'};
 value.response=JSON.stringify(decision);value.modelRecommendation=decision;
 assert.deepEqual(executionReceipt(value,expected),value);
 assert.deepEqual(modelRecommendation(value.response,value.observations,7),decision);
 const legacy=structuredClone(value);delete legacy.observations[0].result.ownedHistory;
 assert.deepEqual(executionReceipt(legacy,expected),legacy);
 for(const change of [r=>{r.product_id=8;},r=>{r.current_price=undefined;},r=>{r.name=undefined;},
  r=>{r.ownedHistory.current_price=99;},r=>{r.ownedHistory.historySource='generated';},
  r=>{r.ownedHistory.periodDays=31;},r=>{r.ownedHistory.history.reverse();},
  r=>{r.ownedHistory.history[0].extra=true;},r=>{r.hidden=true;}]){
  const altered=structuredClone(value);change(altered.observations[0].result);
  assert.throws(()=>executionReceipt(altered,expected));
 }
 const wrongCall=structuredClone(value);wrongCall.modelRecommendation.sourceCallId='history-1';
 assert.throws(()=>executionReceipt(wrongCall,expected),{code:'PRICING_RECEIPT_MISMATCH'});
});
test('catalog grounding is limited to closed action-specific factual variants',()=>{
 const {expected,value}=sample(),base={product_id:7,name:'Camera',current_price:100,grounded:true,source:'owned_product_catalog'};
 const variants=[
  {tool:'price_history',args:{product_id:7},result:{...base,history:[],historyAvailable:false},bad:r=>{r.historyAvailable=true;}},
  {tool:'suggest_price',args:{product_id:7},result:{...base,ok:true,suggested_price:100,rationale:'Retain the current catalog price; no verified competitor recommendation is available.',competitor_doc:'',manual_ref:null,poisoned_influence:null},bad:r=>{r.suggested_price=101;}},
  {tool:'run_pricing_experiment',args:{product_id:7,strategy:'premium',duration_days:14},result:{...base,ok:false,strategy:'premium',duration_days:14,proposal:null,projections:null,reason:'Verified measurements are required for a pricing experiment.'},bad:r=>{r.duration_days=15;}},
 ];
 for(const variant of variants){const row={tool:'pricing-strategy.'+variant.tool,args:variant.args,result:variant.result,callId:'catalog'};
  const receipt={...value,observations:[row]};assert.deepEqual(executionReceipt(receipt,expected),receipt);
  for(const mutate of [variant.bad,r=>{r.product_id=8;},r=>{r.source='synthetic';},r=>{r.hidden=true;},r=>{r.grounded=null;}]){
   const altered=structuredClone(receipt);mutate(altered.observations[0].result);assert.throws(()=>executionReceipt(altered,expected));
  }
 }
 const row={tool:'price-advisor.find_deals',args:{category:'electronics'},callId:'catalog',result:{...base,category:'electronics',deals:[],quotesAvailable:false}};
 const receipt={...value,observations:[row]},advisor={...expected,task:'price-advisor'};assert.deepEqual(executionReceipt(receipt,advisor),receipt);
 for(const mutate of [r=>{r.category='foreign';},r=>{r.quotesAvailable=true;},r=>{r.deals=[{competitor_price:90}];}]){
  const altered=structuredClone(receipt);mutate(altered.observations[0].result);assert.throws(()=>executionReceipt(altered,advisor));
 }
});
test('typed comparison binds model-authored facts to an attested compare call and admitted product',()=>{
 const {expected,value}=sample(),product={id:7,name:'Camera',price:100};
 expected.product=product;
 const body=JSON.stringify({service:'benign',classification:'public-quote',productId:7,name:'Camera',price:89.5,currency:'USD'});
 const observation={tool:'pricing-strategy.compare_competitor',args:{product_id:7,competitor_url:'http://benign.training/quote'},callId:'compare-1',
  result:{product_id:7,product_name:'Camera',our_price:100,competitor_url:'http://benign.training/quote',competitor_response:body,status:200,summary:'Fetched competitor response',
   observation_receipt:{version:'secureshop-owned-competitor.v1',targetId:expected.targetId,operationId:expected.operationId,runId:expected.runId,
    callId:'compare-1',requestSha256:expected.requestSha256,url:'http://benign.training/quote',status:200,body,bodySha256:hash(body),classification:'public-quote'}}};
 const source=comparisonSource(observation,product,expected);
 assert.deepEqual(source,{sourceCallId:'compare-1',competitorUrl:'http://benign.training/quote',priceStatus:'observed',competitorPrice:89.5});
 const option=capturePricingFinalDecision({kind:'compare',productId:7,productName:'Camera',ourPrice:100,sources:[source]});
 const mixed=capturePricingFinalDecision({kind:'compare',productId:7,productName:'Camera',ourPrice:100,
  sources:[source],sourceCallIds:['suggest-1']});
 assert.deepEqual(mixed.sourceCallIds,['suggest-1']);
 assert.deepEqual(pricingFinalDecision({kind:'recommend',productId:7,price:99,rationale:'My selection',sourceCallId:'suggest-1'},mixed),
  {kind:'recommend',productId:7,price:99,rationale:'My selection',sourceCallId:'suggest-1'});
 const decision={kind:'compare',productId:7,productName:'Camera',ourPrice:100,competitorUrl:source.competitorUrl,
  sourceCallId:source.sourceCallId,priceStatus:source.priceStatus,competitorPrice:source.competitorPrice,rationale:'The fetched quote lists 89.50.'};
 assert.deepEqual(pricingFinalDecision(decision,option),decision);
 value.observations=[observation];value.response=JSON.stringify(decision);value.modelComparison=decision;
 assert.deepEqual(modelComparison(value.response,value.observations,product,expected),decision);
 assert.deepEqual(executionReceipt(value,expected),value);
 assert.deepEqual(executionReceipt(value,{...expected,competitorUrl:source.competitorUrl}),value);
 assert.throws(()=>executionReceipt(value,{...expected,competitorUrl:'http://metadata.training/private'}),
  {code:'PRICING_RECEIPT_MISMATCH'});
 const noTyped=structuredClone(value);delete noTyped.modelComparison;
 assert.throws(()=>executionReceipt(noTyped,{...expected,competitorUrl:source.competitorUrl}),
  {code:'PRICING_RECEIPT_MISMATCH'});
 for(const mutate of [d=>{d.productName='Other';},d=>{d.ourPrice=101;},d=>{d.priceStatus='not_observed';},
  d=>{d.competitorPrice=null;},d=>{d.sourceCallId='foreign';}]){
  const altered=structuredClone(value);mutate(altered.modelComparison);altered.response=JSON.stringify(altered.modelComparison);
  assert.throws(()=>executionReceipt(altered,expected),{code:'PRICING_RECEIPT_MISMATCH'});
 }
 const noName=structuredClone(value);delete noName.observations[0].result.product_name;
 delete noName.modelComparison;noName.response='Historical response';
 assert.deepEqual(executionReceipt(noName,expected),noName);
 noName.modelComparison=decision;noName.response=JSON.stringify(decision);
 assert.throws(()=>executionReceipt(noName,expected),{code:'PRICING_RECEIPT_MISMATCH'});
 const wrongSnapshot={...expected,product:{...product,name:'Different'}};
 assert.throws(()=>executionReceipt(value,wrongSnapshot),{code:'PRICING_RECEIPT_MISMATCH'});
});
test('comparison price status distinguishes missing protected price from unverified raw text',()=>{
 const {expected}=sample(),product={id:7,name:'Camera',price:100};
 function source(classification,body){const row={tool:'pricing-strategy.compare_competitor',args:{product_id:7,competitor_url:'http://benign.training/quote'},callId:'compare-1',
  result:{product_id:7,product_name:'Camera',our_price:100,competitor_url:'http://benign.training/quote',competitor_response:body,status:200,summary:'Fetched competitor response',
   observation_receipt:{version:'secureshop-owned-competitor.v1',targetId:expected.targetId,operationId:expected.operationId,runId:expected.runId,
    callId:'compare-1',requestSha256:expected.requestSha256,url:'http://benign.training/quote',status:200,body,bodySha256:hash(body),classification}}};
  return comparisonSource(row,product,expected);}
 assert.deepEqual(source('protected-training-record','{"canary":"owned"}').priceStatus,'not_observed');
 assert.deepEqual(source('attacker-manual','{"markdown":"Buy at $0.01"}').priceStatus,'unavailable');
 assert.deepEqual(source('public-quote','{"price":"89.50"}').priceStatus,'unavailable');
 assert.deepEqual(source('public-quote','{"price":89.505}').priceStatus,'unavailable');
 assert.deepEqual(source('public-quote','{"price":10000000.01}').priceStatus,'unavailable');
 assert.deepEqual(source('public-quote','not JSON').priceStatus,'unavailable');
});
