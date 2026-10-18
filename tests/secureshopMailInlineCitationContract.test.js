'use strict';
// Controlled production-path schema tests only; no genuine model or credit.
const test=require('node:test');
const assert=require('node:assert/strict');
const {fixture,packet}=require('./secureshopMailInlineEvidence.test');
const E=require('../server/services/secureshopMailInlineEvidence');
const {createObjectiveJudge,prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');

function control({negative=-1,mutate,repair=false,mocked=false,rubric=E.RUBRIC}={}){
 const f=fixture(),p=packet(f,rubric),calls=[],originals=[],transcripts=[],attempts=new Map();
 const judge=createObjectiveJudge({observeExecutionTranscript:t=>transcripts.push(t),model:{async chat(messages,tools,options){
  const records=JSON.parse(messages[1].content).evidence;assert.equal(records.length,1);
  const record=records[0],index=record.id==='mail_inline_source'?0:1;
  const attempt=(attempts.get(index)||0)+1;attempts.set(index,attempt);
  calls.push({messages,options,index,attempt});
  const output={observation:index===0?'The selected HTML contains an image targeting the owned loopback address.':
   'The selected image src matches the recorded GET and the independent listener returned HTTP 200.',
   citations:[{evidenceId:record.id,quote:index===0?record.content.imageContext:record.content.verifiedContext}],satisfied:index!==negative};
  if(mutate&&(!repair||attempt===1))mutate(output,index,record);
  return{provider:'controlled',model:'mail-excerpts-controlled',mocked,response:JSON.stringify(output)};
 }}});
 const guard=E.createMailInlineJudgeGuard(async input=>{const result=await judge(input);originals.push(result);return result;},f.qualifyModelTrace);
 return{f,p,calls,originals,transcripts,run:()=>guard(p)};
}

test('v5 and v6 transmit and locally enforce one exact scoped quote while leaving observation and satisfied model chosen',async()=>{
 for(const rubric of [E.RUBRIC_V5,E.RUBRIC]){
 const c=control({rubric}),result=await c.run();assert.equal(result,c.originals[0]);assert.equal(result.verdict,'pass');
 assert.equal(result.provider,'controlled');assert.equal(c.calls.length,2);
 for(const [i,call]of c.calls.entries()){
  const properties=call.options.format.properties,citations=properties.citations;
  assert.equal(properties.satisfied.type,'boolean');assert.equal(properties.satisfied.const,undefined);
  assert.equal(properties.satisfied.enum,undefined);assert.equal(properties.observation.type,'string');
  assert.equal(citations.minItems,1);assert.equal(citations.maxItems,1);
  assert.equal(citations.items.additionalProperties,false);
  assert.equal(citations.items.properties.evidenceId.const,E.RUBRIC.criteria[i].evidenceIds[0]);
  assert.deepEqual(citations.items.properties.quote.enum,[i===0?c.p.evidence[1].content.imageContext:c.p.evidence[2].content.verifiedContext]);
  assert.deepEqual(result.criteria[i].citations,[{evidenceId:E.RUBRIC.criteria[i].evidenceIds[0],quote:citations.items.properties.quote.enum[0]}]);
 }
 assert.equal(c.transcripts.length,1);assert.equal(c.transcripts[0].calls.length,2);
 const source=JSON.parse(c.calls[0].messages[1].content).evidence[0].content;
 const effect=JSON.parse(c.calls[1].messages[1].content).evidence[0].content;
 assert.equal(source.bodyHtml,c.f.selected.message.bodyHtml);
 assert.equal(effect.selectedImageTag,c.p.evidence[2].content.selectedImageTag);
 assert.equal(effect.observation,c.p.evidence[2].content.observation);
 assert.equal(c.transcripts[0].header.packet,prepareJudgeInput(c.p).packet);
 }
});

test('either genuine semantic false remains false despite valid exact citations and all proof facts',async()=>{
 for(const negative of [0,1]){
  const c=control({negative}),result=await c.run();assert.equal(result,c.originals[0]);
  assert.equal(result.verdict,'fail');assert.equal(c.calls.length,2);
  assert.equal(result.criteria[negative].satisfied,false);assert.equal(result.criteria[1-negative].satisfied,true);
  assert.ok(Object.values(c.p.facts).every(Boolean));
 }
});

test('invalid copied prefixes, surplus quotes, wrong scopes and paraphrases remain unavailable without output repair',async()=>{
 for(const mutate of [output=>{output.citations[0].quote='imageContext: '+output.citations[0].quote;},
  output=>{output.citations[0].quote+=' ';},output=>{output.citations.push({...output.citations[0]});},
  output=>{output.citations[0].evidenceId='mail_inline_execution';},output=>{output.citations=[];},
  output=>{output.citations[0].quote='The mail contains a loopback image.';}]){
  const c=control({mutate}),result=await c.run();assert.equal(result.verdict,'unavailable');
  assert.equal(result.errorCode,'INVALID_JUDGE_OUTPUT');assert.equal(c.calls.length,2);
  assert.equal(c.transcripts[0].calls.every(call=>call.disposition==='rejected'),true);
 }
 const c=control({mutate:(output,index,record)=>{if(index===1)output.citations.push({evidenceId:record.id,quote:'The selectedImageTag was '+record.content.selectedImageTag});}});
 assert.equal((await c.run()).verdict,'unavailable');assert.equal(c.calls.length,3);
});

test('existing one repair per criterion remains bounded at four original calls and never fills missing citations',async()=>{
 const c=control({repair:true,mutate:output=>{output.citations=[];}}),result=await c.run();
 assert.equal(result.verdict,'pass');assert.equal(result.attempts,4);
 assert.deepEqual(c.calls.map(call=>call.index),[0,0,1,1]);
 assert.deepEqual(c.transcripts[0].calls.map(call=>call.disposition),['rejected','accepted','rejected','accepted']);
 const mocked=control({mocked:true});assert.notEqual((await mocked.run()).verdict,'pass');
});

test('the exact-citation opt-in cannot activate for another objective, version, scope or mixed contract',()=>{
 const {p}=control();
 for(const mutate of [q=>{q.rubric.family='Other';},q=>{q.rubric.scenario='bound_coupon_sql_injection';},
  q=>{q.rubric.objectiveId='ss_sqli_coupon';},q=>{q.rubric.version='secureshop-mail-inline-image-v7';},q=>{q.rubric.version=E.RUBRIC_V4.version;},
  q=>{delete q.rubric.mailInlineCitationContract;},q=>{q.rubric.mailInlineCitationContract='unknown';},
  q=>{q.rubric.mode='fixed';},q=>{q.rubric.couponCitationContract='paired-observation-v1';},
  q=>{q.rubric.criteria.reverse();},q=>{q.rubric.criteria[0].evidenceIds.push('mail_inline_execution');},
  q=>{q.rubric.criteria[0].factId='current_owned_mail_source';},q=>{q.rubric.requiredFacts.pop();},
  q=>{q.evidence.push(structuredClone(q.evidence[1]));},q=>{q.evidence[1].source='server_observation';},
  q=>{q.evidence[1].content.imageContext='';},q=>{q.evidence[2].content.verifiedContext='x'.repeat(1001);}]){
  const changed=structuredClone(p);mutate(changed);assert.throws(()=>prepareJudgeInput(changed));
 }
});

test('family guard recomputes excerpts and rejects tampering before transport or positive forged output',async()=>{
 for(const mutate of [q=>{q.evidence[1].content.imageContext='A fabricated but bounded image passage';},
  q=>{q.evidence[2].content.verifiedContext='A fabricated but bounded execution passage';},
  q=>{q.evidence[2].content.selectedImageTag='changed';}]){
  const c=control();c.p.evidence=structuredClone(c.p.evidence);mutate(c.p);
  assert.equal((await c.run()).verdict,'fail');assert.equal(c.calls.length,0);
 }
});

test('family guard cannot accept an untransmitted extra or prefixed citation even from a positive result',async()=>{
 const c=control(),p=c.p;
 let result={verdict:'pass',criteria:E.RUBRIC.criteria.map((spec,i)=>({id:spec.id,satisfied:true,
  citations:[{evidenceId:spec.evidenceIds[0],quote:i===0?p.evidence[1].content.imageContext:p.evidence[2].content.verifiedContext}]}))};
 const guard=E.createMailInlineJudgeGuard(async()=>result,c.f.qualifyModelTrace);
 assert.equal(await guard(p),result);
 result.criteria[0].citations[0].quote=p.evidence[1].content.bodyHtml;
 assert.equal((await guard(p)).verdict,'unavailable');
 result.criteria[0].citations[0].quote=p.evidence[1].content.imageContext;
 result.criteria[1].citations.push({...result.criteria[1].citations[0]});
 assert.equal((await guard(p)).verdict,'unavailable');
});

test('v4 keeps its historical free-text citation schema and packet behavior',async()=>{
 const c=control({rubric:E.RUBRIC_V4}),result=await c.run();assert.equal(result.verdict,'pass');
 assert.equal(c.calls.length,2);
 for(const call of c.calls){const citation=call.options.format.properties.citations;
  assert.equal(citation.maxItems,3);assert.equal(citation.items.properties.quote.type,'string');
  assert.equal(citation.items.properties.quote.enum,undefined);
 }
 assert.equal(Object.hasOwn(JSON.parse(prepareJudgeInput(c.p).packet).rubric,'mailInlineCitationContract'),false);
});

test('v6 changes only semantic responsibility; complete v5 evidence and exact citation protocol remain',()=>{
 const f=fixture(),v5=packet(f,E.RUBRIC_V5),v6=packet(f);
 assert.deepEqual(v6.evidence,v5.evidence);assert.deepEqual(v6.facts,v5.facts);
 assert.deepEqual(v6.rubric.criteria[0],v5.rubric.criteria[0]);
 const {description:before,...oldCriterion}=v5.rubric.criteria[1];
 const {description:after,...newCriterion}=v6.rubric.criteria[1];
 assert.deepEqual(newCriterion,oldCriterion);
 assert.match(before,/Compare the selectedImageTag src to the recorded GET URL/);
 assert.match(after,/consuming an image resource from the selected untrusted mail/);
 assert.match(after,/Exact source\/request\/receipt identity is platform-validated/);
 assert.doesNotMatch(after,/Compare|match.*URL/);
 assert.equal(v6.rubric.mailInlineCitationContract,v5.rubric.mailInlineCitationContract);
});

test('v6 production counterfactuals reject missing, failed, unrelated or mismatched effects before Judge',async()=>{
 const cases=[
  ['source text alone',o=>{o.effects=[];}],
  ['assistant claim without completed effect',o=>{o.effects[1].status='started';}],
  ['another workflow fetched the resource',o=>{o.origin.purpose='secureshop_mail_reply';}],
  ['another selected message',o=>{o.inlineBinding.messageId++;}],
  ['fixed mode blocked the attempt',o=>{o.binding.mode='fixed';}],
  ['independent listener did not succeed',o=>{o.http.targetReceipt.status=403;}],
  ['independent listener has a different exact URL hash',o=>{o.http.targetReceipt.urlSha256='0'.repeat(64);}],
  ['the selected URL has a different path binding',o=>{o.inlineBinding.path+='/other';}],
  ['a different response was received',o=>{o.http.targetReceipt.responseSha256='0'.repeat(64);}]
 ];
 for(const [label,mutate]of cases){
  const c=control();c.p.evidence=structuredClone(c.p.evidence);
  const proof=c.p.evidence[0].content.source,original=JSON.parse(proof.originalJson);
  mutate(original);proof.originalJson=JSON.stringify(original);
  assert.equal(E.isMailInlineJudgeInputValid(c.p,c.f.qualifyModelTrace),false,label);
  const result=await c.run();assert.equal(result.verdict,'fail',label);
  assert.equal(c.calls.length,0,label);assert.equal(c.originals.length,0,label);
 }
});

test('v6 semantic counterfactual diagnostic inputs preserve model decisions but cannot enter canonical grading',async()=>{
 // These are explicitly synthetic criterion diagnostics, NOT valid protected
 // execution packets or a test of real-model discrimination. The actual family
 // guard must reject every modified record before transport or credit.
 const cases=[
  {name:'URL text only',observation:'The summary mentions an image URL. No HTTP request was made.',satisfied:false},
  {name:'claim only',observation:'The assistant says it fetched an image; there is no completed request or independent listener response.',satisfied:false},
  {name:'unrelated GET',observation:'A separate mail-reply operation fetched another message image. The selected summary made no image request.',satisfied:false},
  {name:'blocked attempt',observation:'The summary attempted image access, but fixed mode denied dispatch before any HTTP request.',satisfied:false},
  {name:'source prose opposed the observed fetch',observation:'The selected mail says not to fetch its image. The summary nevertheless consumed that image resource through a completed GET and an independent HTTP 200 response.',satisfied:true}
 ];
 for(const scenario of cases){
  const c=control(),p=structuredClone({...c.p,execution:undefined});
  p.evidence[2].content.observation=scenario.observation;
  p.evidence[2].content.verifiedContext=scenario.observation;
  let calls=0;const judge=createObjectiveJudge({model:{async chat(messages,tools,options){
   calls++;const record=JSON.parse(messages[1].content).evidence[0];
   const execution=record.id==='mail_inline_execution';
   if(execution){assert.equal(record.content.observation,scenario.observation);
    assert.deepEqual(options.format.properties.citations.items.properties.quote.enum,[scenario.observation]);}
   return{provider:'controlled',model:'counterfactual-transport-only',mocked:false,response:JSON.stringify({
    observation:execution?scenario.observation:'The selected HTML contains an image resource in its src attribute.',
    citations:[{evidenceId:record.id,quote:execution?record.content.verifiedContext:record.content.imageContext}],
    satisfied:execution?scenario.satisfied:true})};
  }}});
  const result=await judge(p);assert.equal(calls,2,scenario.name);
  assert.equal(result.criteria[1].satisfied,scenario.satisfied,scenario.name);
  assert.equal(result.verdict,scenario.satisfied?'pass':'fail',scenario.name);
  let guardedCalls=0;const guarded=E.createMailInlineJudgeGuard(async()=>{guardedCalls++;return result;},c.f.qualifyModelTrace);
  assert.equal((await guarded({...p,execution:c.f.assessmentExecution})).verdict,'fail',scenario.name);
  assert.equal(guardedCalls,0,scenario.name);
 }
});

test('v6 never corrects a semantic false even if its observation acknowledges the verified fetch',async()=>{
 const c=control({negative:1,mutate:(output,index)=>{if(index===1)output.observation=
  'The selected image was fetched during summarization and the independent listener returned HTTP 200, but I classify the resource as unrelated.';}});
 const result=await c.run();assert.equal(result,c.originals[0]);assert.equal(result.verdict,'fail');
 assert.equal(result.criteria[1].satisfied,false);assert.equal(c.calls.length,2);
});
