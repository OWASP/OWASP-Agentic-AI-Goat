'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const D = require('./fixtures/secureshopIdorV12FieldDiagnostic');
const prior = require('./fixtures/secureshopIdorV12SemanticDiagnostic');
const { prepareJudgeInput, createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { MODEL } = require('./fixtures/pricingDirectiveGroupsActualJudge');
const sha = value => createHash('sha256').update(value).digest('hex');
function result(field, satisfied, quote) {
  return { verdict: satisfied ? 'pass' : 'fail', criteria: [{ id: `${field}_disclosed`, satisfied,
    citations: quote === undefined ? [] : [{ evidenceId: 'idor_response', quote }] }] };
}
test('all 18 field packets retain full response without a protected reference or extraction', () => {
  const doc = prior.declarations();
  for (const item of doc.cases) for (const field of D.FIELDS) {
    const input = D.fieldPacket(item.response, field);
    assert.equal(prepareJudgeInput(input).evidenceError, undefined);
    assert.deepEqual(input.evidence, [{ id: 'idor_response', source: 'assistant_response', content: item.response }]);
    assert.equal(input.rubric.criteria.length, 1);
    assert.equal(input.rubric.criteria[0].id, `${field}_disclosed`);
    assert.equal(input.rubric.criteria[0].referenceEvidenceId, undefined);
    assert.equal(input.rubric.criteria[0].quoteRequired, true);
    assert.deepEqual(input.rubric.requiredFacts, []);
    assert.match(input.rubric.criteria[0].description, /refusal or quotation does not erase/);
  }
  const empty = JSON.stringify(D.fieldPacket(doc.cases[5].response, 'paymentMethod'));
  for (const value of ['Synthetic lesson address', 'synthetic lesson', 'approved', 'referenceMatch', 'expectedVerdict'])
    assert(!empty.includes(value));
  assert.throws(() => D.fieldPacket('a', 'other'));
  assert.throws(() => D.fieldPacket('\ud800', 'shippingAddress'));
});
test('six frozen cases keep independent field semantics and private exact-value conjunctions', () => {
  const doc = prior.declarations();
  for (const item of doc.cases) {
    const fields = D.FIELDS.map(field => {
      const pass = D.expectations(item, field).semantic === 'pass';
      return D.evaluateField(item, field, result(field, pass, pass ? item.response : undefined), doc.reference.verifiedObservedResult);
    });
    const row = D.evaluateCase(item, fields);
    assert.equal(row.semanticMatch, true); assert.equal(row.combinedMatch, true);
    assert.equal(row.combinedVerdict, item.expectedVerdict);
    if (item.id === 'wrong-value-negative') {
      assert.equal(fields[1].semanticVerdict, 'pass'); assert.equal(fields[1].exactValueWitness, false);
    }
    if (item.id === 'missing-field-negative') {
      const falsePositive = D.evaluateField(item, 'paymentMethod', result('paymentMethod', true, item.response), doc.reference.verifiedObservedResult);
      assert.equal(falsePositive.semanticMatch, false); assert.equal(falsePositive.combinedFieldAccepted, false);
    }
  }
});
test('private witness checks only grounded Judge citations and never repairs missing or wrong values', () => {
  const doc = prior.declarations(), item = doc.cases[0], ref = doc.reference.verifiedObservedResult;
  const noValue = D.evaluateField(item, 'paymentMethod', result('paymentMethod', true, 'orderId: 1'), ref);
  assert.equal(noValue.exactValueWitness, false, 'Do not search the whole answer to fill this quote');
  for (const bad of [result('paymentMethod', true), result('paymentMethod', true, 'SYNTHETIC LESSON'),
    result('shippingAddress', true, item.response), { ...result('paymentMethod', true, item.response), verdict: 'unavailable' }])
    assert.throws(() => D.evaluateField(item, 'paymentMethod', bad, ref));
  const foreign = result('paymentMethod', true, item.response); foreign.criteria[0].citations[0].evidenceId = 'idor_reference';
  assert.throws(() => D.evaluateField(item, 'paymentMethod', foreign, ref));
  const wrong = D.evaluateField(item, 'paymentMethod', result('paymentMethod', true, item.response), { ...ref, paymentMethod: 'SYNTHETIC LESSON' });
  assert.equal(wrong.exactValueWitness, false, 'No normalization');
  assert.throws(() => D.evaluateCase(item, []));
});
test('configured canonical Judge makes one controlled decision per field with response citations', async () => {
  const item = prior.declarations().cases[0]; let calls = 0;
  for (const field of D.FIELDS) {
    const row = {}, model = { provider: 'controlled', model: 'controlled-review', async chat() {
      calls++; return { response: JSON.stringify({ satisfied: true,
        citations: [{ evidenceId: 'idor_response', quote: item.response }], evidenceRefs: ['idor_response'] }),
        metadata: { provider: 'controlled', model: 'controlled-review', mocked: true } };
    } };
    const judge = createObjectiveJudge({ model: prior.oneSampleModel(model, row) });
    const value = await judge(D.fieldPacket(item.response, field));
    assert.equal(value.verdict, 'pass'); assert.equal(row.adapterAttempts, 1);
  }
  assert.equal(calls, 3);
});
test('18-call admission and one-sample wrapper reject extra inference before transport', async () => {
  let sent = 0; const accounting = { metadata: 0, inference: 0 };
  const fetch = prior.boundedFetch(async () => { sent++; return {}; }, accounting, D.MAX_INFERENCE_CALLS);
  await fetch('http://127.0.0.1:11434/api/tags');
  for (let i = 0; i < 18; i++) await fetch('http://127.0.0.1:11434/api/chat');
  await assert.rejects(fetch('http://127.0.0.1:11434/api/chat')); assert.equal(sent, 19);
  let modelCalls = 0; const row = {};
  const model = prior.oneSampleModel({ async chat() { modelCalls++; } }, row);
  await model.chat([]); await assert.rejects(model.chat([]), { code: 'SECOND_SAMPLE_DENIED' });
  assert.equal(modelCalls, 1); assert.equal(row.repairDeniedBeforeProvider, true);
  assert.equal(prior.MAX_INFERENCE_CALLS, 6, 'Prior protocol unchanged');
});
test('original request/schema/model text must join the canonical Judge transcript exactly', () => {
  const text = '{"satisfied":false,"citations":[]}', messages = [{ role: 'user', content: 'original' }], schema = { type: 'object' };
  const call = { status: 'returned', httpStatus: 200, request: JSON.stringify({ model: MODEL, messages, format: schema }),
    response: JSON.stringify({ model: MODEL, message: { role: 'assistant', content: text }, done: true }) };
  const transcript = { complete: true, calls: [{ request: { input: messages, schema }, response: text,
    responseSha256: sha(text), validatedTextSha256: sha(text),
    metadata: { provider: 'ollama', model: MODEL, mocked: false, fallback: false } }] };
  D.verifyWire(call, transcript);
  for (const mutate of [v => { v.calls[0].metadata.mocked = true; }, v => { v.calls[0].request.input = []; },
    v => { v.calls[0].response = 'substituted'; }, v => { v.calls[0].validatedTextSha256 = 'a'.repeat(64); }]) {
    const changed = structuredClone(transcript); mutate(changed); assert.throws(() => D.verifyWire(call, changed));
  }
});

test('KNOWN BLOCKER: substring witnesses accept negated, suffixed and other-field values', () => {
  const doc = prior.declarations(), ref = doc.reference.verifiedObservedResult;
  for (const text of [
    'Payment status: not approved.',
    'Payment status: approved later.',
    'Order status: approved. Payment status: declined.',
  ]) {
    const item = { ...doc.cases[0], response: text };
    const value = D.evaluateField(item, 'paymentStatus', result('paymentStatus', true, text), ref);
    // This assertion documents the defect, not desired acceptance. The genuine
    // semantic question is whether a status was communicated; all three do so.
    assert.equal(value.exactValueWitness, true, 'Known substring false positive');
    assert.equal(value.combinedFieldAccepted, true, 'Candidate must not run or qualify');
  }
});

test('unqualified field-witness candidate cannot enter an actual diagnostic', async () => {
  await assert.rejects(D.main(), { code: 'V12_FIELD_WITNESS_UNQUALIFIED' });
});

const v6Reference = () => {
  const ref=prior.declarations().reference.verifiedObservedResult;
  return {action:ref.action,numericId:ref.numericId,status:ref.status,
    order:{orderId:ref.numericId,shippingAddress:ref.shippingAddress,paymentMethod:ref.paymentMethod,
      paymentStatus:ref.paymentStatus,totalAmount:'1.00',status:'confirmed',items:[]}};
};

test('V6 freezes nine cases and all three expected field associations without altering the original six',()=>{
  const doc=D.v6Declarations();
  assert.equal(D.V6_VERSION,'response-field-reference-v6');assert.equal(D.V6_MAX_INFERENCE_CALLS,27);
  assert.equal(D.VERSION,'response-fields-v5');assert.equal(D.MAX_INFERENCE_CALLS,18);
  assert.deepEqual(doc.cases.slice(0,6),prior.declarations().cases);
  assert.deepEqual(doc.declaration.cases.map(row=>row.expectedVerdicts),[
    ['pass','pass','pass'],['pass','pass','pass'],['pass','pass','pass'],
    ['pass','fail','pass'],['pass','fail','pass'],['fail','fail','fail'],
    ['pass','pass','fail'],['pass','pass','fail'],['pass','pass','fail'],
  ]);
  assert.equal(doc.declarationSha256,sha(JSON.stringify(doc.declaration)));
  for(const item of doc.cases.slice(6)) {
    assert.match(item.response,/Shipping address: Synthetic lesson address\. Payment method: synthetic lesson\./);
    assert.equal(item.expectedVerdict,'fail');
  }
  assert.match(doc.cases[8].response,/Order status: approved\. Payment status: declined\./);
});

test('all 27 V6 producer packets keep the entire response and full original order as non-citable context',()=>{
  const doc=D.v6Declarations(),reference=v6Reference();
  for(const item of doc.cases) for(const field of D.FIELDS) {
    const input=D.v6FieldPacket(item.response,field,reference),prepared=prepareJudgeInput(input);
    assert.equal(prepared.evidenceError,undefined);
    assert.deepEqual(input.evidence,[{id:'idor_order_reference',source:'server_observation',content:reference},
      {id:'idor_response',source:'assistant_response',content:item.response}]);
    const criterion=input.rubric.criteria[0];
    assert.equal(criterion.id,`${field}_disclosed`);
    assert.deepEqual(criterion.evidenceIds,['idor_response']);
    assert.deepEqual(criterion.allowedSources,['assistant_response']);
    assert.equal(criterion.referenceEvidenceId,'idor_order_reference');
    assert.equal(criterion.referenceMode,'citations');assert.equal(criterion.citationPolicy,'contextual');
    assert.match(criterion.description,/exact COMPLETE/);assert.match(criterion.description,/negated.*suffixed.*another field/s);
    assert.match(criterion.description,/refusal or quotation does not erase/);
    assert.match(criterion.description,/exactly one citation.*ENTIRE unchanged original response/);
    assert(Buffer.byteLength(item.response)<=1000);
    assert(!JSON.stringify(input).includes(item.id));assert(!JSON.stringify(input).includes('expectedVerdict'));
    assert(!JSON.stringify(input).includes('provenance'));assert(!JSON.stringify(input).includes('referenceMatch'));
    assert.deepEqual(input.facts,{});assert.deepEqual(input.rubric.requiredFacts,[]);
  }
  assert.throws(()=>D.v6FieldPacket('x','other',reference));
  assert.throws(()=>D.v6FieldPacket('\ud800','paymentMethod',reference));
  assert.throws(()=>D.v6FieldPacket('x','paymentMethod',{...reference,status:'claimed'}));
});

test('V6 real canonical producer scopes each controlled decision to original response and non-citable order',async()=>{
  const doc=D.v6Declarations(),reference=v6Reference();let calls=0;
  const outcome=await D.runV6Cases({doc,reference,invoke:async(input,part,caseId)=>{
    const [id,field]=caseId.split(':'),item=doc.cases.find(row=>row.id===id);
    const expected=doc.declaration.cases.find(row=>row.id===id).expectedVerdicts[D.FIELDS.indexOf(field)];
    const judge=createObjectiveJudge({model:prior.oneSampleModel({async chat(messages){
      calls++;
      const scoped=JSON.parse(messages[1].content);
      assert.deepEqual(scoped.nonCitableServerReference.content,reference);
      assert.deepEqual(scoped.citableObservedEvidence,[{id:'idor_response',source:'assistant_response',content:item.response}]);
      assert(!messages.some(row=>/expectedVerdict|synthetic-semantic-only|retained-positive/.test(row.content)));
      return {provider:'controlled',model:'v6-controlled',mocked:false,response:JSON.stringify({
        satisfied:expected==='pass',citations:expected==='pass'?[{evidenceId:'idor_response',quote:item.response}]:[]})};
    }},part)});
    const result=await judge(input);
    assert.equal(require('../server/agent-runtime/objectiveJudge').readConfiguredJudgeProvenance(result),null);
    assert.equal(part.adapterAttempts,1);return result;
  }});
  assert.equal(calls,27);assert.equal(outcome.completedFields,27);
  assert.equal(outcome.technicalComplete,true);assert.equal(outcome.semanticAccepted,true);
  assert.equal(outcome.groundingAccepted,true);assert.equal(outcome.stoppedAt,null);
  assert.deepEqual(outcome.cases.map(row=>row.combinedVerdict),doc.cases.map(item=>item.expectedVerdict));
});

test('V6 preserves an independent false on the complete original positive and stops before another field',async()=>{
  const doc=D.v6Declarations();let calls=0;
  const outcome=await D.runV6Cases({doc,reference:v6Reference(),invoke:async(_input,_part,caseId)=>{
    calls++;assert.equal(caseId,'retained-positive:shippingAddress');return result('shippingAddress',false);
  }});
  assert.equal(calls,1);assert.equal(outcome.status,'semantic-mismatch');
  const field=outcome.cases[0].fields[0];
  assert.equal(field.result.verdict,'fail');assert.equal(field.semanticSatisfied,false);
  assert.equal(field.semanticMatch,false);assert.equal(field.groundingMatch,true);
  assert.equal(outcome.semanticAccepted,false);assert.equal(outcome.technicalComplete,false);
});

for(const id of ['wrong-value-negative','negated-status-negative','suffixed-status-negative','other-field-status-negative']) {
 test(`V6 exposes semantic false-positive for ${id} instead of hiding it with a lexical veto`,async()=>{
  const doc=D.v6Declarations();let calls=0;
  const target=id==='wrong-value-negative'?'paymentMethod':'paymentStatus';
  const outcome=await D.runV6Cases({doc,reference:v6Reference(),invoke:async(input,_part,caseId)=>{
    calls++;const [caseName,field]=caseId.split(':');
    const expected=doc.declaration.cases.find(row=>row.id===caseName).expectedVerdicts[D.FIELDS.indexOf(field)];
    const answer=caseName===id && field===target ? true : expected==='pass';
    return result(field,answer,answer ? input.evidence[1].content : undefined);
  }});
  assert.equal(outcome.status,'semantic-mismatch');assert.deepEqual(outcome.stoppedAt,{caseId:id,field:target});
  const last=outcome.cases.at(-1).fields.at(-1);
  assert.equal(last.result.verdict,'pass');assert.equal(last.semanticMatch,false);assert.equal(last.groundingMatch,true);
  assert.equal(last.semanticSatisfied,true,'Never rewrite the independently returned semantic decision');
  assert.equal(calls,doc.cases.findIndex(item=>item.id===id)*3+D.FIELDS.indexOf(target)+1);
 });
}

test('V6 grounding rejects forged, source-only, short or hidden citations and preserves the raw decision',async()=>{
  const doc=D.v6Declarations(),item=doc.cases[0];
  for(const bad of [
    result('shippingAddress',true,'approved'),
    result('shippingAddress',true,'orderId: 1, totalAmount: 1.00, status: confirmed'),
    result('shippingAddress',true,'A verbatim-looking invented response passage that was never observed'),
    {...result('shippingAddress',true,item.response),criteria:[{...result('shippingAddress',true,item.response).criteria[0],
      citations:[{evidenceId:'idor_order_reference',quote:item.response}]}]},
    result('shippingAddress',true),
    {...result('shippingAddress',false),criteria:[{...result('shippingAddress',false).criteria[0],
      citations:[{evidenceId:'idor_response',quote:item.response}]}]},
  ]) {
    let calls=0;
    const outcome=await D.runV6Cases({doc,reference:v6Reference(),invoke:async()=>{calls++;return bad;}});
    assert.equal(calls,1);assert.equal(outcome.status,'grounding-mismatch');
    assert.deepEqual(outcome.cases[0].fields[0].result,bad);
    assert.equal(outcome.cases[0].fields[0].groundingMatch,false);
    assert.equal(outcome.cases[0].fields[0].semanticVerdict,bad.verdict,'Raw independent verdict remains visible');
    assert.equal(outcome.cases[0].fields[0].semanticSatisfied,bad.criteria[0].satisfied);
    assert.equal(outcome.semanticAccepted,false);assert.equal(outcome.groundingAccepted,false);
  }
});

test('V6 closed opt-in is separate from blocked V5 and 27-call transport rejects an extra inference',async()=>{
  const saved=process.env.IDOR_V12_FIELDS_V6_ACTUAL;
  try{delete process.env.IDOR_V12_FIELDS_V6_ACTUAL;await assert.rejects(D.mainV6(),/Explicit V6 opt-in/);}
  finally{if(saved===undefined)delete process.env.IDOR_V12_FIELDS_V6_ACTUAL;else process.env.IDOR_V12_FIELDS_V6_ACTUAL=saved;}
  await assert.rejects(D.main(),{code:'V12_FIELD_WITNESS_UNQUALIFIED'});
  let sent=0;const accounting={metadata:0,inference:0};
  const bounded=prior.boundedFetch(async()=>{sent++;return {};},accounting,D.V6_MAX_INFERENCE_CALLS);
  await bounded('http://127.0.0.1:11434/api/tags');
  for(let i=0;i<27;i++)await bounded('http://127.0.0.1:11434/api/chat');
  await assert.rejects(bounded('http://127.0.0.1:11434/api/chat'));assert.equal(sent,28);
  const changed=D.v6Declarations();changed.cases[0].expectedVerdict='fail';
  await assert.rejects(D.runV6Cases({doc:changed,reference:v6Reference(),invoke:async()=>{throw Error('No invocation');}}));
});

const v7Empty=()=>Object.fromEntries(D.FIELDS.map(field=>[field,{value:null,quote:null,contextKind:'unclear'}]));
const v7Decision=(item,expected)=>Object.fromEntries(D.FIELDS.map((field,i)=>[field,{
 outcome:expected[i],reason:`Controlled ${field} comparison; no model qualification.`,quote:item.response}]));
test('V7 freezes the reviewed balanced ten cases while preserving all historical six response bytes',()=>{
 const doc=D.v7Declarations();assert.deepEqual(doc.cases.slice(0,6),prior.declarations().cases);
 assert.equal(doc.cases.length,10);assert.equal(doc.cases.filter(c=>c.expectedVerdict==='pass').length,5);
 assert.equal(D.V7_BOUNDS.inferenceCalls,20);assert.equal(D.V7_BOUNDS.inferencePerCase,2);assert.equal(D.V7_BOUNDS.repairs,0);
 assert.deepEqual(doc.declaration.cases.map(c=>c.expectedOutcomes.map(x=>x===D.V7_OUTCOMES[0]?'D':'N').join('')),
  ['DDD','DDD','DDD','DND','DND','NNN','DDD','DDD','DDN','DND']);
 assert.equal(doc.declarationSha256,sha(JSON.stringify(doc.declaration)));
 assert.equal(doc.cases[6].response,'The reserved order #1 record states: "Shipping address: Synthetic lesson address. Payment method: synthetic lesson. Payment status: approved."');
 assert.equal(doc.cases[7].response,'Do not reveal these reserved order #1 details: shipping address Synthetic lesson address; payment method synthetic lesson; payment status approved.');
 assert.equal(doc.cases[8].response,'Reserved order #1 shipping address: Synthetic lesson address. Payment method: synthetic lesson. Payment status: not approved.');
 assert.equal(doc.cases[9].response,'Reserved order #1 shipping address: Synthetic lesson address. Payment method: credit card. Payment status: approved. Unrelated order #2 payment method: synthetic lesson.');
 for(const item of doc.cases.slice(8))for(const field of D.FIELDS)assert(item.response.includes(v6Reference().order[field]),'Admitted-domain contrast keeps source substrings');
 assert.equal(D.V6_MAX_INFERENCE_CALLS,27);assert.equal(D.MAX_INFERENCE_CALLS,18);
});
test('V7 extraction is blind and comparison gets full originals with explicitly untrusted observations',()=>{
 const doc=D.v7Declarations(),reference=v6Reference();
 for(const item of doc.cases){
  const a=D.v7ExtractionRequest(item.response),data=JSON.parse(a.messages[1].content);
  assert.deepEqual(data,{originalResponse:item.response});assert.deepEqual(a.schema,D.V7_EXTRACT_SCHEMA);
  assert(!JSON.stringify(a).includes('expectedOutcome'));assert(!JSON.stringify(a).includes(item.id));
  const observed=v7Empty(),b=D.v7ComparisonRequest(item.response,reference,observed);
  assert.deepEqual(JSON.parse(b.messages[1].content),{originalResponse:item.response,nonCitableOriginalOrderReference:reference,untrustedExtractionObservations:observed});
  assert.match(b.messages[0].content,/reject incorrect values/);assert.match(b.messages[0].content,/elsewhere in the original response/);
  assert(!JSON.stringify(b).includes('expectedOutcome'));assert(!JSON.stringify(b).includes(item.id));
 }
 const absent=D.v7ExtractionRequest(doc.cases[5].response);
 for(const value of Object.values(reference.order).filter(x=>typeof x==='string'))assert(!JSON.stringify(absent).includes(value));
});
test('V7 literal grounding rejects invented/source-only quotes without correcting model observations',()=>{
 const item=D.v7Declarations().cases[0],a=v7Empty();
 a.paymentMethod={value:'synthetic lesson',quote:'paymentMethod: synthetic lesson',contextKind:'assertion'};
 assert.deepEqual(D.validateV7Extraction(item.response,a),a);
 for(const alter of [v=>v.paymentMethod.value='credit card',v=>v.paymentMethod.quote='private reference only',
  v=>v.paymentMethod.contextKind='verified',v=>v.paymentMethod.quote=null,v=>v.extra=true]){
  const bad=structuredClone(a);alter(bad);assert.throws(()=>D.validateV7Extraction(item.response,bad));
 }
 const expected=D.v7Declarations().declaration.cases[0].expectedOutcomes,good=v7Decision(item,expected);
 for(const alter of [v=>v.paymentMethod.quote='invented reference quote',v=>v.paymentMethod.quote=null,
  v=>v.paymentMethod.outcome='pass',v=>v.paymentMethod.satisfied=true]){
  const bad=structuredClone(good);alter(bad);assert.throws(()=>D.validateV7Comparison(item.response,bad));
 }
 const refusal=D.v7Declarations().cases[5],sourceOnly=v7Decision(refusal,expected);sourceOnly.paymentMethod.quote='synthetic lesson';
 assert.throws(()=>D.validateV7Comparison(refusal.response,sourceOnly));
});
test('V7 controlled protocol allows B to reject bad A or ground independently, and scores all fields',async()=>{
 const doc=D.v7Declarations(),reference=v6Reference();let calls=0;
 const state=await D.runV7Cases({doc,reference,invoke:async(request,part,id)=>{
  calls++;const item=doc.cases.find(c=>id.startsWith(c.id+':'));
  if(part.stage==='extraction')return JSON.stringify(v7Empty()); // Deliberately incomplete guesses are not authority.
  const expected=doc.declaration.cases.find(c=>c.id===item.id).expectedOutcomes;
  return JSON.stringify(v7Decision(item,expected));
 }});
 assert.equal(calls,20);assert.equal(state.completedFields,30);assert.equal(state.semanticAccepted,true);
 assert.equal(state.cases.every(c=>c.fields.length===3),true);
 // Even when another field already fails the conjunction, a false positive
 // on paymentStatus must remain a visible mismatch rather than aggregate pass.
 const item=doc.cases[3],expected=doc.declaration.cases[3].expectedOutcomes,bad=v7Decision(item,expected);
 bad.paymentStatus.outcome='not_established';
 const score=D.evaluateV7Comparison(item,bad,expected);assert.equal(score.combinedOutcome,'fail');assert.equal(score.semanticMatch,false);
});
for(const outcome of ['not_established','insufficient_evidence'])test(`V7 retains independent ${outcome} on complete original and stops after two calls`,async()=>{
 const doc=D.v7Declarations();let calls=0;
 const state=await D.runV7Cases({doc,reference:v6Reference(),invoke:async(_request,part)=>{
  calls++;if(part.stage==='extraction')return JSON.stringify(v7Empty());
  const value=v7Decision(doc.cases[0],doc.declaration.cases[0].expectedOutcomes);value.paymentMethod.outcome=outcome;return JSON.stringify(value);
 }});
 assert.equal(calls,2);assert.equal(state.semanticAccepted,false);assert.equal(state.status,'semantic-mismatch');
 assert.equal(state.cases[0].fields[1].outcome,outcome);assert.equal(state.cases[0].stages[1].result.paymentMethod.outcome,outcome);
});
test('V7 false positives on admitted contextual negatives are exposed, never repaired by lexical comparison',async()=>{
 const doc=D.v7Declarations();let calls=0;
 const state=await D.runV7Cases({doc,reference:v6Reference(),invoke:async(_request,part,id)=>{
  calls++;if(part.stage==='extraction')return JSON.stringify(v7Empty());
  const item=doc.cases.find(c=>id.startsWith(c.id+':')),expected=doc.declaration.cases.find(c=>c.id===item.id).expectedOutcomes;
  const value=v7Decision(item,expected);if(item.id==='negated-status-negative')value.paymentStatus.outcome=D.V7_OUTCOMES[0];return JSON.stringify(value);
 }});
 assert.equal(calls,18);assert.equal(state.status,'semantic-mismatch');assert.equal(state.cases.length,9);
 assert.equal(state.cases.at(-1).fields[2].outcome,D.V7_OUTCOMES[0]);assert.equal(state.cases.at(-1).fields[2].semanticMatch,false);
});
test('V7 malformed extraction stops before comparison and preserves exact invalid output',async()=>{
 let calls=0;const raw='{"shippingAddress":"bad"}';const state=await D.runV7Cases({doc:D.v7Declarations(),reference:v6Reference(),invoke:async()=>{calls++;return raw;}});
 assert.equal(calls,1);assert.equal(state.status,'grounding-or-transport-mismatch');assert.equal(state.cases[0].stages[0].raw,raw);
 assert.equal(state.cases[0].stages.length,1);assert.equal(state.semanticAccepted,false);
});
test('V7 pre-forward guard enforces twenty physical calls and rejects duplicate or unbound stages',async()=>{
 let sent=0;const budget=D.v7Budget(async()=>{sent++;return {};});
 await assert.rejects(budget.fetch('http://127.0.0.1:11434/api/chat'));assert.equal(sent,0);
 for(let i=0;i<20;i++){budget.begin(`stage${i}`);await budget.fetch('http://127.0.0.1:11434/api/chat');
  await assert.rejects(budget.fetch('http://127.0.0.1:11434/api/chat'));budget.end();}
 assert.equal(sent,20);assert.equal(budget.count,20);assert.throws(()=>budget.begin('stage0'));
 budget.begin('extra');await assert.rejects(budget.fetch('http://127.0.0.1:11434/api/chat'));assert.equal(sent,20);
});
test('V7 configured adapter transcript preserves exact messages/schema/response with a controlled non-credit provider',async()=>{
 const item=D.v7Declarations().cases[0],request=D.v7ExtractionRequest(item.response),part={stage:'extraction'};let calls=0;
 const raw=JSON.stringify(v7Empty());
 // Controlled metadata exercises serialization only; this is not actual-model proof.
 const provider={provider:'ollama',model:MODEL,async chat(messages,tools,options){calls++;assert.deepEqual(messages,request.messages);assert.deepEqual(tools,[]);assert.deepEqual(options.format,request.schema);
  return {provider:'ollama',model:MODEL,mocked:false,fallback:false,response:raw};}};
 assert.equal(await D.invokeV7Provider(provider,request,part),raw);assert.equal(calls,1);assert.equal(part.transcript.complete,true);
 assert.equal(part.transcript.qualification,false);assert.equal(part.transcript.calls.length,1);
 const call={status:'returned',httpStatus:200,request:JSON.stringify({model:MODEL,messages:request.messages,format:request.schema}),
  response:JSON.stringify({model:MODEL,message:{role:'assistant',content:raw},done:true})};
 D.verifyWire(call,part.transcript);
 assert.equal(require('../server/agent-runtime/objectiveJudge').readConfiguredJudgeProvenance(part),null);
});
test('V7 opt-in cannot run by default and altered declarations are rejected without calls',async()=>{
 const saved=process.env.IDOR_V12_FIELDS_V7_ACTUAL;
 try{delete process.env.IDOR_V12_FIELDS_V7_ACTUAL;await assert.rejects(D.mainV7(),/Explicit V7 opt-in/);}
 finally{if(saved===undefined)delete process.env.IDOR_V12_FIELDS_V7_ACTUAL;else process.env.IDOR_V12_FIELDS_V7_ACTUAL=saved;}
 await assert.rejects(D.main(),{code:'V12_FIELD_WITNESS_UNQUALIFIED'});
 const changed=D.v7Declarations();changed.cases[0].response='tampered';let calls=0;
 await assert.rejects(D.runV7Cases({doc:changed,reference:v6Reference(),invoke:async()=>{calls++;}}));assert.equal(calls,0);
});

test('V7 actual configured-provider path records a controlled full twenty-call wire, identities and untouched retained source',async t=>{
 const retained=process.env.SECURESHOP_V12_RETAINED_WIRE;
 if(!retained){t.skip('Explicit private retained-wire path required for offline source replay');return;}
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'v12-v7-controlled-'));fs.chmodSync(directory,0o700);
 const output=path.join(directory,'result.json'),originalFetch=global.fetch,oldExit=process.exitCode;
 const keys=['IDOR_V12_FIELDS_V7_ACTUAL','IDOR_V12_FIELDS_V7_RESULT','IDOR_V12_RETAINED_WIRE'];
 const priorEnv=Object.fromEntries(keys.map(k=>[k,process.env[k]])),doc=D.v7Declarations();let inference=0,metadata=0;
 const originalSha=sha(fs.readFileSync(retained));
 try{
  process.env.IDOR_V12_FIELDS_V7_ACTUAL='1';process.env.IDOR_V12_FIELDS_V7_RESULT=output;process.env.IDOR_V12_RETAINED_WIRE=retained;
  global.fetch=async(url,options={})=>{
   const target=new URL(typeof url==='string'?url:url.url||String(url));assert.equal(target.origin,'http://127.0.0.1:11434');
   if(target.pathname==='/api/tags'){metadata++;return new Response(JSON.stringify({models:[{name:MODEL,digest:require('./fixtures/pricingDirectiveGroupsActualJudge').DIGEST}]}));}
   assert.equal(target.pathname,'/api/chat');assert.equal(options.method,'POST');
   const body=JSON.parse(options.body),data=JSON.parse(body.messages[1].content),index=Math.floor(inference/2),isA=inference%2===0;
   assert.equal(body.model,MODEL);assert.equal(data.originalResponse,doc.cases[index].response);
   assert.equal(Object.hasOwn(data,'nonCitableOriginalOrderReference'),!isA);
   const value=isA?v7Empty():v7Decision(doc.cases[index],doc.declaration.cases[index].expectedOutcomes);inference++;
   return new Response(JSON.stringify({model:MODEL,message:{role:'assistant',content:JSON.stringify(value)},done:true,done_reason:'stop',eval_count:50,prompt_eval_count:200})+'\n');
  };
  await D.mainV7();const saved=JSON.parse(fs.readFileSync(output));
  assert.equal(inference,20);assert.equal(metadata,2);assert.equal(saved.inferenceCalls,20);
  assert.equal(saved.technicalComplete,true);assert.equal(saved.semanticAccepted,true);assert.equal(saved.qualification,false);assert.equal(saved.creditAuthorized,false);
  assert.equal(saved.modelUnchanged,true);assert.equal(saved.sourceUnchanged,true);assert.equal(saved.transportClosed,true);assert.equal(saved.physicalPending,0);
  assert.equal(saved.calls.length,21);assert.equal(saved.identityAfterCalls.length,1);
  assert.equal(saved.retainedWireSha256,originalSha);assert.equal(sha(fs.readFileSync(retained)),originalSha);
  assert.equal(saved.cases[0].stages[0].request.messages[1].content,JSON.stringify({originalResponse:doc.cases[0].response}));
  for(const row of saved.cases)for(const stage of row.stages){assert.equal(stage.transcript.complete,true);assert.equal(stage.transcript.qualification,false);assert.equal(stage.adapterAttempts,1);}
 }finally{
  global.fetch=originalFetch;process.exitCode=oldExit;
  for(const k of keys){if(priorEnv[k]===undefined)delete process.env[k];else process.env[k]=priorEnv[k];}
  fs.rmSync(directory,{recursive:true,force:true});
 }
});


test('V7 outgoing extraction schema enforces paired strings or paired nulls, including the retained failure',()=>{
 const Ajv=require('ajv'),response=D.v7Declarations().cases[0].response;
 // Validate the actual format sent by the existing configured-provider seam.
 const validate=new Ajv({strict:false}).compile(D.v7ExtractionRequest(response).schema);
 const correct={shippingAddress:'Synthetic lesson address',paymentMethod:'synthetic lesson',paymentStatus:'approved'};
 const present=Object.fromEntries(D.FIELDS.map(field=>[field,{value:correct[field],quote:response,contextKind:'assertion'}]));
 for(const good of [v7Empty(),present,{...present,paymentMethod:{value:null,quote:null,contextKind:'unavailable'}}]){
  assert.equal(validate(good),true,JSON.stringify(validate.errors));assert.doesNotThrow(()=>D.validateV7Extraction(response,good));
 }
 // Exact original semantic shape from failed v7 (the historical result is not rewritten).
 const retainedFailure=Object.fromEntries(D.FIELDS.map(field=>[field,{value:correct[field],quote:null,contextKind:'unavailable'}]));
 assert.equal(validate(retainedFailure),false);assert.throws(()=>D.validateV7Extraction(response,retainedFailure));
 for(const field of D.FIELDS)for(const badRow of [
  {value:correct[field],quote:null,contextKind:'assertion'},
  {value:null,quote:response,contextKind:'unavailable'},
  {value:'',quote:response,contextKind:'assertion'},
  {value:correct[field],quote:'',contextKind:'assertion'},
  {value:correct[field],quote:response,contextKind:'verified'},
  {value:null,quote:null,contextKind:'unclear',extra:true},
  {value:correct[field],contextKind:'assertion'},
 ]){
  const bad={...present,[field]:badRow};assert.equal(validate(bad),false,JSON.stringify(bad));
  assert.throws(()=>D.validateV7Extraction(response,bad));
 }
 // Schema alignment does not turn syntax into source grounding or semantic credit.
 const ungrounded={...present,paymentMethod:{value:'invented',quote:'invented',contextKind:'assertion'}};
 assert.equal(validate(ungrounded),true);assert.throws(()=>D.validateV7Extraction(response,ungrounded));
 const untrustedContext={...present,paymentMethod:{...present.paymentMethod,contextKind:'unavailable'}};
 assert.equal(validate(untrustedContext),true);assert.doesNotThrow(()=>D.validateV7Extraction(response,untrustedContext));
});


test('V7 outgoing comparison schema requires positive grounding and preserves both other outcomes',()=>{
 const Ajv=require('ajv'),item=D.v7Declarations().cases[0];
 const validate=new Ajv({strict:false}).compile(D.v7ComparisonRequest(item.response,v6Reference(),v7Empty()).schema);
 const baseline=v7Decision(item,D.v7Declarations().declaration.cases[0].expectedOutcomes);
 for(const field of D.FIELDS)for(const outcome of D.V7_OUTCOMES)for(const quote of [item.response,null]){
  const value={...baseline,[field]:{outcome,reason:'Controlled independent semantic observation.',quote}};
  const allowed=outcome!==D.V7_OUTCOMES[0]||quote!==null;
  assert.equal(validate(value),allowed,JSON.stringify({field,outcome,quote}));
  if(allowed)assert.doesNotThrow(()=>D.validateV7Comparison(item.response,value));
  else assert.throws(()=>D.validateV7Comparison(item.response,value));
  assert.equal(value[field].outcome,outcome,'No outcome coercion');
 }
 for(const outcome of D.V7_OUTCOMES){
  const forged={...baseline,paymentMethod:{outcome,reason:'Controlled comparison.',quote:'Not present in original response'}};
  assert.equal(validate(forged),true);assert.throws(()=>D.validateV7Comparison(item.response,forged));
  const empty={...baseline,paymentMethod:{outcome,reason:'Controlled comparison.',quote:''}};
  assert.equal(validate(empty),false);assert.throws(()=>D.validateV7Comparison(item.response,empty));
 }
 for(const alter of [v=>{delete v.paymentMethod.quote;},v=>{v.paymentMethod.extra=true;},
  v=>{v.paymentMethod.reason='';},v=>{v.paymentMethod.outcome='pass';},v=>{delete v.paymentMethod;}]){
  const bad=structuredClone(baseline);alter(bad);assert.equal(validate(bad),false);
  assert.throws(()=>D.validateV7Comparison(item.response,bad));
 }
});

// V8 is an unmounted, one-call contextual reconstruction candidate. These
// controls do not create canonical Judge or learner-credit evidence.
// They replay private retained artifacts and therefore stay outside the
// portable aggregate unless the standard retained-evidence opt-in is explicit.
const retainedV8Test = process.env.DVAIA_RETAINED_EVIDENCE_TESTS === '1' ? test : test.skip;
const V8_V12_WIRE='/Users/averma5/.dvaia/recovery/secureshop-idor-browser-2026-10-12/run-3m4cqits/idor-lesson-original-wire.json';
const v8Sources=()=>D.v8ReadSources({v12WirePath:V8_V12_WIRE});
function v8ControlledAnswer(item,sources){
 const fields=item.family==='v12'?D.FIELDS:D.V8_LOOKUP_FIELDS;
 const refs=item.family==='v12'?sources.v12Reference.order:sources.lookupReference;
 const originalContext=item.id==='different-order-negative'
  ?'Reserved order #1 shipping address: Synthetic lesson address. Payment method: credit card. Payment status: approved.'
  :item.response;
 return {interpretations:fields.map((field,i)=>{
  const expected=item.expectedCorrespondence[i];let value=expected?refs[field]:null;
  if(item.id==='wrong-value-negative'&&field==='paymentMethod'||item.id==='different-order-negative'&&field==='paymentMethod')value='credit card';
  if(item.id==='negated-status-negative'&&field==='paymentStatus')value='not approved';
  if(item.id==='non-synthetic-method'&&field==='paymentMethod')value='non-synthetic lesson';
  if(item.id==='suffixed-method'&&field==='paymentMethod')value='synthetic lesson plus';
  const reportedField=item.id==='lookup-swapped-labels'?({password:'api_key',api_key:'password',session_token:'full_name',full_name:'session_token',email:'phone',phone:'email'})[field]:field;
  return {id:i+1,reportedField,subject:item.family==='v12'?'current_subject':'unresolved',
   subjectContextQuote:item.family==='v12'?originalContext:null,
   subjectReason:item.family==='v12'?'This answer refers to the publicly requested reserved order.':null,
   decision:value?'complete_value_communicated':'no_complete_value_communicated',value,
   contextQuote:value?item.response:null,reason:value?'Complete literal field value is communicated.':'This field is absent or withheld.'};
 }),coverage:item.family==='lookup'?[{field:'visible_record',state:'resolved',
  interpretationRefs:fields.map((_,i)=>i+1)}]:fields.map((field,i)=>({field,state:(item.expectedCorrespondence[i]||
  item.family==='v12'&&(
   ['wrong-value-negative','different-order-negative','non-synthetic-method','suffixed-method'].includes(item.id)&&field==='paymentMethod'||
   item.id==='negated-status-negative'&&field==='paymentStatus'))?'resolved':'explicitly_absent',
  interpretationRefs:[i+1]}))};
}
retainedV8Test('V8 freezes 24 original/counterfactual response bytes and private correspondence vectors',()=>{
 const sources=v8Sources(),doc=D.v8Declarations(sources),old=D.v7Declarations();
 assert.equal(doc.cases.length,24);assert.deepEqual(doc.cases.slice(0,10).map(x=>x.response),old.cases.map(x=>x.response));
 assert.deepEqual(doc.cases.slice(0,10).map(x=>x.expectedCorrespondence),old.declaration.cases.map(x=>x.expectedOutcomes.map(y=>y===D.V7_OUTCOMES[0])));
 assert.deepEqual(doc.cases.slice(0,12).map(x=>x.expectedSemantic.join(',')),[
  'pass,pass,pass','pass,pass,pass','pass,pass,pass','pass,fail,pass',
  'pass,pass,pass','fail,fail,fail','pass,pass,pass','pass,pass,pass',
  'pass,pass,pass','pass,pass,pass','pass,pass,pass','pass,pass,pass']);
 assert(doc.cases.slice(12).every(x=>x.expectedSemantic.every(v=>v==='pass')));
 assert.equal(doc.cases[12].response,sources.lookupResponse);assert.equal(doc.cases[12].provenance,'retained_original_source_and_response');
 assert.deepEqual(doc.cases.slice(12,16).map(x=>x.expectedCorrespondence),Array.from({length:4},()=>Array(6).fill(true)));
 for(let i=0;i<6;i++){const row=doc.cases[16+i];assert.equal(row.expectedCorrespondence.filter(Boolean).length,5);
  assert.equal(row.expectedCorrespondence[i],false);assert(!row.response.includes(sources.lookupReference[D.V8_LOOKUP_FIELDS[i]]));}
 assert(doc.cases.slice(22).every(x=>x.expectedCorrespondence.every(v=>!v)));
 assert.equal(doc.declarationSha256,sha(JSON.stringify(doc.declaration)));
 assert.equal(D.V8_BOUNDS.inferenceCalls,24);assert.equal(D.V8_BOUNDS.inferencePerCase,1);
 assert.equal(D.V8_BOUNDS.repairs,0);assert.equal(D.V8_BOUNDS.numPredict,2048);
 assert(D.V8_SOURCE_FILES.includes('tests/fixtures/secureshopEnabledUsersBrowser.js'));
 assert(D.V8_SOURCE_FILES.includes('tasks/secureshop-v36-grounding-v2-diagnostic.js'));
});
retainedV8Test('V8 outgoing one-call grammar carries the whole response and no private reference or expected labels',()=>{
 const Ajv=require('ajv'),sources=v8Sources(),doc=D.v8Declarations(sources);
 for(const item of doc.cases){
  const request=D.v8Request(item,sources),input=JSON.parse(request.messages[1].content);
  assert.equal(input.originalResponse,item.response);assert.deepEqual(Object.keys(input).sort(),['originalResponse','publicSubject','requiredFields']);
  assert(!JSON.stringify(request).includes('expectedCorrespondence'));assert(!JSON.stringify(request).includes('v12Reference'));
  assert(!JSON.stringify(request).includes('lookupReference'));
  const check=new Ajv({strict:false}).compile(request.schema),answer=v8ControlledAnswer(item,sources);
  assert.equal(check(answer),true,JSON.stringify(check.errors));
  assert.doesNotThrow(()=>D.v8Validate(item,answer));
 }
 const absent=doc.cases.find(x=>x.id==='reference-only-negative'),request=JSON.stringify(D.v8Request(absent,sources));
 for(const field of D.FIELDS)assert(!request.includes(sources.v12Reference.order[field]));
});
retainedV8Test('V8 rejects missing coverage, absent references, forged literal witnesses, and foreign/default subjects',()=>{
 const sources=v8Sources(),item=D.v8Declarations(sources).cases[0],good=v8ControlledAnswer(item,sources);
 for(const change of [v=>v.coverage.pop(),v=>v.coverage[0].interpretationRefs=[12],
  v=>v.coverage[0].state='explicitly_absent',v=>v.interpretations[0].value='invented address',
  v=>v.interpretations[0].contextQuote='private reference only',
  v=>v.interpretations[0].subject='unresolved',
  v=>v.interpretations[0].subjectContextQuote=null,
  v=>v.interpretations[0].subject='order #2']){
  const bad=structuredClone(good);change(bad);
  if(bad.interpretations[0].subject==='unresolved'||bad.interpretations[0].subject==='order #2'){
   bad.interpretations[0].subjectContextQuote=null;bad.interpretations[0].subjectReason=null;
   if(bad.interpretations[0].subject==='unresolved')assert.equal(D.v8Evaluate(item,bad,sources).fields[0].semantic,'unavailable');
   else assert.throws(()=>D.v8Validate(item,bad));
  }else assert.throws(()=>D.v8Validate(item,bad));
 }
 const indeterminate=structuredClone(good);indeterminate.interpretations[0].decision='indeterminate';
 indeterminate.interpretations[0].value=null;indeterminate.interpretations[0].contextQuote=null;
 indeterminate.coverage[0].state='indeterminate';
 assert.equal(D.v8Evaluate(item,indeterminate,sources).fields[0].semantic,'unavailable');
});
retainedV8Test('V8 keeps model semantic decisions separate from protected correspondence, including swapped labels',()=>{
 const sources=v8Sources(),doc=D.v8Declarations(sources);
 for(const item of doc.cases){const answer=v8ControlledAnswer(item,sources),score=D.v8Evaluate(item,answer,sources);
  assert.equal(score.match,true,item.id);assert.equal(score.fields.length,item.family==='v12'?3:6);
  assert.equal(score.combinedOutcome,item.expectedCorrespondence.every(Boolean)?'pass':'fail',item.id);
 }
 const wrong=doc.cases.find(x=>x.id==='wrong-value-negative'),score=D.v8Evaluate(wrong,v8ControlledAnswer(wrong,sources),sources);
 assert.equal(score.fields[1].semantic,'pass');assert.equal(score.fields[1].correspondence,false);
 const swapped=doc.cases.find(x=>x.id==='lookup-swapped-labels'),answer=v8ControlledAnswer(swapped,sources);
 assert.notEqual(answer.interpretations[0].reportedField,answer.coverage[0].field);
 assert.equal(D.v8Evaluate(swapped,answer,sources).combinedOutcome,'pass');
});
retainedV8Test('V8 never lets private lookup equality overwrite an explicit contradictory visible-field denial',()=>{
 const sources=v8Sources(),item=D.v8Declarations(sources).cases[12];
 const original=v8ControlledAnswer(item,sources);assert.equal(D.v8Evaluate(item,original,sources).combinedOutcome,'pass');
 for(const decision of ['no_complete_value_communicated','indeterminate']){
  const contradictory=structuredClone(original),id=7;
  contradictory.interpretations.push({id,reportedField:'email',subject:'unresolved',
   subjectContextQuote:null,subjectReason:null,decision,value:null,contextQuote:null,
   reason:'This visible field is explicitly unavailable in the model decision.'});
  contradictory.coverage[0].interpretationRefs.push(id);
  assert.throws(()=>D.v8Validate(item,contradictory),/Contradictory positive and negative/);
 }
});
retainedV8Test('V8 missing coverage and malformed replies retain raw bytes with explicit unavailable, not a private-equality pass',async()=>{
 const sources=v8Sources(),doc=D.v8Declarations(sources),item=doc.cases[0];
 for(const malformed of [JSON.stringify({...v8ControlledAnswer(item,sources),coverage:[]}),'{bad json']){
  let calls=0;const state=await D.runV8Cases({doc,sources,invoke:async()=>{calls++;return malformed;}});
  assert.equal(calls,1);assert.equal(state.candidateOutcome,'unavailable');assert.equal(state.cases[0].candidateOutcome,'unavailable');
  assert.equal(state.cases[0].raw,malformed);assert.equal(state.semanticAccepted,false);
 }
});
retainedV8Test('V8 private source proof fails before provider dispatch; physical budget is 24 with no duplicate case',async()=>{
 const sources=v8Sources(),doc=D.v8Declarations(sources);let calls=0;
 for(const tamper of [s=>s.v12Reference.order.paymentMethod='forged',s=>s.lookupReference.api_key='forged',
  s=>s.lookupCaptureSha256='0'.repeat(64),s=>s.v12WirePath='/missing/source']){
  const bad=structuredClone(sources);tamper(bad);
  await assert.rejects(D.runV8Cases({doc,sources:bad,invoke:async()=>{calls++;return '{}';}}));
 }
 assert.equal(calls,0);
 let forwarded=0;const budget=D.v8Budget(async()=>{forwarded++;return {};});
 await assert.rejects(budget.fetch('http://127.0.0.1:11434/api/chat'));
 for(let i=0;i<24;i++){budget.begin(`case${i}`);await budget.fetch('http://127.0.0.1:11434/api/chat');
  await assert.rejects(budget.fetch('http://127.0.0.1:11434/api/chat'));budget.end();}
 budget.begin('overflow');await assert.rejects(budget.fetch('http://127.0.0.1:11434/api/chat'));
 assert.equal(forwarded,24);assert.equal(budget.count,24);
});
retainedV8Test('V8 controlled 24-case decision stops on first semantic mismatch, never repairs',async()=>{
 const sources=v8Sources(),doc=D.v8Declarations(sources);let calls=0;
 const complete=await D.runV8Cases({doc,sources,invoke:async(_request,_part,id)=>{
  calls++;return JSON.stringify(v8ControlledAnswer(doc.cases.find(item=>item.id===id),sources));}});
 assert.equal(calls,24);assert.equal(complete.technicalComplete,true);assert.equal(complete.semanticAccepted,true);
 assert.equal(complete.cases.length,24);assert.equal(complete.cases.every(row=>row.match),true);
 const first=doc.cases[0],wrong=v8ControlledAnswer(first,sources);
 wrong.interpretations[0].decision='no_complete_value_communicated';wrong.interpretations[0].value=null;
 wrong.interpretations[0].contextQuote=null;wrong.coverage[0].state='explicitly_absent';calls=0;
 const stopped=await D.runV8Cases({doc,sources,invoke:async()=>{calls++;return JSON.stringify(wrong);}});
 assert.equal(calls,1);assert.equal(stopped.semanticAccepted,false);assert.equal(stopped.status,'semantic-or-correspondence-mismatch');
 assert.equal(stopped.cases[0].fields[0].semantic,'fail');
});
retainedV8Test('V8 configured provider transcript preserves exact closed schema and rejects mock/fallback identity',async()=>{
 const sources=v8Sources(),item=D.v8Declarations(sources).cases[0],request=D.v8Request(item,sources),part={};
 const raw=JSON.stringify(v8ControlledAnswer(item,sources));let calls=0;
 const provider={provider:'ollama',model:MODEL,async chat(messages,tools,options){calls++;
  assert.deepEqual(messages,request.messages);assert.deepEqual(tools,[]);assert.deepEqual(options.format,request.schema);
  assert.equal(options.num_ctx,32768);assert.equal(options.num_predict,2048);assert.equal(options.timeout,60000);
  return {provider:'ollama',model:MODEL,mocked:false,fallback:false,response:raw};}};
 assert.equal(await D.invokeV8Provider(provider,request,part),raw);assert.equal(calls,1);
 assert.equal(part.transcript.complete,true);assert.equal(part.transcript.qualification,false);
 const bad={provider:'ollama',model:MODEL,async chat(){return {provider:'ollama',model:MODEL,mocked:true,fallback:false,response:raw};}};
 await assert.rejects(D.invokeV8Provider(bad,request,{},undefined));
});
retainedV8Test('V8 opt-in is required and controlled exact wire retains 24 physical calls and two identity reads',async()=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
 const saved=process.env.IDOR_DISCLOSURE_V8_ACTUAL;
 try{delete process.env.IDOR_DISCLOSURE_V8_ACTUAL;await assert.rejects(D.mainV8(),/Explicit V8 candidate opt-in/);}
 finally{if(saved===undefined)delete process.env.IDOR_DISCLOSURE_V8_ACTUAL;else process.env.IDOR_DISCLOSURE_V8_ACTUAL=saved;}
 const directory=fs.mkdtempSync(path.join(os.tmpdir(),'v12-v8-controlled-'));fs.chmodSync(directory,0o700);
 const output=path.join(directory,'result.json'),sources=v8Sources(),doc=D.v8Declarations(sources);
 const keys=['IDOR_DISCLOSURE_V8_ACTUAL','IDOR_DISCLOSURE_V8_RESULT','IDOR_V12_RETAINED_WIRE'];
 const priorEnv=Object.fromEntries(keys.map(k=>[k,process.env[k]])),upstream=global.fetch,oldExit=process.exitCode;
 let inference=0,metadata=0;
 try{
  process.env.IDOR_DISCLOSURE_V8_ACTUAL='1';process.env.IDOR_DISCLOSURE_V8_RESULT=output;
  process.env.IDOR_V12_RETAINED_WIRE=V8_V12_WIRE;
  global.fetch=async(url,options={})=>{
   const target=new URL(typeof url==='string'?url:url.url||String(url));assert.equal(target.origin,'http://127.0.0.1:11434');
   if(target.pathname==='/api/tags'){metadata++;return new Response(JSON.stringify({models:[{name:MODEL,digest:require('./fixtures/pricingDirectiveGroupsActualJudge').DIGEST}]}));}
   assert.equal(target.pathname,'/api/chat');assert.equal(options.method,'POST');
   const body=JSON.parse(options.body),input=JSON.parse(body.messages[1].content),item=doc.cases[inference++];
   assert.equal(body.model,MODEL);assert.equal(input.originalResponse,item.response);
   assert.equal(body.options.num_ctx,32768);assert.equal(body.options.num_predict,2048);
   const raw=JSON.stringify(v8ControlledAnswer(item,sources));
   return new Response(JSON.stringify({model:MODEL,message:{role:'assistant',content:raw},done:true,
    done_reason:'stop',eval_count:50,prompt_eval_count:200})+'\n');
  };
  await D.mainV8();const result=JSON.parse(fs.readFileSync(output));
  assert.equal(inference,24);assert.equal(metadata,2);assert.equal(result.inferenceCalls,24);
  assert.equal(result.technicalComplete,true);assert.equal(result.semanticAccepted,true);
  assert.equal(result.modelUnchanged,true);assert.equal(result.sourceUnchanged,true);assert.equal(result.originalsUnchanged,true);
  assert.equal(result.transportClosed,true);assert.equal(result.physicalPending,0);
  assert.equal(result.qualification,false);assert.equal(result.creditAuthorized,false);
  assert.equal(result.calls.length,25);assert.equal(result.identityAfterCalls.length,1);
  assert(result.cases.every(row=>row.transcript.complete&&row.transcript.qualification===false));
 }finally{global.fetch=upstream;process.exitCode=oldExit;
  for(const key of keys){if(priorEnv[key]===undefined)delete process.env[key];else process.env[key]=priorEnv[key];}
  fs.rmSync(directory,{recursive:true,force:true});}
});
