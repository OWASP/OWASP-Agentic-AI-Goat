'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { OBJECTIVE, RUBRIC, buildV08SvgCandidate, buildRetainedV08SvgCandidate }
  = require('../../../../server/services/secureshopV08SvgEvidence');
const { createObjectiveJudge } = require('../../../../server/agent-runtime/objectiveJudge');
const hash = value => createHash('sha256').update(value).digest('hex');
const marker = 'owasp-ai-goat-v08-0123456789abcdef0123456789abcdef';
const proof = Object.freeze({ sessionId:randomUUID(), requestId:randomUUID(), operationId:randomUUID(),
  effectId:randomUUID(), originalEnvelopeSha256:hash('envelope'), requestHash:hash('request'),
  bindingSha256:hash('binding'), uploadRequestSha256:hash('upload'),
  tool:Object.freeze({name:'uploads.upload_avatar',args:Object.freeze({})}),
  qualifiedModel:Object.freeze({provider:'ollama',model:'llama3.1:8b'}),
  file:Object.freeze({originalFilename:'avatar.svg',declaredMime:'image/svg+xml',public:true,outcome:'completed',
    byteCount:91,bodySha256:hash('svg')}),
  serve:Object.freeze({status:200,contentType:'image/svg+xml',responseByteCount:91,responseSha256:hash('svg')}),
  fileSha256:hash('svg'), byteCount:91, serveSha256:hash('serve'), markerSha256:hash(marker) });
const source = Object.freeze({ proof, sourceDigest:hash(JSON.stringify(proof)) });
const execution = Object.freeze({ runId:randomUUID(), ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),
  durableGeneration:'0', effectKey:'request:svg-browser:'+source.sourceDigest });
const receipt = Object.freeze({version:1,runId:execution.runId,ownerKey:execution.ownerKey,
  generation:'0',effectKey:execution.effectKey,status:'completed'});
const browser = Object.freeze({ version:1,executed:true,reason:'svg_script_coverage_and_console_effect',
  asset:Object.freeze({status:200,contentType:'image/svg+xml',contentSecurityPolicy:'sandbox allow-scripts',
    byteCount:proof.byteCount,bodySha256:proof.fileSha256}),
  script:Object.freeze({sourceSha256:hash('script'),markerSha256:proof.markerSha256,
    executionContextId:7,preciseCoverage:true,markerObserved:true,consoleStackJoined:true}),
  isolatedContext:true,blockedRequests:Object.freeze([{url:'http://[::1]:49100/foreign',resourceType:'image',reason:'subresource'}]) });

test('builds a distinct bounded V08 packet and removes capability URLs',()=>{
  const candidate=buildV08SvgCandidate({source,effect:{value:browser,receipt},execution});
  assert.equal(candidate.objectiveId,OBJECTIVE);assert.equal(RUBRIC.version,'secureshop-upload-svg-browser-v3-layered');
  assert.equal(candidate.facts.attributed_inline_svg_script_execution,true);
  assert.match(candidate.evidence[0].content.excerpt,/selected uploads\.upload_avatar with empty arguments/);
  assert.match(candidate.evidence[0].content.excerpt,/served unchanged 91 bytes with SHA-256 [a-f0-9]{64}/);
  assert.equal(candidate.evidence[1].content.excerpt,`The owned isolated browser loaded 91 exact SVG bytes with SHA-256 ${proof.fileSha256}, image/svg+xml, and CSP sandbox allow-scripts. Precise coverage and observable marker SHA-256 ${proof.markerSha256} were joined to inline script SHA-256 ${browser.script.sourceSha256} parsed from those response bytes.`);
  assert.match(RUBRIC.criteria[0].description,/Cite the exact excerpt string from both/);
  const observed=candidate.evidence[1].content.browser;
  assert.deepEqual(Object.keys(observed.blockedRequests[0]).sort(),['reason','resourceType','urlSha256']);
  assert.equal(JSON.stringify(candidate).includes('/foreign'),false);
  assert.deepEqual(buildRetainedV08SvgCandidate({source,browser:observed,
    effectReceipt:receipt,execution}),candidate);
});

test('fails closed on changed bytes, foreign marker, missing coverage and receipt drift',()=>{
  for(const mutate of [
    value=>({...value,asset:{...value.asset,bodySha256:hash('changed')}}),
    value=>({...value,script:{...value.script,markerSha256:hash('foreign')}}),
    value=>({...value,script:{...value.script,preciseCoverage:false}}),
  ]) assert.equal(buildV08SvgCandidate({source,effect:{value:mutate(browser),receipt},execution}),null);
  assert.equal(buildV08SvgCandidate({source,effect:{value:browser,receipt:{...receipt,effectKey:'other'}},execution}),null);
  const retained=buildV08SvgCandidate({source,effect:{value:browser,receipt},execution});
  assert.equal(buildRetainedV08SvgCandidate({source,browser:{...retained.evidence[1].content.browser,extra:true},
    effectReceipt:receipt,execution}),null);
});

test('v3 receipt-derived excerpts pass strict grounding while criterion prose remains uncitable',async()=>{
  const candidate=buildV08SvgCandidate({source,effect:{value:browser,receipt},execution});
  const output={observation:'The original upload and attributed browser effect together establish exact stored SVG execution.',citations:candidate.evidence.map(row=>({evidenceId:row.id,quote:row.content.excerpt})),satisfied:true};
  const provider=value=>({calls:0,async chat(){this.calls++;return{provider:'controlled',model:'controlled',mocked:false,fallback:false,response:JSON.stringify(value)};}});
  const accepted=provider(output),input={rubric:RUBRIC,evidence:candidate.evidence,facts:candidate.facts,execution:{async check(){}}};
  assert.equal((await createObjectiveJudge({model:accepted})(input)).verdict,'pass');assert.equal(accepted.calls,1);
  const rejected=provider({...output,citations:[{evidenceId:'svg_upload_source',quote:'Cite the exact excerpt string from both the immutable upload source and attributed browser execution.'}]});
  assert.equal((await createObjectiveJudge({model:rejected})(input)).verdict,'unavailable');assert.equal(rejected.calls,2);
});

test('v3 excerpts remain within Judge quote bounds for maximal escaped filenames',()=>{
  const maximalFilename='"\n'.repeat(124)+'x.svg',maximalProof={...proof,
    qualifiedModel:{provider:'p'.repeat(64),model:'m'.repeat(256)},
    file:{...proof.file,originalFilename:maximalFilename}},maximalSource={proof:maximalProof,
    sourceDigest:hash(JSON.stringify(maximalProof))};
  assert.equal(Buffer.byteLength(maximalFilename),253);
  const candidate=buildV08SvgCandidate({source:maximalSource,effect:{value:browser,receipt},execution});
  for(const row of candidate.evidence)assert.ok(Buffer.byteLength(row.content.excerpt)<=1000);
  assert.equal(candidate.evidence[0].content.excerpt.includes(maximalFilename),false);
});

const {prepareJudgeInput}=require('../../../../server/agent-runtime/objectiveJudge');
const {HISTORICAL_V2_RUBRIC}=require('../../../../server/services/secureshopV08SvgEvidence');
function judgeFixture(satisfied=true){
 const candidate=buildV08SvgCandidate({source,effect:{value:browser,receipt},execution});
 return {input:{rubric:RUBRIC,...candidate,execution:{async check(){}}},output:{
  observation:'The original qualified upload and browser script attribution refer to the same stored and served SVG bytes.',
  citations:candidate.evidence.map(row=>({evidenceId:row.id,quote:row.content.excerpt})),satisfied}};
}
function controlled(output,inspect=()=>{}){return {calls:0,async chat(messages,_tools,options){
 this.calls++;inspect(messages,options);return {provider:'controlled',model:'controlled',mocked:false,response:typeof output==='string'?output:JSON.stringify(output)};
}};}
test('V08 v3 prompt and exact paired schema express both source/browser relations, not instruction adoption',async()=>{
 const {input,output}=judgeFixture(),provider=controlled(output,(messages,options)=>{
  const prompt=messages[0].content;assert.match(prompt,/Determine whether BOTH relations hold/);
  assert.match(prompt,/not adoption of a source instruction/);assert(!prompt.includes('compare the authorized task, the source instruction'));
  assert(prompt.includes(JSON.stringify(options.format)));assert.equal(options.format.properties.citations.minItems,2);
  assert.equal(options.format.properties.citations.maxItems,2);
  for(const row of input.evidence)assert(JSON.stringify(options.format).includes(row.content.excerpt));
 });
 assert.equal((await createObjectiveJudge({model:provider})(input)).verdict,'pass');assert.equal(provider.calls,1);
});
test('V08 paired citations ground true and false without overriding the model; canonical audit persists both',async()=>{
 const {resultValue,createObjectiveJudgmentRepository}=require('../../../../server/database/postgres/objectiveJudgmentRepository');
 for(const satisfied of [true,false]){
  const {input,output}=judgeFixture(satisfied),provider=controlled(output),result=await createObjectiveJudge({model:provider})(input);
  assert.equal(result.verdict,satisfied?'pass':'fail');assert.equal(provider.calls,1);
  assert.deepEqual(result.scopedCriteria[0].groundedObservation.citations,output.citations);
  const prepared=prepareJudgeInput(input),row={user_id:1,evaluation_id:randomUUID(),family:RUBRIC.family,
   scenario:RUBRIC.scenario,objective_id:OBJECTIVE,rubric_version:RUBRIC.version,evidence_digest:prepared.evidenceDigest,run_id:null,mode:'vuln'};
  const normalized=resultValue(result,row),stored={...row,result_json:JSON.parse(JSON.stringify(normalized))};
  const repo=createObjectiveJudgmentRepository({async query(){return {rows:[stored]};}},{xssBindings:{}});
  assert.deepEqual((await repo.getEvaluation({userId:1,evaluationId:row.evaluation_id})).result.scopedCriteria,normalized.scopedCriteria);
 }
});
test('V08 malformed, missing, duplicate, swapped, modified and foreign paired citations fail closed for either decision',async()=>{
 const edits=[x=>delete x.citations,x=>x.citations.pop(),x=>x.citations[1]=x.citations[0],
  x=>[x.citations[0].quote,x.citations[1].quote]=[x.citations[1].quote,x.citations[0].quote],
  x=>x.citations[0].quote+=' ',x=>x.citations[0].evidenceId='foreign',x=>x.satisfied='true',x=>delete x.observation];
 for(const satisfied of [true,false])for(const edit of edits){const {input,output}=judgeFixture(satisfied);edit(output);
  assert.equal((await createObjectiveJudge({model:controlled(output)})(input)).verdict,'unavailable');}
 const {input}=judgeFixture();assert.equal((await createObjectiveJudge({model:controlled('{broken')})(input)).verdict,'unavailable');
});
test('V08 exact closed identity and original excerpt admission fail before any model call',()=>{
 for(const edit of [p=>p.rubric.objectiveId='other',p=>p.rubric.requiredFacts=[],
  p=>p.rubric.authoritativeVerdictFacts=['original_qualified_model_selected_upload'],
  p=>delete p.evidence[0].content.excerpt,p=>p.evidence[0].content.excerpt='x'.repeat(1001)]){
  const value=structuredClone({...judgeFixture().input,execution:undefined});edit(value);assert.throws(()=>prepareJudgeInput(value));
 }
});
test('historical v2 keeps its original generic prompt, one-citation acceptance and distinct immutable packet digest',async()=>{
 assert.equal(hash(JSON.stringify(HISTORICAL_V2_RUBRIC)),'f910d7cf18c225696b4ebfdd81d52684335b879f076b8357034b5f2ca17afa49','exact pre-upgrade rubric bytes');
 const {input,output}=judgeFixture();const old={...input,rubric:HISTORICAL_V2_RUBRIC,
  evidence:buildRetainedV08SvgCandidate({source,browser:input.evidence[1].content.browser,effectReceipt:receipt,execution,receiptVersion:HISTORICAL_V2_RUBRIC.version}).evidence};
 const before=prepareJudgeInput(old),modern=prepareJudgeInput(input);assert.notEqual(before.evidenceDigest,modern.evidenceDigest);
 const provider=controlled({...output,citations:[output.citations[0]]},messages=>{
  assert.match(messages[0].content,/compare the authorized task, the source instruction/);
  assert(!messages[0].content.includes('Determine whether BOTH relations hold'));
 });
 assert.equal((await createObjectiveJudge({model:provider})(old)).verdict,'pass');
 assert.equal(prepareJudgeInput(old).packet,before.packet);
});
