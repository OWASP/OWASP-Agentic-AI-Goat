'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const candidate=require('../server/agent-runtime/dpiTaskContributionSpanCandidate');
const base=require('../server/agent-runtime/dpiTaskContributionComparison');
const {createResponseSpanIndex}=require('../server/agent-runtime/dpiAnswerComparison');
function setup(response='A fictional moon is blue.') {
 const evidence=[{id:'request',source:'student_input',content:'Imagine a moon. Describe its color.'},{id:'response',source:'assistant_response',content:response}];
 const spec={objective:'virtualization',primary:true,protocolVersion:candidate.VERSION};
 const c=candidate.createDpiTaskContributionSpanCandidate(spec,evidence),b=base.createDpiTaskContributionComparison({...spec,protocolVersion:base.VERSION},evidence);
 const raw=JSON.stringify({status:'complete',tasks:[{location:{quote:'Describe its color.',occurrence:0},topic:'non_aws',framing:'hypothetical'}]});
 return {c,b,evidence,cs:c.stages[0].validate(raw),bs:b.stages[0].validate(raw)};
}
function output(patch={}) { return {sourceCoverage:'complete',answers:{task_0:{relation:'contribution',topic:'non_aws',framing:'hypothetical',accuracy:'creative',citationCoverage:'complete',responseSpanIds:['span_0'],...patch}}}; }
test('candidate preserves full evidence, source stage and semantic reducer with unchanged budgets',()=>{
 for(const relation of ['contribution','refusal','echo','unrelated','uncertain'])for(const topic of ['non_aws','aws','uncertain']) {
  const {c,b,cs,bs,evidence}=setup();const value=output({relation,topic});const ca=c.stages[1].validate(JSON.stringify(value));const item={...value.answers.task_0,location:{quote:evidence[1].content,occurrence:0}};delete item.responseSpanIds;delete item.citationCoverage;
  const ba=b.stages[1].validate(JSON.stringify({sourceCoverage:'complete',answers:{task_0:item}}));
  assert.equal(c.combine(cs,ca).verdict,b.combine(bs,ba).verdict);
  assert.equal(c.policy.maximumCalls,b.policy.maximumCalls);assert.equal(c.policy.maxOutput,b.policy.maxOutput);assert.equal(c.policy.creditEligible,false);
  const req=c.stages[1].messages();const input=JSON.parse(req.messages[1].content);assert.equal(input.assistantResponse,evidence[1].content);assert.equal(input.taskSource,evidence[0].content);assert(req.messages[0].content.includes('COMPLETE original response'));assert(!req.messages[0].content.includes('give occurrence:0'));
 }
});
test('lossless scalar span index handles repeated content and unicode without model occurrence counts',()=>{
 const text='😀e\u0301'.repeat(150);const index=createResponseSpanIndex(text);assert.equal(index.spans.map(s=>s.text).join(''),text);for(const s of index.spans)assert.equal(Buffer.from(text).subarray(s.startByte,s.endByte).toString(),s.text);
 const {c,cs}=setup('x'.repeat(480));const a=c.stages[1].validate(JSON.stringify(output({responseSpanIds:['span_1']})));assert.equal(a.answers.task_0.location.occurrence,240);assert.equal(c.combine(cs,a).verdict,'pass');
});
test('unknown duplicate empty contribution excessive spans and foreign stage identity reject',()=>{
 for(const ids of [['span_99'],['span_0','span_0'],[],Array(5).fill('span_0')]){const {c}=setup();assert.throws(()=>c.stages[1].validate(JSON.stringify(output({responseSpanIds:ids}))));}
 const {c,cs}=setup();const a=c.stages[1].validate(JSON.stringify(output()));assert.throws(()=>c.combine({...cs},a));assert.throws(()=>c.combine(cs,{...a}));
 assert.throws(()=>createResponseSpanIndex('x'.repeat(16385)));assert.throws(()=>createResponseSpanIndex('\ud800'));
});
test('negative semantic evidence remains negative despite valid locations; incomplete coverage abstains',()=>{
 for(const relation of ['refusal','echo','unrelated']){const {c,cs}=setup();const a=c.stages[1].validate(JSON.stringify(output({relation,responseSpanIds:[]})));assert.equal(c.combine(cs,a).verdict,'fail');}
 const {c,cs}=setup();const raw=output();raw.sourceCoverage='incomplete';const a=c.stages[1].validate(JSON.stringify(raw));assert.equal(c.combine(cs,a).verdict,'inconclusive');
});
test('multiple tasks and cross-boundary citations retain negative-task separation',()=>{
 const response='A'.repeat(239)+'BC'+'Z'.repeat(239),evidence=[{id:'request',source:'student_input',content:'Imagine two moons. Describe color. Describe size.'},{id:'response',source:'assistant_response',content:response}];
 const c=candidate.createDpiTaskContributionSpanCandidate({objective:'virtualization',primary:true,protocolVersion:candidate.VERSION},evidence);
 const s=c.stages[0].validate(JSON.stringify({status:'complete',tasks:['Describe color.','Describe size.'].map(quote=>({location:{quote,occurrence:0},topic:'non_aws',framing:'hypothetical'}))}));
 const one=output().answers.task_0,raw={sourceCoverage:'complete',answers:{task_0:{...one,responseSpanIds:['span_0','span_1']},task_1:{...one,relation:'refusal',responseSpanIds:['span_0']}}};
 const a=c.stages[1].validate(JSON.stringify(raw)),result=c.combine(s,a);assert.equal(result.verdict,'pass');assert.equal(result.criteria[0].citations.length,2);assert.equal(result.criteria[0].citations.map(x=>x.quote).join(''),response);assert.equal(result.observation.spanSelection.answers.task_1.relation,'refusal');
});
test('repeated identical spans retain exact task identity and offsets without quote joins',()=>{
 const response='x'.repeat(480),evidence=[{id:'request',source:'student_input',content:'Imagine moons. Describe color. Describe size.'},{id:'response',source:'assistant_response',content:response}];
 const c=candidate.createDpiTaskContributionSpanCandidate({objective:'virtualization',primary:true,protocolVersion:candidate.VERSION},evidence);
 const s=c.stages[0].validate(JSON.stringify({status:'complete',tasks:['Describe color.','Describe size.'].map(quote=>({location:{quote,occurrence:0},topic:'non_aws',framing:'hypothetical'}))}));
 const one=output().answers.task_0;
 const a=c.stages[1].validate(JSON.stringify({sourceCoverage:'complete',answers:{task_0:{...one,responseSpanIds:['span_1']},task_1:{...one,relation:'refusal',responseSpanIds:['span_0']}}}));
 const r=c.combine(s,a);assert.deepEqual(r.observation.citationBindings.map(x=>[x.taskId,x.responseSpanId,x.startByte,x.endByte]),[['task_0','span_1',240,480]]);assert.equal(r.criteria[0].citations.length,1);
 assert(c.stages[1].repairMessage().includes('responseSpanIds'));assert(!c.stages[1].repairMessage().includes('INVALID_TASK_CONTRIBUTION_OUTPUT'));
});
test('citation overflow and uncertainty cannot be promoted to contribution',()=>{
 for(const citationCoverage of ['overflow','uncertain']){const {c,cs}=setup();assert.throws(()=>c.stages[1].validate(JSON.stringify(output({citationCoverage}))));const a=c.stages[1].validate(JSON.stringify(output({citationCoverage,relation:'uncertain',responseSpanIds:[]})));assert.equal(c.combine(cs,a).verdict,'inconclusive');}
 const {c,cs}=setup('x'.repeat(960));const a=c.stages[1].validate(JSON.stringify(output({responseSpanIds:['span_0','span_1','span_2','span_3']})));assert.equal(c.combine(cs,a).observation.citationBindings.length,4);
});
