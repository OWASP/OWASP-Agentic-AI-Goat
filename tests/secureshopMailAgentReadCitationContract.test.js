'use strict';
// Controlled schema/provenance checks only; no configured model or credit.
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');
const {fixture}=require('./secureshopMailAgentReadEvidence.test');
const E=require('../server/services/secureshopMailAgentReadEvidence');
const {createObjectiveJudge,prepareJudgeInput}=require('../server/agent-runtime/objectiveJudge');
function control({satisfied=true,mutateOutput,repair=false}={}){
 const f=fixture(),execution={runId:randomUUID(),ownerKey:JSON.stringify(['SecureShopBoundConversation',randomUUID()]),durableGeneration:'0'};
 const candidate=E.buildMailAgentReadCandidate({source:f.source,qualifyModel:()=>true,execution});
 const input={rubric:E.RUBRIC,...candidate,execution},calls=[];let attempt=0;
 const judge=createObjectiveJudge({model:{async chat(messages,_tools,options){attempt++;const record=JSON.parse(messages[1].content).evidence[0];
  const output={observation:'The numeric caller and recipient differ, and the selected tool returned the saved message body.',
   citations:[{evidenceId:'mail_agent_read',quote:record.content.observation.observedBodyExcerpt}],satisfied};
  if(mutateOutput&&(!repair||attempt===1))mutateOutput(output,record);
  calls.push({messages,options,output:structuredClone(output)});
  return{provider:'controlled',model:'v11-citation-control',mocked:false,response:JSON.stringify(output)};
 }}});
 return{f,input,calls,run:()=>judge(input)};
}
test('V11 v3 transmits one exact raw body quote enum while observation and satisfied remain model-authored',async()=>{
 const c=control(),result=await c.run();assert.equal(result.verdict,'pass');assert.equal(c.calls.length,1);
 const properties=c.calls[0].options.format.properties;assert.equal(properties.satisfied.type,'boolean');
 assert.equal(properties.satisfied.const,undefined);assert.equal(properties.observation.type,'string');
 assert.equal(properties.citations.minItems,1);assert.equal(properties.citations.maxItems,1);
 assert.equal(properties.citations.items.properties.evidenceId.const,'mail_agent_read');
 assert.deepEqual(properties.citations.items.properties.quote.enum,[c.input.evidence[0].content.observation.observedBodyExcerpt]);
 assert.equal(result.criteria[0].citations[0].quote,c.input.evidence[0].content.observation.observedBodyExcerpt);
});
test('V11 v3 exact citation never forces semantic true',async()=>{
 const c=control({satisfied:false}),result=await c.run();assert.equal(result.verdict,'fail');
 assert.equal(result.criteria[0].satisfied,false);assert.equal(c.calls.length,1);
});
test('V11 v3 paraphrase, prefix, surplus and wrong evidence remain unavailable after bounded repair',async()=>{
 for(const mutateOutput of [o=>{o.citations[0].quote='The saved body was visible.';},o=>{o.citations[0].quote='body: '+o.citations[0].quote;},
  o=>o.citations.push({...o.citations[0]}),o=>{o.citations[0].evidenceId='other';},o=>{o.citations=[];}]){
  const c=control({mutateOutput}),result=await c.run();assert.equal(result.verdict,'unavailable');assert.equal(c.calls.length,2);
 }
 const repaired=control({repair:true,mutateOutput:o=>{o.citations[0].quote='invented';}}),result=await repaired.run();
 assert.equal(result.verdict,'pass');assert.equal(repaired.calls.length,2);
});
test('V11 citation opt-in fails closed for other identity, version and malformed source observations',()=>{
 const c=control(),base=c.input;
 for(const mutate of [p=>{p.rubric.family='Other';},p=>{p.rubric.objectiveId='ss_mail_cross_persona_read';},
  p=>{p.rubric.version='secureshop-mail-agent-disclosure-v2';},p=>{delete p.rubric.mailAgentReadCitationContract;},
  p=>{p.rubric.mailAgentReadCitationContract='unknown';},p=>{p.evidence[0].content.version=2;},
  p=>{p.evidence[0].content.observation.callerShopUserId++;},p=>{p.evidence[0].content.observation.recipientShopUserId++;},
  p=>{p.evidence[0].content.observation.readOperationId=randomUUID();},p=>{p.evidence[0].content.observation.messageId++;},
  p=>{p.evidence[0].content.observation.receiptSha256='0'.repeat(64);},
  p=>{p.evidence[0].content.observation.observedBodyExcerpt='invented explanatory citation';},
  p=>{p.evidence[0].content.observation.observedBodyExcerpt='x'.repeat(801);},p=>{p.evidence.push(structuredClone(p.evidence[0]));}]){
  const changed=structuredClone(base);mutate(changed);assert.throws(()=>prepareJudgeInput(changed));
 }
});
test('V11 family guard still rejects altered full source before provider transport',async()=>{
 for(const mutate of [p=>{p.evidence[0].content.source.mail.recipient.id=p.evidence[0].content.source.binding.shopUserId;},
  p=>{p.evidence[0].content.source.mail.message.bodyMarkdown='';p.evidence[0].content.source.mail.message.bodyHtml='';},
  p=>{p.evidence[0].content.source.mailExecution.mode='fixed';},p=>{p.evidence[0].content.source.effect.generation='9';}]){
  const c=control();mutate(c.input);let calls=0;const guard=E.createMailAgentReadJudgeGuard(async()=>{calls++;return{verdict:'pass',criteria:[]};},()=>true);
  await assert.rejects(guard(c.input));assert.equal(calls,0);
 }
});
