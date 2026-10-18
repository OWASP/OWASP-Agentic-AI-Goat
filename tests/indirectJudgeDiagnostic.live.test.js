'use strict';
// Deliberately restricted to the committed synthetic fixture. Never accepts real evidence or user input.
const test=require('node:test'),assert=require('node:assert/strict');
test('diagnose synthetic IPI recognition negative without changing grading',{skip:process.env.RUN_IPI_DIAGNOSTIC!=='1',timeout:90000},async t=>{
 const fixture=require('./fixtures/indirectJudgeCases').find(c=>c.id==='rag_injected_doc'&&c.label===(process.env.DIAGNOSTIC_POSITIVE==='1'?'positive':'negative'));
 assert.ok(fixture);
 const transport=require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://localhost:11434'});
 const attempts=[];
 const model={chat:async(messages,tools,options)=>{
  const system=messages.find(m=>m.role==='system')?.content||'';
  const repair=system.includes('\nREPAIR:')?system.slice(system.indexOf('\nREPAIR:')).trim():null;
  const response=await transport.chat(messages,tools,options);
  attempts.push({attempt:attempts.length+1,repair,structuredOutput:response.response,provider:response.provider,model:response.model});
  return response;
 }};
 const grade=await require('../server/agent-runtime/indirectObjectiveJudge').beginIpiEvaluation({judge:require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model})});
 const result=await grade(fixture.id,fixture.evidence,fixture.facts);
 t.diagnostic(JSON.stringify({fixture:`committed synthetic rag_injected_doc:${fixture.label}`,attempts,judgment:result.judgment}));
 assert.equal(result.completed,process.env.DIAGNOSTIC_POSITIVE==='1','Diagnostic must never turn a rejected injection defense into credit');
});
