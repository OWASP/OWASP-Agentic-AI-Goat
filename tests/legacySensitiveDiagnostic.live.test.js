'use strict';
// Deliberately restricted to the committed synthetic fixture. Never accepts real evidence or user input.
const test=require('node:test'),assert=require('node:assert/strict');
test('diagnose synthetic legacy combined SSI negative without changing grading',{skip:process.env.RUN_LEGACY_DIAGNOSTIC!=='1',timeout:90000},async t=>{
 const fixture=require('./fixtures/legacySensitiveJudgeCases').cases.find(c=>c.objectiveId==='combined_traversal_ssi'&&c.label===(process.env.DIAGNOSTIC_POSITIVE==='1'?'positive':'negative'));
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
 const packet=require('../server/agent-runtime/legacySensitiveJudge').buildPacket(fixture.objectiveId,fixture,{check:async()=>{}});
 const judgment=await require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model})(packet);
 const result={judgment,completed:judgment.verdict==='pass'&&packet.rubric.requiredFacts.every(key=>packet.facts[key]===true)};
 t.diagnostic(JSON.stringify({fixture:`committed synthetic combined_traversal_ssi:${fixture.label}`,attempts,judgment:result.judgment}));
 assert.equal(result.completed,process.env.DIAGNOSTIC_POSITIVE==='1','Diagnostic must never turn a unsuccessful combined SSI attempt into credit');
});
