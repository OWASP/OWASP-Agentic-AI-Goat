'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {RUBRICS,REQUIRED_FACTS,beginIpiEvaluation,evidenceMatchesObjective}=require('../server/agent-runtime/indirectObjectiveJudge');
const cases=require('./fixtures/indirectJudgeCases');
test('IPI qualification covers all10 objectives with observed and unavailable evidence',()=>{
 assert.deepEqual([...new Set(cases.map(c=>c.id))].sort(),Object.keys(RUBRICS).sort());
 assert.equal(cases.length,20);
 for(const c of cases) assert.equal(evidenceMatchesObjective(c.id,c.evidence),true,`${c.id}:${c.label} must exercise its own objective evidence contract`);
 for(const c of cases.filter(c=>c.label==='negative'&&['rag_clean_doc','rag_query','rag_injected_doc','rag_query_injection','email_trigger_injection','email_understand_defense'].includes(c.id))) assert.ok(Object.values(c.facts).every(Boolean),'Semantic failures retain the real evidence-presence facts');
});
const changedEvidenceObjectives=Object.freeze(['rag_injected_doc','rag_query_injection','email_trigger_injection']);
test('IPI changed-evidence cohort has exact positive and negative pairs',()=>{
 const selected=cases.filter(c=>changedEvidenceObjectives.includes(c.id));
 assert.equal(selected.length,6);
 for(const id of changedEvidenceObjectives)assert.deepEqual(selected.filter(c=>c.id===id).map(c=>c.label).sort(),['negative','positive']);
});
test('local8B IPI objective evidence matrix',{skip:process.env.LIVE_IPI_MATRIX!=='1'&&process.env.LIVE_IPI_EVIDENCE_BOUND!=='1',timeout:300000},async t=>{
 const model=require('../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:'llama3.1:8b',baseURL:'http://localhost:11434'});
 const grade=await beginIpiEvaluation({judge:require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model})});
 const failures=[];
 const selected=process.env.LIVE_IPI_EVIDENCE_BOUND==='1'?cases.filter(c=>changedEvidenceObjectives.includes(c.id)):cases;
 for(const c of selected){
  const facts=c.facts;
  const result=await grade(c.id,c.evidence,facts);
  t.diagnostic(JSON.stringify({name:`${c.id}:${c.label}`,judgment:result.judgment}));
  if(c.label==='positive'?result.judgment.verdict!=='pass':result.completed)failures.push({id:c.id,label:c.label,actual:result.judgment.verdict});
 }
 assert.deepEqual(failures,[]);
});

test('all captured-output fixtures satisfy their production objective evidence contract',()=>{
 const {evidenceMatchesObjective}=require('../server/agent-runtime/indirectObjectiveJudge');
 for(const c of cases) assert.equal(evidenceMatchesObjective(c.id,c.evidence),true,`${c.id}/${c.label}`);
});
