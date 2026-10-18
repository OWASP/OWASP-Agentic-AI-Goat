'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {buildSqlNoSqlJudgeCases}=require('./fixtures/sqlNoSqlJudgeCases');
const recorded=require('./fixtures/sqlNoSqlJudgeRecorded.json');

test('local8B ARIA/NOVA qualification:40 recorded PostgreSQL evidence cases',{
 skip:process.env.RUN_LIVE_JUDGE!=='1',timeout:1800000,
},async t=>{
 process.env.JUDGE_PROVIDER='ollama';
 process.env.JUDGE_MODEL='llama3.1:8b';
 const judge=require('../server/agent-runtime/objectiveJudge').createObjectiveJudge();
 const cases=await buildSqlNoSqlJudgeCases(recorded);
 assert.equal(cases.length,40);
 assert.equal(new Set(cases.map(c=>c.rubric.objectiveId)).size,20);
 const totals={positivePass:0,positiveFailure:0,negativeNonPass:0,falsePositive:0};
 const policies=new Set();
 for(const c of cases){
  await t.test(c.id,async()=>{
   const result=await judge({rubric:c.rubric,evidence:c.evidence,facts:c.facts,
    execution:{runId:require('node:crypto').randomUUID(),check:async()=>{}}});
   policies.add(result.judgePolicyDigest);
   totals[c.positive?(result.verdict==='pass'?'positivePass':'positiveFailure'):(result.verdict==='pass'?'falsePositive':'negativeNonPass')]++;
   t.diagnostic(JSON.stringify({case:c.id,expected:c.expected,verdict:result.verdict,explanation:result.explanation,
    judgeVersion:result.judgeVersion,judgePolicyDigest:result.judgePolicyDigest,contextTokens:result.contextTokens,
    family:result.family,durationMs:result.durationMs??null,provider:result.provider,model:result.model,attempts:result.attempts??null}));
   if(c.positive)assert.equal(result.verdict,'pass',result.explanation);
   else assert.notEqual(result.verdict,'pass','Negative observed output must not award credit');
  });
 }
 t.diagnostic(JSON.stringify({totals,policies:[...policies]}));
});
