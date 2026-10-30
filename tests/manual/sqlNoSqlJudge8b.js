'use strict';
process.env.JUDGE_PROVIDER='ollama';process.env.JUDGE_MODEL='llama3.1:8b';
const fs=require('node:fs');
const {createWorkshopObjectiveGrader}=require('../../server/services/workshopObjectiveGrader');
(async()=>{
 const cases=JSON.parse(fs.readFileSync('/tmp/owasp-ai-goat-sql-nosql-judge-cases.json','utf8')),rows=[];
 for(const c of cases.filter(c=>!process.env.QUALIFY_OBJECTIVE||process.env.QUALIFY_OBJECTIVE.split(',').includes(c.objectiveId))){
  const grader=createWorkshopObjectiveGrader({workshopKey:c.workshopKey,postgres:false,readLiteralBaseline:c.literalBaseline?async()=>c.literalBaseline:undefined,objectiveLabels:{},syncObjectiveComplete:async()=>{}});
  const execution={runId:require('node:crypto').randomUUID(),generation:1,check:async()=>{}},attempt=await grader.begin(7,execution);
  for(const result of c.history)await grader.observe({userId:7,result,execution,attempt});
  const r=await grader.evaluate({...c,userId:7,mode:'vuln',execution,attempt});
  const row={objectiveId:c.objectiveId,positive:c.positive,expected:c.expected,...r.judgment};rows.push(row);console.log(JSON.stringify(row));
  fs.writeFileSync('/tmp/owasp-ai-goat-sql-nosql-judge-results.json',JSON.stringify(rows,null,2));
 }
})().catch(e=>{console.error(e);process.exitCode=1;});
