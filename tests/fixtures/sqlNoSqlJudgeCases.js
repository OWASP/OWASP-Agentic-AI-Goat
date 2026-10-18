'use strict';
// Captures actual disposable database outcomes; importing this module has no effects.
const sqlQueries = ["'", "%' OR '1'='1'--", "%' ORDER BY 9--", "%' UNION SELECT NULL--",
 "%' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--", "%' UNION SELECT NULL,NULL,'SQLI_TEST',NULL,NULL,NULL,NULL,NULL--",
 "%' UNION SELECT NULL,NULL,version(),NULL,NULL,NULL,NULL,NULL--",
 "%' UNION SELECT NULL,NULL,tablename,NULL,NULL,NULL,NULL,NULL FROM pg_catalog.pg_tables WHERE schemaname='aria'--",
 "%' UNION SELECT NULL,NULL,column_name,NULL,NULL,NULL,NULL,NULL FROM information_schema.columns WHERE table_schema='aria' AND table_name='orders'--",
 "%' UNION SELECT NULL,NULL,order_number,user_id,total_amount,NULL,NULL,NULL FROM aria.orders--"];
const novaQueries = ['{"$":"test"}', '{"title":{"$gt":""}}', '{"title":{"$regex":".*"}}',
 '{"$where":"db.version()"}', '{"$where":"Object.keys(this)"}', '{"title":{"$ne":"Attention Is All You Need"}}',
 '{"$where":"this.year > 2020"}', '{"year":{"$in":[2020,2021,2022,2023,2024]}}',
 '{"email":{"$regex":".*@.*"}}', '{"access_level":{"$ne":"public"}}'];
async function captureSqlNoSqlJudgeCases({aria,nova}) {
 const cases=[];
 for(const [workshopKey,queries,tool,queryKey,search] of [
  ['sql_injection_workshop',sqlQueries,'search_products','searchTerm',q=>aria.searchProducts(q,null,'vuln')],
  ['nosql_injection_workshop',novaQueries,'search_papers','query',q=>nova.searchPapers(q,null,null,'vuln')],
 ]) {
  async function result(q) {
   let toolResult;try{toolResult=await search(q);}catch(error){toolResult={error:error.message};}
   return {toolUsed:tool,toolInvocation:{tool,params:{[queryKey]:q},decisionSource:'model'},toolResult,response:''};
  }
  for(let i=0;i<queries.length;i++) {
   const objectiveId=`${tool==='search_products'?'sqli':'nosqli'}_${i+1}`;
   const positiveResult=await result(queries[i]);
   const history=objectiveId==='sqli_3'?[await result("%' ORDER BY 8--"),positiveResult]:[];
   cases.push({workshopKey,objectiveId,positive:true,expected:'pass',message:queries[i],result:positiveResult,history});
   cases.push({workshopKey,objectiveId,positive:false,expected:'not_pass',message:queries[i],
    result:await result('no_matching_fixture_qualification_7291'),history:[]});
  }
 }
 for(const item of cases){
  const q=require('../../server/services/sqlNoSqlObjectiveEvidence').literalComparisonQuery(item.objectiveId,item.result);
  if(q!==null)item.literalBaseline=item.workshopKey==='sql_injection_workshop'?await aria.searchProducts(q,null,'fixed'):await nova.searchPapers(q,null,null,'fixed');
 }
 return cases;
}
module.exports={captureSqlNoSqlJudgeCases,sqlQueries,novaQueries};

// Build shared-judge inputs from previously captured real DTOs, with no inference.
async function buildSqlNoSqlJudgeCases(recordedCases) {
 const {createWorkshopObjectiveGrader}=require('../../server/services/workshopObjectiveGrader');
 const built=[];
 for(const item of recordedCases){
  let packet;
  const grader=createWorkshopObjectiveGrader({workshopKey:item.workshopKey,postgres:false,
   readLiteralBaseline:item.literalBaseline?async()=>item.literalBaseline:undefined,
   judge:async value=>{packet=value;return{verdict:'fail'};},syncObjectiveComplete:async()=>{throw Error('Fixture must not persist');}});
  const execution={generation:1,check:async()=>{}},attempt=await grader.begin(7,execution);
  for(const result of item.history)await grader.observe({userId:7,result,execution,attempt});
  await grader.evaluate({...item,userId:7,mode:'vuln',execution,attempt});
  const {execution:ignored,...input}=packet;
  built.push({id:`${item.objectiveId}_${item.positive?'positive':'negative'}`,positive:item.positive,expected:item.expected,...input});
 }
 return built;
}
module.exports.buildSqlNoSqlJudgeCases=buildSqlNoSqlJudgeCases;
