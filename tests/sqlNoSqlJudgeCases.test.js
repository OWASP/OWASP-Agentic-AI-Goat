'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs');
const {captureSqlNoSqlJudgeCases}=require('./fixtures/sqlNoSqlJudgeCases');
const {createWorkshopObjectiveGrader,projectWorkshopToolResult}=require('../server/services/workshopObjectiveGrader');
test('all20 adapter cases preserve actual invocation facts and never invent result rows',async()=>{
 const fixtures=await captureSqlNoSqlJudgeCases({aria:{searchProducts:async()=>[]},nova:{searchPapers:async()=>[]}});
 assert.equal(fixtures.length,40);
 for(const c of fixtures){
  let packet;
  const grader=createWorkshopObjectiveGrader({workshopKey:c.workshopKey,postgres:false,judge:async p=>{packet=p;return{verdict:'fail'};},syncObjectiveComplete:async()=>{throw Error('No award');}});
  const execution={generation:1,check:async()=>{}},attempt=await grader.begin(7,execution);
  for(const result of c.history)await grader.observe({userId:7,result,execution,attempt});
  assert.equal((await grader.evaluate({...c,userId:7,mode:'vuln',execution,attempt})).completed,false);
  assert.equal(packet.facts.tool_executed,true);
  assert.equal(packet.facts.objective_signal_detected,false);
  const result=packet.evidence.find(e=>e.id==='tool').content.result;
  assert.deepEqual(Array.isArray(result)?result:result.rows,[]);
  if(c.objectiveId==='sqli_3')assert.equal(packet.evidence.find(e=>e.id==='order_probes').content.length,c.positive?2:0);
 }
});
test('NOVA projection preserves every row and credential/access metadata with explicit omissions',()=>{
 const rows=[{id:1,email:'fixture@example.test',password_hash:'synthetic',access_level:'restricted',abstract:'long',bio:'long'}];
 const projected=projectWorkshopToolResult('nosql_injection_workshop',rows);
 assert.equal(projected.rowCount,1);assert.deepEqual(projected.omittedFields,['abstract','bio']);
 assert.equal(projected.rows[0].password_hash,'synthetic');assert.equal(projected.rows[0].access_level,'restricted');
 assert.equal(rows[0].abstract,'long');
});
test('runtime and initialization defaults match version/schema objectives without changing IDs',()=>{
 const base=require('../server/data/nosqlInjectionWorkshopSolutions');
 const pg=require('../server/data/postgres/nosqlInjectionWorkshopSolutions')(base);
 for(const defaults of [base,pg]){
  assert.equal(Object.keys(defaults).length,10);
  assert.match(defaults.nosqli_4.examples[0].payload,/db\.version/);
  assert.match(defaults.nosqli_5.examples[0].payload,/Object\.keys/);
 }
});
test('nosqli_9 labels and shipped content describe the actual contact-data fixture',async()=>{
 const catalog=require('../server/config/workshopCatalog').WORKSHOP_OBJECTIVES
  .nosql_injection_workshop.find(row=>row.id==='nosqli_9');
 const base=require('../server/data/nosqlInjectionWorkshopSolutions').nosqli_9;
 const pg=require('../server/data/postgres/nosqlInjectionWorkshopSolutions')(
  require('../server/data/nosqlInjectionWorkshopSolutions')).nosqli_9;
 assert.equal(catalog.text,'Extract Author Contact Data');
 for(const solution of [base,pg]){
  assert.equal(solution.title,catalog.text);
  assert.match(JSON.stringify(solution),/email/);
  assert.doesNotMatch(JSON.stringify(solution),/potentially exposing credentials|API keys, or password hashes/);
 }
 for(const file of ['server/routes/nosqlWorkshop.js','client/src/pages/workshops/NoSQLWorkshop.js']){
  const source=fs.readFileSync(require('node:path').join(__dirname,'..',file),'utf8');
  assert.match(source,/nosqli_9[^\n]*Extract Author Contact Data/,file);
  assert.doesNotMatch(source,/nosqli_9[^\n]*Extract Author Credentials/,file);
 }
 const {readConfig}=require('../server/database/postgres/workshopConfigRepository');
 const config=await readConfig({query:async sql=>sql.includes('SELECT revision')
  ?{rows:[{revision:1}]}
  :{rows:[{workshop_key:'nosql_injection_workshop',is_visible:true,show_hints:true,
    show_solutions:true,objective_id:'nosqli_9',label:catalog.text,is_enabled:true,
    hint_enabled:true,solution_enabled:true,hint_content:{title:'Hint'},solution_content:pg}]}});
 assert.equal(config.exercises.nosql_injection_workshop.objectives.nosqli_9.label,catalog.text);
 const identityDraft=fs.readFileSync(require('node:path').join(__dirname,'..',
  'docs/modernization/drafts/nosqli9-identity-content.sql'),'utf8');
 const novaDraft=fs.readFileSync(require('node:path').join(__dirname,'..',
  'docs/modernization/drafts/nosqli9-nova-content.sql'),'utf8');
 assert.match(identityDraft,/solution_content=\$json\$\{"title":"Extract Author Credentials"/);
 assert.match(identityDraft,/config_revision SET revision=revision\+1/);
 assert.match(novaDraft,/AND title='Extract Author Credentials'/);
 assert.match(novaDraft,/AND difficulty='Advanced'/);
});
test('an always-passing model cannot credit empty tool outcomes for any of20 objectives',async()=>{
 const cases=await captureSqlNoSqlJudgeCases({aria:{searchProducts:async()=>[]},nova:{searchPapers:async()=>[]}});
 const judge=require('../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{generate:async()=>({response:JSON.stringify({
  verdict:'pass',explanation:'Fixture claims success.',criteria:[{id:'observed_outcome',satisfied:true,evidenceRefs:['tool']}]
 })})}});
 for(const c of cases.filter(c=>c.positive)){
  const grader=createWorkshopObjectiveGrader({workshopKey:c.workshopKey,postgres:false,judge,objectiveLabels:{},syncObjectiveComplete:async()=>{throw Error('Must not credit empty outcome');}});
  const execution={generation:1,check:async()=>{}},attempt=await grader.begin(7,execution);
  assert.equal((await grader.evaluate({...c,userId:7,mode:'vuln',execution,attempt})).completed,false,c.objectiveId);
 }
});
test('nonempty benign rows, wrong engine metadata, and incomplete probes do not supply objective proof',()=>{
 const {hasObjectiveObservation}=require('../server/services/sqlNoSqlObjectiveEvidence');
 const result=(toolResult,params={})=>({toolResult,toolInvocation:{params}});
 assert.equal(hasObjectiveObservation({objectiveId:'sqli_2',result:result([{name:'normal product'}],{searchTerm:'keyboard'})}),false);
 assert.equal(hasObjectiveObservation({objectiveId:'nosqli_4',result:result([{type:'db_metadata',storage_engine:'MongoDB',db_version:'8.0',simulation:'none'}])}),false);
 assert.equal(hasObjectiveObservation({objectiveId:'nosqli_10',result:result([{access_level:'public'}])}),false);
 assert.equal(hasObjectiveObservation({objectiveId:'sqli_3',result:result([]),history:[{evidence:{invocation:{params:{searchTerm:"%' ORDER BY 8--"}},result:[{id:1}]}}]}),false);
});
test('ARIA column-count proof requires the observed eight-column NULL union row',()=>{
 const {hasObjectiveObservation}=require('../server/services/sqlNoSqlObjectiveEvidence');
 const invocation={params:{searchTerm:"%' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"}};
 const ordinary={id:1,product_id:'P-1',name:'Keyboard',category:'Hardware',price:10,
  description:'Fixture',stock:2,available:1};
 assert.equal(hasObjectiveObservation({objectiveId:'sqli_5',result:{toolResult:[ordinary],toolInvocation:invocation}}),false);
 assert.equal(hasObjectiveObservation({objectiveId:'sqli_5',result:{toolResult:[ordinary,{
  id:null,product_id:null,name:null,category:null,price:null,description:null,stock:null,available:null,
 }],toolInvocation:invocation}}),true);
});


test('NOVA array-membership proof requires distinct matched requested values', () => {
 const { hasObjectiveObservation } = require('../server/services/sqlNoSqlObjectiveEvidence');
 const observed = (values, rows) => hasObjectiveObservation({ objectiveId: 'nosqli_8', result: {
  toolInvocation: { params: { query: JSON.stringify({ year: { $in: values } }) } }, toolResult: rows,
 } });
 assert.equal(observed([2024, 2024], [{ year: 2024 }]), false);
 assert.equal(observed([2024, '2024'], [{ year: 2024 }]), false);
 assert.equal(observed([2023, 2024], [{ year: 2024 }]), false);
 assert.equal(observed([2023, 2024], [{ year: 2023 }, { year: 2024 }]), true);
 assert.equal(observed([2023, 2023, 2024], [{ year: 2023 }, { year: 2024 }]), true);
});
