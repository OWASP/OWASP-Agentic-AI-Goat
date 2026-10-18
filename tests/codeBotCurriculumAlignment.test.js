'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {WORKSHOP_OBJECTIVES}=require('../server/config/workshopCatalog');
const {solutions,SC_OBJECTIVE_IDS}=require('../server/data/supplyChainSolutions');
const provenance=require('../server/database/postgres/catalogDefaultProvenance');
const {CRITERIA}=require('../server/agent-runtime/codeBotJudge');
test('CodeBot reconnaissance defaults describe the actual rubric without changing objective identities',()=>{
 assert.deepEqual(WORKSHOP_OBJECTIVES.supply_chain_rce.map(o=>o.id),SC_OBJECTIVE_IDS);
 assert.equal(WORKSHOP_OBJECTIVES.supply_chain_rce.find(o=>o.id==='tool_list').text,solutions.tool_list.title);
 for(const name of ['review_code','check_dependencies','explain_error']){assert.ok(CRITERIA.tool_list.includes(name));assert.ok(solutions.tool_list.examples[0].explanation.includes(name));}
 assert.match(solutions.pkg_discover.approach,/fictional training package/);assert.match(solutions.pkg_discover.approach,/not a real package advisory/);
 assert.doesNotMatch(solutions.pkg_discover.approach,/research its known vulnerabilities/);
});
test('corrected label and package explanation upgrade managed defaults only and retain instructor edits on reseed',async()=>{
 const targetLabel=WORKSHOP_OBJECTIVES.supply_chain_rce.find(o=>o.id==='tool_list').text;
 const targetSolution=solutions.pkg_discover,oldSolution={...targetSolution,approach:targetSolution.approach.replace('pkg-parse@1.2.0 is a fictional training package: in this lab its deliberately vulnerable parser evaluates the "transform" field. Use that documented lab behavior for the next exercise; it is not a real package advisory.','Once you know pkg-parse@1.2.0 is involved, you can research its known vulnerabilities — specifically that it calls eval() on the "transform" field.')};
 assert.notEqual(oldSolution.approach,targetSolution.approach);
 for(const [id,field,old,target] of [['tool_list','label','List project dependencies',targetLabel],['pkg_discover','solution_content',oldSolution,targetSolution]]){
  for(const [current,state,expected] of [[old,'managed','upgrade'],[typeof old==='string'?'Instructor tools':{...old,title:'Instructor title'},'managed','mark_custom'],[old,'custom','preserve'],[target,'managed','record']]){
   const queries=[],applied=current===target?target:old;
   const client={query:async(sql,params=[])=>{queries.push({sql,params});if(/SELECT revision/.test(sql))return{rows:[{revision:1}],rowCount:1};if(sql.includes(`SELECT ${field} AS value`))return{rows:[{value:current}],rowCount:1};if(/SELECT \* FROM workshop_platform.catalog_field_defaults/.test(sql))return{rows:[{provenance_state:state,applied_default_hash:provenance.hashDocument(provenance.document(applied))}],rowCount:1};if(/^UPDATE/.test(sql))return{rows:[],rowCount:1};throw Error('Unexpected seed query');}};
   const result=await provenance.reconcileField(client,{entityKind:'objective',workshopKey:'supply_chain_rce',objectiveId:id,fieldName:field,sourceValue:target,sourceVersion:'codebot-content-alignment'});
   assert.equal(result.decision,expected);assert.equal(queries.some(q=>q.sql.includes(`UPDATE workshop_platform.objectives SET ${field}=`)),expected==='upgrade');
  }
 }
});
