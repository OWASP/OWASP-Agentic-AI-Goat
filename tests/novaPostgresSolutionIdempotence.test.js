'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{execFileSync}=require('node:child_process');
const adapt=require('../server/data/postgres/nosqlInjectionWorkshopSolutions');
test('NOVA PostgreSQL solution adapter is idempotent without mutating source content',()=>{
 const base=require('../server/data/nosqlInjectionWorkshopSolutions'),before=JSON.stringify(base),once=adapt(base);
 assert.deepEqual(adapt(once),once);assert.equal(JSON.stringify(base),before);
 assert.equal(Object.keys(once).length,10);
 for(const id of ['nosqli_2','nosqli_3','nosqli_6','nosqli_8','nosqli_9','nosqli_10'])assert.equal(once[id].approach.split('This workshop simulates MongoDB-style operators on PostgreSQL;').length-1,1);
});
test('canonical NOVA seed defaults match across engine settings and module import order',()=>{
 const outputs=[];
 for(const engine of ['postgres','sqlite'])for(const preload of [false,true]){
  const script=`${preload?"require('./server/data/nosqlInjectionWorkshopSolutions');":''}const seed=require('./server/database/postgres/workshopPlatformSeed');const a=seed.solutionFixtures().nosql_injection_workshop;require('node:assert/strict').deepEqual(seed.solutionFixtures().nosql_injection_workshop,a);process.stdout.write(JSON.stringify(a));`;
  outputs.push(execFileSync(process.execPath,['-e',script],{cwd:require('node:path').resolve(__dirname,'..'),env:{...process.env,WORKSHOP_DATABASE_ENGINE:engine},timeout:10000,encoding:'utf8'}));
 }
 for(const value of outputs)assert.deepEqual(JSON.parse(value),JSON.parse(outputs[0]));
});
test('corrected NOVA defaults advance managed duplicate text but preserve instructor edits and null',async()=>{
 const p=require('../server/database/postgres/catalogDefaultProvenance');
 const target=adapt(require('../server/data/nosqlInjectionWorkshopSolutions')).nosqli_2;
 const old={...target,approach:'This workshop simulates MongoDB-style operators on PostgreSQL; it does not execute MongoDB queries or attacker JavaScript. '+target.approach};
 for(const [current,applied,expected] of [[old,old,'upgrade'],[{...old,approach:'Instructor-owned teaching guidance'},old,'mark_custom'],[null,old,'mark_custom'],[target,target,'record']]){
  const writes=[];const client={async query(sql,args){
   if(/SELECT revision/.test(sql))return{rows:[{revision:1}]};
   if(/SELECT solution_content AS value/.test(sql))return{rows:[{value:current}],rowCount:1};
   if(/SELECT \* FROM workshop_platform\.catalog_field_defaults/.test(sql))return{rows:[{provenance_state:'managed',applied_default_hash:p.hashDocument(p.document(applied))}]};
   if(/UPDATE workshop_platform\.objectives SET solution_content=/.test(sql)){writes.push(args);return{rows:[],rowCount:1};}
   if(/UPDATE workshop_platform\.catalog_field_defaults/.test(sql))return{rows:[],rowCount:1};
   throw Error('Unexpected provenance query');
  }};
  const result=await p.reconcileField(client,{entityKind:'objective',workshopKey:'nosql_injection_workshop',objectiveId:'nosqli_2',fieldName:'solution_content',sourceValue:target,sourceVersion:'nova-postgres-idempotence'});
  assert.equal(result.decision,expected);assert.equal(writes.length,expected==='upgrade'?1:0);
 }
});
