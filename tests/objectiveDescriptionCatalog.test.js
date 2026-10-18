'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const provenance=require('../server/database/postgres/catalogDefaultProvenance');
const {createWorkshopPlatformSeed}=require('../server/database/postgres/workshopPlatformSeedCore');

test('objective descriptions seed from curriculum and reconcile on a second run',async()=>{
 const adopted=[],reconciled=[],calls=[];
 let populated=false,revision=1;
 const client={async query(sql,args=[]){calls.push({sql,args});
  if(sql.startsWith('SELECT revision'))return{rows:[{revision}]};
  if(sql.startsWith('INSERT INTO workshop_platform.exercises')||sql.startsWith('INSERT INTO workshop_platform.objectives'))return{rowCount:populated?0:1};
  if(sql.startsWith('UPDATE workshop_platform.config_revision')){revision++;return{rowCount:1};}
  return{rowCount:0,rows:[]};
 }};
 const seed=createWorkshopPlatformSeed({withTransaction:(_pool,work)=>work(client),bump:async()=>{},
  provenance:{adoptInsertedField:async(_client,spec)=>adopted.push(spec),
   reconcileField:async(_client,spec)=>{reconciled.push(spec);return{changed:false};}},
  toChallengeKey:key=>key,legacyXssSolutions:Object.fromEntries(
   ['reflected','stored_user','stored_llm','email'].map(id=>[id,{title:id}]))});
 const input={catalog:{demo:[{id:'one',text:'First',description:'Existing authored guidance'},
  {id:'two',text:'Second',description:null}]},hints:{},solutions:{},challenges:[],catalogVersion:'description-v1'};
 assert.equal((await seed(client,input)).changed,true);
 const inserted=calls.filter(call=>call.sql.startsWith('INSERT INTO workshop_platform.objectives'));
 assert.equal(inserted.length,2);
 assert(inserted.every(call=>call.sql.includes('(workshop_key,objective_id,label,description,category')));
 assert.equal(inserted[0].args[3],'Existing authored guidance');
 assert.equal(inserted[1].args[3],'');
 assert.deepEqual(adopted.filter(spec=>spec.fieldName==='description').map(spec=>spec.sourceValue),
  ['Existing authored guidance','']);

 populated=true;calls.length=0;
 assert.equal((await seed(client,input)).changed,false);
 assert.deepEqual(reconciled.filter(spec=>spec.fieldName==='description').map(spec=>spec.sourceValue),
  ['Existing authored guidance','']);
});

test('new-field provenance upgrades only untouched defaults and preserves instructor edits',()=>{
 const empty=provenance.document('');
 const authored=provenance.document('Existing authored guidance');
 const appliedDefaultHash=provenance.hashDocument(empty);
 const managed={provenance_state:'managed',applied_default_hash:appliedDefaultHash};
 const decision=currentDocument=>provenance.decideReconciliation({
  provenance:managed,currentDocument,sourceDocument:authored,
 }).action;
 assert.equal(decision(empty),'upgrade');
 assert.equal(decision(provenance.document('Instructor edit')),'mark_custom');
 assert.equal(provenance.decideReconciliation({
  provenance:{...managed,provenance_state:'custom'},
  currentDocument:provenance.document('Instructor edit'),sourceDocument:authored,
 }).action,'preserve');
 assert.equal(provenance.decideReconciliation({
  provenance:{...managed,applied_default_hash:provenance.hashDocument(authored)},
  currentDocument:authored,sourceDocument:authored,
 }).action,'record');
 assert.equal(provenance.FIELD.objective.description,'text');
});

test('forward migration initializes the new field at the exact managed empty default',()=>{
 const sql=fs.readFileSync(path.join(__dirname,'../db/postgres/identity-migrations/0132_objective_descriptions.sql'),'utf8');
 assert.match(sql,/ADD COLUMN description text NOT NULL DEFAULT ''/);
 assert.match(sql,/field_name IN \('label','description','category','hint_content','solution_content'\)/);
 assert(sql.includes(provenance.hashDocument(provenance.document(''))));
 assert.match(sql,/FROM workshop_platform.objectives o/);
});
