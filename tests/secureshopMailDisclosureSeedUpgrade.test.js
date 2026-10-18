'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {qualifyDisclosureNullPreservation}=require('./fixtures/secureshopMailDisclosureSeedUpgrade');
const provenance=require('../server/database/postgres/catalogDefaultProvenance');
const id='ss_mail_cross_persona_read',value={title:'Owned default'};
function fixture(fail=false){let values={hint_content:value,solution_content:value},saved,calls=[],released;
 const client={async query(sql,p=[]){calls.push(sql);
  if(sql==='BEGIN'){saved=structuredClone(values);return{};}
  if(sql==='ROLLBACK'){values=saved;return{};}
  if(sql.startsWith('SELECT * FROM workshop_platform.objectives'))return{rows:[{...values}]};
  if(sql.startsWith('SELECT * FROM workshop_platform.catalog_field_defaults ORDER'))return{rows:[{state:'managed'}]};
  if(sql.startsWith('SELECT * FROM workshop_platform.config_revision'))return{rows:[{revision:1}]};
  if(sql.startsWith('UPDATE workshop_platform.objectives SET')){values[/SET (\w+)/.exec(sql)[1]]=null;return{rowCount:1};}
  if(sql.startsWith('SELECT revision')){if(fail)throw Error('owned reconcile failure');return{rows:[{revision:1}]};}
  if(sql.includes(' AS value'))return{rows:[{value:values[/SELECT (\w+)/.exec(sql)[1]]}],rowCount:1};
  if(sql.startsWith('SELECT * FROM workshop_platform.catalog_field_defaults'))return{rows:[{provenance_state:'managed',applied_default_hash:provenance.hashDocument(provenance.document(value))}]};
  if(sql.startsWith('UPDATE workshop_platform.catalog_field_defaults'))return{rowCount:1};
  throw Error('unexpected SQL');},release(error){released={error};}};
 return{migration:{async connect(){return client;}},curriculum:{HINTS:{[id]:value},SOLUTIONS:{[id]:value}},calls,get released(){return released;}};
}
test('null fixture runs actual reconciliation twice per field on one transaction then restores rows',async()=>{const f=fixture();assert.equal(await qualifyDisclosureNullPreservation(f),true);assert.equal(f.calls.filter(s=>s==='BEGIN').length,1);assert.equal(f.calls.filter(s=>s==='ROLLBACK').length,1);assert(!f.calls.includes('COMMIT'));assert.equal(f.calls.filter(s=>s.includes('SELECT revision')).length,4);assert.deepEqual(f.released,{error:undefined});});
test('null reconciliation failure rolls back before releasing borrowed client',async()=>{const f=fixture(true);await assert.rejects(qualifyDisclosureNullPreservation(f),/owned reconcile failure/);assert(f.calls.includes('ROLLBACK'));assert(f.released);assert(!f.calls.includes('COMMIT'));});
