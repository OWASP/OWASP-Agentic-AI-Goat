'use strict';
const test=require('node:test');const assert=require('node:assert/strict');
const provenance=require('../server/database/postgres/catalogDefaultProvenance');
const {validateTransition}=require('../scripts/audit-mcp-promotion-seed-transition');
const missing=provenance.document(undefined,false);const missingHash=provenance.hashDocument(missing);
const base=()=>({entity_kind:'objective',workshop_key:'mcp_workshop',objective_id:'one',field_name:'hint_content',
  provenance_state:'custom',source_hash:'a'.repeat(64),source_document:{present:true,value:{hint:'old'}},
  applied_default_document:{present:true,value:{hint:'instructor'}},updated_at:'before'});
const missingKey='objective\u001fmcp_workshop\u001fone\u001fhint_content';
const expectedSources=new Map([[missingKey,missing]]);
function caught(fn) { try { fn(); } catch (error) { return error; } throw new Error('expected failure'); }

test('accepts only the derived source retirement metadata transition',()=>{
 const before=[base()];const after=[{...base(),source_hash:missingHash,source_document:missing,updated_at:'after'}];
 const result=validateTransition(before,after,{expectedSources});
 assert.equal(result.rows,1);assert.equal(result.changed,1);
 assert.match(result.beforeSha256,/^[a-f0-9]{64}$/);assert.match(result.afterSha256,/^[a-f0-9]{64}$/);
 assert.notEqual(result.beforeSha256,result.afterSha256);
});
test('rejects same-count key, value, and instructor-default rewrites',()=>{
 const before=[base()];const valid={...base(),source_hash:missingHash,source_document:missing,updated_at:'after'};
 const keyError=caught(()=>validateTransition(before,[{...valid,objective_id:'two'}],{expectedSources}));
 assert.equal(keyError.code,'PROVENANCE_TRANSITION_INVALID');assert.deepEqual(keyError.diagnostic.removedKeys,[missingKey]);
 for (const [column,value] of [['provenance_state','managed'],
   ['applied_default_document',{present:true,value:{hint:'changed'}}]]) {
  const error=caught(()=>validateTransition(before,[{...valid,[column]:value}],{expectedSources}));
  assert.equal(error.code,'PROVENANCE_TRANSITION_INVALID');
  assert.deepEqual(error.diagnostic.transitions[0].columns.sort(),[column,'source_document','source_hash','updated_at'].sort());
  assert.equal(error.diagnostic.invalid[0].key,missingKey);
 }
});

test('accepts PostgreSQL timestamp Date values without weakening field checks',()=>{
 const before=[{...base(),updated_at:new Date('2026-09-14T00:00:00Z')}];
 const after=[{...base(),source_hash:missingHash,source_document:missing,
   updated_at:new Date('2026-09-14T00:00:01Z')}];
 assert.equal(validateTransition(before,after,{expectedSources}).changed,1);
});
