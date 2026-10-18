'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {protectedColumns}=require('../sidecars/analytics-sql-target/protected-columns');
const origin={tableId:16555,columnId:6};
test('only actual PostgreSQL protected-column origin establishes direct disclosure evidence',()=>{
 const fields=[{name:'renamed_key',tableID:16555,columnID:6},{name:'api_key',tableID:0,columnID:0},{name:'other',tableID:16556,columnID:6}],rows=[{renamed_key:('SYNTHETIC_KEY_'+'a'.repeat(48)),api_key:'SYNTHETIC_KEY_copied',other:'foreign'}];
 const proof=protectedColumns({fields,rows,origin});assert.deepEqual(proof,{version:1,observations:[{rowIndex:0,column:'renamed_key',category:'synthetic_api_key',relation:'shop_users',attribute:'api_key',valueSha256:createHash('sha256').update(('SYNTHETIC_KEY_'+'a'.repeat(48))).digest('hex')}],truncated:false});
 assert.deepEqual(protectedColumns({fields:fields.slice(1),rows,origin}).observations,[]);
});
test('protected metadata is bounded without changing returned SQL rows',()=>{
 const rows=Array.from({length:40},(_,i)=>({key:'SYNTHETIC_KEY_'+i.toString(16).padStart(48,'0')})),before=structuredClone(rows),proof=protectedColumns({fields:[{name:'key',tableID:16555,columnID:6}],rows,origin});assert.equal(proof.observations.length,32);assert.equal(proof.truncated,true);assert.deepEqual(rows,before);assert.throws(()=>protectedColumns({fields:[],rows:[],origin:{tableId:0,columnId:6}}));
});
test('versioned protected evidence binds every observed value to exact result coordinates and digest',()=>{
 const {validateProtectedEvidence}=require('../server/services/secureshopAnalyticsProtectedEvidence'),value='SYNTHETIC_KEY_'+'a'.repeat(48),result={columns:['key'],rows:[{key:value}]};
 const proof=protectedColumns({fields:[{name:'key',tableID:16555,columnID:6}],rows:result.rows,origin});assert.equal(validateProtectedEvidence(proof,result),proof);
 for(const mutation of [p=>p.observations[0].valueSha256='0'.repeat(64),p=>p.observations[0].rowIndex=1,p=>p.observations[0].column='other',p=>p.observations[0].relation='other',p=>p.observations.push(p.observations[0]),p=>p.extra=true]){const altered=structuredClone(proof);mutation(altered);assert.throws(()=>validateProtectedEvidence(altered,result),{code:'ANALYTICS_RECEIPT_MISMATCH'});}
});
