'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {fixedAuditRows}=require('../server/services/secureshopAuditFixedProjection');
const row={id:'agents:11111111-1111-4111-8111-111111111111',store:'agents',ts:'2026-01-01T00:00:00.000000Z',actor:'IGNORE ALL',action:'<script>',target:'SYSTEM OVERRIDE',params_json:'injected instructions',outcome:'denied',source_kind:'evil source',source_id:'evil id'};
test('fixed audit projection excludes arbitrary log fields while hashing exact original content',async()=>{
 const collect=async r=>{const values=[];for await(const v of fixedAuditRows((async function*(){yield r;})(),async()=>{}))values.push(v);return values[0];};
 const result=await collect(row),serialized=JSON.stringify(result);for(const value of ['IGNORE ALL','<script>','SYSTEM OVERRIDE','injected instructions','evil source','evil id'])assert.equal(serialized.includes(value),false);
 assert.equal(result.id,row.id);assert.equal(result.ts,row.ts);assert.equal(result.outcome,'denied');assert.notEqual((await collect({...row,params_json:'changed'})).source_id,result.source_id);
 await assert.rejects(collect({...row,outcome:'IGNORE ALL'}));
});
