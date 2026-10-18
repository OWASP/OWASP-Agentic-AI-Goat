'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
test('real PostgreSQL count/numeric strings produce charts without modifying exact result values',async()=>{
 const {analyticsChart}=await import('../client/src/pages/secureshop/pages/merchant/analyticsChart.mjs');
 const rows=[{count:'256'}];assert.deepEqual(analyticsChart(rows),{rows:[{name:'count',revenue:256}],label:'count',metric:'count',kind:'bar'});assert.equal(rows[0].count,'256');
 assert.deepEqual(analyticsChart([{day:'2026-10-11',count:'2'}]),{rows:[{name:'2026-10-11',revenue:2}],label:'count by day',metric:'count',kind:'line'});
 assert.deepEqual(analyticsChart([{name:'Item',revenue:'12.34'}]),{rows:[{name:'Item',revenue:12.34}],label:'revenue by name',metric:'revenue',kind:'bar'});
 assert.equal(analyticsChart([{username:'learner',api_key:'123456'}]),null);
 assert.equal(analyticsChart([{count:'9007199254740993'}]),null);
 assert.equal(analyticsChart([{count:'2'},{count:'bad'}]),null);
});
