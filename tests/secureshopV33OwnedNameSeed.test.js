'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const fixture=fs.readFileSync(require.resolve('./postgres/secureshopCustomerPricingActual.integration.test.js'),'utf8');
const begin=fixture.indexOf('const V33_SOURCE_VARIANT =');const end=fixture.indexOf('async function runCanonicalCohort(',begin);assert(begin>=0&&end>begin);const source=fixture.slice(begin,end);
const api=Function('require',source+'\nreturn {admitV33SourceVariant,seedV33OwnedName,V33_SOURCE_VARIANT,V33_SOURCE_NAME};')(require);
test('default has zero setup effects and unknown variant denies',async()=>{
 assert.equal(await api.seedV33OwnedName({variant:'original'}),null);
 assert.throws(()=>api.admitV33SourceVariant('unknown'));
});
test('actual proposed seed changes only owned selected name, records peer/global equality and denies foreign target',async()=>{
 for(const foreign of [false,true]){
  let rows=[{target_id:'actor',product_id:7,name:'Clean',source_product_sha256:Buffer.alloc(32,1)},{target_id:'peer',product_id:7,name:'Peer',source_product_sha256:Buffer.alloc(32,2)}],committed=false,released=false,proof;
  const client={release(){released=true},async query(sql,args){
   if(sql==='BEGIN'||sql==='ROLLBACK')return{};
   if(sql==='COMMIT'){committed=true;return{}};
   if(sql.includes('FOR UPDATE')){assert.deepEqual(Array.from(args),['actor','launch','scene',1,2,3]);return{rows:foreign?[]:[{target_id:'actor'}]}};
   if(sql.includes('listing_overlays'))return{rows:[]};
   if(sql.startsWith('UPDATE')){assert.deepEqual(Array.from(args),['actor',7,api.V33_SOURCE_NAME,'Clean']);rows=rows.map(r=>r.target_id==='actor'?{...r,name:args[2]}:r);return{rowCount:1}};
   assert(sql.includes('target_id=ANY'));return{rows:rows.map(row=>({...row,source_product_sha256:Buffer.from(row.source_product_sha256)}))};
  }};
  const input={variant:api.V33_SOURCE_VARIANT,signal:{throwIfAborted(){}},checkpoint:async(_,p)=>{proof=p},pair:{actor:{target:{targetId:'actor',launchId:'launch'},productId:7,product:{name:'Clean'},authority:{scope:{launchId:'launch',scenarioId:'scene',generation:1,platformOwnerId:2,platformSessionId:3}}},peer:{target:{targetId:'peer'}}},stores:{pools:{REVIEW_MIGRATION:{connect:async()=>client},COMMERCE_RUNTIME:{query:async()=>({rows:[{id:7,name:'Global'}]})}}}};
  if(foreign){await assert.rejects(api.seedV33OwnedName(input));assert.equal(committed,false);assert.equal(rows[0].name,'Clean')}
  else{await api.seedV33OwnedName(input);assert(committed&&proof.peerUnchanged&&proof.globalUnchanged);assert.equal(rows[1].name,'Peer');assert.equal(rows[0].name,api.V33_SOURCE_NAME)}
  assert(released);
 }
});
