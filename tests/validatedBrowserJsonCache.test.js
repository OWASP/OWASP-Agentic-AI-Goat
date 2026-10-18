'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createValidatedBrowserJsonCache,MAX_REPRESENTATIONS_PER_URL}=require('./fixtures/validatedBrowserJsonCache');
function response({url,status=200,etag='W/"owned"',validator,body={student:{id:1}}}) {
 return {url:()=>url,status:()=>status,headers:()=>({etag}),request:()=>({method:()=> 'GET',headers:()=>({'if-none-match':validator})}),json:async()=>{assert.equal(status,200,'304 must not invent a response body');return body;}};
}
test('same-context 200 then matching 304 retains exact owner representation',async()=>{
 const context={},read=createValidatedBrowserJsonCache(context),expectedUrl='http://127.0.0.1:1234/api/admin/student-workshop-view/1';
 const first=await read(response({url:expectedUrl}),{context,expectedUrl});first.student.id=99;
 const cached=await read(response({url:expectedUrl,status:304,validator:'W/"owned"'}),{context,expectedUrl});
 assert.equal(cached.student.id,1);
});
test('observed background 200 is serialized before a later 304 using its updated validator',async()=>{
 const context={},read=createValidatedBrowserJsonCache(context),expectedUrl='http://127.0.0.1:1234/api/workshop/mcp/progress';
 const first=response({url:expectedUrl,etag:'W/"initial"',body:{completed:[]}});
 await read.observe(first,{context,expectedUrl});
 let release;const blocked=new Promise(resolve=>{release=resolve;});let bodyReads=0;
 const updated=response({url:expectedUrl,etag:'W/"updated"',body:{completed:['mcp_indirect_injection']}});
 updated.json=async()=>{bodyReads+=1;await blocked;return {completed:['mcp_indirect_injection']};};
 read.observe(updated,{context,expectedUrl});
 const conditional=response({url:expectedUrl,status:304,etag:'W/"updated"',validator:'W/"updated"'});
 const result=read(conditional,{context,expectedUrl});
 let settled=false;void result.then(()=>{settled=true;});await Promise.resolve();assert.equal(settled,false);
 release();assert.deepEqual(await result,{completed:['mcp_indirect_injection']});assert.equal(bodyReads,1);
 await read.settle({context,expectedUrl});
});
test('a captured older ETag remains valid after a newer concurrent representation arrives',async()=>{
 const context={},read=createValidatedBrowserJsonCache(context),expectedUrl='http://127.0.0.1:1234/api/workshop/mcp/progress';
 await read.observe(response({url:expectedUrl,etag:'W/"old"',body:{completed:[]}}),{context,expectedUrl});
 await read.observe(response({url:expectedUrl,etag:'W/"new"',body:{completed:['mcp_indirect_injection']}}),{context,expectedUrl});
 const old=await read(response({url:expectedUrl,status:304,etag:'W/"old"',validator:'W/"old"'}),{context,expectedUrl});
 assert.deepEqual(old,{completed:[]});
});
test('304 rejects wrong validators, other owners and other browser contexts',async()=>{
 const expectedUrl='http://127.0.0.1:1234/api/admin/student-workshop-view/1';
 for(const change of [{validator:'W/"wrong"'},{etag:'W/"wrong"'},{validator:undefined},{etag:'W/"never-captured"',validator:'W/"never-captured"'}]) {
  const context={},read=createValidatedBrowserJsonCache(context);await read(response({url:expectedUrl}),{context,expectedUrl});
  await assert.rejects(read(response({url:expectedUrl,status:304,validator:'W/"owned"',...change}),{context,expectedUrl}));
 }
 {
  const context={},read=createValidatedBrowserJsonCache(context);await read(response({url:expectedUrl}),{context,expectedUrl});
  const other=expectedUrl.replace(/1$/,'2');await assert.rejects(read(response({url:other,status:304,validator:'W/"owned"'}),{context,expectedUrl:other}));
 }
 {
  const context={},read=createValidatedBrowserJsonCache(context);await read(response({url:expectedUrl}),{context,expectedUrl});
  await assert.rejects(read(response({url:expectedUrl,status:304,validator:'W/"owned"'}),{context:{},expectedUrl}));
  assert.throws(()=>read.observe(response({url:expectedUrl}),{context:{},expectedUrl}),/context mismatch/);
 }
});
test('per-URL representation history evicts the oldest ETag at its explicit bound',async()=>{
 assert.equal(MAX_REPRESENTATIONS_PER_URL,64);
 const context={},read=createValidatedBrowserJsonCache(context),expectedUrl='http://127.0.0.1:1234/api/workshop/mcp/progress';
 for(let index=0;index<=MAX_REPRESENTATIONS_PER_URL;index+=1) {
  await read.observe(response({url:expectedUrl,etag:`W/"${index}"`,body:{index}}),{context,expectedUrl});
 }
 await assert.rejects(read(response({url:expectedUrl,status:304,etag:'W/"0"',validator:'W/"0"'}),{context,expectedUrl}),/captured 200/);
});
test('a failed asynchronous background capture is retained at the qualification fence',async()=>{
 const context={},read=createValidatedBrowserJsonCache(context),expectedUrl='http://127.0.0.1:1234/api/workshop/mcp/progress';
 const failed=response({url:expectedUrl,etag:'W/"updated"'});failed.json=async()=>{throw Error('controlled body failure');};
 read.observe(failed,{context,expectedUrl});
 await assert.rejects(read.settle({context,expectedUrl}),/controlled body failure/);
});
