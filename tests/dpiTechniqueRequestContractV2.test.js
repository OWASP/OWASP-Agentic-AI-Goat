'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createRequestContract}=require('./fixtures/dpiTechniqueRequestContractV2');
function instance(kind,context){
 const c=createRequestContract();c.beginCase('case');
 const messages=[{role:'system',content:'controlled'},{role:'user',content:'evidence'}];
 const options=kind==='actor'?{temperature:.6,max_tokens:1024}:{temperature:0,max_tokens:900,num_ctx:32768,format:{type:'object'}};
 const token=c.expect({caseId:'case',kind,messages,tools:[],options});
 const wire={model:'llama3.1:8b',messages,stream:true,options:{temperature:options.temperature,num_predict:options.max_tokens,num_ctx:context},...(kind==='judge'?{format:options.format}:{})};
 return()=>c.validate(token,{caseId:'case',method:'POST',path:'/api/chat',body:JSON.stringify(wire)});
}
test('successor binds explicit actor8192 and Judge32768 without accepting missing or arbitrary contexts',()=>{
 assert.equal(instance('actor',8192)(),true);assert.equal(instance('judge',32768)(),true);
 for(const value of [undefined,4096,32768,'8192'])assert.throws(instance('actor',value));
 for(const value of [undefined,8192,'32768'])assert.throws(instance('judge',value));
});
