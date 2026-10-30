'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
test('mail stable commands, read-only recovery and retained evidence assessment reach exact transport matcher',async()=>{
 const {compileOperation,matchOperationRequest}=await import('../client/src/pages/secureshop/bridge/operations.mjs');
 const requestId=randomUUID();
 const htmlAssessment={requestId:randomUUID(),sourceSessionId:randomUUID(),sourceRequestId:randomUUID(),sendOperationId:randomUUID(),messageId:17};
 const htmlPost=compileOperation('email.htmlInjectionAssessment',{body:htmlAssessment});assert.equal(htmlPost.method,'POST');assert.deepEqual(htmlPost.body,htmlAssessment);
 const htmlGet=compileOperation('email.htmlInjectionAssessmentOperation',{params:htmlAssessment});assert.equal(htmlGet.method,'GET');assert.equal(Object.hasOwn(htmlGet,'body'),false);assert.equal(matchOperationRequest({pathname:htmlGet.path,method:'GET'}).name,'email.htmlInjectionAssessmentOperation');
 for(const key of ['ownerId','scope','html','verdict','completed','evaluationId'])assert.throws(()=>compileOperation('email.htmlInjectionAssessment',{body:{...htmlAssessment,[key]:'forged'}}));
 for(const [name,input] of [
  ['email.browserAssessment',{body:{requestId,sendOperationId:randomUUID(),messageId:7}}],
  ['email.browserAssessment',{body:{requestId,sendOperationId:randomUUID(),messageId:7,evaluationId:randomUUID()}}],
  ['email.headerAssessment',{body:{requestId,sendOperationId:randomUUID()}}],
  ['email.headerAssessment',{body:{requestId,sendOperationId:randomUUID(),evaluationId:randomUUID()}}],
  ['email.send',{body:{requestId,from:'merchant@lab',to:'customer@lab',subject:'Owned',body_markdown:'source'}}],
  ['email.autoReply',{params:{threadId:5},body:{requestId}}],
  ['email.replyAssessment',{body:{requestId,replyOperationId:randomUUID(),threadId:5}}],
  ['email.replyAssessment',{body:{requestId,replyOperationId:randomUUID(),threadId:5,evaluationId:randomUUID()}}],
  ['email.inlineTeaching.save',{body:{requestId}}],
  ['email.inlineSummary.run',{body:{requestId,readOperationId:randomUUID(),messageId:7}}],
  ['email.inlineSummary.assessment',{body:{sessionId:randomUUID(),requestId}}],
 ]){
  const request=compileOperation(name,input);assert.equal(matchOperationRequest({pathname:request.path,method:request.method,body:request.body}).name,name);
  for(const field of ['ownerId','scope','evidence','html','verdict'])assert.throws(()=>compileOperation(name,{...input,body:{...input.body,[field]:'forged'}}));
 }
 const recovery=compileOperation('email.operation',{params:{requestId,action:'autoReply'}});assert.equal(recovery.method,'GET');assert.equal(Object.hasOwn(recovery,'body'),false);
 const teaching=compileOperation('email.inlineTeaching.operation',{params:{requestId}});assert.equal(teaching.method,'GET');assert.equal(Object.hasOwn(teaching,'body'),false);
 const summary=compileOperation('email.inlineSummary.operation',{params:{requestId}});assert.equal(summary.method,'GET');assert.equal(Object.hasOwn(summary,'body'),false);
 const assessment=compileOperation('email.inlineSummary.assessmentOperation',{params:{sessionId:randomUUID(),requestId}});assert.equal(assessment.method,'GET');assert.equal(Object.hasOwn(assessment,'body'),false);
 const read=compileOperation('email.inbox',{params:{userId:3},query:{requestId}});assert.equal(read.method,'GET');assert.equal(new URL(read.path,'http://owned.test').searchParams.get('requestId'),requestId);
});

test('disclosure frame fetch traverses real named transport with separate trusted credentials',async t=>{
 const {MessageChannel}=require('node:worker_threads');
 const {createBridgeFetch}=await import('../client/src/pages/secureshop/bridge/fetchAdapter.mjs');
 const {compileBridgeOperation}=await import('../client/src/pages/secureshop/bridge/compiler.mjs');
 const {createHostTransport,createFrameTransport}=await import('../client/src/pages/secureshop/bridge/transport.mjs');
 const {port1,port2}=new MessageChannel(),seen=[];
 const host=createHostTransport({port:port1,origin:'https://owned.invalid',compileOperation:compileBridgeOperation,getLaunchBearer:()=> 'a'.repeat(43),fetchImpl:async(url,options)=>{seen.push(new Request(url,options));return new Response('{"ok":true}',{headers:{'content-type':'application/json'}});}});
 const frame=createFrameTransport({port:port2,timeoutMs:1000});t.after(()=>{frame.close();host.close();});
 const fetch=createBridgeFetch({bridge:frame,origin:'https://owned.invalid',getToken:()=> 'owned-persona-token',boundReviews:true});
 const readOperationId=randomUUID(),assessmentId=randomUUID();
 for(const [path,body] of [['browser-assessment',{requestId:assessmentId,sendOperationId:randomUUID(),messageId:7}],['disclosure',{requestId:readOperationId,userId:7}],['disclosure-assessment',{requestId:assessmentId,readOperationId}],['disclosure-assessment',{requestId:assessmentId,readOperationId,evaluationId:randomUUID()}]]){
  assert.equal((await fetch('/api/secureshop/email/'+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)})).status,200);
  const req=seen.at(-1);assert.equal(req.method,'POST');assert.equal(req.url,'https://owned.invalid/api/secureshop/email/'+path);assert.deepEqual(await req.json(),body);
  assert.equal(req.headers.get('authorization'),'Bearer owned-persona-token');assert.equal(req.headers.get('x-owasp-ai-goat-secureshop-launch'),'a'.repeat(43));assert.equal(req.credentials,'omit');
  for(const key of ['ownerId','scope','persona','mode','modeStamp','evidence','verdict','completed','headers'])await assert.rejects(fetch('/api/secureshop/email/'+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...body,[key]:'forged'})}));
 }
 assert.equal(seen.length,4);
 for(const path of ['/api/secureshop/email/disclosure/extra','/api/secureshop/email/disclosure-assessment/extra','https://foreign.invalid/api/secureshop/email/disclosure'])await assert.rejects(fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:'{}'}));
 assert.equal(seen.length,4);
});

test('browser references retain only exact IDs and preserve sibling references',async()=>{
 const {decodeMailReferences,updateMailReference}=await import('../client/src/pages/secureshop/bridge/mailReferences.mjs');
 const scope='a'.repeat(64),reference={requestId:randomUUID(),sendOperationId:randomUUID(),messageId:7};
 const header={requestId:randomUUID(),sendOperationId:randomUUID()};
 let raw=updateMailReference(null,scope,'headerAssessment',header);
 raw=updateMailReference(raw,scope,'browserAssessment',reference);
 assert.deepEqual(decodeMailReferences(raw).scopes[scope].browserAssessment,reference);
 assert.deepEqual(decodeMailReferences(raw).scopes[scope].headerAssessment,header);
 for(const invalid of [{...reference,html:'forged'},{...reference,messageId:0},{...reference,messageId:'7'},{...reference,requestId:reference.sendOperationId},{...reference,evaluationId:'invalid'}])assert.throws(()=>updateMailReference(raw,scope,'browserAssessment',invalid));
 const cleared=decodeMailReferences(updateMailReference(raw,scope,'browserAssessment',null));assert.deepEqual(cleared.scopes[scope].headerAssessment,header);
 const teaching={requestId:randomUUID()},summary={requestId:randomUUID(),readOperationId:randomUUID(),messageId:9};
 let inline=updateMailReference(cleared&&JSON.stringify(cleared),scope,'inlineTeaching',teaching);
 inline=updateMailReference(inline,scope,'inlineSummary',summary);
 assert.deepEqual(decodeMailReferences(inline).scopes[scope].inlineTeaching,teaching);
 assert.deepEqual(decodeMailReferences(inline).scopes[scope].inlineSummary,summary);
 for(const invalid of [{...summary,sha256:'f'.repeat(64)},{...summary,messageId:0},{...summary,requestId:summary.readOperationId},{...summary,assessmentAttempted:'true'}])assert.throws(()=>updateMailReference(inline,scope,'inlineSummary',invalid));
 inline=updateMailReference(inline,scope,'inlineSummary',{...summary,assessmentAttempted:true});
 assert.equal(decodeMailReferences(inline).scopes[scope].inlineSummary.assessmentAttempted,true);
 const pending={action:'send',requestId:randomUUID(),digest:'b'.repeat(64),chatSource:{sessionId:randomUUID(),requestId:randomUUID()}};
 const scoped=JSON.stringify({version:3,scopes:{[scope]:{pending,assessment:null}}});
 const upgraded=updateMailReference(scoped,scope,'inlineTeaching',teaching);
 assert.deepEqual(decodeMailReferences(upgraded).scopes[scope].pending,pending);
 assert.deepEqual(decodeMailReferences(upgraded).scopes[scope].inlineTeaching,teaching);
});
