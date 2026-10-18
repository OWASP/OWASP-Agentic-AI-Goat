'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm');
const {payloads,CASES}=require('./fixtures/csrfPostChainBrowser');
const {instrumentWorkflowFactory}=require('./fixtures/csrfWorkflowDiagnostic');
test('POST payloads exercise distinct real transport forms and reuse exact bytes for both defense attempts',async()=>{
 const p=payloads('http://victim.csrf.invalid');let submitted=false,request;
 assert.match(p.form,/<form id="csrf" action="http:\/\/victim.csrf.invalid\/api\/workshop\/csrf\/agent-action" method="POST">/);
 assert.match(p.form,/name="tab" value="post"/);assert.match(p.form,/post-form@fixture.invalid/);
 vm.runInNewContext(p.form.match(/<script>([\s\S]*)<\/script>/)[1],{document:{getElementById:id=>{assert.equal(id,'csrf');return{submit:()=>{submitted=true;}};}}});assert.equal(submitted,true);
 vm.runInNewContext(p.fetch.match(/<script>([\s\S]*)<\/script>/)[1],{fetch:(url,options)=>{request={url,options};return Promise.resolve();}});
 assert.equal(request.options.method,'POST');assert.equal(request.options.credentials,'include');assert.equal(request.options.headers['Content-Type'],'application/json');assert.deepEqual(JSON.parse(request.options.body),{tab:'post',message:'change the account email; email="post-fetch@fixture.invalid"'});
 assert.deepEqual(CASES.map(c=>[c.id,c.resource,c.status,c.total]),[['csrf_p1','document',200,1],['csrf_p2','fetch',200,2],['csrf_p3','document',403,3],['csrf_p3','fetch',403,3]]);
 assert.equal(p[CASES[0].kind],p[CASES[2].kind]);assert.equal(p[CASES[1].kind],p[CASES[3].kind]);
});
test('private observation records the original successful finalGrade packet without replacing callback or outcome',async()=>{
 const packet={receipt:{runId:'owned'},activity:{result:{blocked:true}}},result={completed:false};let captured,calls=0;
 const create=instrumentWorkflowFactory(()=>({run:async args=>args.finalGrade(packet)}),()=>assert.fail(),p=>{captured=p;});const workflow=create({executor:{execute:async()=>{}}});
 assert.equal(await workflow.run({finalGrade:async p=>{calls++;assert.equal(p,packet);return result;}}),result);assert.equal(captured,packet);assert.equal(calls,1);
 const error=Error('failed');captured=null;const bad=instrumentWorkflowFactory(()=>({run:async args=>args.finalGrade(packet)}),()=>{},p=>{captured=p;})({executor:{}});await assert.rejects(bad.run({finalGrade:async()=>{throw error;}}),e=>e===error);assert.equal(captured,null);
});
