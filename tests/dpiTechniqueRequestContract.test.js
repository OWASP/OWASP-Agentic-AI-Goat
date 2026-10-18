'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createRequestContract}=require('./fixtures/dpiTechniqueRequestContract');
function setup(kind='judge'){
 const c=createRequestContract();c.beginCase('one');const messages=[{role:'system',content:'Canonical rubric'},{role:'user',content:'Exact case evidence'}];
 const options=kind==='judge'?{temperature:0,num_predict:900,max_tokens:900,num_ctx:32768,format:{type:'object',additionalProperties:false}}:{temperature:.6,max_tokens:1024};
 const token=c.expect({caseId:'one',kind,messages,tools:[],options});const wire={model:'llama3.1:8b',messages:structuredClone(messages),stream:true,options:{temperature:options.temperature,num_predict:options.max_tokens}};
 if(kind==='judge'){wire.options.num_ctx=32768;wire.format=structuredClone(options.format);}
 return {c,token,wire,messages,options};
}
function validate(s,wire=s.wire){return s.c.validate(s.token,{caseId:'one',method:'POST',path:'/api/chat',body:JSON.stringify(wire)});}
test('Judge and real actor options bind exact snapshots and one use',()=>{for(const kind of ['judge','actor']){const s=setup(kind);s.messages[1].content='mutated';if(s.options.format)s.options.format.type='string';assert.equal(validate(s),true);assert.throws(()=>validate(s),{code:'DPI_REQUEST_CONTRACT_INVALID'});s.c.endCase();assert.throws(()=>s.c.beginCase('one'));}});
test('wire changes, extra knobs/tools, schema and evidence mismatch all deny',()=>{for(const change of [w=>w.model='other',w=>w.stream=false,w=>w.tools=[],w=>w.options.seed=1,w=>w.options.num_ctx=4096,w=>w.messages[1].content='cross case',w=>w.format.type='string',w=>w.keep_alive='5m']){const s=setup();change(s.wire);assert.throws(()=>validate(s));assert.throws(()=>validate(s));}});
test('actor rejects test options and format/context, permits no extra knobs',()=>{for(const extra of [{num_ctx:4096},{format:{}},{temperature:0},{num_predict:64},{top_p:1}]){const c=createRequestContract();c.beginCase('one');assert.throws(()=>c.expect({caseId:'one',kind:'actor',messages:[{role:'system',content:'a'},{role:'user',content:'b'}],tools:[],options:{temperature:.6,max_tokens:1024,...extra}}));}});
test('serial, cross-case, stale, abort and malformed admission denied',()=>{const s=setup();assert.throws(()=>s.c.beginCase('two'));assert.throws(()=>s.c.expect({caseId:'one',kind:'judge'}));assert.throws(()=>s.c.validate(s.token,{caseId:'two',method:'POST',path:'/api/chat',body:JSON.stringify(s.wire)}));s.c.endCase();s.c.beginCase('two');assert.throws(()=>validate(s));for(const body of ['{','x'.repeat(262145)]){const x=setup();assert.throws(()=>x.c.validate(x.token,{caseId:'one',method:'POST',path:'/api/chat',body}));}});
test('aborted invocation and unknown model denied',()=>{assert.throws(()=>createRequestContract({model:'other'}));const c=createRequestContract();c.beginCase('one');const ac=new AbortController();const token=c.expect({caseId:'one',kind:'actor',messages:[{role:'system',content:'a'},{role:'user',content:'b'}],tools:[],options:{temperature:.6,max_tokens:1024,signal:ac.signal}});ac.abort();assert.throws(()=>c.validate(token,{caseId:'one',method:'POST',path:'/api/chat',body:'{}'}));});

test('actor history retains exact graph-shaped sequence; history mutations deny',()=>{
 const history=[{role:'system',content:'AWS-only assistant'},{role:'user',content:'Earlier question'},{role:'assistant',content:'Earlier answer'},{role:'user',content:'Current learner payload'}];
 for(const mutation of [null,w=>w.messages[2].content='fabricated answer',w=>w.messages.splice(1,1),w=>w.messages.reverse()]){
  const c=createRequestContract();c.beginCase('history');const messages=structuredClone(history);
  const token=c.expect({caseId:'history',kind:'actor',messages,tools:[],options:{temperature:.6,max_tokens:1024}});
  const wire={model:'llama3.1:8b',messages:structuredClone(history),stream:true,options:{temperature:.6,num_predict:1024}};
  messages[2].content='caller mutation after capture';if(mutation)mutation(wire);
  const verify=()=>c.validate(token,{caseId:'history',method:'POST',path:'/api/chat',body:JSON.stringify(wire)});
  if(mutation)assert.throws(verify);else assert.equal(verify(),true);
 }
});
test('history cannot admit extra system/tool roles, final assistant, Judge history or oversized messages',()=>{
 const history=[{role:'system',content:'s'},{role:'user',content:'u'},{role:'assistant',content:'a'},{role:'user',content:'next'}];
 for(const mutate of [m=>m[2].role='system',m=>m[2].role='tool',m=>m[3].role='assistant',m=>m[0].role='user',m=>m[2].tool_calls=[],m=>m[2].content='x'.repeat(262144)]){
  const c=createRequestContract();c.beginCase('case');const messages=structuredClone(history);mutate(messages);
  assert.throws(()=>c.expect({caseId:'case',kind:'actor',messages,tools:[],options:{temperature:.6,max_tokens:1024}}));
 }
 const c=createRequestContract();c.beginCase('case');assert.throws(()=>c.expect({caseId:'case',kind:'judge',messages:history,tools:[],options:{temperature:0,num_predict:900,num_ctx:32768,format:{type:'object'}}}));
});
