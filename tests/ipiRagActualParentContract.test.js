'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const wire=require('./postgres/finflowBackupBrowserActualTransport');
const profile=wire.transportProfile('ipi-rag-query-actual');
const actor=()=>({model:wire.MODEL,stream:true,messages:[{role:'system',content:'Choose the next action for this document question.'},{role:'user',content:'Question: frozen'}],options:{temperature:0,num_predict:1200},format:structuredClone(wire.RAG_ACTOR_FORMAT)});
test('closed RAG transport retains original profile budgets and exact actor/Judge request forms',()=>{
 assert.deepEqual(profile.ids,['owner-upload','owner-query']);for(const [k,v]of Object.entries({actor:8,judge:6,chat:14,generate:0,tags:1,version:0,metadata:1,external:15}))assert.equal(profile[k],v);
 assert.equal(wire.transportProfile('admin-enum').external,113);assert.equal(wire.transportProfile().external,29);
 assert.equal(wire.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(actor())),profile),'chat');
 const judge=actor();judge.options={temperature:0,num_predict:900,num_ctx:32768};judge.format={type:'object'};assert.equal(wire.ragRequestRole(judge),'judge');
 for(const mutate of [x=>x.model='other',x=>x.options.num_predict=1201,x=>x.options.num_ctx=8192,x=>x.tools=[{}],x=>x.format.oneOf[0].properties.topK.maximum=100]){const x=actor();mutate(x);assert.throws(()=>wire.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(x)),profile));}
 assert.throws(()=>wire.validateRequest('GET','/api/version',Buffer.alloc(0),profile));assert.throws(()=>wire.validateRequest('POST','/api/generate',Buffer.from(JSON.stringify(actor())),profile));
 const b=wire.budget(profile);b.reserve('tags');assert.throws(()=>b.reserve('tags'));for(let i=0;i<14;i++)b.reserve('chat');assert.throws(()=>b.reserve('chat'));assert.throws(()=>b.reserve('generate'));
});
test('RAG actor wire schema matches unchanged production decision schema',()=>{
 const {readFileSync}=require('node:fs');const source=readFileSync(require.resolve('../server/agent-runtime/ragDecisions'),'utf8');
 const literal=source.split('const decisionFormat = Object.freeze(')[1].split('\nfunction failure')[0].trim().slice(0,-2);
 const production=require('node:vm').runInNewContext('('+literal+')');assert.equal(JSON.stringify(wire.RAG_ACTOR_FORMAT),JSON.stringify(production));
});
test('closed email transport retains original graph decision and response forms with finite role budgets',()=>{
 const p=wire.transportProfile('ipi-email-trigger-actual'),graph=require('../server/agent-runtime/indirectEmailGraph');
 assert.deepEqual(p.ids,['setup','clean-control','attack']);for(const[k,v]of Object.entries({actor:16,judge:28,chat:44,generate:0,tags:1,version:0,metadata:1,external:45}))assert.equal(p[k],v);
 const decision={model:wire.MODEL,stream:true,messages:[{role:'system',content:graph.EMAIL_DECISION_PROTOCOL},{role:'user',content:'Summarize selected artifact.'}],options:{temperature:.2,num_predict:128},format:graph.emailDecisionFormat(false)};
 assert.equal(wire.emailRequestRole(decision),'actor');assert.equal(wire.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(decision)),p),'chat');
 const final=structuredClone(decision);delete final.format;final.options={temperature:.7,num_predict:512};final.messages[1].content='SERVER-AUTHORED RESPONSE REQUEST: Return grounded response.';assert.equal(wire.emailRequestRole(final),'actor');
 const judge=structuredClone(decision);judge.options={temperature:0,num_predict:2048,num_ctx:32768};judge.format={type:'object'};assert.equal(wire.emailRequestRole(judge),'judge');
 for(const change of [x=>x.format=graph.emailDecisionFormat(true).properties,x=>x.options.temperature=0,x=>x.messages[0].content='unrelated',x=>x.model='other',x=>x.tools=[{}]]){const bad=structuredClone(decision);change(bad);assert.throws(()=>wire.validateRequest('POST','/api/chat',Buffer.from(JSON.stringify(bad)),p));}
 judge.options.num_predict=16385;assert.throws(()=>wire.emailRequestRole(judge));assert.throws(()=>wire.validateRequest('POST','/api/generate',Buffer.from('{}'),p));
 const b=wire.budget(p);b.reserve('tags');assert.throws(()=>b.reserve('tags'));for(let i=0;i<44;i++)b.reserve('chat');assert.throws(()=>b.reserve('chat'));assert.throws(()=>b.reserve('generate'));
 assert.equal(wire.caseDeadlineFor(p,999,()=>1),999);
});
test('email Mailpit admission requires owned label, exact image and independent loopback ports',()=>{
 const main=require('./postgres/codeBotRenderedParityMainV1'),owner='a'.repeat(32),v={creationAttempted:true,name:'owasp-ai-goat-ipi-email-'+owner.slice(0,12),labels:{'owasp-ai-goat.owner':owner,'owasp-ai-goat.cohort':'ipi-email-trigger-actual'},imageId:'sha256:98b916bd3c8d61f7633a52d3ea2f58d00620cb01ca57ab59edde68c347a95365',containerId:'b'.repeat(64),apiUrl:'http://127.0.0.1:4025',smtpHost:'127.0.0.1',smtpPort:4026};
 assert.equal(main.validateEmailMailpit(v,owner),v);
 for(const change of [x=>x.labels['owasp-ai-goat.owner']='other',x=>x.apiUrl='http://example.invalid:4025',x=>x.smtpPort=4025,x=>x.cleanup={status:'removed'},x=>x.imageId='sha256:'+'0'.repeat(64)]){const bad=structuredClone(v);change(bad);assert.throws(()=>main.validateEmailMailpit(bad,owner));}
});
