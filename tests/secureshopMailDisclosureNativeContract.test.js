'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const {assertSemanticNegative,MAX_HTTP_CALLS,controlledResponse}=require('./postgres/secureshopMailDisclosureContract');
const hash=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
const call=(value,stream=false)=>{
 const model='controlled-proof',request=JSON.stringify({model,stream}),content=JSON.stringify(value);
 const frame=(text,done)=>({model,message:{role:'assistant',content:text},done});
 const response=stream?[frame(content.slice(0,7),false),frame(content.slice(7),false),frame('',true)].map(JSON.stringify).join('\n')+'\n':JSON.stringify(frame(content,true));
 return{kind:'judge',model,request,requestSha256:hash(request),response,responseSha256:hash(response),status:200,responseComplete:true,responseCaptureTruncated:false};
};
test('semantic negative binds accepted parser text, not rejected negative or server-fact override',()=>{
 const sha=x=>require('node:crypto').createHash('sha256').update(x).digest('hex');
 const negative={verdict:'fail',criteria:[{id:'owned_foreign_mail_disclosed',satisfied:false}]};
 const text=JSON.stringify(negative),entry={response:text,responseSha256:sha(text),validatedTextSha256:sha(text),disposition:'accepted'};
 const transcript={complete:true,outcome:{value:negative},calls:[entry]};assert.equal(MAX_HTTP_CALLS,8);
 assertSemanticNegative(negative,[call(negative)],transcript);assert.throws(()=>assertSemanticNegative(negative,[],transcript));
 const wrong={verdict:'fail',criteria:[{id:'owned_foreign_mail_disclosed',satisfied:true}]},raw=JSON.stringify(wrong);
 assert.throws(()=>assertSemanticNegative(wrong,[call(negative),call(wrong)],{complete:true,outcome:{value:wrong},calls:[{...entry,disposition:'rejected'},{response:raw,responseSha256:sha(raw),validatedTextSha256:sha(raw),disposition:'accepted'}]}));
 assert.throws(()=>assertSemanticNegative(negative,[call(controlledResponse())],transcript));
 assertSemanticNegative(negative,[call(negative,true)],transcript);
 for(const change of [c=>{c.responseComplete=false;},c=>{c.responseCaptureTruncated=true;},c=>{c.status=503;},c=>{c.response+=' ';},c=>{c.response=c.response.trim().split('\n').slice(0,-1).join('\n');c.responseSha256=hash(c.response);},c=>{c.response+='{}\n';c.responseSha256=hash(c.response);},c=>{c.model='different';},c=>{c.requestSha256='0'.repeat(64);}]){const broken=call(negative,true);change(broken);assert.throws(()=>assertSemanticNegative(negative,[broken],transcript));}
});
test('fixture preserves original JWT authentication, production wiring and bounded actual transport',()=>{
 const s=fs.readFileSync(require.resolve('./postgres/secureshopMailDisclosure.native'),'utf8');
 for(const text of ['authenticateBoundToken({scope:current.scope,token})','req.ssUser=verified.user','createMailProduction','maxHttpCalls:MAX_HTTP_CALLS','assertSemanticNegative(negative,transport.calls.slice(before),state.transcripts.at(-1))','assert.equal(calls(),afterPass)','siblingBefore','packetsBefore','observeExecutionTranscript'])assert(s.includes(text),text);
 assert(!s.includes('PRODUCTION_QUALIFIED='));assert(!s.includes('require.cache'));assert(s.includes("if(actual)assert.equal(process.env.MAIL_DISCLOSURE_STATE,'fresh')"));
});

test('HTTP credentials remain private, closed repository binding has no token field',()=>{
 const {normalize}=require('../server/database/postgres/secureshopBoundMailRepository');const {randomUUID}=require('node:crypto');
 const binding={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:7,platformSessionId:8},targetId:randomUUID(),persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},mode:'vuln',operationId:randomUUID()};
 assert.doesNotThrow(()=>normalize(binding));assert.throws(()=>normalize({...binding,token:'private'}));
 const source=fs.readFileSync(require.resolve('./postgres/secureshopMailDisclosure.native'),'utf8');assert(source.includes('tokens.set(result,login.token)'));assert(source.includes('token=tokens.get(current)'));assert(!source.includes('const result={token:'));
});
test('publication barrier delegates real completion before observation and preserves exact result after release',async()=>{
 const {createCompletionPublicationBarrier}=require('./postgres/secureshopMailDisclosureContract');const barrier=createCompletionPublicationBarrier();const result={completed:true,judgment:{verdict:'pass'}},events=[];
 const completion=barrier.wrap(()=>({async evaluate(){events.push('persisted');return result;}}))({});let settled=false;
 const pending=completion.evaluate({execution:{}}).then(v=>{settled=true;return v;});assert.equal(await barrier.entered,result);assert.deepEqual(events,['persisted']);assert.equal(settled,false);barrier.release();assert.equal(await pending,result);assert.equal(barrier.entries,1);
});
test('publication barrier abort drains after persisted completion without returning stale success',async()=>{
 const {createCompletionPublicationBarrier}=require('./postgres/secureshopMailDisclosureContract');const barrier=createCompletionPublicationBarrier(),controller=new AbortController();let persisted=0;
 const completion=barrier.wrap(()=>({async evaluate(){persisted++;return {completed:true};}}))({});const pending=completion.evaluate({execution:{signal:controller.signal}});const denied=assert.rejects(pending,/reset/);await barrier.entered;controller.abort(Error('reset'));await denied;assert.equal(persisted,1);barrier.release();
});
