'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {cases,reconstruct,transport,MODEL,DIGEST,DEFAULT_JUDGE,STRONG_JUDGE,admitJudgeIdentity,assertMetadataIdentity}=require('./fixtures/pricingDirectiveGroupsActualJudge');
const opts={method:'POST',body:JSON.stringify({model:MODEL,messages:[],format:{}})};
const frame=(text,done)=>JSON.stringify({model:MODEL,message:{role:'assistant',content:text},done});
const strongOpts={method:'POST',body:JSON.stringify({model:STRONG_JUDGE.model,messages:[],format:{}})};
const strongFrame=(text,done)=>JSON.stringify({model:STRONG_JUDGE.model,message:{role:'assistant',content:text},done});
test('exact14 immutable declarations load once in declared order',()=>{const d=cases(process.cwd());assert.equal(d.cases.length,14);assert.equal(d.cases[0].id,'data_only');assert.equal(d.cases.at(-1).id,'split-compound-condition');});
test('strict stream reconstruction rejects partial, wrong model, extra final frames',()=>{assert.equal(reconstruct(frame('one',false)+'\n'+frame('two',true)+'\n'),'onetwo');assert.equal(reconstruct(frame('one',true)),'one');for(const raw of [frame('one',false),frame('one',true)+'\n'+frame('two',true),frame('one',true).replace(MODEL,'other'),'not JSON'])assert.throws(()=>reconstruct(raw));});
test('strong Judge identity is opt-in and binds metadata, requests, and frames',async()=>{
 assert.strictEqual(admitJudgeIdentity(),DEFAULT_JUDGE);assert.strictEqual(admitJudgeIdentity(STRONG_JUDGE),STRONG_JUDGE);
 for(const value of [null,{}, {model:STRONG_JUDGE.model},{digest:STRONG_JUDGE.digest},{...STRONG_JUDGE,extra:true},{...STRONG_JUDGE,model:MODEL},{...STRONG_JUDGE,digest:DIGEST}])assert.throws(()=>admitJudgeIdentity(value),/JUDGE_IDENTITY_CONFIG/);
 assert.strictEqual(assertMetadataIdentity({models:[{name:STRONG_JUDGE.model,digest:STRONG_JUDGE.digest}]},STRONG_JUDGE),STRONG_JUDGE);
 for(const metadata of [{},{models:[{name:STRONG_JUDGE.model}]},{models:[{name:MODEL,digest:STRONG_JUDGE.digest}]}])assert.throws(()=>assertMetadataIdentity(metadata,STRONG_JUDGE));
 let sent=0;const wire=transport({judgeIdentity:STRONG_JUDGE,signal:new AbortController().signal,profile:'manual24',fetch:async()=>{sent++;return new Response(strongFrame('ok',true));}});
 wire.beginCase('strong');await assert.rejects(()=>wire.fetch('http://127.0.0.1:11434/api/chat',opts));for(let i=0;i<6;i++)assert.equal(reconstruct(await(await wire.fetch('http://127.0.0.1:11434/api/chat',strongOpts)).text(),STRONG_JUDGE),'ok');await assert.rejects(()=>wire.fetch('http://127.0.0.1:11434/api/chat',strongOpts));assert.equal(sent,6);wire.endCase();wire.close();
 assert.throws(()=>reconstruct(strongFrame('wrong default',true)));assert.equal(reconstruct(strongFrame('strong',true),STRONG_JUDGE),'strong');
});
test('all84 HTTP budget includes metadata; case6 budget and endpoint fence apply before upstream',async()=>{
 let sent=0;const t=transport({fetch:async()=>{sent++;return new Response('{}');},signal:new AbortController().signal});
 await(await t.fetch('http://127.0.0.1:11434/api/tags')).text();
 for(let i=0;i<14;i++){t.beginCase('case'+i);for(let j=0;j<6;j++){if(sent===84){await assert.rejects(()=>t.fetch('http://127.0.0.1:11434/api/chat',opts));break;}await(await t.fetch('http://127.0.0.1:11434/api/chat',opts)).text();}if(i===0)await assert.rejects(()=>t.fetch('http://127.0.0.1:11434/api/chat',opts));t.endCase();}
 assert.equal(sent,84);assert.equal(t.calls.length,84);t.close();
 const other=transport({fetch:async()=>{throw Error('must not call');},signal:new AbortController().signal});await assert.rejects(()=>other.fetch('https://example.com/api/tags'));other.close();
});
test('oversize stream retains only bounded prefix and incomplete status',async()=>{
 let aborted=false;const t=transport({fetch:async(url,options)=>{options.signal.addEventListener('abort',()=>{aborted=true;});return new Response(new ReadableStream({start(c){c.enqueue(new Uint8Array(4194304));c.enqueue(new Uint8Array(1));c.close();}}));},signal:new AbortController().signal});t.beginCase('owned');await assert.rejects(async()=>await(await t.fetch('http://127.0.0.1:11434/api/chat',opts)).text());assert.equal(aborted,true);assert.equal(t.calls[0].status,'incomplete');assert(t.calls[0].response.length<=4194304);t.close();
});
test('caller cancellation aborts actual upstream and records no retry',async()=>{
 const c=new AbortController();let calls=0;const t=transport({fetch:(url,options)=>new Promise((resolve,reject)=>{calls++;options.signal.addEventListener('abort',()=>reject(Error('cancelled')),{once:true});}),signal:c.signal});t.beginCase('cancel');const work=t.fetch('http://127.0.0.1:11434/api/chat',opts);c.abort();await assert.rejects(work,/cancelled/);assert.equal(calls,1);assert.equal(t.calls[0].status,'incomplete');t.close();
});
test('case expectations and labels never enter canonical model evidence',()=>{const {packet}=require('./fixtures/pricingDirectiveGroupsActualJudge'),rubric=require('../server/services/secureshopPricingAssessment').PRICING_RUBRICS.ss_pricing_manual_injection,d=cases(process.cwd());for(const item of d.cases){const p=packet(rubric,item,d.question);assert.deepEqual(p.evidence.map(e=>e.content),[item.source,item.response,d.question]);assert.equal(Object.hasOwn(p,'expected'),false);assert.equal(JSON.stringify(p),JSON.stringify(packet(rubric,{...item,expected:'a different expected label',id:'not supplied'},d.question)));}});
test('closed factored phase budgets preserve historical84 default, including failed dispatches',async()=>{for(const [profile,limit]of [['historical84',84],['factored6',37],['factored18',109]]){let dispatched=0;const wire=transport({profile,signal:new AbortController().signal,fetch:async()=>{dispatched++;throw Error('controlled failure');}});await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/tags'));for(let i=1;i<limit;i++){if((i-1)%6===0){if(i>1)wire.endCase();wire.beginCase('case'+i);}await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat',opts));}wire.endCase();wire.beginCase('extra');await assert.rejects(wire.fetch('http://127.0.0.1:11434/api/chat',opts));assert.equal(dispatched,limit);assert.equal(wire.calls.length,limit);wire.close();}for(const profile of ['arbitrary',145,['factored6']])assert.throws(()=>transport({profile}));});
test('manual16 limits the four-stage successor to sixteen inference calls plus metadata',async()=>{
 let sent=0;const wire=transport({judgeIdentity:STRONG_JUDGE,signal:new AbortController().signal,profile:'manual16',fetch:async()=>{sent++;return new Response(strongFrame('ok',true));}});
 await(await wire.fetch('http://127.0.0.1:11434/api/tags')).text();
 for(let i=0;i<4;i++){
  wire.beginCase('v6-'+i);
  for(let j=0;j<4;j++)await(await wire.fetch('http://127.0.0.1:11434/api/chat',strongOpts)).text();
  await assert.rejects(()=>wire.fetch('http://127.0.0.1:11434/api/chat',strongOpts));wire.endCase();
 }
 wire.beginCase('extra');await assert.rejects(()=>wire.fetch('http://127.0.0.1:11434/api/chat',strongOpts));
 assert.equal(sent,17);wire.endCase();wire.close();
});

test('mcpDescription32 admits exactly eight four-stage cases and no additional dispatch',async()=>{
 let sent=0;const wire=transport({profile:'mcpDescription32',signal:new AbortController().signal,fetch:async()=>{sent++;return new Response(frame('ok',true));}});
 for(let i=0;i<8;i++){
  wire.beginCase('mcp-description-'+i);
  for(let j=0;j<4;j++)await(await wire.fetch('http://127.0.0.1:11434/api/chat',opts)).text();
  await assert.rejects(()=>wire.fetch('http://127.0.0.1:11434/api/chat',opts));wire.endCase();
 }
 wire.beginCase('extra');await assert.rejects(()=>wire.fetch('http://127.0.0.1:11434/api/chat',opts));
 assert.equal(sent,32);assert.equal(wire.calls.length,32);wire.endCase();wire.close();
});
