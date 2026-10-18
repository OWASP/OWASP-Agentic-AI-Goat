'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {qualifyStandaloneSsrfRendered,qualifyPolicyOutputRendered,createCommittedSsrfAckLoss,assertCounters,exactRunRequest,exactPolicyRunRequest,exactPolicyRunResponse,assertPolicyAssessment,TOTAL_MODEL_CALLS,RUN_PATH,HTML_RUN_PATH,_internals}=require('./fixtures/secureshopStandaloneSsrfRenderedQualification');
const requestId='10000000-0000-4000-8000-000000000001',sessionId='20000000-0000-4000-8000-000000000001';
const counts=(actor=0,judge=0)=>({actor,judge,http:0,turns:0,invocations:0,traces:0,judgments:0,contributions:0});
// Data/browser handles are controlled contracts. One bounded loopback HTTP
// test verifies fault framing; no browser, PostgreSQL store or inference runs.
function exchange({resource='private-policy',status=200,url=RUN_PATH}={}){
 const request={originalUrl:url,method:'POST',body:{resource,request_id:requestId},ssLaunch:{launchId:'30000000-0000-4000-8000-000000000001',platformOwnerId:1,platformSessionId:2,generation:1},boundPersona:{id:3,role:'customer'},ssPersonaSession:{sessionId,authorityVersion:'1'}};
 const response=new EventEmitter();response.statusCode=status;response.jsonCalls=[];response.destroyCalls=0;
 response.json=function(body){this.jsonCalls.push(body);return this;};response.destroy=function(){if(!this.destroyCalls++)this.emit('close');};
 response.written=[];response.writeHead=function(code,headers){this.statusCode=code;this.headers=headers;return this;};
 response.flushHeaders=function(){this.headersFlushed=true;};response.write=function(bytes,done){this.written.push(Buffer.from(bytes));queueMicrotask(()=>done());return true;};
 const packet={resourceKind:resource,replayed:false,stopReason:'end_turn',response:'Controlled source bytes'};
 return {request,response,packet};
}
const source=packet=>({requestId,sessionId,status:'completed',result:{stopReason:'end_turn',text:packet.response,hops:[{controlled:true}]}});
const policyMode=mode=>({version:1,featureId:'controlled_ssrf',policyVersion:'owned-public-destination-v1',effectiveMode:mode,scope:{kind:'launch_feature',id:'controlled_ssrf'}});
const policyPacket=(mode='vuln')=>({sessionId,requestId,response:'Original controlled final answer',stopReason:'end_turn',replayed:false,modeCapability:policyMode(mode)});

test('14-call total is closed and smaller than the approved outer actor/Judge ceilings',()=>{
 assert.equal(TOTAL_MODEL_CALLS,14);for(const pair of [[6,1],[10,4],[13,1]])assert.deepEqual(assertCounters(counts(...pair),{complete:true}),counts(...pair));
 for(const bad of [counts(14,1),counts(10,5),counts(5,1),counts(6,0),{...counts(6,1),actor:1.5},{...counts(6,1),http:-1},{...counts(6,1),actualModelProof:true}])assert.throws(()=>assertCounters(bad,{complete:true}));
});

test('actual browser POST schema admits only resource and unchanged UUID',()=>{
 assert.deepEqual(exactRunRequest({resource:'private-policy',request_id:requestId}),{resource:'private-policy',request_id:requestId});
 for(const bad of [{resource:'internal',request_id:requestId},{resource:'private-policy',request_id:'bad'},{resource:'private-policy',request_id:requestId,policy_url:'http://127.0.0.1'},{resource:'private-policy',request_id:requestId,scope:{}}])assert.throws(()=>exactRunRequest(bad));
});

test('one-shot ACK controller withholds only original successful private packet after matching durable source witness',async()=>{
 const e=exchange(),seen=[];const controller=createCommittedSsrfAckLoss({onCommitted:async row=>{seen.push(row);return source(row.packet);}});
 controller.arm();let next=0;controller.middleware(e.request,e.response,()=>next++);assert.equal(next,1);
 assert.equal(e.response.json(e.packet),e.response);const row=await controller.wait();
 assert.equal(e.response.jsonCalls.length,0);assert.equal(e.response.destroyCalls,1);assert.equal(seen.length,1);
 assert.deepEqual(row.request,e.request.body);assert.deepEqual(row.packet,e.packet);assert.deepEqual(row.source,source(e.packet));assert.equal(row.responseClosed,true);assert.deepEqual(row.authority,{scope:e.request.ssLaunch,persona:e.request.boundPersona,personaSession:e.request.ssPersonaSession});
 assert.equal(row.responseBody,JSON.stringify(e.packet));assert.equal(row.responseBodySha256,require('node:crypto').createHash('sha256').update(row.responseBody).digest('hex'));
 assert.equal(e.response.headersFlushed,true);assert.equal(e.response.headers['content-length'],Buffer.byteLength(row.responseBody));assert.equal(Buffer.concat(e.response.written).toString(),row.responseBody.slice(0,1));
 assert.throws(()=>controller.arm(),/One committed ACK-loss attempt/);
 const second=exchange();controller.middleware(second.request,second.response,()=>{});second.response.json(second.packet);assert.equal(second.response.jsonCalls.length,1);
 await controller.close();assert.equal(controller.snapshot().closed,true);
});

test('committed ACK fault sends original headers and an incomplete original body through real loopback HTTP', {timeout:5000}, async()=>{
 const http=require('node:http'),originalPacket=exchange().packet,originalBody=JSON.stringify(originalPacket);
 const controller=createCommittedSsrfAckLoss({onCommitted:async row=>source(row.packet)});
 const sockets=new Set();let posts=0;
 const server=http.createServer((request,response)=>{
  posts++;assert.equal(request.method,'POST');assert.equal(request.url,RUN_PATH);
  const controlled=exchange().request;
  Object.assign(request,{originalUrl:request.url,body:controlled.body,ssLaunch:controlled.ssLaunch,
   boundPersona:controlled.boundPersona,ssPersonaSession:controlled.ssPersonaSession});
  response.json=function(value){this.end(JSON.stringify(value));return this;};
  controller.middleware(request,response,()=>response.json(originalPacket));
 });
 server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
 try{
  await new Promise((yes,no)=>{server.once('error',no);server.listen(0,'127.0.0.1',yes);});
  controller.arm();
  const observed=await new Promise((yes,no)=>{
   const client=http.request({hostname:'127.0.0.1',port:server.address().port,path:RUN_PATH,method:'POST'},response=>{
    const parts=[];let settled=false;
    const finish=()=>{if(!settled){settled=true;yes({status:response.statusCode,headers:response.headers,
     complete:response.complete,body:Buffer.concat(parts).toString()});}};
    response.on('data',chunk=>parts.push(chunk));response.once('end',finish);response.once('aborted',finish);
    response.once('error',finish);
   });
   client.setTimeout(2000,()=>client.destroy(Error('Controlled HTTP fault deadline')));
   client.once('error',no);client.end(JSON.stringify(exchange().request.body));
  });
  const captured=await controller.wait();
  assert.equal(posts,1);assert.equal(observed.status,200);assert.equal(observed.complete,false);
  assert.equal(Number(observed.headers['content-length']),Buffer.byteLength(originalBody));
  assert.equal(observed.headers['content-type'],'application/json');
  assert.equal(observed.body,originalBody.slice(0,1));assert.throws(()=>JSON.parse(observed.body));
  assert.equal(captured.responseBody,originalBody);assert.deepEqual(captured.packet,originalPacket);
  assert.deepEqual(captured.source,source(originalPacket));assert.equal(captured.responseClosed,true);
 }finally{
  await controller.close();for(const socket of sockets)socket.destroy();
  await new Promise((yes,no)=>server.close(error=>error?no(error):yes()));
 }
});

test('public, failed, unfinished and unrelated responses preserve original response semantics',async t=>{
 for(const [name,options,change]of [['public',{resource:'public-policy'},null],['failed',{status:503},null],['unrelated',{url:'/api/other'},null],['unfinished',{},p=>p.stopReason='max_steps'],['blank',{},p=>p.response='']])await t.test(name,async()=>{
  let callback=0;const controller=createCommittedSsrfAckLoss({onCommitted:async()=>{callback++;throw Error('Forbidden');}}),e=exchange(options);change?.(e.packet);controller.arm();controller.middleware(e.request,e.response,()=>{});
  assert.equal(e.response.json(e.packet),e.response);assert.deepEqual(e.response.jsonCalls,[e.packet]);assert.equal(callback,0);assert.equal(e.response.destroyCalls,0);await controller.close();
 });
});

test('actual failed or nonterminal private response immediately settles ACK wait and retains original packet',async t=>{
 for(const [name,status,change]of [['model unavailable',503,p=>{delete p.response;p.error='Controlled SSRF exercise unavailable';}],['nonterminal',200,p=>p.stopReason='max_steps'],['empty answer',200,p=>p.response='']])await t.test(name,async()=>{
  let sourceReads=0;const controller=createCommittedSsrfAckLoss({onCommitted:async()=>{sourceReads++;throw Error('Must not infer completed source');}}),e=exchange({status});change(e.packet);controller.arm();controller.middleware(e.request,e.response,()=>{});assert.equal(e.response.json(e.packet),e.response);
  await assert.rejects(controller.wait(),error=>error.code==='SSRF_PRIVATE_RESPONSE_INCOMPLETE');assert.deepEqual(e.response.jsonCalls,[e.packet]);assert.equal(e.response.destroyCalls,0);assert.equal(sourceReads,0);assert.equal(controller.snapshot().record.status,status);assert.deepEqual(controller.snapshot().record.packet,e.packet);assert.equal(controller.snapshot().record.source,null);await controller.close();
 });
});

test('arm-time response deadline settles when model returns no packet',async()=>{
 const controller=createCommittedSsrfAckLoss({responseTimeoutMs:5,onCommitted:async()=>{throw Error('No completed packet');}}),e=exchange();controller.arm();controller.middleware(e.request,e.response,()=>{});
 await assert.rejects(controller.wait(),error=>error.code==='SSRF_PRIVATE_RESPONSE_TIMEOUT');assert.equal(e.response.jsonCalls.length,0);assert.equal(e.response.destroyCalls,1);assert.equal(controller.snapshot().record,null);await controller.close();
});

test('wrong request, unfinished source or different original text never becomes a committed witness',async t=>{
 for(const [name,mutate]of [['other request',s=>s.requestId=sessionId],['unfinished source',s=>s.status='prepared'],['different answer',s=>s.result.text='Fabricated answer'],['extra claimed provenance',s=>s.genuineCredit=1]])await t.test(name,async()=>{
  const controller=createCommittedSsrfAckLoss({onCommitted:async row=>{const s=source(row.packet);mutate(s);return s;}}),e=exchange();controller.arm();controller.middleware(e.request,e.response,()=>{});e.response.json(e.packet);
  await assert.rejects(controller.wait());assert.equal(e.response.jsonCalls.length,0);assert.equal(e.response.destroyCalls,1);assert.equal(controller.snapshot().record.source,null);await controller.close();
 });
});

test('native witness error is rethrown unchanged and ACK waiter is immediately handled',async()=>{
 const original=Object.assign(Error('Controlled source query failed'),{code:'42501'}),controller=createCommittedSsrfAckLoss({onCommitted:async()=>{throw original;}}),e=exchange();controller.arm();controller.middleware(e.request,e.response,()=>{});e.response.json(e.packet);
 await assert.rejects(controller.wait(),error=>error===original);await controller.close();assert.equal(e.response.destroyCalls,1);
});

test('closing a pending readonly source witness destroys held response and settles waiter',async()=>{
 let signal,release;const controller=createCommittedSsrfAckLoss({onCommitted:row=>{signal=row.signal;return new Promise(done=>{release=done;});}}),e=exchange();controller.arm();controller.middleware(e.request,e.response,()=>{});e.response.json(e.packet);
 await Promise.resolve();await controller.close();assert.equal(signal.aborted,true);assert.equal(e.response.destroyCalls,1);await assert.rejects(controller.wait(),/closed before durable source/);
 release(source(e.packet));await Promise.resolve();assert.equal(controller.snapshot().record.source,null);
});

test('closing after committed source but before the deferred write callback settles the ACK wait', {timeout:1000}, async()=>{
 const e=exchange();let writeDone,started;
 const writing=new Promise(resolve=>{started=resolve;});
 e.response.write=function(bytes,done){this.written.push(Buffer.from(bytes));writeDone=done;started();return true;};
 const controller=createCommittedSsrfAckLoss({onCommitted:async row=>source(row.packet)});
 controller.arm();controller.middleware(e.request,e.response,()=>{});e.response.json(e.packet);
 await writing;
 assert.deepEqual(controller.snapshot().record.source,source(e.packet));
 assert.equal(e.response.destroyCalls,0);
 await controller.close();
 await assert.rejects(controller.wait(),/closed before response completion/);
 assert.equal(e.response.destroyCalls,1);assert.equal(controller.snapshot().record.responseClosed,true);
 assert.deepEqual(controller.snapshot().record.source,source(e.packet));
 writeDone();await Promise.resolve();
 await assert.rejects(controller.wait(),/closed before response completion/);
 assert.equal(e.response.destroyCalls,1);
});

test('source-witness deadline settles without inventing response or successful source',async()=>{
 const controller=createCommittedSsrfAckLoss({timeoutMs:5,onCommitted:()=>new Promise(()=>{})}),e=exchange();controller.arm();controller.middleware(e.request,e.response,()=>{});e.response.json(e.packet);
 await assert.rejects(controller.wait(),/witness timed out/);assert.equal(e.response.jsonCalls.length,0);assert.equal(e.response.destroyCalls,1);assert.equal(controller.snapshot().record.source,null);await controller.close();
});

test('response observer settles original error and aborts dangling waits during cleanup',async()=>{
 let signal,reject;const original=Error('Controlled page closed');const wait=_internals.observeResponse({waitForResponse(_predicate,options){signal=options.signal;return new Promise((_resolve,no)=>{reject=no;});}},()=>true,30);
 reject(original);await assert.rejects(wait.read(),e=>e===original);await wait.close();assert.equal(signal.aborted,true);
});

test('physical control uses handle click only after hit-test wait and retains actual geometry',async()=>{
 const events=[],element={tagName:'BUTTON',textContent:'Try internal policy',scrollIntoView(){events.push('scroll');},getBoundingClientRect(){return{left:10,top:20,width:30,height:40};}};
 const button={async evaluate(fn){return fn(element);},async click(){events.push('physical-click');}},surface={async waitForFunction(){events.push('wait');return{asElement:()=>button};}};
 assert.deepEqual(await _internals.physicalButton(surface,'Try internal policy'),{x:25,y:40,tagName:'BUTTON',text:'Try internal policy'});assert.deepEqual(events,['wait','scroll','wait','physical-click']);
 let calls=0;const blocked={...surface,async waitForFunction(){if(calls++)throw Error('Controlled hit-test blocked');return{asElement:()=>button};}};await assert.rejects(_internals.physicalButton(blocked,'Try internal policy'),/hit-test blocked/);assert.equal(events.filter(x=>x==='physical-click').length,1);
});

test('Fixed selection physically opens real parent Shop settings and closes it before another frame action',async()=>{
 const fs=require('node:fs'),path=require('node:path'),source=fs.readFileSync(path.resolve(__dirname,'../client/src/pages/secureshop/SecureShopStandaloneBound.jsx'),'utf8');
 assert.match(source,/useState\(false\)/);assert.match(source,/settingsOpen && <aside id="secureshop-settings"/);assert.match(source,/aria-controls="secureshop-settings"/);assert.match(source,/<SecureShopStandaloneModeControl client=\{client\}/);
 let open=false;const clicks=[],captures=[];const page={
  async waitForFunction(_fn,_options,label){assert(label==='Shop settings'||open,'Fixed is unavailable before settings opens');const element={tagName:'BUTTON',textContent:label,scrollIntoView(){},getBoundingClientRect(){return{left:1,top:2,width:8,height:8};}};
   return{asElement:()=>({async evaluate(fn){return fn(element);},async click(){clicks.push(label);if(label==='Shop settings')open=!open;}})};},
  async waitForSelector(selector,options){assert.equal(selector,'aside#secureshop-settings');assert.equal(open,options.visible===true);},
 };
 const result=await _internals.selectFixedThroughSettings(page,{observe:predicate=>{assert(open);assert(predicate({request:()=>({method:()=> 'POST'}),url:()=> 'http://127.0.0.1:1/api/secureshop/auth/mode'}));return{async read(){assert.deepEqual(clicks,['Shop settings','Fixed']);return{status:()=>200,json:async()=>({mode:'fixed',revision:'2'})};}};},onCapture:async value=>captures.push(value)});
 assert.deepEqual(clicks,['Shop settings','Fixed','Shop settings']);assert.equal(open,false);assert.equal(result.settingsClosed,true);assert.equal(result.response.body.mode,'fixed');assert.equal(captures[0].response,null);assert.equal(captures[1].settingsClosed,false);assert.equal(captures.at(-1).settingsClosed,true);
});

test('flow initialization failure closes only owned context/controller and never produces qualification',async()=>{
 let contexts=0,controllers=0;const captures=[],original=Error('Controlled browser page unavailable');const ackLoss={arm(){},wait(){throw Error('Unused');},snapshot(){},async close(){controllers++;}};
 const browser={async createBrowserContext(){return{async newPage(){throw original;},async close(){contexts++;}};}};
 await assert.rejects(qualifyStandaloneSsrfRendered({browser,origin:'http://127.0.0.1:1',credentials:{username:'synthetic',password:'synthetic-only'},evidenceDirectory:'/owned/fixture',ackLoss,bindBootstrap:async()=>{},readCase:async()=>{},readCounters:async()=>counts(),readPrivateSnapshot:async()=>{},onCapture:async e=>captures.push(e)}),e=>e===original);
 assert.equal(contexts,1);assert.equal(controllers,1);assert(captures.some(e=>e.phase==='failed'));assert.equal(captures.at(-1).contextsClosed,true);assert.equal(captures.at(-1).ackControllerClosed,true);assert.equal(captures.at(-1).modelCounters.actor,0);assert.equal(captures.at(-1).modelCounters.judge,0);assert.equal(captures.at(-1).qualifiedObjectiveIds,undefined);
});

test('V27 physical request and original six-key response bind exact UUID, HTML and mode',()=>{
 const request={request_id:requestId,policy_html:'<p>Owned synthetic policy</p>'};
 assert.deepEqual(exactPolicyRunRequest(request),request);
 for(const bad of [{...request,resource:'public-policy'},{...request,policy_html:''},{...request,policy_html:'x'.repeat(8193)},{...request,policy_html:'\ud800'},{...request,policy_html:'a\0b'},{...request,request_id:'bad'}])assert.throws(()=>exactPolicyRunRequest(bad));
 const packet=policyPacket();assert.equal(exactPolicyRunResponse(packet,{requestId,mode:'vuln'}),packet);
 assert.equal(exactPolicyRunResponse({...packet,replayed:true},{requestId,sessionId,mode:'vuln',replayed:true}).replayed,true);
 for(const bad of [{...packet,resourceKind:'html-policy'},{...packet,requestId:sessionId},{...packet,sessionId:'bad'},{...packet,replayed:true},{...packet,stopReason:'max_steps'},{...packet,response:'x'.repeat(20001)},{...packet,modeCapability:policyMode('fixed')},{...packet,modeCapability:{...policyMode('vuln'),policyVersion:'stale'}},{...packet,response:'\ud800'}])assert.throws(()=>exactPolicyRunResponse(bad,{requestId,mode:'vuln'}));
 assert.throws(()=>exactPolicyRunResponse(packet,{requestId,sessionId:requestId,mode:'vuln'}));
});

test('V27 ACK option withholds only armed original HTML response and retains exact durable text/session',async()=>{
 const e=exchange({url:HTML_RUN_PATH});e.request.body={request_id:requestId,policy_html:'<p>Owned source</p>'};e.packet=policyPacket();
 const controller=createCommittedSsrfAckLoss({policyOutput:true,onCommitted:async row=>source(row.packet)});
 controller.arm();const unrelated=exchange();controller.middleware(unrelated.request,unrelated.response,()=>{});unrelated.response.json(unrelated.packet);
 assert.equal(unrelated.response.jsonCalls.length,1);assert.equal(controller.snapshot().used,false);
 controller.middleware(e.request,e.response,()=>{});e.response.json(e.packet);const retained=await controller.wait();
 assert.equal(e.response.jsonCalls.length,0);assert.deepEqual(retained.packet,e.packet);assert.deepEqual(retained.request,e.request.body);assert.equal(retained.responseBody,JSON.stringify(e.packet));assert.equal(retained.source.sessionId,e.packet.sessionId);await controller.close();
});

test('V27 ACK wrong durable session never becomes a committed witness',async()=>{
 const e=exchange({url:HTML_RUN_PATH});e.request.body={request_id:requestId,policy_html:'<p>Owned source</p>'};e.packet=policyPacket();
 const controller=createCommittedSsrfAckLoss({policyOutput:true,onCommitted:async row=>({...source(row.packet),sessionId:requestId})});
 controller.arm();controller.middleware(e.request,e.response,()=>{});e.response.json(e.packet);await assert.rejects(controller.wait());assert.equal(controller.snapshot().record.source,null);assert.equal(e.response.destroyCalls,1);await controller.close();
});

test('V27 ACK refuses fixed, forged, nonterminal and failed original packets without altering original errors',async t=>{
 for(const [name,change,status]of [['fixed',p=>p.modeCapability=policyMode('fixed'),200],['extra key',p=>p.genuineCredit=true,200],['nonterminal',p=>p.stopReason='max_steps',200],['foreign request',p=>p.requestId=sessionId,200],['failed',p=>{p.error='Original unavailable';delete p.response;},503]])await t.test(name,async()=>{
  const e=exchange({url:HTML_RUN_PATH,status});e.request.body={request_id:requestId,policy_html:'<p>Owned source</p>'};e.packet=policyPacket();change(e.packet);let reads=0;
  const controller=createCommittedSsrfAckLoss({policyOutput:true,onCommitted:async()=>{reads++;throw Error('No completed source');}});
  controller.arm();controller.middleware(e.request,e.response,()=>{});e.response.json(e.packet);await assert.rejects(controller.wait(),error=>error.code==='SSRF_PRIVATE_RESPONSE_INCOMPLETE');
  assert.deepEqual(e.response.jsonCalls,[e.packet]);assert.equal(reads,0);assert.equal(controller.snapshot().record.source,null);await controller.close();
 });
});

test('V27 producer-shaped baseline/fixed and POST/GET assessment markers are mandatory',()=>{
 const fixed={completed:false,status:'ineligible',modelEvaluated:false},baseline={...fixed,replayed:false};
 assert.equal(assertPolicyAssessment(fixed,'fixed'),fixed);assert.equal(assertPolicyAssessment(baseline,'baseline'),baseline);
 const passed={completed:true,judgment:{evaluationId:sessionId,verdict:'pass'},replayed:false},saved={...passed,replayed:true};
 assert.equal(assertPolicyAssessment(passed,'attack'),passed);assert.equal(assertPolicyAssessment(saved,'recovered-attack'),saved);
 for(const [bad,kind]of [[fixed,'baseline'],[baseline,'fixed'],[{...baseline,replayed:true},'baseline'],[{...fixed,modelEvaluated:true},'fixed'],[passed,'recovered-attack'],[saved,'attack'],[{completed:true,judgment:passed.judgment},'attack'],[{...passed,completed:false},'attack'],[{...passed,judgment:{evaluationId:sessionId,verdict:'fail'}},'attack'],[{...passed,judgment:{verdict:'pass'}},'attack']])assert.throws(()=>assertPolicyAssessment(bad,kind));
});

test('V27 physical clearing removes retained multiline baseline without native select-all shortcuts',async()=>{
 const {POLICY_OUTPUT_BASELINE,POLICY_OUTPUT_ATTACK}=require('./fixtures/secureshopStandaloneSsrfQualification');
 const events=[],element={value:POLICY_OUTPUT_BASELINE+'\nsecond line',cursor:4,scrollIntoView(){events.push('scroll');}};
 const original=element.value;let focused=false;
 const input={async click(){events.push('click');focused=true;},async type(text){events.push(['type',text]);assert.equal(element.value,'');element.value=element.value.slice(0,element.cursor)+text+element.value.slice(element.cursor);element.cursor+=text.length;},async evaluate(fn){return fn(element);}};
 const keyboard={async press(key){events.push(key);assert(focused);if(key==='ArrowRight')element.cursor=Math.min(element.value.length,element.cursor+1);else if(key==='Backspace'&&element.cursor>0){element.value=element.value.slice(0,element.cursor-1)+element.value.slice(element.cursor);element.cursor--;}}};
 let waits=0;const frame={async waitForSelector(selector){assert.equal(selector,'textarea[aria-label="Policy HTML"]');return input;},async waitForFunction(){waits++;},page:()=>({keyboard})};
 assert.deepEqual(await _internals.physicallyTypePolicy(frame,POLICY_OUTPUT_ATTACK),{selector:'textarea[aria-label="Policy HTML"]',value:POLICY_OUTPUT_ATTACK});
 assert.equal(waits,3);assert.deepEqual(events.slice(0,2),['scroll','click']);assert.deepEqual(events.slice(2,original.length+3),Array(original.length+1).fill('ArrowRight'));
 assert.deepEqual(events.slice(original.length+3,-1),Array(original.length+1).fill('Backspace'));assert.deepEqual(events.at(-1),['type',POLICY_OUTPUT_ATTACK]);
 assert.equal(element.value,POLICY_OUTPUT_ATTACK);
 // A broken deletion must fail at the empty readback before typing a duplicate.
 element.value=POLICY_OUTPUT_BASELINE;element.cursor=0;const typed=events.filter(e=>Array.isArray(e)&&e[0]==='type').length;
 keyboard.press=async key=>{if(key==='ArrowRight')element.cursor=Math.min(element.value.length,element.cursor+1);};
 await assert.rejects(_internals.physicallyTypePolicy(frame,POLICY_OUTPUT_ATTACK));assert.equal(events.filter(e=>Array.isArray(e)&&e[0]==='type').length,typed);assert.equal(element.value,POLICY_OUTPUT_BASELINE);
});

test('V27 blocked hit-test or missing focus stops before clearing or typing',async()=>{
 for(const blocked of [2,3]){
  let waits=0,keys=0,typed=0;const input={async click(){},async evaluate(fn){return fn({value:'old',scrollIntoView(){}});},async type(){typed++;}};
  const frame={async waitForSelector(){return input;},async waitForFunction(){if(++waits===blocked)throw Error('Controlled input admission blocked');},page:()=>({keyboard:{async press(){keys++;}}})};
  await assert.rejects(_internals.physicallyTypePolicy(frame,'new'),/input admission blocked/);assert.equal(keys,0);assert.equal(typed,0);
 }
});

test('V27 initialization failure retains actual counters and closes owned context without invoking evidence or lifecycle callbacks',async()=>{
 let closed=0,ackClosed=0;const captures=[],original=Error('Controlled page unavailable');
 const ackLoss={arm(){},wait(){throw Error('Unused');},snapshot(){return{used:false};},async close(){ackClosed++;}};
 const forbidden=async()=>{throw Error('Evidence callback must not run');};
 await assert.rejects(qualifyPolicyOutputRendered({browser:{async createBrowserContext(){return{async newPage(){throw original;},async close(){closed++;}};}},origin:'http://127.0.0.1:1',credentials:{username:'synthetic',password:'synthetic-only'},evidenceDirectory:'/owned/fixture',ackLoss,bindBootstrap:forbidden,readOriginal:forbidden,readAssessment:forbidden,readCounters:async()=>counts(),readPublicProgress:forbidden,verifyLifecycle:forbidden,onCapture:async e=>captures.push(e)}),error=>error===original);
 assert.equal(closed,1);assert.equal(ackClosed,1);assert.equal(captures.at(-1).contextsClosed,true);assert.equal(captures.at(-1).ackControllerClosed,true);assert.equal(captures.at(-1).modelCounters.actor,0);assert.equal(captures.at(-1).qualifiedObjectiveIds,undefined);
});

// Use the existing frontend DOM dependency for deterministic read-only witness
// controls. These synthetic DOMs are not browser execution or qualification.
function policyDomFixture(html){
 const {JSDOM}=require('../client/node_modules/jsdom');
 const dom=new JSDOM('<section><h2 id="policy-final-html-title">Policy answer</h2><div data-testid="agent-turn-reply"></div></section>',{runScripts:'outside-only'});
 const reply=dom.window.document.querySelector('[data-testid="agent-turn-reply"]');reply.innerHTML=html;
 dom.window.HTMLElement.prototype.getClientRects=function(){return[{left:1,top:1,width:30,height:12}];};
 const H=require('./fixtures/secureshopStandaloneSsrfQualification');
 const contract={handler:H.POLICY_OUTPUT_HANDLER,selector:H.POLICY_OUTPUT_MARKER_SELECTOR,text:H.POLICY_OUTPUT_MARKER_TEXT};
 const observe=dom.window.eval('('+_internals.policyDomObservation.toString()+')');
 return{dom,reply,H,read:(text,mode='vuln',markerRequired=true)=>observe(text,mode,markerRequired,contract)};
}

test('V27 marker witness admits only generated adjacent marker and reconstructs whole original DOM without mutating it',()=>{
 const H=require('./fixtures/secureshopStandaloneSsrfQualification'),original='<p>Original policy</p>'+H.POLICY_OUTPUT_CANARY_HTML;
 const fixture=policyDomFixture(original);
 try{
  assert.equal(fixture.read(original),null,'Active markup alone cannot establish handler execution');
  const img=fixture.reply.querySelector('img');
  // Simulate the exact completed handler effect in this controlled DOM only.
  img.insertAdjacentHTML('afterend','<strong data-v27-owned-canary="executed">v27-owned-canary</strong>');
  const before=fixture.reply.innerHTML,value=fixture.read(original);
  assert.equal(value.marker.text,H.POLICY_OUTPUT_MARKER_TEXT);assert.equal(value.marker.adjacentToOriginalImage,true);assert.equal(value.marker.visible,true);
  assert.equal(value.originalHtml,value.reconstructedHtml);assert.equal(value.html,before);assert.equal(fixture.reply.innerHTML,before,'Observer may not remove the actual marker');
  assert.equal(fixture.reply.querySelector('img').getAttribute('onerror'),H.POLICY_OUTPUT_HANDLER);
 }finally{fixture.dom.window.close();}
});

test('V27 static marker in original final answer, duplicate or foreign handlers cannot qualify',()=>{
 const H=require('./fixtures/secureshopStandaloneSsrfQualification'),marker='<strong data-v27-owned-canary="executed">v27-owned-canary</strong>';
 const f=policyDomFixture(H.POLICY_OUTPUT_CANARY_HTML+marker);
 try{
  for(const html of [H.POLICY_OUTPUT_CANARY_HTML+marker,H.POLICY_OUTPUT_CANARY_HTML+'<template>'+marker+'</template>'])assert.throws(()=>f.read(html),/static marker/);
  for(const html of ['<p>Reference only</p>',H.POLICY_OUTPUT_CANARY_HTML+H.POLICY_OUTPUT_CANARY_HTML,'<img src=x onerror="alert(\'v27-owned-canary\')">'])assert.throws(()=>f.read(html),/exactly one owned image handler/);
 }finally{f.dom.window.close();}
});

test('V27 unrelated, hidden, malformed or duplicate live marker and other DOM changes fail exact attribution',()=>{
 const H=require('./fixtures/secureshopStandaloneSsrfQualification'),original='<p>Original policy</p>'+H.POLICY_OUTPUT_CANARY_HTML,marker='<strong data-v27-owned-canary="executed">v27-owned-canary</strong>';
 for(const actual of [marker+original,original+'<i>intervening</i>'+marker,original+marker+marker,original+marker.replace('v27-owned-canary</strong>','wrong</strong>'),original+marker.replace('</strong>','<i></i></strong>'),original+marker.replace('="executed"','="other"'),original+marker.replace('>v27-',' hidden>v27-'),original+marker+'<p>Unrelated mutation</p>',original.replace('Original policy','Different policy')+marker]){
  const f=policyDomFixture(actual);try{assert.equal(f.read(original),null,actual);}finally{f.dom.window.close();}
 }
 const f=policyDomFixture(original+marker);try{f.reply.querySelector('strong').getClientRects=()=>[];assert.equal(f.read(original),null);}finally{f.dom.window.close();}
});

test('V27 fixed output is literal original text with no marker or active nodes',()=>{
 const H=require('./fixtures/secureshopStandaloneSsrfQualification'),original='<p>Policy</p>'+H.POLICY_OUTPUT_CANARY_HTML;
 const f=policyDomFixture('');try{
  f.reply.textContent=original;const before=f.reply.innerHTML,value=f.read(original,'fixed',false);
  assert.equal(value.text,original);assert.equal(value.activeElements,0);assert.equal(value.marker,null);assert.equal(f.reply.innerHTML,before);
  f.reply.innerHTML=original;assert.equal(f.read(original,'fixed',false),null);
 }finally{f.dom.window.close();}
});
