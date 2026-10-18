'use strict';const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');
test('V11 staged caller has no second reload and no manifest guard constants',()=>{const s=fs.readFileSync(require.resolve('./secureshopMailAgentReadRenderedLifecycle'),'utf8');assert.equal((s.match(/armReload\(/g)||[]).length,1);assert.equal((s.match(/finishReload\(/g)||[]).length,1);assert.equal(s.includes('runV11Qualification'),false);for(const token of ['assertRecoveryCounts(reloadBefore','mailReadEffectRows','judgeCalls','credits','ownerSnapshot','siblingSnapshot','activeContribution','assessmentPosts','savedAssessmentGets'])assert.equal(s.includes(token),true,token);});

const C=require('./secureshopMailAgentReadRenderedLifecycle');
const Q=require('./secureshopMailAgentReadRenderedQualification');const{createHash}=require('node:crypto');
const priorModel=process.env.OLLAMA_MODEL;
test.before(()=>{process.env.OLLAMA_MODEL='controlled-v11';});
test.after(()=>{if(priorModel===undefined)delete process.env.OLLAMA_MODEL;else process.env.OLLAMA_MODEL=priorModel;});
function fixedFixture(deniedHopCount=1){
 const choiceId='55555555-5555-4555-8555-555555555555',sessionId='66666666-6666-4666-8666-666666666666',requestId='77777777-7777-4777-8777-777777777777';
 const selection={choiceId,intent:'mail_list'},message='Show this recipient’s mailbox.',text='Mailbox access is forbidden.';
 const fixedTurn={body:{sessionId,requestId,message,selection},receipt:{sessionId,requestId,status:'completed',stopReason:'end_turn',text,mailRead:null,hops:[]}};
 const messages=[{role:'system',content:'Controlled fixed mail catalog'},{role:'user',content:JSON.stringify({version:1,role:'merchant',message,selection})}],actorWires=Array.from({length:10},()=>({kind:'actor'}));
 const expected={agent:'merchant',tool:'mail_list',args:{choiceId}};
 const wire=(input,output)=>{const request=JSON.stringify({model:process.env.OLLAMA_MODEL,messages:input}),response=JSON.stringify({model:process.env.OLLAMA_MODEL,message:{role:'assistant',content:JSON.stringify(output)},done:true,done_reason:'stop'})+'\n',hash=value=>createHash('sha256').update(value).digest('hex');return{kind:'actor',status:200,terminalReason:'end',responseComplete:true,responseCaptureTruncated:false,model:process.env.OLLAMA_MODEL,request,requestBytes:Buffer.byteLength(request),requestSha256:hash(request),response,responseBytes:Buffer.byteLength(response),responseObservedBytes:Buffer.byteLength(response),responseChunkCount:1,responseSha256:hash(response)};};
 for(let index=0;index<deniedHopCount;index++){
  actorWires.push(wire(messages,{tool_calls:[expected]}));const id=`ollama_controlled-${index}`;
  messages.push({role:'assistant',content:JSON.stringify({tool_calls:[{id,...expected}]})},{role:'user',content:`Tool observation for completed call ${JSON.stringify(id)} (tool result):\nERROR: Mailbox forbidden`});
  fixedTurn.receipt.hops.push({step:index+1,tool:'merchant.mail_list',params:{choiceId},result:{isError:true,content:[{type:'text',text:'ERROR: Mailbox forbidden'}]}});
 }
 actorWires.push(wire(messages,{reply:text}));return{actorCallsBefore:10,actorWires,fixedTurn,fixedChoice:{choiceId},wire};
}
test('saved GET changes only its exact GET counter',()=>{const before=Object.fromEntries(C.V11_COUNT_KEYS.map(k=>[k,0])),after={...before,savedAssessmentGets:1};assert.equal(C.assertRecoveryCounts(before,after),true);for(const key of C.V11_COUNT_KEYS.filter(k=>k!=='savedAssessmentGets'))assert.throws(()=>C.assertRecoveryCounts(before,{...after,[key]:1}),undefined,key);assert.throws(()=>C.assertRecoveryCounts(before,{...after,sourceReads:0}));assert.throws(()=>C.assertRecoveryCounts(before,{...after,savedAssessmentGets:2}));});

test('fixed protected POST changes only its POST counter',()=>{const before=Object.fromEntries(C.V11_COUNT_KEYS.map(k=>[k,4])),after={...before,assessmentPosts:5};assert.equal(C.assertFixedCounts(before,after),true);for(const key of C.V11_COUNT_KEYS.filter(k=>k!=='assessmentPosts'))assert.throws(()=>C.assertFixedCounts(before,{...after,[key]:after[key]+1}),undefined,key);assert.throws(()=>C.assertFixedCounts(before,{...after,assessmentPosts:6}));});

test('physical Assess owns the first persisted reference and lifecycle retains its exact snapshot',async()=>{
 const ids={sessionId:'11111111-1111-4111-8111-111111111111',requestId:'22222222-2222-4222-8222-222222222222'},ready={version:1,shopUserId:7,...ids,startedAt:123},events=[];
 const zero=()=>Object.fromEntries(C.V11_COUNT_KEYS.map(key=>[key,0]));
 const lifecycle=C.createV11MailLifecycle({fixtureLocalCandidateAdmission:true,recoveryAuthority:{arm:()=>true,authorize:async()=>true},shopUserId:7,actions:{visibleBody:async body=>body==='foreign body',assess:async expected=>{events.push(['assess',expected]);return{snapshot:ready,value:{completed:true,replayed:false,judgment:{verdict:'pass'}}};},armReload(){},finishReload(){}},observer:{original:async()=>({...ids,body:'foreign body'}),canonical:async()=>({retainedPacket:true,durableProgress:true})},http:async()=>{},headers:{},siblingHeaders:{},counts:async()=>zero(),ownerSnapshot:async()=>({}),siblingSnapshot:async()=>({}),sharedTargetMessages:async()=>[],readReference:async()=>{events.push(['read',null]);return null;}});
 await lifecycle.initialize();assert.equal(await lifecycle.afterDetail({detail:{body:ids},source:{body:'foreign body'}}),true);assert.deepEqual(events,[['read',null],['assess',{shopUserId:7,...ids}]]);
});


test('sibling persona snapshot preserves every field while authentication advances only liveness',()=>{
 const row={session_id:'11111111-1111-4111-8111-111111111111',jti_sha256:'\\x01',platform_launch_id:'22222222-2222-4222-8222-222222222222',platform_scenario_id:'33333333-3333-4333-8333-333333333333',platform_launch_generation:1,original_platform_owner_id:8,original_platform_session_id:7,shop_user_id:9,username:'peer',role:'merchant',email:'peer@example.invalid',full_name:null,phone:null,created_at:'2026-10-16T03:23:54.53528+00:00',expires_at:'2026-10-16T03:53:54.433+00:00',revoked_at:null,ip:null,user_agent:null,credential_version:1,standalone_principal_id:'44444444-4444-4444-8444-444444444444',standalone_session_id:6,bootstrap_jti:'55555555-5555-4555-8555-555555555555',standalone_credential_version:1,standalone_authority_version:1,bootstrap_persona_authority_version:1,bootstrap_membership_version:1,last_seen_at:'2026-10-16T03:23:57.177679+00:00'};
 const snapshot=value=>({personaSession:[{row:{...row,...value}}]});
 assert.deepEqual(C.assertPersonaSessionPreserved(snapshot({}),snapshot({last_seen_at:'2026-10-16T03:25:03.713678+00:00'})),{identityPreserved:true,livenessAdvanced:true});
 assert.deepEqual(C.assertPersonaSessionPreserved(snapshot({}),snapshot({}),{requireAdvance:false}),{identityPreserved:true,livenessAdvanced:false});
 assert.throws(()=>C.assertPersonaSessionPreserved(snapshot({}),snapshot({last_seen_at:'2026-10-16T03:20:00.000000+00:00'})));
 assert.throws(()=>C.assertPersonaSessionPreserved(snapshot({}),snapshot({last_seen_at:'invalid'})));
 for(const mutation of [{role:'customer'},{credential_version:2},{revoked_at:'2026-10-16T03:25:03.713678+00:00'},{platform_launch_generation:2},{extra:'forbidden'}])assert.throws(()=>C.assertPersonaSessionPreserved(snapshot({}),snapshot({last_seen_at:'2026-10-16T03:25:03.713678+00:00',...mutation}),{requireAdvance:true}));
});


test('sibling and reset probes have closed denied-only counter deltas',()=>{const before=Object.fromEntries(C.V11_COUNT_KEYS.map(key=>[key,3]));assert.equal(C.assertSiblingCounts(before,{...before,deniedAssessmentPosts:4,deniedSourceGets:5}),true);assert.equal(C.assertResetCounts(before,{...before,deniedSourceGets:4,deniedSavedAssessmentGets:4}),true);for(const key of C.V11_COUNT_KEYS.filter(key=>!['deniedAssessmentPosts','deniedSourceGets'].includes(key)))assert.throws(()=>C.assertSiblingCounts(before,{...before,deniedAssessmentPosts:4,deniedSourceGets:5,[key]:4}),undefined,key);for(const key of C.V11_COUNT_KEYS.filter(key=>!['deniedSourceGets','deniedSavedAssessmentGets'].includes(key)))assert.throws(()=>C.assertResetCounts(before,{...before,deniedSourceGets:4,deniedSavedAssessmentGets:4,[key]:4}),undefined,key);});

test('full lifecycle binds both permitted denial counts and preserves owner/sibling/reset gates',async t=>{
 for(const deniedHopCount of [1,2])await t.test(`${deniedHopCount} denied hop(s)`,async()=>{
  const fixture=fixedFixture(deniedHopCount),actorCalls=11+deniedHopCount,judgeCalls=3-deniedHopCount;
  const ids={sessionId:'11111111-1111-4111-8111-111111111111',requestId:'22222222-2222-4222-8222-222222222222'},evaluationId='33333333-3333-4333-8333-333333333333';
  const ready={version:1,shopUserId:7,...ids,startedAt:123},state=Object.fromEntries(C.V11_COUNT_KEYS.map(key=>[key,0]));
  let activeContribution=1,shared=[4],peerSeen=0;
  const persona=()=>({personaSession:[{row:{session_id:'44444444-4444-4444-8444-444444444444',role:'merchant',credential_version:1,revoked_at:null,platform_launch_generation:1,last_seen_at:new Date(1000+peerSeen++*1000).toISOString()}}]});
  const owner=()=>({immutable:{turn:[1],receipts:[2],judgments:[3],contributions:[4],completions:[5]},activeContribution});
  const response=(completed=false)=>completed?{completed:true,replayed:false,judgment:{verdict:'pass',evaluationId,canRetry:false}}:{completed:false,status:'ineligible',modelEvaluated:false};
  const http=async(path,auth)=>{
   if(path.endsWith('/assess')){
    if(auth.kind==='sibling'){state.deniedAssessmentPosts++;return{status:401,value:null};}
    state.assessmentPosts++;return{status:200,value:response(false)};
   }
   if(path.includes('/assessment/')){state.deniedSavedAssessmentGets++;return{status:401,value:null};}
   state.deniedSourceGets++;return{status:401,value:null};
  };
  const actions={visibleBody:async()=>true,assess:async()=>{state.assessmentPosts++;return{snapshot:ready,value:response(true)};},armReload:()=>true,finishReload:async()=>{state.savedAssessmentGets++;return{value:{...response(true),replayed:true}};}};
  const lifecycle=C.createV11MailLifecycle({shopUserId:7,fixtureLocalCandidateAdmission:true,actions,observer:{original:async()=>({...ids,body:'foreign body'}),canonical:async()=>({retainedPacket:true,durableProgress:true,proof:{calls:Array(judgeCalls).fill(1)}})},http,headers:{kind:'owner'},siblingHeaders:{kind:'sibling'},counts:async()=>({...state}),actorWires:()=>fixture.actorWires,ownerSnapshot:async()=>owner(),siblingSnapshot:async()=>persona(),sharedTargetMessages:async()=>[...shared],readReference:async()=>null,recoveryAuthority:{arm:()=>true,authorize:async()=>true}});
  await lifecycle.initialize();await lifecycle.afterDetail({detail:{body:ids},source:{body:'foreign body'}});
  Object.assign(state,{actorCalls:8,toolCalls:4,effectRows:4,mailReadEffectRows:1,judgeCalls,judgments:1,credits:1,completions:1});
  await lifecycle.beforeReload();await lifecycle.afterReload();await lifecycle.beforeSibling();state.deniedSourceGets++;
  await lifecycle.afterSibling({siblingReadStatus:401});state.actorCalls=actorCalls;
  await lifecycle.afterFixed(fixture);await lifecycle.beforeReset();activeContribution=0;shared=[];await lifecycle.afterReset();
  await assert.rejects(lifecycle.finalize({status:{},actorCalls:actorCalls+1,roleTurns:6}));
  state.actorCalls++;await assert.rejects(lifecycle.finalize({status:{},actorCalls,roleTurns:6}));state.actorCalls--;
  const status={};await lifecycle.finalize({status,actorCalls,roleTurns:6});assert.equal(status.passed,true);assert.equal(status.deniedHopCount,deniedHopCount);
  assert.deepEqual({assessmentPosts:state.assessmentPosts,savedAssessmentGets:state.savedAssessmentGets,deniedAssessmentPosts:state.deniedAssessmentPosts,deniedSourceGets:state.deniedSourceGets,deniedSavedAssessmentGets:state.deniedSavedAssessmentGets},{assessmentPosts:2,savedAssessmentGets:1,deniedAssessmentPosts:1,deniedSourceGets:3,deniedSavedAssessmentGets:1});
 });
});

test('fixed accounting accepts only one or two physically joined same-choice denied hops and one terminal response',()=>{
 for(const count of [1,2])assert.equal(Q.assertFixedDenialAccounting(fixedFixture(count)),count);
});
test('fixed accounting rejects changed choice/tool, successful hops, count drift and missing terminal',()=>{
 const rejects=mutate=>{const fixture=fixedFixture(2);mutate(fixture);assert.throws(()=>Q.assertFixedDenialAccounting(fixture));};
 rejects(f=>{f.fixedTurn.receipt.hops[1].params.choiceId='88888888-8888-4888-8888-888888888888';});
 rejects(f=>{f.fixedTurn.receipt.hops[1].tool='merchant.mail_detail';});
 rejects(f=>{f.fixedTurn.receipt.hops[1].result.isError=false;});
 rejects(f=>{f.fixedTurn.receipt.hops[1].result.content[0].text='SUCCESS';});
 rejects(f=>{f.actorCallsBefore=9;});
 rejects(f=>{f.actorWires.splice(0,1);});
 rejects(f=>{f.actorWires.pop();});
 rejects(f=>{f.fixedTurn.receipt.stopReason='max_steps';});
 rejects(f=>{f.actorWires.at(-1).responseComplete=false;});
 rejects(f=>{f.actorWires.at(-1).requestSha256='0'.repeat(64);});
 rejects(f=>{f.fixedTurn.receipt.hops=[];});
 rejects(f=>{f.fixedTurn.receipt.hops.push({...f.fixedTurn.receipt.hops[1],step:3});});
});
test('fixed accounting checks serialized decisions and exact user-role observations without inventing tool messages',()=>{
 const rejects=mutate=>{const fixture=fixedFixture(2),last=fixture.actorWires.at(-1),request=JSON.parse(last.request);mutate(request.messages);fixture.actorWires[fixture.actorWires.length-1]=fixture.wire(request.messages,{reply:fixture.fixedTurn.receipt.text});assert.throws(()=>Q.assertFixedDenialAccounting(fixture));};
 rejects(messages=>{messages.at(-1).role='tool';});
 rejects(messages=>{messages.at(-1).content='ERROR: Mailbox forbidden';});
 rejects(messages=>{const decision=JSON.parse(messages.at(-2).content);decision.tool_calls[0].args.choiceId='88888888-8888-4888-8888-888888888888';messages.at(-2).content=JSON.stringify(decision);});
 rejects(messages=>{const decision=JSON.parse(messages.at(-2).content);decision.tool_calls[0].tool='mail_detail';messages.at(-2).content=JSON.stringify(decision);});
 rejects(messages=>{const decision=JSON.parse(messages.at(-2).content);decision.tool_calls[0].id=JSON.parse(messages[2].content).tool_calls[0].id;messages.at(-2).content=JSON.stringify(decision);});
 rejects(messages=>{messages.splice(2,2);});
 const fixture=fixedFixture();fixture.actorWires[11]=fixture.wire(JSON.parse(fixture.actorWires[11].request).messages,{tool_calls:[{agent:'merchant',tool:'mail_list',args:{choiceId:fixture.fixedChoice.choiceId}}]});assert.throws(()=>Q.assertFixedDenialAccounting(fixture));
});

test('qualified V11 lifecycle preserves every gate and reports candidate admission false',async()=>{
 const source=require('node:fs').readFileSync(require.resolve('./secureshopMailAgentReadRenderedLifecycle'),'utf8');
 assert.match(source,/value\.fixtureLocalCandidateAdmission=fixtureLocalCandidateAdmission/);
 const f={actions:{visibleBody(){},assess(){},armReload(){},finishReload(){}},observer:{original(){},canonical(){}},http(){},counts(){},ownerSnapshot(){},siblingSnapshot(){},sharedTargetMessages(){},readReference(){},recoveryAuthority:{arm(){return true;},async authorize(){return true;}}};
 const lifecycle=C.createV11MailLifecycle({...f,headers:{},siblingHeaders:{},shopUserId:7,fixtureLocalCandidateAdmission:false});assert.equal(lifecycle.fixtureLocalCandidateAdmission,false);
});
